"""Subprocess wrapper around the opengrep CLI.

`subprocess.run` and nothing else. opengrep is an OCaml CLI with zero bindings
in any language (plan/00-SPINE.md S12), so there is no in-process path to
accidentally take, and the LGPL-2.1 combined-work question never engages.

Output format is SARIF 2.1.0 via `--sarif-output=<file>`, which is both the
invocation form documented in the opengrep v1.26.0 README and Anvil's record
format (plan/00-SPINE.md S4/S6). Findings are read out of the SARIF document, so
this wrapper never has to parse decorated console text.

Failure is always an exception. There is no code path in this module that
returns an empty finding list because something was missing — a missing binary,
a missing ruleset, a non-recoverable exit code and unparseable output each raise.
An empty `ScanResult.findings` therefore means exactly one thing: opengrep ran
the pinned rules over the target and matched nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import (
    EngineNotAvailable,
    OpengrepOutputError,
    OpengrepRunError,
    RulesetNotAvailable,
)
from .manifest import Manifest, assert_rule_source_permitted, load_manifest

# opengrep inherits semgrep's exit-code convention:
#   0 = ran cleanly, 1 = ran cleanly and blocking findings were reported.
# Everything else (2 fatal, 3 missing config, 4 invalid pattern, 7 all rules
# failed, 8 missing language) is a tool failure and must not be mistaken for
# "clean scan".
OK_EXIT_CODES = frozenset({0, 1})

DEFAULT_TIMEOUT_SECONDS = 900


@dataclass(frozen=True)
class Finding:
    """One opengrep match, flattened out of SARIF.

    `line` is advisory. plan/30-lane-b-detection.md treats file/function as the
    authoritative identity for a candidate and line numbers as a hint, because
    line numbers drift the moment anything above them is edited.
    """

    rule_id: str
    path: str
    line: int | None
    end_line: int | None
    message: str
    severity: str
    fingerprint: str | None = None

    @property
    def candidate_key(self) -> str:
        """File-authoritative identity; deliberately excludes the line number."""
        return f"{self.path}::{self.rule_id}"


@dataclass(frozen=True)
class ScanResult:
    target: Path
    ruleset: Path
    findings: tuple[Finding, ...]
    exit_code: int
    engine_version: str
    ruleset_commit_sha: str
    duration_seconds: float
    stderr: str = ""
    sarif: dict = field(default_factory=dict, repr=False)

    @property
    def candidate_count(self) -> int:
        """The INSTR-01 quantity: candidates produced by the recall tier."""
        return len(self.findings)


class OpengrepRunner:
    """Invokes the pinned opengrep binary against the pinned ruleset."""

    def __init__(
        self,
        engine_path: str | Path | None = None,
        ruleset_path: str | Path | None = None,
        manifest: Manifest | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        extra_args: tuple[str, ...] = (),
    ) -> None:
        # Imported lazily so `manifest`/`runner` stay importable without `acquire`
        # having ever been run.
        from . import acquire

        self.manifest = manifest or load_manifest()
        self.engine_path = (
            Path(engine_path) if engine_path else acquire.engine_path(manifest=self.manifest)
        )
        self.ruleset_path = (
            Path(ruleset_path) if ruleset_path else acquire.ruleset_path(manifest=self.manifest)
        )
        self.timeout_seconds = timeout_seconds
        self.extra_args = tuple(extra_args)

        # S5 gate, applied to whatever path the caller actually handed us — not
        # just to the manifest. A hard exclusion enforced only on the happy path
        # is not enforced.
        assert_rule_source_permitted(str(self.ruleset_path))

    # -- availability ------------------------------------------------------

    def engine_available(self) -> bool:
        return self.engine_path.is_file() and (
            os.name == "nt" or os.access(self.engine_path, os.X_OK)
        )

    def ruleset_available(self) -> bool:
        return self.ruleset_path.is_dir()

    def ensure_available(self) -> None:
        """Raise a specific, actionable exception if anything is missing.

        Called at the top of every scan. This is the "fail loudly" contract: the
        harness must never report zero candidates because a binary was absent.
        """
        if not self.engine_available():
            raise EngineNotAvailable(
                f"pinned opengrep binary not found or not executable at:\n  {self.engine_path}\n"
                f"Manifest pins {self.manifest.engine_repo} {self.manifest.engine_version} "
                f"({self.manifest.engine_license}).\n"
                "Fetch it deliberately with:  python -m anvil_opengrep.acquire --engine\n"
                "This is NOT a scan with zero findings. No scan happened."
            )
        if not self.ruleset_available():
            raise RulesetNotAvailable(
                f"pinned ruleset checkout not found at:\n  {self.ruleset_path}\n"
                f"Manifest pins {self.manifest.ruleset_name} @ "
                f"{self.manifest.ruleset_commit_sha} ({self.manifest.ruleset_license}).\n"
                "Fetch it deliberately with:  python -m anvil_opengrep.acquire --rules\n"
                "This is NOT a scan with zero findings. No scan happened."
            )

    # -- invocation --------------------------------------------------------

    def build_argv(self, target: str | Path, sarif_output: str | Path) -> list[str]:
        """Construct the exact argv. Pure, so tests can assert on it with no binary present.

        Form verified against the opengrep v1.26.0 README:
            opengrep scan --sarif-output=<file> -f <rules> <target>
        """
        return [
            str(self.engine_path),
            "scan",
            f"--sarif-output={sarif_output}",
            "-f",
            str(self.ruleset_path),
            *self.extra_args,
            str(target),
        ]

    def version(self) -> str:
        """`opengrep --version`. Raises EngineNotAvailable if the binary is absent."""
        if not self.engine_available():
            raise EngineNotAvailable(f"pinned opengrep binary not found at {self.engine_path}")
        proc = subprocess.run(  # noqa: S603 - fixed argv from the manifest, no shell
            [str(self.engine_path), "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.returncode != 0:
            raise OpengrepRunError(
                f"opengrep --version exited {proc.returncode}: {proc.stderr.strip()}"
            )
        return proc.stdout.strip()

    def scan(self, target: str | Path) -> ScanResult:
        """Run the pinned rules over `target` and return parsed candidates."""
        import time

        self.ensure_available()
        target_path = Path(target)
        if not target_path.exists():
            raise OpengrepRunError(f"scan target does not exist: {target_path}")

        workdir = Path(tempfile.mkdtemp(prefix="anvil-opengrep-"))
        sarif_file = workdir / "results.sarif"
        argv = self.build_argv(target_path, sarif_file)
        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(workdir, ignore_errors=True)
            raise OpengrepRunError(
                f"opengrep exceeded {self.timeout_seconds}s on {target_path}"
            ) from exc
        duration = time.monotonic() - started

        try:
            if proc.returncode not in OK_EXIT_CODES:
                raise OpengrepRunError(
                    f"opengrep exited {proc.returncode} "
                    f"(expected one of {sorted(OK_EXIT_CODES)}).\n"
                    f"argv: {argv}\n"
                    f"stderr:\n{proc.stderr.strip()[:4000]}"
                )
            if not sarif_file.is_file():
                raise OpengrepOutputError(
                    f"opengrep exited {proc.returncode} but wrote no SARIF to {sarif_file}.\n"
                    f"stdout:\n{proc.stdout.strip()[:2000]}\nstderr:\n{proc.stderr.strip()[:2000]}"
                )
            try:
                sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise OpengrepOutputError(
                    f"opengrep SARIF output is not valid JSON: {exc}"
                ) from exc
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        return ScanResult(
            target=target_path,
            ruleset=self.ruleset_path,
            findings=parse_sarif(sarif),
            exit_code=proc.returncode,
            engine_version=self.manifest.engine_version,
            ruleset_commit_sha=self.manifest.ruleset_commit_sha,
            duration_seconds=duration,
            stderr=proc.stderr.strip(),
            sarif=sarif,
        )


def parse_sarif(document: dict) -> tuple[Finding, ...]:
    """Flatten a SARIF 2.1.0 document into Findings.

    Tolerant of absent optional members (SARIF makes almost everything optional)
    but strict about the shape: a document with no `runs` key at all is a
    malformed result, not an empty one.
    """
    if not isinstance(document, dict) or "runs" not in document:
        raise OpengrepOutputError("SARIF document has no 'runs' member; output is malformed")

    findings: list[Finding] = []
    for run in document.get("runs") or []:
        # Rule-level default severity, used when a result omits its own level.
        rule_levels: dict[str, str] = {}
        driver = ((run.get("tool") or {}).get("driver")) or {}
        for rule in driver.get("rules") or []:
            rule_id = rule.get("id")
            level = (rule.get("defaultConfiguration") or {}).get("level")
            if rule_id and level:
                rule_levels[rule_id] = level

        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or "<unknown-rule>"
            message = ((result.get("message") or {}).get("text")) or ""
            severity = result.get("level") or rule_levels.get(rule_id) or "warning"
            fingerprints = result.get("fingerprints") or {}
            fingerprint = next(iter(fingerprints.values()), None) if fingerprints else None

            locations = result.get("locations") or []
            if not locations:
                findings.append(
                    Finding(rule_id, "<no-location>", None, None, message, severity, fingerprint)
                )
                continue
            for location in locations:
                physical = location.get("physicalLocation") or {}
                uri = ((physical.get("artifactLocation") or {}).get("uri")) or "<no-uri>"
                region = physical.get("region") or {}
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        path=uri,
                        line=region.get("startLine"),
                        end_line=region.get("endLine"),
                        message=message,
                        severity=str(severity),
                        fingerprint=fingerprint,
                    )
                )
    return tuple(findings)

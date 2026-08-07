"""Load and validate MANIFEST.toml — the single source of truth for what may be fetched.

Stdlib only (`tomllib`, Python 3.11+). The evaluation harness must be able to
read its own pins without any third-party dependency being installed first.
"""

from __future__ import annotations

import platform
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import ManifestError

# Repository roots that plan/00-SPINE.md S5 hard-excludes. Matched as substrings
# against any rule-source path or URL the caller supplies. Cheap, and it turns a
# licence violation into an exception instead of a code review someone skipped.
FORBIDDEN_RULE_SOURCES: tuple[str, ...] = (
    "opengrep/opengrep-rules",
    "opengrep-rules-archived",
    "semgrep/semgrep-rules",
    "semgrep-rules",
)

# The one permitted rule source, by repo slug.
PERMITTED_RULE_SOURCE = "AikidoSec/opengrep-rules"

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "MANIFEST.toml"


@dataclass(frozen=True)
class EngineAsset:
    platform: str
    filename: str
    url: str
    sha256: str
    size_bytes: int
    sigstore_sig: str | None = None
    sigstore_cert: str | None = None


@dataclass(frozen=True)
class RulesetFile:
    path: str
    blob_sha1: str
    size_bytes: int


@dataclass(frozen=True)
class Manifest:
    path: Path
    engine_version: str
    engine_repo: str
    engine_commit_sha: str
    engine_license: str
    engine_assets: tuple[EngineAsset, ...]
    ruleset_name: str
    ruleset_repo: str
    ruleset_commit_sha: str
    ruleset_license: str
    ruleset_files: tuple[RulesetFile, ...]
    ruleset_rule_ids: tuple[str, ...]

    def asset_for(self, platform_key: str | None = None) -> EngineAsset:
        """Return the pinned asset for a platform key, defaulting to this host."""
        key = platform_key or current_platform_key()
        for asset in self.engine_assets:
            if asset.platform == key:
                return asset
        known = ", ".join(sorted(a.platform for a in self.engine_assets))
        raise ManifestError(
            f"no pinned opengrep asset for platform {key!r}. Pinned platforms: {known}"
        )


def current_platform_key() -> str:
    """Map this interpreter's host to a MANIFEST.toml `engine.assets.platform` key."""
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        arch = "x86_64"
    elif machine in {"arm64", "aarch64"}:
        arch = "aarch64" if sys.platform.startswith("linux") else "arm64"
    else:
        raise ManifestError(f"unsupported CPU architecture for opengrep: {machine!r}")

    if sys.platform.startswith("linux"):
        # libc flavour matters: the manylinux build will not run on musl.
        libc = "musl" if _is_musl() else "glibc"
        return f"linux-{arch}-{libc}"
    if sys.platform == "darwin":
        return f"darwin-{'arm64' if arch == 'arm64' else 'x86_64'}"
    if sys.platform in {"win32", "cygwin"}:
        return "windows-x86_64"
    raise ManifestError(f"unsupported platform for opengrep: {sys.platform!r}")


def _is_musl() -> bool:
    try:
        libc, _ = platform.libc_ver()
    except (OSError, ValueError):  # pragma: no cover - platform dependent
        return False
    if libc:
        return "musl" in libc.lower()
    # platform.libc_ver() returns ("", "") on musl systems; the marker file is
    # the pragmatic fallback.
    return any(Path("/lib").glob("ld-musl-*.so.1"))


def _require(table: dict, key: str, where: str):
    if key not in table:
        raise ManifestError(f"MANIFEST.toml: missing required key {where}.{key}")
    return table[key]


def load_manifest(path: str | Path | None = None) -> Manifest:
    """Parse and validate MANIFEST.toml.

    Validation is deliberately strict: an under-specified pin is a supply-chain
    hole, and a manifest that parses but omits a SHA is worse than one that
    fails to parse, because it looks fine.
    """
    manifest_path = Path(path) if path is not None else DEFAULT_MANIFEST_PATH
    if not manifest_path.is_file():
        raise ManifestError(f"MANIFEST.toml not found at {manifest_path}")

    try:
        with manifest_path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"MANIFEST.toml is not valid TOML: {exc}") from exc

    engine = _require(data, "engine", "<root>")
    ruleset = _require(data, "ruleset", "<root>")

    linkage = engine.get("linkage")
    if linkage != "subprocess":
        raise ManifestError(
            "MANIFEST.toml: engine.linkage must be 'subprocess'. "
            "plan/00-SPINE.md S12: opengrep has zero bindings in any language; "
            "linking it is not merely discouraged, it is impossible, and claiming "
            "otherwise in the manifest means the manifest is wrong."
        )

    raw_assets = engine.get("assets") or []
    if not raw_assets:
        raise ManifestError("MANIFEST.toml: engine.assets is empty; nothing is pinned")
    assets = []
    for index, raw in enumerate(raw_assets):
        where = f"engine.assets[{index}]"
        sha256 = str(_require(raw, "sha256", where))
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ManifestError(f"{where}.sha256 is not a lowercase hex sha256: {sha256!r}")
        assets.append(
            EngineAsset(
                platform=str(_require(raw, "platform", where)),
                filename=str(_require(raw, "filename", where)),
                url=str(_require(raw, "url", where)),
                sha256=sha256,
                size_bytes=int(_require(raw, "size_bytes", where)),
                sigstore_sig=raw.get("sigstore_sig"),
                sigstore_cert=raw.get("sigstore_cert"),
            )
        )

    ruleset_repo = str(_require(ruleset, "repo", "ruleset"))
    ruleset_name = str(_require(ruleset, "name", "ruleset"))
    assert_rule_source_permitted(ruleset_repo)
    assert_rule_source_permitted(ruleset_name)
    if PERMITTED_RULE_SOURCE.lower() not in ruleset_name.lower():
        raise ManifestError(
            f"MANIFEST.toml: ruleset.name is {ruleset_name!r}; plan/00-SPINE.md S4 "
            f"names {PERMITTED_RULE_SOURCE} as the only permitted rule source."
        )

    ruleset_sha = str(_require(ruleset, "commit_sha", "ruleset"))
    if len(ruleset_sha) != 40:
        raise ManifestError(
            "MANIFEST.toml: ruleset.commit_sha must be a full 40-char SHA. "
            "plan/00-SPINE.md S7 pins by commit SHA; a branch name or short SHA is not a pin."
        )

    files = tuple(
        RulesetFile(
            path=str(_require(raw, "path", f"ruleset.files[{i}]")),
            blob_sha1=str(_require(raw, "blob_sha1", f"ruleset.files[{i}]")),
            size_bytes=int(_require(raw, "size_bytes", f"ruleset.files[{i}]")),
        )
        for i, raw in enumerate(ruleset.get("files") or [])
    )
    if not files:
        raise ManifestError(
            "MANIFEST.toml: ruleset.files is empty; the checkout cannot be verified"
        )

    coverage = ruleset.get("coverage") or {}
    rule_ids = tuple(str(r) for r in coverage.get("rule_ids", ()))

    engine_sha = str(_require(engine, "release_commit_sha", "engine"))
    if len(engine_sha) != 40:
        raise ManifestError("MANIFEST.toml: engine.release_commit_sha must be a full 40-char SHA")

    return Manifest(
        path=manifest_path,
        engine_version=str(_require(engine, "version", "engine")),
        engine_repo=str(_require(engine, "repo", "engine")),
        engine_commit_sha=engine_sha,
        engine_license=str(_require(engine, "license_spdx", "engine")),
        engine_assets=tuple(assets),
        ruleset_name=ruleset_name,
        ruleset_repo=ruleset_repo,
        ruleset_commit_sha=ruleset_sha,
        ruleset_license=str(_require(ruleset, "license_spdx", "ruleset")),
        ruleset_files=files,
        ruleset_rule_ids=rule_ids,
    )


def assert_rule_source_permitted(source: str) -> None:
    """Raise if `source` names an S5 hard-excluded rule repository.

    Called on the manifest at load time and on every `--config` argument at run
    time. plan/00-SPINE.md S5 excludes opengrep/opengrep-rules (archived,
    NOASSERTION, LGPL-2.1 + Commons Clause) and all Semgrep-maintained rules.
    """
    from .errors import ForbiddenRuleSource  # local import: keeps manifest import-light

    normalised = str(source).replace("\\", "/").lower()
    for forbidden in FORBIDDEN_RULE_SOURCES:
        if forbidden.lower() in normalised:
            raise ForbiddenRuleSource(
                f"rule source {source!r} matches the hard exclusion {forbidden!r}. "
                "plan/00-SPINE.md S5: opengrep/opengrep-rules is archived, NOASSERTION, "
                "LGPL-2.1 + Commons Clause; Semgrep-maintained rules are internal-business-use "
                f"only. Use {PERMITTED_RULE_SOURCE} (MIT)."
            )

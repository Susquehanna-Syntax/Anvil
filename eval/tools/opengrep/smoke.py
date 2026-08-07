"""End-to-end smoke run for M0.7's recall-tier acquisition.

    python eval/tools/opengrep/smoke.py

Materializes the sample repo, runs the pinned opengrep binary against the pinned
AikidoSec ruleset, prints the candidate list, and exits:

    0  scan completed and matched the expected rule IDs
    1  scan completed but the findings did not match expectations (pin drift)
    2  the engine or the ruleset is not present  <-- loud, not a "clean scan"
    3  the scan itself failed (bad exit code, unparseable output)

Exit 2 is deliberately distinct. An absent binary must never be reportable as
"zero candidates found"; INSTR-01 (plan/10-milestone0-evaluation.md M0.11) reads
candidate counts as a measurement, and a silent zero would poison it.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from anvil_opengrep import (  # noqa: E402
    EngineNotAvailable,
    OpengrepRunner,
    RulesetNotAvailable,
)
from anvil_opengrep.errors import OpengrepError  # noqa: E402
from anvil_opengrep.fixtures import (  # noqa: E402
    EXPECTED_CLEAN_PATHS,
    EXPECTED_RULE_IDS,
    materialize_sample_repo,
)
from anvil_opengrep.manifest import load_manifest  # noqa: E402


def main() -> int:
    manifest = load_manifest()
    print("=== Anvil M0.7 opengrep smoke run ===")
    print(f"engine  : {manifest.engine_repo} {manifest.engine_version} [{manifest.engine_license}]")
    print(f"ruleset : {manifest.ruleset_name} @ {manifest.ruleset_commit_sha} [{manifest.ruleset_license}]")
    print(f"rules   : {', '.join(manifest.ruleset_rule_ids) or '(none recorded)'}")

    runner = OpengrepRunner(manifest=manifest)
    print(f"binary  : {runner.engine_path}")
    print(f"rulesdir: {runner.ruleset_path}")

    try:
        runner.ensure_available()
    except (EngineNotAvailable, RulesetNotAvailable) as exc:
        print(f"\nUNAVAILABLE: {type(exc).__name__}\n{exc}", file=sys.stderr)
        return 2

    print(f"version : {runner.version()}")

    sample = materialize_sample_repo()
    try:
        print(f"target  : {sample}")
        print(f"argv    : {runner.build_argv(sample, '<sarif>')}")
        try:
            result = runner.scan(sample)
        except OpengrepError as exc:
            print(f"\nSCAN FAILED: {type(exc).__name__}\n{exc}", file=sys.stderr)
            return 3

        print(f"\nexit    : {result.exit_code}")
        print(f"duration: {result.duration_seconds:.2f}s")
        print(f"candidates (INSTR-01 quantity): {result.candidate_count}")
        for finding in result.findings:
            print(f"  - {finding.rule_id}  {finding.path}:{finding.line}  [{finding.severity}]")

        observed_rules = {f.rule_id for f in result.findings}
        observed_paths = {f.path.replace("\\", "/") for f in result.findings}

        ok = True
        missing = EXPECTED_RULE_IDS - observed_rules
        if missing:
            print(f"\nPIN DRIFT: expected rule IDs never fired: {sorted(missing)}", file=sys.stderr)
            ok = False
        unexpected = observed_rules - EXPECTED_RULE_IDS
        if unexpected:
            print(f"\nPIN DRIFT: unexpected rule IDs fired: {sorted(unexpected)}", file=sys.stderr)
            ok = False
        dirty = {p for p in observed_paths if any(p.endswith(c) for c in EXPECTED_CLEAN_PATHS)}
        if dirty:
            print(f"\nMISATTRIBUTION: findings on control files: {sorted(dirty)}", file=sys.stderr)
            ok = False

        if ok:
            print("\nOK: pinned engine + pinned ruleset produced exactly the expected candidates.")
        return 0 if ok else 1
    finally:
        shutil.rmtree(sample, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

"""Runner behaviour that must hold whether or not the opengrep binary exists.

The single most important property under test: when the engine or the ruleset is
absent, the runner RAISES. It does not return an empty ScanResult. INSTR-01
counts candidates, and a silent zero from a missing binary would be recorded as
a real measurement.
"""

from __future__ import annotations

import json

import pytest
from anvil_opengrep import OpengrepRunner
from anvil_opengrep.errors import (
    EngineNotAvailable,
    ForbiddenRuleSource,
    OpengrepOutputError,
    RulesetNotAvailable,
)
from anvil_opengrep.runner import OK_EXIT_CODES, parse_sarif


def _runner(tmp_path, *, engine=True, rules=True):
    engine_path = tmp_path / "opengrep-fake"
    rules_path = tmp_path / "aikido-rules"
    if engine:
        engine_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        engine_path.chmod(0o755)
    if rules:
        rules_path.mkdir()
    return OpengrepRunner(engine_path=engine_path, ruleset_path=rules_path)


def test_missing_engine_raises_rather_than_returning_zero_findings(tmp_path):
    runner = _runner(tmp_path, engine=False)
    with pytest.raises(EngineNotAvailable) as excinfo:
        runner.ensure_available()
    message = str(excinfo.value)
    assert "No scan happened" in message
    assert "anvil_opengrep.acquire" in message, "the error must say how to fix it"


def test_missing_ruleset_raises_rather_than_returning_zero_findings(tmp_path):
    runner = _runner(tmp_path, rules=False)
    with pytest.raises(RulesetNotAvailable) as excinfo:
        runner.ensure_available()
    assert "No scan happened" in str(excinfo.value)


def test_scan_refuses_before_touching_the_target_when_engine_absent(tmp_path):
    runner = _runner(tmp_path, engine=False)
    with pytest.raises(EngineNotAvailable):
        runner.scan(tmp_path)


def test_version_raises_when_binary_absent(tmp_path):
    runner = _runner(tmp_path, engine=False)
    with pytest.raises(EngineNotAvailable):
        runner.version()


def test_runner_refuses_an_s5_excluded_ruleset_path(tmp_path):
    engine_path = tmp_path / "opengrep-fake"
    engine_path.write_text("", encoding="utf-8")
    bad_rules = tmp_path / "opengrep" / "opengrep-rules"
    bad_rules.mkdir(parents=True)
    with pytest.raises(ForbiddenRuleSource):
        OpengrepRunner(engine_path=engine_path, ruleset_path=bad_rules)


def test_argv_matches_the_documented_opengrep_invocation(tmp_path):
    """`opengrep scan --sarif-output=<file> -f <rules> <target>` per the v1.26.0 README."""
    runner = _runner(tmp_path)
    argv = runner.build_argv("/repo", "/tmp/out.sarif")
    assert argv[1] == "scan"
    assert argv[2] == "--sarif-output=/tmp/out.sarif"
    assert argv[3] == "-f"
    assert argv[4] == str(runner.ruleset_path)
    assert argv[-1] == "/repo"


def test_findings_and_only_findings_are_the_ok_exit_codes():
    """0 = clean, 1 = findings. 2/3/4/7/8 are tool failures, never 'clean scan'."""
    assert OK_EXIT_CODES == {0, 1}


SARIF_SAMPLE = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "opengrep",
                    "rules": [
                        {
                            "id": "npm_staged_publishing_missing",
                            "defaultConfiguration": {"level": "warning"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "github_workflow_prompt_injection",
                    "level": "warning",
                    "message": {"text": "untrusted inference output"},
                    "fingerprints": {"matchBasedId/v1": "abc123"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": ".github/workflows/a.yml"},
                                "region": {"startLine": 22, "endLine": 22},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "npm_staged_publishing_missing",
                    "message": {"text": "use staged publishing"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": ".github/workflows/b.yml"},
                                "region": {"startLine": 17},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


def test_parse_sarif_flattens_results():
    findings = parse_sarif(json.loads(json.dumps(SARIF_SAMPLE)))
    assert len(findings) == 2
    first = findings[0]
    assert first.rule_id == "github_workflow_prompt_injection"
    assert first.path == ".github/workflows/a.yml"
    assert first.line == 22
    assert first.fingerprint == "abc123"
    # Candidate identity is file-authoritative; the line number is a hint only.
    assert first.candidate_key == ".github/workflows/a.yml::github_workflow_prompt_injection"


def test_parse_sarif_falls_back_to_rule_default_severity():
    findings = parse_sarif(json.loads(json.dumps(SARIF_SAMPLE)))
    second = findings[1]
    assert second.severity == "warning", "result had no level; rule default should apply"


def test_parse_sarif_accepts_an_empty_but_well_formed_run():
    assert parse_sarif({"version": "2.1.0", "runs": []}) == ()


def test_parse_sarif_rejects_a_document_with_no_runs_member():
    """A malformed result must not be indistinguishable from a clean scan."""
    with pytest.raises(OpengrepOutputError):
        parse_sarif({"version": "2.1.0"})

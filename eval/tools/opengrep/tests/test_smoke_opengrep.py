"""The packet's smoke run: pinned engine + pinned ruleset over a sample repo.

SKIPPED, not failed, when the artefacts are absent — M0.7 was scoped by the
orchestrator to produce the acquisition machinery without downloading the
opengrep binary, so on a fresh checkout these skip. Run

    python -m anvil_opengrep.acquire

first, then re-run, and the skip turns into a real assertion.

The skip reason is explicit about what was NOT verified. A silently-passing
test suite that never ran the engine would be worse than no test at all.
"""

from __future__ import annotations

import shutil

import pytest
from anvil_opengrep import OpengrepRunner
from anvil_opengrep.fixtures import (
    EXPECTED_CLEAN_PATHS,
    EXPECTED_RULE_IDS,
    materialize_sample_repo,
)


@pytest.fixture(scope="module")
def runner():
    candidate = OpengrepRunner()
    if not candidate.engine_available():
        pytest.skip(
            f"pinned opengrep binary absent at {candidate.engine_path}; "
            "the engine/ruleset smoke path is UNVERIFIED. "
            "Run `python -m anvil_opengrep.acquire` to enable it."
        )
    if not candidate.ruleset_available():
        pytest.skip(
            f"pinned AikidoSec ruleset absent at {candidate.ruleset_path}; "
            "the engine/ruleset smoke path is UNVERIFIED. "
            "Run `python -m anvil_opengrep.acquire --rules` to enable it."
        )
    return candidate


@pytest.fixture()
def sample_repo():
    root = materialize_sample_repo()
    yield root
    shutil.rmtree(root, ignore_errors=True)


def test_fixture_materializes_into_the_path_the_rules_require(sample_repo):
    """Runs with or without the binary — both pinned rules filter on .github/workflows."""
    assert (sample_repo / ".github/workflows/workflow_prompt_injection.yml").is_file()
    assert (sample_repo / ".github/workflows/workflow_npm_publish.yml").is_file()
    assert (sample_repo / ".github/workflows/clean_workflow.yml").is_file()
    assert (sample_repo / "src/decoy_app.py").is_file()
    assert not (sample_repo / ".git").exists(), (
        "the sample repo must not be a git repo: opengrep scans only git-tracked "
        "files when the target is one, which would silently skip the fixture"
    )


def test_engine_reports_the_pinned_version(runner):
    version = runner.version()
    assert version, "opengrep --version produced no output"
    assert runner.manifest.engine_version.lstrip("v") in version, (
        f"engine reports {version!r}, manifest pins {runner.manifest.engine_version}"
    )


def test_smoke_scan_returns_parseable_output_and_a_sane_exit_code(runner, sample_repo):
    result = runner.scan(sample_repo)
    assert result.exit_code in {0, 1}
    assert isinstance(result.sarif, dict) and "runs" in result.sarif
    assert result.ruleset_commit_sha == runner.manifest.ruleset_commit_sha


def test_smoke_scan_fires_exactly_the_pinned_rules(runner, sample_repo):
    result = runner.scan(sample_repo)
    observed = {f.rule_id for f in result.findings}
    assert observed == set(EXPECTED_RULE_IDS), (
        f"pin drift: expected {sorted(EXPECTED_RULE_IDS)}, observed {sorted(observed)}"
    )


def test_control_files_produce_no_findings(runner, sample_repo):
    """The clean workflow and the Python decoy must both come back empty.

    src/decoy_app.py contains an unguarded command injection. That the pinned
    MIT ruleset does not flag it is the coverage finding in LICENSES.md section
    4, made executable: two YAML-only rules cover no application source.
    """
    result = runner.scan(sample_repo)
    flagged = {f.path.replace("\\", "/") for f in result.findings}
    for control in EXPECTED_CLEAN_PATHS:
        assert not any(p.endswith(control) for p in flagged), f"unexpected finding on {control}"

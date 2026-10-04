"""The candidates-per-scan instrument's bookkeeping: diffs, the anvil recall boundary, refusals.

The tools themselves are not in the eval CI job; Lane B's own tests replay their recorded reports
and CI's Lane B job runs them. The planted-fixture control that runs them is part of every real
run and is recorded in its artifact; it was first seen failing on 2026-10-03, when the Java
fixture did not match GitLab's taint rule (a String[] is not one of its sources).
"""

from __future__ import annotations

import subprocess

import pytest

from anvil_eval.experiments import candidates as cps


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_changed_lines_are_numbered_as_in_the_new_commit(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.py").write_text("one\ntwo\nthree\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "first")
    (tmp_path / "a.py").write_text("zero\none\nTWO\nthree\nfour\n")
    (tmp_path / "b.py").write_text("new\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "second")
    assert cps.changed_lines(tmp_path, "HEAD") == {"a.py": {1, 3, 5}, "b.py": {1}}


def test_a_deleted_file_has_no_changed_lines(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.py").write_text("x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "first")
    _git(tmp_path, "rm", "-q", "a.py")
    _git(tmp_path, "commit", "-qm", "second")
    assert cps.changed_lines(tmp_path, "HEAD") == {}


def test_a_missing_tool_is_a_refusal_not_zero(tmp_path, monkeypatch):
    anvil = cps.Anvil.__new__(cps.Anvil)
    anvil.bin, anvil.config = tmp_path / "anvil", tmp_path / "anvil.yml"
    anvil.bin.write_text("#!/bin/sh\necho 'recall: opengrep is not available' >&2\nexit 4\n")
    anvil.bin.chmod(0o755)
    with pytest.raises(cps.ToolMissing):
        anvil.recall(tmp_path)


def test_a_failed_run_is_an_error_not_zero(tmp_path):
    anvil = cps.Anvil.__new__(cps.Anvil)
    anvil.bin, anvil.config = tmp_path / "anvil", tmp_path / "anvil.yml"
    anvil.bin.write_text("#!/bin/sh\nexit 5\n")
    anvil.bin.chmod(0o755)
    with pytest.raises(cps.ToolFailed):
        anvil.recall(tmp_path)


def test_candidates_are_read_from_anvil_recall_json():
    doc = {"candidates": [{"tool": "gosec", "ruleIdVersioned": "gosec/G204@2.29.0", "path": "a.go",
                           "startLine": 3, "cwe": "CWE-78"}]}
    assert cps.candidates_of(doc) == [cps.Candidate("gosec", "gosec/G204@2.29.0", "a.go", 3,
                                                    "CWE-78")]


def test_the_previous_measurement_is_carried_forward():
    assert cps.PREVIOUS["value"] == 10714 and cps.PREVIOUS["full_scan"]["curl"] == 10714

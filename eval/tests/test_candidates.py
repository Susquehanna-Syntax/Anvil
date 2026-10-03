"""The candidates-per-scan counter's bookkeeping: diffs, de-duplication and refusals.

The tools themselves are not in CI. The planted-fixture control that runs them is part of every
real run and is recorded in its artifact; it was first seen failing on 2026-10-03, when the Java
fixture did not match GitLab's taint rule (a String[] is not one of its sources).
"""

from __future__ import annotations

import subprocess

import pytest

from anvil_eval import recall
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


def test_zero_padded_and_bare_cwe_ids_are_one_candidate():
    a = cps.Candidate("opengrep", "os-system", "x.py", 9, cps._cwe("CWE-078: OS Command"))
    b = cps.Candidate("bandit", "B605", "x.py", 9, cps._cwe({"id": 78}))
    assert len(cps.dedupe([a, b])) == 1


def test_two_tools_on_one_line_and_cwe_are_one_candidate():
    a = cps.Candidate("opengrep", "eval", "x.py", 4, "CWE-95")
    b = cps.Candidate("bandit", "B307", "x.py", 4, "CWE-95")
    c = cps.Candidate("bandit", "B101", "x.py", 4, "CWE-703")
    assert len(cps.dedupe([a, b, c])) == 2


@pytest.mark.parametrize(
    "raw,cwe",
    [("CWE-95: Eval Injection", "CWE-95"), (["CWE-078"], "CWE-78"), ({"id": "22"}, "CWE-22"),
     (None, ""), ("", "")],
)
def test_cwe_labels_from_each_tool(raw, cwe):
    assert cps._cwe(raw) == cwe


def test_a_missing_tool_is_a_refusal_not_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(recall, "opengrep_bin", lambda: tmp_path / "absent")
    (tmp_path / "x.py").write_text("eval(input())\n")
    with pytest.raises(cps.ToolMissing):
        cps.scan(tmp_path, [tmp_path / "x.py"])


def test_a_tree_with_nothing_scannable_is_zero_without_running_anything(tmp_path, monkeypatch):
    monkeypatch.setattr(recall, "opengrep_bin", lambda: tmp_path / "absent")
    (tmp_path / "README.txt").write_text("hello\n")
    assert cps.scan(tmp_path, [tmp_path / "README.txt"]) == []


def test_only_the_allowlisted_gitlab_directories_are_read():
    assert recall.GITLAB_RULE_DIRS == ("c", "csharp", "go", "java", "javascript", "python",
                                       "scala")
    assert "doc" not in recall.GITLAB_RULE_DIRS  # CC BY-SA 4.0 under GitLab's LICENSE

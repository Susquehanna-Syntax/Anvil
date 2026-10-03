"""The patch-quality experiment's corpus adapter and its in-run control."""

from __future__ import annotations

import csv

import pytest

from anvil_eval.data import CorpusError, cwebenchjava
from anvil_eval.experiments import patch


def _csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


@pytest.fixture
def seed(tmp_path):
    base = {"cve_id": "CVE-1", "cwe_id": "CWE-022", "cwe_name": "Path Traversal",
            "github_url": "https://example.invalid/x", "buggy_commit_id": "a" * 40}
    _csv(tmp_path / "data" / "project_info.csv",
         [dict(base, project_slug="ok"), dict(base, project_slug="broken"),
          dict(base, project_slug="gradle")])
    _csv(tmp_path / "data" / "build_info.csv", [
        {"project_slug": "ok", "status": "success", "jdk_version": "8u202",
         "mvn_version": "3.5.0", "gradle_version": "n/a", "use_gradlew": "n/a"},
        {"project_slug": "broken", "status": "fail", "jdk_version": "8u202",
         "mvn_version": "3.5.0", "gradle_version": "n/a", "use_gradlew": "n/a"},
        {"project_slug": "gradle", "status": "success", "jdk_version": "17",
         "mvn_version": "n/a", "gradle_version": "7.6.4", "use_gradlew": "true"}])
    _csv(tmp_path / "data" / "fix_info.csv", [
        {"project_slug": s, "file": "src/main/java/A.java", "class": "A", "method": "read"}
        for s in ("ok", "broken", "gradle")])
    return tmp_path


def test_only_buildable_cases_become_projects(seed):
    ps = cwebenchjava.projects(seed)
    assert [p.slug for p in ps] == ["ok", "gradle"]
    assert cwebenchjava.finding(ps[0]) == "CWE-022 Path Traversal in A.read (CVE-1)"


def test_each_build_tool_gets_its_own_commands(seed):
    mvn, gradle = cwebenchjava.projects(seed)
    assert cwebenchjava.commands(mvn)[0][0] == "mvn" and "-DskipTests" in cwebenchjava.commands(
        mvn)[0]
    assert cwebenchjava.commands(gradle)[1][:2] == ["./gradlew", "--offline"]


def test_a_missing_seed_table_is_refused(tmp_path):
    with pytest.raises(CorpusError, match="missing"):
        cwebenchjava.projects(tmp_path)


def test_the_in_run_control_tells_a_real_fix_from_a_cosmetic_one():
    assert patch.control() == {"real_fix": "verified_fixed",
                               "cosmetic_patch": "exploit_still_triggers", "passed": True}

"""Recording a result fills the register's result block and can never write a decision."""

from __future__ import annotations

import shutil

import pytest
import yaml

from anvil_eval import REGISTER_PATH, results

GIT = {"commit": "0" * 40, "dirty": False}


def _artifact(rid="prefill-sweep", passed=True, value=812.5):
    return {
        "id": rid,
        "measured_at": "2026-10-03",
        "value": value,
        "unit": "tokens/s",
        "command": "python -m anvil_eval.experiments.prefill run",
        "git": GIT,
        "pins": {"llama.cpp": "b11146"},
        "result": {"rows": []},
        "negative_control": {
            "description": "a run that must fail",
            "expected": "refused",
            "observed": "refused" if passed else "accepted",
            "passed": passed,
        },
    }


def test_an_artifact_whose_negative_control_failed_is_not_written(tmp_path):
    with pytest.raises(results.RecordError):
        results.write_artifact(_artifact(passed=False), tmp_path / "x.json")
    assert not (tmp_path / "x.json").exists()


def test_record_fills_the_result_and_keeps_the_decision(tmp_path):
    reg = tmp_path / "register.yaml"
    shutil.copy(REGISTER_PATH, reg)
    art = results.write_artifact(_artifact(), tmp_path / "prefill-sweep.json")
    results.record("prefill-sweep", register=reg, artifact=art)
    rows = {r["id"]: r for r in yaml.safe_load(reg.read_text())["experiments"]}
    row = rows["prefill-sweep"]
    assert row["status"] == "complete"
    assert row["result"]["value"] == 812.5 and row["result"]["unit"] == "tokens/s"
    assert row["decision"] == "UNRESOLVED"
    original = {r["id"]: r for r in yaml.safe_load(REGISTER_PATH.read_text())["experiments"]}
    assert all(rows[k] == original[k] for k in rows if k != "prefill-sweep")
    assert reg.read_text().count("# HOW TO READ THE `decision` FIELD") == 1  # comments survive


def test_record_refuses_an_artifact_for_another_row(tmp_path):
    reg = tmp_path / "register.yaml"
    shutil.copy(REGISTER_PATH, reg)
    art = results.write_artifact(_artifact("prefill-sweep"), tmp_path / "a.json")
    with pytest.raises(results.RecordError, match="not 'patch-quality'"):
        results.record("patch-quality", register=reg, artifact=art)


def test_record_refuses_when_a_decision_would_change(tmp_path, monkeypatch):
    """Negative control: corrupt the edit so it also writes PASS, and the guard must refuse."""
    reg = tmp_path / "register.yaml"
    shutil.copy(REGISTER_PATH, reg)
    art = results.write_artifact(_artifact(), tmp_path / "prefill-sweep.json")
    real_subn = results.re.subn

    def subn(pattern, repl, string, count=0):
        out, n = real_subn(pattern, repl, string, count=count)
        return out.replace("decision: UNRESOLVED", "decision: PASS"), n

    monkeypatch.setattr(results.re, "subn", subn)
    with pytest.raises(results.RecordError):
        results.record("prefill-sweep", register=reg, artifact=art)
    assert yaml.safe_load(reg.read_text()) == yaml.safe_load(REGISTER_PATH.read_text())


def test_committed_artifacts_validate_and_match_their_rows():
    """Every file under eval/results/ validates, and every complete row points at one."""
    rows = {r["id"]: r for r in yaml.safe_load(REGISTER_PATH.read_text())["experiments"]}
    for rid, row in rows.items():
        if row["status"] == "complete":
            import json
            from pathlib import Path

            path = Path(results.REPO_ROOT) / row["result"]["artifact_path"]
            doc = json.loads(path.read_text())
            results.validate_artifact(doc)
            assert doc["id"] == rid and doc["value"] == row["result"]["value"]

"""The prefill driver: what it runs, what it refuses, and its thread-count control."""

from __future__ import annotations

import json

import pytest

from anvil_eval import results
from anvil_eval.experiments import permutation as perm
from anvil_eval.experiments import prefill


def _rows(threads, scale, gen=True):
    rows = [{"n_prompt": p, "n_gen": 0, "avg_ts": scale * 1000 / (1 + p / 4000),
             "stddev_ts": 1.0, "samples_ts": [1.0], "n_batch": 2048, "n_ubatch": 512,
             "n_threads": threads, "n_gpu_layers": 0, "devices": "none", "flash_attn": -1,
             "model_type": "qwen35 2B", "build_number": 11146} for p in prefill.PROMPTS]
    if gen:
        rows.append(dict(rows[0], n_prompt=0, n_gen=prefill.GEN, avg_ts=scale * 30))
    return rows


def test_a_cpu_arm_hides_every_gpu():
    arm = prefill.ARMS["tier-s"]
    cmd = prefill.command(perm.Path("m.gguf"), arm, prefill.PROMPTS, prefill.GEN, 5)
    assert cmd[cmd.index("-dev") + 1] == "none" and cmd[cmd.index("-ngl") + 1] == "0"
    assert cmd[cmd.index("-t") + 1] == "4"
    assert prefill.env(arm)["CUDA_VISIBLE_DEVICES"] == ""
    gpu = prefill.ARMS["rtx4070"]
    cmd = prefill.command(perm.Path("m.gguf"), gpu, prefill.PROMPTS, prefill.GEN, 5)
    assert cmd[cmd.index("-dev") + 1] == "CUDA0" and "-t" not in cmd


@pytest.mark.parametrize("raw", ["[]", '[{"avg_ts": 0}]', "{}"])
def test_no_throughput_is_never_recorded_as_a_number(raw):
    with pytest.raises(ValueError):
        prefill.parse(raw)


def _write_runs(tmp_path, monkeypatch, one_thread_scale):
    monkeypatch.setattr(prefill, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(results, "result_path", lambda rid: tmp_path / f"{rid}.json")
    scales = {"rtx4070": 20, "rtx4060": 12, "cpu12": 1.5, "tier-s": 0.7, "cpu1": one_thread_scale}
    for arm, s in scales.items():
        rows = _rows(prefill.ARMS[arm]["threads"], s, gen=arm != "cpu1")
        (tmp_path / f"{perm.PRIMARY}__{arm}.json").write_text(json.dumps(rows))


def test_report_reads_the_tier_s_headline(tmp_path, monkeypatch):
    _write_runs(tmp_path, monkeypatch, one_thread_scale=0.2)
    doc = json.loads(prefill.report().read_text())
    expected = 0.7 * 1000 / (1 + 2000 / 4000)
    assert doc["value"] == pytest.approx(expected, abs=0.1)
    assert doc["result"]["headline"]["meets_bar"] is (expected >= 600)
    assert doc["negative_control"]["passed"] is True
    assert set(doc["result"]["table"][perm.PRIMARY]) == set(prefill.ARMS)


def test_a_cpu_arm_that_ignores_threads_fails_the_control(tmp_path, monkeypatch):
    _write_runs(tmp_path, monkeypatch, one_thread_scale=0.7)  # 1 thread as fast as 4
    with pytest.raises(results.RecordError, match="negative_control"):
        prefill.report()


def test_report_refuses_a_missing_arm(tmp_path, monkeypatch):
    _write_runs(tmp_path, monkeypatch, one_thread_scale=0.2)
    (tmp_path / f"{perm.PRIMARY}__rtx4060.json").unlink()
    with pytest.raises(SystemExit, match="rtx4060"):
        prefill.report()

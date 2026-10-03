"""The encoder worker's surface and the round-trip arithmetic, against a fake scorer.

The real scorer needs onnxruntime and the exported model, which live outside CI; it was run on
2026-10-03 on this machine (see the module docstring for what it showed).
"""

from __future__ import annotations

import http.server
import itertools
import json
import threading

import pytest

from anvil_eval import encoder, results


def _worker(score):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), encoder.handler_for(score))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def honest(pairs):
    return [len(a) / (len(a) + len(c)) for a, c in pairs]


def test_the_worker_exposes_two_paths_and_refuses_the_rest():
    srv, base = _worker(honest)
    try:
        c = encoder.control(base, ("adv", "code"), ("adv2", "longer code"))
        assert encoder.control_passed(c)
        assert encoder._post(base, "/embed", {"x": 1})[0] == 404
        assert encoder._post(base, "/score_batch", {"pairs": []})[0] == 400
    finally:
        srv.shutdown()


def test_a_worker_whose_answers_depend_on_call_order_fails_the_control():
    counter = itertools.count()

    def noisy(pairs):
        return [next(counter) * 1e-3 for _ in pairs]

    srv, base = _worker(noisy)
    try:
        assert not encoder.control_passed(encoder.control(base, ("a", "b"), ("c", "d")))
    finally:
        srv.shutdown()


def test_time_batches_covers_every_pair_once():
    seen = []

    def count(pairs):
        seen.extend(pairs)
        return [0.0] * len(pairs)

    srv, base = _worker(count)
    try:
        pairs = [(f"a{i}", f"c{i}") for i in range(100)]
        t = encoder.time_batches(base, pairs, 32)
        assert t["pairs"] == 100 and sorted(seen) == sorted(pairs)
    finally:
        srv.shutdown()


def test_report_divides_by_the_measured_model_time(tmp_path, monkeypatch):
    monkeypatch.setattr(encoder, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(results, "result_path", lambda rid: tmp_path / f"{rid}.json")
    monkeypatch.setattr(encoder, "onnx_dir", lambda: tmp_path)
    (tmp_path / "MANIFEST.json").write_text('{"files": {}}')
    (tmp_path / "prefill-sweep.json").write_text(json.dumps(
        {"result": {"headline": {"tokens_per_s": 250.0}}}))
    (tmp_path / "candidates-per-scan.json").write_text(json.dumps({"value": 400}))
    ctl = {"other_path_status": 404, "malformed_status": 400,
           "duplicate_in_batch_difference": 0.0, "alone_vs_mixed_batch_difference": 0.02}
    timings = [{"batch": 32, "pairs": 5000, "seconds": 450.0, "ms_per_pair": 90.0},
               {"batch": 64, "pairs": 5000, "seconds": 400.0, "ms_per_pair": 80.0}]
    (tmp_path / "timings.json").write_text(json.dumps(
        {"control": ctl, "timings": timings, "provenance": {}, "threads": 4, "max_tokens": 512}))
    doc = json.loads(encoder.report().read_text())
    # 2,000 tokens at 250 tokens/s is 8 s a candidate; 80 ms of 8 s is 1%.
    assert doc["value"] == pytest.approx(0.01)
    assert doc["result"]["encoder_seconds_per_full_scan"] == pytest.approx(32.0)
    assert doc["result"]["within_bar"] is True

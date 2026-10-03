"""The encoder round trip (register row encoder-round-trip, plan nodes costs and encoder).

Three parts, kept apart because they need different environments:

* ``export`` turns the pinned unixcoder-base into ONNX and then dynamic INT8. It needs torch and
  transformers, so it runs under ``eval/.venv-convert``. The weights are a pickled
  ``pytorch_model.bin``; transformers 4.57 loads it with ``torch.load(weights_only=True)``.
* ``serve`` is the encoder worker: a separate, always-on process over HTTP that exposes
  ``/score`` and ``/score_batch`` and nothing else (plan node encoder). It also runs under
  ``.venv-convert`` (onnxruntime and the tokenizer). The score is the cosine similarity of the
  mean-pooled embeddings of the advisory and the code: an off-the-shelf use of a frozen encoder,
  with nothing fitted.
* ``measure`` (this venv, standard library only) starts the worker as its own process, sends a
  realistic volume of pairs in batches of 32 and 64, and times the round trips.

The report divides the per-candidate round trip by the per-candidate model-tier time from the
prefill sweep (a 2,000-token prompt at the Tier S proxy's measured prefill rate). The candidate
count cancels out of that fraction; it is still recorded so the arithmetic can be followed.

Negative control: the worker must refuse every path but its two, refuse a malformed body, and
give one pair, sent twice in one batch, the same score twice.

A pair does *not* score the same alone as inside a mixed batch: dynamic INT8 quantisation sets its
activation scale over the whole padded batch, so batch-mates move a score (0.778 alone against
0.758 beside a longer function, measured on 2026-10-03). The report records that effect on the
measured sample, because a ranker built this way orders candidates partly by their batch-mates.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from anvil_eval import EVAL_ROOT, RESULTS_DIR, acquire, models

ID = "encoder-round-trip"
CANDIDATE = "unixcoder-base"
MAX_TOKENS = 512
THREADS = 4  # the Tier S proxy, as in the prefill sweep
BATCHES = (32, 64)
DEFAULT_PAIRS = 5000
BAR = 0.20  # the register's proposed ceiling on the encoder's share of the model tier
CONVERT_PY = EVAL_ROOT / ".venv-convert" / "bin" / "python"
RUNS_DIR = RESULTS_DIR / "runs" / ID


def onnx_dir() -> Path:
    return models.get(CANDIDATE).dir / "onnx"


# ---------------------------------------------------------------------------------------------
# export (runs under .venv-convert)


def export() -> dict:
    import torch
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from transformers import AutoModel

    c = models.get(CANDIDATE)
    models.verify_licence(c)
    model = AutoModel.from_pretrained(c.hf_dir).eval()
    out = onnx_dir()
    out.mkdir(parents=True, exist_ok=True)
    fp32, int8 = out / "unixcoder-base.onnx", out / "unixcoder-base-int8.onnx"
    ids = torch.ones((2, 16), dtype=torch.long)
    torch.onnx.export(
        model, (ids, torch.ones_like(ids)), fp32, input_names=["input_ids", "attention_mask"],
        output_names=["last_hidden_state"], opset_version=17, dynamo=False,
        dynamic_axes={"input_ids": {0: "b", 1: "t"}, "attention_mask": {0: "b", 1: "t"},
                      "last_hidden_state": {0: "b", 1: "t"}},
    )
    quantize_dynamic(str(fp32), str(int8), weight_type=QuantType.QInt8)
    record = {
        "from": {"repo": c.repo, "revision": c.revision},
        "torch": torch.__version__,
        "files": {p.name: {"sha256": acquire.sha256_file(p)} for p in (fp32, int8)},
        "quantisation": "onnxruntime quantize_dynamic, QInt8 weights",
    }
    (out / "MANIFEST.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


# ---------------------------------------------------------------------------------------------
# serve (runs under .venv-convert)


def onnx_scorer(threads: int = THREADS) -> Callable[[list[tuple[str, str]]], list[float]]:
    import numpy as np
    import onnxruntime as ort
    from transformers import AutoTokenizer

    c = models.get(CANDIDATE)
    tok = AutoTokenizer.from_pretrained(c.hf_dir)
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = threads
    opts.inter_op_num_threads = 1
    sess = ort.InferenceSession(str(onnx_dir() / "unixcoder-base-int8.onnx"), opts,
                                providers=["CPUExecutionProvider"])

    def embed(texts: list[str]):
        enc = tok(texts, padding=True, truncation=True, max_length=MAX_TOKENS,
                  return_tensors="np")
        mask = enc["attention_mask"].astype("int64")
        feeds = {"input_ids": enc["input_ids"].astype("int64"), "attention_mask": mask}
        (hidden,) = sess.run(["last_hidden_state"], feeds)
        pooled = (hidden * mask[..., None]).sum(1) / mask.sum(1, keepdims=True)
        return pooled / np.linalg.norm(pooled, axis=1, keepdims=True)

    def score(pairs: list[tuple[str, str]]) -> list[float]:
        a = embed([p[0] for p in pairs])
        b = embed([p[1] for p in pairs])
        return [float(x) for x in (a * b).sum(1)]

    return score


def handler_for(score: Callable[[list[tuple[str, str]]], list[float]]):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _reply(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            self._reply(404, {"error": "only POST /score and POST /score_batch exist"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in ("/score", "/score_batch"):
                self._reply(404, {"error": "only /score and /score_batch exist"})
                return
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                if self.path == "/score":
                    pairs = [(str(body["advisory"]), str(body["code"]))]
                else:
                    pairs = [(str(p["advisory"]), str(p["code"])) for p in body["pairs"]]
                    if not pairs:
                        raise ValueError("empty batch")
            except (ValueError, KeyError, TypeError) as exc:
                self._reply(400, {"error": f"malformed request: {exc}"})
                return
            scores = score(pairs)
            if self.path == "/score":
                self._reply(200, {"score": scores[0]})
            else:
                self._reply(200, {"scores": scores})

        def log_message(self, *args) -> None:
            pass

    return Handler


def serve(port: int, score=None) -> None:
    srv = http.server.HTTPServer(("127.0.0.1", port), handler_for(score or onnx_scorer()))
    print(f"encoder worker on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()


# ---------------------------------------------------------------------------------------------
# measure (this venv)


def _post(base: str, path: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def control(base: str, sample: tuple[str, str], other: tuple[str, str]) -> dict:
    a, b = {"advisory": sample[0], "code": sample[1]}, {"advisory": other[0], "code": other[1]}
    alone = _post(base, "/score", a)[1]["score"]
    twice = _post(base, "/score_batch", {"pairs": [a, a]})[1]["scores"]
    mixed = _post(base, "/score_batch", {"pairs": [a, b]})[1]["scores"]
    try:
        with urllib.request.urlopen(base + "/health", timeout=10) as r:
            other = r.status
    except urllib.error.HTTPError as exc:
        other = exc.code
    return {
        "other_path_status": other,
        "malformed_status": _post(base, "/score_batch", {"pairs": "nope"})[0],
        "duplicate_in_batch_difference": abs(twice[0] - twice[1]),
        "alone_vs_mixed_batch_difference": abs(alone - mixed[0]),
    }


def control_passed(c: dict) -> bool:
    return (c["other_path_status"] == 404 and c["malformed_status"] == 400
            and c["duplicate_in_batch_difference"] < 1e-9)


def time_batches(base: str, pairs: list[tuple[str, str]], batch: int) -> dict:
    start = time.perf_counter()
    for i in range(0, len(pairs), batch):
        chunk = [{"advisory": a, "code": c} for a, c in pairs[i:i + batch]]
        status, body = _post(base, "/score_batch", {"pairs": chunk})
        if status != 200 or len(body["scores"]) != len(chunk):
            raise RuntimeError(f"worker answered {status} for a batch of {len(chunk)}")
    total = time.perf_counter() - start
    return {"batch": batch, "pairs": len(pairs), "seconds": total,
            "ms_per_pair": 1000 * total / len(pairs)}


def sample_pairs(n: int) -> tuple[list[tuple[str, str]], dict]:
    """CWE-framed advisory and function pairs from PrimeVul's paired test split, cycled to n."""
    from anvil_eval.experiments import permutation as perm

    pairs, catalogue, info = perm.corpus()
    texts, _ = perm.advisories(pairs, catalogue)
    by_key = {p.key: p for p in pairs}
    base = [(t, by_key[k].vulnerable.func) for k, t in texts["cwe"].items()]
    base += [(t, by_key[k].patched.func) for k, t in texts["cwe"].items()]
    return [base[i % len(base)] for i in range(n)], {"corpus": info, "distinct_pairs": len(base)}


def measure(n: int, port: int = 0) -> Path:
    port = port or 18000 + os.getpid() % 1000
    pairs, provenance = sample_pairs(n)
    log = (RUNS_DIR / "worker.log")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CUDA_VISIBLE_DEVICES="", OMP_NUM_THREADS=str(THREADS))
    proc = subprocess.Popen([str(CONVERT_PY), "-m", "anvil_eval.encoder", "serve", "--port",
                             str(port)], env=env, cwd=EVAL_ROOT / "src",
                            stdout=log.open("w"), stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(240):
            try:
                _post(base, "/score", {"advisory": "warm", "code": "up"})
                break
            except OSError:
                time.sleep(0.5)
        longest = max(pairs, key=lambda p: len(p[1]))
        ctl = control(base, pairs[0], longest)
        timings = [time_batches(base, pairs, b) for b in BATCHES]
    finally:
        proc.terminate()
        proc.wait(30)
    out = RUNS_DIR / "timings.json"
    out.write_text(json.dumps({"control": ctl, "timings": timings, "provenance": provenance,
                               "threads": THREADS, "max_tokens": MAX_TOKENS}, indent=1) + "\n")
    return out


def report() -> Path:
    from anvil_eval import results  # jsonschema and yaml live in this venv only
    from anvil_eval.experiments import prefill

    run = json.loads((RUNS_DIR / "timings.json").read_text())
    pre = json.loads(results.result_path(prefill.ID).read_text())
    tps = pre["result"]["headline"]["tokens_per_s"]
    model_s_per_candidate = prefill.HEADLINE_PROMPT / tps
    cps_path = results.result_path("candidates-per-scan")
    candidates = json.loads(cps_path.read_text())["value"] if cps_path.is_file() else None
    best = min(run["timings"], key=lambda t: t["ms_per_pair"])
    fraction = (best["ms_per_pair"] / 1000) / model_s_per_candidate
    onnx = json.loads((onnx_dir() / "MANIFEST.json").read_text())
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": round(fraction, 4),
        "unit": "encoder round trip as a fraction of model-tier time per candidate (Tier S proxy)",
        "command": "python -m anvil_eval.encoder report",
        "git": results.git_state(),
        "pins": {"encoder": onnx, "threads": run["threads"], "max_tokens": run["max_tokens"],
                 "pairs": run["provenance"], "prefill_artifact": f"eval/results/{prefill.ID}.json"},
        "result": {
            "timings": run["timings"],
            "best": best,
            "model_tier_seconds_per_candidate": model_s_per_candidate,
            "prefill_tokens_per_s_tier_s": tps,
            "candidates_per_full_scan": candidates,
            "encoder_seconds_per_full_scan": (best["ms_per_pair"] / 1000 * candidates
                                              if candidates is not None else None),
            "model_tier_seconds_per_full_scan": (model_s_per_candidate * candidates
                                                 if candidates is not None else None),
            "bar": BAR,
            "within_bar": fraction <= BAR,
            "batch_composition_effect": {
                "alone_vs_beside_the_longest_function": run["control"][
                    "alone_vs_mixed_batch_difference"],
                "note": "dynamic INT8 sets activation scales per batch, so batch-mates move scores",
            },
        },
        "negative_control": {
            "description": "the worker refuses other paths and malformed bodies, and scores one "
                           "pair sent twice in a batch the same twice",
            "expected": "404, 400, and a duplicate difference under 1e-9",
            "observed": run["control"],
            "passed": control_passed(run["control"]),
        },
    }
    return results.write_artifact(doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.encoder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("export")
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    m = sub.add_parser("measure")
    m.add_argument("--pairs", type=int, default=DEFAULT_PAIRS)
    sub.add_parser("report")
    a = ap.parse_args(argv)
    if a.cmd == "export":
        print(json.dumps(export(), indent=1))
    elif a.cmd == "serve":
        serve(a.port)
    elif a.cmd == "measure":
        print(measure(a.pairs))
    else:
        print(report())
    return 0


if __name__ == "__main__":
    sys.exit(main())

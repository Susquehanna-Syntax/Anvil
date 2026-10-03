"""The prefill sweep (register row prefill-sweep, plan node costs).

``llama-bench`` from the pinned llama.cpp build measures prompt processing for each adjudicator
candidate at realistic candidate-prompt lengths, on the RTX 4070, on the RTX 4060 and on the CPU
alone, where four threads stand in for Tier S (8 GB, 4 cores, no GPU). Every number is recorded
with its batch size, micro-batch size, threads and device, because each of those moves it.

The headline is prefill at a 2,000-token prompt for the primary candidate on the Tier S proxy;
generation speed is recorded beside it and is not the headline.

Negative control: the same CPU measurement with one thread must be clearly slower than with four
(ratio under 0.75). If a GPU leaked into a "CPU" arm, or the thread setting were ignored, the two
would match and the artifact would not validate.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from anvil_eval import RESULTS_DIR, models, results
from anvil_eval.experiments import permutation as perm

ID = "prefill-sweep"
RUNS_DIR = RESULTS_DIR / "runs" / ID
PROMPTS = (512, 1000, 2000, 4000)
HEADLINE_PROMPT = 2000
GEN = 128
REPS = 5
BAR = 600.0  # tokens/s, the register's pass threshold for the ~2B candidate on Tier S
CONTROL_PROMPT = 512
CONTROL_RATIO = 0.75

ARMS = {
    "rtx4070": {"device": "CUDA0", "ngl": 999, "threads": None, "label": "RTX 4070 12 GB"},
    "rtx4060": {"device": "CUDA1", "ngl": 999, "threads": None, "label": "RTX 4060 8 GB"},
    "cpu12": {"device": "none", "ngl": 0, "threads": 12, "label": "CPU, 12 threads"},
    "tier-s": {"device": "none", "ngl": 0, "threads": 4, "label": "CPU, 4 threads (Tier S proxy)"},
    "cpu1": {"device": "none", "ngl": 0, "threads": 1, "label": "CPU, 1 thread (control)"},
}
GPU_ARMS = ("rtx4070", "rtx4060")


def command(gguf: Path, arm: dict, prompts: tuple[int, ...], gen: int, reps: int) -> list[str]:
    exe = models.LLAMA_CPP_DIR / f"llama-{models.LLAMA_CPP_BUILD}" / "llama-bench"
    cmd = [str(exe), "-m", str(gguf), "-p", ",".join(map(str, prompts)), "-n", str(gen),
           "-ngl", str(arm["ngl"]), "-dev", arm["device"], "-r", str(reps), "-o", "json"]
    if arm["threads"]:
        cmd += ["-t", str(arm["threads"])]
    return cmd


def env(arm: dict) -> dict[str, str]:
    lib = models.LLAMA_CPP_DIR / f"llama-{models.LLAMA_CPP_BUILD}"
    e = dict(os.environ, LD_LIBRARY_PATH=str(lib))
    if arm["device"] == "none":
        e["CUDA_VISIBLE_DEVICES"] = ""  # a CPU arm cannot reach a GPU
    return e


def parse(raw: str) -> list[dict]:
    rows = json.loads(raw)
    if not isinstance(rows, list) or not rows:
        raise ValueError("llama-bench produced no measurements")
    keep = ("n_prompt", "n_gen", "avg_ts", "stddev_ts", "samples_ts", "n_batch", "n_ubatch",
            "n_threads", "n_gpu_layers", "devices", "flash_attn", "model_type", "build_number")
    out = []
    for r in rows:
        if r.get("avg_ts", 0) <= 0:
            raise ValueError(f"llama-bench reported no throughput: {r}")
        out.append({k: r.get(k) for k in keep})
    return out


def run(candidate: str, arm_names: list[str]) -> None:
    c = models.get(candidate)
    models.verify_licence(c)
    gguf = c.gguf(perm.QUANT)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    for name in arm_names:
        arm = ARMS[name]
        prompts = (CONTROL_PROMPT,) if name == "cpu1" else PROMPTS
        gen = 0 if name == "cpu1" else GEN
        proc = subprocess.run(command(gguf, arm, prompts, gen, REPS), env=env(arm),
                              capture_output=True, text=True, check=True)
        rows = parse(proc.stdout)
        if int(rows[0]["build_number"]) != int(models.LLAMA_CPP_BUILD.lstrip("b")):
            raise SystemExit(f"llama-bench is build {rows[0]['build_number']}")
        (RUNS_DIR / f"{candidate}__{name}.json").write_text(json.dumps(rows, indent=1) + "\n")
        print(f"{candidate} {arm['label']}: " + ", ".join(
            f"pp{r['n_prompt']} {r['avg_ts']:.0f} t/s" if r["n_prompt"] else
            f"tg{r['n_gen']} {r['avg_ts']:.1f} t/s" for r in rows))


def _prefill(rows: list[dict], n_prompt: int) -> float:
    for r in rows:
        if r["n_prompt"] == n_prompt and r["n_gen"] == 0:
            return float(r["avg_ts"])
    raise KeyError(n_prompt)


def summarise(runs: dict[str, dict[str, list[dict]]]) -> dict:
    """``runs[candidate][arm]`` is the parsed llama-bench output for that arm."""
    table = {}
    for cand, arms in runs.items():
        table[cand] = {}
        for arm, rows in arms.items():
            table[cand][arm] = {
                "label": ARMS[arm]["label"],
                "prefill_tokens_per_s": {str(r["n_prompt"]): r["avg_ts"] for r in rows
                                         if r["n_prompt"] and r["n_gen"] == 0},
                "generation_tokens_per_s": next((r["avg_ts"] for r in rows if r["n_gen"]), None),
                "settings": {k: rows[0][k] for k in ("n_batch", "n_ubatch", "n_threads",
                                                       "n_gpu_layers", "devices", "flash_attn")},
                "repetitions": REPS,
            }
    return table


def report() -> Path:
    runs: dict[str, dict] = {}
    for f in sorted(RUNS_DIR.glob("*.json")):
        cand, arm = f.stem.split("__")
        runs.setdefault(cand, {})[arm] = json.loads(f.read_text())
    primary = runs.get(perm.PRIMARY, {})
    missing = [a for a in ARMS if a not in primary]
    if missing:
        raise SystemExit(f"{perm.PRIMARY}: arms not yet measured: {missing}")
    headline = _prefill(primary["tier-s"], HEADLINE_PROMPT)
    one = _prefill(primary["cpu1"], CONTROL_PROMPT)
    four = _prefill(primary["tier-s"], CONTROL_PROMPT)
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": round(headline, 1),
        "unit": f"tokens/s prefill at a {HEADLINE_PROMPT}-token prompt, Qwen3.5-2B {perm.QUANT}, "
                "CPU with 4 threads (Tier S proxy); every arm in the artifact",
        "command": "python -m anvil_eval.experiments.prefill report",
        "git": results.git_state(),
        "pins": {"llama_cpp": {"build": models.LLAMA_CPP_BUILD,
                               "commit": models.LLAMA_CPP_COMMIT},
                 "quant": perm.QUANT, "repetitions": REPS, "prompts": list(PROMPTS),
                 "machine": "Ryzen 5 9600X (12 threads), 30 GB RAM, RTX 4070 12 GB, RTX 4060 8 GB"},
        "result": {
            "table": summarise(runs),
            "headline": {"candidate": perm.PRIMARY, "arm": "tier-s", "prompt": HEADLINE_PROMPT,
                         "tokens_per_s": headline, "bar": BAR,
                         "meets_bar": headline >= BAR},
            "note": "The Tier S arm is four threads of this machine's CPU, not a Tier S host: "
                    "it is recorded as a proxy, and the bar is the register's proposal.",
        },
        "negative_control": {
            "description": f"CPU prefill at {CONTROL_PROMPT} tokens with 1 thread against 4",
            "expected": f"1-thread throughput under {CONTROL_RATIO} of 4-thread",
            "observed": {"one_thread": one, "four_threads": four, "ratio": one / four},
            "passed": one / four < CONTROL_RATIO,
        },
    }
    return results.write_artifact(doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.experiments.prefill")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--model", required=True, choices=[perm.PRIMARY, perm.SECOND])
    r.add_argument("--arms", nargs="+", required=True, choices=list(ARMS))
    sub.add_parser("report")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        run(a.model, a.arms)
    else:
        print(report())
    return 0


if __name__ == "__main__":
    sys.exit(main())

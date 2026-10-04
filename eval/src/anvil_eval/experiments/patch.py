"""Patch quality (register row patch-quality, plan node patchquality).

The coder (Qwen3-Coder-30B-A3B, Q4_K_M, served by llama-server across both GPUs with the experts
that do not fit kept in system RAM) runs the patch loop. This module drives CWE-Bench-Java, which
has no exploit oracle, so its verified-fix rate is reported as not measurable. The owner allowed a
reproducible-vulnerability corpus for local-only use on 2026-10-03; its adapter, which gives the
loop a real oracle (the corpus replays a fuzzer's crashing input), is built with the run after
Phase 9, and the register's bars apply to that rate.

Negative control, inside every report: the synthetic C case with a reproducer, run with two
canned patches and no model. The real fix must come out ``verified_fixed`` and the cosmetic one
``exploit_still_triggers``; if the oracle path cannot tell them apart in this environment, the
artifact does not validate.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from anvil_eval import EVAL_ROOT, RESULTS_DIR, models, patchloop, results
from anvil_eval.data import cwebenchjava

ID = "patch-quality"
CODER = "qwen3-coder-30b-a3b"
QUANT = "Q4_K_M"
RUNS_DIR = RESULTS_DIR / "runs" / ID
SYNTHETIC = EVAL_ROOT / "tests" / "fixtures" / "patch" / "overflow"
N_PREDICT = 2048


def synthetic_case(tmp: Path) -> patchloop.Case:
    root = tmp / "overflow"
    shutil.copytree(SYNTHETIC, root)
    for cmd in (["init", "-q"], ["add", "."], ["-c", "user.email=eval@anvil.invalid", "-c",
                                               "user.name=anvil-eval", "commit", "-qm", "case"]):
        subprocess.run(["git", "-C", str(root), *cmd], check=True)
    return patchloop.Case("synthetic-overflow", root, "greet.c",
                          "CWE-121 stack-based buffer overflow in greet()",
                          ["cc", "-fsanitize=address", "-g", "-o", "greet", "greet.c"],
                          ["sh", "test.sh"], ["sh", "oracle.sh"], timeout=120)


def _edit(search: str, replace: str) -> str:
    return f"<<<<<<< SEARCH\n{search}\n=======\n{replace}\n>>>>>>> REPLACE\n"


def control() -> dict:
    real = _edit("    strcpy(buf, name);", '    snprintf(buf, sizeof buf, "%s", name);')
    cosmetic = _edit('    printf("hello %s\\n", buf);', '    printf("hello %s\\n", buf);\n'
                     "    fflush(stdout);")
    with tempfile.TemporaryDirectory() as tmp:
        case = synthetic_case(Path(tmp))
        a = patchloop.attempt(case, lambda m: real).outcome
        b = patchloop.attempt(case, lambda m: cosmetic).outcome
    return {"real_fix": a, "cosmetic_patch": b,
            "passed": a == "verified_fixed" and b == "exploit_still_triggers"}


def generator(client) -> Callable[[list[dict]], str]:
    def generate(messages: list[dict]) -> str:
        prompt = client.apply_template(messages)
        out = client._call("/completion", {"prompt": prompt, "n_predict": N_PREDICT,
                                           "temperature": 0, "top_k": 1, "cache_prompt": True})
        return out["content"]

    return generate


def run(limit: int | None, jdk_homes: dict[str, str]) -> Path:
    from anvil_eval.llm import LlamaServer

    c = models.get(CODER)
    models.verify_licence(c)
    projects = cwebenchjava.projects()[:limit]
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    out = RUNS_DIR / "outcomes.jsonl"
    done = ({json.loads(line)["case"] for line in out.read_text().splitlines()}
            if out.is_file() else set())
    srv = LlamaServer(c.gguf(QUANT), "CUDA0,CUDA1", ctx=32768,
                      log=RUNS_DIR / "server.log", extra=["--n-cpu-moe", "24"])
    with srv as client, out.open("a") as fh:
        gen = generator(client)
        for p in projects:
            if p.slug in done:
                continue
            build, test = cwebenchjava.commands(p)
            root = cwebenchjava.checkout(p, cwebenchjava.ROOT.parent / "cwe-bench-java-cases" /
                                         p.slug)
            jdk = jdk_homes.get(p.jdk)
            if jdk is None:
                raise SystemExit(f"no JDK home given for {p.jdk} (case {p.slug})")
            env_wrap = ["env", f"JAVA_HOME={jdk}", f"PATH={jdk}/bin:{os.environ['PATH']}"]
            case = patchloop.Case(p.slug, root, p.fixed_file, cwebenchjava.finding(p),
                                  env_wrap + build, env_wrap + test, None, timeout=1800)
            fh.write(json.dumps(patchloop.attempt(case, gen).as_dict()) + "\n")
            fh.flush()
    return out


def report() -> Path:
    rows = [json.loads(line) for line in (RUNS_DIR / "outcomes.jsonl").read_text().splitlines()]
    outcomes = [patchloop.Outcome(**r) for r in rows]
    summary = patchloop.summarise(outcomes, oracle_cases=0)
    ctl = control()
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": round(summary["build_pass_rate"], 4),
        "unit": "share of CWE-Bench-Java cases whose patched project still builds; the "
                "verified-fix rate is not measurable on this corpus (no oracle)",
        "command": "python -m anvil_eval.experiments.patch report",
        "git": results.git_state(),
        "pins": {"coder": {"repo": models.get(CODER).repo,
                           "revision": models.get(CODER).revision, "quant": QUANT},
                 "corpus": {"repo": cwebenchjava.REPO, "commit": cwebenchjava.COMMIT},
                 "llama_cpp": models.LLAMA_CPP_BUILD},
        "result": {**summary, "bars": "proposed: verified >= 5%, fails < 2% (need owner "
                                      "sign-off; apply to a verified-fix rate only)"},
        "negative_control": {
            "description": "the synthetic C case with a real and a cosmetic canned patch",
            "expected": "verified_fixed and exploit_still_triggers",
            "observed": {k: v for k, v in ctl.items() if k != "passed"},
            "passed": ctl["passed"],
        },
    }
    return results.write_artifact(doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.experiments.patch")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--limit", type=int)
    r.add_argument("--jdk", action="append", default=[], metavar="VERSION=HOME",
                   help="e.g. --jdk 8u202=/opt/jdk8 --jdk 17=/opt/jdk17")
    sub.add_parser("report")
    sub.add_parser("control")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        print(run(a.limit, dict(x.split("=", 1) for x in a.jdk)))
    elif a.cmd == "control":
        print(json.dumps(control(), indent=1))
    else:
        print(report())
    return 0


if __name__ == "__main__":
    sys.exit(main())

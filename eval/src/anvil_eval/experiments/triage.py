"""Triage precision (register row triage-precision, plan node triage).

Before the triage gate's verdicts may decide whether a patch is generated, its precision has to be
measured on Lane B candidates whose truth is known. No labelled sample of Anvil's own candidates
exists, so the sample is NIST's Juliet test suites (C/C++ and Java 1.3), local only: each test
case marks its flawed code in functions named ``bad`` (``CWE..._bad``, ``badSink``) and its
correct code in functions named ``good`` (``goodG2B``, ``CWE..._good``). A Lane B candidate inside
a ``bad`` function is labelled a true positive and one inside a ``good`` function a false
positive; a candidate in any other function (``main``, helpers) is left unlabelled and out of the
sample. That label is a proxy: Juliet's code is synthetic, and a match in a ``bad`` function need
not be the flaw the test case is about. The artifact reports the stricter reading too (the
candidate's CWE matches the test case's).

Measured through the product, never re-implemented: ``sample`` drives ``anvil recall`` over the
extracted test cases (CPU only), and ``run`` drives ``anvil triage``, which builds each prompt with
the triage gate's own input builder, prompt and parser and calls the configured endpoint through
the isolated generation process. ``run`` needs the coder on the GPUs; the owner deferred every GPU
run to after Phase 9 (2026-10-04), so it has not run.

Negative control, inside every report: ``anvil triage`` over a planted tree against a stub
endpoint that answers "plausible" to everything must return one verdict per candidate, every one
of them true_positive; a label-blind gate's precision must then equal the sample's base rate. If
either fails, the artifact does not validate.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import math
import re
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from anvil_eval import RESULTS_DIR, results
from anvil_eval.experiments.candidates import FIXTURES as RECALL_FIXTURES
from anvil_eval.experiments.candidates import Anvil, ToolFailed, ToolMissing, materialise

ID = "triage-precision"
RUNS_DIR = RESULTS_DIR / "runs" / ID
JULIET = Path.home() / ".cache" / "anvil-eval" / "juliet"
#: The extracted test cases live with the archives, outside the repository: Juliet is a corpus,
#: and corpora are never committed.
TREE = JULIET / "tree"
SEED = "20261004"
#: The two suites, pinned by the SHA-256 of the archive NIST serves.
SUITES = {
    "c": ("juliet-c-cpp-v1.3.zip",
          "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb",
          "C/testcases/", (".c", ".cpp")),
    "java": ("juliet-java-v1.3.zip",
             "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60",
             "Java/src/testcases/", (".java",)),
}
#: Test cases drawn per CWE directory, per suite: pre-registered on 2026-10-04.
PER_CWE = {"c": 6, "java": 4}


def _rank(name: str) -> str:
    return hashlib.sha256((SEED + "\0" + name).encode()).hexdigest()


def select(names: list[str], prefix: str, suffixes: tuple[str, ...], per_cwe: int) -> list[str]:
    """Up to ``per_cwe`` test-case files from each CWE directory, chosen by a seeded hash."""
    by_cwe: dict[str, list[str]] = {}
    for n in names:
        if not n.startswith(prefix) or not n.endswith(suffixes):
            continue
        rest = n[len(prefix):].split("/")
        if len(rest) < 2 or not rest[0].startswith("CWE"):
            continue
        if not re.match(r"CWE\d+_.*_\d+[a-z]?\.(c|cpp|java)$", rest[-1]):
            continue  # support files, servlets and harnesses are not test cases
        by_cwe.setdefault(rest[0], []).append(n)
    out: list[str] = []
    for cwe in sorted(by_cwe):
        out += sorted(by_cwe[cwe], key=_rank)[:per_cwe]
    return out


_C_FUNC = re.compile(r"^[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*$")
_JAVA_FUNC = re.compile(r"^\s+(?:(?:public|private|protected|static|final|synchronized)\s+)+"
                        r"[\w<>\[\],\s]+?\s(\w+)\s*\(")


def functions(text: str, lang: str) -> list[tuple[int, str]]:
    """(first line, name) of each function definition, in order. Juliet's layout is regular: a C
    definition starts at column 0 and is not a declaration; a Java method is indented."""
    pattern = _C_FUNC if lang == "c" else _JAVA_FUNC
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = pattern.match(line)
        if m and m.group(1) not in ("if", "while", "for", "switch", "return", "sizeof"):
            out.append((i, m.group(1)))
    return out


def label_of(name: str) -> str | None:
    """``bad`` for Juliet's flawed functions, ``good`` for its correct ones, else None."""
    if name == "bad" or name.endswith("_bad") or name.startswith("bad"):
        return "bad"
    if name == "good" or name.endswith("_good") or name.startswith("good"):
        return "good"
    return None


def enclosing(funcs: list[tuple[int, str]], line: int) -> str | None:
    name = None
    for start, n in funcs:
        if start > line:
            break
        name = n
    return name


def cwe_of_case(path: str) -> str:
    m = re.match(r"CWE(\d+)_", Path(path).name)
    return f"CWE-{m.group(1)}" if m else ""


def extract(dest: Path) -> dict[str, list[str]]:
    """Unpack the selected test cases into ``dest/<suite>/...``; verify each archive's hash."""
    picked: dict[str, list[str]] = {}
    for suite, (zipname, sha, prefix, suffixes) in SUITES.items():
        path = JULIET / zipname
        if not path.is_file():
            raise SystemExit(f"{path} is missing; fetch it from samate.nist.gov first")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != sha:
            raise SystemExit(f"{path} has SHA-256 {digest}, not the pinned {sha}")
        with zipfile.ZipFile(path) as z:
            names = select(z.namelist(), prefix, suffixes, PER_CWE[suite])
            for n in names:
                out = dest / suite / n[len(prefix):]
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(z.read(n))
        picked[suite] = [n[len(prefix):] for n in names]
    return picked


def labelled(root: Path, candidates: list[dict]) -> list[dict]:
    """Attach Juliet's label to every candidate; drop those in neither kind of function."""
    cache: dict[str, list[tuple[int, str]]] = {}
    out = []
    for c in candidates:
        lang = "java" if c["path"].endswith(".java") else "c"
        if c["path"] not in cache:
            text = (root / c["path"]).read_text(encoding="utf-8", errors="replace")
            cache[c["path"]] = functions(text, lang)
        fn = enclosing(cache[c["path"]], c["startLine"])
        lab = label_of(fn) if fn else None
        if lab is None:
            continue
        out.append({"path": c["path"], "startLine": c["startLine"], "ruleId": c["ruleIdVersioned"],
                    "cwe": c["cwe"], "function": fn, "label": lab,
                    "case_cwe": cwe_of_case(c["path"])})
    return out


def sample() -> Path:
    """Extract the pre-registered test cases, run ``anvil recall`` over them, label the result."""
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    tree = TREE
    if tree.exists():
        subprocess.run(["rm", "-rf", str(tree)], check=True)
    picked = extract(tree)
    with tempfile.TemporaryDirectory() as tmp:
        anvil = Anvil(Path(tmp))
        doc = anvil.recall(tree)
    rows = labelled(tree, doc["candidates"])
    out = RUNS_DIR / "sample.json"
    out.write_text(json.dumps({
        "measured_at": results.today(), "git": results.git_state(),
        "seed": SEED, "per_cwe": PER_CWE,
        "files": {k: len(v) for k, v in picked.items()},
        "candidates": doc["count"], "problems": doc["problems"],
        "labelled": rows,
    }, indent=1) + "\n")
    return out


def run(config: Path, anvil_bin: Path) -> Path:
    """``anvil triage`` over the sample tree with the operator's endpoint configuration."""
    tree = TREE
    out = RUNS_DIR / "verdicts.jsonl"
    with out.open("w") as fh:
        proc = subprocess.run([str(anvil_bin), "triage", "--config", str(config), str(tree)],
                              stdout=fh, stderr=subprocess.PIPE, text=True)
    if proc.returncode not in (0, 3):
        raise ToolFailed(f"anvil triage exited {proc.returncode}: {proc.stderr[-800:]}")
    return out


def wilson(k: int, n: int) -> list[float] | None:
    if n == 0:
        return None
    z = 1.959963984540054
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(max(0.0, mid - half), 4), round(min(1.0, mid + half), 4)]


def score(rows: list[dict], verdicts: dict[tuple[str, int, str], dict],
          strict: bool = False) -> dict:
    """Precision and recall of the gate's "plausible" against Juliet's labels."""
    tp = fp = fn = tn = ic_bad = ic_good = 0
    seconds, tokens = [], []
    for r in rows:
        v = verdicts[(r["path"], r["startLine"], r["ruleId"])]
        truth = r["label"] == "bad" and (not strict or r["cwe"] == r["case_cwe"])
        seconds.append(v.get("seconds", 0.0))
        tokens.append(v.get("promptTokens", 0))
        if v["verdict"] == "insufficient_context":
            ic_bad += truth
            ic_good += not truth
        elif v["verdict"] == "true_positive":
            tp += truth
            fp += not truth
        else:
            fn += truth
            tn += not truth
    n = len(rows)
    base = sum(r["label"] == "bad" and (not strict or r["cwe"] == r["case_cwe"]) for r in rows)
    return {
        "n": n, "base_rate": round(base / n, 4) if n else None,
        "plausible_precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "plausible_precision_ci95": wilson(tp, tp + fp),
        "plausible_recall": round(tp / base, 4) if base else None,
        "false_positive_drop_rate": round(tn / (n - base), 4) if n - base else None,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                      "insufficient_context_on_true": ic_bad,
                      "insufficient_context_on_false": ic_good},
        "cost": {"mean_seconds": round(sum(seconds) / n, 3) if n else None,
                 "mean_prompt_tokens": round(sum(tokens) / n, 1) if n else None},
    }


class _Stub(http.server.BaseHTTPRequestHandler):
    """An OpenAI-compatible endpoint that answers plausible to everything."""

    def do_POST(self):  # noqa: N802 (http.server's naming)
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({"choices": [{"message": {"role": "assistant",
                           "content": '{"verdict": "plausible", "reason": "stub"}'}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def control() -> dict:
    """``anvil triage`` over the planted recall fixture against the always-plausible stub."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            anvil = Anvil(Path(tmp))
            cfg = Path(tmp) / "anvil.yml"
            cfg.write_text(anvil.config.read_text() + "remediation:\n  enabled: true\n  endpoint:\n"
                           f"    url: http://127.0.0.1:{srv.server_address[1]}/v1\n"
                           "    model: stub\n    tier: local\n")
            planted = materialise(RECALL_FIXTURES / "planted", Path(tmp) / "planted")
            found = anvil.recall(planted)["count"]
            proc = subprocess.run([str(anvil.bin), "triage", "--config", str(cfg), str(planted)],
                                  capture_output=True, text=True)
            lines = [json.loads(x) for x in proc.stdout.splitlines() if x.strip()]
    finally:
        srv.shutdown()
    verdicts = sorted({x.get("verdict", x.get("error", "")) for x in lines})
    return {"candidates": found, "verdicts": len(lines), "distinct": verdicts,
            "exit": proc.returncode,
            "passed": found > 0 and len(lines) == found and verdicts == ["true_positive"]}


def report() -> Path:
    sample_doc = json.loads((RUNS_DIR / "sample.json").read_text())
    rows = sample_doc["labelled"]
    verdicts = {}
    for line in (RUNS_DIR / "verdicts.jsonl").read_text().splitlines():
        v = json.loads(line)
        verdicts[(v["path"], v["startLine"], v["ruleId"])] = v
    missing = [r for r in rows if (r["path"], r["startLine"], r["ruleId"]) not in verdicts]
    if missing:
        raise SystemExit(f"{len(missing)} labelled candidates have no verdict; the run does not "
                         "cover the pre-registered sample")
    if any("error" in verdicts[(r["path"], r["startLine"], r["ruleId"])] for r in rows):
        raise SystemExit("some verdicts are model-call errors; the run is not complete")
    ctl = control()
    blind = {k: {"verdict": "true_positive"} for k in verdicts}
    blind_score = score(rows, blind)
    equal = blind_score["plausible_precision"] == blind_score["base_rate"]
    ctl["label_blind_precision_equals_base_rate"] = equal
    ctl["passed"] = ctl["passed"] and ctl["label_blind_precision_equals_base_rate"]
    main_score = score(rows, verdicts)
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": main_score["plausible_precision"],
        "unit": "precision of the triage gate's plausible verdict on Lane B's Juliet candidates "
                "(true positive = a match inside a Juliet bad function)",
        "command": "python -m anvil_eval.experiments.triage report",
        "git": results.git_state(),
        "result": {"function_label": main_score,
                   "function_and_cwe_label": score(rows, verdicts, strict=True),
                   "sample": {k: sample_doc[k]
                              for k in ("seed", "per_cwe", "files", "candidates", "problems")}},
        "negative_control": {
            "description": "anvil triage against an always-plausible stub endpoint on the planted "
                           "recall fixture, and a label-blind gate on this sample",
            "expected": "one true_positive per candidate, and label-blind precision equal to "
                        "the base rate",
            "observed": {k: v for k, v in ctl.items() if k != "passed"},
            "passed": ctl["passed"],
        },
    }
    return results.write_artifact(doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.experiments.triage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sample")
    r = sub.add_parser("run")
    r.add_argument("--config", type=Path, required=True, help="an anvil.yml naming the endpoint")
    r.add_argument("--anvil", type=Path, required=True, help="the anvil binary")
    sub.add_parser("control")
    sub.add_parser("report")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "sample":
            t = time.time()
            print(sample(), f"{time.time() - t:.0f} s")
        elif a.cmd == "run":
            print(run(a.config, a.anvil))
        elif a.cmd == "control":
            print(json.dumps(control(), indent=1))
        else:
            print(report())
    except ToolMissing as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())

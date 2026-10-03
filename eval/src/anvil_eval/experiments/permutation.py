"""The advisory-permutation ablation (register row advisory-permutation, plan node ablation).

``run`` asks one candidate, for every pair in the pre-registered set and in both framings, three
questions: the vulnerable function with its real advisory, the vulnerable function with an
unrelated advisory, and the patched function with its real advisory. The third feeds the
code-metrics baseline's model arm. Each answer is appended to
``eval/results/runs/advisory-permutation/<candidate>.jsonl`` as it arrives, so an interrupted run
resumes where it stopped.

``report`` reads both candidates' runs and writes ``eval/results/advisory-permutation.json``. It
reads the pre-registered bands, but the register's ``decision`` stays the owner's.

The negative control runs inside every run: for the first 50 pairs of each framing the vulnerable
function is asked again with its *own* advisory and the prompt cache off. That is a permutation
that changes nothing, so it must produce no flips; flips there would mean the metric is counting
noise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from anvil_eval import RESULTS_DIR, adjudicator, models, results, stats
from anvil_eval.data import cwe, primevul

ID = "advisory-permutation"
PRIMARY, SECOND = "qwen3.5-2b", "gemma-4-e2b-it"
FRAMINGS = ("cwe", "cve")
DECIDING_FRAMING = "cwe"  # Lane-B-shaped; the register says this number decides
QUANT = "Q4_K_M"
CTX = 8192
CONTROL_PAIRS = 50
CONTROL_TOLERANCE = 1  # flips allowed in the identity control per framing
ERROR_LIMIT = 0.01  # a run with more unreadable answers than this is refused
RUNS_DIR = RESULTS_DIR / "runs" / ID
PASS_ABOVE, FAIL_BELOW = 0.80, 0.50


@dataclass(frozen=True)
class Item:
    pair: str
    framing: str
    role: str  # vuln_real, vuln_perm, fixed_real, vuln_identity
    advisory: str
    code: str
    partner: str | None = None

    @property
    def key(self) -> str:
        h = hashlib.sha256(self.advisory.encode()).hexdigest()[:16]
        return f"{self.pair}|{self.framing}|{self.role}|{h}"


def advisories(pairs: list[primevul.Pair], catalogue: dict) -> tuple[dict, dict]:
    """Each framing's advisory text per pair, and how many pairs each framing left out."""
    texts: dict[str, dict[str, str]] = {f: {} for f in FRAMINGS}
    excluded = {"cwe": {"missing_or_placeholder": 0, "not_in_catalogue": 0}, "cve": {"no_text": 0}}
    for p in pairs:
        if p.cve_desc.strip():
            cve_id = p.vulnerable.cve.strip()
            texts["cve"][p.key] = f"{cve_id}: {p.cve_desc.strip()}" if cve_id else p.cve_desc
        else:
            excluded["cve"]["no_text"] += 1
        label = cwe.normalise(p.cwe) if p.cwe else ""
        if label in cwe.NO_CWE:
            excluded["cwe"]["missing_or_placeholder"] += 1
        elif label not in catalogue:
            excluded["cwe"]["not_in_catalogue"] += 1
        else:
            texts["cwe"][p.key] = catalogue[label].advisory_text()
    return texts, excluded


def draw(texts: dict[str, str], framing: str) -> dict[str, str]:
    """For each pair, an unrelated advisory's owner drawn from the full pool (seeded).

    Uniform over every other pair in the framing whose advisory text differs from this pair's
    own; never restricted to, or away from, the same CWE.
    """
    keys = list(texts)
    rng = np.random.default_rng([stats.SEED, FRAMINGS.index(framing)])
    out = {}
    for k in keys:
        pool = [j for j in keys if j != k and texts[j] != texts[k]]
        if not pool:
            raise ValueError(f"{framing}: no unrelated advisory for {k}")
        out[k] = pool[int(rng.integers(len(pool)))]
    return out


def plan(pairs: list[primevul.Pair], catalogue: dict) -> tuple[list[Item], dict]:
    by_key = {p.key: p for p in pairs}
    texts, excluded = advisories(pairs, catalogue)
    items: list[Item] = []
    for framing in FRAMINGS:
        t = texts[framing]
        partner = draw(t, framing)
        for i, k in enumerate(t):
            p = by_key[k]
            items += [
                Item(k, framing, "vuln_real", t[k], p.vulnerable.func),
                Item(k, framing, "vuln_perm", t[partner[k]], p.vulnerable.func, partner[k]),
                Item(k, framing, "fixed_real", t[k], p.patched.func),
            ]
            if i < CONTROL_PAIRS:
                items.append(Item(k, framing, "vuln_identity", t[k], p.vulnerable.func))
    meta = {
        "pairs_within_length": len(pairs),
        "eligible": {f: len(texts[f]) for f in FRAMINGS},
        "excluded": excluded,
    }
    return items, meta


def load_runs(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    return {r["key"]: r for r in map(json.loads, path.read_text("utf-8").splitlines()) if r}


def corpus() -> tuple[list[primevul.Pair], dict, dict]:
    test = primevul.verified("primevul_test_paired.jsonl")
    all_pairs = primevul.pairs(test)
    kept, dropped = primevul.within_length(all_pairs)
    info = {
        "file": "primevul_test_paired.jsonl",
        "sha256": json.loads((primevul.PRIMEVUL_DIR / "MANIFEST.json").read_text())["files"][
            "primevul_test_paired.jsonl"]["sha256"],
        "pairs": len(all_pairs),
        "dropped_by_length_rule": dropped,
        "max_function_chars": primevul.MAX_FUNC_CHARS,
    }
    return kept, cwe.load(), info


def execute(client, items: Iterable[Item], out: Path, model_sha: str) -> int:
    """Ask every item not already answered in ``out``; return how many were asked."""
    done = load_runs(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    asked = 0
    with out.open("a", encoding="utf-8") as fh:
        for item in items:
            if item.key in done:
                continue
            rec = {"key": item.key, "pair": item.pair, "framing": item.framing,
                   "role": item.role, "partner": item.partner, "model_sha256": model_sha}
            try:
                j = adjudicator.judge(client, item.advisory, item.code,
                                      adjudicator.TEMPLATE_KWARGS,
                                      cache=item.role != "vuln_identity")
                rec.update(j.as_dict())
                rec["evidence"] = list(j.evidence)
            except adjudicator.AdjudicationError as exc:
                rec["error"] = str(exc)
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            asked += 1
    return asked


def run(candidate: str, device: str, limit: int | None, out: Path | None) -> Path:
    from anvil_eval.llm import LlamaServer

    c = models.get(candidate)
    models.verify_licence(c)
    gguf = c.gguf(QUANT)
    model_sha = json.loads((gguf.parent / "MANIFEST.json").read_text())["files"][QUANT]["sha256"]
    pairs, catalogue, _ = corpus()
    if limit is not None:
        pairs = pairs[:limit]
        if out is None or out.resolve().is_relative_to(RESULTS_DIR.resolve()):
            raise SystemExit("--limit runs are trials: pass --out outside eval/results/")
    items, meta = plan(pairs, catalogue)
    out = out or RUNS_DIR / f"{candidate}.jsonl"
    log = out.with_suffix(".server.log")
    with LlamaServer(gguf, device, ctx=CTX, log=log) as client:
        props = client.props()
        if props.get("build_info", "").split("-")[0] != models.LLAMA_CPP_BUILD:
            raise SystemExit(f"llama-server reports {props.get('build_info')!r}")
        n = execute(client, items, out, model_sha)
    print(f"{candidate}: asked {n}; {len(items)} items in the plan; {meta}")
    return out


# ---------------------------------------------------------------------------------------------
# report


def _verdicts(runs: dict[str, dict], items: list[Item]) -> dict[tuple, dict]:
    return {(i.pair, i.framing, i.role): runs.get(i.key) for i in items}


def framing_summary(v: dict[tuple, dict], keys: list[str], framing: str) -> dict:
    """Flip rate with its interval, the insufficient-context rate, and the model-arm metrics."""
    def get(k, role):
        r = v.get((k, framing, role))
        return None if r is None or "error" in r else r

    rows = []  # one per pair whose three answers all read: (den, flip, ins, pc, vscore, fscore)
    for k in keys:
        real, perm, fixed = get(k, "vuln_real"), get(k, "vuln_perm"), get(k, "fixed_real")
        if real is None or perm is None or fixed is None:
            continue  # an unreadable answer takes its pair out of this framing; counted below
        d = real["verdict"] == "exhibits"
        rows.append((
            float(d),
            float(d and perm["verdict"] == "does_not_exhibit"),
            float(d and perm["verdict"] == "insufficient_context"),
            float(d and fixed["verdict"] != "exhibits"),
            real["score"],
            fixed["score"],
        ))
    if not rows:
        raise SystemExit(f"{framing}: no pair has three readable answers")
    den, flip, ins, pc, vs, fs = (np.array(col, dtype=float) for col in zip(*rows, strict=True))
    n = len(rows)
    flip_iv = stats.bootstrap(stats.ratio(flip, den), n)
    ins_iv = stats.bootstrap(stats.ratio(ins, den), n)
    pc_iv = stats.bootstrap(stats.ratio(pc, np.ones(n)), n)
    missing = int(np.isnan(vs).sum() + np.isnan(fs).sum())
    vs, fs = np.nan_to_num(vs, nan=0.0), np.nan_to_num(fs, nan=0.0)
    par_iv = stats.bootstrap(stats.paired_precision_at_recall(vs, fs), n)
    return {
        "pairs": len(keys),
        "pairs_usable": n,
        "real_advisory_exhibits": int(den.sum()),
        "flips": int(flip.sum()),
        "moves_to_insufficient_context": int(ins.sum()),
        "flip_rate": flip_iv.as_dict(),
        "insufficient_context_rate": ins_iv.as_dict(),
        "band": stats.band(flip_iv, FAIL_BELOW, PASS_ABOVE),
        "model_arm": {
            "pairwise_correct": pc_iv.as_dict(),
            "precision_at_recall_0_70": par_iv.as_dict(),
            "scores_missing_counted_as_zero": missing,
        },
    }


def identity_control(v: dict[tuple, dict], keys: list[str], framing: str) -> dict:
    flips = asked = 0
    for k in keys[:CONTROL_PAIRS]:
        real, same = v.get((k, framing, "vuln_real")), v.get((k, framing, "vuln_identity"))
        if real is None or same is None or "error" in real or "error" in same:
            continue
        asked += 1
        flips += real["verdict"] != same["verdict"]
    return {"pairs": asked, "verdict_changes": flips}


def reading(summaries: dict[str, dict]) -> dict:
    """The pre-registered reading of the bands. It is not the decision; the owner records that."""
    primary = summaries[PRIMARY][DECIDING_FRAMING]["band"]
    if primary != "ambiguous":
        return {"primary_band": primary, "proceeds_with": PRIMARY if primary == "pass" else None,
                "pre_registered_outcome": primary.upper()}
    second = summaries[SECOND][DECIDING_FRAMING]["band"]
    return {
        "primary_band": "ambiguous",
        "second_band": second,
        "proceeds_with": SECOND if second == "pass" else None,
        "pre_registered_outcome": (
            "PASS" if second == "pass" else "FAIL (ambiguous, treated as a fail for v1)"
        ),
    }


def summarise(runs_by_candidate: dict[str, dict], items: list[Item], meta: dict) -> dict:
    keys = {f: list(dict.fromkeys(i.pair for i in items if i.framing == f)) for f in FRAMINGS}
    out: dict = {"summaries": {}, "controls": {}, "errors": {}}
    for cand, runs in runs_by_candidate.items():
        missing = [i.key for i in items if i.key not in runs]
        if missing:
            raise SystemExit(f"{cand}: {len(missing)} of {len(items)} items unanswered; resume run")
        errors = sum(1 for i in items if "error" in runs[i.key])
        if errors > ERROR_LIMIT * len(items):
            raise SystemExit(f"{cand}: {errors} unreadable answers exceed {ERROR_LIMIT:.0%}")
        v = _verdicts(runs, items)
        out["summaries"][cand] = {f: framing_summary(v, keys[f], f) for f in FRAMINGS}
        out["controls"][cand] = {f: identity_control(v, keys[f], f) for f in FRAMINGS}
        out["errors"][cand] = errors
    out["reading"] = reading(out["summaries"])
    out["meta"] = meta
    return out


def pins(info: dict) -> dict:
    prompt = json.dumps([adjudicator.SYSTEM, adjudicator.USER, adjudicator.SCHEMA])
    p = {
        "corpus": info,
        "cwe_catalogue": {"file": cwe.CWE_ZIP.name, "sha256": cwe.CWE_SHA256},
        "llama_cpp": {"build": models.LLAMA_CPP_BUILD, "commit": models.LLAMA_CPP_COMMIT},
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "template_kwargs": adjudicator.TEMPLATE_KWARGS,
        "decoding": {"temperature": 0, "top_k": 1, "n_predict": adjudicator.N_PREDICT,
                     "n_probs": adjudicator.N_PROBS, "ctx": CTX, "quant": QUANT},
        "bootstrap": {"resamples": stats.RESAMPLES, "seed": stats.SEED,
                      "interval": "95% percentile"},
        "models": {},
    }
    for name in (PRIMARY, SECOND):
        c = models.get(name)
        g = json.loads((c.gguf(QUANT).parent / "MANIFEST.json").read_text())
        p["models"][name] = {"repo": c.repo, "revision": c.revision,
                             "gguf_sha256": g["files"][QUANT]["sha256"]}
    return p


def report() -> Path:
    pairs, catalogue, info = corpus()
    items, meta = plan(pairs, catalogue)
    runs = {c: load_runs(RUNS_DIR / f"{c}.jsonl") for c in (PRIMARY, SECOND)}
    s = summarise(runs, items, meta)
    control_ok = all(
        ctl["verdict_changes"] <= CONTROL_TOLERANCE
        for per in s["controls"].values() for ctl in per.values()
    )
    decide = s["summaries"][PRIMARY][DECIDING_FRAMING]["flip_rate"]
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": round(decide["estimate"], 4),
        "unit": "flip rate, CWE-text framing, Qwen3.5-2B (interval, both framings and both "
                "candidates in the artifact)",
        "command": "python -m anvil_eval.experiments.permutation report",
        "git": results.git_state(),
        "pins": pins(info),
        "result": s,
        "negative_control": {
            "description": (f"identity permutation: the first {CONTROL_PAIRS} pairs of each "
                            "framing asked again with their own advisory, prompt cache off"),
            "expected": f"at most {CONTROL_TOLERANCE} verdict change per framing per candidate",
            "observed": s["controls"],
            "passed": control_ok,
        },
    }
    return results.write_artifact(doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.experiments.permutation")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--model", required=True, choices=[PRIMARY, SECOND])
    r.add_argument("--device", required=True, choices=["CUDA0", "CUDA1", "cpu"])
    r.add_argument("--limit", type=int, help="trial run on the first N pairs (needs --out)")
    r.add_argument("--out", type=Path)
    sub.add_parser("report")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        run(a.model, a.device, a.limit, a.out)
    else:
        print(report())
    return 0


if __name__ == "__main__":
    sys.exit(main())

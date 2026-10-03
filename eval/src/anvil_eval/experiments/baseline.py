"""The code-metrics baseline (register row code-metrics-baseline, plan node baseline).

A logistic regression over classic code metrics against the adjudicator, on the same pairs, with
the same resample indices. The regression trains on PrimeVul's unpaired training split as it is
(no rebalancing), takes its pairwise threshold from the paired validation split, and is scored on
the paired test pairs the model arm answered in the CWE-text framing. The model arm is read from
the advisory-permutation run, so this module needs no GPU.

The comparison rule is pre-registered in the register and is an engineering judgement, not a
citation: the model is clearly better on a metric when the regression's interval lies wholly below
the model's.

Negative control: a pair-blind scorer, which gives both versions of a pair the regression's score
for the vulnerable one, cannot tell the versions apart, so its P-C must be exactly 0 and its
precision at recall 0.70 exactly 0.5; and the model compared with itself on the same resamples
must read as overlap on both metrics. A shuffled-label regression is not a valid control here:
fixes change the metrics systematically (they tend to add lines), so even random weights rank one
version of each pair consistently and precision moves away from 0.5 (seen on 2026-10-03 on the
synthetic corpus in tests/test_baseline.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from anvil_eval import logreg, metrics, results, stats
from anvil_eval.data import primevul
from anvil_eval.experiments import permutation as perm

ID = "code-metrics-baseline"
FRAMING = "cwe"
C = 1.0


def features(path: Path, rows: list[primevul.Function]) -> np.ndarray:
    """Metrics for every row, cached beside the corpus under the file's hash."""
    sha = json.loads((primevul.PRIMEVUL_DIR / "MANIFEST.json").read_text())["files"][path.name][
        "sha256"]
    cache = primevul.PRIMEVUL_DIR / f".features-{sha[:16]}.npy"
    if cache.is_file():
        x = np.load(cache)
        if x.shape == (len(rows), len(metrics.FEATURES)):
            return x
    x = np.array([metrics.vector(r.func) for r in rows], dtype=float)
    np.save(cache, x)
    return x


def pc_threshold(vuln: np.ndarray, fixed: np.ndarray) -> tuple[float, float]:
    """The threshold that maximises P-C (the highest such threshold), and that P-C."""
    best_t, best = np.inf, -1.0
    for t in np.unique(np.concatenate([vuln, fixed]))[::-1]:
        pc = float(np.mean((vuln >= t) & (fixed < t)))
        if pc > best:
            best_t, best = float(t), pc
    return best_t, best


def model_arm(candidate: str, pairs: list[primevul.Pair], catalogue: dict) -> tuple[list, dict]:
    """The model's verdicts and scores on the CWE-framed pairs, keyed by pair."""
    items, _ = perm.plan(pairs, catalogue)
    runs = perm.load_runs(perm.RUNS_DIR / f"{candidate}.jsonl")
    v = perm._verdicts(runs, items)
    keys = list(dict.fromkeys(i.pair for i in items if i.framing == FRAMING))
    out = {}
    for k in keys:
        real, fixed = v.get((k, FRAMING, "vuln_real")), v.get((k, FRAMING, "fixed_real"))
        if real is None or fixed is None:
            raise SystemExit(f"{candidate}: {k} unanswered; finish the permutation run first")
        if "error" in real or "error" in fixed:
            continue
        out[k] = (real["verdict"] == "exhibits", fixed["verdict"] == "exhibits",
                  real["score"], fixed["score"])
    return keys, out


def arm_intervals(vuln_pred, fixed_pred, vuln_score, fixed_score, idx) -> dict:
    n = len(vuln_pred)
    pc = stats.pairwise_correct(vuln_pred, fixed_pred)
    vs = np.nan_to_num(np.asarray(vuln_score, float), nan=0.0)
    fs = np.nan_to_num(np.asarray(fixed_score, float), nan=0.0)
    return {
        "pairwise_correct": stats.bootstrap(stats.ratio(pc, np.ones(n)), n, idx),
        "precision_at_recall_0_70": stats.bootstrap(stats.paired_precision_at_recall(vs, fs), n,
                                                    idx),
    }


def outcome(comparisons: dict[str, str]) -> str:
    better = sum(c == "model_clearly_better" for c in comparisons.values())
    return {2: "PASS", 0: "FAIL"}.get(better, "AMBIGUOUS")


def report() -> Path:
    test_pairs, catalogue, info = perm.corpus()
    ablation = json.loads(results.result_path(perm.ID).read_text())
    candidate = ablation["result"]["reading"].get("proceeds_with") or perm.PRIMARY

    keys, arm = model_arm(candidate, test_pairs, catalogue)
    by_key = {p.key: p for p in test_pairs}
    used = [k for k in keys if k in arm]
    n = len(used)

    train_path = primevul.verified("primevul_train.jsonl")
    train_rows = primevul.read_rows(train_path)
    x_train = features(train_path, train_rows)
    y_train = np.array([r.target for r in train_rows], dtype=float)
    lr = logreg.fit(x_train, y_train, c=C)

    valid = primevul.pairs(primevul.verified("primevul_valid_paired.jsonl"))
    vv = lr.proba(np.array([metrics.vector(p.vulnerable.func) for p in valid]))
    vf = lr.proba(np.array([metrics.vector(p.patched.func) for p in valid]))
    threshold, valid_pc = pc_threshold(vv, vf)

    tv = lr.proba(np.array([metrics.vector(by_key[k].vulnerable.func) for k in used]))
    tf = lr.proba(np.array([metrics.vector(by_key[k].patched.func) for k in used]))

    idx = stats.resample_indices(n)  # one set of resamples for both arms
    reg = arm_intervals(tv >= threshold, tf >= threshold, tv, tf, idx)
    mod = arm_intervals([arm[k][0] for k in used], [arm[k][1] for k in used],
                        [arm[k][2] for k in used], [arm[k][3] for k in used], idx)
    comparisons = {m: stats.compare(reg[m], mod[m]) for m in reg}

    blind = arm_intervals(tv >= threshold, tv >= threshold, tv, tv, idx)
    self_cmp = {m: stats.compare(mod[m], mod[m]) for m in mod}
    control_ok = (
        blind["pairwise_correct"].estimate == 0.0
        and blind["precision_at_recall_0_70"].estimate == 0.5
        and set(self_cmp.values()) == {"overlap"}
    )

    better = sum(c == "model_clearly_better" for c in comparisons.values())
    doc = {
        "id": ID,
        "measured_at": results.today(),
        "value": better,
        "unit": "metrics (of two) on which the model's 95% interval lies wholly above the "
                "regression's: 2 is PASS, 0 is FAIL, 1 is AMBIGUOUS (pre-registered)",
        "command": "python -m anvil_eval.experiments.baseline report",
        "git": results.git_state(),
        "pins": {
            "corpus": info,
            "train": {"file": train_path.name, "rows": len(train_rows),
                      "vulnerable": int(y_train.sum())},
            "valid_pairs": len(valid),
            "features": list(metrics.FEATURES),
            "regression": {"penalty": "l2", "C": C, "standardised": True,
                           "class_weight": None, "iterations": lr.iterations},
            "model_arm": {"candidate": candidate, "framing": FRAMING,
                          "from": f"eval/results/{perm.ID}.json and its runs"},
            "bootstrap": {"resamples": stats.RESAMPLES, "seed": stats.SEED,
                          "paired": "the same resample indices for both arms"},
        },
        "result": {
            "pairs": n,
            "pairs_left_out_for_unreadable_answers": len(keys) - n,
            "regression": {k: v.as_dict() for k, v in reg.items()},
            "regression_pc_threshold": threshold,
            "regression_valid_pc": valid_pc,
            "model": {k: v.as_dict() for k, v in mod.items()},
            "comparisons": comparisons,
            "pre_registered_outcome": outcome(comparisons),
            "note": "The equivalence rule is an engineering judgement, not a citation.",
        },
        "negative_control": {
            "description": ("a pair-blind scorer (both versions of a pair get the regression's "
                            "score for the vulnerable one), and the model compared with itself"),
            "expected": "P-C exactly 0, precision at recall 0.70 exactly 0.5, self-comparison "
                        "overlap on both metrics",
            "observed": {"pair_blind": {k: v.as_dict() for k, v in blind.items()},
                         "self_comparison": self_cmp},
            "passed": control_ok,
        },
    }
    return results.write_artifact(doc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anvil_eval.experiments.baseline")
    ap.add_argument("cmd", choices=["report"])
    ap.parse_args(argv)
    print(report())
    return 0


if __name__ == "__main__":
    sys.exit(main())


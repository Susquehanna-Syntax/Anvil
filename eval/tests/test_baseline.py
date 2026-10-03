"""The code-metrics baseline end to end on a synthetic PrimeVul, with a fake model arm."""

from __future__ import annotations

import json

import numpy as np
import pytest

from anvil_eval import results
from anvil_eval.data import primevul
from anvil_eval.experiments import baseline
from anvil_eval.experiments import permutation as perm
from test_permutation import CATALOGUE, CWES, FakeModel


def _func(name: str, calls: int) -> str:
    body = "\n".join(f"    step{j}(a);" for j in range(calls))
    return f"int {name}(int a) {{\n{body}\n    return a;\n}}"


def _row(i, target, func, commit=None):
    cwe = CWES[i % len(CWES)]
    return {"idx": i, "project": "p", "commit_id": commit or f"c{i}", "target": target,
            "func": func, "cwe": [cwe], "cve": f"CVE-2021-{i}", "cve_desc": f"text {i}"}


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    rng = np.random.default_rng(0)
    d = tmp_path / "primevul"
    d.mkdir()
    train = []
    for i in range(3000):  # 5% vulnerable; vulnerable functions are a little longer
        t = int(rng.random() < 0.05)
        train.append(_row(i, t, _func(f"t{i}", int(rng.poisson(8 if t else 5)))))
    (d / "primevul_train.jsonl").write_text("".join(json.dumps(r) + "\n" for r in train))
    for split, n in (("valid", 80), ("test", 150)):
        rows = []
        for i in range(n):
            calls = int(rng.integers(3, 12))
            # The patch adds one guard call, as fixes often do: metrics barely move.
            rows += [_row(i, 1, _func(f"f{i}", calls).replace("step0", f"bad{i}"), f"{split}{i}"),
                     _row(i, 0, _func(f"f{i}", calls + 1), f"{split}{i}")]
        (d / f"primevul_{split}_paired.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(primevul, "PRIMEVUL_DIR", d)
    primevul.write_manifest(d)
    monkeypatch.setattr(perm.cwe, "load", lambda: CATALOGUE)
    monkeypatch.setattr(perm, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(perm, "pins", lambda info: {"corpus": info})
    out = tmp_path / "results"
    monkeypatch.setattr(results, "result_path", lambda rid: out / f"{rid}.json")
    return tmp_path


def _ablation_runs(rule, tmp_path):
    pairs, catalogue, _ = perm.corpus()
    items, _ = perm.plan(pairs, catalogue)
    for cand in (perm.PRIMARY, perm.SECOND):
        perm.execute(FakeModel(rule), items, perm.RUNS_DIR / f"{cand}.jsonl", "sha")
    perm.report()


def _oracle(advisory, code):
    """Knows which version is vulnerable: a model far better than any metric."""
    return ("exhibits", 0.95) if "bad" in code else ("does_not_exhibit", 0.05)


def test_a_model_far_better_than_metrics_passes(corpus):
    _ablation_runs(_oracle, corpus)
    doc = json.loads(baseline.report().read_text())
    r = doc["result"]
    assert r["model"]["pairwise_correct"]["estimate"] == 1.0
    assert r["comparisons"] == {"pairwise_correct": "model_clearly_better",
                                "precision_at_recall_0_70": "model_clearly_better"}
    assert r["pre_registered_outcome"] == "PASS" and doc["value"] == 2
    assert doc["negative_control"]["passed"] is True
    assert doc["pins"]["regression"]["class_weight"] is None


def _length_reader(advisory, code):
    """A model whose judgement is function length, which is what a metric sees."""
    calls = code.count("(a);")
    return ("exhibits", calls / 20) if calls >= 8 else ("does_not_exhibit", calls / 20)


def test_a_model_no_better_than_metrics_fails(corpus):
    _ablation_runs(_length_reader, corpus)
    doc = json.loads(baseline.report().read_text())
    assert doc["result"]["comparisons"] == {"pairwise_correct": "overlap",
                                            "precision_at_recall_0_70": "overlap"}
    assert doc["result"]["pre_registered_outcome"] == "FAIL" and doc["value"] == 0


@pytest.mark.parametrize(
    "comparisons,expected",
    [
        ({"a": "model_clearly_better", "b": "model_clearly_better"}, "PASS"),
        ({"a": "overlap", "b": "overlap"}, "FAIL"),
        ({"a": "model_clearly_better", "b": "overlap"}, "AMBIGUOUS"),
    ],
)
def test_outcome_follows_the_preregistered_rule(comparisons, expected):
    assert baseline.outcome(comparisons) == expected


def test_pc_threshold_is_the_best_and_highest():
    vuln = np.array([0.9, 0.6, 0.4])
    fixed = np.array([0.3, 0.7, 0.1])
    t, pc = baseline.pc_threshold(vuln, fixed)
    # Pair 1 is right for t in (0.3, 0.9], pair 3 for t in (0.1, 0.4], pair 2 never.
    assert pc == pytest.approx(2 / 3) and t == 0.4

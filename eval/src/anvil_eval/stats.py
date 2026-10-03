"""Bootstrap intervals and the ranking metrics the two kill experiments report.

Every interval is a 95% percentile bootstrap over pairs: a resample draws pair indices with
replacement, and both functions of a pair travel together. When two arms are compared they are
scored on the same resample indices, so the comparison is paired.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass

import numpy as np

SEED = 20261003
RESAMPLES = 10_000


@dataclass(frozen=True)
class Interval:
    estimate: float
    low: float
    high: float
    n: int
    resamples: int
    undefined_resamples: int  # resamples where the statistic had no denominator

    def as_dict(self) -> dict:
        return asdict(self)


def resample_indices(n: int, resamples: int = RESAMPLES, seed: int = SEED) -> np.ndarray:
    if n <= 0:
        raise ValueError("cannot bootstrap an empty sample")
    return np.random.default_rng(seed).integers(0, n, size=(resamples, n))


def bootstrap(
    statistic: Callable[[np.ndarray], float],
    n: int,
    indices: np.ndarray | None = None,
) -> Interval:
    """Percentile interval of ``statistic(idx)`` over resampled index arrays.

    ``statistic`` returns NaN when a resample leaves it undefined (an empty denominator); those
    resamples are counted and left out of the percentiles rather than silently scored as zero.
    """
    idx = resample_indices(n) if indices is None else indices
    point = float(statistic(np.arange(n)))
    values = np.array([statistic(row) for row in idx], dtype=float)
    defined = values[~np.isnan(values)]
    if defined.size == 0:
        raise ValueError("the statistic is undefined on every resample")
    low, high = np.percentile(defined, [2.5, 97.5])
    return Interval(point, float(low), float(high), n, len(idx), int(values.size - defined.size))


def ratio(numer: np.ndarray, denom: np.ndarray) -> Callable[[np.ndarray], float]:
    """A statistic sum(numer[idx]) / sum(denom[idx]); NaN when the denominator is zero."""
    numer = np.asarray(numer, dtype=float)
    denom = np.asarray(denom, dtype=float)

    def stat(idx: np.ndarray) -> float:
        d = denom[idx].sum()
        return float("nan") if d == 0 else float(numer[idx].sum() / d)

    return stat


def pairwise_correct(vuln_pred: Sequence[bool], fixed_pred: Sequence[bool]) -> np.ndarray:
    """Per pair: 1 when the vulnerable version is flagged and the patched one is not."""
    v = np.asarray(vuln_pred, dtype=bool)
    f = np.asarray(fixed_pred, dtype=bool)
    if v.shape != f.shape:
        raise ValueError("one prediction per function of each pair")
    return (v & ~f).astype(float)


def precision_at_recall(scores: np.ndarray, labels: np.ndarray, recall: float = 0.70) -> float:
    """Precision at the highest score threshold whose recall reaches ``recall``.

    Every function scoring at or above the threshold is flagged, so tied scores are flagged
    together; no tie is broken in either arm's favour. NaN when there are no positives.
    """
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=bool)
    positives = labels.sum()
    if positives == 0:
        return float("nan")
    for t in np.unique(scores)[::-1]:
        flagged = scores >= t
        tp = (flagged & labels).sum()
        if tp / positives >= recall:
            return float(tp / flagged.sum())
    raise AssertionError("the lowest threshold flags everything, so recall reaches 1")


def paired_precision_at_recall(
    vuln_scores: np.ndarray, fixed_scores: np.ndarray, recall: float = 0.70
) -> Callable[[np.ndarray], float]:
    """Precision at ``recall`` over both functions of the resampled pairs."""
    v = np.asarray(vuln_scores, dtype=float)
    f = np.asarray(fixed_scores, dtype=float)

    def stat(idx: np.ndarray) -> float:
        scores = np.concatenate([v[idx], f[idx]])
        labels = np.concatenate([np.ones(len(idx), bool), np.zeros(len(idx), bool)])
        return precision_at_recall(scores, labels, recall)

    return stat


def band(interval: Interval, fail_below: float, pass_above: float) -> str:
    """Classify an interval against pre-registered bands: pass, fail or ambiguous.

    A pass needs the whole interval above ``pass_above`` and a fail the whole interval below
    ``fail_below``; anything touching or crossing either edge is ambiguous.
    """
    if interval.low > pass_above:
        return "pass"
    if interval.high < fail_below:
        return "fail"
    return "ambiguous"


def compare(regression: Interval, model: Interval) -> str:
    """The baseline's overlap rule for one metric: ``model_clearly_better`` or ``overlap``.

    ``overlap`` covers both an overlap and the regression exceeding the model, which the rule
    treats alike: regression upper bound >= model lower bound.
    """
    return "model_clearly_better" if regression.high < model.low else "overlap"

"""The interval and band arithmetic the gate reads. Each rule is pinned by a case that breaks it."""

from __future__ import annotations

import numpy as np
import pytest

from anvil_eval import stats


def test_bootstrap_of_a_known_proportion_brackets_it():
    hits = np.array([1] * 300 + [0] * 200, dtype=float)
    iv = stats.bootstrap(stats.ratio(hits, np.ones_like(hits)), len(hits))
    assert iv.estimate == pytest.approx(0.6)
    # The binomial standard error is about 0.022, so the interval is about +/- 0.043.
    assert 0.54 < iv.low < 0.58 and 0.62 < iv.high < 0.66
    assert iv.resamples == stats.RESAMPLES and iv.n == 500


def test_bootstrap_is_reproducible_from_the_seed():
    hits = np.random.default_rng(1).integers(0, 2, 200).astype(float)
    a = stats.bootstrap(stats.ratio(hits, np.ones_like(hits)), 200)
    b = stats.bootstrap(stats.ratio(hits, np.ones_like(hits)), 200)
    assert a == b


def test_undefined_resamples_are_counted_not_scored_as_zero():
    numer = np.array([1.0, 0, 0, 0])
    denom = np.array([1.0, 0, 0, 0])  # only one pair contributes a denominator
    iv = stats.bootstrap(stats.ratio(numer, denom), 4)
    assert iv.undefined_resamples > 0
    assert iv.low == iv.high == 1.0


@pytest.mark.parametrize(
    "low,high,expected",
    [
        (0.81, 0.95, "pass"),
        (0.80, 0.95, "ambiguous"),  # touching the edge is not above it
        (0.76, 0.92, "ambiguous"),  # a point estimate of 0.84 does not pass
        (0.55, 0.75, "ambiguous"),
        (0.45, 0.55, "ambiguous"),
        (0.30, 0.49, "fail"),
        (0.30, 0.50, "ambiguous"),
    ],
)
def test_the_preregistered_bands_read_the_interval(low, high, expected):
    iv = stats.Interval((low + high) / 2, low, high, 500, 10_000, 0)
    assert stats.band(iv, fail_below=0.50, pass_above=0.80) == expected


@pytest.mark.parametrize(
    "reg,model,expected",
    [
        ((0.10, 0.20), (0.25, 0.40), "model_clearly_better"),
        ((0.10, 0.25), (0.25, 0.40), "overlap"),  # touching counts as overlap
        ((0.10, 0.30), (0.25, 0.40), "overlap"),
        ((0.50, 0.60), (0.25, 0.40), "overlap"),  # the regression exceeding the model
    ],
)
def test_the_overlap_rule(reg, model, expected):
    r = stats.Interval(sum(reg) / 2, *reg, 500, 10_000, 0)
    m = stats.Interval(sum(model) / 2, *model, 500, 10_000, 0)
    assert stats.compare(r, m) == expected


def test_pairwise_correct_needs_both_halves_right():
    pc = stats.pairwise_correct([True, True, False, False], [False, True, False, True])
    assert pc.tolist() == [1.0, 0.0, 0.0, 0.0]


def test_precision_at_recall_on_a_hand_worked_ranking():
    # Positives at ranks 1, 2, 4 of 6. Recall 0.70 of 3 positives needs 3 hits -> rank 4.
    scores = np.array([0.9, 0.8, 0.7, 0.6, 0.5, 0.4])
    labels = np.array([1, 1, 0, 1, 0, 0], dtype=bool)
    assert stats.precision_at_recall(scores, labels) == pytest.approx(3 / 4)


def test_ties_are_flagged_together():
    # A scorer that says the same thing for everything flags everything: precision = prevalence.
    scores = np.zeros(10)
    labels = np.array([1] * 5 + [0] * 5, dtype=bool)
    assert stats.precision_at_recall(scores, labels) == pytest.approx(0.5)


def test_a_perfect_ranker_and_a_random_one_are_told_apart():
    rng = np.random.default_rng(0)
    n = 400
    perfect = stats.paired_precision_at_recall(np.ones(n), np.zeros(n))
    random = stats.paired_precision_at_recall(rng.random(n), rng.random(n))
    assert perfect(np.arange(n)) == 1.0
    assert 0.4 < random(np.arange(n)) < 0.6

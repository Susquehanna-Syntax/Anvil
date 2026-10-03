"""The baseline's features and its regression, each checked against a hand-worked answer."""

from __future__ import annotations

import numpy as np
import pytest

from anvil_eval import logreg, metrics

FUNC = r"""
static int copy(char *dst, const char *src, size_t n) {
    // copy at most n bytes
    size_t i;
    if (!dst || !src) return -1;
    for (i = 0; i < n && src[i]; i++) {
        if (src[i] == '{') {        /* a brace in a literal is not a block */
            dst[i] = *src;
        } else {
            dst[i] = src[i];
        }
    }
    do { i--; } while (i > 0);
    log_msg("copied {} bytes", i);
    return memcmp(dst, src, n) ? 1 : 0;
}
"""


def test_hand_counted_metrics():
    m = metrics.compute(FUNC)
    assert m["parameters"] == 3
    assert m["returns"] == 2
    assert m["loops"] == 2  # for, and one do-while
    assert m["conditionals"] == 3  # two ifs and one ?:
    # 1 + if + if + for + while + && + || + ? = 8
    assert m["cyclomatic"] == 8
    assert m["max_nesting"] == 2  # the for block, then the if block inside it
    assert m["calls"] == 2 and m["distinct_callees"] == 2  # log_msg, memcmp
    assert m["array_subscripts"] == 5
    assert m["pointer_derefs"] == 1  # *src; the * in 'char *dst' is outside the body
    assert m["comment_lines"] == 2
    assert m["halstead_volume"] > 0


def test_void_parameter_list_counts_zero():
    assert metrics.compute("int f(void) { return 0; }")["parameters"] == 0
    assert metrics.compute("int f() { return 0; }")["parameters"] == 0


def test_feature_vector_order_is_the_registered_list():
    assert len(metrics.vector(FUNC)) == len(metrics.FEATURES) == 14


def _kkt(model: logreg.Model, x, y, c):
    z = np.hstack([np.ones((len(x), 1)), (x - model.mean) / model.scale])
    p = 1 / (1 + np.exp(-(z @ model.weights)))
    penalty = np.r_[0.0, np.ones(x.shape[1]) / c]
    return np.abs(z.T @ (p - y) + penalty * model.weights).max()


@pytest.mark.parametrize("c", [0.01, 1.0, 100.0])
def test_the_fit_is_the_penalised_optimum(c):
    rng = np.random.default_rng(3)
    x = rng.normal(size=(2000, 5)) * [1, 10, 0.1, 5, 1]
    y = (x[:, 0] - 0.2 * x[:, 1] + rng.normal(size=2000) > 0.5).astype(float)
    model = logreg.fit(x, y, c=c)
    assert _kkt(model, x, y, c) < 1e-6  # the gradient of a convex objective vanishes only here


def test_it_recovers_the_signal_and_its_sign():
    rng = np.random.default_rng(4)
    x = rng.normal(size=(5000, 3))
    y = (rng.random(5000) < 1 / (1 + np.exp(-(2 * x[:, 0] - 1 * x[:, 2])))).astype(float)
    w = logreg.fit(x, y).weights
    assert w[1] > 1.5 and abs(w[2]) < 0.15 and w[3] < -0.7


def test_an_imbalanced_set_is_not_rebalanced():
    rng = np.random.default_rng(5)
    x = rng.normal(size=(10_000, 2))
    y = (rng.random(10_000) < 0.03).astype(float)  # PrimeVul-like prevalence, no signal
    p = logreg.fit(x, y).proba(x)
    assert p.mean() == pytest.approx(0.03, abs=0.005)


def test_separable_data_still_converges_under_the_penalty():
    x = np.array([[-2.0], [-1.0], [1.0], [2.0]])
    y = np.array([0.0, 0.0, 1.0, 1.0])
    model = logreg.fit(x, y, c=1.0)
    assert _kkt(model, x, y, 1.0) < 1e-6

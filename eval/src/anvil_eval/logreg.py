"""L2-regularised logistic regression, by Newton's method, in numpy.

The objective is scikit-learn's ``LogisticRegression(penalty="l2", C=C)``: minimise
``0.5 * |w|^2 + C * sum(log-loss)`` with an unpenalised intercept. Features are standardised with
the training set's mean and standard deviation. There is no class weighting and no rebalancing:
the register forbids balanced training for this baseline, because balancing is what manufactures
false confidence on an imbalanced test set.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class Model:
    mean: np.ndarray
    scale: np.ndarray
    weights: np.ndarray  # intercept first
    iterations: int
    gradient_norm: float

    def decision(self, x: np.ndarray) -> np.ndarray:
        z = (np.asarray(x, dtype=float) - self.mean) / self.scale
        return self.weights[0] + z @ self.weights[1:]

    def proba(self, x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-self.decision(x)))


def fit(
    x: np.ndarray, y: np.ndarray, c: float = 1.0, tol: float = 1e-8, max_iter: int = 100
) -> Model:
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    if set(np.unique(y)) - {0.0, 1.0} or len(np.unique(y)) < 2:
        raise ValueError("labels must be 0 and 1, with both present")
    mean = x.mean(axis=0)
    scale = x.std(axis=0)
    scale[scale == 0] = 1.0
    z = np.hstack([np.ones((len(x), 1)), (x - mean) / scale])
    w = np.zeros(z.shape[1])
    penalty = np.ones_like(w) / c
    penalty[0] = 0.0
    grad_norm = np.inf
    for it in range(1, max_iter + 1):
        p = 1.0 / (1.0 + np.exp(-(z @ w)))
        grad = z.T @ (p - y) + penalty * w
        grad_norm = float(np.linalg.norm(grad))
        if grad_norm < tol * len(y):
            return Model(mean, scale, w, it, grad_norm)
        hess = (z * (p * (1 - p))[:, None]).T @ z + np.diag(penalty)
        step = np.linalg.solve(hess, grad)
        # Damped Newton: halve the step until the objective does not rise.
        before = _objective(z, y, w, penalty)
        t = 1.0
        while _objective(z, y, w - t * step, penalty) > before and t > 1e-10:
            t /= 2
        w = w - t * step
    raise RuntimeError(f"Newton did not converge in {max_iter} iterations (|g| = {grad_norm:.3g})")


def _objective(z: np.ndarray, y: np.ndarray, w: np.ndarray, penalty: np.ndarray) -> float:
    m = z @ w
    # log(1 + exp(-m)) for y=1 and log(1 + exp(m)) for y=0, computed stably.
    loss = np.logaddexp(0.0, -m) * y + np.logaddexp(0.0, m) * (1 - y)
    return float(loss.sum() + 0.5 * (penalty * w * w).sum())

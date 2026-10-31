"""Paired scenario-level statistics for protocol v1.1 §11 (WP7).

* Exact two-sided paired sign-flip randomisation test on the mean difference: every one of the
  2^n sign patterns of the n per-scenario differences is enumerated. Zero differences are kept
  (flipping them changes nothing), so the reference distribution is conditional on them.
  p = #{patterns with |mean| >= |observed mean| - tol} / 2^n. All-zero differences give p = 1.
* Holm step-down adjustment within a declared family.

Units are scenarios; the test assumes exchangeable signs under the null of no paired difference.
Overlapping training folds make it a conditional consistency analysis over these scenarios,
not deployment inference.
"""

from __future__ import annotations

import itertools
from dataclasses import asdict, dataclass

import numpy as np

TOLERANCE = 1e-12


@dataclass(frozen=True)
class SignFlipResult:
    n: int
    mean_difference: float
    median_difference: float
    positive: int
    negative: int
    zero: int
    p_two_sided: float
    patterns: int
    min_attainable_p: float

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def sign_flip_test(differences, tolerance: float = TOLERANCE) -> SignFlipResult:
    d = np.asarray(differences, dtype=float)
    if d.ndim != 1 or len(d) == 0 or np.isnan(d).any():
        raise ValueError("differences must be a non-empty 1-d array without missing values")
    n = len(d)
    observed = abs(float(d.mean()))
    signs = np.array(list(itertools.product((1.0, -1.0), repeat=n)))
    means = np.abs(signs @ d) / n
    extreme = int(np.sum(means >= observed - tolerance))
    return SignFlipResult(
        n=n, mean_difference=float(d.mean()), median_difference=float(np.median(d)),
        positive=int((d > 0).sum()), negative=int((d < 0).sum()), zero=int((d == 0).sum()),
        p_two_sided=extreme / len(signs), patterns=len(signs), min_attainable_p=2 / len(signs),
    )


def holm_adjust(p_values) -> np.ndarray:
    """Holm step-down adjusted p-values, in the input order."""

    p = np.asarray(p_values, dtype=float)
    m = len(p)
    order = np.argsort(p, kind="stable")
    adjusted = np.empty(m)
    running = 0.0
    for rank, index in enumerate(order):
        running = max(running, min(1.0, (m - rank) * p[index]))
        adjusted[index] = running
    return adjusted

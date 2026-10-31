"""Queue ordering and the three selection metrics used for tuning (protocol v1.1 §4.2, §5).

This module holds the primary order rule and the three selection metrics used for
tuning (critical-step interval coverage@k, FP@k, linear NDCG@k). The metric values
come from :mod:`soc_alert_ranking.revision.metrics`, the single implementation of the
WP3 metric contract.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from soc_alert_ranking.revision.labels import ScenarioLabels
from soc_alert_ranking.revision.metrics import metrics_at_k


def _primary_key(scores: np.ndarray) -> np.ndarray:
    scores = np.asarray(scores, dtype=float)
    return np.where(np.isnan(scores), np.inf, -scores)


def full_order(scores: np.ndarray, timestamps: np.ndarray, hash_keys: np.ndarray) -> np.ndarray:
    """Positions sorted by score desc (NaN last), timestamp asc, tie hash asc."""

    timestamps = np.where(np.isnan(timestamps), np.inf, timestamps)
    return np.lexsort((np.asarray(hash_keys, dtype=np.uint64), timestamps, _primary_key(scores)))


def top_k_order(scores: np.ndarray, timestamps: np.ndarray, hash_keys: np.ndarray, k: int) -> np.ndarray:
    """Exactly the first min(k, n) positions of :func:`full_order`, without a full sort."""

    n = len(scores)
    if k >= n:
        return full_order(scores, timestamps, hash_keys)
    primary = _primary_key(scores)
    threshold = np.partition(primary, k - 1)[k - 1]
    candidates = np.flatnonzero(primary <= threshold)
    local = full_order(np.asarray(scores, dtype=float)[candidates], np.asarray(timestamps, dtype=float)[candidates],
                       np.asarray(hash_keys)[candidates])
    return candidates[local[:k]]


@dataclass(frozen=True)
class SelectionMetrics:
    k: int
    queue_length: int
    queue_shorter_than_k: bool
    fp: int
    ndcg: float | None                  # None when IDCG == 0
    coverage: float | None              # over intervals containing any alert; None if none
    coverage_all_defined: float | None  # over all defined critical intervals; None if none defined
    covered_intervals: int
    eligible_intervals: int
    defined_intervals: int
    multi_interval_alerts_in_top_k: int


def selection_metrics(order_top: np.ndarray, labels: ScenarioLabels, k: int) -> SelectionMetrics:
    """The three selection metrics, taken from the WP3 contract implementation."""

    m = metrics_at_k(order_top, labels, k)
    return SelectionMetrics(
        k=k,
        queue_length=m.n,
        queue_shorter_than_k=m.short_queue,
        fp=m.negatives_in_top,
        ndcg=m.ndcg_linear,
        coverage=m.coverage_eligible,
        coverage_all_defined=m.coverage_all,
        covered_intervals=m.covered_intervals,
        eligible_intervals=m.eligible_intervals,
        defined_intervals=m.defined_intervals,
        multi_interval_alerts_in_top_k=m.multi_interval_alerts_in_top,
    )

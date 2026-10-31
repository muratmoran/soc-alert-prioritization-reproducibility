"""Exact queue metrics of the WP3 metric contract (docs/revision/wp3/metric_contract.md).

Terminology: an *interval-labeled positive* is an alert whose timestamp lies in at
least one attack interval (y = 1); it is not a verified malicious alert. A queue is
the ordered set of eligible alerts of one scenario (or of one detector within a
scenario for within-detector analyses). Every metric that divides returns ``None``
when its denominator is zero; counts are integers; queue lengths shorter than the
budget are flagged rather than padded.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction

import numpy as np

from soc_alert_ranking.revision.labels import ScenarioLabels


K_GRID = (10, 25, 50, 100, 250, 500, 1000)
QUEUE_FRACTIONS = (Fraction(1, 1000), Fraction(1, 100), Fraction(1, 20), Fraction(1, 10), Fraction(1, 4), Fraction(1, 2))
RECALL_TARGETS = (Fraction(1, 2), Fraction(4, 5), Fraction(9, 10))
COVERAGE_TARGETS = (Fraction(1, 2), Fraction(4, 5), Fraction(1, 1))


def ceil_fraction(fraction: Fraction, count: int) -> int:
    """ceil(fraction * count) in exact integer arithmetic (no floating-point rounding)."""

    return -((-fraction.numerator * count) // fraction.denominator)


def discounts(length: int) -> np.ndarray:
    """1 / log2(j + 1) for positions j = 1..length."""

    return 1.0 / np.log2(np.arange(2, length + 2, dtype=float))


def restrict_queue(labels: ScenarioLabels, mask: np.ndarray) -> ScenarioLabels:
    """Labels of a sub-queue (e.g. one detector). Defined intervals are kept; eligibility is recomputed."""

    mask = np.asarray(mask, dtype=bool)
    return labels.replace_arrays(
        alert_ids=labels.alert_ids[mask], y=labels.y[mask], s_star=labels.s_star[mask], z=labels.z[mask],
        r=labels.r[mask], phase_membership=labels.phase_membership[mask],
        critical_membership=labels.critical_membership[mask],
    )


@dataclass(frozen=True)
class MetricsAtK:
    budget: str
    k: int | None
    n: int
    k_eff: int
    short_queue: bool
    empty_queue: bool
    positives_in_top: int
    negatives_in_top: int            # FP@k: interval-labeled negatives among the first k_eff alerts
    precision: float | None
    positives_total: int
    attack_recall: float | None
    critical_in_top: int
    critical_total: int
    critical_recall: float | None
    dcg_linear: float
    idcg_linear: float
    ndcg_linear: float | None
    ndcg_exponential: float | None
    covered_intervals: int
    eligible_intervals: int
    defined_intervals: int
    coverage_eligible: float | None
    coverage_all: float | None
    multi_interval_alerts_in_top: int

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def _ratio(numerator: float, denominator: float) -> float | None:
    return float(numerator) / float(denominator) if denominator else None


def metrics_at_k(order: np.ndarray, labels: ScenarioLabels, k: int | None, budget: str | None = None) -> MetricsAtK:
    """All budgeted metrics for the first min(k, n) positions of ``order``.

    ``order`` lists queue positions (indices into ``labels``) from rank 1 onward and must
    contain at least min(k, n) entries. ``k=None`` evaluates the whole queue.
    """

    n = len(labels.y)
    k_eff = n if k is None else min(int(k), n)
    order = np.asarray(order, dtype=np.int64)
    if len(order) < k_eff:
        raise ValueError("order is shorter than the evaluated budget")
    top = order[:k_eff]
    if len(np.unique(top)) != len(top) or (len(top) and (top.min() < 0 or top.max() >= n)):
        raise ValueError("order must list distinct valid queue positions")

    positives_in_top = int(labels.y[top].sum())
    positives_total = int(labels.y.sum())
    critical_in_top = int(labels.z[top].sum())
    critical_total = int(labels.z.sum())

    d = discounts(k_eff)
    dcg = float(np.sum(labels.r[top] * d))
    ideal = np.sort(labels.r)[::-1][:k_eff]
    idcg = float(np.sum(ideal * d))
    gain = np.power(2.0, labels.r) - 1.0
    dcg_exp = float(np.sum(gain[top] * d))
    idcg_exp = float(np.sum(np.sort(gain)[::-1][:k_eff] * d))

    membership = labels.critical_membership
    defined = int(labels.defined_critical_intervals)
    eligible_mask = membership.any(axis=0) if n else np.zeros(membership.shape[1], dtype=bool)
    covered_mask = membership[top].any(axis=0) if k_eff else np.zeros(membership.shape[1], dtype=bool)
    covered = int(covered_mask.sum())
    eligible = int(eligible_mask.sum())

    return MetricsAtK(
        budget=budget or ("all" if k is None else f"k={k}"),
        k=k,
        n=n,
        k_eff=k_eff,
        short_queue=k is not None and n < int(k),
        empty_queue=n == 0,
        positives_in_top=positives_in_top,
        negatives_in_top=k_eff - positives_in_top,
        precision=_ratio(positives_in_top, k_eff),
        positives_total=positives_total,
        attack_recall=_ratio(positives_in_top, positives_total),
        critical_in_top=critical_in_top,
        critical_total=critical_total,
        critical_recall=_ratio(critical_in_top, critical_total),
        dcg_linear=dcg,
        idcg_linear=idcg,
        ndcg_linear=_ratio(dcg, idcg),
        ndcg_exponential=_ratio(dcg_exp, idcg_exp),
        covered_intervals=covered,
        eligible_intervals=eligible,
        defined_intervals=defined,
        coverage_eligible=_ratio(covered, eligible),
        coverage_all=_ratio(covered, defined),
        multi_interval_alerts_in_top=int((membership[top].sum(axis=1) > 1).sum()) if k_eff and membership.shape[1] else 0,
    )


@dataclass(frozen=True)
class SubgroupInMixedQueue:
    """Retrieval of one subgroup inside the original mixed queue (no reranking).

    The order and k_eff come from the full queue. Subgroup counts use subgroup alerts among the
    first k_eff positions; ratios use subgroup totals. ``subgroup_eligible_intervals`` are
    critical intervals containing at least one subgroup alert; ``subgroup_covered_intervals``
    are those covered by a subgroup alert in the top k_eff.
    """

    budget: str
    k: int | None
    n: int
    k_eff: int
    subgroup_n: int
    subgroup_in_top: int
    subgroup_share_of_top: float | None
    subgroup_positives_in_top: int
    subgroup_negatives_in_top: int
    subgroup_positives_total: int
    subgroup_attack_recall: float | None
    subgroup_critical_in_top: int
    subgroup_critical_total: int
    subgroup_critical_recall: float | None
    subgroup_covered_intervals: int
    subgroup_eligible_intervals: int
    subgroup_coverage: float | None

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def subgroup_in_mixed_queue(order: np.ndarray, labels: ScenarioLabels, mask: np.ndarray, k: int | None,
                            budget: str | None = None) -> SubgroupInMixedQueue:
    """Subgroup retrieval within the mixed queue ranked by ``order`` (compare ``restrict_queue``)."""

    mask = np.asarray(mask, dtype=bool)
    n = len(labels.y)
    if len(mask) != n:
        raise ValueError("subgroup mask must cover the whole queue")
    k_eff = n if k is None else min(int(k), n)
    order = np.asarray(order, dtype=np.int64)
    if len(order) < k_eff:
        raise ValueError("order is shorter than the evaluated budget")
    top = order[:k_eff]
    if len(np.unique(top)) != len(top) or (len(top) and (top.min() < 0 or top.max() >= n)):
        raise ValueError("order must list distinct valid queue positions")
    sub_top = top[mask[top]]
    membership = labels.critical_membership
    positives_in_top = int(labels.y[sub_top].sum())
    positives_total = int(labels.y[mask].sum())
    critical_in_top = int(labels.z[sub_top].sum())
    critical_total = int(labels.z[mask].sum())
    eligible = int(membership[mask].any(axis=0).sum()) if mask.any() else 0
    covered = int(membership[sub_top].any(axis=0).sum()) if len(sub_top) else 0
    return SubgroupInMixedQueue(
        budget=budget or ("all" if k is None else f"k={k}"), k=k, n=n, k_eff=k_eff,
        subgroup_n=int(mask.sum()), subgroup_in_top=int(len(sub_top)),
        subgroup_share_of_top=_ratio(len(sub_top), k_eff),
        subgroup_positives_in_top=positives_in_top, subgroup_negatives_in_top=int(len(sub_top)) - positives_in_top,
        subgroup_positives_total=positives_total, subgroup_attack_recall=_ratio(positives_in_top, positives_total),
        subgroup_critical_in_top=critical_in_top, subgroup_critical_total=critical_total,
        subgroup_critical_recall=_ratio(critical_in_top, critical_total),
        subgroup_covered_intervals=covered, subgroup_eligible_intervals=eligible,
        subgroup_coverage=_ratio(covered, eligible),
    )


def queue_fraction_budget(n: int, fraction: Fraction) -> int | None:
    """k = max(1, ceil(fraction * n)) for a non-empty queue; None for an empty queue."""

    if n == 0:
        return None
    return max(1, ceil_fraction(fraction, n))


@dataclass(frozen=True)
class Effort:
    kind: str                 # critical_recall | interval_coverage
    target: str
    total: int                # critical alerts, or eligible intervals
    required: int | None      # ceil(target * total)
    position: int | None      # 1-based rank at which the requirement is first met
    queue_fraction: float | None

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def effort_to_critical_recall(order: np.ndarray, labels: ScenarioLabels, target: Fraction) -> Effort:
    n = len(labels.y)
    total = int(labels.z.sum())
    if total == 0:
        return Effort("critical_recall", str(target), 0, None, None, None)
    required = ceil_fraction(target, total)
    cumulative = np.cumsum(labels.z[np.asarray(order, dtype=np.int64)])
    position = int(np.flatnonzero(cumulative >= required)[0]) + 1
    return Effort("critical_recall", str(target), total, required, position, position / n)


def effort_to_interval_coverage(order: np.ndarray, labels: ScenarioLabels, target: Fraction) -> Effort:
    n = len(labels.y)
    membership = labels.critical_membership
    eligible = membership.any(axis=0) if n else np.zeros(membership.shape[1], dtype=bool)
    total = int(eligible.sum())
    if total == 0:
        return Effort("interval_coverage", str(target), 0, None, None, None)
    required = ceil_fraction(target, total)
    ordered = membership[np.asarray(order, dtype=np.int64)][:, eligible]
    first_position = np.array([np.flatnonzero(ordered[:, c])[0] + 1 for c in range(total)])
    position = int(np.sort(first_position)[required - 1])
    return Effort("interval_coverage", str(target), total, required, position, position / n)


@dataclass(frozen=True)
class FirstCritical:
    position: int | None      # None means the queue contains no interval-labeled critical alert
    critical_total: int
    prevalence: float | None  # critical_total / n

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def first_critical_rank(order: np.ndarray, labels: ScenarioLabels) -> FirstCritical:
    n = len(labels.y)
    total = int(labels.z.sum())
    if total == 0:
        return FirstCritical(None, 0, 0.0 if n else None)
    position = int(np.flatnonzero(labels.z[np.asarray(order, dtype=np.int64)])[0]) + 1
    return FirstCritical(position, total, total / n)


@dataclass(frozen=True)
class ScoreAvailability:
    n: int
    missing: int
    missing_rate: float | None
    ordering_defined: bool     # False when every score is missing: no score ordering exists

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def score_availability(scores: np.ndarray) -> ScoreAvailability:
    """Missing-score accounting for a queue; a queue with only missing scores has no score order."""

    scores = np.asarray(scores, dtype=float)
    n = len(scores)
    missing = int(np.isnan(scores).sum())
    return ScoreAvailability(n, missing, missing / n if n else None, missing < n)


def queue_report(order: np.ndarray, labels: ScenarioLabels, k_grid=K_GRID, fractions=QUEUE_FRACTIONS,
                 recall_targets=RECALL_TARGETS, coverage_targets=COVERAGE_TARGETS) -> dict[str, object]:
    """Complete static report for one fully ordered queue."""

    n = len(labels.y)
    order = np.asarray(order, dtype=np.int64)
    if len(order) != n or len(np.unique(order)) != n:
        raise ValueError("queue_report needs a complete permutation of the queue")
    budgets = [metrics_at_k(order, labels, k).to_record() for k in k_grid]
    for fraction in fractions:
        k = queue_fraction_budget(n, fraction)
        if k is None:
            record = metrics_at_k(order, labels, 0, budget=f"fraction={fraction}").to_record()
            record.update({"k": None, "empty_queue": True})
        else:
            record = metrics_at_k(order, labels, k, budget=f"fraction={fraction}").to_record()
        budgets.append(record)
    return {
        "n": n,
        "budgets": budgets,
        "first_critical": first_critical_rank(order, labels).to_record(),
        "effort": [effort_to_critical_recall(order, labels, t).to_record() for t in recall_targets]
        + [effort_to_interval_coverage(order, labels, t).to_record() for t in coverage_targets],
    }

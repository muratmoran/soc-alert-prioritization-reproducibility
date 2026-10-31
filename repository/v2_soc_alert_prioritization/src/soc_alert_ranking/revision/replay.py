"""Chronological queue replay (protocol v1.1 §8; docs/revision/wp5/replay_specification.md).

One analyst, non-preemptive, equal service time, 24-hour staffing, horizon from a scenario's
first to its last alert, no initial backlog and no draining. Alerts arriving at or before a
decision time are selectable at that time (arrivals before selection at equal time); a future
alert never is. Selection takes the best declared-order rank (score descending, missing last,
timestamp ascending, tie hash ascending) among arrived, uninvestigated alerts.

The simulation takes scores, timestamps and tie hashes only. Labels enter afterwards through
:func:`replay_metrics`.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass

import numpy as np

from soc_alert_ranking.revision.evaluation import full_order
from soc_alert_ranking.revision.labels import ScenarioLabels

HOUR = 3600.0
DELAYS_HOURS = (1, 4, 24)
PRIMARY_RATE = 12.0
SENSITIVITY_RATES = (6.0, 30.0, 60.0)


@dataclass(frozen=True)
class ReplayTrace:
    rate_per_hour: float
    service_seconds: float
    t0: float
    horizon_end: float
    selected: np.ndarray               # queue positions in selection order
    start: np.ndarray                  # service start times
    backlog_at_selection: np.ndarray   # backlog size at the selection, before removal
    tie_decided: np.ndarray            # next-best backlog alert had the same score
    arrivals: int

    @property
    def investigations(self) -> int:
        return int(len(self.selected))

    @property
    def busy_seconds(self) -> float:
        return float(np.sum(np.minimum(self.start + self.service_seconds, self.horizon_end) - self.start))

    @property
    def idle_seconds(self) -> float:
        return float((self.horizon_end - self.t0) - self.busy_seconds)


def priority_ranks(scores: np.ndarray, timestamps: np.ndarray, hash_keys: np.ndarray) -> np.ndarray:
    """Rank of each alert in the declared total order (0 = first)."""

    order = full_order(np.asarray(scores, dtype=float), np.asarray(timestamps, dtype=float), np.asarray(hash_keys, dtype=np.uint64))
    ranks = np.empty(len(order), dtype=np.int64)
    ranks[order] = np.arange(len(order))
    return ranks


def arrival_order(timestamps: np.ndarray, hash_keys: np.ndarray) -> np.ndarray:
    """Positions sorted by arrival time (tie hash breaks equal times; irrelevant to selection)."""

    return np.lexsort((np.asarray(hash_keys, dtype=np.uint64), np.asarray(timestamps, dtype=float)))


class _PrefixMin:
    """Minimum over a prefix of arrival slots, with point removal (values are unique ranks)."""

    def __init__(self, values: np.ndarray, empty: int):
        n = len(values)
        self.size = 1 << max(0, (n - 1).bit_length())
        self.empty = empty
        tree = np.full(2 * self.size, empty, dtype=np.int64)
        tree[self.size:self.size + n] = values
        lo = self.size
        while lo > 1:
            parent = lo // 2
            tree[parent:lo] = np.minimum(tree[lo:2 * lo:2], tree[lo + 1:2 * lo:2])
            lo = parent
        self.tree = tree.tolist()

    def query(self, count: int) -> int:
        tree, result = self.tree, self.empty
        left, right = self.size, self.size + count
        while left < right:
            if left & 1:
                result = min(result, tree[left])
                left += 1
            if right & 1:
                right -= 1
                result = min(result, tree[right])
            left >>= 1
            right >>= 1
        return result

    def remove(self, slot: int) -> None:
        tree = self.tree
        i = self.size + slot
        tree[i] = self.empty
        i >>= 1
        while i:
            left, right = tree[2 * i], tree[2 * i + 1]
            tree[i] = left if left < right else right
            i >>= 1


def replay_alerts(scores: np.ndarray, timestamps: np.ndarray, hash_keys: np.ndarray, rate_per_hour: float) -> ReplayTrace:
    scores = np.asarray(scores, dtype=float)
    timestamps = np.asarray(timestamps, dtype=float)
    n = len(timestamps)
    if n == 0:
        empty = np.zeros(0)
        return ReplayTrace(rate_per_hour, HOUR / rate_per_hour, math.nan, math.nan, empty.astype(np.int64), empty,
                           empty.astype(np.int64), empty.astype(bool), 0)
    if np.isnan(timestamps).any():
        raise ValueError("replay needs finite timestamps")
    service = HOUR / rate_per_hour
    arrivals = arrival_order(timestamps, hash_keys)
    arrival_times = timestamps[arrivals].tolist()
    ranks = priority_ranks(scores, timestamps, hash_keys)
    by_rank = np.argsort(ranks)                    # queue position of each rank
    slot_of_position = np.empty(n, dtype=np.int64)
    slot_of_position[arrivals] = np.arange(n)
    backlog = _PrefixMin(ranks[arrivals], empty=n)
    sorted_scores = scores[by_rank]
    t0, horizon_end = arrival_times[0], arrival_times[-1]

    selected, starts, sizes, ties = [], [], [], []
    arrived = 0
    free = t0
    while True:
        while arrived < n and arrival_times[arrived] <= free:
            arrived += 1
        if arrived == len(selected):               # nothing waiting: wait for the next arrival
            if arrived == n:
                break
            time = arrival_times[arrived]
            while arrived < n and arrival_times[arrived] <= time:
                arrived += 1
        else:
            time = free
        if time > horizon_end:
            break
        best = backlog.query(arrived)
        position = int(by_rank[best])
        backlog.remove(int(slot_of_position[position]))
        runner_up = backlog.query(arrived)
        tie = False
        if runner_up < n:
            a, b = sorted_scores[best], sorted_scores[runner_up]
            tie = bool(a == b or (math.isnan(a) and math.isnan(b)))
        selected.append(position)
        starts.append(time)
        sizes.append(arrived - len(selected) + 1)
        ties.append(tie)
        free = time + service
    return ReplayTrace(rate_per_hour, service, t0, horizon_end, np.array(selected, dtype=np.int64),
                       np.array(starts, dtype=float), np.array(sizes, dtype=np.int64), np.array(ties, dtype=bool), n)


# ------------------------------------------------------------------ integrity checks

@dataclass
class TraceCheck:
    violations: list[str]
    checked_selections: int

    @property
    def passed(self) -> bool:
        return not self.violations


def check_trace(trace: ReplayTrace, scores: np.ndarray, timestamps: np.ndarray, hash_keys: np.ndarray,
                sample_seed: int = 42, sample: int = 50) -> TraceCheck:
    """Spec §2 integrity checks, with an independent full-backlog scan on sampled selections."""

    violations: list[str] = []
    n = len(timestamps)
    if n == 0:
        return TraceCheck([] if trace.investigations == 0 else ["investigations without alerts"], 0)
    timestamps = np.asarray(timestamps, dtype=float)
    t0, horizon_end, service = float(timestamps.min()), float(timestamps.max()), trace.service_seconds
    if trace.t0 != t0 or trace.horizon_end != horizon_end:
        violations.append("horizon differs from first/last alert")
    sel, start = trace.selected, trace.start
    if len(np.unique(sel)) != len(sel):
        violations.append("an alert was investigated twice")
    if len(sel) and np.any(timestamps[sel] > start):
        violations.append("selection before arrival")
    if len(sel) > 1 and np.any(np.diff(start) < service - 1e-9):
        violations.append("overlapping service (more than one alert in service)")
    if len(sel) and np.any(start > horizon_end):
        violations.append("selection after the horizon")
    if len(sel) and start[0] != t0:
        violations.append("first selection not at the first arrival")
    if abs(trace.busy_seconds + trace.idle_seconds - (horizon_end - t0)) > 1e-6 or trace.idle_seconds < -1e-6:
        violations.append("service accounting does not sum to the horizon")
    if len(sel) > math.floor((horizon_end - t0) / service) + 1:
        violations.append("more investigations than capacity allows")
    # work conservation: waiting between services only when nothing had arrived uninvestigated
    for k in range(1, len(sel)):
        free = start[k - 1] + service
        if start[k] > free + 1e-9:
            waiting = int(np.sum(timestamps <= free)) - k
            if waiting > 0:
                violations.append(f"analyst idle at {free} with {waiting} alerts waiting")
                break
    if len(sel) < math.floor((horizon_end - t0) / service) + 1:
        last_free = start[-1] + service if len(sel) else t0
        if last_free <= horizon_end and int(np.sum(timestamps <= horizon_end)) > len(sel):
            violations.append("horizon ended with capacity and waiting alerts unused")
    # independent priority check on sampled selections
    rng = np.random.default_rng(sample_seed)
    picks = sorted(set(range(min(sample, len(sel)))) | set(rng.choice(len(sel), size=min(sample, len(sel)), replace=False).tolist())) if len(sel) else []
    keys = np.lexsort((np.asarray(hash_keys, dtype=np.uint64), timestamps,
                       np.where(np.isnan(scores), np.inf, -np.asarray(scores, dtype=float)), np.isnan(scores)))
    rank = np.empty(n, dtype=np.int64)
    rank[keys] = np.arange(n)
    investigated_before = np.full(n, np.inf)
    investigated_before[sel] = np.arange(len(sel))
    for k in picks:
        waiting = (timestamps <= start[k]) & (investigated_before >= k)
        best = int(np.flatnonzero(waiting)[np.argmin(rank[waiting])])
        if best != int(sel[k]):
            violations.append(f"selection {k} is not the best-ranked waiting alert")
            break
    return TraceCheck(violations, len(picks))


# ------------------------------------------------------------------ metrics (labels enter here)

def _ratio(a: float, b: float) -> float | None:
    return float(a) / float(b) if b else None


def replay_metrics(trace: ReplayTrace, labels: ScenarioLabels, timestamps: np.ndarray,
                   low_confidence: np.ndarray, delays_hours=DELAYS_HOURS) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Summary metrics (spec §3) and per-interval delay rows for one replay."""

    timestamps = np.asarray(timestamps, dtype=float)
    n = len(timestamps)
    sel, start = trace.selected, trace.start
    t0, horizon_end = trace.t0, trace.horizon_end
    span = horizon_end - t0
    y, z = labels.y.astype(bool), labels.z.astype(bool)
    membership = labels.critical_membership
    investigated = np.zeros(n, dtype=bool)
    investigated[sel] = True
    start_of = np.full(n, np.nan)
    start_of[sel] = start
    waits = start - timestamps[sel] if len(sel) else np.zeros(0)
    critical_total = int(z.sum())
    record: dict[str, object] = {
        "rate_per_hour": trace.rate_per_hour, "service_seconds": trace.service_seconds, "alerts": n,
        "horizon_hours": span / HOUR, "investigations": trace.investigations,
        "busy_seconds": trace.busy_seconds, "idle_seconds": trace.idle_seconds,
        "utilization": _ratio(trace.busy_seconds, span),
        "positive_investigations": int(y[sel].sum()), "fp_investigations": int((~y[sel]).sum()),
        "fp_investigation_share": _ratio(int((~y[sel]).sum()), len(sel)),
        "critical_investigations": int(z[sel].sum()),
        "critical_total": critical_total, "critical_recall_by_horizon": _ratio(int(z[sel].sum()), critical_total),
        "starved_critical": int((z & ~investigated).sum()), "starved_critical_share": _ratio(int((z & ~investigated).sum()), critical_total),
        "low_confidence_critical": int((z & low_confidence).sum()),
        "starved_low_confidence_critical": int((z & low_confidence & ~investigated).sum()),
        "other_critical": int((z & ~low_confidence).sum()),
        "starved_other_critical": int((z & ~low_confidence & ~investigated).sum()),
        "tie_decided_selections": int(trace.tie_decided.sum()), "tie_decided_share": _ratio(int(trace.tie_decided.sum()), len(sel)),
        "peak_backlog": int(max(int(trace.backlog_at_selection.max()) if len(sel) else 0, n - len(sel))),
        "backlog_at_horizon": int(n - len(sel)),
        "time_average_backlog": _ratio(float(np.sum(np.where(investigated, start_of, horizon_end) - timestamps)), span),
        "wait_median_seconds": float(np.median(waits)) if len(waits) else None,
        "wait_p90_seconds": float(np.percentile(waits, 90)) if len(waits) else None,
        "wait_max_seconds": float(waits.max()) if len(waits) else None,
    }
    ages = horizon_end - timestamps[~investigated]
    record["uninvestigated_age_median_seconds"] = float(np.median(ages)) if len(ages) else None
    record["uninvestigated_age_max_seconds"] = float(ages.max()) if len(ages) else None
    for d in delays_hours:
        limit = d * HOUR
        record[f"critical_recall_within_{d}h"] = _ratio(int((z[sel] & (waits <= limit)).sum()), critical_total)
        record[f"critical_arriving_after_T_minus_{d}h"] = int((z & (timestamps > horizon_end - limit)).sum())

    rows = []
    defined = labels.defined_critical_intervals
    detected = censored = 0
    delays, restricted = [], []
    covered_within = {d: 0 for d in delays_hours}
    order_by_start = np.argsort(start, kind="stable")
    for c in range(membership.shape[1]):
        inside = membership[:, c]
        eligible = bool(inside.any())
        first = float(timestamps[inside].min()) if eligible else math.nan
        hits = sel[order_by_start][membership[sel[order_by_start], c]] if len(sel) else np.zeros(0, dtype=np.int64)
        detection = float(start_of[hits[0]]) if len(hits) else math.nan
        is_detected = bool(len(hits))
        delay = detection - first if is_detected else math.nan
        censor_time = horizon_end - first if eligible else math.nan
        if eligible:
            if is_detected:
                detected += 1
                delays.append(delay)
                restricted.append(delay)
                for d in delays_hours:
                    covered_within[d] += int(delay <= d * HOUR)
            else:
                censored += 1
                restricted.append(censor_time)
        rows.append({"interval": labels.critical_interval_ids[c], "eligible": eligible, "first_alert_offset_hours": (first - t0) / HOUR if eligible else None,
                     "detected": is_detected, "detection_offset_hours": (detection - t0) / HOUR if is_detected else None,
                     "delay_hours": delay / HOUR if is_detected else None,
                     "censored": eligible and not is_detected, "censoring_hours": censor_time / HOUR if eligible and not is_detected else None,
                     "detecting_alert_position": int(hits[0]) if is_detected else None})
    eligible_count = sum(r["eligible"] for r in rows)
    record.update({
        "defined_intervals": defined, "eligible_intervals": eligible_count, "covered_intervals": detected,
        "uninvestigated_intervals": defined - detected, "censored_intervals": censored,
        "coverage_defined": _ratio(detected, defined), "coverage_eligible": _ratio(detected, eligible_count),
        "median_delay_hours_detected": float(np.median(delays)) / HOUR if delays else None,
        "restricted_mean_delay_hours_lower_bound": float(np.mean(restricted)) / HOUR if restricted else None,
        **{f"intervals_covered_within_{d}h": covered_within[d] for d in delays_hours},
    })
    return record, rows


def trace_record(trace: ReplayTrace) -> dict[str, object]:
    return {k: v for k, v in asdict(trace).items() if not isinstance(v, np.ndarray)}

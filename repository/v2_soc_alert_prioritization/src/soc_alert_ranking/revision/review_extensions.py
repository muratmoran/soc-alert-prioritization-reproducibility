"""Exploratory October 30 extensions; original protocol implementations stay frozen."""
from __future__ import annotations

from dataclasses import replace

import numpy as np

from .features import KeyTableProvider
from .replay import ReplayTrace, _PrefixMin


class CriticalReliabilityProvider(KeyTableProvider):
    """Preserve mapping counts; use critical positives only for reliability fitting."""

    def get(self, scenario, purpose="fitting"):
        table = super().get(scenario, purpose)
        if purpose not in {"class_heights", "key_heights"}:
            return table
        labels = self.store.get(scenario, purpose + ":critical_target")
        key = self.ranking.rows(scenario).key_id.to_numpy()
        return replace(table, positives=np.bincount(key, weights=labels.z,
                                                   minlength=self.ranking.n_keys))


def random_priorities(hash_keys, seed):
    """SplitMix64 permutation of stable hashes: label-free and prefix invariant.

    Priorities can be calculated on arrival without seeing any other record.
    The bijective mixing function introduces no new hash collisions.
    """
    x = np.asarray(hash_keys, dtype=np.uint64).copy()
    with np.errstate(over="ignore"):
        x += np.uint64(seed) + np.uint64(0x9E3779B97F4A7C15)
        x = (x ^ (x >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        x = (x ^ (x >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
    return x ^ (x >> np.uint64(31))


def simulate(scores, arrivals, hashes, rate, t0, horizon, priorities=None):
    """Causal prefix-min replay with explicit horizon and optional random ties."""
    scores, arrivals = np.asarray(scores, float), np.asarray(arrivals, float)
    hashes = np.asarray(hashes, np.uint64)
    if not (rate > 0 and horizon >= t0) or not np.isfinite(arrivals).all():
        raise ValueError("invalid service rate, horizon or arrival times")
    n = len(scores)
    if len(arrivals) != n or len(hashes) != n:
        raise ValueError("unaligned arrays")
    if n and np.min(arrivals) < t0:
        raise ValueError("arrival precedes observation origin")
    secondary = arrivals if priorities is None else np.asarray(priorities)
    if len(secondary) != n:
        raise ValueError("unaligned priorities")
    primary = np.where(np.isnan(scores), np.inf, -scores)
    ordering = np.lexsort((hashes, arrivals))
    by_rank = np.lexsort((hashes, arrivals, secondary, primary))
    ranks = np.empty(n, dtype=int); ranks[by_rank] = np.arange(n)
    slots = np.empty(n, dtype=int); slots[ordering] = np.arange(n)
    backlog = _PrefixMin(ranks[ordering], empty=n) if n else None
    selected, starts, sizes, ties = [], [], [], []
    cursor, now, service = 0, float(t0), 3600.0 / rate
    while now <= horizon:
        while cursor < n and arrivals[ordering[cursor]] <= now:
            cursor += 1
        if cursor == len(selected):
            if cursor == n or arrivals[ordering[cursor]] > horizon:
                break
            now = float(arrivals[ordering[cursor]])
            continue
        sizes.append(cursor - len(selected))
        best = backlog.query(cursor); i = int(by_rank[best])
        backlog.remove(int(slots[i])); runner = backlog.query(cursor)
        ties.append(bool(runner < n and primary[by_rank[runner]] == primary[i]))
        selected.append(i); starts.append(now)
        now += service
    return ReplayTrace(rate, service, t0, horizon, np.array(selected, dtype=np.int64),
                       np.array(starts), np.array(sizes, dtype=np.int64),
                       np.array(ties, dtype=bool), int((arrivals <= horizon).sum()))


def group_arrays(clusters, timestamps, scores):
    """Closed-window release and max score, in representative array order."""
    reps = np.flatnonzero(clusters.representative)
    inverse = np.empty(clusters.n_clusters, dtype=int)
    inverse[clusters.cluster_id[reps]] = np.arange(len(reps))
    group_index = inverse[clusters.cluster_id]
    group_scores = np.full(len(reps), -np.inf)
    finite_scores = np.where(np.isnan(scores), -np.inf, scores)
    np.maximum.at(group_scores, group_index, finite_scores)
    all_missing = np.ones(len(reps), bool)
    np.logical_and.at(all_missing, group_index, np.isnan(scores))
    group_scores[all_missing] = np.nan
    release = np.asarray(timestamps)[reps] + clusters.window_seconds
    if np.any(np.asarray(timestamps) >= release[group_index]):
        raise ValueError("a group contains a record arriving at/after closure")
    return reps, group_index, release, group_scores


def service_outcomes(trace, labels, member_labels=None, group_index=None):
    """Queue-unit outcomes and interval-end timing; labels enter only here."""
    sel = trace.selected
    membership = labels.critical_membership
    first = np.full(membership.shape[1], np.inf)
    for i, started in zip(sel, trace.start):
        first[membership[i]] = np.minimum(first[membership[i]], started)
    ends = np.array([float(i.rsplit("|", 1)[-1]) for i in labels.critical_interval_ids])
    chosen = np.zeros(len(labels.y), bool); chosen[sel] = True
    result = {
        "units": len(labels.y), "released_units": trace.arrivals,
        "investigations": len(sel), "critical_units": int(labels.z.sum()),
        "critical_investigated": int(labels.z[sel].sum()),
        "negative_investigations": int((~labels.y[sel]).sum()),
        "defined_intervals": len(first), "covered": int(np.isfinite(first).sum()),
        "before_end": int((first < ends).sum()),
        "late": int((np.isfinite(first) & (first >= ends)).sum()),
        "busy_seconds": trace.busy_seconds, "idle_seconds": trace.idle_seconds,
        "horizon_seconds": trace.horizon_end - trace.t0,
        "tie_decided": int(trace.tie_decided.sum()),
        "critical_uninvestigated": int(labels.z[~chosen].sum()),
    }
    if member_labels is not None:
        members_chosen = chosen[group_index]
        result["critical_records_contained"] = int(member_labels.z[members_chosen].sum())
        result["critical_records_total"] = int(member_labels.z.sum())
    return result

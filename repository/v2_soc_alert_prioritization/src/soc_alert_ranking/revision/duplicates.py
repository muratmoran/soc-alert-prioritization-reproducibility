"""Duplicate clusters and their evaluation units (WP3 metric contract §8).

Clusters are formed from ranking-time fields only. Within one (scenario, detector,
native_key, host) group, alerts are taken in arrival order (timestamp, then tie hash).
The first unassigned alert opens a cluster and is its representative; later alerts with
timestamp < representative timestamp + W join it. The window is anchored at the
representative (it does not extend with each member), so membership is decided at
arrival time and labels never form or suppress a cluster.

Evaluation units are kept separate:

* ``original``: every alert, its own labels (primary static metrics).
* ``representative_own``: queue of representatives, each with only its *own* labels.
* ``static_cluster``: queue of representatives carrying the cluster outcome (any member
  positive, maximum member severity, union of member intervals). This is explicitly
  static; it has no time dimension and is never used for time-based metrics.
* chronological coverage (:func:`interval_detection_times`): an interval is detected only
  by an investigated alert whose own timestamp lies in it, at that alert's investigation
  time. Suppressed members confer nothing, so a future member can never give a
  representative an earlier detection time.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from soc_alert_ranking.revision.labels import ScenarioLabels

WINDOWS_SECONDS = (60, 300, 900)


@dataclass(frozen=True)
class Clusters:
    window_seconds: float
    cluster_id: np.ndarray        # per alert, cluster index within the queue
    representative: np.ndarray    # bool per alert
    representative_of: np.ndarray # per alert, queue index of its cluster representative

    @property
    def n_clusters(self) -> int:
        return int(self.representative.sum())


def assign_clusters(detector: np.ndarray, native_key: np.ndarray, host: np.ndarray, timestamp: np.ndarray,
                    hash_key: np.ndarray, window_seconds: float) -> Clusters:
    """Anchored-window clusters for one scenario queue."""

    n = len(timestamp)
    frame = pd.DataFrame({"detector": np.asarray(detector).astype(str), "key": np.asarray(native_key).astype(str),
                          "host": np.asarray(host).astype(str), "t": np.asarray(timestamp, dtype=float),
                          "h": np.asarray(hash_key, dtype=np.uint64), "i": np.arange(n)})
    frame = frame.sort_values(["detector", "key", "host", "t", "h"], kind="mergesort")
    group_start = (frame[["detector", "key", "host"]] != frame[["detector", "key", "host"]].shift()).any(axis=1).to_numpy()
    times = frame["t"].to_numpy()
    positions = frame["i"].to_numpy()
    cluster_id = np.empty(n, dtype=np.int64)
    representative = np.zeros(n, dtype=bool)
    representative_of = np.empty(n, dtype=np.int64)
    current = -1
    anchor_time = 0.0
    anchor_index = -1
    for row in range(n):
        if group_start[row] or times[row] >= anchor_time + window_seconds:
            current += 1
            anchor_time = times[row]
            anchor_index = positions[row]
            representative[anchor_index] = True
        cluster_id[positions[row]] = current
        representative_of[positions[row]] = anchor_index
    return Clusters(float(window_seconds), cluster_id, representative, representative_of)


@dataclass(frozen=True)
class ClusterLabelSummary:
    clusters: int
    mixed_label_clusters: int              # both interval-labeled positives and negatives among members
    member_conferred_positive_clusters: int # representative negative, some member positive
    multi_interval_clusters: int           # members fall in more than one critical interval


def static_cluster_labels(labels: ScenarioLabels, clusters: Clusters) -> tuple[ScenarioLabels, np.ndarray, ClusterLabelSummary]:
    """Static cluster outcome on representatives; returns (labels, representative positions, summary)."""

    reps = np.flatnonzero(clusters.representative)
    index_of_cluster = {int(clusters.cluster_id[r]): k for k, r in enumerate(reps)}
    member_cluster = np.array([index_of_cluster[int(c)] for c in clusters.cluster_id])
    m = len(reps)

    def any_by_cluster(values: np.ndarray) -> np.ndarray:
        out = np.zeros((m,) + values.shape[1:], dtype=bool)
        np.logical_or.at(out, member_cluster, values.astype(bool))
        return out

    y = any_by_cluster(labels.y)
    negatives = any_by_cluster(~labels.y)
    s_star = np.zeros(m)
    np.maximum.at(s_star, member_cluster, labels.s_star)
    s_star = np.where(y, s_star, 0.0)
    critical_membership = any_by_cluster(labels.critical_membership)
    summary = ClusterLabelSummary(
        clusters=m,
        mixed_label_clusters=int((y & negatives).sum()),
        member_conferred_positive_clusters=int((y & ~labels.y[reps]).sum()),
        multi_interval_clusters=int((critical_membership.sum(axis=1) > 1).sum()),
    )
    cluster_labels = labels.replace_arrays(
        alert_ids=labels.alert_ids[reps], y=y, s_star=s_star, z=y & (s_star >= labels.tau), r=np.where(y, s_star, 0.0),
        phase_membership=any_by_cluster(labels.phase_membership), critical_membership=critical_membership,
    )
    return cluster_labels, reps, summary


def interval_detection_times(investigation_time: dict[int, float], timestamps: np.ndarray,
                             labels: ScenarioLabels) -> list[float | None]:
    """Earliest detection time per critical interval under chronological investigation.

    ``investigation_time`` maps queue positions of investigated alerts to the time their
    investigation starts. Only an investigated alert whose own timestamp lies in an
    interval detects it. Investigating an alert before it arrives is an error.
    """

    detected: list[float | None] = [None] * labels.critical_membership.shape[1]
    for position, start in investigation_time.items():
        if start < timestamps[position]:
            raise ValueError(f"alert {position} investigated at {start} before arrival {timestamps[position]}")
        for interval in np.flatnonzero(labels.critical_membership[position]):
            if detected[interval] is None or start < detected[interval]:
                detected[interval] = float(start)
    return detected

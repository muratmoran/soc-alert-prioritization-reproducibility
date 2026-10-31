"""Independent reference for WP5 replay, for verification only.

Written from docs/revision/wp5/replay_specification.md with plain loops over alert dicts and a
full backlog scan at every decision. It shares no code with soc_alert_ranking.revision (no
numpy ordering helpers, no production rank or prefix structure), so agreement is evidence.
Alerts: dicts with id, t, score (None or NaN = missing), y, z, intervals (set of labels).
"""

from __future__ import annotations

import hashlib
import math


def tie_hash(alert_id):
    return int.from_bytes(hashlib.sha256(f"cose04000|{alert_id}".encode()).digest()[:8], "big")


def missing(score):
    return score is None or (isinstance(score, float) and math.isnan(score))


def priority(alert):
    return (1 if missing(alert["score"]) else 0, 0.0 if missing(alert["score"]) else -alert["score"], alert["t"], tie_hash(alert["id"]))


def simulate(alerts, rate_per_hour):
    service = 3600.0 / rate_per_hour
    if not alerts:
        return []
    t0 = min(a["t"] for a in alerts)
    horizon = max(a["t"] for a in alerts)
    done = set()
    trace = []
    free = t0
    while True:
        waiting = [a for a in alerts if a["t"] <= free and a["id"] not in done]
        if waiting:
            now = free
        else:
            later = [a["t"] for a in alerts if a["t"] > free and a["id"] not in done]
            if not later:
                break
            now = min(later)
            waiting = [a for a in alerts if a["t"] <= now and a["id"] not in done]
        if now > horizon:
            break
        waiting.sort(key=priority)
        best = waiting[0]
        tie = len(waiting) > 1 and (best["score"] == waiting[1]["score"] or (missing(best["score"]) and missing(waiting[1]["score"])))
        trace.append({"id": best["id"], "start": now, "backlog": len(waiting), "tie": bool(tie)})
        done.add(best["id"])
        free = now + service
    return trace


def metrics(alerts, trace, rate_per_hour, defined_intervals, delays_hours=(1, 4, 24)):
    service = 3600.0 / rate_per_hour
    t0 = min(a["t"] for a in alerts)
    horizon = max(a["t"] for a in alerts)
    by_id = {a["id"]: a for a in alerts}
    started = {row["id"]: row["start"] for row in trace}
    critical = [a for a in alerts if a["z"]]
    out = {
        "investigations": len(trace),
        "fp_investigations": sum(1 for row in trace if not by_id[row["id"]]["y"]),
        "critical_investigations": sum(1 for row in trace if by_id[row["id"]]["z"]),
        "starved_critical": sum(1 for a in critical if a["id"] not in started),
        "backlog_at_horizon": len(alerts) - len(trace),
        "peak_backlog": max([row["backlog"] for row in trace] + [len(alerts) - len(trace)]),
        "tie_decided_selections": sum(1 for row in trace if row["tie"]),
    }
    busy = sum(min(row["start"] + service, horizon) - row["start"] for row in trace)
    out["busy_seconds"] = busy
    out["idle_seconds"] = (horizon - t0) - busy
    span = horizon - t0
    out["time_average_backlog"] = None if span == 0 else sum((started.get(a["id"], horizon) - a["t"]) for a in alerts) / span
    for d in delays_hours:
        limit = d * 3600.0
        hit = sum(1 for a in critical if a["id"] in started and started[a["id"]] - a["t"] <= limit)
        out[f"critical_recall_within_{d}h"] = None if not critical else hit / len(critical)
    out["critical_recall_by_horizon"] = None if not critical else (len(critical) - out["starved_critical"]) / len(critical)
    covered = censored = 0
    delays = []
    intervals = {}
    for label in defined_intervals:
        inside = [a for a in alerts if label in a["intervals"]]
        if not inside:
            intervals[label] = {"eligible": False, "detected": False}
            continue
        first = min(a["t"] for a in inside)
        starts = [started[a["id"]] for a in inside if a["id"] in started]
        if starts:
            covered += 1
            delays.append(min(starts) - first)
            intervals[label] = {"eligible": True, "detected": True, "delay": min(starts) - first}
        else:
            censored += 1
            intervals[label] = {"eligible": True, "detected": False, "censoring": horizon - first}
    out["covered_intervals"] = covered
    out["censored_intervals"] = censored
    out["uninvestigated_intervals"] = len(defined_intervals) - covered
    out["intervals"] = intervals
    for d in delays_hours:
        out[f"intervals_covered_within_{d}h"] = sum(1 for x in delays if x <= d * 3600.0)
    return out

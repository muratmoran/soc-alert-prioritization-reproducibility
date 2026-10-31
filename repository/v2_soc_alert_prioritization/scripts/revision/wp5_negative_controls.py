#!/usr/bin/env python
"""WP5: show that the replay tests detect injected event-handling and metric defects.

Each control replaces one production function (in every loaded module bound to it) with a
deliberately defective variant, runs the WP5 tests, and records failures. A control is
detected only if at least one test fails and none errors. Synthetic data only.
Writes docs/revision/wp5/negative_controls.json.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import sys
import unittest
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import test_wp5_replay  # noqa: E402,F401
from soc_alert_ranking.revision import replay  # noqa: E402

TESTS = "test_wp5_replay"


def run(names: list[str]) -> dict[str, int]:
    suite = unittest.TestSuite()
    for name in names:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors)}


@contextlib.contextmanager
def patched(obj, name, value):
    original = getattr(obj, name)
    bound = [m for m in list(sys.modules.values()) if m is not None and m is not obj and getattr(m, name, None) is original]
    setattr(obj, name, value)
    for module in bound:
        setattr(module, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)
        for module in bound:
            setattr(module, name, original)


def defective_replay(lookahead=0.0, strict_arrivals=False, drain=False, preempt=False, hash_descending=False, prefer=None):
    """A plain replay with one injected defect (kept independent of the production structure)."""

    def simulate(scores, timestamps, hash_keys, rate_per_hour):
        scores = np.asarray(scores, dtype=float)
        t = np.asarray(timestamps, dtype=float)
        h = np.asarray(hash_keys, dtype=np.uint64)
        n = len(t)
        service = replay.HOUR / rate_per_hour
        hash_key = (np.iinfo(np.uint64).max - h) if hash_descending else h
        primary = np.where(np.isnan(scores), np.inf, -scores)
        keys = (hash_key, t, primary) if prefer is None else (hash_key, t, primary, ~prefer)  # label-aware: positives first
        order = np.lexsort(keys)
        rank = np.empty(n, dtype=np.int64)
        rank[order] = np.arange(n)
        t0, horizon = float(t.min()), float(t.max())
        done = np.zeros(n, dtype=bool)
        free = t0
        selected, starts, sizes, ties = [], [], [], []
        while True:
            visible = (t < free) if strict_arrivals else (t <= free + lookahead)
            waiting = visible & ~done
            if waiting.any():
                now = free
            else:
                later = t[(t > free) & ~done]
                if not len(later):
                    break
                now = float(later.min())
                waiting = ((t < now) if strict_arrivals else (t <= now + lookahead)) & ~done
                if not waiting.any():
                    waiting = (t <= now) & ~done
            if now > horizon and not drain:
                break
            candidates = np.flatnonzero(waiting)
            best = int(candidates[np.argmin(rank[candidates])])
            done[best] = True
            selected.append(best)
            starts.append(now)
            sizes.append(len(candidates))
            ties.append(False)
            free = now + (service / 2 if preempt else service)
            if drain and done.all():
                break
        return replay.ReplayTrace(rate_per_hour, service, t0, horizon, np.array(selected, dtype=np.int64), np.array(starts, dtype=float),
                                  np.array(sizes, dtype=np.int64), np.array(ties, dtype=bool), n)
    return simulate


def main() -> int:
    controls = []

    def control(description, patches, tests):
        with contextlib.ExitStack() as stack:
            for obj, name, value in patches:
                stack.enter_context(patched(obj, name, value))
            outcome = run(tests)
        detected = outcome["failures"] > 0 and outcome["errors"] == 0
        controls.append({"control": description, "tests": tests, **outcome, "detected": detected})
        print(f"{'DETECTED' if detected else 'MISSED  '} {description}: {outcome}", flush=True)

    hand = [f"{TESTS}.HandExamples"]
    control("lookahead: alerts arriving during the next service are selectable", [(replay, "replay_alerts", defective_replay(lookahead=10.0))], hand)
    control("selection before enqueuing arrivals at the same instant", [(replay, "replay_alerts", defective_replay(strict_arrivals=True))], hand)
    control("draining after the horizon", [(replay, "replay_alerts", defective_replay(drain=True))], hand)
    control("preemption / two alerts in service", [(replay, "replay_alerts", defective_replay(preempt=True))], hand)
    control("tie hash reversed", [(replay, "replay_alerts", defective_replay(hash_descending=True))],
            [f"{TESTS}.HandExamples.test_arrival_at_completion_is_selectable_and_simultaneous_ties_use_hash", f"{TESTS}.ReferenceAgreement"])

    original_metrics = replay.replay_metrics

    def crediting_at_arrival(trace, labels, timestamps, low_confidence, delays_hours=replay.DELAYS_HOURS):
        record, rows = original_metrics(trace, labels, timestamps, low_confidence, delays_hours)
        for row in rows:
            if row["detected"]:
                row["delay_hours"] = 0.0
        record["median_delay_hours_detected"] = 0.0 if record["median_delay_hours_detected"] is not None else None
        return record, rows

    control("interval credited at the detecting alert's arrival instead of investigation start",
            [(replay, "replay_metrics", crediting_at_arrival)], hand + [f"{TESTS}.ReferenceAgreement"])

    def recall_over_investigated(trace, labels, timestamps, low_confidence, delays_hours=replay.DELAYS_HOURS):
        record, rows = original_metrics(trace, labels, timestamps, low_confidence, delays_hours)
        investigated_critical = record["critical_investigations"]
        for d in delays_hours:
            if record[f"critical_recall_within_{d}h"] is not None and investigated_critical:
                record[f"critical_recall_within_{d}h"] = record[f"critical_recall_within_{d}h"] * record["critical_total"] / investigated_critical
        return record, rows

    control("critical recall within delay divided by investigated critical alerts only",
            [(replay, "replay_metrics", recall_over_investigated)], hand + [f"{TESTS}.ReferenceAgreement"])

    def censoring_dropped(trace, labels, timestamps, low_confidence, delays_hours=replay.DELAYS_HOURS):
        record, rows = original_metrics(trace, labels, timestamps, low_confidence, delays_hours)
        record["censored_intervals"] = 0
        record["uninvestigated_intervals"] = record["defined_intervals"] - record["eligible_intervals"]
        return record, rows

    control("censored and uninvestigated intervals not reported", [(replay, "replay_metrics", censoring_dropped)],
            hand + [f"{TESTS}.ReferenceAgreement"])

    def backlog_over_investigated(trace, labels, timestamps, low_confidence, delays_hours=replay.DELAYS_HOURS):
        record, rows = original_metrics(trace, labels, timestamps, low_confidence, delays_hours)
        t = np.asarray(timestamps, dtype=float)
        span = trace.horizon_end - trace.t0
        record["time_average_backlog"] = float(np.sum(trace.start - t[trace.selected])) / span if span else None
        return record, rows

    control("time-average backlog counts investigated alerts only", [(replay, "replay_metrics", backlog_over_investigated)],
            hand + [f"{TESTS}.ReferenceAgreement"])

    original_replay = replay.replay_alerts
    leaked = {}

    def label_aware(scores, timestamps, hash_keys, rate_per_hour):
        # uses held-out interval labels captured from the test's label store: selection depends on labels
        key = len(timestamps)
        if key in leaked:
            return defective_replay(prefer=leaked[key])(scores, timestamps, hash_keys, rate_per_hour)
        return original_replay(scores, timestamps, hash_keys, rate_per_hour)

    from soc_alert_ranking.revision.labels import LabelStore
    original_replace = LabelStore.replace

    def capture_replace(self, scenario, labels):
        leaked[len(labels.y)] = np.asarray(labels.y, dtype=bool)
        return original_replace(self, scenario, labels)

    control("selection depends on held-out labels", [(replay, "replay_alerts", label_aware), (LabelStore, "replace", capture_replace)],
            [f"{TESTS}.LabelInvariance"])

    original_check = replay.check_trace

    def lenient_check(trace, scores, timestamps, hash_keys, sample_seed=42, sample=50):
        result = original_check(trace, scores, timestamps, hash_keys, sample_seed, sample)
        result.violations = [v for v in result.violations if "before arrival" not in v and "overlapping" not in v]
        return result

    control("trace checker ignores selection before arrival and overlapping service", [(replay, "check_trace", lenient_check)],
            [f"{TESTS}.Integrity.test_forged_traces_are_rejected"])

    record = {
        "work_package": "WP5 chronological replay",
        "note": "Synthetic data only. Detected means at least one test failed and none errored.",
        "controls": controls,
        "all_detected": all(c["detected"] for c in controls),
        "test_module_sha256": hashlib.sha256((PROJECT_ROOT / "tests/test_wp5_replay.py").read_bytes()).hexdigest(),
    }
    out = PROJECT_ROOT / "docs/revision/wp5/negative_controls.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps({"all_detected": record["all_detected"], "controls": len(controls)}))
    return 0 if record["all_detected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

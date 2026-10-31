"""WP5: chronological replay (hand examples, independent reference, integrity checks, label invariance)."""

from __future__ import annotations

import dataclasses
import math
import unittest

import numpy as np
import pandas as pd

import wp5_reference_replay as ref
from wp2_fixtures import synthetic_setup
from wp3_support import PHASES, SEVERITY
from soc_alert_ranking.revision.features import stable_hash_keys
from soc_alert_ranking.revision.labels import build_scenario_labels, intervals_from_frame
from soc_alert_ranking.revision.replay import arrival_order, check_trace, replay_alerts, replay_metrics

TAU = 8.0


def run(alerts, rate, intervals=()):
    ids = np.array([a["id"] for a in alerts], dtype=object)
    t = np.array([a["t"] for a in alerts], dtype=float)
    scores = np.array([np.nan if a["score"] is None else a["score"] for a in alerts], dtype=float)
    hashes = stable_hash_keys(ids.tolist())
    trace = replay_alerts(scores, t, hashes, rate)
    frame = intervals_from_frame(pd.DataFrame(list(intervals), columns=["scenario", "attack", "start", "end"]), SEVERITY, TAU) \
        if intervals else intervals_from_frame(pd.DataFrame([{"scenario": "ex", "attack": "dirb", "start": -10.0, "end": -5.0}]), SEVERITY, TAU)
    labels = build_scenario_labels("ex", ids, t, frame, PHASES, TAU)
    record, rows = replay_metrics(trace, labels, t, np.zeros(len(alerts), dtype=bool))
    return trace, record, rows, ids, (scores, t, hashes), labels


def selected_ids(trace, ids):
    return [ids[i] for i in trace.selected]


class HandExamples(unittest.TestCase):
    def test_no_lookahead_non_preemption_idle_and_accounting(self):
        alerts = [{"id": "a", "t": 0.0, "score": 1.0}, {"id": "b", "t": 5.0, "score": 100.0},
                  {"id": "c", "t": 0.0, "score": 0.5}, {"id": "d", "t": 100.0, "score": 0.0}]
        trace, record, _, ids, inputs, _ = run(alerts, 360.0)          # service 10 s
        self.assertEqual(selected_ids(trace, ids), ["a", "b", "c", "d"])  # b arrives during a's service and waits
        np.testing.assert_array_equal(trace.start, [0.0, 10.0, 20.0, 100.0])
        self.assertEqual((trace.busy_seconds, trace.idle_seconds), (30.0, 70.0))
        self.assertTrue(check_trace(trace, *inputs).passed)

    def test_arrival_at_completion_is_selectable_and_simultaneous_ties_use_hash(self):
        alerts = [{"id": "a", "t": 0.0, "score": 1.0}, {"id": "b", "t": 0.0, "score": 0.0},
                  {"id": "c", "t": 10.0, "score": 5.0}, {"id": "d", "t": 10.0, "score": 5.0},
                  {"id": "e", "t": 40.0, "score": -1.0}]
        trace, _, _, ids, inputs, _ = run(alerts, 360.0)
        first_tied, second_tied = sorted(["c", "d"], key=ref.tie_hash)
        self.assertEqual(selected_ids(trace, ids), ["a", first_tied, second_tied, "b", "e"])
        np.testing.assert_array_equal(trace.start, [0.0, 10.0, 20.0, 30.0, 40.0])
        np.testing.assert_array_equal(trace.tie_decided, [False, True, False, False, False])
        np.testing.assert_array_equal(trace.backlog_at_selection, [2, 3, 2, 1, 1])
        self.assertTrue(check_trace(trace, *inputs).passed)

    def test_missing_scores_last_then_oldest_then_hash(self):
        alerts = [{"id": "x", "t": 0.0, "score": None}, {"id": "w", "t": 0.0, "score": None},
                  {"id": "y", "t": 1.0, "score": 2.0}, {"id": "v", "t": 20.0, "score": None}]
        trace, _, _, ids, _, _ = run(alerts, 360.0)
        first = min(["x", "w"], key=ref.tie_hash)
        other = "w" if first == "x" else "x"
        # at t = 20 the older missing-score alert beats v; the next free time 30 exceeds T = 20, so v is censored
        self.assertEqual(selected_ids(trace, ids), [first, "y", other])
        self.assertTrue(trace.tie_decided[0])

    def test_metrics_intervals_boundaries_delays_and_backlog(self):
        intervals = [{"scenario": "ex", "attack": "dirb", "start": 0.0, "end": 50.0},
                     {"scenario": "ex", "attack": "dnsteal", "start": 100.0, "end": 200.0},
                     {"scenario": "ex", "attack": "webshell", "start": 300.0, "end": 310.0},
                     {"scenario": "ex", "attack": "privilege_escalation", "start": 400.0, "end": 500.0}]
        alerts = [{"id": "n1", "t": 0.0, "score": 5.0}, {"id": "n2", "t": 100.0, "score": 1.0},
                  {"id": "n3", "t": 150.0, "score": 3.0}, {"id": "n4", "t": 200.0, "score": 9.0},
                  {"id": "n5", "t": 305.0, "score": 0.0}, {"id": "n6", "t": 600.0, "score": 2.0}]
        trace, record, rows, ids, inputs, _ = run(alerts, 36.0, intervals)       # service 100 s
        self.assertEqual(selected_ids(trace, ids), ["n1", "n2", "n4", "n3", "n5", "n6"])
        np.testing.assert_array_equal(trace.start, [0.0, 100.0, 200.0, 300.0, 400.0, 600.0])
        expected = {"investigations": 6, "fp_investigations": 2, "positive_investigations": 4, "critical_investigations": 3,
                    "critical_total": 3, "starved_critical": 0, "critical_recall_by_horizon": 1.0,
                    "critical_recall_within_1h": 1.0, "defined_intervals": 3, "eligible_intervals": 2, "covered_intervals": 2,
                    "uninvestigated_intervals": 1, "censored_intervals": 0, "busy_seconds": 500.0, "idle_seconds": 100.0,
                    "peak_backlog": 2, "backlog_at_horizon": 0, "wait_median_seconds": 0.0, "wait_max_seconds": 150.0}
        for key, value in expected.items():
            self.assertEqual(record[key], value, key)
        self.assertAlmostEqual(record["time_average_backlog"], 245.0 / 600.0, places=12)
        by_phase = {r["interval"].split("|")[1]: r for r in rows}
        self.assertEqual((by_phase["dnsteal"]["delay_hours"], by_phase["webshell"]["delay_hours"]), (0.0, 95.0 / 3600))
        self.assertFalse(by_phase["privilege_escalation"]["eligible"])
        self.assertEqual(record["median_delay_hours_detected"], 47.5 / 3600)
        self.assertTrue(check_trace(trace, *inputs).passed)

    def test_horizon_censoring_and_recall_denominators(self):
        intervals = [{"scenario": "ex", "attack": "dnsteal", "start": 100.0, "end": 200.0},
                     {"scenario": "ex", "attack": "webshell", "start": 300.0, "end": 310.0}]
        alerts = [{"id": "n1", "t": 0.0, "score": 5.0}, {"id": "n2", "t": 100.0, "score": 1.0},
                  {"id": "n3", "t": 150.0, "score": 3.0}, {"id": "n4", "t": 200.0, "score": 9.0},
                  {"id": "n5", "t": 305.0, "score": 0.0}, {"id": "n6", "t": 600.0, "score": 2.0}]
        trace, record, rows, ids, inputs, _ = run(alerts, 14.4, intervals)       # service 250 s
        self.assertEqual(selected_ids(trace, ids), ["n1", "n4", "n3"])            # next free time 750 > T = 600
        self.assertEqual(record["starved_critical"], 2)
        self.assertAlmostEqual(record["critical_recall_within_1h"], 1 / 3)
        self.assertAlmostEqual(record["critical_recall_by_horizon"], 1 / 3)
        self.assertEqual(record["critical_arriving_after_T_minus_1h"], 3)
        self.assertEqual((record["covered_intervals"], record["censored_intervals"]), (1, 1))
        webshell = [r for r in rows if "webshell" in r["interval"]][0]
        self.assertTrue(webshell["censored"])
        self.assertAlmostEqual(webshell["censoring_hours"], 295.0 / 3600)
        self.assertAlmostEqual(record["restricted_mean_delay_hours_lower_bound"], (400.0 + 295.0) / 2 / 3600)
        self.assertEqual(record["backlog_at_horizon"], 3)
        self.assertEqual(trace.busy_seconds, 250.0 + 250.0 + 100.0)
        self.assertTrue(check_trace(trace, *inputs).passed)

    def test_service_in_progress_at_horizon_counts_and_is_truncated(self):
        alerts = [{"id": "a", "t": 0.0, "score": 1.0}, {"id": "b", "t": 5.0, "score": 2.0}]
        trace, record, _, ids, inputs, _ = run(alerts, 360.0)
        self.assertEqual(selected_ids(trace, ids), ["a"])     # next free time 10 > T = 5
        self.assertEqual((trace.busy_seconds, trace.idle_seconds), (5.0, 0.0))
        self.assertTrue(check_trace(trace, *inputs).passed)


def random_instance(rng, n):
    phases = ["dnsteal", "webshell", "dirb", "privilege_escalation", "network_scans"]
    intervals = []
    for phase in phases:
        if rng.random() < 0.8:
            start = float(rng.integers(0, 60))
            intervals.append({"scenario": "ex", "attack": phase, "start": start, "end": start + float(rng.integers(1, 25))})
    alerts = []
    for i in range(n):
        score = rng.choice([None, 0.0, 1.0, 1.0, 2.5, 5.0, float(rng.integers(0, 4))])
        alerts.append({"id": f"r{rng.integers(1_000_000)}-{i}", "t": float(rng.integers(0, 80)), "score": score})
    return alerts, intervals


class ReferenceAgreement(unittest.TestCase):
    def test_random_instances_match_reference_trace_and_metrics(self):
        rng = np.random.default_rng(2026)
        for trial in range(150):
            alerts, intervals = random_instance(rng, int(rng.integers(1, 45)))
            rate = float(rng.choice([360.0, 720.0, 1800.0, 3600.0, 144.0]))
            trace, record, rows, ids, inputs, labels = run(alerts, rate, intervals)
            label_of = {a["id"]: i for i, a in enumerate(alerts)}
            interval_names = list(labels.critical_interval_ids)
            ref_alerts = [{**a, "y": bool(labels.y[label_of[a["id"]]]), "z": bool(labels.z[label_of[a["id"]]]),
                           "intervals": {interval_names[c] for c in np.flatnonzero(labels.critical_membership[label_of[a["id"]]])}}
                          for a in alerts]
            expected = ref.simulate(ref_alerts, rate)
            with self.subTest(trial=trial):
                self.assertEqual(selected_ids(trace, ids), [row["id"] for row in expected])
                np.testing.assert_array_equal(trace.start, [row["start"] for row in expected])
                np.testing.assert_array_equal(trace.backlog_at_selection, [row["backlog"] for row in expected])
                np.testing.assert_array_equal(trace.tie_decided, [row["tie"] for row in expected])
                ref_metrics = ref.metrics(ref_alerts, expected, rate, interval_names)
                for key, value in ref_metrics.items():
                    if key == "intervals":
                        continue
                    if value is None or record[key] is None:
                        self.assertEqual(record[key], value, key)
                    else:
                        self.assertTrue(math.isclose(record[key], value, rel_tol=0, abs_tol=1e-9), (key, record[key], value))
                for row in rows:
                    info = ref_metrics["intervals"][row["interval"]]
                    self.assertEqual((row["eligible"], row["detected"]), (info["eligible"], info["detected"]))
                    if info["detected"]:
                        self.assertAlmostEqual(row["delay_hours"] * 3600, info["delay"], places=9)
                    elif info["eligible"]:
                        self.assertAlmostEqual(row["censoring_hours"] * 3600, info["censoring"], places=9)
                self.assertTrue(check_trace(trace, *inputs).passed, check_trace(trace, *inputs).violations)


class Integrity(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(5)
        self.alerts, self.intervals = random_instance(rng, 60)
        self.trace, _, _, self.ids, self.inputs, _ = run(self.alerts, 720.0, self.intervals)
        self.assertTrue(check_trace(self.trace, *self.inputs).passed)

    def forged(self, **changes):
        return check_trace(dataclasses.replace(self.trace, **changes), *self.inputs)

    def test_forged_traces_are_rejected(self):
        scores, t, hashes = self.inputs
        start = self.trace.start.copy()
        late = int(np.argmax(t))
        faults = {
            "selection before arrival": dict(selected=np.r_[late, self.trace.selected[1:]]) if self.trace.selected[0] != late else None,
            "overlapping service": dict(start=np.r_[start[0], start[1:] - 1.0]) if len(start) > 1 else None,
            "after the horizon": dict(start=np.r_[start[:-1], t.max() + 1.0]),
            "not the best-ranked": dict(selected=self.trace.selected[::-1].copy()) if len(start) > 2 else None,
            "investigated twice": dict(selected=np.r_[self.trace.selected[:-1], self.trace.selected[0]]) if len(start) > 1 else None,
            "idle at": dict(start=np.r_[start[:1], start[1:] + 5.0]) if len(start) > 1 else None,
        }
        for expected_violation, change in faults.items():
            if change is None:
                continue
            with self.subTest(fault=expected_violation):
                result = self.forged(**change)
                self.assertFalse(result.passed)
                self.assertTrue(any(expected_violation in v for v in result.violations), result.violations)

    def test_arrivals_identical_across_rankers(self):
        scores, t, hashes = self.inputs
        rng = np.random.default_rng(0)
        first = arrival_order(t, hashes)
        for _ in range(5):
            other = replay_alerts(rng.normal(size=len(t)), t, hashes, 720.0)
            np.testing.assert_array_equal(arrival_order(t, hashes), first)
            self.assertEqual((other.t0, other.horizon_end, other.arrivals), (self.trace.t0, self.trace.horizon_end, self.trace.arrivals))


class LabelInvariance(unittest.TestCase):
    def test_label_mutation_changes_metrics_not_traces(self):
        config, _, ranking, store, pipeline = synthetic_setup()
        held_out = ranking.scenarios[0]
        result = pipeline.run_outer_fold(held_out, config.primary_policy)
        rows = ranking.rows(held_out)
        t, hashes = rows["timestamp"].to_numpy(float), rows["hash_key"].to_numpy(np.uint64)
        labels = store.labels[held_out]
        traces = {cid: replay_alerts(scores, t, hashes, 12.0) for cid, scores in result.outer_scores.items()}
        before = {cid: replay_metrics(tr, labels, t, np.zeros(len(t), dtype=bool))[0] for cid, tr in traces.items()}
        rng = np.random.default_rng(1)
        mutated = labels.replace_arrays(y=rng.random(len(t)) < 0.5, z=rng.random(len(t)) < 0.2,
                                        critical_membership=rng.random(labels.critical_membership.shape) < 0.3)
        store.replace(held_out, mutated)
        again = pipeline.run_outer_fold(held_out, config.primary_policy)
        for cid, scores in again.outer_scores.items():
            retrace = replay_alerts(scores, t, hashes, 12.0)
            np.testing.assert_array_equal(retrace.selected, traces[cid].selected)
            np.testing.assert_array_equal(retrace.start, traces[cid].start)
        changed = sum(replay_metrics(traces[c], mutated, t, np.zeros(len(t), dtype=bool))[0] != before[c] for c in traces)
        self.assertGreater(changed, 0)


if __name__ == "__main__":
    unittest.main()

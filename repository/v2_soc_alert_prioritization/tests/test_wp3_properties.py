"""WP3: randomized agreement between production metrics and the independent reference."""

from __future__ import annotations

import math
import unittest

import numpy as np
import pandas as pd

import wp3_reference_metrics as ref
from wp3_support import PHASES, SEVERITY, reference_severity_table
from soc_alert_ranking.revision.duplicates import assign_clusters
from soc_alert_ranking.revision.evaluation import full_order
from soc_alert_ranking.revision.features import stable_hash_keys
from soc_alert_ranking.revision.labels import build_scenario_labels, intervals_from_frame
from soc_alert_ranking.revision.metrics import (
    COVERAGE_TARGETS, K_GRID, QUEUE_FRACTIONS, RECALL_TARGETS, ceil_fraction, effort_to_critical_recall,
    effort_to_interval_coverage, first_critical_rank, metrics_at_k, queue_fraction_budget, queue_report, score_availability,
)
from soc_alert_ranking.revision.ties import expected_under_random_ties, permuted_order, tie_diagnostics

PHASE_NAMES = ["dirb", "webshell", "dnsteal", "privilege_escalation", "cracking", "service_stop"]


def random_case(rng, n_alerts, overlapping):
    intervals = []
    cursor = 0.0
    for _ in range(int(rng.integers(1, 6))):
        start = cursor + float(rng.integers(0, 30))
        end = start + float(rng.integers(1, 60))
        intervals.append({"scenario": "ex", "attack": str(rng.choice(PHASE_NAMES)), "start": start, "end": end})
        cursor = start if overlapping else end
    if rng.random() < 0.3:
        intervals.append(dict(intervals[0]))           # exact duplicate row
    rng.shuffle(intervals)
    horizon = max(i["end"] for i in intervals) + 20
    # timestamps include exact interval boundaries
    boundaries = [i["start"] for i in intervals] + [i["end"] for i in intervals]
    times = np.concatenate([rng.choice(boundaries, size=n_alerts // 3), rng.integers(0, int(horizon), n_alerts - n_alerts // 3)]).astype(float)
    scores = rng.choice([np.nan, 0.0, 1.0, 2.0, 2.5, 3.0], size=n_alerts)
    ids = [f"x{i}" for i in range(n_alerts)]
    return intervals, times, scores, ids


def build(intervals, times, scores, ids, tau=8.0):
    frame = intervals_from_frame(pd.DataFrame(intervals), SEVERITY, tau)
    labels = build_scenario_labels("ex", np.array(ids, dtype=object), times, frame, PHASES, tau)
    order = full_order(scores, times, stable_hash_keys(ids))
    ref_alerts = [{"id": i, "t": float(t), "score": (None if np.isnan(s) else float(s))} for i, t, s in zip(ids, times, scores)]
    ref_intervals = [{"scenario": r["scenario"], "phase": r["attack"], "start": r["start"], "end": r["end"]} for r in intervals]
    ref_labelled, keys = ref.reference_labels(ref_alerts, ref_intervals, reference_severity_table(), tau)
    return labels, order, ref.reference_order(ref_labelled), keys


def assert_close(testcase, a, b, label):
    if a is None or b is None:
        testcase.assertEqual(a, b, label)
    else:
        testcase.assertTrue(math.isclose(float(a), float(b), rel_tol=1e-12, abs_tol=1e-12), f"{label}: {a} vs {b}")


class RandomizedAgreement(unittest.TestCase):
    def test_labels_order_and_all_budgets_match_reference(self):
        rng = np.random.default_rng(2026)
        for trial in range(60):
            n = int(rng.integers(0, 40))
            intervals, times, scores, ids = random_case(rng, n, overlapping=trial % 2 == 0)
            for tau in (7.0, 8.0, 9.0):
                labels, order, ref_ordered, keys = build(intervals, times, scores, ids, tau)
                self.assertEqual([ids[i] for i in order], [a["id"] for a in ref_ordered])
                for k in (1, 2, 5, 10, 25, 1000):
                    production = metrics_at_k(order, labels, k).to_record()
                    reference = ref.reference_at_k(ref_ordered, keys, k)
                    for metric, value in reference.items():
                        assert_close(self, production[metric], value, f"trial {trial} tau {tau} {metric}@{k}")
                for fraction in QUEUE_FRACTIONS:
                    self.assertEqual(queue_fraction_budget(n, fraction), ref.reference_fraction_budget(n, fraction))
                for target in RECALL_TARGETS:
                    effort = effort_to_critical_recall(order, labels, target)
                    expected = ref.reference_effort_critical(ref_ordered, target)
                    self.assertEqual(effort.position, None if expected is None else expected["position"])
                for target in COVERAGE_TARGETS:
                    effort = effort_to_interval_coverage(order, labels, target)
                    expected = ref.reference_effort_coverage(ref_ordered, target)
                    self.assertEqual(effort.position, None if expected is None else expected["position"])
                self.assertEqual(first_critical_rank(order, labels).position, ref.reference_first_critical(ref_ordered))

    def test_label_file_order_never_changes_labels(self):
        rng = np.random.default_rng(7)
        for trial in range(40):
            intervals, times, scores, ids = random_case(rng, 30, overlapping=True)
            base, *_ = build(intervals, times, scores, ids)
            for _ in range(5):
                shuffled = list(intervals)
                rng.shuffle(shuffled)
                other, *_ = build(shuffled, times, scores, ids)
                for field in ("y", "s_star", "z", "r", "phase_membership", "critical_membership"):
                    np.testing.assert_array_equal(getattr(base, field), getattr(other, field))

    def test_tie_expectations_match_exhaustive_enumeration(self):
        rng = np.random.default_rng(11)
        checked = 0
        while checked < 25:
            n = int(rng.integers(2, 9))
            intervals, times, _, ids = random_case(rng, n, overlapping=False)
            scores = rng.choice([1.0, 2.0, 3.0], size=n)
            labels, order, ref_ordered, keys = build(intervals, times, scores, ids)
            if math.prod(math.factorial(len(b)) for b in ref.score_blocks(ref_ordered)) > 5000:
                continue
            for k in (1, 2, 3, n):
                expected = expected_under_random_ties(scores, labels, k)
                for field, metric in (("expected_negatives_in_top", "negatives_in_top"),
                                      ("expected_critical_recall", "critical_recall"),
                                      ("expected_attack_recall", "attack_recall"),
                                      ("expected_ndcg_linear", "ndcg_linear")):
                    reference = ref.reference_at_k(ref_ordered, keys, k)[metric]
                    brute = None if reference is None else ref.brute_force_expectation(ref_ordered, keys, k, metric)
                    assert_close(self, getattr(expected, field), brute, f"{field}@{k}")
            checked += 1

    def test_permutations_only_reorder_within_score_blocks_and_are_seeded(self):
        rng = np.random.default_rng(5)
        scores = rng.choice([np.nan, 1.0, 2.0, 3.0], size=500)
        declared = full_order(scores, rng.random(500), np.arange(500, dtype=np.uint64))
        for seed in range(20):
            permuted = permuted_order(scores, seed)
            ordered_scores = scores[permuted]
            np.testing.assert_array_equal(np.nan_to_num(ordered_scores, nan=-1), np.nan_to_num(scores[declared], nan=-1))
            np.testing.assert_array_equal(permuted, permuted_order(scores, seed))
        self.assertFalse(np.array_equal(permuted_order(scores, 0), permuted_order(scores, 1)))

    def test_tie_diagnostic_invariants(self):
        rng = np.random.default_rng(3)
        for _ in range(50):
            n = int(rng.integers(0, 300))
            scores = rng.choice([np.nan, 0.0, 1.0, 2.0], size=n)
            order = full_order(scores, rng.random(n), np.arange(n, dtype=np.uint64))
            d = tie_diagnostics(scores, order)
            if n:
                self.assertEqual(d["alerts_in_tied_blocks"] + (d["blocks"] - d["tied_blocks"]), n)
            for row in d["cutoffs"]:
                self.assertLessEqual(row["members_selected_by_tie_rule"], row["positions_in_tied_blocks"])
                if row["crosses_cutoff"]:
                    self.assertGreater(row["cutoff_block_size"], 1)

    def test_clusters_match_reference(self):
        rng = np.random.default_rng(9)
        for _ in range(30):
            n = int(rng.integers(1, 80))
            alerts = [{"id": f"c{i}", "t": float(rng.integers(0, 400)), "detector": str(rng.choice(["w", "s"])),
                       "key": str(rng.choice(["k1", "k2"])), "host": str(rng.choice(["h1", "h2", ""]))} for i in range(n)]
            for window in (60.0, 300.0):
                clusters = assign_clusters(np.array([a["detector"] for a in alerts]), np.array([a["key"] for a in alerts]),
                                           np.array([a["host"] for a in alerts]), np.array([a["t"] for a in alerts]),
                                           stable_hash_keys([a["id"] for a in alerts]), window)
                expected = ref.reference_clusters(alerts, window)
                self.assertEqual({alerts[i]["id"]: alerts[clusters.representative_of[i]]["id"] for i in range(n)}, expected)
                reps = clusters.representative_of
                for i in range(n):  # no member precedes its representative, and all are inside its window
                    self.assertGreaterEqual(alerts[i]["t"], alerts[reps[i]]["t"])
                    self.assertLess(alerts[i]["t"], alerts[reps[i]]["t"] + window)

    def test_float_ceilings_agree_with_exact_arithmetic_for_declared_fractions(self):
        counts = np.arange(1, 2_000_001, dtype=np.int64)
        for fraction in set(RECALL_TARGETS) | set(COVERAGE_TARGETS) | set(QUEUE_FRACTIONS):
            exact = -((-fraction.numerator * counts) // fraction.denominator)
            np.testing.assert_array_equal(np.ceil(float(fraction) * counts).astype(np.int64), exact)
        self.assertEqual(ceil_fraction(QUEUE_FRACTIONS[0], 1001), 2)

    def test_score_availability(self):
        self.assertFalse(score_availability(np.array([np.nan, np.nan])).ordering_defined)
        record = score_availability(np.array([np.nan, 1.0, 2.0, np.nan]))
        self.assertEqual((record.missing, record.missing_rate, record.ordering_defined), (2, 0.5, True))
        self.assertIsNone(score_availability(np.array([])).missing_rate)

    def test_queue_report_is_complete(self):
        rng = np.random.default_rng(1)
        intervals, times, scores, ids = random_case(rng, 30, overlapping=False)
        labels, order, *_ = build(intervals, times, scores, ids)
        report = queue_report(order, labels)
        self.assertEqual(len(report["budgets"]), len(K_GRID) + len(QUEUE_FRACTIONS))
        self.assertEqual(len(report["effort"]), len(RECALL_TARGETS) + len(COVERAGE_TARGETS))
        with self.assertRaises(ValueError):
            queue_report(order[:-1], labels)


if __name__ == "__main__":
    unittest.main()

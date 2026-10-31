"""WP2: interval labels (v1.1), queue ordering and the selection metrics, on hand-built examples."""

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

import wp2_fixtures  # noqa: F401  (sets sys.path)
from soc_alert_ranking.mappings.severity import SeverityMapping
from soc_alert_ranking.revision.evaluation import full_order, selection_metrics, top_k_order
from soc_alert_ranking.revision.features import stable_hash_keys
from soc_alert_ranking.revision.labels import build_scenario_labels, intervals_from_frame, phase_order


SEVERITY = SeverityMapping.from_file()
PHASES = phase_order(SEVERITY)


def intervals(rows):
    return intervals_from_frame(pd.DataFrame(rows, columns=["scenario", "attack", "start", "end"]), SEVERITY, 8.0)


class IntervalLabels(unittest.TestCase):
    def setUp(self) -> None:
        self.iv = intervals([
            ("s", "cracking", 10, 20),        # 6.5, not critical
            ("s", "webshell", 15, 25),        # 8.5, critical, overlaps cracking
            ("s", "webshell", 15, 25),        # exact duplicate, counted once
            ("s", "webshell", 40, 50),        # distinct repeat, separate interval
            ("s", "dnsteal", 90, 100),        # critical, no alerts below
        ])

    def test_duplicates_repeats_and_validation(self):
        self.assertEqual(len(self.iv), 4)
        self.assertEqual(int(self.iv["critical"].sum()), 3)
        with self.assertRaises(ValueError):
            intervals([("s", "not_a_phase", 1, 2)])
        with self.assertRaises(ValueError):
            intervals([("s", "dirb", 5, 5)])

    def test_all_overlapping_intervals_half_open(self):
        t = np.array([10.0, 15.0, 20.0, 25.0, 45.0, 5.0])
        labels = build_scenario_labels("s", np.array([f"a{i}" for i in range(6)]), t, self.iv, PHASES, 8.0)
        np.testing.assert_array_equal(labels.y, [True, True, True, False, True, False])
        np.testing.assert_allclose(labels.s_star, [6.5, 8.5, 8.5, 0.0, 8.5, 0.0])
        np.testing.assert_array_equal(labels.z, [False, True, True, False, True, False])
        np.testing.assert_allclose(labels.r, labels.s_star)
        phase = {p: labels.phase_membership[:, PHASES.index(p)] for p in ("cracking", "webshell")}
        np.testing.assert_array_equal(phase["cracking"], [True, True, False, False, False, False])
        np.testing.assert_array_equal(phase["webshell"], [False, True, True, False, True, False])
        self.assertEqual(labels.defined_critical_intervals, 3)
        self.assertEqual(labels.critical_membership.shape, (6, 3))
        self.assertEqual(labels.critical_membership.sum(axis=0).tolist(), [2, 1, 0])


class Ordering(unittest.TestCase):
    def test_rule_order_and_row_order_independence(self):
        ids = np.array(["x", "y", "z", "w", "v"])
        scores = np.array([1.0, np.nan, 2.0, 1.0, 1.0])
        timestamps = np.array([5.0, 1.0, 9.0, 5.0, 3.0])
        hashes = stable_hash_keys(ids)
        order = ids[full_order(scores, timestamps, hashes)]
        self.assertEqual(order[0], "z")
        self.assertEqual(order[1], "v")
        self.assertEqual(order[-1], "y")
        tied = [i for i in ("x", "w")]
        expected_tied = sorted(tied, key=lambda i: int(stable_hash_keys([i])[0]))
        self.assertEqual(list(order[2:4]), expected_tied)
        perm = np.array([3, 0, 4, 2, 1])
        self.assertEqual(list(ids[perm][full_order(scores[perm], timestamps[perm], hashes[perm])]), list(order))

    def test_hash_keys_are_salted_sha256_prefixes(self):
        import hashlib

        expected = int.from_bytes(hashlib.sha256(b"cose04000|ait-7").digest()[:8], "big")
        self.assertEqual(int(stable_hash_keys(["ait-7"])[0]), expected)

    def test_top_k_matches_full_order_under_heavy_ties(self):
        rng = np.random.default_rng(11)
        for trial in range(30):
            n = int(rng.integers(1, 400))
            scores = rng.choice([0.0, 1.0, 2.0, np.nan], size=n)
            timestamps = rng.choice([1.0, 2.0, 3.0], size=n)
            hashes = rng.permutation(n).astype(np.uint64)
            full = full_order(scores, timestamps, hashes)
            for k in (1, 5, 50, 100, n, n + 3):
                np.testing.assert_array_equal(top_k_order(scores, timestamps, hashes, k), full[:k])


class SelectionMetricsByHand(unittest.TestCase):
    def setUp(self) -> None:
        iv = intervals([("s", "webshell", 0, 10), ("s", "dnsteal", 20, 30), ("s", "reverse_shell", 50, 60),
                        ("s", "dirb", 30, 40)])
        # alerts: 0 webshell, 1 webshell, 2 dnsteal, 3 dirb, 4 benign, 5 benign
        t = np.array([1.0, 2.0, 25.0, 35.0, 45.0, 46.0])
        self.labels = build_scenario_labels("s", np.array([f"a{i}" for i in range(6)]), t, iv, PHASES, 8.0)

    def test_values(self):
        order = np.array([4, 0, 1, 3, 2, 5])
        m = selection_metrics(order, self.labels, 3)
        self.assertEqual(m.fp, 1)
        self.assertEqual((m.eligible_intervals, m.defined_intervals, m.covered_intervals), (2, 3, 1))
        self.assertAlmostEqual(m.coverage, 0.5)
        self.assertAlmostEqual(m.coverage_all_defined, 1 / 3)
        r = self.labels.r  # [8.5, 8.5, 9, 3, 0, 0]
        dcg = r[4] / np.log2(2) + r[0] / np.log2(3) + r[1] / np.log2(4)
        idcg = 9.0 / np.log2(2) + 8.5 / np.log2(3) + 8.5 / np.log2(4)
        self.assertAlmostEqual(m.ndcg, dcg / idcg)
        self.assertFalse(m.queue_shorter_than_k)

    def test_short_queue_and_not_applicable(self):
        m = selection_metrics(np.array([4, 5, 0, 1, 2, 3]), self.labels, 100)
        self.assertTrue(m.queue_shorter_than_k)
        self.assertEqual(m.fp, 2)
        self.assertEqual(m.coverage, 1.0)
        benign = self.labels.replace_arrays(r=np.zeros(6), y=np.zeros(6, bool),
                                            critical_membership=np.zeros((6, 3), bool))
        m = selection_metrics(np.arange(6), benign, 3)
        self.assertIsNone(m.ndcg)
        self.assertIsNone(m.coverage)
        self.assertEqual(m.coverage_all_defined, 0.0)
        self.assertEqual(m.fp, 3)


if __name__ == "__main__":
    unittest.main()

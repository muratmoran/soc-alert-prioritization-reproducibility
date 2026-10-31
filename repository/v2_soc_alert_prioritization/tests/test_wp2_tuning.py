"""WP2: lexicographic selection rules of protocol v1.1 §6.4 on hand-built inner metric tables."""

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

import wp2_fixtures  # noqa: F401
from soc_alert_ranking.revision.tuning import PRIMARY, SECONDARY, select_candidate


def inner(rows):
    """rows: (candidate_id, grid_index, n_nonzero, scenario, coverage, fp, ndcg)."""

    frame = pd.DataFrame(rows, columns=["candidate_id", "grid_index", "n_nonzero", "inner_scenario", "coverage", "fp", "ndcg"])
    frame["family"] = "F"
    return frame


def two_scenarios(candidates):
    """candidates: (id, grid_index, n_nonzero, (cov1, fp1, ndcg1), (cov2, fp2, ndcg2))."""

    rows = []
    for cid, grid, nz, first, second in candidates:
        rows.append((cid, grid, nz, "s1", *first))
        rows.append((cid, grid, nz, "s2", *second))
    return inner(rows)


class PrimaryRule(unittest.TestCase):
    def test_coverage_dominates_false_positives(self):
        record = select_candidate(two_scenarios([
            ("A", 0, 1, (0.8, 90, 0.1), (0.8, 90, 0.1)),
            ("B", 1, 1, (0.6, 1, 0.9), (0.6, 1, 0.9)),
        ]))
        self.assertEqual(record.selected_candidate, "A")
        self.assertEqual(record.remaining_after_steps["coverage"], 1)

    def test_ties_break_by_fp_then_ndcg_then_simplicity_then_grid(self):
        base = (0.5, 10, 0.4)
        cases = [
            ([("A", 0, 1, base, base), ("B", 1, 1, (0.5, 8, 0.1), (0.5, 8, 0.1))], "B"),
            ([("A", 0, 1, base, base), ("B", 1, 1, (0.5, 10, 0.6), (0.5, 10, 0.6))], "B"),
            ([("A", 0, 2, base, base), ("B", 1, 1, base, base)], "B"),
            ([("A", 3, 1, base, base), ("B", 1, 1, base, base)], "B"),
        ]
        for rows, expected in cases:
            self.assertEqual(select_candidate(two_scenarios(rows)).selected_candidate, expected)

    def test_macro_averages_not_pooled_and_tolerance_is_roundoff_only(self):
        record = select_candidate(two_scenarios([
            ("A", 0, 1, (1.0, 10, 0.5), (0.0, 10, 0.5)),     # macro coverage 0.5
            ("B", 1, 1, (0.5, 9, 0.5), (0.5 + 5e-13, 9, 0.5)),  # macro 0.5 + 2.5e-13 -> tie, lower FP wins
        ]))
        self.assertEqual(record.selected_candidate, "B")
        record = select_candidate(two_scenarios([
            ("A", 0, 1, (1.0, 10, 0.5), (0.0, 10, 0.5)),
            ("B", 1, 1, (0.5, 9, 0.5), (0.5 - 1e-9, 9, 0.5)),   # genuinely lower coverage
        ]))
        self.assertEqual(record.selected_candidate, "A")

    def test_common_eligibility_denominators_and_fallbacks(self):
        record = select_candidate(two_scenarios([
            ("A", 0, 1, (np.nan, 10, np.nan), (0.4, 10, 0.3)),
            ("B", 1, 1, (np.nan, 5, np.nan), (0.2, 5, 0.9)),
        ]))
        self.assertEqual((record.coverage_scenarios, record.fp_scenarios, record.ndcg_scenarios), (1, 2, 1))
        self.assertEqual(record.selected_candidate, "A")
        self.assertAlmostEqual(record.macro_coverage, 0.4)
        record = select_candidate(two_scenarios([
            ("A", 0, 1, (np.nan, 10, 0.5), (np.nan, 10, 0.5)),
            ("B", 1, 1, (np.nan, 5, 0.1), (np.nan, 5, 0.1)),
        ]))
        self.assertTrue(record.coverage_fallback)
        self.assertIsNone(record.macro_coverage)
        self.assertEqual(record.selected_candidate, "B")

    def test_inconsistent_or_incomplete_tables_are_rejected(self):
        with self.assertRaises(ValueError):
            select_candidate(two_scenarios([
                ("A", 0, 1, (np.nan, 10, 0.5), (0.4, 10, 0.5)),
                ("B", 1, 1, (0.3, 5, 0.1), (0.4, 5, 0.1)),
            ]))
        frame = two_scenarios([("A", 0, 1, (0.5, 1, 0.5), (0.5, 1, 0.5)), ("B", 1, 1, (0.5, 1, 0.5), (0.5, 1, 0.5))])
        with self.assertRaises(ValueError):
            select_candidate(frame.iloc[:-1])
        with self.assertRaises(ValueError):
            select_candidate(frame.assign(family=["F", "G"] * 2))


class SecondaryRule(unittest.TestCase):
    def test_ndcg_only_then_simplicity(self):
        rows = [
            ("A", 0, 1, (0.9, 1, 0.2), (0.9, 1, 0.2)),
            ("B", 1, 2, (0.1, 99, 0.8), (0.1, 99, 0.8)),
            ("C", 2, 1, (0.1, 99, 0.8), (0.1, 99, 0.8)),
        ]
        self.assertEqual(select_candidate(two_scenarios(rows), SECONDARY).selected_candidate, "C")
        self.assertEqual(select_candidate(two_scenarios(rows), PRIMARY).selected_candidate, "A")

    def test_ndcg_fallback_flag(self):
        rows = [("A", 0, 1, (0.5, 3, np.nan), (0.5, 3, np.nan)), ("B", 1, 0, (0.5, 3, np.nan), (0.5, 3, np.nan))]
        record = select_candidate(two_scenarios(rows), SECONDARY)
        self.assertTrue(record.ndcg_fallback)
        self.assertEqual(record.selected_candidate, "B")


if __name__ == "__main__":
    unittest.main()

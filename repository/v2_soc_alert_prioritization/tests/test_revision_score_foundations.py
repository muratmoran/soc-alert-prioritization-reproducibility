"""Fast algebra/domain checks for WP1; no dataset or third-party dependencies."""

import math
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from soc_alert_ranking.rankers.revision_scores import (
    constrained_linear_log_score as constrained,
    exponential_discount_score as exponential,
    gaussian_membership,
    linear_log_score as historical,
    monotone_kappa_limit,
    severity_coefficient,
)


class ScoreFoundations(unittest.TestCase):
    def test_historical_counterexample_reverses_severity_and_asset_importance(self):
        self.assertLess(historical(9, 0.5, 0.05, 1), historical(5, 0.5, 0.05, 1))
        self.assertLess(historical(5, 0.5, 0.05, 1), historical(2.5, 0.5, 0.05, 1))

    def test_severity_difference_equals_total_derivative(self):
        for u in (0, 0.1, 0.35, 0.5):
            for h in (0.05, 0.2, 0.95, 1):
                for k in (0, 0.5, 1, 2):
                    delta = historical(9, u, h, k) - historical(3, u, h, k)
                    self.assertAlmostEqual(delta / 6, severity_coefficient(u, h, k))

    def test_global_bound_and_boundary(self):
        limit = monotone_kappa_limit()
        self.assertAlmostEqual(limit, 0.6676164013906681)
        self.assertAlmostEqual(severity_coefficient(0.5, 0.05, limit), 0)
        self.assertLess(severity_coefficient(0.5, 0.05, limit * 1.000001), 0)
        with self.assertRaises(ValueError):
            constrained(5, 0.5, 0.05, limit)

    def test_declared_constrained_grid_increases_in_severity(self):
        for k in (0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.6676):
            for u in (0, 0.1, 0.35, 0.5):
                for h in (0.05, 0.2, 0.95, 1):
                    self.assertGreater(constrained(9, u, h, k), constrained(3, u, h, k))

    def test_reliability_and_uncertainty_directions(self):
        for score in (historical, exponential):
            self.assertGreater(score(5, 0.5, 0.95, 0.5), score(5, 0.5, 0.05, 0.5))
            self.assertGreater(score(5, 0.1, 0.05, 0.5), score(5, 0.5, 0.05, 0.5))

    def test_limiting_cases_are_explicit(self):
        for score in (historical, constrained, exponential):
            self.assertEqual(score(5, 0, 0.05, 0.5), 5)
            self.assertEqual(score(5, 0.5, 1, 0.5), 5)
            self.assertEqual(score(5, 0.5, 0.05, 0), 5)
            self.assertEqual(score(0, 0.5, 0.05, 0.5), 0)
        self.assertEqual(monotone_kappa_limit(0, 0.05), math.inf)
        self.assertEqual(monotone_kappa_limit(0.5, 1), math.inf)

    def test_monotonicity_does_not_prevent_deferral(self):
        # An unknown alert can remain behind mapped reconnaissance even when
        # increasing severity would increase its score. No truth label is input.
        self.assertLess(constrained(5, 0.5, 0.05, 0.5), constrained(3, 0.1, 0.95, 0.5))
        self.assertLess(exponential(5, 0.5, 0.05, 1), exponential(3, 0.1, 0.95, 1))

    def test_exponential_dominates_linear_pointwise_but_changes_pair_order(self):
        for u in (0, 0.1, 0.5):
            for h in (0.05, 0.5, 1):
                self.assertGreaterEqual(exponential(5, u, h, 1), historical(5, u, h, 1))
        # t=2 for A, t=0 for B. A's pointwise improvement reverses their order.
        self.assertLess(historical(10, 1, math.exp(-2), 1), historical(1, 0, 1, 1))
        self.assertGreater(exponential(10, 1, math.exp(-2), 1), exponential(1, 0, 1, 1))

    def test_invalid_inputs_rejected_without_imputation_or_clipping(self):
        for score in (historical, constrained, exponential):
            for args in ((-1, .1, .5, .5), (1, -.1, .5, .5), (1, .1, 0, .5),
                         (1, .1, 1.1, .5), (1, .1, .5, -1), (math.nan, .1, .5, .5),
                         (1, math.inf, .5, .5), (1, .1, math.nan, .5)):
                with self.subTest(score=score.__name__, args=args), self.assertRaises(ValueError):
                    score(*args)
        for args in ((1, .6, .5, .5), (1, .1, .01, .5), (1, .1, .5, 1)):
            with self.assertRaises(ValueError):
                constrained(*args)

    def test_membership_zero_spread_and_symmetric_positive_spread(self):
        self.assertEqual(gaussian_membership(5, 5, 0, .2), .2)
        self.assertEqual(gaussian_membership(4, 5, 0, .2), 0)
        self.assertEqual(gaussian_membership(4, 5, .5, .2), gaussian_membership(6, 5, .5, .2))
        self.assertAlmostEqual(gaussian_membership(6, 5, 1, .2), .2 * math.exp(-.5))
        with self.assertRaises(ValueError):
            gaussian_membership(5, 5, -1, .2)

    def test_underflow_is_not_silently_a_strictly_increasing_score(self):
        with self.assertRaises(ValueError):
            exponential(1, 1000, .05, 1)
        with self.assertRaises(ValueError):
            exponential(1e-320, 1, .05, 8)


if __name__ == "__main__":
    unittest.main()

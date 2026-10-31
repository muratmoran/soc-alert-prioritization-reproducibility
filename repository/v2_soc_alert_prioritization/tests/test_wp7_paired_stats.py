"""WP7: exact sign-flip test and Holm adjustment against brute force and hand values."""

from __future__ import annotations

import itertools
import unittest
from fractions import Fraction

import numpy as np

import wp2_fixtures  # noqa: F401  (sets sys.path)
from soc_alert_ranking.revision.paired_stats import holm_adjust, sign_flip_test


def brute_force_p(differences):
    d = [Fraction(x).limit_denominator(10**9) for x in differences]
    n = len(d)
    observed = abs(sum(d))
    count = 0
    for signs in itertools.product((1, -1), repeat=n):
        if abs(sum(s * x for s, x in zip(signs, d))) >= observed:
            count += 1
    return Fraction(count, 2 ** n)


class SignFlip(unittest.TestCase):
    def test_hand_values(self):
        self.assertEqual(sign_flip_test([1] * 8).p_two_sided, 2 / 256)          # all eight agree
        self.assertEqual(sign_flip_test([0] * 8).p_two_sided, 1.0)             # no difference at all
        result = sign_flip_test([2, 0, 0, 0, 0, 0, 0, -2])
        self.assertEqual((result.positive, result.negative, result.zero, result.p_two_sided), (1, 1, 6, 1.0))
        self.assertEqual(sign_flip_test([1, 1, 1, 1, 1, 1, 1, -1]).p_two_sided, 18 / 256)  # |sum| >= 6: 9 patterns each sign
        self.assertEqual(sign_flip_test([1] * 8).min_attainable_p, 2 / 256)

    def test_random_against_brute_force(self):
        rng = np.random.default_rng(11)
        for _ in range(200):
            n = int(rng.integers(1, 9))
            d = rng.choice([-3, -1, -0.5, 0, 0, 0.25, 1, 2, 4], size=n)
            self.assertAlmostEqual(sign_flip_test(d).p_two_sided, float(brute_force_p(d)), places=12)

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            sign_flip_test([])
        with self.assertRaises(ValueError):
            sign_flip_test([1.0, float("nan")])


class Holm(unittest.TestCase):
    def test_hand_values(self):
        np.testing.assert_allclose(holm_adjust([0.01, 0.04, 0.03, 0.5]), [0.04, 0.09, 0.09, 0.5])
        np.testing.assert_allclose(holm_adjust([0.0078125] * 6), [0.046875] * 6)
        np.testing.assert_allclose(holm_adjust([1.0, 0.2]), [1.0, 0.4])

    def test_monotone_and_bounded(self):
        rng = np.random.default_rng(3)
        for _ in range(100):
            p = rng.random(int(rng.integers(1, 10)))
            adjusted = holm_adjust(p)
            order = np.argsort(p, kind="stable")
            self.assertTrue(np.all(np.diff(adjusted[order]) >= -1e-15))
            self.assertTrue(np.all(adjusted >= p - 1e-15) and np.all(adjusted <= 1.0))


if __name__ == "__main__":
    unittest.main()

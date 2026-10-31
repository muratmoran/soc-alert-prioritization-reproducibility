"""WP2: configuration schema, grids, family formulas and learned-sample rules."""

from __future__ import annotations

import copy
import math
import unittest

import numpy as np

from wp2_fixtures import CONFIG_PATH, toy_features
from soc_alert_ranking.config import load_yaml
from soc_alert_ranking.revision.config import ConfigError, load_comparison_config, validate_raw
from soc_alert_ranking.revision.evaluation import full_order
from soc_alert_ranking.revision.families import (
    Candidate, DomainError, TrainingSample, draw_training_rows, equalizing_weights, fit_learner, score_closed_form,
    validate_inputs,
)


def candidate(family: str, **params) -> Candidate:
    return Candidate(family, tuple(params.items()), 0, 0)


class ConfigSchema(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = load_yaml(CONFIG_PATH)
        self.config = load_comparison_config(CONFIG_PATH)

    def test_protocol_grid_sizes_and_unique_ids(self):
        sizes = {name: len(spec.candidates) for name, spec in self.config.families.items() if spec.tuned}
        self.assertEqual(sum(sizes.values()), 145)
        self.assertEqual(sum(len(spec.candidates) for spec in self.config.families.values() if not spec.tuned), 12)
        self.assertEqual(sizes["A_additive"], 66)
        ids = [c.candidate_id for spec in self.config.families.values() for c in spec.candidates]
        self.assertEqual(len(ids), len(set(ids)))
        registry = self.config.registry()
        self.assertEqual(registry["registry_sha256"], self.config.registry()["registry_sha256"])

    def test_additive_simplex_sums_to_one_on_tenths(self):
        for c in self.config.families["A_additive"].candidates:
            p = c.params_dict
            self.assertAlmostEqual(p["a"] + p["b"] + p["d"], 1.0, places=12)
            for value in p.values():
                self.assertAlmostEqual(value * 10, round(value * 10), places=9)

    def test_config_drift_is_rejected(self):
        edits = [
            lambda r: r["grids"]["W"]["alpha"].pop(),
            lambda r: r["evaluation"].__setitem__("tau", 7.0),
            lambda r: r["grids"]["S1"]["kappa"].__setitem__(-1, 0.6677),
            lambda r: r["policies"]["primary"].__setitem__("context", "asset_profile"),
            lambda r: r["reliability"].__setitem__("class_lambda", 40),
            lambda r: r.__setitem__("extra_setting", True),
            lambda r: r["learned"].__setitem__("max_training_alerts", True),
        ]
        for edit in edits:
            raw = copy.deepcopy(self.raw)
            edit(raw)
            with self.assertRaises(ConfigError):
                validate_raw(raw)

    def test_simplicity_counts(self):
        fams = self.config.families
        w = {c.params_dict["alpha"]: c.n_nonzero for c in fams["W_weighted"].candidates}
        self.assertEqual((w[0.0], w[0.5], w[1.0]), (1, 2, 1))
        a = {tuple(c.params_dict.values()): c.n_nonzero for c in fams["A_additive"].candidates}
        self.assertEqual(a[(0.0, 0.0, 1.0)], 1)
        self.assertEqual(a[(0.2, 0.3, 0.5)], 3)
        m = {tuple(c.params_dict.values()): c.n_nonzero for c in fams["M_multiplicative"].candidates}
        self.assertEqual(m[(0.0, 0.0)], 0)
        self.assertEqual(fams["S1_linear_log_constrained"].candidates[0].n_nonzero, 0)
        self.assertTrue(fams["S1_linear_log_constrained"].heuristic_label)
        self.assertIn("not a Gaussian derivation", fams["S2_exponential_discount"].heuristic_label)


class FamilyFormulas(unittest.TestCase):
    def setUp(self) -> None:
        self.f = toy_features()

    def assertScores(self, family, expected, **params):
        np.testing.assert_allclose(score_closed_form(candidate(family, **params), self.f), expected, rtol=0, atol=1e-6)

    def test_hand_calculated_values(self):
        self.assertScores("H_weighted", [3.65, 4.95, 1.5])
        self.assertScores("W_weighted", [0.185, 0.755, 0.35], alpha=0.3)
        self.assertScores("A_additive", [-0.175, 0.475, 0.04], a=0.2, b=0.5, d=0.3)
        self.assertScores("M_multiplicative", [5 * 0.05**2 * math.exp(-0.5), 3 * 0.95**2 * math.exp(-0.1), 0.0], a=2.0, b=1.0)
        self.assertScores("P_probability_proxy", [0.25, 2.85, 0.0])
        self.assertScores("C_cost_sensitive", [-2.125, 2.725, -1.25], c_fp=2.5)
        self.assertScores("S0_linear_log_historical", [-2.489331, 2.984612, 0.0], kappa=1.0)
        self.assertScores("S1_linear_log_constrained", [1.255335, 2.992306, 0.0], kappa=0.5)
        self.assertScores("S2_exponential_discount", [1.118034, 2.984652, 0.0], kappa=1.0)
        self.assertScores("R_key_reliability", [0.2, 0.9, 0.6])
        self.assertScores("R_severity_key_reliability", [1.0, 2.7, 0.0])
        self.assertScores("S1_linear_log_constrained_key", [5 * (1 + 0.25 * math.log(0.2)), 3 * (1 + 0.05 * math.log(0.9)), 0.0], kappa=0.5)
        self.assertScores("O_severity", [5.0, 3.0, 0.0])
        self.assertScores("O_reliability", [0.05, 0.95, 0.5])
        self.assertScores("O_oldest_first", [-10.0, -20.0, -30.0])
        self.assertScores("O_newest_first", [10.0, 20.0, 30.0])

    def test_equivalences_are_exact(self):
        rng = np.random.default_rng(3)
        f = toy_features(c=rng.uniform(0, 10, 200), u=rng.uniform(0, 0.5, 200), h=rng.uniform(0.05, 0.95, 200),
                         h_key=rng.uniform(0.05, 0.95, 200), timestamp=rng.uniform(0, 100, 200),
                         hash_key=np.arange(200, dtype=np.uint64), alert_ids=np.arange(200).astype(str),
                         native_score=np.zeros(200), detector=np.array(["wazuh"] * 200),
                         mapped=np.ones(200, bool), h_fallback=np.zeros(200, np.int8), h_key_fallback=np.zeros(200, np.int8))
        np.testing.assert_array_equal(score_closed_form(candidate("C_cost_sensitive", c_fp=0.0), f),
                                      score_closed_form(candidate("P_probability_proxy"), f))
        cost = score_closed_form(candidate("C_cost_sensitive", c_fp=5.0), f)
        equivalent = f.h * (f.c + 5.0)
        np.testing.assert_array_equal(np.argsort(-cost, kind="mergesort"), np.argsort(-equivalent, kind="mergesort"))
        key_level_p = toy_features(c=f.c, u=f.u, h=f.h_key, h_key=f.h_key, timestamp=f.timestamp, hash_key=f.hash_key,
                                   alert_ids=f.alert_ids, native_score=f.native_score, detector=f.detector,
                                   mapped=f.mapped, h_fallback=f.h_fallback, h_key_fallback=f.h_key_fallback)
        np.testing.assert_array_equal(score_closed_form(candidate("R_severity_key_reliability"), f),
                                      score_closed_form(candidate("P_probability_proxy"), key_level_p))

    def test_native_scores_keep_single_scales_and_missing_values_last(self):
        level = score_closed_form(candidate("O_native_rule_level"), self.f)
        np.testing.assert_array_equal(level, [np.nan, 7.0, 6.0])
        self.assertEqual(full_order(level, self.f.timestamp, self.f.hash_key)[-1], 0)
        severity = score_closed_form(candidate("O_native_suricata_severity"), self.f)
        np.testing.assert_array_equal(severity, [np.nan, np.nan, -2.0])
        self.assertEqual(list(full_order(severity, self.f.timestamp, self.f.hash_key)), [2, 0, 1])
        self.assertNotEqual(level[1], self.f.h[1])

    def test_domain_checks_reject_without_clipping(self):
        with self.assertRaises(DomainError):
            score_closed_form(candidate("S1_linear_log_constrained", kappa=0.6677), self.f)
        with self.assertRaises(DomainError):
            score_closed_form(candidate("S2_exponential_discount", kappa=1e5), self.f)
        for bad in (dict(c=np.array([np.nan, 1.0, 1.0])), dict(u=np.array([0.6, 0.1, 0.1])),
                    dict(h=np.array([0.04, 0.5, 0.5])), dict(c=np.array([11.0, 1.0, 1.0]))):
            with self.assertRaises(DomainError):
                score_closed_form(candidate("H_weighted"), toy_features(**bad))
        with self.assertRaises(DomainError):
            validate_inputs(np.array([1.0]), np.array([0.1]), np.array([1.0]))


class LearnedSampling(unittest.TestCase):
    def test_training_rows_ignore_row_order_and_respect_cap(self):
        rng = np.random.default_rng(0)
        ids = {s: np.array([f"{s}-{i}" for i in range(400)]) for s in ("a", "b", "c")}
        hashes = {s: rng.integers(0, 2**62, 400).astype(np.uint64) for s in ids}
        chosen = draw_training_rows(ids, hashes, max_rows=500, seed=42)
        self.assertEqual(sum(len(v) for v in chosen.values()), 500)
        selected = {s: set(ids[s][chosen[s]]) for s in ids}
        perm = {s: rng.permutation(400) for s in ids}
        chosen_perm = draw_training_rows({s: ids[s][perm[s]] for s in ids}, {s: hashes[s][perm[s]] for s in ids}, 500, 42)
        self.assertEqual(selected, {s: set(ids[s][perm[s]][chosen_perm[s]]) for s in ids})
        uncapped = draw_training_rows(ids, hashes, max_rows=5000, seed=42)
        self.assertTrue(all(len(v) == 400 for v in uncapped.values()))

    def test_equalizing_weights_give_equal_scenario_totals(self):
        scenarios = np.array(["a"] * 10 + ["b"] * 30 + ["c"] * 60)
        weights = equalizing_weights(scenarios)
        totals = [weights[scenarios == s].sum() for s in ("a", "b", "c")]
        self.assertTrue(np.allclose(totals, totals[0]))
        self.assertAlmostEqual(weights.mean(), 1.0)

    def test_logistic_single_class_uses_logged_constant_probability(self):
        sample = TrainingSample(X=np.column_stack([np.full(20, 5.0), np.full(20, 0.5), np.full(20, 0.5)]),
                                y=np.zeros(20, bool), r=np.zeros(20), weights=np.ones(20),
                                scenarios=np.array(["a"] * 20), alert_ids=np.arange(20).astype(str), sampled_from=20)
        learner = fit_learner(candidate("L1_logistic", C=1.0), sample, 42, {})
        self.assertEqual(learner.fallback, "single_class_constant_probability")
        np.testing.assert_array_equal(learner.score(toy_features()), np.zeros(3))


if __name__ == "__main__":
    unittest.main()

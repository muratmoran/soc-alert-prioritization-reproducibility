"""WP2: mapping/height fitting arithmetic and complete fitting isolation (protocol v1.1 §2, §6.1)."""

from __future__ import annotations

import unittest

import numpy as np

from wp2_fixtures import mutate_scenario_labels, synthetic_setup
from soc_alert_ranking.revision.features import (
    FALLBACK_DETECTOR, FALLBACK_GLOBAL, FitFailure, FittingSettings, InputPolicy, KeyTable,
    apply_class_heights, fit_class_heights, fit_key_heights, fit_mapping,
)
from soc_alert_ranking.revision.labels import LabelAccessError

SETTINGS = FittingSettings()
PHASES = ("dirb", "webshell", "wpscan")


def table(n, positives, phase_positives, scenario="s"):
    return KeyTable(scenario, np.array(n, float), np.array(positives, float), np.array(phase_positives, float))


class MappingArithmetic(unittest.TestCase):
    def test_thresholds_purity_and_alphabetical_ties(self):
        t = table(
            n=[10, 4, 10, 10, 10, 10],
            positives=[8, 4, 10, 4, 4, 5],
            phase_positives=[[8, 0, 0], [4, 0, 0], [6, 4, 0], [2, 2, 0], [0, 0, 4], [5, 0, 5]],
        )
        fit = fit_mapping([t], 6, 3, SETTINGS, frozenset({"s"}))
        np.testing.assert_array_equal(fit.accepted, [True, False, False, False, False, True])
        # key 1 fails support; key 2 purity 0.6; key 3 precision 0.4 (and purity 0.5); key 4 precision 0.4.
        np.testing.assert_allclose(fit.purity[:3], [1.0, 1.0, 0.6])
        self.assertEqual(fit.top_phase[5], 0)          # dirb/wpscan tie (overlapping windows) -> alphabetical
        self.assertAlmostEqual(fit.purity[5], 1.0)     # both phases contain all five positives
        np.testing.assert_array_equal(fit.classes(3), [0, 3, 3, 3, 3, 0])

    def test_tables_are_summed_over_the_fit_set(self):
        a = table([3, 0], [3, 0], [[3, 0, 0], [0, 0, 0]], "a")
        b = table([3, 5], [2, 0], [[2, 0, 0], [0, 0, 0]], "b")
        fit = fit_mapping([a, b], 2, 3, SETTINGS, frozenset({"a", "b"}))
        np.testing.assert_allclose(fit.support, [6, 5])
        self.assertTrue(fit.accepted[0])
        self.assertFalse(fit_mapping([a], 2, 3, SETTINGS, frozenset({"a"})).accepted[0])


class HeightArithmetic(unittest.TestCase):
    def setUp(self) -> None:
        self.key_detector = np.array(["wazuh", "wazuh", "suricata", "aminer"])
        self.class_names = list(PHASES) + ["unknown"]
        # scenario rows: key0 dirb (n=100, pos=90), key1 unknown (n=900, pos=9), key2 unknown (n=50, pos=1)
        self.t = table([100, 900, 50, 0], [90, 9, 1, 0], [[90, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0]])
        self.classes = np.array([0, 3, 3, 3])

    def test_shrinkage_priors_and_clipping(self):
        fit = fit_class_heights([(self.t, self.classes)], self.key_detector, self.class_names, SETTINGS, frozenset({"s"}))
        rows = {(r.detector, r["class"]): r for _, r in fit.table.iterrows()}
        prior = 99 / 1000
        w = 100 / 150
        self.assertAlmostEqual(rows[("wazuh", "dirb")]["unclipped"], w * 0.9 + (1 - w) * prior)
        w = 900 / 950
        self.assertAlmostEqual(rows[("wazuh", "unknown")]["unclipped"], w * 0.01 + (1 - w) * prior)
        self.assertEqual(rows[("wazuh", "unknown")]["height"], 0.05)
        self.assertEqual((rows[("wazuh", "dirb")]["prior_positives"], rows[("wazuh", "dirb")]["prior_n"]), (99, 1000))
        self.assertEqual(fit.global_prior, (100, 1050))

    def test_fallbacks_detector_then_global_then_failure(self):
        fit = fit_class_heights([(self.t, self.classes)], self.key_detector, self.class_names, SETTINGS, frozenset({"s"}))
        heights, fallback = apply_class_heights(fit, np.array([2, 3, 0, 3]), self.key_detector, SETTINGS)
        self.assertEqual(fallback[0], FALLBACK_DETECTOR)     # wazuh wpscan never seen
        self.assertAlmostEqual(heights[0], 99 / 1000)
        self.assertEqual(fallback[2], FALLBACK_DETECTOR)     # suricata dirb unseen; suricata prior 1/50 clipped
        self.assertEqual(heights[2], 0.05)
        self.assertEqual(fallback[3], FALLBACK_GLOBAL)       # aminer has no training rows
        self.assertAlmostEqual(heights[3], 100 / 1050)
        empty = fit_class_heights([], self.key_detector, self.class_names, SETTINGS, frozenset())
        with self.assertRaises(FitFailure):
            apply_class_heights(empty, np.array([0, 0, 0, 0]), self.key_detector, SETTINGS)

    def test_key_heights(self):
        fit = fit_key_heights([self.t], self.key_detector, SETTINGS, frozenset({"s"}))
        w = 100 / 150
        self.assertAlmostEqual(fit.unclipped[0], w * 0.9 + (1 - w) * 99 / 1000)
        self.assertEqual(fit.fallback[3], FALLBACK_GLOBAL)
        self.assertTrue(np.isnan(fit.unclipped[3]))


class FittingIsolation(unittest.TestCase):
    def setUp(self) -> None:
        self.config, self.severity, self.ranking, self.store, self.pipeline = synthetic_setup()
        self.builder = self.pipeline.builder
        self.scenarios = list(self.ranking.scenarios)

    def features(self, target, fit_set, policy=InputPolicy()):
        return self.builder.alert_features(target, fit_set, policy, role="test")

    def test_fit_set_components_never_read_outside_labels(self):
        fit_set = self.scenarios[1:3]
        outside = [s for s in self.scenarios if s not in fit_set]
        with self.store.locked(outside):
            keys = self.builder.key_features(fit_set)
        self.assertEqual(sorted(s for s, _ in keys.crossfit_mapping_sets), sorted(fit_set))
        for row_scenario, mapping_set in keys.crossfit_mapping_sets:
            self.assertNotIn(row_scenario, mapping_set)

    def test_training_scenario_features_exclude_its_own_labels(self):
        training = self.scenarios[1:]
        g = training[0]
        with self.store.locked([g]):
            before = self.features(g, set(training) - {g})
        mutate_scenario_labels(self.store, g, seed=5)
        self.builder.clear_cache()
        after = self.features(g, set(training) - {g})
        for name in ("c", "u", "h", "h_key", "mapped", "h_fallback"):
            np.testing.assert_array_equal(getattr(before, name), getattr(after, name))

    def test_isolation_check_is_sensitive_to_permitted_labels(self):
        training = self.scenarios[1:]
        g, j = training[0], training[1]
        before = self.features(g, set(training) - {g})
        labels = self.store.labels[j]
        self.store.replace(j, labels.replace_arrays(y=np.zeros_like(labels.y), r=np.zeros_like(labels.r),
                                                    z=np.zeros_like(labels.z),
                                                    phase_membership=np.zeros_like(labels.phase_membership)))
        self.builder.clear_cache()
        after = self.features(g, set(training) - {g})
        self.assertFalse(np.array_equal(before.h, after.h) and np.array_equal(before.c, after.c))

    def test_learned_training_sample_is_isolated_and_label_independent(self):
        training = self.scenarios[1:]
        sample = self.pipeline.training_sample(training, InputPolicy(), role="test")
        for g in training:
            mask = sample.scenarios == g
            features = self.features(g, set(training) - {g})
            lookup = dict(zip(features.alert_ids, range(len(features))))
            idx = [lookup[a] for a in sample.alert_ids[mask]]
            np.testing.assert_array_equal(sample.X[mask], np.column_stack([features.c[idx], features.u[idx], features.h[idx]]))
        mutate_scenario_labels(self.store, training[0], seed=9)
        self.builder.clear_cache()
        resampled = self.pipeline.training_sample(training, InputPolicy(), role="test")
        np.testing.assert_array_equal(sample.alert_ids, resampled.alert_ids)
        purposes = [p for s, p in self.store.access_log if "learned_training_targets" in p]
        self.assertTrue(purposes)

    def test_locked_labels_raise(self):
        with self.store.locked([self.scenarios[0]]):
            with self.assertRaises(LabelAccessError):
                self.features(self.scenarios[1], [self.scenarios[0]])


class PipelineIsolation(unittest.TestCase):
    """Held-out and inner-validation label mutations cannot change fitting, selection or scores."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config, _, cls.ranking, cls.store, cls.pipeline = synthetic_setup()
        cls.held_out = cls.ranking.scenarios[0]
        cls.reference = cls.pipeline.run_outer_fold(cls.held_out, cls.config.primary_policy)

    def test_outer_labels_never_accessed_during_fold(self):
        self.assertNotIn(self.held_out, {s for s, _ in self.reference.label_access_log})
        for request in self.reference.manifest:
            self.assertNotIn(self.held_out, request["fit_set"])
            self.assertNotIn(request["target"], request["fit_set"])
            for source in request["height_row_sources"]:
                self.assertNotIn(source["rows_from"], source["mapped_with"])
                self.assertNotIn(self.held_out, source["mapped_with"])

    def test_inner_evaluation_reads_labels_only_after_scoring(self):
        log = self.reference.label_access_log
        for inner in self.reference.training_scenarios:
            own_fold = [(i, p) for i, (s, p) in enumerate(log) if s == inner and f"|inner={inner}:" in p]
            # During its own inner fold the validation scenario is read exactly once, for evaluation,
            # and that read comes after every fitting read of the fold.
            self.assertEqual([p.rsplit(":", 1)[-1] for _, p in own_fold], ["inner_evaluation"])
            fold_reads = [i for i, (s, p) in enumerate(log) if f"|inner={inner}:" in p]
            self.assertEqual(own_fold[0][0], max(fold_reads))

    def test_outer_label_mutation_changes_nothing(self):
        _, _, ranking, store, pipeline = synthetic_setup()
        mutate_scenario_labels(store, self.held_out, seed=21)
        mutated = pipeline.run_outer_fold(self.held_out, self.config.primary_policy)
        self.assertTrue(self.reference.inner_metrics.equals(mutated.inner_metrics))
        self.assertTrue(self.reference.selections.equals(mutated.selections))
        self.assertEqual(sorted(self.reference.outer_scores), sorted(mutated.outer_scores))
        for cid, scores in self.reference.outer_scores.items():
            np.testing.assert_array_equal(scores, mutated.outer_scores[cid])
        self.assertEqual(self.reference.learner_diagnostics, mutated.learner_diagnostics)

    def test_inner_validation_labels_only_change_its_metrics(self):
        _, _, ranking, store, pipeline = synthetic_setup()
        inner = self.reference.training_scenarios[0]
        mutate_scenario_labels(store, inner, seed=33)
        mutated = pipeline.run_outer_fold(self.held_out, self.config.primary_policy)
        ref_other = self.reference.inner_metrics[self.reference.inner_metrics["inner_scenario"] != inner]
        mut_other = mutated.inner_metrics[mutated.inner_metrics["inner_scenario"] != inner]
        # Other inner folds may train on the mutated scenario, so only its own validation fold is compared:
        own_ref = [d for d in self.reference.learner_diagnostics if d["role"] == f"loso:{self.held_out}|inner={inner}"]
        own_mut = [d for d in mutated.learner_diagnostics if d["role"] == f"loso:{self.held_out}|inner={inner}"]
        self.assertEqual(own_ref, own_mut)
        builder_ref = synthetic_setup()[4].builder
        training = [s for s in self.reference.training_scenarios if s != inner]
        f_ref = builder_ref.alert_features(inner, training, self.config.primary_policy, role="test")
        f_mut = pipeline.builder.alert_features(inner, training, self.config.primary_policy, role="test")
        for name in ("c", "u", "h", "h_key"):
            np.testing.assert_array_equal(getattr(f_ref, name), getattr(f_mut, name))
        self.assertEqual(len(ref_other), len(mut_other))


if __name__ == "__main__":
    unittest.main()

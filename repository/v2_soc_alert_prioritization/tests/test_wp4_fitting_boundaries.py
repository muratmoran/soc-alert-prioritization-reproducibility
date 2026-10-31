"""WP4: fitting boundaries (synthetic data only).

* adversarial changes to excluded data: mutate labels, delete rows and add rows of excluded
  identifiers, at identifier level and at class level (a whole mapped class excluded), with
  fitted components, selections and scores compared by key name and alert id;
* cache invalidation by fitting population, label version, exclusion set, reliability policy,
  fitting settings and severity table; read-only label arrays;
* reliability arithmetic against an independent reference, fallbacks, empty and single-class
  training, uncertainty variants;
* split machinery (forward chaining, identifier groups, holdout, unseen identifiers) and the
  learned-family fallback when inner selection is not estimable;
* execution-trace verification on real fold executions, and its sensitivity to forged traces.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import unittest

import numpy as np
import pandas as pd

import wp4_reference_fitting as ref
from wp2_fixtures import CONFIG_PATH
from soc_alert_ranking.mappings.severity import SeverityMapping
from soc_alert_ranking.revision.config import load_comparison_config
from soc_alert_ranking.revision.features import (
    FALLBACK_DETECTOR, FALLBACK_GLOBAL, FitFailure, InputPolicy, RankingFrame, normalized_identifier,
)
from soc_alert_ranking.revision.labels import LabelStore, intervals_from_frame, phase_order
from soc_alert_ranking.revision.pipeline import ComparisonPipeline, simplest_candidate, verify_fold_trace
from soc_alert_ranking.revision.severity_variants import variant
from soc_alert_ranking.revision.splits import (
    OuterSplit, forward_chaining_splits, identifier_groups, identifier_holdout_splits, loso_splits,
    unseen_identifier_mask,
)
from soc_alert_ranking.revision.synthetic import PHASE_WINDOWS, make_synthetic_alerts

CONFIG = load_comparison_config(CONFIG_PATH)
SEVERITY = SeverityMapping.from_file()
PHASES = phase_order(SEVERITY)
BASE_ALERTS, BASE_LABELS = make_synthetic_alerts(4, 500, seed=1)
IDENTIFIER_EXCLUSION = frozenset({("wazuh", "wazuh:dirb")})
CLASS_EXCLUSION = frozenset({("wazuh", "wazuh:dirb"), ("aminer", "aminer:wpscan")})  # every key following dirb/wpscan


def build(alerts: pd.DataFrame, label_frame: pd.DataFrame = BASE_LABELS, config=CONFIG):
    ranking = RankingFrame.from_alerts(alerts)
    intervals = intervals_from_frame(label_frame, SEVERITY, config.tau)
    store = LabelStore.from_alerts(ranking.frame, intervals, PHASES, config.tau)
    return ranking, store, ComparisonPipeline(ranking, store, SEVERITY, config)


def key_signature(pipeline: ComparisonPipeline, fit_set, excluded_names=frozenset(), reliability="detector_class"):
    """Every fitted per-key quantity and every height cell, keyed by names rather than internal ids."""

    ranking = pipeline.ranking
    keys = pipeline.builder.key_features(fit_set, ranking.key_ids_for(excluded_names), reliability)
    per_key = {}
    for k, name in enumerate(zip(ranking.key_detector, ranking.key_name)):
        per_key[(str(name[0]), str(name[1]))] = (
            bool(keys.mapping.accepted[k]), int(keys.classes[k]), float(keys.severity[k]), float(keys.height[k]),
            int(keys.height_fallback[k]), float(keys.key_heights.heights[k]), int(keys.key_heights.fallback[k]),
            tuple(float(keys.u_by_policy[p][k]) for p in sorted(keys.u_by_policy)),
        )
    cells = None if keys.heights is None else (
        keys.heights.table.to_dict(orient="records"), keys.heights.detector_prior, keys.heights.global_prior)
    return per_key, cells


def excluded_rows(ranking: RankingFrame, scenario: str, names) -> np.ndarray:
    rows = ranking.rows(scenario)
    return np.array([(d, k) in names for d, k in zip(rows["detector"], rows["native_key"])])


def mutate_rows(store: LabelStore, scenario: str, mask: np.ndarray, seed: int) -> None:
    """Randomize the labels of selected rows (internally consistent), leaving other rows untouched."""

    rng = np.random.default_rng(seed)
    labels = store.labels[scenario]
    m = int(mask.sum())
    phases = labels.phase_membership.copy()
    phases[mask] = rng.random((m, phases.shape[1])) < 0.5
    y = labels.y.copy()
    y[mask] = phases[mask].any(axis=1)
    s_star = labels.s_star.copy()
    s_star[mask] = np.where(y[mask], rng.uniform(2.0, 9.5, m), 0.0)
    critical = labels.critical_membership.copy()
    critical[mask] = rng.random((m, critical.shape[1])) < 0.3
    store.replace(scenario, labels.replace_arrays(y=y, s_star=s_star, z=y & (s_star >= labels.tau),
                                                  r=np.where(y, s_star, 0.0), phase_membership=phases,
                                                  critical_membership=critical))


def added_excluded_rows(alerts: pd.DataFrame, scenarios, per_scenario: int = 60, seed: int = 7) -> pd.DataFrame:
    """New alerts of an existing excluded key and of a brand-new excluded identifier inside attack windows."""

    rng = np.random.default_rng(seed)
    windows = {phase: (start, end) for phase, start, end in PHASE_WINDOWS}
    frames = []
    for scenario in scenarios:
        offset = 100.0 * int(scenario.removeprefix("scn"))
        for detector, key, phase in (("wazuh", "wazuh:dirb", "webshell"), ("wazuh", "wazuh:newrule", "dirb")):
            start, end = windows[phase]
            frames.append(pd.DataFrame({
                "alert_id": [f"{scenario}-added-{key}-{i}" for i in range(per_scenario)], "scenario": scenario,
                "timestamp": np.round(rng.uniform(start + offset, end + offset, per_scenario), 3),
                "detector": detector, "native_key": key, "native_category": f"{detector}-group",
                "native_name": key.split(":")[1], "native_short": key.split(":")[1], "host": "web-01", "ip": "",
                "detector_score": 10.0, "native_rule_level": 10.0, "native_suricata_severity": np.nan,
                "native_record_type": "wazuh",
            }))
    return pd.concat([alerts, *frames], ignore_index=True)


# ---------------------------------------------------------------------------------------------
class ExcludedIdentifierData(unittest.TestCase):
    """Fitted components ignore every property of excluded identifiers' training alerts."""

    held_out = "scn0"
    training = ("scn1", "scn2", "scn3")

    def fit_set_signatures(self, pipeline, names):
        fit_sets = [self.training, *[tuple(s for s in self.training if s != g) for g in self.training]]
        return {fs: key_signature(pipeline, fs, names) for fs in fit_sets}

    def assert_same_signatures(self, reference, other, keys=None):
        for fit_set, (per_key, cells) in reference.items():
            other_key, other_cells = other[fit_set]
            names = keys if keys is not None else per_key.keys()
            self.assertEqual({k: per_key[k] for k in names}, {k: other_key[k] for k in names}, fit_set)
            self.assertEqual(cells, other_cells, fit_set)

    def test_sensitivity_without_exclusion(self):
        """The mutation below does change fits when the identifier is not excluded (non-vacuous test)."""

        ranking, store, pipeline = build(BASE_ALERTS)
        before = key_signature(pipeline, self.training)
        for scenario in self.training:
            mutate_rows(store, scenario, excluded_rows(ranking, scenario, IDENTIFIER_EXCLUSION), seed=3)
        self.assertNotEqual(before, key_signature(pipeline, self.training))

    def test_class_level_exclusion_makes_the_class_unseen(self):
        ranking, store, pipeline = build(BASE_ALERTS)
        dirb = PHASES.index("dirb")
        included = pipeline.builder.key_features(self.training)
        excluded = pipeline.builder.key_features(self.training, ranking.key_ids_for(CLASS_EXCLUSION))
        self.assertIn(dirb, set(included.classes.tolist()))
        self.assertNotIn(dirb, set(excluded.classes.tolist()))
        self.assertNotIn(dirb, set(excluded.heights.table["class_index"].tolist()))

    def test_mutating_excluded_labels(self):
        for names in (IDENTIFIER_EXCLUSION, CLASS_EXCLUSION):
            for reliability in ("detector_class", "native_key"):
                ranking, store, pipeline = build(BASE_ALERTS)
                reference = {fs: key_signature(pipeline, fs, names, reliability) for fs in [self.training]}
                for i, scenario in enumerate(self.training):
                    mutate_rows(store, scenario, excluded_rows(ranking, scenario, names), seed=10 + i)
                self.assertEqual(reference, {fs: key_signature(pipeline, fs, names, reliability) for fs in [self.training]},
                                 f"{sorted(names)} {reliability}")
            ranking, store, pipeline = build(BASE_ALERTS)
            reference = self.fit_set_signatures(pipeline, names)
            for i, scenario in enumerate(self.training):
                mutate_rows(store, scenario, excluded_rows(ranking, scenario, names), seed=20 + i)
            self.assert_same_signatures(reference, self.fit_set_signatures(pipeline, names))

    def test_deleting_excluded_rows(self):
        for names in (IDENTIFIER_EXCLUSION, CLASS_EXCLUSION):
            _, _, pipeline = build(BASE_ALERTS)
            reference = self.fit_set_signatures(pipeline, names)
            keep = ~(BASE_ALERTS["scenario"].isin(self.training)
                     & [(d, k) in names for d, k in zip(BASE_ALERTS["detector"], BASE_ALERTS["native_key"])])
            _, _, deleted = build(BASE_ALERTS[keep].reset_index(drop=True))
            self.assert_same_signatures(reference, self.fit_set_signatures(deleted, names))

    def test_adding_excluded_rows_including_a_new_identifier(self):
        names = IDENTIFIER_EXCLUSION | {("wazuh", "wazuh:newrule")}
        _, _, pipeline = build(BASE_ALERTS)
        reference = self.fit_set_signatures(pipeline, IDENTIFIER_EXCLUSION)
        original_keys = next(iter(reference.values()))[0].keys()
        _, _, added = build(added_excluded_rows(BASE_ALERTS, self.training))
        self.assert_same_signatures(reference, self.fit_set_signatures(added, names), keys=original_keys)
        # Without the exclusion the added rows do change the fit (non-vacuous).
        self.assertNotEqual(key_signature(pipeline, self.training)[1], key_signature(added, self.training)[1])

    def test_learned_sample_under_a_cap_ignores_excluded_rows(self):
        capped = dataclasses.replace(CONFIG, max_training_alerts=400)
        ranking, _, pipeline = build(BASE_ALERTS, config=capped)
        _, _, added = build(added_excluded_rows(BASE_ALERTS, self.training), config=capped)
        names = IDENTIFIER_EXCLUSION | {("wazuh", "wazuh:newrule")}
        a = pipeline.training_sample(list(self.training), CONFIG.primary_policy, "t",
                                     tuple(ranking.key_ids_for(IDENTIFIER_EXCLUSION)))
        b = added.training_sample(list(self.training), CONFIG.primary_policy, "t", tuple(added.ranking.key_ids_for(names)))
        np.testing.assert_array_equal(a.alert_ids, b.alert_ids)
        np.testing.assert_array_equal(a.X, b.X)
        np.testing.assert_array_equal(a.y, b.y)
        self.assertEqual(a.sampled_from, b.sampled_from)
        self.assertFalse(any("wazuh:dirb" in str(k) for k in ranking.frame.set_index("alert_id").loc[a.alert_ids, "native_key"]))


class ExcludedIdentifierPipeline(unittest.TestCase):
    """Whole nested folds: inner metrics, selections, learned fits and outer scores are unchanged."""

    held_out = "scn0"
    training = ("scn1", "scn2", "scn3")

    @classmethod
    def setUpClass(cls):
        cls.results = {}
        ranking, store, pipeline = build(BASE_ALERTS)
        split = OuterSplit("holdout:test", cls.held_out, cls.training, tuple(ranking.key_ids_for(CLASS_EXCLUSION)))
        cls.results["reference"] = (pipeline.run_outer_fold(split, CONFIG.primary_policy), ranking)

        ranking, store, pipeline = build(BASE_ALERTS)
        for i, scenario in enumerate(cls.training):
            mutate_rows(store, scenario, excluded_rows(ranking, scenario, CLASS_EXCLUSION), seed=40 + i)
        split = OuterSplit("holdout:test", cls.held_out, cls.training, tuple(ranking.key_ids_for(CLASS_EXCLUSION)))
        cls.results["mutated"] = (pipeline.run_outer_fold(split, CONFIG.primary_policy), ranking)

        keep = ~(BASE_ALERTS["scenario"].isin(cls.training)
                 & [(d, k) in CLASS_EXCLUSION for d, k in zip(BASE_ALERTS["detector"], BASE_ALERTS["native_key"])])
        ranking, store, pipeline = build(BASE_ALERTS[keep].reset_index(drop=True))
        split = OuterSplit("holdout:test", cls.held_out, cls.training, tuple(ranking.key_ids_for(CLASS_EXCLUSION)))
        cls.results["deleted"] = (pipeline.run_outer_fold(split, CONFIG.primary_policy), ranking)

        names = CLASS_EXCLUSION | {("wazuh", "wazuh:newrule")}
        ranking, store, pipeline = build(added_excluded_rows(BASE_ALERTS, cls.training))
        split = OuterSplit("holdout:test", cls.held_out, cls.training, tuple(ranking.key_ids_for(names)))
        cls.results["added"] = (pipeline.run_outer_fold(split, CONFIG.primary_policy), ranking)

    def test_variants_leave_the_fold_unchanged(self):
        reference, _ = self.results["reference"]
        for variant in ("mutated", "deleted", "added"):
            result, ranking = self.results[variant]
            with self.subTest(variant=variant):
                self.assertTrue(reference.inner_metrics.equals(result.inner_metrics))
                self.assertTrue(reference.selections.equals(result.selections))
                self.assertEqual(reference.learner_diagnostics, result.learner_diagnostics)
                np.testing.assert_array_equal(reference.outer_alert_ids, result.outer_alert_ids)
                self.assertEqual(sorted(reference.outer_scores), sorted(result.outer_scores))
                for cid, scores in reference.outer_scores.items():
                    np.testing.assert_array_equal(scores, result.outer_scores[cid], cid)
                self.assertTrue(verify_fold_trace(result, ranking).passed)

    def test_excluded_alerts_stay_in_the_outer_queue_with_fallback_inputs(self):
        result, ranking = self.results["reference"]
        excluded = excluded_rows(ranking, self.held_out, CLASS_EXCLUSION)
        self.assertEqual(len(result.outer_alert_ids), len(ranking.rows(self.held_out)))
        records = result.fit_records["outer_target_fallback_alerts"]
        self.assertEqual(records["excluded_identifier_alerts"], int(excluded.sum()))
        per_key = pd.DataFrame(result.fit_records["per_key"])
        rows = per_key[per_key["excluded"]]
        self.assertTrue((rows["class"] == "unknown").all())
        self.assertTrue((rows["key_height_fallback"] > 0).all())
        removed = [e for e in result.trace if e["event"] == "inner_queue"]
        self.assertTrue(all(e["excluded_identifier_alerts_removed"] > 0 for e in removed))


# ---------------------------------------------------------------------------------------------
class CacheInvalidation(unittest.TestCase):
    def setUp(self):
        self.ranking, self.store, self.pipeline = build(BASE_ALERTS)
        self.builder = self.pipeline.builder
        self.fit_set = ("scn1", "scn2", "scn3")

    def fits_since(self, start):
        return [e for e in self.builder.trace[start:] if e["event"] == "fit"]

    def test_repeated_request_is_cached(self):
        first = self.builder.key_features(self.fit_set)
        start = len(self.builder.trace)
        self.assertIs(first, self.builder.key_features(self.fit_set))
        self.assertEqual(self.fits_since(start), [])
        self.builder.alert_features("scn0", self.fit_set, CONFIG.primary_policy, role="x")
        self.assertTrue(self.builder.manifest[-1]["cached"])

    def test_label_replacement_invalidates_only_fits_that_used_the_scenario(self):
        first = self.builder.key_features(self.fit_set)
        other = self.builder.key_features(("scn1", "scn2"))
        labels = self.store.labels["scn3"]
        self.store.replace("scn3", labels.replace_arrays(y=np.zeros_like(labels.y), r=np.zeros_like(labels.r),
                                                         z=np.zeros_like(labels.z),
                                                         phase_membership=np.zeros_like(labels.phase_membership)))
        start = len(self.builder.trace)
        second = self.builder.key_features(self.fit_set)
        self.assertIsNot(first, second)
        self.assertTrue(self.fits_since(start))
        self.assertFalse(np.array_equal(first.key_heights.heights, second.key_heights.heights))
        self.assertIs(other, self.builder.key_features(("scn1", "scn2")))

    def test_in_place_label_mutation_is_impossible(self):
        labels = self.store.labels["scn1"]
        for name in ("y", "s_star", "z", "r", "phase_membership", "critical_membership"):
            with self.assertRaises(ValueError, msg=name):
                getattr(labels, name)[0] = 1

    def test_population_exclusion_policy_settings_and_severity_are_cache_keys(self):
        base = self.builder.key_features(self.fit_set)
        variants = {
            "fit population": lambda: self.builder.key_features(("scn1", "scn2")),
            "exclusion set": lambda: self.builder.key_features(self.fit_set, self.ranking.key_ids_for(IDENTIFIER_EXCLUSION)),
            "reliability policy": lambda: self.builder.key_features(self.fit_set, reliability="global_class"),
        }
        for label, request in variants.items():
            start = len(self.builder.trace)
            result = request()
            self.assertIsNot(result, base, label)
            self.assertTrue(self.fits_since(start), label)
        self.builder.settings = dataclasses.replace(self.builder.settings, class_lambda=5.0)
        start = len(self.builder.trace)
        changed = self.builder.key_features(self.fit_set)
        self.assertTrue(self.fits_since(start))
        self.assertFalse(np.array_equal(base.height, changed.height))
        self.builder.settings = CONFIG.settings
        self.assertIs(base, self.builder.key_features(self.fit_set))
        original = self.builder.severity
        self.builder.severity = variant(original, "severity_plus_0.5")[0]
        start = len(self.builder.trace)
        self.assertFalse(np.array_equal(base.severity, self.builder.key_features(self.fit_set).severity))
        self.assertTrue(self.fits_since(start))
        self.builder.severity = original

    def test_uncertainty_and_context_are_applied_from_the_same_fit(self):
        start = len(self.builder.trace)
        outputs = {}
        for uncertainty in ("table", "ambiguity_aware", "constant_0.5", "purity_only", "precision_only", "zero"):
            for context in ("flat", "asset_profile"):
                policy = InputPolicy(context=context, uncertainty=uncertainty)
                outputs[(uncertainty, context)] = self.builder.alert_features("scn0", self.fit_set, policy, role="x")
        self.assertEqual(len([e for e in self.fits_since(start) if e["component"] == "mapping"]), 1 + 3)
        keys = self.builder.key_features(self.fit_set)
        key_ids = self.ranking.rows("scn0")["key_id"].to_numpy()
        q = self.ranking.rows("scn0")["q_asset_profile"].to_numpy(float)
        for (uncertainty, context), features in outputs.items():
            np.testing.assert_array_equal(features.u, keys.u_by_policy[uncertainty][key_ids])
            np.testing.assert_array_equal(features.c, keys.severity[key_ids] * (q if context == "asset_profile" else 1.0))


# ---------------------------------------------------------------------------------------------
class ReliabilityArithmetic(unittest.TestCase):
    """Production heights equal an independent per-alert reference, including every fallback."""

    @classmethod
    def setUpClass(cls):
        cls.ranking, cls.store, cls.pipeline = build(BASE_ALERTS)

    def reference_inputs(self, ranking, store, fit_set, excluded=frozenset()):
        return {s: ref.records(ranking.rows(s), store.labels[s], PHASES, excluded) for s in fit_set}

    def check(self, ranking, store, pipeline, fit_set, excluded=frozenset()):
        alerts = self.reference_inputs(ranking, store, fit_set, excluded)
        all_keys = [(str(d), str(k)) for d, k in zip(ranking.key_detector, ranking.key_name)]
        final_classes, stats = ref.mapping(alerts, fit_set, PHASES)
        for grouping in ("detector_class", "global_class", "detector_only"):
            keys = pipeline.builder.key_features(fit_set, ranking.key_ids_for(excluded), grouping)
            heights, detector_totals, global_prior = ref.class_heights(alerts, fit_set, PHASES, grouping)
            table = keys.heights.table
            self.assertEqual(len(table), len(heights), grouping)
            for row in table.itertuples(index=False):
                cls = "all_classes" if row.class_index < 0 else row._1
                cell = heights[(row.detector, cls)]
                self.assertEqual((row.positives, row.n, row.prior_positives, row.prior_n),
                                 (cell["positives"], cell["n"], cell["prior_positives"], cell["prior_n"]), (grouping, row))
                self.assertAlmostEqual(row.unclipped, cell["unclipped"], places=12)
                self.assertAlmostEqual(row.height, cell["height"], places=12)
            for k, key in enumerate(all_keys):
                expected_class = final_classes.get(key, ref.UNKNOWN)
                self.assertEqual(pipeline.builder.class_names[keys.classes[k]], expected_class, key)
                height, fallback = ref.applied_class_height(key, final_classes, heights, detector_totals, global_prior, grouping)
                self.assertAlmostEqual(keys.height[k], height, places=12, msg=(grouping, key))
                self.assertEqual(int(keys.height_fallback[k]), fallback, (grouping, key))
        keys = pipeline.builder.key_features(fit_set, ranking.key_ids_for(excluded), "native_key")
        for k, key in enumerate(all_keys):
            height, fallback = ref.key_heights(alerts, fit_set, all_keys)[key]
            self.assertAlmostEqual(keys.height[k], height, places=12, msg=key)
            self.assertEqual(int(keys.height_fallback[k]), fallback, key)
            self.assertAlmostEqual(keys.key_heights.heights[k], height, places=12)
        none = pipeline.builder.key_features(fit_set, ranking.key_ids_for(excluded), "none")
        self.assertTrue(np.all(none.height == 1.0))

    def test_heights_match_reference(self):
        for fit_set in (("scn1", "scn2", "scn3"), ("scn0", "scn2"), ("scn3",)):
            self.check(self.ranking, self.store, self.pipeline, fit_set)

    def test_heights_match_reference_with_exclusions(self):
        self.check(self.ranking, self.store, self.pipeline, ("scn1", "scn2", "scn3"), CLASS_EXCLUSION)

    def test_unseen_class_and_unseen_detector_fallbacks(self):
        solo = BASE_ALERTS[BASE_ALERTS["scenario"] == "scn1"].head(40).copy()
        solo["alert_id"] = [f"solo-{i}" for i in range(len(solo))]
        solo["detector"], solo["native_key"] = "suricata", "suricata:solo"
        solo["timestamp"] = np.linspace(5000.0 + 100.0 + 1, 5100.0 + 100.0 - 1, len(solo))  # privilege_escalation window of scn1
        alerts = pd.concat([BASE_ALERTS, solo], ignore_index=True)
        ranking, store, pipeline = build(alerts)
        fit_set = ("scn1", "scn2", "scn3")
        aminer = frozenset((str(d), str(k)) for d, k in zip(ranking.key_detector, ranking.key_name) if d == "aminer")
        keys = pipeline.builder.key_features(fit_set, ranking.key_ids_for(aminer))
        solo_id = int(ranking.key_ids_for({("suricata", "suricata:solo")})[0])
        self.assertEqual(pipeline.builder.class_names[keys.classes[solo_id]], "privilege_escalation")
        self.assertEqual(int(keys.height_fallback[solo_id]), FALLBACK_DETECTOR)      # (suricata, priv-esc) cell unseen
        table = keys.heights.table
        pos, n = keys.heights.detector_prior["suricata"]
        self.assertAlmostEqual(keys.height[solo_id], float(np.clip(pos / n, 0.05, 0.95)), places=12)
        for key_id in ranking.key_ids_for(aminer):
            self.assertEqual(int(keys.height_fallback[key_id]), FALLBACK_GLOBAL)    # detector unseen after exclusion
            self.assertEqual(int(keys.key_heights.fallback[key_id]), FALLBACK_GLOBAL)
        self.assertNotIn("aminer", set(table["detector"]))
        self.check(ranking, store, pipeline, fit_set, aminer)

    def test_empty_and_fully_excluded_training_fail_explicitly(self):
        with self.assertRaises(FitFailure):
            self.pipeline.builder.key_features(())
        everything = frozenset((str(d), str(k)) for d, k in zip(self.ranking.key_detector, self.ranking.key_name))
        with self.assertRaises(FitFailure):
            self.pipeline.builder.key_features(("scn1", "scn2"), self.ranking.key_ids_for(everything))

    def test_single_class_training(self):
        for positive in (False, True):
            ranking, store, pipeline = build(BASE_ALERTS)
            for scenario in ("scn1", "scn2", "scn3"):
                labels = store.labels[scenario]
                phases = np.zeros_like(labels.phase_membership)
                if positive:
                    phases[:, PHASES.index("dirb")] = True
                y = np.full_like(labels.y, positive)
                store.replace(scenario, labels.replace_arrays(y=y, r=np.where(y, 3.0, 0.0), s_star=np.where(y, 3.0, 0.0),
                                                              z=np.zeros_like(labels.z), phase_membership=phases))
            keys = pipeline.builder.key_features(("scn1", "scn2", "scn3"))
            expected = 0.95 if positive else 0.05
            self.assertTrue(np.all(keys.height == expected), positive)
            self.assertTrue(np.all(keys.key_heights.heights == expected), positive)
            self.assertEqual(bool(keys.mapping.accepted.any()), positive)
            self.check(ranking, store, pipeline, ("scn1", "scn2", "scn3"))
            sample = pipeline.training_sample(["scn1", "scn2", "scn3"], CONFIG.primary_policy, role="t")
            l1 = [c for c in CONFIG.families["L1_logistic"].candidates][0]
            from soc_alert_ranking.revision.families import fit_learner
            self.assertEqual(fit_learner(l1, sample, 42, CONFIG.learned_fixed).fallback, "single_class_constant_probability")

    def test_uncertainty_variants(self):
        keys = self.pipeline.builder.key_features(("scn1", "scn2", "scn3"))
        mapped = keys.classes < len(PHASES)
        table = np.array([SEVERITY.uncertainty_factor.get(SEVERITY.ait_phase_uncertainty.get(PHASES[c], "novel_or_ambiguous"), 0.5)
                          if m else 0.5 for c, m in zip(keys.classes, mapped)])
        m = keys.mapping
        expected = {
            "table": table,
            "ambiguity_aware": np.where(mapped, np.clip(table + 0.20 * (1 - m.precision) + 0.15 * (1 - m.purity), 0, 0.5), 0.5),
            "constant_0.5": np.full(len(table), 0.5),
            "purity_only": np.where(mapped, 0.35 * (1 - m.purity), 0.5),
            "precision_only": np.where(mapped, 0.35 * (1 - m.precision), 0.5),
            "zero": np.zeros(len(table)),
        }
        for name, values in expected.items():
            np.testing.assert_allclose(keys.u_by_policy[name], values, rtol=0, atol=1e-15, err_msg=name)
        self.assertTrue(mapped.any() and (~mapped).any())

    def test_heights_use_interval_labels_not_other_columns(self):
        noisy = BASE_ALERTS.assign(is_attack=np.random.default_rng(0).random(len(BASE_ALERTS)) < 0.5,
                                   true_attack_phase="dirb", raw_label="malicious")
        _, _, pipeline = build(noisy)
        self.assertEqual(key_signature(pipeline, ("scn1", "scn2", "scn3")),
                         key_signature(self.pipeline, ("scn1", "scn2", "scn3")))


# ---------------------------------------------------------------------------------------------
def shifted(alerts: pd.DataFrame, labels: pd.DataFrame, shifts: dict[str, float]):
    a, l = alerts.copy(), labels.copy()
    for scenario, shift in shifts.items():
        a.loc[a["scenario"] == scenario, "timestamp"] += shift
        l.loc[l["scenario"] == scenario, ["start", "end"]] += shift
    return a, l


class SplitMachinery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        alerts, labels = make_synthetic_alerts(5, 300, seed=4)
        # extents: scn0 ~[0,10400]; scn1 +20000; scn2 +25000 (overlaps scn1); scn3 +40000; scn4 +60000
        cls.alerts, cls.labels = shifted(alerts, labels, {"scn1": 20000.0, "scn2": 25000.0, "scn3": 40000.0, "scn4": 60000.0})
        cls.ranking, cls.store, cls.pipeline = build(cls.alerts, cls.labels)

    def test_forward_chaining_eligibility(self):
        splits, table = forward_chaining_splits(self.ranking)
        rows = table.set_index("test_scenario")
        self.assertEqual(rows.loc["scn0", "fit_scenarios"], [])
        self.assertEqual(rows.loc["scn1", "fit_scenarios"], ["scn0"])
        self.assertEqual(rows.loc["scn2", "fit_scenarios"], ["scn0"])            # scn1 ends after scn2 starts
        self.assertEqual(rows.loc["scn3", "fit_scenarios"], ["scn0", "scn1", "scn2"])
        self.assertEqual(rows.loc["scn4", "fit_scenarios"], ["scn0", "scn1", "scn2", "scn3"])
        self.assertEqual([s.held_out for s in splits], ["scn3", "scn4"])
        self.assertTrue(all(s.learned_estimable for s in splits))
        touching, _ = shifted(self.alerts, self.labels, {})
        start3 = touching.loc[touching["scenario"] == "scn3", "timestamp"].min()
        touching.loc[touching.loc[touching["scenario"] == "scn0", "timestamp"].idxmax(), "timestamp"] = start3  # scn0 ends at scn3's start
        _, table = forward_chaining_splits(RankingFrame.from_alerts(touching))
        self.assertNotIn("scn0", table.set_index("test_scenario").loc["scn3", "fit_scenarios"])

    def test_two_fit_scenarios_use_simplest_learned_grid_point(self):
        ranking, store, pipeline = build(self.alerts, self.labels)
        split = OuterSplit("forward:scn3-two", "scn3", ("scn0", "scn1"), learned_estimable=False, note="two fit scenarios")
        result = pipeline.run_outer_fold(split, CONFIG.primary_policy)
        learned = result.selections[result.selections["family"].isin(["L1_logistic", "L2_gradient_boosting"])]
        self.assertEqual(len(learned), 4)
        for family, part in learned.groupby("family"):
            expected = simplest_candidate(list(CONFIG.families[family].candidates)).candidate_id
            self.assertEqual(set(part["selected_candidate"]), {expected})
            self.assertEqual(set(part["selection_fallback"]), {"inner_fit_failure_simplest_grid_point"})
            self.assertIn(expected, result.outer_scores)
        self.assertEqual(simplest_candidate(list(CONFIG.families["L1_logistic"].candidates)).candidate_id, "L1_logistic[C=0.01]")
        self.assertFalse(any("|inner=" in d["role"] for d in result.learner_diagnostics))
        self.assertTrue(verify_fold_trace(result, ranking).passed, verify_fold_trace(result, ranking).violations)

    def test_identifier_groups_follow_the_protocol_hash(self):
        groups = identifier_groups(self.ranking)
        for row in groups.itertuples(index=False):
            identifier = f"{row.detector}:{str(row.native_key).split(':')[1]}"
            self.assertEqual(row.identifier, identifier)
            self.assertEqual(row.group, int(hashlib.sha256(identifier.encode()).hexdigest(), 16) % 5)
        self.assertEqual(groups.groupby("identifier")["group"].nunique().max(), 1)
        self.assertEqual(normalized_identifier("wazuh", "wazuh:31101:web,accesslog,attack:web server 400 error code."), "wazuh:31101")
        self.assertEqual(normalized_identifier("suricata", "suricata:20100::first time this ids alert is generated."), "suricata:20100")

    def test_holdout_splits_partition_keys_within_each_loso_fold(self):
        splits = identifier_holdout_splits(self.ranking)
        self.assertEqual(len(splits), 5 * len(self.ranking.scenarios))
        for base in loso_splits(self.ranking):
            own = [s for s in splits if s.held_out == base.held_out]
            self.assertTrue(all(s.training == base.training for s in own))
            union = [k for s in own for k in s.excluded_key_ids]
            self.assertEqual(sorted(union), list(range(self.ranking.n_keys)))

    def test_unseen_identifiers(self):
        ranking, _, _ = build(BASE_ALERTS)
        mask = unseen_identifier_mask(ranking, "scn0", ("scn1", "scn2", "scn3"))
        rows = ranking.rows("scn0")
        np.testing.assert_array_equal(mask, (rows["native_key"] == "suricata:rare").to_numpy())
        mask3 = unseen_identifier_mask(ranking, "scn3", ("scn0", "scn1", "scn2"))
        self.assertFalse(mask3.any())                           # scn3 lacks wazuh:webshell but has no new key


# ---------------------------------------------------------------------------------------------
class TraceVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ranking, cls.store, cls.pipeline = build(BASE_ALERTS)
        groups = identifier_groups(cls.ranking)
        cls.runs = []
        for split in loso_splits(cls.ranking)[:2]:
            cls.runs.append(cls.pipeline.run_fitting_chain(split, CONFIG.primary_policy))
        dirb = int(cls.ranking.key_ids_for({("wazuh", "wazuh:dirb")})[0])
        holdout = [s for s in identifier_holdout_splits(cls.ranking) if s.held_out == "scn0" and dirb in s.excluded_key_ids]
        cls.runs.append(cls.pipeline.run_fitting_chain(holdout[0], CONFIG.primary_policy))
        for policy in (CONFIG.secondary_policy, InputPolicy(reliability="native_key"), InputPolicy(reliability="none"),
                       InputPolicy(reliability="global_class"), InputPolicy(reliability="detector_only"),
                       InputPolicy(uncertainty="purity_only")):
            cls.runs.append(cls.pipeline.run_fitting_chain(loso_splits(cls.ranking)[0], policy))
        cls.groups = groups

    def test_executed_traces_pass(self):
        for result in self.runs:
            verification = verify_fold_trace(result, self.ranking)
            self.assertTrue(verification.passed, (result.split.name, result.policy, verification.violations))
            self.assertFalse(result.outer_scores)              # fitting chain: no scores, no metrics
            self.assertTrue(result.inner_metrics.empty)
            roles = {r["role"] for r in result.manifest}
            self.assertTrue(any(":validation" in r for r in roles) and any(":training_features" in r for r in roles)
                            and any(":outer_validation" in r for r in roles))

    def test_forged_traces_are_rejected(self):
        base = self.runs[2]                                      # holdout split with exclusions
        self.assertTrue(verify_fold_trace(base, self.ranking).passed)
        held_out = base.split.held_out

        def forged(mutator):
            result = copy.deepcopy(base)
            mutator(result)
            return verify_fold_trace(result, self.ranking)

        def height_source_self_mapped(r):
            request = next(q for q in r.manifest if q["height_row_sources"])
            request["height_row_sources"][0]["mapped_with"].append(request["height_row_sources"][0]["rows_from"])

        def held_out_in_fit_set(r):
            r.manifest[0]["fit_set"].append(held_out)

        def exclusion_dropped(r):
            r.manifest[-1]["excluded_keys"] = []

        def mapping_on_larger_set(r):
            r.manifest[0]["mapping_fit_set"] = sorted(set(r.manifest[0]["mapping_fit_set"]) | {r.manifest[0]["target"]})

        def excluded_rows_in_sample(r):
            next(e for e in r.trace if e["event"] == "learned_sample")["excluded_key_rows_in_sample"] = 3

        def inner_queue_not_restricted(r):
            next(e for e in r.trace if e["event"] == "inner_queue" and e["excluded_identifier_alerts_removed"])[
                "excluded_identifier_alerts_removed"] = 0

        def held_out_table_read(r):
            r.trace.append({"event": "table_read", "scenario": held_out, "purpose": "mapping", "version": 0,
                            "excluded_keys": len(r.split.excluded_key_ids), "feature_fit_set": [held_out]})

        def held_out_label_access(r):
            r.label_access_log.append((held_out, "peek"))

        def training_features_include_target(r):
            request = next(q for q in r.manifest if ":training_features" in q["role"])
            request["fit_set"] = sorted(set(request["fit_set"]) | {request["target"]})

        def inner_scenario_read_for_fitting(r):
            inner = r.split.training[0]
            r.label_access_log.append((inner, f"{r.split.name}|inner={inner}:learned_training_targets"))

        def sample_scope_widened(r):
            event = next(e for e in r.trace if e["event"] == "learned_sample" and "|inner=" in e["role"])
            event["standardization_scope"] = sorted(r.split.training)

        for mutator in (height_source_self_mapped, held_out_in_fit_set, exclusion_dropped, mapping_on_larger_set,
                        excluded_rows_in_sample, inner_queue_not_restricted, held_out_table_read, held_out_label_access,
                        training_features_include_target, inner_scenario_read_for_fitting, sample_scope_widened):
            with self.subTest(fault=mutator.__name__):
                self.assertFalse(forged(mutator).passed)


if __name__ == "__main__":
    unittest.main()

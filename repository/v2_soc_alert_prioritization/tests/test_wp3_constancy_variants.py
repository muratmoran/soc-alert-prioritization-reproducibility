"""WP3: within-key score constancy per family and policy, severity variants, within-detector queues."""

from __future__ import annotations

import unittest

import numpy as np

from wp2_fixtures import synthetic_setup
from wp3_support import PHASES, SEVERITY
from soc_alert_ranking.revision.families import LEARNED_FAMILIES, fit_learner, score_candidate
from soc_alert_ranking.revision.metrics import metrics_at_k, restrict_queue
from soc_alert_ranking.revision.evaluation import full_order
from soc_alert_ranking.revision.severity_variants import VARIANTS, variant
from soc_alert_ranking.revision.ties import (
    FAMILY_INPUTS, candidate_inputs, guaranteed_constant_within_key, varying_inputs, within_group_constancy,
)


class WithinKeyConstancy(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config, _, cls.ranking, cls.store, cls.pipeline = synthetic_setup()
        cls.target = cls.ranking.scenarios[0]
        cls.training = list(cls.ranking.scenarios[1:])

    def audit(self, policy):
        features = self.pipeline.builder.alert_features(self.target, self.training, policy, role="test")
        keys = self.ranking.rows(self.target)["key_id"].to_numpy()
        inputs = {"c": features.c, "u": features.u, "h": features.h, "h_key": features.h_key,
                  "timestamp": features.timestamp, "native_rule_level": features.native_rule_level,
                  "native_suricata_severity": features.native_suricata_severity}
        varying = varying_inputs(inputs, keys)
        sample = self.pipeline.training_sample(self.training, policy, role="test")
        observed = {}
        for spec in self.config.families.values():
            for candidate in spec.candidates:
                learner = fit_learner(candidate, sample, 42, self.config.learned_fixed) if candidate.family in LEARNED_FAMILIES else None
                scores = score_candidate(candidate, features, learner)
                constant = within_group_constancy(scores, keys)["varying_groups"] == 0
                guaranteed = guaranteed_constant_within_key(candidate_inputs(candidate.family, candidate.params_dict), varying)
                if guaranteed:
                    self.assertTrue(constant, f"{policy.name} {candidate.candidate_id} should be constant within keys")
                observed[candidate.candidate_id] = (guaranteed, constant)
        return varying, observed

    def test_primary_policy_class_inputs_are_constant_within_keys(self):
        varying, observed = self.audit(self.config.primary_policy)
        self.assertEqual(varying & {"c", "u", "h", "h_key"}, set())
        self.assertIn("timestamp", varying)
        self.assertTrue(observed["P_probability_proxy"][1])
        self.assertFalse(observed["O_oldest_first"][1])

    def test_asset_context_policy_is_audited_separately(self):
        varying, observed = self.audit(self.config.secondary_policy)
        self.assertIn("c", varying)                       # q varies with host inside a key
        self.assertEqual(varying & {"u", "h", "h_key"}, set())
        self.assertFalse(observed["P_probability_proxy"][0])
        self.assertFalse(observed["P_probability_proxy"][1])
        self.assertTrue(observed["O_reliability"][1])      # h only: still constant
        self.assertTrue(observed["W_weighted[alpha=0]"][0])  # zero weight on c removes the dependence

    def test_every_family_has_declared_inputs(self):
        self.assertEqual(set(FAMILY_INPUTS), set(self.config.families))


class SeverityVariants(unittest.TestCase):
    def test_declared_variants(self):
        plus, tau = variant(SEVERITY, "severity_plus_0.5")
        self.assertEqual(tau, 8.0)
        self.assertEqual(plus.ait_phase_severity["service_stop"], 8.0)
        self.assertEqual(plus.ait_phase_severity["privilege_escalation"], 10.0)
        minus, _ = variant(SEVERITY, "severity_minus_0.5")
        self.assertEqual(minus.ait_phase_severity["network_scans"], 1.5)
        swapped, _ = variant(SEVERITY, "swap_lowest_critical_levels")
        self.assertEqual(swapped.ait_phase_severity["webshell"], 9.0)
        self.assertEqual({swapped.ait_phase_severity[p] for p in ("reverse_shell", "dnsteal", "data_exfiltration")}, {8.5})
        self.assertEqual(swapped.ait_phase_severity["privilege_escalation"], 9.5)
        unknown, _ = variant(SEVERITY, "default_unknown_3.0")
        self.assertEqual((unknown.default_unknown, unknown.ait_phase_severity), (3.0, SEVERITY.ait_phase_severity))
        self.assertEqual(variant(SEVERITY, "tau_7")[1], 7.0)
        self.assertEqual(variant(SEVERITY, "tau_9")[1], 9.0)
        self.assertEqual(SEVERITY.default_unknown, 5.0)   # base mapping untouched
        self.assertEqual(len(VARIANTS), 7)
        for name in VARIANTS:
            mapping, _ = variant(SEVERITY, name)
            order = sorted(mapping.ait_phase_severity, key=lambda p: (mapping.ait_phase_severity[p], p))
            if name not in {"swap_lowest_critical_levels"}:
                base = sorted(SEVERITY.ait_phase_severity, key=lambda p: (SEVERITY.ait_phase_severity[p], p))
                self.assertEqual(order, base, name)


class WithinDetectorQueues(unittest.TestCase):
    def test_restricted_queue_uses_subset_denominators_and_keeps_defined_intervals(self):
        config, _, ranking, store, pipeline = synthetic_setup()
        scenario = ranking.scenarios[0]
        labels = store.get(scenario, "test")
        rows = ranking.rows(scenario)
        for detector in ("wazuh", "suricata", "aminer"):
            mask = (rows["detector"] == detector).to_numpy()
            sub = restrict_queue(labels, mask)
            self.assertEqual(len(sub.y), int(mask.sum()))
            self.assertEqual(sub.defined_critical_intervals, labels.defined_critical_intervals)
            order = full_order(np.arange(mask.sum(), dtype=float), rows["timestamp"].to_numpy()[mask],
                               rows["hash_key"].to_numpy()[mask])
            m = metrics_at_k(order, sub, 100)
            self.assertEqual(m.critical_total, int(labels.z[mask].sum()))
            self.assertEqual(m.eligible_intervals, int(labels.critical_membership[mask].any(axis=0).sum()))
        native = rows["detector_score"].to_numpy(float)
        missing = {d: float(np.isnan(native[(rows["detector"] == d).to_numpy()]).mean()) for d in ("wazuh", "suricata", "aminer")}
        self.assertEqual(missing, {"wazuh": 0.0, "suricata": 0.0, "aminer": 1.0})


if __name__ == "__main__":
    unittest.main()

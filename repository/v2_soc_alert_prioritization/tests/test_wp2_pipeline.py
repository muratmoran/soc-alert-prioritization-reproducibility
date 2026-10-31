"""WP2: end-to-end nested pipeline on synthetic data (structure, determinism, outputs)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np

from wp2_fixtures import synthetic_setup
from soc_alert_ranking.revision.pipeline import write_fold_outputs
from soc_alert_ranking.revision.tuning import PRIMARY, SECONDARY


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config, _, cls.ranking, cls.store, cls.pipeline = synthetic_setup()
        cls.held_out = cls.ranking.scenarios[1]
        cls.result = cls.pipeline.run_outer_fold(cls.held_out, cls.config.primary_policy)

    def test_structure(self):
        r = self.result
        tuned = [name for name, spec in self.config.families.items() if spec.tuned]
        self.assertEqual(len(r.inner_metrics), 145 * len(r.training_scenarios))
        self.assertEqual(set(r.inner_metrics["inner_scenario"]), set(r.training_scenarios))
        self.assertEqual(len(r.selections), 2 * len(tuned))
        self.assertEqual(set(r.selections["rule"]), {PRIMARY, SECONDARY})
        untuned = {c.candidate_id for name, spec in self.config.families.items() if not spec.tuned for c in spec.candidates}
        self.assertTrue(untuned.issubset(r.outer_scores))
        self.assertTrue(set(r.selections["selected_candidate"]).issubset(r.outer_scores))
        n = len(self.ranking.rows(self.held_out))
        self.assertTrue(all(len(v) == n for v in r.outer_scores.values()))
        self.assertIn("S0_linear_log_historical_key[kappa=1]", r.outer_scores)
        roles = {d["role"] for d in r.learner_diagnostics}
        self.assertEqual(roles, {f"loso:{self.held_out}|inner={s}" for s in r.training_scenarios} | {f"loso:{self.held_out}"})

    def test_deterministic_rerun(self):
        _, _, _, _, pipeline = synthetic_setup()
        again = pipeline.run_outer_fold(self.held_out, self.config.primary_policy)
        self.assertTrue(self.result.inner_metrics.equals(again.inner_metrics))
        self.assertTrue(self.result.selections.equals(again.selections))
        for cid, scores in self.result.outer_scores.items():
            np.testing.assert_array_equal(scores, again.outer_scores[cid])

    def test_secondary_policy_changes_inputs_not_protocol(self):
        primary = self.pipeline.builder.alert_features(self.held_out, self.result.training_scenarios,
                                                       self.config.primary_policy, role="test")
        secondary = self.pipeline.builder.alert_features(self.held_out, self.result.training_scenarios,
                                                         self.config.secondary_policy, role="test")
        np.testing.assert_array_equal(primary.h, secondary.h)
        self.assertFalse(np.array_equal(primary.c, secondary.c))
        self.assertTrue(np.all(primary.c[~primary.mapped] == 5.0))
        self.assertTrue(np.all(primary.u[~primary.mapped] == 0.5))

    def test_outputs_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_fold_outputs(self.result, Path(tmp))
            files = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(len(files), 5)
            scores = np.load(next(Path(tmp).glob("*_outer_scores.npz")))
            self.assertEqual(set(scores.files) - {"alert_ids"}, set(self.result.outer_scores))


if __name__ == "__main__":
    unittest.main()

"""Information-boundary tests for the historical (submitted) pipelines.

Run from the project root with:

    python -m unittest discover -s tests -v

A held-out label mutation may change evaluation metrics, but it must not change
sample inclusion, fitted components, scores, or queue order. Known violations of
the submitted protocol are encoded as expected failures so that they stay
visible until the revised protocol removes them.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.ait_detector_mapping import (  # noqa: E402
    apply_native_key_mapping,
    learn_native_key_mapping,
)
from soc_alert_ranking.mappings.context import apply_asset_context, apply_uncertainty_policy  # noqa: E402
from soc_alert_ranking.mappings.reliability import (  # noqa: E402
    apply_reliability_heights,
    calibrate_alert_precision_reliability,
)
from soc_alert_ranking.metrics.ranking import rank_alerts  # noqa: E402
from soc_alert_ranking.rankers.baselines import add_ranking_scores  # noqa: E402


EVALUATION_ONLY = ["true_attack_phase", "true_severity", "is_attack", "is_critical", "raw_label"]
SCORE_COLUMNS = ["score_sgfn", "score_severity", "score_reliability", "score_weighted", "score_detector", "score_recency"]


def load_script(name: str):
    path = PROJECT_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_ait_alerts(seed: int = 7, per_scenario: int = 400) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    phases = ["benign", "dirb", "wpscan", "privilege_escalation", "dnsteal"]
    severity = {"benign": 0.0, "dirb": 3.0, "wpscan": 3.0, "privilege_escalation": 9.5, "dnsteal": 9.0}
    rows = []
    for scenario in ["alpha", "bravo", "charlie"]:
        for index in range(per_scenario):
            detector = rng.choice(["wazuh", "suricata", "aminer"])
            key_id = int(rng.integers(0, 12))
            phase = phases[key_id % len(phases)] if rng.random() < 0.8 else "benign"
            rows.append({
                "alert_id": f"{scenario}-{index}",
                "dataset": "synthetic",
                "scenario": scenario,
                "timestamp": float(index) + rng.random(),
                "detector": detector,
                "native_key": f"{detector}:{key_id}:rule-{key_id}",
                "native_category": f"group-{key_id % 3}",
                "host": rng.choice(["web-01", "mail", "wazuh-client", ""]),
                "ip": "",
                "attack_class": "unknown",
                "attack_phase": "unknown",
                "severity": 5.0,
                "uncertainty_factor": 0.5,
                "detector_score": float(rng.integers(3, 12)) if detector == "wazuh" else None,
                "native_severity": None,
                "asset_criticality": 1.0,
                "true_attack_phase": phase,
                "true_severity": severity[phase],
                "is_attack": phase != "benign",
                "is_critical": severity[phase] >= 8.0,
                "raw_label": phase,
            })
    return pd.DataFrame(rows)


def score_ait_fold(train: pd.DataFrame, test: pd.DataFrame) -> pd.DataFrame:
    """Replicates the per-fold scoring steps of scripts/run_ait_ranking.py."""

    mapping = learn_native_key_mapping(train)
    mapped_train = apply_native_key_mapping(train, mapping)
    mapped_test = apply_native_key_mapping(test, mapping)
    reliability = calibrate_alert_precision_reliability(mapped_train)
    scored = apply_reliability_heights(mapped_test, reliability)
    scored = apply_asset_context(scored, "asset_profile")
    scored = apply_uncertainty_policy(scored, "ambiguity_aware")
    return add_ranking_scores(scored, kappa=1.0)


def mutate_labels(frame: pd.DataFrame, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    out = frame.copy()
    out["is_attack"] = rng.random(len(out)) < 0.5
    out["true_attack_phase"] = rng.choice(["benign", "dnsteal", "dirb"], size=len(out))
    out["true_severity"] = rng.uniform(0, 10, size=len(out))
    out["is_critical"] = out["true_severity"] >= 8.0
    out["raw_label"] = out["true_attack_phase"]
    return out


class AitHeldOutLabelIsolation(unittest.TestCase):
    def setUp(self) -> None:
        alerts = synthetic_ait_alerts()
        self.train = alerts[alerts["scenario"] != "charlie"].copy()
        self.test = alerts[alerts["scenario"] == "charlie"].copy()
        self.reference = score_ait_fold(self.train, self.test)

    def test_mutating_held_out_labels_leaves_scores_and_queue_unchanged(self) -> None:
        for seed in range(5):
            mutated = score_ait_fold(self.train, mutate_labels(self.test, seed))
            pd.testing.assert_frame_equal(mutated[SCORE_COLUMNS], self.reference[SCORE_COLUMNS])
            for column in ["score_sgfn", "score_weighted", "score_detector"]:
                self.assertEqual(
                    rank_alerts(mutated, column)["alert_id"].tolist(),
                    rank_alerts(self.reference, column)["alert_id"].tolist(),
                )

    def test_scoring_runs_without_evaluation_columns(self) -> None:
        stripped = score_ait_fold(self.train, self.test.drop(columns=EVALUATION_ONLY))
        pd.testing.assert_frame_equal(stripped[SCORE_COLUMNS], self.reference[SCORE_COLUMNS])

    def test_training_labels_do_change_fitted_components(self) -> None:
        """Sanity check that the test above is sensitive: training labels matter."""

        mutated = score_ait_fold(mutate_labels(self.train, 11), self.test)
        self.assertFalse(np.allclose(mutated["score_sgfn"], self.reference["score_sgfn"]))


def synthetic_nf_uq_sample(seed: int = 3, rows_per_group: int = 60) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    frames = []
    for domain_index, domain in enumerate(["NF-A", "NF-B", "NF-C"]):
        for class_index, category in enumerate(["Benign", "DoS", "DDoS", "Reconnaissance"]):
            center = class_index * 2.0 + domain_index * 0.5
            frames.append(pd.DataFrame({
                "IN_BYTES": rng.normal(center, 1.0, rows_per_group),
                "OUT_BYTES": rng.normal(-center, 1.0, rows_per_group),
                "FLOW_DURATION_MILLISECONDS": rng.normal(center * 3, 2.0, rows_per_group),
                "source_domain": domain,
                "true_attack_class": category,
                "is_attack": category != "Benign",
            }))
    return pd.concat(frames, ignore_index=True)


class NfUqHeldOutLabelIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = load_script("run_nf_uq_robustness")
        from soc_alert_ranking.mappings.severity import SeverityMapping

        cls.severity = SeverityMapping.from_file()

    def _ranked(self, sample: pd.DataFrame) -> pd.DataFrame:
        fold = self.script.run_one_fold(
            sample=sample,
            feature_columns=["IN_BYTES", "OUT_BYTES", "FLOW_DURATION_MILLISECONDS"],
            held_out_domain="NF-C",
            model_name="logistic_regression",
            severity_mapping=self.severity,
            seed=42,
            kappa=1.0,
        )
        return fold["ranked_alerts"].reset_index(drop=True)

    def test_mutating_target_domain_labels_leaves_generated_queue_unchanged(self) -> None:
        sample = synthetic_nf_uq_sample()
        reference = self._ranked(sample)
        mutated_sample = sample.copy()
        target = mutated_sample["source_domain"] == "NF-C"
        rng = np.random.default_rng(5)
        mutated_sample.loc[target, "true_attack_class"] = rng.choice(["Benign", "Backdoor"], size=int(target.sum()))
        mutated = self._ranked(mutated_sample)
        self.assertEqual(mutated["alert_id"].tolist(), reference["alert_id"].tolist())
        pd.testing.assert_series_equal(mutated["score_sgfn"], reference["score_sgfn"])

    @unittest.expectedFailure
    def test_sample_inclusion_is_label_independent(self) -> None:
        """Known violation N1: build_domain_category_sample filters and caps by true category."""

        rng = np.random.default_rng(9)
        flows = pd.DataFrame({
            "IN_BYTES": rng.normal(size=400),
            "Dataset": "NF-UNSW-NB15-v2",
            "Attack": rng.choice(["Benign", "DoS", "Exploits"], size=400),
            "Label": 1,
        })
        flows["Label"] = (flows["Attack"] != "Benign").astype(int)
        mutated = flows.copy()
        mutated["Attack"] = np.where(flows["Attack"] == "Exploits", "DoS", flows["Attack"])

        def selected_ids(frame: pd.DataFrame, tmp: Path) -> set[int]:
            frame = frame.assign(row_id=np.arange(len(frame)))
            path = tmp / "sample.csv"
            frame.to_csv(path, index=False)
            sample = self.script.build_domain_category_sample(
                files=[path], chunksize=1000, max_per_group=50,
                categories={"DoS", "DDoS", "Reconnaissance", "Backdoor"}, seed=42,
            )
            return set(sample["row_id"].tolist())

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(selected_ids(flows, Path(tmp)), selected_ids(mutated, Path(tmp)))


if __name__ == "__main__":
    unittest.main()

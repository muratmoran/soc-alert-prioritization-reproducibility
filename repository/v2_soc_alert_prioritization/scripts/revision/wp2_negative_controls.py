#!/usr/bin/env python
"""WP2: show that the isolation, ordering, metric and selection tests detect injected faults.

Each control monkeypatches one deliberate defect, runs the relevant tests, and
records how many tests fail. A control passes only if at least one test fails.
Writes docs/revision/wp2/negative_controls.json.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import sys
import unittest
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import wp2_fixtures  # noqa: E402,F401
import test_wp2_labels_ordering_metrics as ordering_tests  # noqa: E402
import test_wp2_tuning as tuning_tests  # noqa: E402
from soc_alert_ranking.revision import evaluation, features, labels, pipeline, tuning  # noqa: E402


def run(names: list[str]) -> dict[str, int]:
    suite = unittest.TestSuite()
    for name in names:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors)}


@contextlib.contextmanager
def patched(obj, name, value):
    original = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)


def main() -> int:
    controls = []
    original_features = features.FeatureBuilder.alert_features

    def leaky_outer_features(self, target, fit_set, policy, role, excluded_key_ids=()):
        fit_set = frozenset(fit_set)
        base = original_features(self, target, fit_set, policy, role, excluded_key_ids)
        if role.endswith("outer_validation"):
            keys = self.key_features(fit_set | {target}, excluded_key_ids, policy.reliability)
            key_ids = self.ranking.rows(target)["key_id"].to_numpy()
            base.h, base.c = keys.height[key_ids], keys.severity[key_ids]
            self.manifest[-1]["fit_set"] = sorted(fit_set | {target})
        return base

    no_lock = contextlib.contextmanager(lambda self, scenarios: (yield))
    with patched(labels.LabelStore, "locked", no_lock), patched(features.FeatureBuilder, "alert_features", leaky_outer_features):
        controls.append({"control": "held-out labels leak into outer features (locks disabled)",
                         **run(["test_wp2_fitting_isolation.PipelineIsolation"])})

    original_sample = pipeline.ComparisonPipeline.training_sample

    def leaky_sample(self, fit_scenarios, policy, role, excluded_key_ids=()):
        sample = original_sample(self, fit_scenarios, policy, role, excluded_key_ids)
        keys = self.builder.key_features(fit_scenarios)  # includes each training scenario g
        for g in sorted(fit_scenarios):
            key_of = dict(zip(self.ranking.rows(g)["alert_id"], self.ranking.rows(g)["key_id"]))
            mask = sample.scenarios == g
            sample.X[mask, 2] = keys.height[[key_of[a] for a in sample.alert_ids[mask]]]
        return sample

    with patched(pipeline.ComparisonPipeline, "training_sample", leaky_sample):
        controls.append({"control": "training scenario's own labels shape its learned-ranker heights",
                         **run(["test_wp2_fitting_isolation.FittingIsolation.test_learned_training_sample_is_isolated_and_label_independent"])})

    def no_hash_tiebreak(scores, timestamps, hash_keys):
        return np.lexsort((np.where(np.isnan(timestamps), np.inf, timestamps), evaluation._primary_key(scores)))

    with patched(evaluation, "full_order", no_hash_tiebreak):
        controls.append({"control": "hash tie-break dropped from queue order",
                         **run(["test_wp2_labels_ordering_metrics.Ordering"])})

    def reversed_fp(inner, rule=tuning.PRIMARY, tolerance=1e-12):
        return tuning.select_candidate(inner.assign(fp=-inner["fp"]), rule, tolerance)

    with patched(tuning_tests, "select_candidate", reversed_fp):
        controls.append({"control": "false-positive tie-break direction reversed",
                         **run(["test_wp2_tuning"])})

    original_metrics = evaluation.selection_metrics

    def wrong_denominator(order, scenario_labels, k):
        m = original_metrics(order, scenario_labels, k)
        return dataclasses.replace(m, coverage=m.coverage_all_defined)

    with patched(ordering_tests, "selection_metrics", wrong_denominator):
        controls.append({"control": "coverage uses all defined intervals instead of alert-containing intervals",
                         **run(["test_wp2_labels_ordering_metrics.SelectionMetricsByHand"])})

    for control in controls:
        # Errors are not accepted as detection: a patch that no longer fits the code would raise instead.
        control["detected"] = control["failures"] > 0 and control["errors"] == 0
    out = PROJECT_ROOT / "docs/revision/wp2/negative_controls.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(controls, indent=2), encoding="utf-8")
    for control in controls:
        print(f"{'DETECTED' if control['detected'] else 'MISSED  '} {control['control']}: {control}")
    return 0 if all(c["detected"] for c in controls) else 1


if __name__ == "__main__":
    raise SystemExit(main())

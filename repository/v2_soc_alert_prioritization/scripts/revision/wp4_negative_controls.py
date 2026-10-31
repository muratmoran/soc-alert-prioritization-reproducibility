#!/usr/bin/env python
"""WP4: show that the fitting-boundary tests detect injected faults (synthetic data only).

Each control monkeypatches one deliberate defect into production code, runs the WP4 tests
(plus the WP2 isolation tests and WP3 reference examples where relevant) and records how many
tests fail. A control is detected only if at least one test fails. Several controls leave the
execution trace looking correct, so detection must come from behavioural tests (adversarial
data changes and the independent reference), not from trace checks alone.
Writes docs/revision/wp4/negative_controls.json.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import test_wp2_fitting_isolation  # noqa: E402,F401
import test_wp3_reference_examples  # noqa: E402,F401
import test_wp4_fitting_boundaries  # noqa: E402,F401
from soc_alert_ranking.revision import features, metrics, pipeline, splits  # noqa: E402

WP4 = "test_wp4_fitting_boundaries"


def run(names: list[str]) -> dict[str, int]:
    suite = unittest.TestSuite()
    for name in names:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors)}


@contextlib.contextmanager
def patched(obj, name, value):
    """Replace an attribute on its module or class and on every loaded module bound to the same object."""

    original = getattr(obj, name)
    bound = [module for module in list(sys.modules.values())
             if module is not None and module is not obj and getattr(module, name, None) is original]
    setattr(obj, name, value)
    for module in bound:
        setattr(module, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)
        for module in bound:
            setattr(module, name, original)


def main() -> int:
    controls = []

    def control(description, patches, tests, trace_visible):
        with contextlib.ExitStack() as stack:
            for obj, name, value in patches:
                stack.enter_context(patched(obj, name, value))
            outcome = run(tests)
        detected = outcome["failures"] > 0 and outcome["errors"] == 0   # an erroring patch is not a detection
        controls.append({"control": description, "trace_would_show_it": trace_visible, "tests": tests, **outcome,
                         "detected": detected})
        print(f"{'DETECTED' if detected else 'MISSED  '} {description}: {outcome}", flush=True)

    # 1. Height rows mapped with M(F) instead of M(F minus {j}); the manifest still claims cross-fitting.
    original_mapping = features.FeatureBuilder.mapping

    def full_mapping_for_heights(self, fit_set, excluded=frozenset(), context=None):
        if context and context.get("role_in_features") == "crossfit_mapping":
            fit_set = frozenset(context["feature_fit_set"])
        return original_mapping(self, fit_set, excluded, context)

    control("class-height rows classified by a mapping fitted on their own scenario (trace unchanged)",
            [(features.FeatureBuilder, "mapping", full_mapping_for_heights)],
            [f"{WP4}.ReliabilityArithmetic"], trace_visible=False)

    # 2. Excluded identifiers left in fitting tables.
    control("excluded identifiers not removed from mapping/height tables",
            [(features.KeyTable, "without_keys", lambda self, key_ids: self)],
            [f"{WP4}.ExcludedIdentifierData", f"{WP4}.ReliabilityArithmetic"], trace_visible=False)

    # 3. Excluded identifiers left in learned training samples (sample trace computed without the exclusion).
    original_sample = pipeline.ComparisonPipeline.training_sample
    control("excluded identifiers left in learned-ranker training samples",
            [(pipeline.ComparisonPipeline, "training_sample",
              lambda self, fit, policy, role, excluded_key_ids=(): original_sample(self, fit, policy, role, ()))],
            [f"{WP4}.ExcludedIdentifierData.test_learned_sample_under_a_cap_ignores_excluded_rows",
             f"{WP4}.ExcludedIdentifierPipeline"], trace_visible=False)

    # 4. Inner validation queues keep excluded identifiers.
    control("inner validation queues keep excluded-identifier alerts",
            [(pipeline.ComparisonPipeline, "_inner_queue_mask",
              lambda self, scenario, excluded: np.ones(len(self.ranking.rows(scenario)), dtype=bool))],
            [f"{WP4}.ExcludedIdentifierPipeline"], trace_visible=True)

    # 5-8. Cache keys missing a component.
    def base_key_without(index):
        def key(self, fit_set, excluded):
            versions = tuple((s, self.provider.version(s)) for s in sorted(fit_set))
            parts = [fit_set, versions, excluded, self.settings.digest(), self._severity_digest(), self.ranking.n_keys]
            parts[index] = None
            return tuple(parts)
        return key

    control("feature cache ignores label versions", [(features.FeatureBuilder, "_base_key", base_key_without(1))],
            [f"{WP4}.CacheInvalidation", f"{WP4}.ExcludedIdentifierData.test_sensitivity_without_exclusion"], trace_visible=False)
    control("feature cache ignores the exclusion set", [(features.FeatureBuilder, "_base_key", base_key_without(2))],
            [f"{WP4}.CacheInvalidation"], trace_visible=False)
    control("feature cache ignores fitting settings", [(features.FeatureBuilder, "_base_key", base_key_without(3))],
            [f"{WP4}.CacheInvalidation"], trace_visible=False)
    original_key_features = features.FeatureBuilder.key_features

    def stale_reliability(self, fit_set, excluded_key_ids=(), reliability="detector_class"):
        cache_key = ("reliability-blind", *self._base_key(frozenset(fit_set), frozenset(int(k) for k in excluded_key_ids)))
        if cache_key not in self._feature_cache:
            self._feature_cache[cache_key] = original_key_features(self, fit_set, excluded_key_ids, reliability)
        return self._feature_cache[cache_key]

    control("feature cache ignores the reliability policy", [(features.FeatureBuilder, "key_features", stale_reliability)],
            [f"{WP4}.CacheInvalidation"], trace_visible=False)

    # 9. Training scenario g's own labels shape its learned-ranker heights (manifest records the clean fit set).
    original_alert_features = features.FeatureBuilder.alert_features

    def own_labels_in_training_features(self, target, fit_set, policy, role, excluded_key_ids=()):
        result = original_alert_features(self, target, fit_set, policy, role, excluded_key_ids)
        if role.endswith(":training_features"):
            keys = original_key_features(self, frozenset(fit_set) | {target}, excluded_key_ids, policy.reliability)
            result.h = keys.height[self.ranking.rows(target)["key_id"].to_numpy()]
        return result

    control("training scenario's own labels shape its learned-ranker heights (manifest unchanged)",
            [(features.FeatureBuilder, "alert_features", own_labels_in_training_features)],
            ["test_wp2_fitting_isolation.FittingIsolation"], trace_visible=False)

    # 10-12. Reliability arithmetic.
    original_prior = features._prior_height
    control("unseen (detector, class) falls back to the global prior instead of the detector prior",
            [(features, "_prior_height", lambda d, g, det, s: original_prior({}, g, det, s))],
            [f"{WP4}.ReliabilityArithmetic"], trace_visible=False)
    original_heights = features.fit_class_heights

    def unclipped_heights(*args, **kwargs):
        fit = original_heights(*args, **kwargs)
        fit.table["height"] = fit.table["unclipped"]
        return fit

    control("class heights not clipped to [0.05, 0.95]", [(features, "fit_class_heights", unclipped_heights)],
            [f"{WP4}.ReliabilityArithmetic"], trace_visible=False)
    control("shrinkage ignores lambda (raw frequencies)",
            [(features, "_shrink", lambda positives, n, prior, lam: positives / n)],
            [f"{WP4}.ReliabilityArithmetic"], trace_visible=False)

    # 13-15. Split machinery.
    def non_strict_forward(ranking):
        extents = splits.scenario_extents(ranking)
        records, out = [], []
        for test, row in extents.iterrows():
            fit = tuple(sorted(s for s, other in extents.iterrows() if other["end"] <= row["start"] and s != test))
            records.append({"test_scenario": test, "start": row["start"], "end": row["end"], "fit_scenarios": list(fit),
                            "eligible": len(fit) >= 2, "learned_estimable": len(fit) >= 3})
            if len(fit) >= 2:
                out.append(splits.OuterSplit(f"forward:{test}", test, fit, learned_estimable=len(fit) >= 3))
        return out, pd.DataFrame(records)

    control("forward chaining admits a scenario ending exactly when the test scenario starts",
            [(splits, "forward_chaining_splits", non_strict_forward)],
            [f"{WP4}.SplitMachinery.test_forward_chaining_eligibility"], trace_visible=False)
    control("identifier groups hashed with an undeclared salt", [(splits, "HOLDOUT_SALT", "cose04000|")],
            [f"{WP4}.SplitMachinery.test_identifier_groups_follow_the_protocol_hash"], trace_visible=False)
    control("unseen identifiers defined against all scenarios instead of the outer training scenarios",
            [(splits, "unseen_identifier_mask",
              lambda ranking, held_out, training: np.zeros(len(ranking.rows(held_out)), dtype=bool))],
            [f"{WP4}.SplitMachinery.test_unseen_identifiers"], trace_visible=False)

    # 16. Learned fallback not the simplest grid point.
    control("non-estimable learned families use the last grid point instead of the simplest",
            [(pipeline, "simplest_candidate", lambda candidates: max(candidates, key=lambda c: c.grid_index))],
            [f"{WP4}.SplitMachinery.test_two_fit_scenarios_use_simplest_learned_grid_point"], trace_visible=False)

    # 17. Subgroup metric reranks the subgroup instead of reading the mixed queue.
    original_subgroup = metrics.subgroup_in_mixed_queue

    def reranked_subgroup(order, labels, mask, k, budget=None):
        subgroup_first = np.array([i for i in order if mask[i]] + [i for i in order if not mask[i]], dtype=np.int64)
        return original_subgroup(subgroup_first, labels, mask, k, budget)

    control("subgroup retrieval computed from a reranked subgroup rather than the mixed queue",
            [(metrics, "subgroup_in_mixed_queue", reranked_subgroup)],
            ["test_wp3_reference_examples"], trace_visible=False)

    # 18. Trace logging suppressed: the verifier must not pass a fold whose table reads were not logged.
    original_table = features.FeatureBuilder._table

    def silent_table(self, scenario, purpose, excluded, context):
        before = len(self.trace)
        table = original_table(self, scenario, purpose, excluded, context)
        del self.trace[before:]
        return table

    control("table reads not logged (verifier must reject an incomplete trace)",
            [(features.FeatureBuilder, "_table", silent_table)],
            [f"{WP4}.TraceVerification.test_executed_traces_pass"], trace_visible=True)

    # 19. Verifier weakened: forged traces must be rejected.
    original_verify = pipeline.verify_fold_trace

    def lenient_verify(result, ranking):
        verification = original_verify(result, ranking)
        verification.violations = [v for v in verification.violations if "mapped with" not in v and "held-out" not in v]
        return verification

    control("trace verifier ignores self-mapped height rows and held-out use",
            [(pipeline, "verify_fold_trace", lenient_verify)],
            [f"{WP4}.TraceVerification.test_forged_traces_are_rejected"], trace_visible=True)

    record = {
        "work_package": "WP4 fitting boundaries",
        "note": "Synthetic data only. Each control injects one defect; detected means at least one test failed.",
        "controls": controls,
        "all_detected": all(c["detected"] for c in controls),
        "undetectable_from_trace_alone": sum(not c["trace_would_show_it"] for c in controls),
        "test_module_sha256": hashlib.sha256((PROJECT_ROOT / "tests/test_wp4_fitting_boundaries.py").read_bytes()).hexdigest(),
    }
    out = PROJECT_ROOT / "docs/revision/wp4/negative_controls.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps({"all_detected": record["all_detected"], "controls": len(controls)}))
    return 0 if record["all_detected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

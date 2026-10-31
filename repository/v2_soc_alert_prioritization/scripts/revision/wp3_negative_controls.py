#!/usr/bin/env python
"""WP3: inject incorrect metric definitions and confirm that verification fails.

Each control replaces one production function (in every loaded module that imported it)
with a deliberately wrong variant, reruns the WP3 verification tests, and records the
number of failing tests. A control is detected when at least one test fails and none errors
(an erroring patch may simply no longer fit the code, which is not a detection).
Writes docs/revision/wp3/negative_controls.json.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import math
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import wp2_fixtures  # noqa: E402,F401
import wp3_support  # noqa: E402,F401
import test_wp3_reference_examples  # noqa: E402,F401
import test_wp3_properties  # noqa: E402,F401
from soc_alert_ranking.revision import duplicates, labels, metrics, ties  # noqa: E402

SUITES = ["test_wp3_reference_examples", "test_wp3_properties"]


@contextlib.contextmanager
def replaced(original, replacement):
    """Swap every module-level binding of ``original`` for ``replacement``."""

    bindings = [(module, name) for module in list(sys.modules.values()) if module is not None
                for name, value in list(vars(module).items()) if value is original]
    for module, name in bindings:
        setattr(module, name, replacement)
    try:
        yield len(bindings)
    finally:
        for module, name in bindings:
            setattr(module, name, original)


def run_suites() -> dict[str, int]:
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in SUITES)
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors)}


def with_record_change(function, **changes):
    def wrapped(*args, **kwargs):
        record = function(*args, **kwargs)
        values = {name: change(record) for name, change in changes.items()}
        return dataclasses.replace(record, **values)
    return wrapped


def main() -> int:
    original_metrics = metrics.metrics_at_k
    original_build = labels.build_scenario_labels
    original_intervals = labels.intervals_from_frame

    def boundary_variant(closed_end: bool, open_start: bool):
        def build(scenario, alert_ids, timestamps, intervals, phases, tau):
            own = intervals[intervals["scenario"] == scenario].reset_index(drop=True)
            shifted = own.copy()
            if closed_end:
                shifted["end"] = np.nextafter(shifted["end"].to_numpy(float), np.inf)   # t == end now included
            if open_start:
                shifted["start"] = np.nextafter(shifted["start"].to_numpy(float), np.inf)  # t == start now excluded
            other = intervals[intervals["scenario"] != scenario]
            return original_build(scenario, alert_ids, timestamps, pd.concat([other, shifted]), phases, tau)
        return build

    def no_dedup(raw, severity, tau):
        rows = raw.rename(columns={"attack": "phase"}).copy()
        rows["phase"] = rows["phase"].str.lower()
        rows["severity"] = rows["phase"].map(lambda p: float(severity.ait_phase_severity[p]))
        rows["critical"] = rows["severity"] >= tau
        rows["interval_id"] = [f"{r.scenario}|{r.phase}|{r.start:.3f}|{r.end:.3f}|{i}" for i, r in enumerate(rows.itertuples(index=False))]
        return rows.reset_index(drop=True)

    original_effort = metrics.effort_to_critical_recall

    def effort_variant(requirement, strictly_greater=False):
        def effort(order, scenario_labels, target):
            record = original_effort(order, scenario_labels, target)
            if record.total == 0:
                return record
            required = max(1, requirement(target, record.total))
            cumulative = np.cumsum(scenario_labels.z[np.asarray(order)])
            reached = cumulative > required if strictly_greater else cumulative >= required
            hits = np.flatnonzero(reached)
            position = int(hits[0]) + 1 if len(hits) else len(scenario_labels.y)
            return dataclasses.replace(record, required=required, position=position, queue_fraction=position / len(scenario_labels.y))
        return effort

    def floor_budget(n, fraction):
        return None if n == 0 else max(1, int(fraction * n))

    original_expected = ties.expected_under_random_ties

    def untruncated_expectation(scores, scenario_labels, k):
        # Wrong: evaluates the expectation through the end of the cutoff block instead of truncating at k.
        n = len(scores)
        if n == 0 or k >= n:
            return original_expected(scores, scenario_labels, k)
        order = np.lexsort((np.arange(n), np.where(np.isnan(scores), np.inf, -np.asarray(scores, dtype=float))))
        blocks = ties.block_ids_along_order(scores, order)
        block_end = int(np.flatnonzero(blocks == blocks[k - 1]).max()) + 1
        return dataclasses.replace(original_expected(scores, scenario_labels, block_end), k=k)

    original_detection = duplicates.interval_detection_times

    def member_credit(investigation_time, timestamps, scenario_labels):
        detected = original_detection(investigation_time, timestamps, scenario_labels)
        membership = scenario_labels.critical_membership
        for position, start in investigation_time.items():
            nearby = np.flatnonzero(np.abs(timestamps - timestamps[position]) < 60)   # credit members of the window
            for interval in np.flatnonzero(membership[nearby].any(axis=0)):
                if detected[interval] is None or start < detected[interval]:
                    detected[interval] = float(start)
        return detected

    controls = [
        ("coverage over all defined intervals instead of alert-containing intervals",
         original_metrics, with_record_change(original_metrics, coverage_eligible=lambda r: r.coverage_all)),
        ("critical recall divided by k_eff instead of total critical alerts",
         original_metrics, with_record_change(original_metrics, critical_recall=lambda r: None if r.k_eff == 0 else r.critical_in_top / r.k_eff)),
        ("precision divided by k instead of k_eff for short queues",
         original_metrics, with_record_change(original_metrics, precision=lambda r: None if r.k_eff == 0 else r.positives_in_top / (r.k or r.n))),
        ("NDCG normalized by the ranked list's own DCG instead of the ideal DCG",
         original_metrics, with_record_change(original_metrics, ndcg_linear=lambda r: None if r.dcg_linear == 0 else 1.0)),
        ("zero-relevance NDCG reported as 0 instead of not applicable",
         original_metrics, with_record_change(original_metrics, ndcg_linear=lambda r: 0.0 if r.ndcg_linear is None else r.ndcg_linear)),
        ("empty-queue coverage over defined intervals reported as not applicable",
         original_metrics, with_record_change(original_metrics, coverage_all=lambda r: None if r.empty_queue else r.coverage_all)),
        ("closed interval end (t == end included)", original_build, boundary_variant(closed_end=True, open_start=False)),
        ("open interval start (t == start excluded)", original_build, boundary_variant(closed_end=False, open_start=True)),
        ("duplicate label rows not de-duplicated", original_intervals, no_dedup),
        ("critical-recall effort requirement uses floor instead of ceiling", original_effort,
         effort_variant(lambda target, total: math.floor(target * total))),
        ("critical-recall effort stops when cumulative count exceeds (not reaches) the requirement", original_effort,
         effort_variant(lambda target, total: math.ceil(target * total), strictly_greater=True)),
        ("queue-fraction budget with floor instead of ceiling", metrics.queue_fraction_budget, floor_budget),
        ("tie expectation not truncated at the cutoff", original_expected, untruncated_expectation),
        ("chronological coverage credited from cluster members", original_detection, member_credit),
    ]
    results = []
    for description, original, replacement in controls:
        with replaced(original, replacement) as bindings:
            outcome = run_suites()
        detected = outcome["failures"] > 0 and outcome["errors"] == 0
        results.append({"control": description, "bindings_replaced": bindings, **outcome, "detected": detected})
        print(f"{'DETECTED' if detected else 'MISSED  '} {description}: {outcome}")
    baseline = run_suites()
    payload = {"baseline_without_faults": baseline, "controls": results,
               "all_detected": all(r["detected"] for r in results) and baseline["failures"] == baseline["errors"] == 0}
    out = PROJECT_ROOT / "docs/revision/wp3/negative_controls.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("baseline", baseline, "all_detected", payload["all_detected"])
    return 0 if payload["all_detected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

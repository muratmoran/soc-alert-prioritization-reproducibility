"""WP3: hand-calculated reference examples, checked against production and the independent reference."""

from __future__ import annotations

import itertools
import math
import unittest

import numpy as np

import wp3_reference_metrics as ref
from wp3_support import (
    fraction, load_examples, production_labels, production_order, production_scores, reference_intervals,
    reference_severity_table,
)
from soc_alert_ranking.revision.duplicates import assign_clusters, interval_detection_times, static_cluster_labels
from soc_alert_ranking.revision.features import stable_hash_keys
from soc_alert_ranking.revision.metrics import (
    effort_to_critical_recall, effort_to_interval_coverage, first_critical_rank, metrics_at_k, queue_fraction_budget,
    restrict_queue, subgroup_in_mixed_queue,
)
from soc_alert_ranking.revision.ties import expected_under_random_ties, round_significant, tie_diagnostics

EXAMPLES = load_examples()


def close(testcase, actual, expected, label):
    if expected is None:
        testcase.assertIsNone(actual, label)
    elif isinstance(expected, bool):
        testcase.assertEqual(bool(actual), expected, label)
    elif isinstance(expected, (int, float)):
        testcase.assertIsNotNone(actual, label)
        testcase.assertTrue(math.isclose(float(actual), float(expected), rel_tol=0, abs_tol=1e-12), f"{label}: {actual} != {expected}")
    else:
        testcase.assertEqual(actual, expected, label)


class ExampleChecks(unittest.TestCase):
    def check_example(self, name):
        example = EXAMPLES[name]
        labels, frame = production_labels(example)
        order = production_order(example)
        ids = [a["id"] for a in example["alerts"]]
        ref_labelled, ref_keys = ref.reference_labels(
            [{"id": a["id"], "t": a["t"], "score": a["score"]} for a in example["alerts"]],
            reference_intervals(example), reference_severity_table(), example["tau"])
        ref_ordered = ref.reference_order(ref_labelled)

        if "expected_labels" in example:
            for i, alert_id in enumerate(ids):
                exp = example["expected_labels"][alert_id]
                self.assertEqual(bool(labels.y[i]), exp["y"], alert_id)
                self.assertEqual(float(labels.s_star[i]), exp["s_star"], alert_id)
                self.assertEqual(bool(labels.z[i]), exp["z"], alert_id)
                covered = sorted(
                    f"{iid.split('|')[1]}@{float(iid.split('|')[2]):g}-{float(iid.split('|')[3]):g}"
                    for iid, member in zip(labels.critical_interval_ids, labels.critical_membership[i]) if member)
                self.assertEqual(covered, sorted(exp["critical"]), alert_id)
                self.assertEqual(ref_labelled[i]["y"], exp["y"])
        if "expected_intervals" in example:
            exp = example["expected_intervals"]
            self.assertEqual(len(frame), exp["distinct"])
            self.assertEqual(labels.defined_critical_intervals, exp["defined_critical"])
            self.assertEqual(int(labels.critical_membership.any(axis=0).sum()), exp["eligible_critical"])
        if "expected_order" in example:
            self.assertEqual([ids[i] for i in order], example["expected_order"])
            self.assertEqual([a["id"] for a in ref_ordered], example["expected_order"])

        for k_text, expected in example.get("expected_at_k", {}).items():
            k = int(k_text)
            production = metrics_at_k(order, labels, k).to_record()
            reference = ref.reference_at_k(ref_ordered, ref_keys, k)
            for metric, value in expected.items():
                if metric == "derivation":
                    continue
                close(self, production[metric], value, f"{name} production {metric}@{k}")
                if metric in reference:
                    close(self, reference[metric], value, f"{name} reference {metric}@{k}")

        if "expected_subgroup_in_mixed_queue" in example:
            spec = example["expected_subgroup_in_mixed_queue"]
            members = set(spec["members"])
            mask = np.array([alert_id in members for alert_id in ids])
            for k_text, expected in spec["at_k"].items():
                production = subgroup_in_mixed_queue(order, labels, mask, int(k_text)).to_record()
                reference = ref.reference_subgroup_in_mixed(ref_ordered, members, int(k_text))
                for metric, value in expected.items():
                    if metric == "derivation":
                        continue
                    close(self, production[metric], value, f"{name} subgroup production {metric}@{k_text}")
                    close(self, reference[metric], value, f"{name} subgroup reference {metric}@{k_text}")
            sub_labels = restrict_queue(labels, mask)
            sub_scores = production_scores(example)[mask]
            from soc_alert_ranking.revision.evaluation import full_order
            sub_order = full_order(sub_scores, np.array([a["t"] for a in example["alerts"]])[mask],
                                   stable_hash_keys(np.array(ids)[mask]))
            for k_text, expected in spec["within_subgroup_at_k"].items():
                production = metrics_at_k(sub_order, sub_labels, int(k_text)).to_record()
                reference = ref.reference_at_k([a for a in ref_ordered if a["id"] in members], ref_keys, int(k_text))
                for metric, value in expected.items():
                    if metric == "derivation":
                        continue
                    close(self, production[metric], value, f"{name} within-subgroup production {metric}@{k_text}")
                    close(self, reference[metric], value, f"{name} within-subgroup reference {metric}@{k_text}")

        if "expected_first_critical" in example:
            first = first_critical_rank(order, labels).to_record()
            for metric, value in example["expected_first_critical"].items():
                close(self, first[metric], value, f"{name} first_critical {metric}")
            self.assertEqual(ref.reference_first_critical(ref_ordered), example["expected_first_critical"]["position"])

        for target, expected in example.get("expected_effort_critical_recall", {}).items():
            effort = effort_to_critical_recall(order, labels, fraction(target))
            reference = ref.reference_effort_critical(ref_ordered, fraction(target))
            if expected is None:
                self.assertIsNone(effort.position)
                self.assertIsNone(reference)
            else:
                for metric, value in expected.items():
                    close(self, getattr(effort, metric), value, f"{name} effort {target} {metric}")
                    close(self, reference[metric], value, f"{name} reference effort {target} {metric}")
        for target, expected in example.get("expected_effort_interval_coverage", {}).items():
            effort = effort_to_interval_coverage(order, labels, fraction(target))
            reference = ref.reference_effort_coverage(ref_ordered, fraction(target))
            if expected is None:
                self.assertIsNone(effort.position)
                self.assertIsNone(reference)
            else:
                for metric, value in expected.items():
                    close(self, getattr(effort, metric), value, f"{name} coverage effort {target} {metric}")
                    close(self, reference[metric], value, f"{name} reference coverage effort {target} {metric}")
        for f_text, expected in example.get("expected_fraction_budgets", {}).items():
            self.assertEqual(queue_fraction_budget(len(ids), fraction(f_text)), expected)
            self.assertEqual(ref.reference_fraction_budget(len(ids), fraction(f_text)), expected)

        if "expected_ties" in example:
            diagnostics = tie_diagnostics(production_scores(example), order, k_grid=(3, 4, 5, 6, 10))
            expected = example["expected_ties"]
            for metric, value in expected.items():
                if metric in {"cutoffs", "derivation"}:
                    continue
                close(self, diagnostics[metric], value, f"ties {metric}")
            cutoffs = {row["k"]: row for row in diagnostics["cutoffs"]}
            for k_text, fields in expected["cutoffs"].items():
                for metric, value in fields.items():
                    close(self, cutoffs[int(k_text)][metric], value, f"ties k={k_text} {metric}")

        for k_text, expected in example.get("expected_random_tie_expectations", {}).items():
            k = int(k_text)
            production = expected_under_random_ties(production_scores(example), labels, k).to_record()
            for metric, value in expected.items():
                if metric == "derivation":
                    continue
                close(self, production[metric], value, f"expected ties {metric}@{k}")
            brute = ref.brute_force_expectation(ref_ordered, ref_keys, k, "critical_recall")
            close(self, brute, expected["expected_critical_recall"], f"brute-force critical recall@{k}")
            brute_fp = ref.brute_force_expectation(ref_ordered, ref_keys, k, "negatives_in_top")
            close(self, brute_fp, expected["expected_negatives_in_top"], f"brute-force FP@{k}")
            if "expected_ndcg_linear" in expected:
                close(self, ref.brute_force_expectation(ref_ordered, ref_keys, k, "ndcg_linear"),
                      expected["expected_ndcg_linear"], f"brute-force NDCG@{k}")

    def test_example_a(self):
        self.check_example("A_boundaries_unequal_windows_repeats_no_alert_interval_ties")

    def test_example_empty_queue(self):
        self.check_example("B_empty_queue")

    def test_example_zero_relevant(self):
        self.check_example("C_zero_relevant_alerts")

    def test_example_effort_integer_ceiling(self):
        self.check_example("D_effort_exact_integer_ceiling")

    def test_shuffled_label_file_order_gives_identical_labels(self):
        example = EXAMPLES["A_boundaries_unequal_windows_repeats_no_alert_interval_ties"]
        base, _ = production_labels(example)
        for permutation in itertools.islice(itertools.permutations(example["intervals"]), 0, 120, 7):
            shuffled, _ = production_labels(example, intervals=list(permutation))
            for field in ("y", "s_star", "z", "r", "phase_membership", "critical_membership"):
                np.testing.assert_array_equal(getattr(base, field), getattr(shuffled, field), field)
            self.assertEqual(base.critical_interval_ids, shuffled.critical_interval_ids)

    def test_duplicates_example(self):
        example = EXAMPLES["E_duplicates_anchored_windows"]
        alerts = example["alerts"]
        labels, _ = production_labels(example)
        ids = [a["id"] for a in alerts]
        clusters = assign_clusters(np.array([a["detector"] for a in alerts]), np.array([a["key"] for a in alerts]),
                                   np.array([a["host"] for a in alerts]), np.array([a["t"] for a in alerts]),
                                   stable_hash_keys(ids), example["window_seconds"])
        representative_of = {ids[i]: ids[clusters.representative_of[i]] for i in range(len(ids))}
        self.assertEqual(representative_of, example["expected_representative_of"])
        self.assertEqual(ref.reference_clusters(alerts, example["window_seconds"]), example["expected_representative_of"])
        cluster_labels, reps, summary = static_cluster_labels(labels, clusters)
        self.assertEqual(summary.__dict__, example["expected_cluster_summary"])
        self.assertEqual({ids[r]: bool(cluster_labels.y[j]) for j, r in enumerate(reps)}, example["expected_static_cluster_positive"])
        own = restrict_queue(labels, clusters.representative)
        self.assertEqual({ids[r]: bool(own.y[j]) for j, r in enumerate(reps)}, example["expected_representative_own_positive"])
        timestamps = np.array([a["t"] for a in alerts])
        for case in example["chronological_cases"]:
            investigations = {ids.index(alert_id): t for alert_id, t in case["investigations"].items()}
            if "expected_error" in case:
                with self.assertRaises(ValueError):
                    interval_detection_times(investigations, timestamps, labels)
            else:
                self.assertEqual(interval_detection_times(investigations, timestamps, labels), case["expected_detection"])

    def test_near_tie_rounding(self):
        example = EXAMPLES["F_near_tie_rounding"]
        np.testing.assert_array_equal(round_significant(np.array(example["scores"])), np.array(example["expected_rounded"]))


if __name__ == "__main__":
    unittest.main()

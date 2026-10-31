#!/usr/bin/env python
"""WP3: write the hand-calculated reference examples (docs/revision/wp3/reference_examples.json).

Every expected value below is written as an explicit hand formula derived from the metric
contract. Only elementary arithmetic (``math.log2``, fractions) is evaluated here; no
production or reference metric code is imported.
"""

from __future__ import annotations

import json
from math import log2
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEV = {"dirb": 3.0, "webshell": 8.5, "dnsteal": 9.0, "privilege_escalation": 9.5}
G = {r: 2 ** r - 1 for r in (3.0, 8.5, 9.0)}   # exponential gains 7, 361.0386719675123, 511


def example_a() -> dict:
    intervals = [  # deliberately non-chronological file order with an exact duplicate row
        {"scenario": "ex", "attack": "dnsteal", "start": 100.0, "end": 200.0},
        {"scenario": "ex", "attack": "dirb", "start": 0.0, "end": 50.0},
        {"scenario": "ex", "attack": "privilege_escalation", "start": 300.0, "end": 310.0},
        {"scenario": "ex", "attack": "webshell", "start": 50.0, "end": 60.0},
        {"scenario": "ex", "attack": "dnsteal", "start": 100.0, "end": 200.0},
    ]
    alerts = [
        {"id": "a1", "t": 0.0, "score": 3.0}, {"id": "a2", "t": 50.0, "score": 3.0},
        {"id": "a3", "t": 59.999, "score": 1.0}, {"id": "a4", "t": 60.0, "score": 5.0},
        {"id": "a5", "t": 100.0, "score": 3.0}, {"id": "a6", "t": 150.0, "score": 4.0},
        {"id": "a7", "t": 199.999, "score": None}, {"id": "a8", "t": 200.0, "score": 2.0},
        {"id": "a9", "t": 250.0, "score": 5.0}, {"id": "a10", "t": 299.999, "score": 2.0},
    ]
    # Declared order (score desc, NaN last, timestamp asc): a4 a9 a6 a1 a2 a5 a8 a10 a3 a7
    idcg3 = 9 + 9 / log2(3) + 9 / log2(4)
    idcg5 = idcg3 + 8.5 / log2(5) + 8.5 / log2(6)
    idcg10 = idcg5 + 3 / log2(7)
    dcg5 = 9 / log2(4) + 3 / log2(5) + 8.5 / log2(6)
    dcg10 = dcg5 + 9 / log2(7) + 8.5 / log2(10) + 9 / log2(11)
    idcg3_e = G[9.0] * (1 + 1 / log2(3) + 1 / log2(4))
    idcg5_e = idcg3_e + G[8.5] * (1 / log2(5) + 1 / log2(6))
    dcg5_e = G[9.0] / log2(4) + G[3.0] / log2(5) + G[8.5] / log2(6)
    block3_mean_r = (3 + 8.5 + 9) / 3
    block3_mean_g = (G[3.0] + G[8.5] + G[9.0]) / 3
    return {
        "name": "A_boundaries_unequal_windows_repeats_no_alert_interval_ties",
        "purpose": "Half-open boundaries at 0, 50, 60, 100, 200, 300; windows of 50, 10, 100 and 10 s; three alerts in one dnsteal window; a critical interval without alerts; an exact duplicate label row; non-chronological label order; tied scores crossing cutoffs; a missing score.",
        "tau": 8.0,
        "intervals": intervals,
        "alerts": alerts,
        "expected_labels": {
            "a1": {"y": True, "s_star": 3.0, "z": False, "critical": []},
            "a2": {"y": True, "s_star": 8.5, "z": True, "critical": ["webshell@50-60"], "note": "t=50 is dirb's end (excluded) and webshell's start (included)"},
            "a3": {"y": True, "s_star": 8.5, "z": True, "critical": ["webshell@50-60"]},
            "a4": {"y": False, "s_star": 0.0, "z": False, "critical": [], "note": "t=60 is webshell's end (excluded)"},
            "a5": {"y": True, "s_star": 9.0, "z": True, "critical": ["dnsteal@100-200"], "note": "start included"},
            "a6": {"y": True, "s_star": 9.0, "z": True, "critical": ["dnsteal@100-200"]},
            "a7": {"y": True, "s_star": 9.0, "z": True, "critical": ["dnsteal@100-200"]},
            "a8": {"y": False, "s_star": 0.0, "z": False, "critical": [], "note": "t=200 is dnsteal's end (excluded)"},
            "a9": {"y": False, "s_star": 0.0, "z": False, "critical": []},
            "a10": {"y": False, "s_star": 0.0, "z": False, "critical": [], "note": "t=299.999 precedes privilege_escalation's start"},
        },
        "expected_intervals": {"distinct": 4, "defined_critical": 3, "eligible_critical": 2},
        "expected_order": ["a4", "a9", "a6", "a1", "a2", "a5", "a8", "a10", "a3", "a7"],
        "expected_at_k": {
            "3": {"n": 10, "k_eff": 3, "short_queue": False, "negatives_in_top": 2, "precision": 1 / 3,
                  "attack_recall": 1 / 6, "critical_recall": 1 / 5, "covered_intervals": 1, "eligible_intervals": 2,
                  "defined_intervals": 3, "coverage_eligible": 1 / 2, "coverage_all": 1 / 3,
                  "ndcg_linear": (9 / log2(4)) / idcg3, "ndcg_exponential": (G[9.0] / log2(4)) / idcg3_e,
                  "derivation": "top = a4(0) a9(0) a6(dnsteal, r=9); DCG = 9/log2(4); IDCG uses r sorted 9,9,9"},
            "5": {"n": 10, "k_eff": 5, "short_queue": False, "negatives_in_top": 2, "precision": 3 / 5,
                  "attack_recall": 3 / 6, "critical_recall": 2 / 5, "covered_intervals": 2, "eligible_intervals": 2,
                  "defined_intervals": 3, "coverage_eligible": 1.0, "coverage_all": 2 / 3,
                  "ndcg_linear": dcg5 / idcg5, "ndcg_exponential": dcg5_e / idcg5_e,
                  "derivation": "top adds a1(dirb, r=3) and a2(webshell, r=8.5); privilege_escalation has no alert so coverage_all < 1"},
            "25": {"n": 10, "k_eff": 10, "short_queue": True, "negatives_in_top": 4, "precision": 6 / 10,
                   "attack_recall": 1.0, "critical_recall": 1.0, "covered_intervals": 2, "eligible_intervals": 2,
                   "defined_intervals": 3, "coverage_eligible": 1.0, "coverage_all": 2 / 3,
                   "ndcg_linear": dcg10 / idcg10,
                   "derivation": "short queue: k_eff = n = 10; FP counts only existing alerts; precision divides by k_eff"},
        },
        "expected_first_critical": {"position": 3, "critical_total": 5, "prevalence": 5 / 10},
        "expected_subgroup_in_mixed_queue": {
            "members": ["a2", "a3", "a9", "a10"],
            "purpose": "Subgroup retrieval inside the original mixed order (e.g. unseen identifiers) versus reranking the subgroup alone.",
            "at_k": {
                "3": {"n": 10, "k_eff": 3, "subgroup_n": 4, "subgroup_in_top": 1, "subgroup_share_of_top": 1 / 3,
                      "subgroup_positives_in_top": 0, "subgroup_negatives_in_top": 1, "subgroup_positives_total": 2,
                      "subgroup_attack_recall": 0.0, "subgroup_critical_in_top": 0, "subgroup_critical_total": 2,
                      "subgroup_critical_recall": 0.0, "subgroup_covered_intervals": 0, "subgroup_eligible_intervals": 1,
                      "subgroup_coverage": 0.0,
                      "derivation": "mixed top 3 = a4 a9 a6; only a9 (negative) is a member; members a2, a3 lie in webshell"},
                "5": {"n": 10, "k_eff": 5, "subgroup_n": 4, "subgroup_in_top": 2, "subgroup_share_of_top": 2 / 5,
                      "subgroup_positives_in_top": 1, "subgroup_negatives_in_top": 1, "subgroup_positives_total": 2,
                      "subgroup_attack_recall": 1 / 2, "subgroup_critical_in_top": 1, "subgroup_critical_total": 2,
                      "subgroup_critical_recall": 1 / 2, "subgroup_covered_intervals": 1, "subgroup_eligible_intervals": 1,
                      "subgroup_coverage": 1.0,
                      "derivation": "mixed top 5 adds a1 and a2; a2 is a critical member covering webshell"},
            },
            "within_subgroup_at_k": {
                "3": {"n": 4, "k_eff": 3, "negatives_in_top": 2, "critical_in_top": 1, "covered_intervals": 1,
                      "eligible_intervals": 1, "defined_intervals": 3, "coverage_eligible": 1.0, "coverage_all": 1 / 3,
                      "derivation": "subgroup alone ordered a9(5) a2(3) a10(2) a3(1): a2 enters the top 3, unlike in the mixed queue"},
            },
        },
        "expected_effort_critical_recall": {"1/2": {"required": 3, "position": 6, "queue_fraction": 0.6},
                                            "4/5": {"required": 4, "position": 9, "queue_fraction": 0.9},
                                            "9/10": {"required": 5, "position": 10, "queue_fraction": 1.0}},
        "expected_effort_interval_coverage": {"1/2": {"required": 1, "position": 3, "queue_fraction": 0.3},
                                              "4/5": {"required": 2, "position": 5, "queue_fraction": 0.5},
                                              "1": {"required": 2, "position": 5, "queue_fraction": 0.5}},
        "expected_fraction_budgets": {"1/1000": 1, "1/100": 1, "1/20": 1, "1/10": 1, "1/4": 3, "1/2": 5},
        "expected_ties": {
            "distinct_finite_scores": 5, "missing_scores": 1, "blocks": 6, "tied_blocks": 3, "alerts_in_tied_blocks": 7,
            "share_in_tied_blocks": 0.7, "max_block_size": 3, "median_block_size": 1.5,
            "cutoffs": {
                "3": {"cutoff_block_size": 1, "crosses_cutoff": False, "positions_in_tied_blocks": 2, "order_share": 2 / 3, "members_selected_by_tie_rule": 0, "membership_share": 0.0},
                "4": {"cutoff_block_size": 3, "crosses_cutoff": True, "positions_in_tied_blocks": 3, "order_share": 3 / 4, "members_selected_by_tie_rule": 1, "membership_share": 1 / 4},
                "5": {"cutoff_block_size": 3, "crosses_cutoff": True, "positions_in_tied_blocks": 4, "order_share": 4 / 5, "members_selected_by_tie_rule": 2, "membership_share": 2 / 5},
                "6": {"cutoff_block_size": 3, "crosses_cutoff": False, "positions_in_tied_blocks": 5, "order_share": 5 / 6, "members_selected_by_tie_rule": 0, "membership_share": 0.0},
                "10": {"cutoff_block_size": 1, "crosses_cutoff": False, "positions_in_tied_blocks": 7, "order_share": 0.7, "members_selected_by_tie_rule": 0, "membership_share": 0.0},
            },
            "derivation": "blocks along order: {a4,a9} {a6} {a1,a2,a5} {a8,a10} {a3} {a7:NaN}",
        },
        "expected_random_tie_expectations": {
            "5": {"expected_negatives_in_top": 2.0, "expected_precision": 3 / 5, "expected_attack_recall": 1 / 2,
                  "expected_critical_recall": (1 + 2 * (2 / 3)) / 5,
                  "expected_ndcg_linear": (9 / log2(4) + block3_mean_r * (1 / log2(5) + 1 / log2(6))) / idcg5,
                  "expected_ndcg_exponential": (G[9.0] / log2(4) + block3_mean_g * (1 / log2(5) + 1 / log2(6))) / idcg5_e,
                  "derivation": "block {a1,a2,a5} fills 2 of its 3 positions within the top 5: mean y = 1, mean z = 2/3, mean r = 20.5/3"},
            "3": {"expected_negatives_in_top": 2.0, "expected_critical_recall": 1 / 5,
                  "derivation": "no block crosses k = 3 and block {a4,a9} contains only negatives"},
        },
    }


def example_empty() -> dict:
    return {
        "name": "B_empty_queue",
        "purpose": "No alerts in the queue; a defined critical interval remains uncovered.",
        "tau": 8.0,
        "intervals": [{"scenario": "ex", "attack": "webshell", "start": 0.0, "end": 10.0}],
        "alerts": [],
        "expected_at_k": {"10": {"n": 0, "k_eff": 0, "short_queue": True, "empty_queue": True, "negatives_in_top": 0,
                                 "precision": None, "attack_recall": None, "critical_recall": None, "ndcg_linear": None,
                                 "covered_intervals": 0, "eligible_intervals": 0, "defined_intervals": 1,
                                 "coverage_eligible": None, "coverage_all": 0.0}},
        "expected_first_critical": {"position": None, "critical_total": 0, "prevalence": None},
        "expected_effort_critical_recall": {"1/2": None},
        "expected_effort_interval_coverage": {"1/2": None},
        "expected_fraction_budgets": {"1/4": None},
    }


def example_zero_relevant() -> dict:
    return {
        "name": "C_zero_relevant_alerts",
        "purpose": "Alerts exist but none lies in an interval: ratio metrics with zero denominators are NA; FP counts all.",
        "tau": 8.0,
        "intervals": [{"scenario": "ex", "attack": "webshell", "start": 0.0, "end": 10.0}],
        "alerts": [{"id": "n1", "t": 20.0, "score": 3.0}, {"id": "n2", "t": 30.0, "score": 2.0}, {"id": "n3", "t": 40.0, "score": 1.0}],
        "expected_at_k": {"2": {"n": 3, "k_eff": 2, "short_queue": False, "empty_queue": False, "negatives_in_top": 2,
                                "precision": 0.0, "attack_recall": None, "critical_recall": None, "ndcg_linear": None,
                                "covered_intervals": 0, "eligible_intervals": 0, "defined_intervals": 1,
                                "coverage_eligible": None, "coverage_all": 0.0}},
        "expected_first_critical": {"position": None, "critical_total": 0, "prevalence": 0.0},
        "expected_effort_critical_recall": {"1/2": None},
        "expected_effort_interval_coverage": {"1/2": None},
    }


def example_effort_integer() -> dict:
    alerts = [{"id": f"c{i}", "t": float(i), "score": float(100 - i)} for i in range(30)]
    alerts += [{"id": f"n{i}", "t": 200.0 + i, "score": 1.0} for i in range(10)]
    return {
        "name": "D_effort_exact_integer_ceiling",
        "purpose": "30 critical alerts ranked first in a 40-alert queue: required counts are exact ceilings (15, 24, 27) and effort positions equal them; queue-fraction budgets for n = 40. (Floating-point ceilings agree with exact arithmetic for the declared targets and fractions for every count up to 2,000,000; exact integer arithmetic is used regardless.)",
        "tau": 8.0,
        "intervals": [{"scenario": "ex", "attack": "webshell", "start": 0.0, "end": 100.0}],
        "alerts": alerts,
        "expected_effort_critical_recall": {"1/2": {"required": 15, "position": 15, "queue_fraction": 15 / 40},
                                            "4/5": {"required": 24, "position": 24, "queue_fraction": 24 / 40},
                                            "9/10": {"required": 27, "position": 27, "queue_fraction": 27 / 40}},
        "expected_effort_interval_coverage": {"1": {"required": 1, "position": 1, "queue_fraction": 1 / 40}},
        "expected_fraction_budgets": {"1/1000": 1, "1/100": 1, "1/20": 2, "1/10": 4, "1/4": 10, "1/2": 20},
    }


def example_duplicates() -> dict:
    same = {"detector": "wazuh", "key": "k", "host": "h1"}
    return {
        "name": "E_duplicates_anchored_windows",
        "purpose": "Anchored 60 s windows; a cluster whose representative is negative but a member lies in a critical interval; chronological credit only from the investigated alert itself.",
        "tau": 8.0,
        "window_seconds": 60.0,
        "intervals": [{"scenario": "ex", "attack": "webshell", "start": 50.0, "end": 110.0}],
        "alerts": [
            {"id": "d1", "t": 0.0, "score": 1.0, **same}, {"id": "d2", "t": 30.0, "score": 1.0, **same},
            {"id": "d3", "t": 59.999, "score": 1.0, **same}, {"id": "d4", "t": 60.0, "score": 1.0, **same},
            {"id": "d5", "t": 100.0, "score": 1.0, **same}, {"id": "d6", "t": 125.0, "score": 1.0, **same},
            {"id": "d7", "t": 0.0, "score": 1.0, "detector": "wazuh", "key": "k", "host": "h2"},
        ],
        "expected_representative_of": {"d1": "d1", "d2": "d1", "d3": "d1", "d4": "d4", "d5": "d4", "d6": "d6", "d7": "d7"},
        "expected_cluster_summary": {"clusters": 4, "mixed_label_clusters": 1, "member_conferred_positive_clusters": 1,
                                     "multi_interval_clusters": 0},
        "expected_static_cluster_positive": {"d1": True, "d4": True, "d6": False, "d7": False},
        "expected_representative_own_positive": {"d1": False, "d4": True, "d6": False, "d7": False},
        "chronological_cases": [
            {"investigations": {"d1": 10.0, "d7": 5.0}, "expected_detection": [None],
             "derivation": "d1 (t=0) is outside the interval; its suppressed member d3 (t=59.999) confers nothing"},
            {"investigations": {"d1": 10.0, "d4": 70.0}, "expected_detection": [70.0]},
            {"investigations": {"d4": 55.0}, "expected_error": "investigation before arrival (d4 arrives at 60)"},
        ],
    }


def example_near_ties() -> dict:
    return {
        "name": "F_near_tie_rounding",
        "purpose": "Four significant digits (correctly rounded); values chosen away from exact halves.",
        "scores": [1.23456, 1.23464, 1.23449, 0.00012346, 12345.6, -2.71828, 0.0],
        "expected_rounded": [1.235, 1.235, 1.234, 0.0001235, 12350.0, -2.718, 0.0],
    }


def main() -> int:
    examples = [example_a(), example_empty(), example_zero_relevant(), example_effort_integer(), example_duplicates(),
                example_near_ties()]
    payload = {
        "description": "Hand-calculated reference examples for the WP3 metric contract. Expected values are explicit formulas in scripts/revision/wp3_build_reference_examples.py.",
        "severity_table": SEV,
        "examples": examples,
    }
    out = PROJECT_ROOT / "docs/revision/wp3/reference_examples.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {len(examples)} examples to {out.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

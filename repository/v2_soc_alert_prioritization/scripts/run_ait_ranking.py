#!/usr/bin/env python
"""Run AIT leave-one-scenario-out alert ranking experiments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from soc_alert_ranking.loaders.ait_alert import load_ait_alerts
from soc_alert_ranking.mappings.ait_detector_mapping import (
    MappingThresholds,
    apply_native_key_mapping,
    evaluate_phase_mapping,
    learn_native_key_mapping,
    leave_one_scenario_out_splits,
)
from soc_alert_ranking.mappings.context import apply_asset_context, apply_uncertainty_policy
from soc_alert_ranking.mappings.reliability import (
    apply_reliability_heights,
    calibrate_alert_precision_reliability,
)
from soc_alert_ranking.metrics.ranking import compute_ranking_metrics, rank_alerts
from soc_alert_ranking.rankers.baselines import add_ranking_scores


METHODS = {
    "sgfn": "score_sgfn",
    "severity": "score_severity",
    "reliability": "score_reliability",
    "weighted": "score_weighted",
    "detector_native": "score_detector",
    "recency": "score_recency",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-path",
        default=str(PROJECT_ROOT / "data/raw/ait_alert"),
        help="Path containing extracted AIT JSON files and labels.csv.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(PROJECT_ROOT / "results/ait_alert/ranking_eval"),
        help="Output directory for ranking results.",
    )
    parser.add_argument("--kappa", type=float, default=1.0)
    parser.add_argument(
        "--context-mode",
        choices=["flat", "asset_profile"],
        default="flat",
        help="Asset criticality policy.",
    )
    parser.add_argument(
        "--uncertainty-mode",
        choices=["table", "ambiguity_aware"],
        default="table",
        help="Uncertainty factor policy.",
    )
    parser.add_argument("--k-values", type=int, nargs="*", default=[10, 25, 50, 100, 250, 500, 1000])
    parser.add_argument("--min-support", type=int, default=5)
    parser.add_argument("--min-positive", type=int, default=3)
    parser.add_argument("--min-precision", type=float, default=0.5)
    parser.add_argument("--min-phase-purity", type=float, default=0.7)
    parser.add_argument("--height-shrinkage-lambda", type=float, default=50.0)
    parser.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="Optional subset of scenarios to evaluate.",
    )
    parser.add_argument(
        "--write-top-samples",
        action="store_true",
        help="Write top-1000 ranked samples for each fold and method.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading AIT alerts...")
    selected_files = None
    if args.scenarios:
        raw_path = Path(args.raw_path)
        keep = set(args.scenarios)
        selected_files = [
            path
            for path in raw_path.glob("*.json")
            if path.stem.rsplit("_", 1)[0] in keep
        ]
    alerts = load_ait_alerts(args.raw_path, files=selected_files)
    if args.scenarios:
        keep = set(args.scenarios)
        alerts = alerts[alerts["scenario"].isin(keep)].reset_index(drop=True)
    if alerts.empty:
        print("No alerts loaded.")
        return 1

    thresholds = MappingThresholds(
        min_support=args.min_support,
        min_positive=args.min_positive,
        min_precision=args.min_precision,
        min_phase_purity=args.min_phase_purity,
    )

    metric_rows = []
    mapping_rows = []
    for train_scenarios, held_out in leave_one_scenario_out_splits(alerts["scenario"]):
        print(f"Ranking held-out scenario: {held_out}")
        train = alerts[alerts["scenario"].isin(train_scenarios)].copy()
        test = alerts[alerts["scenario"] == held_out].copy()

        native_mapping = learn_native_key_mapping(train, thresholds)
        mapped_train = apply_native_key_mapping(train, native_mapping)
        mapped_test = apply_native_key_mapping(test, native_mapping)
        mapping_metrics = evaluate_phase_mapping(mapped_test)
        mapping_metrics.update(
            {
                "held_out": held_out,
                "accepted_keys": int(native_mapping["accepted"].sum()) if not native_mapping.empty else 0,
                "total_keys": int(len(native_mapping)),
            }
        )
        mapping_rows.append(mapping_metrics)

        reliability = calibrate_alert_precision_reliability(
            mapped_train,
            shrinkage_lambda=args.height_shrinkage_lambda,
        )
        scored = apply_reliability_heights(mapped_test, reliability)
        scored = apply_asset_context(scored, args.context_mode)
        scored = apply_uncertainty_policy(scored, args.uncertainty_mode)
        scored = add_ranking_scores(scored, kappa=args.kappa)

        native_mapping.to_csv(out_dir / f"native_mapping_train_without_{held_out}.csv", index=False)
        reliability.to_csv(out_dir / f"reliability_train_without_{held_out}.csv", index=False)

        for method, score_column in METHODS.items():
            metrics = compute_ranking_metrics(scored, score_column, k_values=args.k_values)
            metrics.update(
                {
                    "held_out": held_out,
                    "method": method,
                    "score_column": score_column,
                    "test_rows": int(len(scored)),
                    "kappa": args.kappa,
                    "context_mode": args.context_mode,
                    "uncertainty_mode": args.uncertainty_mode,
                }
            )
            metric_rows.append(metrics)
            if args.write_top_samples:
                rank_alerts(scored, score_column).head(1000).to_csv(
                    out_dir / f"top1000_{held_out}_{method}.csv",
                    index=False,
                )

    metrics_df = pd.DataFrame(metric_rows)
    mapping_df = pd.DataFrame(mapping_rows)
    metrics_df.to_csv(out_dir / "ranking_metrics.csv", index=False)
    mapping_df.to_csv(out_dir / "mapping_metrics.csv", index=False)

    summary = {
        "kappa": args.kappa,
        "context_mode": args.context_mode,
        "uncertainty_mode": args.uncertainty_mode,
        "thresholds": thresholds.__dict__,
        "method_means": _method_means(metrics_df),
        "mapping_means": {
            col: float(mapping_df[col].mean())
            for col in [
                "coverage",
                "attack_coverage",
                "critical_coverage",
                "mapped_attack_precision",
                "phase_accuracy_when_mapped",
            ]
            if col in mapping_df
        },
    }
    (out_dir / "ranking_eval_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps(summary["method_means"], indent=2, sort_keys=True))
    print(f"Wrote ranking results to {out_dir}")
    return 0


def _method_means(metrics_df: pd.DataFrame) -> dict[str, dict[str, float]]:
    wanted = [
        "ndcg@10",
        "ndcg@100",
        "ndcg@500",
        "critical_recall@10",
        "critical_recall@100",
        "critical_recall@500",
        "false_positives@100",
        "rank_first_critical",
        "effort_for_critical_recall_0.5",
        "effort_for_critical_recall_0.8",
        "effort_for_critical_recall_0.9",
        "effort_for_critical_recall_0.95",
    ]
    output: dict[str, dict[str, float]] = {}
    for method, group in metrics_df.groupby("method"):
        output[method] = {
            col: float(group[col].mean())
            for col in wanted
            if col in group.columns
        }
    return output


if __name__ == "__main__":
    raise SystemExit(main())

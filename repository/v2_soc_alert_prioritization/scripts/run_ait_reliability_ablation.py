#!/usr/bin/env python
"""Run AIT reliability-calibration ablations."""

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
    leave_one_scenario_out_splits,
    learn_native_key_mapping,
)
from soc_alert_ranking.mappings.context import apply_asset_context, apply_uncertainty_policy
from soc_alert_ranking.mappings.reliability import (
    apply_reliability_heights,
    calibrate_alert_precision_reliability,
)
from soc_alert_ranking.metrics.ranking import compute_ranking_metrics
from soc_alert_ranking.rankers.baselines import add_ranking_scores


POLICIES = {
    "detector_class": "Detector-class SGFN",
    "global_class": "Global-class SGFN",
    "detector_only": "Detector-only SGFN",
    "native_detector": "Native detector score",
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
        default=str(PROJECT_ROOT / "results/ait_alert/reliability_ablation"),
        help="Output directory for ablation results.",
    )
    parser.add_argument("--kappa", type=float, default=1.0)
    parser.add_argument("--context-mode", choices=["flat", "asset_profile"], default="asset_profile")
    parser.add_argument(
        "--uncertainty-mode",
        choices=["table", "ambiguity_aware"],
        default="ambiguity_aware",
    )
    parser.add_argument("--k-values", type=int, nargs="*", default=[10, 25, 50, 100, 250, 500, 1000])
    parser.add_argument("--min-support", type=int, default=5)
    parser.add_argument("--min-positive", type=int, default=3)
    parser.add_argument("--min-precision", type=float, default=0.5)
    parser.add_argument("--min-phase-purity", type=float, default=0.7)
    parser.add_argument("--height-shrinkage-lambda", type=float, default=50.0)
    parser.add_argument("--height-min", type=float, default=0.05)
    parser.add_argument("--height-max", type=float, default=0.95)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    alerts = load_ait_alerts(args.raw_path)
    if alerts.empty:
        print("No AIT alerts loaded.")
        return 1

    thresholds = MappingThresholds(
        min_support=args.min_support,
        min_positive=args.min_positive,
        min_precision=args.min_precision,
        min_phase_purity=args.min_phase_purity,
    )

    metric_rows = []
    calibration_rows = []
    for train_scenarios, held_out in leave_one_scenario_out_splits(alerts["scenario"]):
        print(f"Reliability ablation held-out scenario: {held_out}")
        train = alerts[alerts["scenario"].isin(train_scenarios)].copy()
        test = alerts[alerts["scenario"] == held_out].copy()

        native_mapping = learn_native_key_mapping(train, thresholds)
        mapped_train = apply_native_key_mapping(train, native_mapping)
        mapped_test = apply_native_key_mapping(test, native_mapping)
        mapped_test = apply_asset_context(mapped_test, args.context_mode)
        mapped_test = apply_uncertainty_policy(mapped_test, args.uncertainty_mode)

        policy_frames = build_policy_frames(
            mapped_train,
            mapped_test,
            shrinkage_lambda=args.height_shrinkage_lambda,
            height_min=args.height_min,
            height_max=args.height_max,
        )

        for policy, policy_frame in policy_frames.items():
            scored = add_ranking_scores(policy_frame, kappa=args.kappa)
            score_column = "score_detector" if policy == "native_detector" else "score_sgfn"
            metrics = compute_ranking_metrics(scored, score_column, k_values=args.k_values)
            metrics.update(
                {
                    "held_out": held_out,
                    "policy": policy,
                    "policy_label": POLICIES[policy],
                    "score_column": score_column,
                    "test_rows": int(len(scored)),
                    "kappa": args.kappa,
                    "context_mode": args.context_mode,
                    "uncertainty_mode": args.uncertainty_mode,
                }
            )
            metric_rows.append(metrics)

        calibration_rows.extend(
            calibration_diagnostics(
                mapped_train,
                held_out=held_out,
                shrinkage_lambda=args.height_shrinkage_lambda,
                height_min=args.height_min,
                height_max=args.height_max,
            )
        )

    metrics_df = pd.DataFrame(metric_rows)
    diagnostics_df = pd.DataFrame(calibration_rows)
    summary_df = summarize_metrics(metrics_df)

    metrics_path = out_dir / "ait_reliability_ablation_metrics.csv"
    summary_path = out_dir / "ait_reliability_ablation_summary.csv"
    diagnostics_path = out_dir / "ait_reliability_ablation_calibration_diagnostics.csv"
    metadata_path = out_dir / "ait_reliability_ablation_summary.json"

    metrics_df.to_csv(metrics_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    diagnostics_df.to_csv(diagnostics_path, index=False)
    metadata = {
        "source_raw_path": str(args.raw_path),
        "folds": int(metrics_df["held_out"].nunique()),
        "policies": POLICIES,
        "kappa": args.kappa,
        "context_mode": args.context_mode,
        "uncertainty_mode": args.uncertainty_mode,
        "height_shrinkage_lambda": args.height_shrinkage_lambda,
        "metrics_output": str(metrics_path),
        "summary_output": str(summary_path),
        "diagnostics_output": str(diagnostics_path),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(summary_df.to_string(index=False))
    return 0


def build_policy_frames(
    mapped_train: pd.DataFrame,
    mapped_test: pd.DataFrame,
    shrinkage_lambda: float,
    height_min: float,
    height_max: float,
) -> dict[str, pd.DataFrame]:
    detector_class = calibrate_alert_precision_reliability(
        mapped_train,
        shrinkage_lambda=shrinkage_lambda,
        height_min=height_min,
        height_max=height_max,
    )
    return {
        "detector_class": apply_reliability_heights(mapped_test, detector_class),
        "global_class": apply_global_class_heights(
            mapped_test,
            calibrate_global_class_reliability(
                mapped_train,
                shrinkage_lambda=shrinkage_lambda,
                height_min=height_min,
                height_max=height_max,
            ),
        ),
        "detector_only": apply_detector_heights(
            mapped_test,
            calibrate_detector_reliability(
                mapped_train,
                shrinkage_lambda=shrinkage_lambda,
                height_min=height_min,
                height_max=height_max,
            ),
        ),
        "native_detector": apply_native_detector_height(mapped_test),
    }


def calibrate_global_class_reliability(
    alerts: pd.DataFrame,
    class_column: str = "attack_class",
    label_column: str = "is_attack",
    shrinkage_lambda: float = 50.0,
    height_min: float = 0.05,
    height_max: float = 0.95,
) -> pd.DataFrame:
    required = {class_column, label_column}
    missing = required.difference(alerts.columns)
    if missing:
        raise ValueError(f"Missing columns for global-class reliability: {sorted(missing)}")
    working = alerts[list(required)].copy()
    working[label_column] = working[label_column].astype(bool)
    global_prior = float(working[label_column].mean()) if len(working) else 0.5
    grouped = (
        working.groupby(class_column)[label_column]
        .agg(["count", "mean"])
        .rename(columns={"count": "support", "mean": "precision"})
        .reset_index()
    )
    weights = grouped["support"] / (grouped["support"] + shrinkage_lambda)
    grouped["height"] = weights * grouped["precision"] + (1.0 - weights) * global_prior
    grouped["height"] = grouped["height"].clip(lower=height_min, upper=height_max)
    grouped["global_prior"] = global_prior
    return grouped.rename(columns={class_column: "attack_class"})


def apply_global_class_heights(alerts: pd.DataFrame, reliability: pd.DataFrame) -> pd.DataFrame:
    merged = alerts.merge(
        reliability[["attack_class", "height", "global_prior"]],
        on="attack_class",
        how="left",
    )
    default_height = (
        float(reliability["global_prior"].iloc[0]) if not reliability.empty else 0.5
    )
    merged["height"] = merged["height"].fillna(default_height).clip(lower=0.05, upper=0.95)
    return merged.drop(columns=["global_prior"])


def calibrate_detector_reliability(
    alerts: pd.DataFrame,
    detector_column: str = "detector",
    label_column: str = "is_attack",
    shrinkage_lambda: float = 50.0,
    height_min: float = 0.05,
    height_max: float = 0.95,
) -> pd.DataFrame:
    required = {detector_column, label_column}
    missing = required.difference(alerts.columns)
    if missing:
        raise ValueError(f"Missing columns for detector reliability: {sorted(missing)}")
    working = alerts[list(required)].copy()
    working[label_column] = working[label_column].astype(bool)
    global_prior = float(working[label_column].mean()) if len(working) else 0.5
    grouped = (
        working.groupby(detector_column)[label_column]
        .agg(["count", "mean"])
        .rename(columns={"count": "support", "mean": "precision"})
        .reset_index()
    )
    weights = grouped["support"] / (grouped["support"] + shrinkage_lambda)
    grouped["height"] = weights * grouped["precision"] + (1.0 - weights) * global_prior
    grouped["height"] = grouped["height"].clip(lower=height_min, upper=height_max)
    grouped["global_prior"] = global_prior
    return grouped.rename(columns={detector_column: "detector"})


def apply_detector_heights(alerts: pd.DataFrame, reliability: pd.DataFrame) -> pd.DataFrame:
    merged = alerts.merge(
        reliability[["detector", "height", "global_prior"]],
        on="detector",
        how="left",
    )
    default_height = (
        float(reliability["global_prior"].iloc[0]) if not reliability.empty else 0.5
    )
    merged["height"] = merged["height"].fillna(default_height).clip(lower=0.05, upper=0.95)
    return merged.drop(columns=["global_prior"])


def apply_native_detector_height(alerts: pd.DataFrame) -> pd.DataFrame:
    out = alerts.copy()
    detector_score = out["detector_score"].fillna(0.5).astype(float)
    out["height"] = detector_score.clip(lower=0.05, upper=0.95)
    return out


def calibration_diagnostics(
    mapped_train: pd.DataFrame,
    held_out: str,
    shrinkage_lambda: float,
    height_min: float,
    height_max: float,
) -> list[dict[str, float | int | str]]:
    rows: list[dict[str, float | int | str]] = []
    detector_class = calibrate_alert_precision_reliability(
        mapped_train,
        shrinkage_lambda=shrinkage_lambda,
        height_min=height_min,
        height_max=height_max,
    )
    global_class = calibrate_global_class_reliability(
        mapped_train,
        shrinkage_lambda=shrinkage_lambda,
        height_min=height_min,
        height_max=height_max,
    )
    detector_only = calibrate_detector_reliability(
        mapped_train,
        shrinkage_lambda=shrinkage_lambda,
        height_min=height_min,
        height_max=height_max,
    )
    for policy, frame in [
        ("detector_class", detector_class),
        ("global_class", global_class),
        ("detector_only", detector_only),
    ]:
        rows.append(
            {
                "held_out": held_out,
                "policy": policy,
                "calibration_cells": int(len(frame)),
                "mean_support": float(frame["support"].mean()) if not frame.empty else 0.0,
                "mean_height": float(frame["height"].mean()) if not frame.empty else 0.0,
                "min_height": float(frame["height"].min()) if not frame.empty else 0.0,
                "max_height": float(frame["height"].max()) if not frame.empty else 0.0,
            }
        )
    return rows


def summarize_metrics(metrics: pd.DataFrame) -> pd.DataFrame:
    wanted = [
        "ndcg@10",
        "ndcg@100",
        "ndcg@500",
        "critical_recall@100",
        "false_positives@100",
        "rank_first_critical",
        "effort_for_critical_recall_0.8",
    ]
    rows = []
    for policy in POLICIES:
        group = metrics[metrics["policy"] == policy]
        row = {
            "policy": policy,
            "policy_label": POLICIES[policy],
            "folds": int(group["held_out"].nunique()),
        }
        for metric in wanted:
            if metric in group:
                row[metric] = float(group[metric].mean())
        rows.append(row)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    raise SystemExit(main())

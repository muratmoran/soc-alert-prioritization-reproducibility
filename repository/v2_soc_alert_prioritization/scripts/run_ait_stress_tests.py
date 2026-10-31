#!/usr/bin/env python
"""Run AIT robustness stress tests for alert-ranking inputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from soc_alert_ranking.loaders.ait_alert import load_ait_alerts
from soc_alert_ranking.mappings.ait_detector_mapping import (
    MappingThresholds,
    apply_native_key_mapping,
    learn_native_key_mapping,
    leave_one_scenario_out_splits,
)
from soc_alert_ranking.mappings.context import apply_asset_context, apply_uncertainty_policy
from soc_alert_ranking.mappings.reliability import (
    apply_reliability_heights,
    calibrate_alert_precision_reliability,
)
from soc_alert_ranking.metrics.ranking import compute_ranking_metrics
from soc_alert_ranking.rankers.baselines import add_ranking_scores


METHODS = {
    "sgfn": "score_sgfn",
    "severity": "score_severity",
    "weighted": "score_weighted",
    "detector_native": "score_detector",
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
        default=str(PROJECT_ROOT / "results/ait_alert/stress_tests"),
        help="Output directory for stress-test results.",
    )
    parser.add_argument("--kappa", type=float, default=1.0)
    parser.add_argument("--context-mode", choices=["flat", "asset_profile"], default="asset_profile")
    parser.add_argument("--uncertainty-mode", choices=["table", "ambiguity_aware"], default="ambiguity_aware")
    parser.add_argument("--k-values", type=int, nargs="*", default=[10, 25, 50, 100, 250, 500])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-support", type=int, default=5)
    parser.add_argument("--min-positive", type=int, default=3)
    parser.add_argument("--min-precision", type=float, default=0.5)
    parser.add_argument("--min-phase-purity", type=float, default=0.7)
    parser.add_argument("--height-shrinkage-lambda", type=float, default=50.0)
    parser.add_argument(
        "--noise-fraction",
        type=float,
        default=0.01,
        help="High-severity benign alert injection rate relative to held-out rows.",
    )
    parser.add_argument(
        "--noise-cap",
        type=int,
        default=5000,
        help="Maximum injected high-severity benign alerts per held-out fold.",
    )
    parser.add_argument(
        "--duplicate-fraction",
        type=float,
        default=0.02,
        help="Benign duplicate pressure rate relative to held-out rows.",
    )
    parser.add_argument(
        "--duplicate-cap",
        type=int,
        default=5000,
        help="Maximum duplicated benign alerts per held-out fold.",
    )
    parser.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="Optional subset of AIT scenarios for smoke tests.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rng = np.random.default_rng(args.seed)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

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
        alerts = alerts[alerts["scenario"].isin(set(args.scenarios))].reset_index(drop=True)
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
    stress_rows = []
    top_samples = []
    for fold_index, (train_scenarios, held_out) in enumerate(leave_one_scenario_out_splits(alerts["scenario"])):
        print(f"Stress testing held-out scenario: {held_out}")
        train = alerts[alerts["scenario"].isin(train_scenarios)].copy()
        test = alerts[alerts["scenario"] == held_out].copy()

        native_mapping = learn_native_key_mapping(train, thresholds)
        mapped_train = apply_native_key_mapping(train, native_mapping)
        mapped_test = apply_native_key_mapping(test, native_mapping)
        reliability = calibrate_alert_precision_reliability(
            mapped_train,
            shrinkage_lambda=args.height_shrinkage_lambda,
        )
        base = apply_reliability_heights(mapped_test, reliability)
        base = apply_asset_context(base, args.context_mode)
        base = apply_uncertainty_policy(base, args.uncertainty_mode)
        base = add_ranking_scores(base, kappa=args.kappa)

        fold_rng = np.random.default_rng(args.seed + fold_index)
        variants = build_stress_variants(base, args, fold_rng)
        for stress_name, stress_info, frame in variants:
            scored = add_ranking_scores(frame, kappa=args.kappa)
            stress_info.update(
                {
                    "held_out": held_out,
                    "stress": stress_name,
                    "rows": int(len(scored)),
                    "attack_rows": int(scored["is_attack"].sum()),
                    "critical_rows": int(scored["is_critical"].sum()),
                    "synthetic_rows": int(scored.get("synthetic_stress", False).sum())
                    if "synthetic_stress" in scored.columns
                    else 0,
                }
            )
            stress_rows.append(stress_info)
            for method, score_column in METHODS.items():
                metrics = compute_ranking_metrics(scored, score_column, k_values=args.k_values)
                metrics.update(
                    {
                        "held_out": held_out,
                        "stress": stress_name,
                        "method": method,
                        "score_column": score_column,
                        "kappa": args.kappa,
                        "context_mode": args.context_mode,
                        "uncertainty_mode": args.uncertainty_mode,
                        "seed": args.seed,
                    }
                )
                metric_rows.append(metrics)
            if stress_name != "baseline":
                sample = scored.sort_values("score_sgfn", ascending=False).head(100)
                sample = sample.assign(held_out=held_out, stress=stress_name)
                top_samples.append(sample)

    metrics_df = pd.DataFrame(metric_rows)
    stress_df = pd.DataFrame(stress_rows)
    summary_df = build_summary(metrics_df)
    metrics_df.to_csv(out_dir / "ait_stress_metrics.csv", index=False)
    stress_df.to_csv(out_dir / "ait_stress_metadata.csv", index=False)
    summary_df.to_csv(out_dir / "ait_stress_summary.csv", index=False)
    if top_samples:
        pd.concat(top_samples, ignore_index=True).to_csv(out_dir / "ait_stress_top_sgfn_samples.csv", index=False)

    summary = {
        "dataset": "ait_alert",
        "stress_design": {
            "reliability_overconfidence": "height is transformed with sqrt(height), inflating low reliability.",
            "asset_shuffle": "asset criticality is shuffled within each held-out scenario.",
            "high_severity_false_positives": "synthetic benign alerts with high severity and high confidence are injected.",
            "duplicate_false_positive_pressure": "benign alerts from frequent native keys are duplicated.",
        },
        "parameters": {
            "kappa": args.kappa,
            "context_mode": args.context_mode,
            "uncertainty_mode": args.uncertainty_mode,
            "seed": args.seed,
            "noise_fraction": args.noise_fraction,
            "noise_cap": args.noise_cap,
            "duplicate_fraction": args.duplicate_fraction,
            "duplicate_cap": args.duplicate_cap,
            "thresholds": thresholds.__dict__,
        },
        "method_stress_means": summary_df.to_dict(orient="records"),
    }
    (out_dir / "ait_stress_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(summary_df.to_string(index=False))
    print(f"Wrote stress-test results to {out_dir}")
    return 0


def build_stress_variants(
    base: pd.DataFrame,
    args: argparse.Namespace,
    rng: np.random.Generator,
) -> list[tuple[str, dict[str, object], pd.DataFrame]]:
    variants: list[tuple[str, dict[str, object], pd.DataFrame]] = []
    baseline = base.copy()
    baseline["synthetic_stress"] = False
    variants.append(("baseline", {"description": "Unchanged AIT ranking input."}, baseline))

    overconfident = base.copy()
    original_height = overconfident["height"].astype(float).clip(lower=0.05, upper=0.95)
    overconfident["height"] = np.sqrt(original_height).clip(lower=0.05, upper=0.95)
    overconfident["synthetic_stress"] = False
    variants.append(
        (
            "reliability_overconfidence",
            {
                "description": "Inflate low reliability with sqrt(height).",
                "mean_height_before": float(original_height.mean()),
                "mean_height_after": float(overconfident["height"].mean()),
            },
            overconfident,
        )
    )

    shuffled = base.copy()
    asset_values = shuffled["asset_criticality"].to_numpy(copy=True)
    rng.shuffle(asset_values)
    shuffled["asset_criticality"] = asset_values
    shuffled["synthetic_stress"] = False
    variants.append(
        (
            "asset_criticality_shuffle",
            {
                "description": "Shuffle asset criticality within the held-out scenario.",
                "unique_asset_values": int(pd.Series(asset_values).nunique()),
            },
            shuffled,
        )
    )

    noisy = inject_high_severity_false_positives(
        base,
        rng,
        fraction=args.noise_fraction,
        cap=args.noise_cap,
    )
    variants.append(
        (
            "high_severity_false_positives",
            {
                "description": "Inject synthetic benign alerts with high ranking-time severity.",
                "requested_fraction": args.noise_fraction,
                "cap": args.noise_cap,
                "injected_rows": int(noisy["synthetic_stress"].sum()),
            },
            noisy,
        )
    )

    duplicated = duplicate_benign_pressure(
        base,
        rng,
        fraction=args.duplicate_fraction,
        cap=args.duplicate_cap,
    )
    variants.append(
        (
            "duplicate_false_positive_pressure",
            {
                "description": "Duplicate benign alerts from frequent native keys.",
                "requested_fraction": args.duplicate_fraction,
                "cap": args.duplicate_cap,
                "duplicated_rows": int(duplicated["synthetic_stress"].sum()),
            },
            duplicated,
        )
    )
    return variants


def inject_high_severity_false_positives(
    base: pd.DataFrame,
    rng: np.random.Generator,
    fraction: float,
    cap: int,
) -> pd.DataFrame:
    count = min(int(round(len(base) * fraction)), cap)
    out = base.copy()
    out["synthetic_stress"] = False
    if count <= 0:
        return out
    benign = base[~base["is_attack"].astype(bool)]
    source = benign if not benign.empty else base
    sampled = source.sample(n=count, replace=len(source) < count, random_state=int(rng.integers(0, 2**31 - 1))).copy()
    sampled = reset_synthetic_alerts(sampled, "high-severity-fp")
    sampled["attack_class"] = "synthetic_high_severity_false_positive"
    sampled["attack_phase"] = "synthetic_high_severity_false_positive"
    sampled["severity"] = 9.5
    sampled["true_severity"] = 0.0
    sampled["uncertainty_factor"] = 0.10
    sampled["height"] = 0.95
    sampled["detector_score"] = 0.95
    sampled["native_severity"] = 10.0
    sampled["asset_criticality"] = 1.0
    sampled["is_attack"] = False
    sampled["is_critical"] = False
    sampled["raw_label"] = "benign"
    sampled["synthetic_stress"] = True
    return pd.concat([out, sampled], ignore_index=True)


def duplicate_benign_pressure(
    base: pd.DataFrame,
    rng: np.random.Generator,
    fraction: float,
    cap: int,
) -> pd.DataFrame:
    count = min(int(round(len(base) * fraction)), cap)
    out = base.copy()
    out["synthetic_stress"] = False
    if count <= 0:
        return out
    benign = base[~base["is_attack"].astype(bool)].copy()
    if benign.empty:
        return out
    frequent_keys = benign["native_key"].value_counts().head(20).index
    pool = benign[benign["native_key"].isin(frequent_keys)]
    if pool.empty:
        pool = benign
    sampled = pool.sample(n=count, replace=len(pool) < count, random_state=int(rng.integers(0, 2**31 - 1))).copy()
    sampled = reset_synthetic_alerts(sampled, "duplicate-fp")
    sampled["synthetic_stress"] = True
    sampled["timestamp"] = sampled["timestamp"].astype(float) + np.arange(1, len(sampled) + 1) * 1e-6
    return pd.concat([out, sampled], ignore_index=True)


def reset_synthetic_alerts(frame: pd.DataFrame, prefix: str) -> pd.DataFrame:
    out = frame.copy()
    out["alert_id"] = [f"ait-stress-{prefix}-{idx}" for idx in range(len(out))]
    out["native_key"] = out["native_key"].astype(str) + f":{prefix}"
    return out


def build_summary(metrics_df: pd.DataFrame) -> pd.DataFrame:
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
    for (stress, method), group in metrics_df.groupby(["stress", "method"], sort=True):
        row = {"stress": stress, "method": method}
        for column in wanted:
            if column in group.columns:
                row[column] = float(group[column].mean())
        rows.append(row)
    summary = pd.DataFrame(rows)
    if summary.empty:
        return summary
    baseline = summary[summary["stress"] == "baseline"].set_index("method")
    for metric in ["ndcg@100", "false_positives@100", "rank_first_critical"]:
        delta_col = f"delta_{metric}"
        summary[delta_col] = np.nan
        for index, row in summary.iterrows():
            method = row["method"]
            if method in baseline.index and metric in baseline.columns:
                summary.loc[index, delta_col] = row.get(metric, np.nan) - baseline.loc[method, metric]
    return summary.sort_values(["stress", "method"]).reset_index(drop=True)


if __name__ == "__main__":
    raise SystemExit(main())

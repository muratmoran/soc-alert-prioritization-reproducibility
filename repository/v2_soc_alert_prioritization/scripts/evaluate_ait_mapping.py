#!/usr/bin/env python
"""Evaluate calibration-learned AIT native-key mappings."""

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-path",
        default=str(PROJECT_ROOT / "data/raw/ait_alert"),
        help="Path containing extracted AIT JSON files and labels.csv.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(PROJECT_ROOT / "results/ait_alert/mapping_eval"),
        help="Output directory for mapping evaluation results.",
    )
    parser.add_argument("--min-support", type=int, default=5)
    parser.add_argument("--min-positive", type=int, default=3)
    parser.add_argument("--min-precision", type=float, default=0.5)
    parser.add_argument("--min-phase-purity", type=float, default=0.7)
    parser.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="Optional subset of scenarios to evaluate.",
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

    fold_rows = []
    for train_scenarios, held_out in leave_one_scenario_out_splits(alerts["scenario"]):
        print(f"Evaluating held-out scenario: {held_out}")
        train = alerts[alerts["scenario"].isin(train_scenarios)].copy()
        test = alerts[alerts["scenario"] == held_out].copy()
        mapping = learn_native_key_mapping(train, thresholds)
        mapped_test = apply_native_key_mapping(test, mapping)
        metrics = evaluate_phase_mapping(mapped_test)
        metrics.update(
            {
                "held_out": held_out,
                "train_rows": int(len(train)),
                "test_rows": int(len(test)),
                "accepted_keys": int(mapping["accepted"].sum()) if not mapping.empty else 0,
                "total_keys": int(len(mapping)),
            }
        )
        fold_rows.append(metrics)
        mapping.to_csv(out_dir / f"mapping_train_without_{held_out}.csv", index=False)
        mapped_test.head(1000).to_csv(out_dir / f"mapped_sample_{held_out}.csv", index=False)

    fold_df = pd.DataFrame(fold_rows).sort_values("held_out")
    fold_df.to_csv(out_dir / "leave_one_scenario_mapping_metrics.csv", index=False)
    aggregate = {
        "thresholds": thresholds.__dict__,
        "folds": fold_df.to_dict(orient="records"),
        "mean": {
            col: float(fold_df[col].mean())
            for col in [
                "coverage",
                "attack_coverage",
                "critical_coverage",
                "mapped_attack_precision",
                "phase_accuracy_when_mapped",
            ]
        },
    }
    (out_dir / "mapping_eval_summary.json").write_text(
        json.dumps(aggregate, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps(aggregate["mean"], indent=2, sort_keys=True))
    print(f"Wrote mapping evaluation results to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

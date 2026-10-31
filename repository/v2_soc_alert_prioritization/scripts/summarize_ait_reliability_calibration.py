#!/usr/bin/env python
"""Summarize AIT detector-class reliability calibration across LOSO folds."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RANKING_DIR = PROJECT_ROOT / "results/ait_alert/ranking_eval_asset_ambiguity"
DEFAULT_OUT_DIR = PROJECT_ROOT / "results/ait_alert/calibration_summary"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ranking-dir",
        default=str(DEFAULT_RANKING_DIR),
        help="AIT ranking result directory containing reliability_train_without_*.csv files.",
    )
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Output directory for calibration summary artifacts.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ranking_dir = Path(args.ranking_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = summarize_detector_class_reliability(ranking_dir)
    if summary.empty:
        raise SystemExit(f"No reliability calibration files found under {ranking_dir}")

    summary_path = out_dir / "ait_detector_class_reliability_summary.csv"
    summary.to_csv(summary_path, index=False)

    metadata = {
        "source_dir": str(ranking_dir),
        "folds": int(summary["folds"].max()),
        "detector_classes": int(len(summary)),
        "detectors": sorted(summary["detector"].unique().tolist()),
        "output": str(summary_path),
    }
    (out_dir / "ait_detector_class_reliability_summary.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(summary.to_string(index=False))
    return 0


def summarize_detector_class_reliability(ranking_dir: Path) -> pd.DataFrame:
    files = sorted(ranking_dir.glob("reliability_train_without_*.csv"))
    frames = []
    for path in files:
        held_out = path.stem.replace("reliability_train_without_", "")
        fold = pd.read_csv(path)
        required = {"detector", "attack_class", "support", "precision", "detector_prior", "height"}
        missing = required.difference(fold.columns)
        if missing:
            raise ValueError(f"{path} is missing required columns: {sorted(missing)}")
        fold = fold.copy()
        fold["held_out"] = held_out
        detector_total = fold.groupby("detector")["support"].transform("sum")
        fold["detector_share"] = fold["support"] / detector_total.replace(0, pd.NA)
        fold["positive_support"] = fold["support"] * fold["precision"]
        frames.append(fold)

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    grouped = (
        combined.groupby(["detector", "attack_class"], as_index=False)
        .agg(
            folds=("held_out", "nunique"),
            mean_support=("support", "mean"),
            total_support=("support", "sum"),
            mean_positive_support=("positive_support", "mean"),
            mean_detector_share=("detector_share", "mean"),
            mean_ppv=("precision", "mean"),
            min_ppv=("precision", "min"),
            max_ppv=("precision", "max"),
            mean_detector_prior=("detector_prior", "mean"),
            mean_height=("height", "mean"),
            min_height=("height", "min"),
            max_height=("height", "max"),
        )
    )
    grouped["class_role"] = grouped["attack_class"].map(
        lambda value: "unmapped fallback" if str(value) == "unknown" else "mapped class"
    )
    grouped["_detector_order"] = grouped["detector"].map(
        {"aminer": 0, "suricata": 1, "wazuh": 2}
    ).fillna(99)
    grouped["_unknown_last"] = (grouped["attack_class"] == "unknown").astype(int)
    grouped = grouped.sort_values(
        ["_detector_order", "_unknown_last", "attack_class"]
    ).drop(columns=["_detector_order", "_unknown_last"])

    numeric_cols = [
        "mean_support",
        "total_support",
        "mean_positive_support",
        "mean_detector_share",
        "mean_ppv",
        "min_ppv",
        "max_ppv",
        "mean_detector_prior",
        "mean_height",
        "min_height",
        "max_height",
    ]
    grouped[numeric_cols] = grouped[numeric_cols].astype(float).round(6)
    return grouped.reset_index(drop=True)


if __name__ == "__main__":
    raise SystemExit(main())

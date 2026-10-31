#!/usr/bin/env python
"""Summarize AIT analyst effort at fixed critical-alert recall targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METRICS = PROJECT_ROOT / "results/ait_alert/ranking_eval_asset_ambiguity/ranking_metrics.csv"
DEFAULT_OUT_DIR = PROJECT_ROOT / "results/ait_alert/analyst_effort"

METHOD_ORDER = ["sgfn", "weighted", "severity", "reliability", "detector_native", "recency"]
TARGETS = [0.5, 0.8]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", default=str(DEFAULT_METRICS))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metrics_path = Path(args.metrics)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    metrics = pd.read_csv(metrics_path)
    fold_details, summary = analyst_effort_summary(metrics)

    detail_path = out_dir / "ait_analyst_effort_fold_metrics.csv"
    summary_path = out_dir / "ait_analyst_effort_summary.csv"
    metadata_path = out_dir / "ait_analyst_effort_summary.json"
    fold_details.to_csv(detail_path, index=False)
    summary.to_csv(summary_path, index=False)

    metadata = {
        "source_metrics": str(metrics_path),
        "folds": int(metrics["held_out"].nunique()),
        "methods": METHOD_ORDER,
        "targets": TARGETS,
        "detail_output": str(detail_path),
        "summary_output": str(summary_path),
        "interpretation": "Lower fixed-recall effort is better. The metric measures exhaustive critical-label recovery, not only first-critical triage.",
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(summary.to_string(index=False))
    return 0


def analyst_effort_summary(metrics: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    required = {
        "held_out",
        "method",
        "rows",
        "total_critical",
        "critical_recall@100",
        "critical_recall@500",
        "false_positives@100",
        "rank_first_critical",
        *(f"effort_for_critical_recall_{target:g}" for target in TARGETS),
    }
    missing = required.difference(metrics.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    details = metrics.copy()
    for target in TARGETS:
        effort_col = f"effort_for_critical_recall_{target:g}"
        details[f"effort_fraction_{target:g}"] = details[effort_col] / details["rows"]

    keep_columns = [
        "held_out",
        "method",
        "rows",
        "total_critical",
        "critical_recall@100",
        "critical_recall@500",
        "false_positives@100",
        "rank_first_critical",
    ]
    for target in TARGETS:
        keep_columns.extend(
            [
                f"effort_for_critical_recall_{target:g}",
                f"effort_fraction_{target:g}",
            ]
        )
    details = details[keep_columns].copy()
    details["method"] = pd.Categorical(details["method"], categories=METHOD_ORDER, ordered=True)
    details = details.sort_values(["method", "held_out"]).reset_index(drop=True)

    summary_rows = []
    for method, group in details.groupby("method", observed=True):
        row = {
            "method": method,
            "folds": int(group["held_out"].nunique()),
            "mean_rows": float(group["rows"].mean()),
            "mean_total_critical": float(group["total_critical"].mean()),
            "mean_critical_recall_at_100": float(group["critical_recall@100"].mean()),
            "mean_critical_recall_at_500": float(group["critical_recall@500"].mean()),
            "mean_false_positives_at_100": float(group["false_positives@100"].mean()),
            "mean_rank_first_critical": float(group["rank_first_critical"].mean()),
        }
        for target in TARGETS:
            effort_col = f"effort_for_critical_recall_{target:g}"
            fraction_col = f"effort_fraction_{target:g}"
            suffix = str(target).replace(".", "_")
            row[f"mean_effort_recall_{suffix}"] = float(group[effort_col].mean())
            row[f"median_effort_recall_{suffix}"] = float(group[effort_col].median())
            row[f"mean_effort_fraction_recall_{suffix}"] = float(group[fraction_col].mean())
            row[f"median_effort_fraction_recall_{suffix}"] = float(group[fraction_col].median())
        summary_rows.append(row)

    summary = pd.DataFrame(summary_rows)
    summary["method"] = pd.Categorical(summary["method"], categories=METHOD_ORDER, ordered=True)
    summary = summary.sort_values("method").reset_index(drop=True)
    return details, summary


if __name__ == "__main__":
    raise SystemExit(main())

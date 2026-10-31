#!/usr/bin/env python
"""Summarize paired AIT fold-level SGFN improvements over baselines."""

from __future__ import annotations

import argparse
import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METRICS = PROJECT_ROOT / "results/ait_alert/ranking_eval_asset_ambiguity/ranking_metrics.csv"
DEFAULT_OUT_DIR = PROJECT_ROOT / "results/ait_alert/paired_improvements"

BASELINES = ["severity", "detector_native", "weighted"]
METRICS = {
    "ndcg@100": {
        "label": "Delta NDCG@100",
        "direction": "higher",
    },
    "false_positives@100": {
        "label": "FP@100 reduction",
        "direction": "lower",
    },
    "rank_first_critical": {
        "label": "First-critical rank reduction",
        "direction": "lower",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", default=str(DEFAULT_METRICS))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--bootstrap-samples", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metrics_path = Path(args.metrics)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    metrics = pd.read_csv(metrics_path)
    fold_details, summary = paired_improvement_summary(
        metrics,
        baselines=BASELINES,
        bootstrap_samples=args.bootstrap_samples,
        seed=args.seed,
    )

    detail_path = out_dir / "ait_paired_improvement_fold_differences.csv"
    summary_path = out_dir / "ait_paired_improvement_summary.csv"
    metadata_path = out_dir / "ait_paired_improvement_summary.json"
    fold_details.to_csv(detail_path, index=False)
    summary.to_csv(summary_path, index=False)

    metadata = {
        "source_metrics": str(metrics_path),
        "folds": int(metrics["held_out"].nunique()),
        "baselines": BASELINES,
        "metrics": list(METRICS),
        "bootstrap_samples": int(args.bootstrap_samples),
        "seed": int(args.seed),
        "detail_output": str(detail_path),
        "summary_output": str(summary_path),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(summary.to_string(index=False))
    return 0


def paired_improvement_summary(
    metrics: pd.DataFrame,
    baselines: list[str],
    bootstrap_samples: int,
    seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    required = {"held_out", "method", *METRICS.keys()}
    missing = required.difference(metrics.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    rng = np.random.default_rng(seed)
    sgfn = metrics[metrics["method"] == "sgfn"].set_index("held_out")
    if sgfn.empty:
        raise ValueError("No SGFN rows found in metrics.")

    detail_rows = []
    summary_rows = []
    for baseline in baselines:
        base = metrics[metrics["method"] == baseline].set_index("held_out")
        folds = sorted(set(sgfn.index).intersection(base.index))
        if not folds:
            raise ValueError(f"No paired folds found for baseline {baseline}")
        for metric, spec in METRICS.items():
            if spec["direction"] == "higher":
                diff = sgfn.loc[folds, metric].to_numpy(dtype=float) - base.loc[folds, metric].to_numpy(dtype=float)
            else:
                diff = base.loc[folds, metric].to_numpy(dtype=float) - sgfn.loc[folds, metric].to_numpy(dtype=float)

            for fold, value in zip(folds, diff, strict=True):
                detail_rows.append(
                    {
                        "baseline": baseline,
                        "metric": metric,
                        "metric_label": spec["label"],
                        "held_out": fold,
                        "improvement": float(value),
                    }
                )

            ci_low, ci_high = bootstrap_mean_ci(diff, rng, samples=bootstrap_samples)
            summary_rows.append(
                {
                    "baseline": baseline,
                    "metric": metric,
                    "metric_label": spec["label"],
                    "folds": len(folds),
                    "mean_improvement": float(np.mean(diff)),
                    "median_improvement": float(np.median(diff)),
                    "ci95_low": ci_low,
                    "ci95_high": ci_high,
                    "positive_folds": int(np.sum(diff > 0)),
                    "zero_folds": int(np.sum(diff == 0)),
                    "negative_folds": int(np.sum(diff < 0)),
                    "wilcoxon_p_greater": wilcoxon_greater_p(diff),
                }
            )

    detail = pd.DataFrame(detail_rows)
    summary = pd.DataFrame(summary_rows)
    summary["baseline"] = pd.Categorical(summary["baseline"], categories=baselines, ordered=True)
    summary["metric"] = pd.Categorical(summary["metric"], categories=list(METRICS), ordered=True)
    summary = summary.sort_values(["baseline", "metric"]).reset_index(drop=True)
    return detail, summary


def bootstrap_mean_ci(diff: np.ndarray, rng: np.random.Generator, samples: int) -> tuple[float, float]:
    if diff.size == 0:
        return 0.0, 0.0
    indices = rng.integers(0, diff.size, size=(samples, diff.size))
    means = diff[indices].mean(axis=1)
    low, high = np.quantile(means, [0.025, 0.975])
    return float(low), float(high)


def wilcoxon_greater_p(diff: np.ndarray) -> float:
    nonzero = diff[diff != 0]
    if nonzero.size == 0:
        return 1.0
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            return float(wilcoxon(diff, alternative="greater", zero_method="pratt").pvalue)
    except ValueError:
        return 1.0


if __name__ == "__main__":
    raise SystemExit(main())

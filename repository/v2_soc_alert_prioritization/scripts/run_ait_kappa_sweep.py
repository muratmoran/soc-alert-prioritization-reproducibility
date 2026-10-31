#!/usr/bin/env python
"""Run an AIT kappa sensitivity sweep."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kappas",
        type=float,
        nargs="*",
        default=[0.0, 0.25, 0.5, 1.0, 1.5, 2.0],
        help="Kappa values to evaluate.",
    )
    parser.add_argument(
        "--context-mode",
        choices=["flat", "asset_profile"],
        default="asset_profile",
    )
    parser.add_argument(
        "--uncertainty-mode",
        choices=["table", "ambiguity_aware"],
        default="ambiguity_aware",
    )
    parser.add_argument(
        "--base-out-dir",
        default=str(PROJECT_ROOT / "results/ait_alert/kappa_sweep"),
    )
    parser.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="Optional scenario subset for a faster smoke sweep.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_out = Path(args.base_out_dir)
    base_out.mkdir(parents=True, exist_ok=True)

    rows = []
    for kappa in args.kappas:
        label = _kappa_label(kappa)
        out_dir = base_out / f"kappa_{label}"
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts/run_ait_ranking.py"),
            "--kappa",
            str(kappa),
            "--context-mode",
            args.context_mode,
            "--uncertainty-mode",
            args.uncertainty_mode,
            "--out-dir",
            str(out_dir),
        ]
        if args.scenarios:
            cmd.extend(["--scenarios", *args.scenarios])
        print("Running", " ".join(cmd), flush=True)
        subprocess.run(cmd, check=True)

        metrics = pd.read_csv(out_dir / "ranking_metrics.csv")
        sgfn = metrics[metrics["method"] == "sgfn"].copy()
        sgfn["kappa"] = kappa
        rows.append(sgfn)

    all_sgfn = pd.concat(rows, ignore_index=True)
    all_sgfn.to_csv(base_out / "sgfn_kappa_fold_metrics.csv", index=False)
    summary = (
        all_sgfn.groupby("kappa")
        .agg(
            {
                "ndcg@10": "mean",
                "ndcg@100": "mean",
                "ndcg@500": "mean",
                "critical_recall@10": "mean",
                "critical_recall@100": "mean",
                "critical_recall@500": "mean",
                "false_positives@100": "mean",
                "rank_first_critical": "mean",
                "effort_for_critical_recall_0.8": "mean",
            }
        )
        .reset_index()
    )
    summary.to_csv(base_out / "sgfn_kappa_summary.csv", index=False)
    best = {
        "best_ndcg@10": _best(summary, "ndcg@10", maximize=True),
        "best_ndcg@100": _best(summary, "ndcg@100", maximize=True),
        "best_ndcg@500": _best(summary, "ndcg@500", maximize=True),
        "lowest_false_positives@100": _best(summary, "false_positives@100", maximize=False),
        "lowest_rank_first_critical": _best(summary, "rank_first_critical", maximize=False),
    }
    (base_out / "sgfn_kappa_best.json").write_text(
        json.dumps(best, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(summary.to_string(index=False))
    print(json.dumps(best, indent=2, sort_keys=True))
    return 0


def _kappa_label(kappa: float) -> str:
    return str(kappa).replace(".", "p").replace("-", "m")


def _best(summary: pd.DataFrame, column: str, maximize: bool) -> dict[str, float]:
    idx = summary[column].idxmax() if maximize else summary[column].idxmin()
    row = summary.loc[idx]
    return {"kappa": float(row["kappa"]), column: float(row[column])}


if __name__ == "__main__":
    raise SystemExit(main())

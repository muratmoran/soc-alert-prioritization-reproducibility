#!/usr/bin/env python
"""Inspect staged UWF-ZeekData24 CSV and metric files."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from soc_alert_ranking.loaders.uwf_zeekdata24 import (
    discover_uwf_csv_files,
    discover_uwf_metric_files,
    iter_uwf_chunks,
    load_metric_table,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-path",
        default=str(PROJECT_ROOT / "data/raw/uwf_zeekdata24"),
        help="Path containing staged UWF-ZeekData24 csv/ and metrics/ folders.",
    )
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--write-summary", action="store_true")
    parser.add_argument("--sample-rows", type=int, default=1000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_path = Path(args.raw_path)
    files = discover_uwf_csv_files(raw_path)
    if not files:
        print(f"No UWF-ZeekData24 CSV files found under {raw_path}")
        print("Stage the public CSV subset under data/raw/uwf_zeekdata24/csv/.")
        return 1

    counters = {
        "tactics": Counter(),
        "techniques": Counter(),
        "cves": Counter(),
        "subnet_pairs": Counter(),
    }
    rows = 0
    attacks = 0
    critical = 0
    mapped_tactics = 0
    valid_techniques = 0
    valid_cves = 0
    min_time = None
    max_time = None
    sample_frames = []
    sample_remaining = max(args.sample_rows, 0)

    for chunk in iter_uwf_chunks(
        raw_path=raw_path,
        chunksize=args.chunksize,
        max_rows=args.max_rows,
    ):
        rows += len(chunk)
        attacks += int(chunk["is_attack"].sum())
        critical += int(chunk["is_critical"].sum())
        mapped_tactics += int(chunk["mitre_tactic"].notna().sum())
        valid_techniques += int(chunk["mitre_technique"].notna().sum())
        valid_cves += int(chunk["label_cve"].notna().sum())
        counters["tactics"].update(chunk["attack_class"].astype(str))
        counters["techniques"].update(chunk["mitre_technique"].dropna().astype(str))
        counters["cves"].update(chunk["label_cve"].dropna().astype(str))
        counters["subnet_pairs"].update(chunk["subnet_pair"].astype(str))
        chunk_time = pd.to_numeric(chunk["timestamp"], errors="coerce").dropna()
        if not chunk_time.empty:
            chunk_min = float(chunk_time.min())
            chunk_max = float(chunk_time.max())
            min_time = chunk_min if min_time is None else min(min_time, chunk_min)
            max_time = chunk_max if max_time is None else max(max_time, chunk_max)
        if sample_remaining > 0:
            sample = chunk.head(sample_remaining)
            sample_frames.append(sample)
            sample_remaining -= len(sample)

    metric_summary = {}
    metric_files = discover_uwf_metric_files(raw_path)
    for metric_name, metric_path in metric_files.items():
        label_column = f"label_{metric_name}"
        table = load_metric_table(metric_path, label_column)
        metric_summary[metric_name] = {
            row[label_column]: int(row["total_count"])
            for _, row in table.iterrows()
        }

    summary = {
        "rows": rows,
        "attack_rows": attacks,
        "attack_rate": attacks / rows if rows else 0.0,
        "critical_rows": critical,
        "critical_rate": critical / rows if rows else 0.0,
        "mapped_tactic_rate": mapped_tactics / attacks if attacks else 0.0,
        "valid_technique_rate": valid_techniques / attacks if attacks else 0.0,
        "valid_cve_rate": valid_cves / attacks if attacks else 0.0,
        "time_min_epoch": min_time,
        "time_max_epoch": max_time,
        "csv_files": [str(path) for path in files],
        "tactics": dict(counters["tactics"].most_common()),
        "techniques": dict(counters["techniques"].most_common()),
        "cves": dict(counters["cves"].most_common()),
        "top_subnet_pairs": dict(counters["subnet_pairs"].most_common(20)),
        "published_metric_counts": metric_summary,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    if args.write_summary:
        out_dir = PROJECT_ROOT / "results/uwf_zeekdata24"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "uwf_inspection_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        if sample_frames:
            pd.concat(sample_frames, ignore_index=True).head(args.sample_rows).to_csv(
                out_dir / "uwf_canonical_sample.csv",
                index=False,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python
"""Inspect staged NF-UQ-NIDS-v2 files with chunked normalization."""

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

from soc_alert_ranking.loaders.nf_uq_nids import discover_nf_uq_files, iter_nf_uq_chunks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-path",
        default=str(PROJECT_ROOT / "data/raw/nf_uq_nids_v2"),
        help="Path containing the merged NF-UQ-NIDS-v2 CSV or source-domain CSVs.",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=100_000,
        help="Rows per streaming chunk.",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Optional row cap for staged smoke tests or samples.",
    )
    parser.add_argument(
        "--write-summary",
        action="store_true",
        help="Write summary files under results/nf_uq_nids_v2.",
    )
    parser.add_argument(
        "--sample-rows",
        type=int,
        default=1000,
        help="Rows to retain for a normalized sample when --write-summary is set.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_path = Path(args.raw_path)
    files = discover_nf_uq_files(raw_path)
    if not files:
        print(f"No NF-UQ-NIDS-v2 CSV files found under {raw_path}")
        print("Stage either the merged NF-UQ-NIDS-v2 CSV or the four source-domain v2 CSVs there.")
        print("The official UQ RDM link is browser/application mediated, and the full corpus is large.")
        return 1

    counters = {
        "detectors": Counter(),
        "source_domains": Counter(),
        "attack_categories": Counter(),
    }
    rows = 0
    attacks = 0
    critical = 0
    domain_category: Counter[tuple[str, str]] = Counter()
    sample_frames = []
    sample_remaining = max(args.sample_rows, 0)

    for chunk in iter_nf_uq_chunks(
        raw_path=raw_path,
        chunksize=args.chunksize,
        max_rows=args.max_rows,
    ):
        rows += len(chunk)
        attacks += int(chunk["is_attack"].sum())
        critical += int(chunk["is_critical"].sum())
        counters["detectors"].update(chunk["detector"].astype(str))
        counters["source_domains"].update(chunk["source_domain"].astype(str))
        counters["attack_categories"].update(chunk["attack_class"].astype(str))
        domain_category.update(
            zip(chunk["source_domain"].astype(str), chunk["attack_class"].astype(str))
        )
        if sample_remaining > 0:
            sample_frames.append(chunk.head(sample_remaining))
            sample_remaining -= len(sample_frames[-1])

    summary = {
        "rows": rows,
        "attack_rate": attacks / rows if rows else 0.0,
        "critical_rate": critical / rows if rows else 0.0,
        "detectors": dict(counters["detectors"]),
        "source_domains": dict(counters["source_domains"]),
        "attack_categories": dict(counters["attack_categories"].most_common()),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    if args.write_summary:
        out_dir = PROJECT_ROOT / "results/nf_uq_nids_v2"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "nf_uq_inspection_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        category_rows = [
            {"source_domain": domain, "attack_category": category, "count": count}
            for (domain, category), count in sorted(domain_category.items())
        ]
        pd.DataFrame(category_rows).to_csv(out_dir / "nf_uq_domain_category_counts.csv", index=False)
        if sample_frames:
            pd.concat(sample_frames, ignore_index=True).head(args.sample_rows).to_csv(
                out_dir / "nf_uq_canonical_sample.csv",
                index=False,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

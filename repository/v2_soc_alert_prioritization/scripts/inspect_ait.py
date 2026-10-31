#!/usr/bin/env python
"""Inspect AIT Alert Dataset files and canonical normalization."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from soc_alert_ranking.loaders.ait_alert import discover_ait_files, load_ait_alerts
from soc_alert_ranking.mappings.reliability import calibrate_alert_precision_reliability
from soc_alert_ranking.metrics.inspection import summarize_alert_frame


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-path",
        default=str(PROJECT_ROOT / "data/raw/ait_alert"),
        help="Path containing AIT alert files.",
    )
    parser.add_argument(
        "--limit-files",
        type=int,
        default=None,
        help="Inspect only the first N discovered files.",
    )
    parser.add_argument(
        "--write-sample",
        action="store_true",
        help="Write a normalized sample CSV under results/ait_alert.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_path = Path(args.raw_path)
    files = discover_ait_files(raw_path)
    if args.limit_files is not None:
        files = files[: args.limit_files]

    if not files:
        print(f"No AIT alert files found under {raw_path}")
        print("Expected files include CSV/TXT files with columns:")
        print("time,name,ip,host,short,time_label,event_label")
        return 1

    alerts = load_ait_alerts(raw_path, files=files)
    summary = summarize_alert_frame(alerts)
    reliability = calibrate_alert_precision_reliability(alerts)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("\nDetector-conditioned reliability preview:")
    print(
        reliability.sort_values(["detector", "height"], ascending=[True, False])
        .head(30)
        .to_string(index=False)
    )

    if args.write_sample:
        out_dir = PROJECT_ROOT / "results/ait_alert"
        out_dir.mkdir(parents=True, exist_ok=True)
        alerts.head(1000).to_csv(out_dir / "ait_canonical_sample.csv", index=False)
        reliability.to_csv(out_dir / "ait_detector_reliability_preview.csv", index=False)
        (out_dir / "ait_inspection_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

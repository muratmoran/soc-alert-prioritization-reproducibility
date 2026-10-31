#!/usr/bin/env python
"""Download the public UWF-ZeekData24 CSV subset and metric tables."""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.request import urlretrieve


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "https://datasets.uwf.edu/data/UWF-ZeekData24"

FILES = {
    "csv/Benign/part-00000-b039213f-1208-4f1b-b71d-5e8e3a4a2939-c000.csv": "csv/Benign.csv",
    "csv/Credential_Access/part-00000-912fdc44-5727-4d42-8fd6-a0e206ba29f8-c000.csv": "csv/Credential_Access.csv",
    "csv/Defense_Evasion/part-00000-de4985c7-284a-4b6e-b507-e69a2d172582-c000.csv": "csv/Defense_Evasion.csv",
    "csv/Exfiltration/part-00000-6a530c25-0f6b-46a1-ba16-c6b658ef75e8-c000.csv": "csv/Exfiltration.csv",
    "csv/Initial_Access/part-00000-9a37b839-429e-444b-82a5-a6d5e69dad7e-c000.csv": "csv/Initial_Access.csv",
    "csv/Persistence/part-00000-fb5a764a-e65e-4e10-b6fb-1a189589d5e0-c000.csv": "csv/Persistence.csv",
    "csv/Privilege_Escalation/part-00000-d8fcf83a-aed1-4cb1-babf-581208088293-c000.csv": "csv/Privilege_Escalation.csv",
    "csv/Reconnaissance/part-00000-49ed1cc6-3205-4c76-8e28-4da9abf78363-c000.csv": "csv/Reconnaissance.csv",
    "parquet/_parquet_tactic_metrics_/part-00000-96b98da6-0c8b-4f3f-b73d-484cff64125e-c000.csv": "metrics/tactic_metrics.csv",
    "parquet/_parquet_technique_metrics_/part-00000-1c38cbb2-0dd0-47ea-a67e-4e70a8053a4b-c000.csv": "metrics/technique_metrics.csv",
    "parquet/_parquet_cve_metrics_/part-00000-723c46a3-eb6d-4e9b-afb0-d89e104c759a-c000.csv": "metrics/cve_metrics.csv",
    "parquet/_parquet_binary_metrics_/part-00000-4cde30e0-bdbe-4bf7-91e0-96bf7023d0d3-c000.csv": "metrics/binary_metrics.csv",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "data/raw/uwf_zeekdata24"),
        help="Destination directory for the UWF csv/ and metrics/ folders.",
    )
    parser.add_argument("--force", action="store_true", help="Redownload existing files.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    for remote_path, local_path in FILES.items():
        target = output_dir / local_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.stat().st_size > 0 and not args.force:
            print(f"skip {target} ({target.stat().st_size} bytes)")
            continue
        url = f"{BASE_URL}/{remote_path}"
        print(f"download {url} -> {target}")
        urlretrieve(url, target)
        print(f"wrote {target.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

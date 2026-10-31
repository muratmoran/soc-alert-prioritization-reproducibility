#!/usr/bin/env python
"""WP2 real-data comparison runner (AIT), gated behind WP3 and WP4 verification.

Modes:

* ``--construction-check``: verify input identities and build the label-free ranking
  frame and the interval table on real data. No features are fitted, no candidate is
  scored, and no metric is computed.
* full run (no flag): runs every outer fold for the requested policies. Refuses to
  start unless docs/revision/wp3/metric_verification.json and
  docs/revision/wp4/fitting_boundary_verification.json both exist with "verified": true,
  and the grid registry matches the frozen record.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.features import RANKING_TIME_COLUMNS, RankingFrame  # noqa: E402
from soc_alert_ranking.revision.labels import LabelStore, load_label_intervals, phase_order  # noqa: E402
from soc_alert_ranking.revision.native_scores import load_revised_alerts  # noqa: E402
from soc_alert_ranking.revision.pipeline import ComparisonPipeline, write_fold_outputs  # noqa: E402

GATES = [PROJECT_ROOT / "docs/revision/wp3/metric_verification.json",
         PROJECT_ROOT / "docs/revision/wp4/fitting_boundary_verification.json"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_inputs(cache: Path, labels_csv: Path, provenance: Path):
    manifest = json.loads((PROJECT_ROOT / "docs/revision/provenance_manifest.json").read_text())
    expected_md5 = manifest["raw_data_verification"]["ait_alert"]["details"]["published_md5"]["labels.csv"]["expected"]
    if hashlib.md5(labels_csv.read_bytes()).hexdigest() != expected_md5:
        raise SystemExit("labels.csv does not match the published Zenodo MD5")
    alerts, identities = load_revised_alerts(cache, provenance)
    identity = {"sha256": identities["canonical_cache_sha256"], "provenance_sha256": identities["provenance_cache_sha256"]}
    # Only ranking-time columns enter the pipeline; loader labels and inferred phases are discarded.
    return alerts.loc[:, list(RANKING_TIME_COLUMNS)], identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", default=str(Path.home() / "soc_revision_data/cache/ait_canonical_original_labels.pkl.gz"))
    parser.add_argument("--labels", default=str(Path.home() / "soc_revision_data/ait_alert/labels.csv"))
    parser.add_argument("--provenance", default=str(Path.home() / "soc_revision_data/cache/ait_native_score_provenance.pkl.gz"))
    parser.add_argument("--config", default=str(PROJECT_ROOT / "configs/revision_wp2.yaml"))
    parser.add_argument("--policies", nargs="+", choices=["primary", "secondary"], default=["primary", "secondary"])
    parser.add_argument("--out-dir", default=str(PROJECT_ROOT / "results/revision_cose_04000/wp2/real"))
    parser.add_argument("--construction-check", action="store_true")
    args = parser.parse_args()

    config = load_comparison_config(args.config)
    severity = SeverityMapping.from_file()
    started = time.perf_counter()
    alerts, identity = load_inputs(Path(args.cache), Path(args.labels), Path(args.provenance))
    ranking = RankingFrame.from_alerts(alerts)
    intervals = load_label_intervals(args.labels, severity, config.tau)

    if args.construction_check:
        raw = pd.read_csv(args.labels)
        overlaps = 0
        for scenario, part in intervals.groupby("scenario"):
            spans = part[["start", "end"]].to_numpy()
            for i in range(len(spans)):
                for j in range(i + 1, len(spans)):
                    overlaps += int(spans[i, 0] < spans[j, 1] and spans[j, 0] < spans[i, 1])
        report = {
            "mode": "construction_check",
            "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "note": "No features fitted, no candidates scored, no metrics computed.",
            "cache_sha256": identity["sha256"],
            "rows": int(len(ranking.frame)),
            "rows_per_scenario": {s: int(len(r)) for s, r in ranking.scenario_rows.items()},
            "ranking_columns": list(RANKING_TIME_COLUMNS),
            "keys": int(ranking.n_keys),
            "keys_per_detector": {d: int((ranking.key_detector == d).sum()) for d in ranking.detectors},
            "tie_hash_unique_within_scenarios": True,
            "label_rows": int(len(raw)),
            "intervals_after_exact_deduplication": int(len(intervals)),
            "critical_intervals_tau_8": int(intervals["critical"].sum()),
            "overlapping_interval_pairs": overlaps,
            "setup_seconds": round(time.perf_counter() - started, 1),
            "registry_sha256": config.registry()["registry_sha256"],
        }
        out = PROJECT_ROOT / "docs/revision/wp2/real_data_construction_check.json"
        out.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        return 0

    for gate in GATES:
        if not gate.exists() or not json.loads(gate.read_text()).get("verified", False):
            raise SystemExit(f"refusing to run comparisons: {gate.relative_to(PROJECT_ROOT)} is missing or not verified")
        pinned = json.loads(gate.read_text()).get("code_identity", {}).get("file_sha256", {})
        if not pinned:
            raise SystemExit(f"refusing to run comparisons: {gate.relative_to(PROJECT_ROOT)} pins no file hashes")
        stale = [path for path, digest in pinned.items()
                 if not (PROJECT_ROOT / path).exists() or sha256(PROJECT_ROOT / path) != digest]
        if stale:
            raise SystemExit(f"refusing to run comparisons: verification in {gate.relative_to(PROJECT_ROOT)} is stale for {stale[:5]}")
    frozen = json.loads((PROJECT_ROOT / "docs/revision/wp2/grid_registry.json").read_text())
    if frozen["registry_sha256"] != config.registry()["registry_sha256"]:
        raise SystemExit("grid registry differs from the frozen record")
    store = LabelStore.from_alerts(ranking.frame, intervals, phase_order(severity), config.tau)
    pipeline = ComparisonPipeline(ranking, store, severity, config)
    out = Path(args.out_dir)
    policies = {"primary": config.primary_policy, "secondary": config.secondary_policy}
    for name in args.policies:
        for held_out in ranking.scenarios:
            fold_started = time.perf_counter()
            result = pipeline.run_outer_fold(held_out, policies[name])
            write_fold_outputs(result, out / name)
            print(f"{name} {held_out}: {time.perf_counter() - fold_started:.0f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

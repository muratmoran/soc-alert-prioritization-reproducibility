#!/usr/bin/env python
"""WP2: run the complete nested pipeline on synthetic data only.

Two uses:

* ``--mode logs`` (default): all outer folds under both input policies on a small
  synthetic dataset. Writes full outputs to results/revision_cose_04000/wp2/synthetic_check
  and one example fold to docs/revision/wp2/example_logs.
* ``--mode scale``: one outer fold at AIT scale (8 scenarios x 330,000 alerts) to
  measure runtime and memory before real runs. No real data is read in either mode.
"""

from __future__ import annotations

import argparse
import json
import resource
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.features import RankingFrame  # noqa: E402
from soc_alert_ranking.revision.labels import LabelStore, intervals_from_frame, phase_order  # noqa: E402
from soc_alert_ranking.revision.pipeline import ComparisonPipeline, write_fold_outputs  # noqa: E402
from soc_alert_ranking.revision.synthetic import make_synthetic_alerts  # noqa: E402


def build(n_scenarios: int, per_scenario: int, seed: int):
    config = load_comparison_config(PROJECT_ROOT / "configs/revision_wp2.yaml")
    severity = SeverityMapping.from_file()
    started = time.perf_counter()
    alerts, labels = make_synthetic_alerts(n_scenarios, per_scenario, seed=seed)
    ranking = RankingFrame.from_alerts(alerts)
    intervals = intervals_from_frame(labels, severity, config.tau)
    store = LabelStore.from_alerts(ranking.frame, intervals, phase_order(severity), config.tau)
    setup_seconds = time.perf_counter() - started
    return config, ComparisonPipeline(ranking, store, severity, config), setup_seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["logs", "scale"], default="logs")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    out_root = PROJECT_ROOT / "results/revision_cose_04000/wp2"

    if args.mode == "logs":
        config, pipeline, setup = build(4, 600, args.seed)
        out = out_root / "synthetic_check"
        summary = []
        for policy in (config.primary_policy, config.secondary_policy):
            for held_out in pipeline.ranking.scenarios:
                started = time.perf_counter()
                result = pipeline.run_outer_fold(held_out, policy)
                write_fold_outputs(result, out)
                summary.append({"policy": policy.name, "held_out": held_out,
                                "seconds": round(time.perf_counter() - started, 2),
                                "inner_rows": len(result.inner_metrics), "selections": len(result.selections),
                                "outer_candidates": len(result.outer_scores),
                                "held_out_label_reads_during_fold": sum(s == held_out for s, _ in result.label_access_log)})
        (out / "synthetic_check_summary.json").write_text(json.dumps(summary, indent=2))
        example = PROJECT_ROOT / "docs/revision/wp2/example_logs"
        example.mkdir(parents=True, exist_ok=True)
        for path in out.glob("flat_table_outer_scn0_*"):
            if path.suffix != ".npz":
                shutil.copy(path, example / path.name)
        print(json.dumps(summary, indent=2))
        return 0 if all(row["held_out_label_reads_during_fold"] == 0 for row in summary) else 1

    config, pipeline, setup = build(8, 330_000, args.seed)
    started = time.perf_counter()
    result = pipeline.run_outer_fold(pipeline.ranking.scenarios[0], config.primary_policy)
    fold_seconds = time.perf_counter() - started
    peak_rss_gb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024**3  # macOS reports bytes
    report = {
        "synthetic_rows": int(len(pipeline.ranking.frame)), "setup_seconds": round(setup, 1),
        "one_outer_fold_seconds": round(fold_seconds, 1), "peak_rss_gb": round(peak_rss_gb, 2),
        "runtime_breakdown_seconds": {k: round(v, 2) for k, v in sorted(result.runtime_seconds.items())},
        "estimated_primary_policy_all_folds_minutes": round(8 * fold_seconds / 60, 1),
        "note": "Synthetic data at AIT scale; no real alerts or labels were read.",
    }
    (out_root / "synthetic_scale_benchmark.json").parent.mkdir(parents=True, exist_ok=True)
    (out_root / "synthetic_scale_benchmark.json").write_text(json.dumps(report, indent=2))
    shutil.copy(out_root / "synthetic_scale_benchmark.json", PROJECT_ROOT / "docs/revision/wp2/synthetic_scale_benchmark.json")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

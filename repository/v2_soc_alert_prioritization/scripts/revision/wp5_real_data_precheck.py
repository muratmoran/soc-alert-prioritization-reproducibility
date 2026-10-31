#!/usr/bin/env python
"""WP5: real-data replay precheck (integrity, runtime and output size; no outcome metrics).

Before full replay, on the real AIT held-out queues and the stored stage-2 scores:

1. Verifies the stage-2 copy against its pinned SHA256SUMS hash and every used file's hash.
2. Checks that stored alert ids align with the ranking frame for every R1 and R2 fold.
3. Replays O_oldest_first at the primary rate for every fold, and every R1 candidate at every
   rate for the largest fold (wilson), running all integrity checks. Only label-free quantities
   are recorded: violations, investigation counts, horizon and runtime.
4. Checks label-mutation invariance on real data: replacing held-out labels leaves traces unchanged.
5. Measures compressed trace size and projects the full-replay output size.

No replay metric that uses labels is computed. Writes docs/revision/wp5/real_data_precheck.json.
"""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "scripts/revision"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from wp5_common import RATES, STAGE2, fold_inputs, sha256, verify_stage2_copy  # noqa: E402
from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.features import RANKING_TIME_COLUMNS, RankingFrame  # noqa: E402
from soc_alert_ranking.revision.labels import LabelStore, load_label_intervals, phase_order  # noqa: E402
from soc_alert_ranking.revision.native_scores import load_revised_alerts  # noqa: E402
from soc_alert_ranking.revision.replay import PRIMARY_RATE, check_trace, replay_alerts  # noqa: E402

DATA = Path.home() / "soc_revision_data"
HASHED = ["src/soc_alert_ranking/revision/replay.py", "scripts/revision/wp5_common.py", "scripts/revision/wp5_real_data_precheck.py"]


def main() -> int:
    started = time.perf_counter()
    stage2 = verify_stage2_copy()
    config = load_comparison_config(PROJECT_ROOT / "configs/revision_wp2.yaml")
    severity = SeverityMapping.from_file()
    alerts, identity = load_revised_alerts(DATA / "cache/ait_canonical_original_labels.pkl.gz",
                                           DATA / "cache/ait_native_score_provenance.pkl.gz")
    ranking = RankingFrame.from_alerts(alerts.loc[:, list(RANKING_TIME_COLUMNS)])
    del alerts
    intervals = load_label_intervals(DATA / "ait_alert/labels.csv", severity, config.tau)
    store = LabelStore.from_alerts(ranking.frame, intervals, phase_order(severity), config.tau)

    alignment, folds = {}, []
    for run in ("R1", "R2"):
        for held_out in ranking.scenarios:
            split_dir = f"loso_{held_out}"
            inputs = fold_inputs(run, split_dir, stage2["files"])
            rows = ranking.rows(held_out)
            alignment[f"{run}/{held_out}"] = bool(np.array_equal(inputs["alert_ids"], rows["alert_id"].astype(str).to_numpy()))
            if run != "R1":
                continue
            t = rows["timestamp"].to_numpy(float)
            h = rows["hash_key"].to_numpy(np.uint64)
            tic = time.perf_counter()
            trace = replay_alerts(inputs["scores"]["O_oldest_first"], t, h, PRIMARY_RATE)
            check = check_trace(trace, inputs["scores"]["O_oldest_first"], t, h)
            folds.append({"held_out": held_out, "alerts": int(len(t)), "horizon_hours": (trace.horizon_end - trace.t0) / 3600,
                          "investigations_at_primary_rate": trace.investigations, "integrity_passed": check.passed,
                          "violations": check.violations, "seconds": round(time.perf_counter() - tic, 2),
                          "candidates": len(inputs["scores"])})

    # every candidate and rate for the largest fold
    largest = max(ranking.scenarios, key=lambda s: len(ranking.rows(s)))
    inputs = fold_inputs("R1", f"loso_{largest}", stage2["files"])
    rows = ranking.rows(largest)
    t, h = rows["timestamp"].to_numpy(float), rows["hash_key"].to_numpy(np.uint64)
    checks, arrays, tic = [], {}, time.perf_counter()
    arrival_signatures = set()
    for cid, scores in inputs["scores"].items():
        for rate in RATES:
            trace = replay_alerts(scores, t, h, rate)
            check = check_trace(trace, scores, t, h)
            arrival_signatures.add((trace.t0, trace.horizon_end, trace.arrivals))
            checks.append({"candidate_id": cid, "rate_per_hour": rate, "passed": check.passed, "violations": check.violations,
                           "investigations": trace.investigations})
            key = f"{cid}@{rate:g}"
            arrays[f"{key}|selected"] = trace.selected.astype(np.int32)
            arrays[f"{key}|start"] = trace.start
            arrays[f"{key}|backlog"] = trace.backlog_at_selection.astype(np.int32)
            arrays[f"{key}|tie"] = trace.tie_decided
    full_seconds = time.perf_counter() - tic
    buffer = io.BytesIO()
    np.savez_compressed(buffer, **arrays)
    trace_bytes_largest_fold = buffer.getbuffer().nbytes

    # label-mutation invariance on real data
    cid = "P_probability_proxy"
    before = replay_alerts(inputs["scores"][cid], t, h, PRIMARY_RATE)
    labels = store.labels[largest]
    rng = np.random.default_rng(7)
    store.replace(largest, labels.replace_arrays(y=rng.random(len(t)) < 0.5, z=rng.random(len(t)) < 0.1,
                                                 critical_membership=rng.random(labels.critical_membership.shape) < 0.2))
    rescored = fold_inputs("R1", f"loso_{largest}", stage2["files"])["scores"][cid]
    after = replay_alerts(rescored, t, h, PRIMARY_RATE)
    store.replace(largest, labels)
    invariance = bool(np.array_equal(before.selected, after.selected) and np.array_equal(before.start, after.start))

    candidates_total = 0
    for run in ("R1", "R2"):
        for held_out in ranking.scenarios:
            candidates_total += len(np.load(STAGE2 / run / f"loso_{held_out}" / "outer_scores.npz").files) - 1
    replays_total = candidates_total * len(RATES)
    per_replay_bytes = trace_bytes_largest_fold / len(checks)
    projected_bytes = int(per_replay_bytes * replays_total * 1.5 + 50e6)          # traces plus tables, 1.5x margin
    per_replay_seconds = full_seconds / len(checks)
    record = {
        "work_package": "WP5 real-data replay precheck",
        "scope": "Integrity, alignment, label invariance, runtime and output size only; no label-dependent replay metric computed.",
        "stage2_sha256sums_sha256": stage2["sha256sums_sha256"],
        "canonical_cache_sha256": identity["canonical_cache_sha256"],
        "score_alignment_all_folds": all(alignment.values()), "score_alignment": alignment,
        "oldest_first_primary_rate_by_fold": folds,
        "largest_fold": {"held_out": largest, "alerts": int(len(t)), "replays": len(checks),
                         "all_integrity_passed": all(c["passed"] for c in checks),
                         "failed": [c for c in checks if not c["passed"]][:5],
                         "identical_arrivals_across_candidates": len(arrival_signatures) == 1,
                         "seconds": round(full_seconds, 1), "trace_npz_bytes": trace_bytes_largest_fold},
        "label_mutation_invariance_real_data": invariance,
        "projection": {"replays_total": replays_total, "per_replay_seconds_upper": round(per_replay_seconds, 3),
                       "projected_seconds_single_process": round(per_replay_seconds * replays_total),
                       "projected_output_bytes": projected_bytes},
        "code_sha256": {path: sha256(PROJECT_ROOT / path) for path in HASHED},
        "runtime_seconds": round(time.perf_counter() - started, 1),
    }
    record["passed"] = bool(record["score_alignment_all_folds"] and all(f["integrity_passed"] for f in folds)
                            and record["largest_fold"]["all_integrity_passed"] and record["largest_fold"]["identical_arrivals_across_candidates"]
                            and invariance)
    out = PROJECT_ROOT / "docs/revision/wp5/real_data_precheck.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: record[k] for k in ("passed", "score_alignment_all_folds", "label_mutation_invariance_real_data", "projection")}, indent=1))
    print(json.dumps(record["largest_fold"], indent=1, default=str)[:800])
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

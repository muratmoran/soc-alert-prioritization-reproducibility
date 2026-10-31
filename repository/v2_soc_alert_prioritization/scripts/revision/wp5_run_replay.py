#!/usr/bin/env python
"""WP5: gated full chronological replay (docs/revision/wp5/replay_specification.md).

Refuses to start unless:
- the WP3, WP4 and WP5 verification records are verified and not stale;
- the WP5 record pins the current replay specification;
- the local stage-2 copy matches its pinned SHA256SUMS hash;
- free disk space minus the precheck's projected output size is at least 5 GB.

Replays P1 (R1 outer candidates) and P2 (R2 outer candidates) for every LOSO fold at rates 12, 6,
30 and 60. Every trace passes the integrity checks, or the run stops. Writes only to
~/soc_revision_data/wp5_replay.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import shutil
import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "scripts/revision"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from wp5_common import POLICIES, candidate_roles, fold_inputs, replay_fold, sha256, verify_stage2_copy, write_fold  # noqa: E402
from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.features import RANKING_TIME_COLUMNS, RankingFrame  # noqa: E402
from soc_alert_ranking.revision.labels import LabelStore, load_label_intervals, phase_order  # noqa: E402
from soc_alert_ranking.revision.native_scores import load_revised_alerts  # noqa: E402

DATA = Path.home() / "soc_revision_data"
OUT = DATA / "wp5_replay"
SPEC = "docs/revision/wp5/replay_specification.md"
GATES = ["docs/revision/wp3/metric_verification.json", "docs/revision/wp4/fitting_boundary_verification.json",
         "docs/revision/wp5/replay_verification.json"]
RESERVE_BYTES = 5 * 1024 ** 3


def check_gates() -> dict[str, object]:
    identities = {}
    for gate in GATES:
        path = PROJECT_ROOT / gate
        if not path.exists():
            raise SystemExit(f"refusing to replay: {gate} is missing")
        record = json.loads(path.read_text())
        if not record.get("verified"):
            raise SystemExit(f"refusing to replay: {gate} is not verified")
        pinned = record.get("code_identity", {}).get("file_sha256", {})
        stale = [p for p, d in pinned.items() if not (PROJECT_ROOT / p).exists() or sha256(PROJECT_ROOT / p) != d]
        if not pinned or stale:
            raise SystemExit(f"refusing to replay: {gate} pins no files or is stale for {stale[:5]}")
        identities[gate] = {"sha256": sha256(path), "generated_at": record["generated_at"]}
    wp5 = json.loads((PROJECT_ROOT / GATES[2]).read_text())
    if wp5["code_identity"]["file_sha256"].get(SPEC) != sha256(PROJECT_ROOT / SPEC):
        raise SystemExit("refusing to replay: the WP5 record does not pin the current replay specification")
    precheck = json.loads((PROJECT_ROOT / "docs/revision/wp5/real_data_precheck.json").read_text())
    projected = int(precheck["projection"]["projected_output_bytes"])
    OUT.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(OUT).free
    if free - projected < RESERVE_BYTES:
        raise SystemExit(f"refusing to replay: free {free / 1e9:.1f} GB minus projected {projected / 1e9:.2f} GB is below the 5 GB reserve")
    identities["disk"] = {"free_bytes_at_start": free, "projected_output_bytes": projected, "reserve_bytes": RESERVE_BYTES}
    identities["replay_specification_sha256"] = sha256(PROJECT_ROOT / SPEC)
    return identities


def main() -> int:
    started = time.perf_counter()
    identities = check_gates()
    stage2 = verify_stage2_copy()
    config = load_comparison_config(PROJECT_ROOT / "configs/revision_wp2.yaml")
    severity = SeverityMapping.from_file()
    alerts, data_identity = load_revised_alerts(DATA / "cache/ait_canonical_original_labels.pkl.gz",
                                                DATA / "cache/ait_native_score_provenance.pkl.gz")
    ranking = RankingFrame.from_alerts(alerts.loc[:, list(RANKING_TIME_COLUMNS)])
    del alerts
    intervals = load_label_intervals(DATA / "ait_alert/labels.csv", severity, config.tau)
    store = LabelStore.from_alerts(ranking.frame, intervals, phase_order(severity), config.tau)
    import numpy as _np, pandas, scipy, sklearn  # noqa: E401
    manifest = {"started_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "gates": identities,
                "stage2_sha256sums_sha256": stage2["sha256sums_sha256"], "data": data_identity,
                "script_sha256": {p: sha256(PROJECT_ROOT / p) for p in ("scripts/revision/wp5_run_replay.py", "scripts/revision/wp5_common.py",
                                                                        "src/soc_alert_ranking/revision/replay.py")},
                "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": _np.__version__,
                                "pandas": pandas.__version__}, "folds": []}
    for policy, run in POLICIES.items():
        for held_out in ranking.scenarios:
            tic = time.perf_counter()
            inputs = fold_inputs(run, f"loso_{held_out}", stage2["files"])
            rows = ranking.rows(held_out)
            if not np.array_equal(inputs["alert_ids"], rows["alert_id"].astype(str).to_numpy()):
                raise SystemExit(f"score alignment failure {policy} {held_out}")
            t, h = rows["timestamp"].to_numpy(float), rows["hash_key"].to_numpy(np.uint64)
            low_confidence = ~inputs["mapped"] | (inputs["h"] <= 0.2)
            roles = candidate_roles(inputs["scores"], inputs["selections"], config)
            labels = store.get(held_out, purpose=f"wp5_replay_metrics:{policy}")    # consumed only by replay_metrics, after each trace
            result = replay_fold(policy, held_out, inputs["scores"], roles, t, h, labels, low_confidence)
            write_fold(OUT / policy / f"loso_{held_out}", result)
            summary = {"policy": policy, "held_out": held_out, "replays": int(len(result["integrity"])),
                       "integrity_passed": bool(result["integrity"]["passed"].all()), "seconds": round(time.perf_counter() - tic, 1)}
            manifest["folds"].append(summary)
            (OUT / "run_manifest.json").write_text(json.dumps(manifest, indent=1, default=str))
            print(f"{policy} {held_out}: {summary['replays']} replays, integrity {summary['integrity_passed']}, {summary['seconds']}s", flush=True)
    manifest["finished_at"] = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    manifest["runtime_seconds"] = round(time.perf_counter() - started, 1)
    (OUT / "run_manifest.json").write_text(json.dumps(manifest, indent=1, default=str))
    files = sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    sums = "\n".join(f"{sha256(p)}  ./{p.relative_to(OUT)}" for p in files) + "\n"
    (OUT / "SHA256SUMS").write_text(sums)
    print(json.dumps({"folds": len(manifest["folds"]), "sha256sums_sha256": hashlib.sha256(sums.encode()).hexdigest(),
                      "runtime_seconds": manifest["runtime_seconds"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

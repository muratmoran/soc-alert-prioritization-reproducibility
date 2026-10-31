"""Shared WP5 helpers: stage-2 score inputs, per-fold replay, and output writing (no gate logic)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.revision.replay import (  # noqa: E402
    PRIMARY_RATE, SENSITIVITY_RATES, check_trace, replay_alerts, replay_metrics,
)

STAGE2 = Path.home() / "soc_revision_data/wp4_stage2"
RATES = (PRIMARY_RATE, *SENSITIVITY_RATES)
POLICIES = {"P1": "R1", "P2": "R2"}
PRIMARY_RULE = "primary_coverage_fp_ndcg"
SAMPLE_CANDIDATES = ("P_probability_proxy", "S1_linear_log_constrained_key", "O_oldest_first")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_stage2_copy() -> dict[str, object]:
    """The local stage-2 copy matches the SHA256SUMS hash pinned in the WP4 output manifest."""

    manifest = json.loads((PROJECT_ROOT / "docs/revision/wp4/stage2_output_manifest.json").read_text())
    sums_path = STAGE2 / "SHA256SUMS"
    if hashlib.sha256(sums_path.read_bytes()).hexdigest() != manifest["sha256sums_sha256"]:
        raise SystemExit("stage-2 SHA256SUMS does not match the pinned manifest")
    sums = {}
    for line in sums_path.read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        sums[name.strip().removeprefix("./")] = digest
    return {"sha256sums_sha256": manifest["sha256sums_sha256"], "files": sums}


def fold_inputs(run: str, split_dir: str, sums: dict[str, str]) -> dict[str, object]:
    """Stored outer scores, R1 outer features and candidate roles for one fold, hash-checked."""

    fold = STAGE2 / run / split_dir
    reference = STAGE2 / "R1" / split_dir
    for path in (fold / "outer_scores.npz", fold / "e12_selections.csv.gz", reference / "outer_features.npz"):
        relative = str(path.relative_to(STAGE2))
        if sha256(path) != sums.get(relative):
            raise SystemExit(f"stage-2 file {relative} does not match SHA256SUMS")
    scores = np.load(fold / "outer_scores.npz", allow_pickle=False)
    features = np.load(reference / "outer_features.npz", allow_pickle=False)
    selections = pd.read_csv(fold / "e12_selections.csv.gz")
    return {"alert_ids": scores["alert_ids"], "scores": {k: scores[k] for k in scores.files if k != "alert_ids"},
            "mapped": features["mapped"].astype(bool), "h": features["h"].astype(float), "selections": selections}


def candidate_roles(candidate_ids, selections: pd.DataFrame, config) -> dict[str, dict[str, str]]:
    roles = {}
    untuned = {c.candidate_id: name for name, spec in config.families.items() if not spec.tuned for c in spec.candidates}
    for cid in candidate_ids:
        if cid in untuned:
            roles[cid] = {"family": untuned[cid], "rules": "untuned"}
    for row in selections.itertuples(index=False):
        cid = row.selected_candidate
        if not isinstance(cid, str):
            continue
        tag = "primary" if row.rule == PRIMARY_RULE else "secondary"
        entry = roles.setdefault(cid, {"family": row.family, "rules": ""})
        entry["rules"] = tag if not entry["rules"] else "+".join(sorted(set(entry["rules"].split("+")) | {tag}))
    return roles


def replay_fold(policy: str, held_out: str, scores: dict[str, np.ndarray], roles: dict[str, dict[str, str]],
                timestamps: np.ndarray, hash_keys: np.ndarray, labels, low_confidence: np.ndarray, rates=RATES,
                sample_selections: int = 50) -> dict[str, object]:
    """Replay every candidate at every rate for one fold; integrity failures raise."""

    summaries, intervals, integrity, samples = [], [], [], []
    traces = {}
    base = {"policy": policy, "held_out": held_out}
    for cid, candidate_scores in scores.items():
        role = roles.get(cid, {"family": cid.split("[")[0], "rules": "?"})
        for rate in rates:
            trace = replay_alerts(candidate_scores, timestamps, hash_keys, rate)
            check = check_trace(trace, candidate_scores, timestamps, hash_keys)
            integrity.append({**base, "candidate_id": cid, "rate_per_hour": rate, "passed": check.passed,
                              "violations": "; ".join(check.violations), "checked_selections": check.checked_selections,
                              "investigations": trace.investigations})
            if not check.passed:
                raise RuntimeError(f"replay integrity failure {policy} {held_out} {cid} {rate}: {check.violations}")
            record, rows = replay_metrics(trace, labels, timestamps, low_confidence)
            summaries.append({**base, "candidate_id": cid, **role, **record})
            intervals.extend({**base, "candidate_id": cid, **role, "rate_per_hour": rate, **row} for row in rows)
            key = f"{cid}@{rate:g}"
            traces[f"{key}|selected"] = trace.selected.astype(np.int32)
            traces[f"{key}|start"] = trace.start
            traces[f"{key}|backlog"] = trace.backlog_at_selection.astype(np.int32)
            traces[f"{key}|tie"] = trace.tie_decided
            if rate == PRIMARY_RATE and role["family"] in SAMPLE_CANDIDATES and ("primary" in role["rules"] or role["rules"] == "untuned"):
                for k in range(min(sample_selections, trace.investigations)):
                    position = int(trace.selected[k])
                    samples.append({**base, "candidate_id": cid, "selection": k, "arrival": float(timestamps[position]),
                                    "start": float(trace.start[k]), "score": float(candidate_scores[position]),
                                    "backlog_size": int(trace.backlog_at_selection[k]), "tie_decided": bool(trace.tie_decided[k])})
    return {"summaries": pd.DataFrame(summaries), "intervals": pd.DataFrame(intervals), "integrity": pd.DataFrame(integrity),
            "samples": pd.DataFrame(samples), "traces": traces}


def write_fold(out_dir: Path, result: dict[str, object]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in ("summaries", "intervals", "integrity", "samples"):
        result[name].to_csv(out_dir / f"{name}.csv.gz", index=False, compression="gzip")
    np.savez_compressed(out_dir / "traces.npz", **result["traces"])

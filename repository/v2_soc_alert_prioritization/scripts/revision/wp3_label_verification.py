#!/usr/bin/env python
"""WP3: verify v1.1 evaluation-label construction on real AIT data (method-independent).

Checks, using only labels.csv and alert timestamps (no method scores, no metrics):

1. 79 label rows, 79 distinct intervals, no overlapping pair (half-open), adjacent pairs and
   non-chronological file rows listed.
2. Critical-interval counts at tau in {7, 8, 9}; defined and alert-containing critical
   intervals per scenario; durations and alert counts per critical interval.
3. Exact-boundary alerts: every alert whose timestamp equals an interval start or end is
   checked against the half-open rule, including shared boundaries end_i == start_j.
4. Row-by-row equality of v1.1 labels (y, s*, z at tau=8) with the historical loader labels.
5. Invariance to label-file row order (reversed and five seeded shuffles).
6. Duplicate clusters with mixed interval labels per window (dataset descriptor).

Writes docs/revision/wp3/label_verification.json.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.duplicates import WINDOWS_SECONDS, assign_clusters, static_cluster_labels  # noqa: E402
from soc_alert_ranking.revision.features import stable_hash_keys  # noqa: E402
from soc_alert_ranking.revision.labels import build_scenario_labels, intervals_from_frame, phase_order  # noqa: E402

CACHE = Path.home() / "soc_revision_data/cache/ait_canonical_original_labels.pkl.gz"
LABELS = Path.home() / "soc_revision_data/ait_alert/labels.csv"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def label_digest(labels_by_scenario) -> str:
    digest = hashlib.sha256()
    for scenario in sorted(labels_by_scenario):
        lab = labels_by_scenario[scenario]
        for array in (lab.y, lab.s_star, lab.z, lab.phase_membership, lab.critical_membership):
            digest.update(np.ascontiguousarray(array).tobytes())
        digest.update("|".join(lab.critical_interval_ids).encode())
    return digest.hexdigest()


def build_all(alerts: pd.DataFrame, raw: pd.DataFrame, severity, tau: float):
    intervals = intervals_from_frame(raw, severity, tau)
    phases = phase_order(severity)
    labels = {}
    for scenario, part in alerts.groupby("scenario", sort=True):
        labels[scenario] = build_scenario_labels(scenario, part["alert_id"].to_numpy(), part["timestamp"].to_numpy(float),
                                                 intervals, phases, tau)
    return intervals, labels


def main() -> int:
    identity = json.loads(CACHE.with_suffix(".json").read_text())
    if sha256(CACHE) != identity["sha256"]:
        raise SystemExit("cache identity mismatch")
    manifest = json.loads((PROJECT_ROOT / "docs/revision/provenance_manifest.json").read_text())
    if hashlib.md5(LABELS.read_bytes()).hexdigest() != manifest["raw_data_verification"]["ait_alert"]["details"]["published_md5"]["labels.csv"]["expected"]:
        raise SystemExit("labels.csv MD5 mismatch")
    severity = SeverityMapping.from_file()
    alerts = pd.read_pickle(CACHE, compression="gzip")
    raw = pd.read_csv(LABELS)
    checks: dict[str, bool] = {}

    intervals, labels = build_all(alerts, raw, severity, 8.0)
    # 1. interval table
    overlaps, adjacent, non_chronological = [], [], []
    for scenario, part in intervals.groupby("scenario"):
        rows = part.sort_values("start").to_dict("records")
        for i, a in enumerate(rows):
            for b in rows[i + 1:]:
                if a["start"] < b["end"] and b["start"] < a["end"]:
                    overlaps.append((scenario, a["phase"], b["phase"]))
                if a["end"] == b["start"]:
                    adjacent.append((scenario, a["phase"], b["phase"]))
        file_rows = raw.index[raw["scenario"].str.lower() == scenario]
        starts = raw.loc[file_rows, "start"].to_numpy()
        inversions = [(raw.loc[file_rows[i], "attack"], raw.loc[file_rows[i + 1], "attack"])
                      for i in range(len(starts) - 1) if starts[i + 1] < starts[i]]
        non_chronological.extend((scenario, a, b) for a, b in inversions)
    interval_table = {"label_rows": int(len(raw)), "distinct_intervals": int(len(intervals)),
                      "overlapping_pairs": len(overlaps), "adjacent_pairs_end_equals_start": len(adjacent),
                      "file_order_inversions": [list(x) for x in non_chronological]}
    checks["79_rows_79_distinct_no_overlap"] = len(raw) == 79 and len(intervals) == 79 and not overlaps

    # 2. critical intervals
    critical = {}
    for tau in (7.0, 8.0, 9.0):
        table = intervals_from_frame(raw, severity, tau)
        critical[f"tau_{tau:g}"] = {"critical_intervals": int(table["critical"].sum()),
                                    "critical_phases": sorted(table.loc[table["critical"], "phase"].unique())}
    per_scenario = {}
    per_interval = []
    for scenario, lab in labels.items():
        counts = lab.critical_membership.sum(axis=0)
        per_scenario[scenario] = {"alerts": int(len(lab.y)), "defined_critical_intervals": lab.defined_critical_intervals,
                                  "alert_containing_critical_intervals": int((counts > 0).sum())}
        for interval_id, count in zip(lab.critical_interval_ids, counts):
            _, phase, start, end = interval_id.split("|")
            per_interval.append({"scenario": scenario, "phase": phase, "duration_seconds": float(end) - float(start),
                                 "alerts": int(count)})
    per_interval = pd.DataFrame(per_interval)
    critical_summary = {
        "by_tau": critical,
        "per_scenario_tau_8": per_scenario,
        "defined_total_tau_8": int(sum(v["defined_critical_intervals"] for v in per_scenario.values())),
        "alert_containing_total_tau_8": int(sum(v["alert_containing_critical_intervals"] for v in per_scenario.values())),
        "duration_seconds_by_phase": per_interval.groupby("phase")["duration_seconds"].agg(["min", "median", "max"]).to_dict("index"),
        "alerts_per_interval_by_phase": per_interval.groupby("phase")["alerts"].agg(["min", "median", "max", "sum"]).to_dict("index"),
        "no_alert_critical_intervals": per_interval.loc[per_interval["alerts"] == 0, ["scenario", "phase"]].to_dict("records"),
    }
    checks["critical_counts_consistent"] = critical_summary["defined_total_tau_8"] == critical["tau_8"]["critical_intervals"]

    # 3. exact boundaries
    boundary_rows = []
    violations = 0
    for scenario, part in alerts.groupby("scenario"):
        lab = labels[scenario]
        own = intervals[intervals["scenario"] == scenario]
        t = part["timestamp"].to_numpy(float)
        for row in own.itertuples(index=False):
            for kind, value in (("start", row.start), ("end", row.end)):
                hits = np.flatnonzero(t == value)
                if not len(hits):
                    continue
                containing = own[(own["start"] <= value) & (value < own["end"])]
                expected_y = len(containing) > 0
                expected_s = float(containing["severity"].max()) if expected_y else 0.0
                bad = int(((lab.y[hits] != expected_y) | (lab.s_star[hits] != expected_s)).sum())
                violations += bad
                boundary_rows.append({"scenario": scenario, "interval": row.phase, "boundary": kind, "alerts": int(len(hits)),
                                      "assigned_to": list(containing["phase"]), "violations": bad})
    checks["half_open_boundaries"] = violations == 0
    boundary_summary = {"boundary_alert_groups": len(boundary_rows),
                        "alerts_on_start": int(sum(r["alerts"] for r in boundary_rows if r["boundary"] == "start")),
                        "alerts_on_end": int(sum(r["alerts"] for r in boundary_rows if r["boundary"] == "end")),
                        "violations": violations, "groups": boundary_rows}

    # 4. agreement with historical loader labels
    mismatches = {"y": 0, "s_star": 0, "z": 0}
    for scenario, part in alerts.groupby("scenario"):
        lab = labels[scenario]
        mismatches["y"] += int((lab.y != part["is_attack"].to_numpy(bool)).sum())
        mismatches["s_star"] += int((lab.s_star != part["true_severity"].to_numpy(float)).sum())
        mismatches["z"] += int((lab.z != part["is_critical"].to_numpy(bool)).sum())
    checks["matches_historical_loader_labels"] = not any(mismatches.values())

    # 5. file-order invariance
    base_digest = label_digest(labels)
    digests = {"reversed": label_digest(build_all(alerts, raw.iloc[::-1].reset_index(drop=True), severity, 8.0)[1])}
    for seed in range(5):
        shuffled = raw.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        digests[f"shuffle_seed_{seed}"] = label_digest(build_all(alerts, shuffled, severity, 8.0)[1])
    checks["file_order_invariant"] = all(d == base_digest for d in digests.values())

    # 6. mixed-label duplicate clusters
    clusters_summary = {}
    for window in WINDOWS_SECONDS:
        totals = {"clusters": 0, "mixed_label_clusters": 0, "member_conferred_positive_clusters": 0, "multi_interval_clusters": 0}
        for scenario, part in alerts.groupby("scenario"):
            clusters = assign_clusters(part["detector"].to_numpy(), part["native_key"].to_numpy(), part["host"].to_numpy(),
                                       part["timestamp"].to_numpy(float), stable_hash_keys(part["alert_id"]), window)
            _, _, summary = static_cluster_labels(labels[scenario], clusters)
            for key in totals:
                totals[key] += getattr(summary, key)
        clusters_summary[f"{window}s"] = totals

    report = {
        "analysis_role": "WP3 evaluation-label construction check; no method scores or metrics",
        "inputs": {"cache_sha256": identity["sha256"], "labels_csv_sha256": sha256(LABELS)},
        "interval_table": interval_table,
        "critical_intervals": critical_summary,
        "boundaries": boundary_summary,
        "historical_label_mismatches": mismatches,
        "file_order_digests": {"base": base_digest, **digests},
        "duplicate_cluster_labels": clusters_summary,
        "checks": checks,
        "passed": all(checks.values()),
    }
    out = PROJECT_ROOT / "docs/revision/wp3/label_verification.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("interval_table", "historical_label_mismatches", "checks", "passed")}, indent=2, default=str))
    print(json.dumps(critical_summary["per_scenario_tau_8"], indent=1))
    print(json.dumps({k: v for k, v in boundary_summary.items() if k != "groups"}), json.dumps(clusters_summary))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

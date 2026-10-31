#!/usr/bin/env python
"""WP7: UWF-ZeekData24 ATT&CK mapping coverage and crosswalk consistency (protocol v1.1 §10).

Supporting analysis only. UWF supplies tactic/technique labels and frequencies; both severity
tables compared here are author-defined in configs/severity_mapping.yaml, so agreement measures
internal consistency of the author's crosswalk, not independent severity validation.

Reads the local copy $SOC_REVISION_DATA/uwf_zeekdata24/csv (default ~/soc_revision_data) (SHA-256 recorded; no published
checksums exist) and writes docs/revision/wp7/uwf/*.csv and uwf_summary.json.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.severity import SeverityMapping, canonical_mitre_tactic  # noqa: E402

RAW = Path(os.environ.get("SOC_REVISION_DATA", Path.home() / "soc_revision_data")).expanduser() / "uwf_zeekdata24/csv"
OUT = PROJECT_ROOT / "docs/revision/wp7/uwf"
THRESHOLDS = (7.5, 8.0, 8.5)
LABELS = ("label_tactic", "label_technique", "label_binary", "label_cve")


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def spearman(x, y):
    x, y = pd.Series(x, dtype=float), pd.Series(y, dtype=float)
    if len(x) < 2 or x.nunique() < 2 or y.nunique() < 2:
        return None
    return float(x.rank(method="average").corr(y.rank(method="average")))


def kendall_tau_b(x, y):
    concordant = discordant = tie_x = tie_y = 0
    for i, j in itertools.combinations(range(len(x)), 2):
        dx, dy = x[i] - x[j], y[i] - y[j]
        if dx == 0 and dy == 0:
            continue
        if dx == 0:
            tie_x += 1
        elif dy == 0:
            tie_y += 1
        elif dx * dy > 0:
            concordant += 1
        else:
            discordant += 1
    denominator = math.sqrt((concordant + discordant + tie_x) * (concordant + discordant + tie_y))
    return None if denominator == 0 else (concordant - discordant) / denominator


def jaccard(left: set, right: set):
    union = left | right
    return 1.0 if not union else len(left & right) / len(union)


def main() -> int:
    mapping = SeverityMapping.from_file()
    files = sorted(RAW.glob("*.csv"))
    frames, file_rows = [], []
    for path in files:
        frame = pd.read_csv(path, dtype=str, keep_default_na=False)
        frame["source_file"] = path.name
        frames.append(frame)
        file_rows.append({"file": path.name, "rows": len(frame), "sha256": sha256(path),
                          "label_tactic_values": ";".join(f"{k}:{v}" for k, v in frame["label_tactic"].value_counts().items())})
    data = pd.concat(frames, ignore_index=True)
    OUT.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(file_rows).to_csv(OUT / "uwf_files.csv", index=False)

    # coverage
    data["tactic"] = data["label_tactic"].map(canonical_mitre_tactic)
    benign = data["label_tactic"].str.lower().isin({"none", "benign", ""})
    attacks = data[~benign]
    known_tactics = set(mapping.mitre_tactic_severity)
    technique_valid = attacks["label_technique"].str.match(r"^T\d{4}(\.\d{3})?$")
    cve_valid = attacks["label_cve"].str.match(r"^CVE-\d{4}-\d+$")
    coverage = {
        "rows": int(len(data)), "benign_rows": int(benign.sum()), "attack_rows": int(len(attacks)),
        "attack_rows_with_tactic_in_severity_table": int(attacks["tactic"].isin(known_tactics).sum()),
        "tactic_mapping_coverage": float(attacks["tactic"].isin(known_tactics).mean()),
        "attack_rows_with_valid_technique": int(technique_valid.sum()), "technique_coverage": float(technique_valid.mean()),
        "attack_rows_with_valid_cve": int(cve_valid.sum()), "cve_coverage": float(cve_valid.mean()),
        "technique_label_values_not_valid": attacks.loc[~technique_valid, "label_technique"].value_counts().to_dict(),
    }

    # tactic table with both author-defined severities
    crosswalk = {}
    for phase, tactic in mapping.ait_phase_to_mitre_tactic.items():
        crosswalk.setdefault(canonical_mitre_tactic(tactic), []).append((phase, float(mapping.ait_phase_severity[phase])))
    counts = attacks.groupby("tactic").size()
    rows = []
    for tactic, n in counts.sort_values(ascending=False).items():
        phases = crosswalk.get(tactic, [])
        techniques = attacks.loc[attacks["tactic"] == tactic, "label_technique"].value_counts()
        rows.append({
            "tactic": tactic, "uwf_rows": int(n), "uwf_attack_share": n / len(attacks),
            "tactic_table_severity": float(mapping.mitre_tactic_severity[tactic]) if tactic in mapping.mitre_tactic_severity else None,
            "overlaps_ait_crosswalk": bool(phases),
            "ait_phases": ";".join(f"{p}:{s:g}" for p, s in phases),
            "crosswalk_severity_max": max(s for _, s in phases) if phases else None,
            "crosswalk_severity_mean": float(np.mean([s for _, s in phases])) if phases else None,
            "techniques": ";".join(f"{k}:{v}" for k, v in techniques.items()),
        })
    table = pd.DataFrame(rows)
    table["discrepancy_max"] = table["tactic_table_severity"] - table["crosswalk_severity_max"]
    table["discrepancy_mean"] = table["tactic_table_severity"] - table["crosswalk_severity_mean"]
    table.to_csv(OUT / "uwf_tactics.csv", index=False)

    overlap = table[table["overlaps_ait_crosswalk"]].reset_index(drop=True)

    def statistics(frame: pd.DataFrame, crosswalk_column: str, threshold: float = 8.0) -> dict[str, object]:
        x = frame["tactic_table_severity"].to_list()
        y = frame[crosswalk_column].to_list()
        weights = frame["uwf_rows"].to_numpy(float)
        absolute = np.abs(np.array(x) - np.array(y))
        left = {t for t, v in zip(frame["tactic"], x) if v >= threshold}
        right = {t for t, v in zip(frame["tactic"], y) if v >= threshold}
        return {"tactics": len(frame), "spearman": spearman(x, y), "kendall_tau_b": kendall_tau_b(x, y),
                "mean_absolute_discrepancy_unweighted": float(absolute.mean()),
                "mean_absolute_discrepancy_frequency_weighted": float(np.sum(weights * absolute) / weights.sum()),
                "jaccard": jaccard(left, right), "set_tactic_table": ";".join(sorted(left)), "set_crosswalk": ";".join(sorted(right))}

    results = []
    for column, label in (("crosswalk_severity_max", "max over mapped AIT phases (historical)"), ("crosswalk_severity_mean", "mean over mapped AIT phases (sensitivity)")):
        for threshold in THRESHOLDS:
            results.append({"crosswalk": label, "threshold": threshold, **statistics(overlap, column, threshold)})
    pd.DataFrame(results).to_csv(OUT / "uwf_agreement_thresholds.csv", index=False)

    influence = [{"left_out": "none", **statistics(overlap, "crosswalk_severity_max")}]
    for tactic in overlap["tactic"]:
        influence.append({"left_out": tactic, **statistics(overlap[overlap["tactic"] != tactic].reset_index(drop=True), "crosswalk_severity_max")})
    pd.DataFrame(influence).to_csv(OUT / "uwf_leave_one_tactic_out.csv", index=False)

    # duplicate-row checks
    content_columns = [c for c in data.columns if c not in {"source_file", "tactic"}]
    full_dup = data.duplicated(subset=content_columns, keep=False)
    connection_columns = [c for c in content_columns if c not in LABELS]
    connection_groups = data[~benign].groupby(connection_columns, dropna=False)["source_file"].agg(lambda s: tuple(sorted(set(s))))
    multi_file_connections = connection_groups[connection_groups.map(len) > 1]
    uid_files = attacks.groupby("uid")["source_file"].agg(lambda s: tuple(sorted(set(s))))
    uid_multi = uid_files[uid_files.map(len) > 1]
    duplicate_labels = {column: int((data[column].str.lower() == "duplicate").sum()) for column in LABELS}
    duplicate_label_by_file = (data.assign(any_duplicate=data[list(LABELS)].apply(lambda r: r.str.lower().eq("duplicate").any(), axis=1))
                               .groupby("source_file")["any_duplicate"].sum().astype(int).to_dict())
    three = attacks[attacks["source_file"].isin(["Persistence.csv", "Privilege_Escalation.csv", "Defense_Evasion.csv"])]
    three_connections = three.groupby(connection_columns, dropna=False)["source_file"].agg(lambda s: tuple(sorted(set(s))))
    duplicates = {
        "exact_full_row_duplicates_including_labels": int(full_dup.sum()),
        "attack_connections_in_more_than_one_tactic_file": int(len(multi_file_connections)),
        "attack_connection_file_patterns": {"+".join(k): int(v) for k, v in multi_file_connections.value_counts().items()},
        "attack_uids_in_more_than_one_tactic_file": int(len(uid_multi)),
        "rows_with_Duplicate_label_value": duplicate_labels,
        "rows_with_any_Duplicate_label_by_file": duplicate_label_by_file,
        "three_326_row_tactics_distinct_connections": int(len(three_connections)),
        "three_326_row_tactics_connections_shared_by_all_three": int((three_connections.map(len) == 3).sum()),
    }

    summary = {
        "role": "ATT&CK mapping coverage and crosswalk consistency (supporting only; no independent severity validation)",
        "input_directory": str(RAW), "files": file_rows,
        "coverage": coverage,
        "observed_attack_tactics": int(len(table)), "overlapping_tactics": overlap["tactic"].tolist(),
        "credential_access_share": float(table.loc[table["tactic"] == "Credential Access", "uwf_attack_share"].iloc[0]),
        "agreement_theta_8_max": statistics(overlap, "crosswalk_severity_max"),
        "duplicates": duplicates,
        "script_sha256": sha256(Path(__file__)),
        "severity_mapping_sha256": sha256(PROJECT_ROOT / "configs/severity_mapping.yaml"),
    }
    (OUT / "uwf_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    pd.set_option("display.width", 250); pd.set_option("display.max_colwidth", 60)
    print(table.drop(columns=["techniques"]).to_string(index=False))
    print(pd.DataFrame(results).round(4).to_string(index=False))
    print(pd.DataFrame(influence).round(4).to_string(index=False))
    print(json.dumps({"coverage": coverage, "duplicates": duplicates}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

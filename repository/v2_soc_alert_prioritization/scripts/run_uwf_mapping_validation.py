#!/usr/bin/env python
"""Validate ATT&CK severity ordering on UWF-ZeekData24."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from soc_alert_ranking.loaders.uwf_zeekdata24 import discover_uwf_csv_files, iter_uwf_chunks
from soc_alert_ranking.mappings.severity import SeverityMapping, canonical_mitre_tactic


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-path",
        default=str(PROJECT_ROOT / "data/raw/uwf_zeekdata24"),
        help="Path containing staged UWF-ZeekData24 csv/ and metrics/ folders.",
    )
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--critical-threshold", type=float, default=8.0)
    parser.add_argument("--sensitivity-delta", type=float, default=0.5)
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "results/uwf_zeekdata24"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_path = Path(args.raw_path)
    files = discover_uwf_csv_files(raw_path)
    if not files:
        print(f"No UWF-ZeekData24 CSV files found under {raw_path}")
        return 1

    mapping = SeverityMapping.from_file()
    tactic_table, technique_counts, cve_counts, coverage = build_uwf_tactic_table(
        raw_path=raw_path,
        mapping=mapping,
        chunksize=args.chunksize,
        max_rows=args.max_rows,
    )
    if tactic_table.empty:
        print("No UWF attack tactics were available after normalization.")
        return 1

    ait_profile = build_ait_tactic_profile(mapping)
    comparison = tactic_table.merge(ait_profile, on="mitre_tactic", how="left")
    comparison["overlap_with_ait"] = comparison["ait_phase_count"].fillna(0).astype(int) > 0
    overlap = comparison[comparison["overlap_with_ait"]].copy()
    agreement = compute_agreement(
        overlap=overlap,
        threshold=args.critical_threshold,
        delta=args.sensitivity_delta,
    )
    summary = {
        "dataset": "uwf_zeekdata24",
        "role": "enterprise_attack_mapping_validation",
        "raw_path": str(raw_path),
        "csv_files": [str(path) for path in files],
        "rows": coverage["rows"],
        "attack_rows": coverage["attack_rows"],
        "attack_rate": coverage["attack_rate"],
        "observed_attack_tactics": int(len(tactic_table)),
        "overlap_tactics_with_ait": int(len(overlap)),
        "mapped_tactic_rate": coverage["mapped_tactic_rate"],
        "valid_technique_rate": coverage["valid_technique_rate"],
        "valid_cve_rate": coverage["valid_cve_rate"],
        "critical_threshold": args.critical_threshold,
        "sensitivity_delta": args.sensitivity_delta,
        "agreement": agreement,
        "top_techniques": dict(technique_counts.most_common(20)),
        "top_cves": dict(cve_counts.most_common(20)),
    }

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    comparison.sort_values(["mitre_table_severity", "uwf_rows"], ascending=[False, False]).to_csv(
        out_dir / "uwf_tactic_mapping_validation.csv",
        index=False,
    )
    pd.DataFrame(
        [
            {"mitre_technique": label, "count": int(count)}
            for label, count in technique_counts.most_common()
        ]
    ).to_csv(out_dir / "uwf_technique_counts.csv", index=False)
    cve_rows = [{"label_cve": label, "count": int(count)} for label, count in cve_counts.most_common()]
    pd.DataFrame(cve_rows, columns=["label_cve", "count"]).to_csv(
        out_dir / "uwf_cve_counts.csv",
        index=False,
    )
    (out_dir / "uwf_mapping_validation_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    printable = {
        "attack_rows": summary["attack_rows"],
        "observed_attack_tactics": summary["observed_attack_tactics"],
        "overlap_tactics_with_ait": summary["overlap_tactics_with_ait"],
        "mapped_tactic_rate": round(summary["mapped_tactic_rate"], 4),
        "valid_technique_rate": round(summary["valid_technique_rate"], 4),
        "valid_cve_rate": round(summary["valid_cve_rate"], 4),
        "spearman": agreement["spearman"],
        "kendall_tau_b": agreement["kendall_tau_b"],
        "top_risk_jaccard": agreement["top_risk_jaccard"],
        "pairwise_order_stability": agreement["pairwise_order_stability"],
    }
    print(json.dumps(printable, indent=2, sort_keys=True))
    return 0


def build_uwf_tactic_table(
    raw_path: Path,
    mapping: SeverityMapping,
    chunksize: int,
    max_rows: int | None,
) -> tuple[pd.DataFrame, Counter[str], Counter[str], dict[str, float]]:
    stats = defaultdict(
        lambda: {
            "rows": 0,
            "valid_technique_rows": 0,
            "valid_cve_rows": 0,
            "critical_rows": 0,
            "severity": 0.0,
            "techniques": Counter(),
            "cves": Counter(),
            "subnet_pairs": Counter(),
        }
    )
    technique_counts: Counter[str] = Counter()
    cve_counts: Counter[str] = Counter()
    total_rows = 0
    attack_rows = 0
    mapped_tactic_rows = 0
    valid_technique_rows = 0
    valid_cve_rows = 0

    for chunk in iter_uwf_chunks(
        raw_path=raw_path,
        severity_mapping=mapping,
        chunksize=chunksize,
        max_rows=max_rows,
    ):
        total_rows += len(chunk)
        attacks = chunk[chunk["is_attack"]].copy()
        attack_rows += len(attacks)
        mapped_tactic_rows += int(attacks["mitre_tactic"].notna().sum())
        valid_technique_rows += int(attacks["mitre_technique"].notna().sum())
        valid_cve_rows += int(attacks["label_cve"].notna().sum())
        technique_counts.update(attacks["mitre_technique"].dropna().astype(str))
        cve_counts.update(attacks["label_cve"].dropna().astype(str))
        for tactic, group in attacks.groupby("mitre_tactic", dropna=True):
            canonical = canonical_mitre_tactic(tactic)
            if not canonical:
                continue
            entry = stats[canonical]
            entry["rows"] += int(len(group))
            entry["valid_technique_rows"] += int(group["mitre_technique"].notna().sum())
            entry["valid_cve_rows"] += int(group["label_cve"].notna().sum())
            entry["critical_rows"] += int(group["is_critical"].sum())
            entry["severity"] = mapping.severity_for_mitre_tactic(canonical)
            entry["techniques"].update(group["mitre_technique"].dropna().astype(str))
            entry["cves"].update(group["label_cve"].dropna().astype(str))
            entry["subnet_pairs"].update(group["subnet_pair"].dropna().astype(str))

    rows = []
    for tactic, entry in sorted(stats.items()):
        row_count = int(entry["rows"])
        rows.append(
            {
                "mitre_tactic": tactic,
                "uwf_rows": row_count,
                "uwf_attack_share": row_count / attack_rows if attack_rows else 0.0,
                "mitre_table_severity": float(entry["severity"]),
                "uwf_critical_rows": int(entry["critical_rows"]),
                "valid_technique_rows": int(entry["valid_technique_rows"]),
                "valid_technique_rate": entry["valid_technique_rows"] / row_count if row_count else 0.0,
                "valid_cve_rows": int(entry["valid_cve_rows"]),
                "valid_cve_rate": entry["valid_cve_rows"] / row_count if row_count else 0.0,
                "distinct_techniques": ";".join(sorted(entry["techniques"])),
                "distinct_cves": ";".join(sorted(entry["cves"])),
                "distinct_subnet_pairs": int(len(entry["subnet_pairs"])),
                "top_subnet_pairs": ";".join(
                    f"{label}:{count}" for label, count in entry["subnet_pairs"].most_common(5)
                ),
            }
        )

    coverage = {
        "rows": int(total_rows),
        "attack_rows": int(attack_rows),
        "attack_rate": attack_rows / total_rows if total_rows else 0.0,
        "mapped_tactic_rate": mapped_tactic_rows / attack_rows if attack_rows else 0.0,
        "valid_technique_rate": valid_technique_rows / attack_rows if attack_rows else 0.0,
        "valid_cve_rate": valid_cve_rows / attack_rows if attack_rows else 0.0,
    }
    return pd.DataFrame(rows), technique_counts, cve_counts, coverage


def build_ait_tactic_profile(mapping: SeverityMapping) -> pd.DataFrame:
    rows = []
    grouped = defaultdict(list)
    for phase, tactic in mapping.ait_phase_to_mitre_tactic.items():
        canonical = canonical_mitre_tactic(tactic)
        if not canonical:
            continue
        grouped[canonical].append(
            {
                "ait_phase": phase,
                "ait_phase_severity": mapping.severity_for_ait_phases([phase]),
            }
        )
    for tactic, values in sorted(grouped.items()):
        severities = [float(item["ait_phase_severity"]) for item in values]
        rows.append(
            {
                "mitre_tactic": tactic,
                "ait_phase_count": len(values),
                "ait_phase_max_severity": max(severities),
                "ait_phase_mean_severity": sum(severities) / len(severities),
                "ait_phases": ";".join(item["ait_phase"] for item in values),
            }
        )
    return pd.DataFrame(rows)


def compute_agreement(overlap: pd.DataFrame, threshold: float, delta: float) -> dict[str, object]:
    if overlap.empty:
        return {
            "spearman": None,
            "kendall_tau_b": None,
            "top_risk_jaccard": None,
            "top_risk_uwf": [],
            "top_risk_ait": [],
            "pairwise_order_stability": None,
            "threshold_sensitive_tactics": [],
        }
    x = overlap["mitre_table_severity"].astype(float).tolist()
    y = overlap["ait_phase_max_severity"].astype(float).tolist()
    tactics = overlap["mitre_tactic"].astype(str).tolist()
    uwf_top = {
        tactic
        for tactic, severity in zip(tactics, x)
        if severity >= threshold
    }
    ait_top = {
        tactic
        for tactic, severity in zip(tactics, y)
        if severity >= threshold
    }
    return {
        "overlap_tactics": tactics,
        "spearman": _round_or_none(spearman_correlation(x, y)),
        "kendall_tau_b": _round_or_none(kendall_tau_b(x, y)),
        "top_risk_jaccard": _round_or_none(jaccard(uwf_top, ait_top)),
        "top_risk_uwf": sorted(uwf_top),
        "top_risk_ait": sorted(ait_top),
        "pairwise_order_stability": _round_or_none(pairwise_order_stability(x, delta)),
        "threshold_sensitive_tactics": [
            tactic
            for tactic, severity in zip(tactics, x)
            if abs(severity - threshold) <= delta
        ],
    }


def spearman_correlation(x: Iterable[float], y: Iterable[float]) -> float | None:
    x_series = pd.Series(list(x), dtype=float)
    y_series = pd.Series(list(y), dtype=float)
    if len(x_series) < 2:
        return None
    return float(x_series.rank(method="average").corr(y_series.rank(method="average")))


def kendall_tau_b(x: Iterable[float], y: Iterable[float]) -> float | None:
    x_values = list(x)
    y_values = list(y)
    concordant = 0
    discordant = 0
    tie_x = 0
    tie_y = 0
    for i in range(len(x_values)):
        for j in range(i + 1, len(x_values)):
            dx = x_values[i] - x_values[j]
            dy = y_values[i] - y_values[j]
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
    if denominator == 0:
        return None
    return (concordant - discordant) / denominator


def jaccard(left: set[str], right: set[str]) -> float | None:
    if not left and not right:
        return 1.0
    union = left | right
    if not union:
        return None
    return len(left & right) / len(union)


def pairwise_order_stability(values: Iterable[float], delta: float) -> float | None:
    severities = list(values)
    comparable = 0
    stable = 0
    for i in range(len(severities)):
        for j in range(i + 1, len(severities)):
            difference = abs(severities[i] - severities[j])
            if difference == 0:
                continue
            comparable += 1
            if difference > 2 * delta:
                stable += 1
    if comparable == 0:
        return None
    return stable / comparable


def _round_or_none(value: float | None) -> float | None:
    if value is None or pd.isna(value):
        return None
    return round(float(value), 4)


if __name__ == "__main__":
    raise SystemExit(main())

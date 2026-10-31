"""UWF-ZeekData24 loader and ATT&CK-label normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Optional

import pandas as pd

from soc_alert_ranking.mappings.severity import (
    SeverityMapping,
    canonical_mitre_tactic,
    is_benign_label,
)


UWF_CANONICAL_COLUMNS = [
    "alert_id",
    "dataset",
    "scenario",
    "timestamp",
    "datetime",
    "detector",
    "source_domain",
    "attack_class",
    "attack_phase",
    "true_attack_phase",
    "mitre_tactic",
    "mitre_technique",
    "severity",
    "true_severity",
    "uncertainty_factor",
    "detector_score",
    "native_severity",
    "native_key",
    "native_category",
    "asset_criticality",
    "is_attack",
    "is_critical",
    "raw_label",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "service",
    "src_subnet",
    "dst_subnet",
    "subnet_pair",
    "label_binary",
    "label_cve",
]


def discover_uwf_csv_files(raw_path: str | Path) -> list[Path]:
    """Return staged UWF-ZeekData24 CSV subset files."""

    root = Path(raw_path)
    if not root.exists():
        return []
    csv_root = root / "csv"
    search_root = csv_root if csv_root.exists() else root
    return sorted(
        path
        for path in search_root.rglob("*.csv")
        if path.is_file() and "metric" not in path.name.lower()
    )


def discover_uwf_metric_files(raw_path: str | Path) -> dict[str, Path]:
    """Return staged UWF metric-table files keyed by metric name."""

    root = Path(raw_path)
    metric_root = root / "metrics"
    if not metric_root.exists():
        return {}
    return {
        path.stem.replace("_metrics", ""): path
        for path in sorted(metric_root.glob("*_metrics.csv"))
        if path.is_file()
    }


def iter_uwf_chunks(
    raw_path: str | Path,
    severity_mapping: Optional[SeverityMapping] = None,
    files: Optional[Iterable[str | Path]] = None,
    chunksize: int = 100_000,
    max_rows: Optional[int] = None,
) -> Iterator[pd.DataFrame]:
    """Yield normalized UWF-ZeekData24 CSV records as canonical chunks."""

    mapping = severity_mapping or SeverityMapping.from_file()
    selected_files = [Path(path) for path in files] if files is not None else discover_uwf_csv_files(raw_path)
    remaining = max_rows
    for path in selected_files:
        row_offset = 0
        for chunk in pd.read_csv(path, chunksize=chunksize):
            if remaining is not None:
                if remaining <= 0:
                    return
                chunk = chunk.head(remaining)
            if chunk.empty:
                continue
            yield normalize_uwf_frame(
                chunk,
                path=path,
                mapping=mapping,
                row_offset=row_offset,
            )
            row_offset += len(chunk)
            if remaining is not None:
                remaining -= len(chunk)


def load_uwf_alerts(
    raw_path: str | Path,
    severity_mapping: Optional[SeverityMapping] = None,
    files: Optional[Iterable[str | Path]] = None,
    chunksize: int = 100_000,
    max_rows: Optional[int] = None,
) -> pd.DataFrame:
    """Load the staged UWF CSV subset into memory."""

    frames = list(
        iter_uwf_chunks(
            raw_path=raw_path,
            severity_mapping=severity_mapping,
            files=files,
            chunksize=chunksize,
            max_rows=max_rows,
        )
    )
    if not frames:
        return pd.DataFrame(columns=UWF_CANONICAL_COLUMNS)
    return pd.concat(frames, ignore_index=True)[UWF_CANONICAL_COLUMNS]


def normalize_uwf_frame(
    frame: pd.DataFrame,
    path: str | Path,
    mapping: SeverityMapping,
    row_offset: int = 0,
) -> pd.DataFrame:
    """Normalize one UWF CSV chunk into canonical alert fields."""

    data = frame.copy()
    path = Path(path)
    raw_tactic = _series_from_aliases(data, ["label_tactic"])
    tactic = raw_tactic.map(canonical_mitre_tactic)
    file_tactic = canonical_mitre_tactic(path.stem)
    tactic = tactic.where(tactic.astype(bool), file_tactic)
    raw_technique = _series_from_aliases(data, ["label_technique"])
    technique = raw_technique.map(_valid_technique)
    cve = _series_from_aliases(data, ["label_cve"]).map(_valid_cve)
    label_binary = _series_from_aliases(data, ["label_binary"])
    src_ip = _series_from_aliases(data, ["src_ip_zeek", "src_ip"])
    dst_ip = _series_from_aliases(data, ["dest_ip_zeek", "dst_ip", "dest_ip"])
    src_subnet = src_ip.map(_subnet24)
    dst_subnet = dst_ip.map(_subnet24)
    subnet_pair = src_subnet.astype(str) + "->" + dst_subnet.astype(str)
    timestamp = _timestamp_series(data, row_offset)
    is_attack = tactic.astype(bool)
    severity = tactic.map(mapping.severity_for_mitre_tactic)
    uncertainty = tactic.map(mapping.uncertainty_for_mitre_tactic)
    detector_score = is_attack.astype(float)
    file_key = _safe_identifier(path.stem)
    service = _series_from_aliases(data, ["service"])
    protocol = _series_from_aliases(data, ["proto", "protocol"])
    dst_port = _series_from_aliases(data, ["dest_port_zeek", "dst_port"])
    src_port = _series_from_aliases(data, ["src_port_zeek", "src_port"])
    native_key = [
        f"zeek:{tac or 'benign'}:{tech or 'no-technique'}:cve={cv or 'none'}:"
        f"proto={proto}:dport={dport}:service={svc}"
        for tac, tech, cv, proto, dport, svc in zip(
            tactic, technique, cve, protocol, dst_port, service
        )
    ]

    out = pd.DataFrame(index=data.index)
    out["alert_id"] = [f"uwf-{file_key}-{row_offset + idx}" for idx in range(len(data))]
    out["dataset"] = "uwf_zeekdata24"
    out["scenario"] = tactic.where(tactic.astype(bool), "Benign")
    out["timestamp"] = timestamp
    out["datetime"] = _series_from_aliases(data, ["datetime"])
    out["detector"] = "zeek_attack_label"
    out["source_domain"] = subnet_pair
    out["attack_class"] = tactic.where(tactic.astype(bool), "Benign")
    out["attack_phase"] = out["attack_class"]
    out["true_attack_phase"] = out["attack_class"]
    out["mitre_tactic"] = tactic.where(tactic.astype(bool), None)
    out["mitre_technique"] = technique.where(technique.astype(bool), None)
    out["severity"] = severity
    out["true_severity"] = severity
    out["uncertainty_factor"] = uncertainty
    out["detector_score"] = detector_score
    out["native_severity"] = severity
    out["native_key"] = native_key
    out["native_category"] = out["attack_class"]
    out["asset_criticality"] = 1.0
    out["is_attack"] = is_attack
    out["is_critical"] = severity >= 8.0
    out["raw_label"] = raw_tactic
    out["src_ip"] = src_ip
    out["dst_ip"] = dst_ip
    out["src_port"] = src_port
    out["dst_port"] = dst_port
    out["protocol"] = protocol
    out["service"] = service
    out["src_subnet"] = src_subnet
    out["dst_subnet"] = dst_subnet
    out["subnet_pair"] = subnet_pair
    out["label_binary"] = label_binary
    out["label_cve"] = cve.where(cve.astype(bool), None)
    return out


def load_metric_table(path: str | Path, label_column: str) -> pd.DataFrame:
    """Load a published UWF metric table and return one row per label."""

    frame = pd.read_csv(path)
    if label_column not in frame.columns:
        raise ValueError(f"{path} does not contain {label_column}")
    week_columns = [column for column in frame.columns if column != label_column]
    rows = []
    for _, row in frame.iterrows():
        label = str(row[label_column]).strip()
        if not label or label.startswith("dt_") or label == "total_record_count":
            continue
        counts = pd.to_numeric(row[week_columns], errors="coerce").fillna(0)
        rows.append(
            {
                label_column: label,
                "total_count": int(counts.sum()),
                "active_weeks": int((counts > 0).sum()),
            }
        )
    return pd.DataFrame(rows)


def _series_from_aliases(data: pd.DataFrame, aliases: list[str]) -> pd.Series:
    for alias in aliases:
        if alias in data.columns:
            return data[alias]
    return pd.Series([""] * len(data), index=data.index, dtype=object)


def _timestamp_series(data: pd.DataFrame, row_offset: int) -> pd.Series:
    if "ts" in data.columns:
        return pd.to_numeric(data["ts"], errors="coerce").fillna(row_offset).astype(float)
    if "datetime" in data.columns:
        parsed = pd.to_datetime(data["datetime"], errors="coerce", utc=True)
        return (parsed.astype("int64") / 1_000_000_000).where(parsed.notna(), row_offset)
    return pd.Series(range(row_offset, row_offset + len(data)), index=data.index, dtype=float)


def _valid_technique(value: object) -> str:
    label = str(value).strip()
    normalized = label.lower()
    if normalized in {"", "none", "duplicate", "false", "nan"}:
        return ""
    return label


def _valid_cve(value: object) -> str:
    label = str(value).strip()
    normalized = label.lower()
    if normalized in {"", "none", "duplicate", "false", "nan"}:
        return ""
    return label


def _subnet24(value: object) -> str:
    parts = str(value).strip().split(".")
    if len(parts) != 4:
        return ""
    return ".".join(parts[:3]) + ".0/24"


def _safe_identifier(value: object) -> str:
    text = str(value).strip().lower()
    return "".join(char if char.isalnum() else "-" for char in text).strip("-")

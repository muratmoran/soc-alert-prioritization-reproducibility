"""NF-UQ-NIDS-v2 chunked loader and normalization."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator, Optional

import pandas as pd

from soc_alert_ranking.mappings.severity import (
    SeverityMapping,
    is_benign_label,
    normalize_label,
)


NF_UQ_CANONICAL_COLUMNS = [
    "alert_id",
    "dataset",
    "scenario",
    "timestamp",
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
    "native_name",
    "native_short",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "l7_protocol",
]


SOURCE_DOMAIN_ALIASES = {
    "NF-UNSW-NB15-v2": ["nf-unsw-nb15-v2", "unsw-nb15", "unsw"],
    "NF-ToN-IoT-v2": ["nf-ton-iot-v2", "ton-iot", "ton"],
    "NF-BoT-IoT-v2": ["nf-bot-iot-v2", "bot-iot", "bot"],
    "NF-CSE-CIC-IDS2018-v2": [
        "nf-cse-cic-ids2018-v2",
        "cse-cic-ids2018",
        "cse-cic",
        "ids2018",
    ],
}


ATTACK_CATEGORY_ALIASES = {
    "benign": "Benign",
    "normal": "Benign",
    "ddos": "DDoS",
    "dos": "DoS",
    "reconnaissance": "Reconnaissance",
    "recon": "Reconnaissance",
    "scanning": "Scanning",
    "scan": "Scanning",
    "injection": "Injection",
    "sql injection": "Injection",
    "sqlinjection": "Injection",
    "xss": "XSS",
    "cross site scripting": "XSS",
    "cross-site scripting": "XSS",
    "bruteforce": "Brute Force",
    "brute force": "Brute Force",
    "brute_force": "Brute Force",
    "brute-force": "Brute Force",
    "password": "Password",
    "infilteration": "Infiltration",
    "infiltration": "Infiltration",
    "exploits": "Exploits",
    "exploit": "Exploits",
    "fuzzers": "Fuzzers",
    "fuzzer": "Fuzzers",
    "backdoor": "Backdoor",
    "backdoors": "Backdoor",
    "bot": "Bot",
    "generic": "Generic",
    "analysis": "Analysis",
    "theft": "Theft",
    "shellcode": "Shellcode",
    "mitm": "MITM",
    "worms": "Worms",
    "worm": "Worms",
    "ransomware": "Ransomware",
    "web attacks": "Injection",
    "web attack": "Injection",
}


def discover_nf_uq_files(raw_path: str | Path) -> list[Path]:
    """Return candidate NF-UQ CSV files under a raw data directory."""

    root = Path(raw_path)
    if not root.exists():
        return []
    patterns = ["*.csv", "*.csv.gz"]
    files: list[Path] = []
    for pattern in patterns:
        files.extend(root.rglob(pattern))
    return sorted(
        {
            path
            for path in files
            if path.is_file()
            and not path.name.startswith(".")
            and "feature" not in path.stem.lower()
        }
    )


def iter_nf_uq_chunks(
    raw_path: str | Path,
    severity_mapping: Optional[SeverityMapping] = None,
    files: Optional[Iterable[str | Path]] = None,
    chunksize: int = 100_000,
    max_rows: Optional[int] = None,
    detector: str = "netflow_v2",
) -> Iterator[pd.DataFrame]:
    """Yield normalized NF-UQ-NIDS-v2 records as canonical DataFrame chunks."""

    mapping = severity_mapping or SeverityMapping.from_file()
    selected_files = [Path(path) for path in files] if files is not None else discover_nf_uq_files(raw_path)
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
            yield normalize_nf_uq_frame(
                chunk,
                path=path,
                mapping=mapping,
                row_offset=row_offset,
                detector=detector,
            )
            row_offset += len(chunk)
            if remaining is not None:
                remaining -= len(chunk)


def load_nf_uq_alerts(
    raw_path: str | Path,
    severity_mapping: Optional[SeverityMapping] = None,
    files: Optional[Iterable[str | Path]] = None,
    chunksize: int = 100_000,
    max_rows: Optional[int] = None,
    detector: str = "netflow_v2",
) -> pd.DataFrame:
    """Load a small or sampled NF-UQ subset into memory.

    For the full 75M-flow corpus, use :func:`iter_nf_uq_chunks` or the
    inspection scripts instead of materializing the entire DataFrame.
    """

    frames = list(
        iter_nf_uq_chunks(
            raw_path=raw_path,
            severity_mapping=severity_mapping,
            files=files,
            chunksize=chunksize,
            max_rows=max_rows,
            detector=detector,
        )
    )
    if not frames:
        return pd.DataFrame(columns=NF_UQ_CANONICAL_COLUMNS)
    return pd.concat(frames, ignore_index=True)[NF_UQ_CANONICAL_COLUMNS]


def normalize_nf_uq_frame(
    frame: pd.DataFrame,
    path: str | Path,
    mapping: SeverityMapping,
    row_offset: int = 0,
    detector: str = "netflow_v2",
) -> pd.DataFrame:
    """Normalize one NF-UQ CSV chunk into canonical alert-ranking columns."""

    data = frame.copy()
    path = Path(path)
    metadata = extract_nf_uq_metadata(data, path)
    source_domain = metadata["source_domain"]
    label_series = metadata["raw_label"]
    attack_class = metadata["attack_class"].tolist()
    is_attack = metadata["is_attack"].tolist()
    dst_port = _series_from_aliases(data, ["L4_DST_PORT", "dst_port", "Destination Port", "Dport"])
    src_port = _series_from_aliases(data, ["L4_SRC_PORT", "src_port", "Source Port", "Sport"])
    protocol = _series_from_aliases(data, ["PROTOCOL", "Protocol", "proto"])
    l7_protocol = _series_from_aliases(data, ["L7_PROTO", "l7_proto", "Application Protocol"])
    src_ip = _series_from_aliases(data, ["IPV4_SRC_ADDR", "src_ip", "Source IP", "Src IP"])
    dst_ip = _series_from_aliases(data, ["IPV4_DST_ADDR", "dst_ip", "Destination IP", "Dst IP"])
    timestamp = _timestamp_series(data, row_offset)
    detector_score = _numeric_series_from_aliases(
        data,
        ["detector_score", "score", "probability", "confidence", "predicted_probability"],
    )
    severity = [mapping.severity_for_nf_uq_category(category) for category in attack_class]
    uncertainty = [mapping.uncertainty_for_nf_uq_category(category) for category in attack_class]
    file_key = _safe_identifier(path.stem)
    native_category = [
        category if not is_benign_label(category) else "Benign"
        for category in attack_class
    ]
    native_key = [
        f"netflow:{domain}:{category}:proto={proto}:dport={dport}:l7={l7}".lower()
        for domain, category, proto, dport, l7 in zip(
            source_domain, native_category, protocol, dst_port, l7_protocol
        )
    ]

    out = pd.DataFrame(index=data.index)
    out["alert_id"] = [f"nf-uq-{file_key}-{row_offset + idx}" for idx in range(len(data))]
    out["dataset"] = "nf_uq_nids_v2"
    out["scenario"] = source_domain
    out["timestamp"] = timestamp
    out["detector"] = detector
    out["source_domain"] = source_domain
    out["attack_class"] = attack_class
    out["attack_phase"] = attack_class
    out["true_attack_phase"] = attack_class
    out["mitre_tactic"] = None
    out["mitre_technique"] = None
    out["severity"] = severity
    out["true_severity"] = severity
    out["uncertainty_factor"] = uncertainty
    out["detector_score"] = detector_score
    out["native_severity"] = None
    out["native_key"] = native_key
    out["native_category"] = native_category
    out["asset_criticality"] = 1.0
    out["is_attack"] = is_attack
    out["is_critical"] = [value >= 8.0 for value in severity]
    out["raw_label"] = [
        "" if pd.isna(label) else str(label)
        for label in label_series
    ]
    out["native_name"] = [
        f"{domain} {category} flow"
        for domain, category in zip(source_domain, native_category)
    ]
    out["native_short"] = native_category
    out["src_ip"] = src_ip.fillna("").astype(str)
    out["dst_ip"] = dst_ip.fillna("").astype(str)
    out["src_port"] = src_port
    out["dst_port"] = dst_port
    out["protocol"] = protocol.fillna("").astype(str)
    out["l7_protocol"] = l7_protocol.fillna("").astype(str)
    return out[NF_UQ_CANONICAL_COLUMNS]


def extract_nf_uq_metadata(frame: pd.DataFrame, path: str | Path) -> pd.DataFrame:
    """Extract source-domain and label metadata from an NF-UQ raw chunk."""

    data = frame.copy()
    fallback_domain = infer_source_domain_from_path(path)
    source_domain = _series_from_aliases(
        data,
        ["Dataset", "dataset", "Source", "source", "source_domain", "Source_Domain"],
        default=fallback_domain,
    ).map(lambda value: canonicalize_source_domain(value, fallback=fallback_domain))
    label_series = _series_from_aliases(
        data,
        ["Label", "label", "Binary Label", "binary_label", "Attack_label", "is_attack"],
        default=None,
    )
    category_series = _attack_category_series(data, label_series)
    attack_class = [
        canonicalize_attack_category(category, label)
        for category, label in zip(category_series, label_series)
    ]
    is_attack = [
        _parse_attack_flag(label, category)
        for label, category in zip(label_series, attack_class)
    ]
    return pd.DataFrame(
        {
            "source_domain": source_domain,
            "attack_class": attack_class,
            "is_attack": is_attack,
            "raw_label": label_series,
        },
        index=data.index,
    )


def canonicalize_attack_category(value: object, label: object = None) -> str:
    """Map raw NF-UQ attack labels into the pre-specified category table."""

    if value is None or pd.isna(value):
        return "Unknown" if _parse_attack_flag(label, "Unknown") else "Benign"
    text = str(value).strip()
    if not text:
        return "Unknown" if _parse_attack_flag(label, "Unknown") else "Benign"
    lowered = re.sub(r"\s+", " ", text.replace("_", " ").strip().lower())
    if lowered in ATTACK_CATEGORY_ALIASES:
        return ATTACK_CATEGORY_ALIASES[lowered]
    compact = re.sub(r"[^a-z0-9]+", "", lowered)
    if compact in ATTACK_CATEGORY_ALIASES:
        return ATTACK_CATEGORY_ALIASES[compact]
    if _looks_numeric(text):
        return "Unknown" if _parse_attack_flag(label, "Unknown") else "Benign"
    return text


def canonicalize_source_domain(value: object, fallback: str = "unknown") -> str:
    """Map source-domain labels or filenames to canonical NF-UQ domains."""

    if value is None or pd.isna(value):
        return fallback
    text = str(value).strip()
    if not text:
        return fallback
    normalized = _normalize_free_text(text)
    for canonical, aliases in SOURCE_DOMAIN_ALIASES.items():
        if normalized == _normalize_free_text(canonical):
            return canonical
        if any(alias in normalized for alias in aliases):
            return canonical
    return text


def infer_source_domain_from_path(path: str | Path) -> str:
    """Infer an NF-UQ source domain from a file path."""

    text = _normalize_free_text(Path(path).name)
    for canonical, aliases in SOURCE_DOMAIN_ALIASES.items():
        if any(alias in text for alias in aliases):
            return canonical
    return "unknown"


def _attack_category_series(data: pd.DataFrame, label_series: pd.Series) -> pd.Series:
    category = _series_from_aliases(
        data,
        [
            "Attack",
            "attack",
            "Attack Category",
            "Attack_Category",
            "attack_cat",
            "Category",
            "category",
            "Class",
            "class",
        ],
        default=None,
    )
    if not category.isna().all():
        return category
    if not _series_looks_binary(label_series):
        return label_series
    return pd.Series([None] * len(data), index=data.index)


def _series_from_aliases(
    data: pd.DataFrame,
    aliases: list[str],
    default: object = "",
) -> pd.Series:
    normalized = {_normalize_column_name(column): column for column in data.columns}
    for alias in aliases:
        column = normalized.get(_normalize_column_name(alias))
        if column is not None:
            return data[column]
    return pd.Series([default] * len(data), index=data.index)


def _numeric_series_from_aliases(data: pd.DataFrame, aliases: list[str]) -> pd.Series:
    values = _series_from_aliases(data, aliases, default=None)
    return pd.to_numeric(values, errors="coerce")


def _timestamp_series(data: pd.DataFrame, row_offset: int) -> pd.Series:
    values = _series_from_aliases(
        data,
        [
            "timestamp",
            "Timestamp",
            "ts",
            "FLOW_START_MILLISECONDS",
            "flow_start",
            "start_time",
            "stime",
        ],
        default=None,
    )
    if values.isna().all():
        return pd.Series(
            [float(row_offset + idx) for idx in range(len(data))],
            index=data.index,
        )
    numeric = pd.to_numeric(values, errors="coerce")
    if not numeric.isna().all():
        return numeric
    parsed = pd.to_datetime(values, utc=True, errors="coerce")
    return parsed.map(lambda value: float(value.timestamp()) if not pd.isna(value) else float("nan"))


def _parse_attack_flag(label: object, category: object) -> bool:
    if category is not None and not pd.isna(category):
        category_text = str(category)
        if category_text == "Unknown":
            return _parse_label_flag(label)
        if not is_benign_label(category_text):
            return True
    return _parse_label_flag(label)


def _parse_label_flag(value: object) -> bool:
    if value is None or pd.isna(value):
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "attack", "attacks", "malicious", "anomaly", "yes"}:
        return True
    if text in {"0", "false", "benign", "normal", "none", "no"}:
        return False
    if _looks_numeric(text):
        return float(text) > 0
    return normalize_label(text) not in {"", "benign", "normal"}


def _series_looks_binary(values: pd.Series) -> bool:
    sample = values.dropna().astype(str).str.strip().str.lower().head(100)
    if sample.empty:
        return False
    binary_values = {"0", "1", "true", "false", "attack", "benign", "normal", "malicious"}
    return all(value in binary_values for value in sample)


def _looks_numeric(value: object) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def _normalize_column_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).lower())


def _normalize_free_text(value: object) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", str(value).strip().lower()).strip("-")


def _safe_identifier(value: object) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", str(value)).strip("-").lower() or "file"

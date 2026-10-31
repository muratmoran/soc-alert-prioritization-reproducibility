"""AIT Alert Dataset loader."""

from __future__ import annotations

import json
import re
import warnings
from pathlib import Path
from typing import Any, Iterable, Optional

import pandas as pd

from soc_alert_ranking.mappings.severity import (
    SeverityMapping,
    choose_attack_label,
    is_benign_label,
    normalize_label,
    split_label_list,
)


CANONICAL_COLUMNS = [
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
    "host",
    "ip",
]


def discover_ait_files(raw_path: str | Path) -> list[Path]:
    """Return likely AIT alert files under a raw data directory."""

    root = Path(raw_path)
    if not root.exists():
        return []
    patterns = ["*alerts*.csv", "*alerts*.txt", "*labeled*.csv", "*.json", "*.jsonl"]
    files: list[Path] = []
    for pattern in patterns:
        files.extend(root.rglob(pattern))
    return sorted({path for path in files if path.is_file()})


def load_ait_alerts(
    raw_path: str | Path,
    severity_mapping: Optional[SeverityMapping] = None,
    files: Optional[Iterable[str | Path]] = None,
) -> pd.DataFrame:
    """Load AIT alerts into the canonical DataFrame schema."""

    mapping = severity_mapping or SeverityMapping.from_file()
    selected_files = [Path(path) for path in files] if files is not None else discover_ait_files(raw_path)
    label_intervals = load_ait_label_intervals(raw_path)
    frames = [_load_one_file(path, mapping, label_intervals) for path in selected_files]
    frames = [frame for frame in frames if not frame.empty]
    if not frames:
        return pd.DataFrame(columns=CANONICAL_COLUMNS)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        data = pd.concat(frames, ignore_index=True)
    data["alert_id"] = [f"ait-{idx}" for idx in range(len(data))]
    return data[CANONICAL_COLUMNS]


def load_ait_label_intervals(raw_path: str | Path) -> dict[str, list[tuple[float, float, str]]]:
    """Load AIT interval labels keyed by scenario."""

    root = Path(raw_path)
    candidates = [root / "labels.csv", *root.rglob("labels.csv")] if root.exists() else []
    label_path = next((path for path in candidates if path.is_file()), None)
    if label_path is None:
        return {}
    labels = pd.read_csv(label_path)
    required = {"scenario", "attack", "start", "end"}
    if not required.issubset(labels.columns):
        return {}
    intervals: dict[str, list[tuple[float, float, str]]] = {}
    for row in labels.itertuples(index=False):
        scenario = normalize_label(getattr(row, "scenario"))
        attack = normalize_label(getattr(row, "attack"))
        intervals.setdefault(scenario, []).append(
            (float(getattr(row, "start")), float(getattr(row, "end")), attack)
        )
    for scenario in intervals:
        intervals[scenario].sort(key=lambda item: item[0])
    return intervals


def _load_one_file(
    path: Path,
    mapping: SeverityMapping,
    label_intervals: dict[str, list[tuple[float, float, str]]],
) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix in {".csv", ".txt"}:
        frame = pd.read_csv(path)
        if path.name == "labels.csv":
            return pd.DataFrame(columns=CANONICAL_COLUMNS)
        if frame.empty:
            return pd.DataFrame(columns=CANONICAL_COLUMNS)
        return normalize_ait_frame(frame, path, mapping)
    elif suffix in {".json", ".jsonl"}:
        return normalize_ait_json_file(path, mapping, label_intervals)
    else:
        return pd.DataFrame(columns=CANONICAL_COLUMNS)


def _read_json_records(path: Path) -> pd.DataFrame:
    """Read newline-delimited or array-style JSON alerts."""

    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if not stripped:
        return pd.DataFrame()
    if stripped.startswith("["):
        data = json.loads(text)
        return pd.json_normalize(data)
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
    return pd.json_normalize(records)


def normalize_ait_json_file(
    path: Path,
    mapping: SeverityMapping,
    label_intervals: dict[str, list[tuple[float, float, str]]],
) -> pd.DataFrame:
    """Stream a raw AIT JSON/JSONL file into canonical columns."""

    scenario = _scenario_from_path(path)
    default_detector = _detector_from_path(path)
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            obj = json.loads(line)
            extracted = _extract_json_alert(obj)
            timestamp = _parse_timestamp(extracted["time"])
            true_label = _interval_label(label_intervals, scenario, timestamp)
            true_phases = split_label_list(true_label)
            true_phase = _primary_phase(true_phases)
            detector = infer_detector_from_json(
                obj,
                extracted["name"],
                extracted["short"],
                default_detector=default_detector,
            )
            inferred_phase = infer_attack_phase(extracted["name"], extracted["short"])
            ranking_severity = (
                mapping.severity_for_ait_phases([inferred_phase])
                if inferred_phase != "unknown"
                else mapping.default_unknown
            )
            rows.append(
                {
                    "alert_id": "",
                    "dataset": "ait_alert",
                    "scenario": scenario,
                    "timestamp": timestamp,
                    "detector": detector,
                    "source_domain": None,
                    "attack_class": inferred_phase,
                    "attack_phase": inferred_phase,
                    "true_attack_phase": true_phase,
                    "mitre_tactic": None,
                    "mitre_technique": None,
                    "severity": ranking_severity,
                    "true_severity": mapping.severity_for_ait_phases(true_phases),
                    "uncertainty_factor": (
                        mapping.uncertainty_for_ait_phases([inferred_phase])
                        if inferred_phase != "unknown"
                        else 0.5
                    ),
                    "detector_score": _detector_score_from_json(obj, detector),
                    "native_severity": _native_severity_from_json(obj),
                    "native_key": _native_key_from_json(obj, detector),
                    "native_category": _native_category_from_json(obj, detector),
                    "asset_criticality": 1.0,
                    "is_attack": not is_benign_label(true_label),
                    "is_critical": mapping.severity_for_ait_phases(true_phases) >= 8.0,
                    "raw_label": true_label,
                    "native_name": extracted["name"],
                    "native_short": extracted["short"],
                    "host": extracted["host"],
                    "ip": extracted["ip"],
                }
            )
    if not rows:
        return pd.DataFrame(columns=CANONICAL_COLUMNS)
    return pd.DataFrame(rows, columns=CANONICAL_COLUMNS)


def _extract_json_alert(obj: dict[str, Any]) -> dict[str, Any]:
    rule = obj.get("rule") or {}
    data = obj.get("data") or {}
    alert = data.get("alert") or {}
    analysis = obj.get("AnalysisComponent") or {}
    log_data = obj.get("LogData") or {}
    agent = obj.get("agent") or {}
    predecoder = obj.get("predecoder") or {}
    aminer = obj.get("AMiner") or {}

    name = (
        rule.get("description")
        or analysis.get("AnalysisComponentName")
        or alert.get("signature")
        or analysis.get("AnalysisComponentType")
        or ""
    )
    short = (
        rule.get("id")
        or alert.get("signature_id")
        or analysis.get("AnalysisComponentIdentifier")
        or ""
    )
    timestamp = (
        obj.get("@timestamp")
        or data.get("timestamp")
        or _first(log_data.get("DetectionTimestamp"))
        or _first(log_data.get("Timestamps"))
    )
    ip = agent.get("ip") or data.get("src_ip") or aminer.get("ID") or ""
    host = predecoder.get("hostname") or agent.get("name") or data.get("host") or aminer.get("ID") or ""
    return {"time": timestamp, "name": str(name), "short": str(short), "ip": str(ip), "host": str(host)}


def infer_detector_from_json(
    obj: dict[str, Any],
    name: object,
    short: object = "",
    default_detector: str = "unknown",
) -> str:
    rule = obj.get("rule") or {}
    groups = " ".join(str(group).lower() for group in rule.get("groups", []))
    location = str(obj.get("location", "")).lower()
    name_text = str(name or "").lower()
    if "suricata" in groups or "suricata" in location or "suricata" in name_text:
        return "suricata"
    if "AnalysisComponent" in obj or "AMiner" in obj:
        return "aminer"
    inferred = infer_detector(name, short)
    if inferred != "unknown":
        return inferred
    return default_detector


def _detector_score_from_json(obj: dict[str, Any], detector: str) -> Optional[float]:
    if detector == "wazuh":
        return _as_float((obj.get("rule") or {}).get("level"))
    if detector == "suricata":
        alert = (obj.get("data") or {}).get("alert") or {}
        severity = _as_float(alert.get("severity"))
        if severity is None:
            return _as_float((obj.get("rule") or {}).get("level"))
        # Suricata uses lower numeric severity for stronger alerts; invert to [0, 1].
        return max(0.0, min(1.0, (5.0 - severity) / 4.0))
    return None


def _native_severity_from_json(obj: dict[str, Any]) -> Optional[float]:
    alert = (obj.get("data") or {}).get("alert") or {}
    return (
        _as_float((obj.get("rule") or {}).get("level"))
        or _as_float(alert.get("severity"))
        or _as_float((obj.get("AnalysisComponent") or {}).get("AnalysisComponentIdentifier"))
    )


def _native_key_from_json(obj: dict[str, Any], detector: str) -> str:
    rule = obj.get("rule") or {}
    data = obj.get("data") or {}
    alert = data.get("alert") or {}
    analysis = obj.get("AnalysisComponent") or {}
    if detector == "suricata":
        signature_id = alert.get("signature_id") or rule.get("id") or ""
        signature = alert.get("signature") or rule.get("description") or ""
        category = alert.get("category") or ""
        return f"suricata:{signature_id}:{category}:{signature}".lower()
    if detector == "aminer":
        component_id = analysis.get("AnalysisComponentIdentifier") or ""
        component_type = analysis.get("AnalysisComponentType") or ""
        component_name = analysis.get("AnalysisComponentName") or ""
        return f"aminer:{component_id}:{component_type}:{component_name}".lower()
    rule_id = rule.get("id") or ""
    groups = ",".join(str(group) for group in rule.get("groups", []))
    description = rule.get("description") or ""
    return f"wazuh:{rule_id}:{groups}:{description}".lower()


def _native_category_from_json(obj: dict[str, Any], detector: str) -> Optional[str]:
    rule = obj.get("rule") or {}
    data = obj.get("data") or {}
    alert = data.get("alert") or {}
    analysis = obj.get("AnalysisComponent") or {}
    if detector == "suricata":
        value = alert.get("category")
    elif detector == "aminer":
        value = analysis.get("AnalysisComponentType")
    else:
        groups = rule.get("groups")
        value = ",".join(str(group) for group in groups) if isinstance(groups, list) else groups
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _first(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0]
    return value


def _as_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _interval_label(
    label_intervals: dict[str, list[tuple[float, float, str]]],
    scenario: str,
    timestamp: float,
) -> str:
    if pd.isna(timestamp):
        return "false_positive"
    for start, end, attack in label_intervals.get(normalize_label(scenario), []):
        if start <= timestamp < end:
            return attack
    return "false_positive"


def normalize_ait_frame(frame: pd.DataFrame, path: Path, mapping: SeverityMapping) -> pd.DataFrame:
    """Normalize a raw AIT CSV/JSON frame to canonical columns."""

    data = frame.copy()
    scenario = _scenario_from_path(path)

    data["_time"] = _coalesce(data, ["time", "timestamp", "@timestamp"])
    data["_name"] = _coalesce(data, ["name", "rule.description", "alert.signature", "AnalysisComponentName"])
    data["_short"] = _coalesce(data, ["short", "rule.id", "alert.signature_id"])
    data["_ip"] = _coalesce(data, ["ip", "agent.ip", "src_ip", "source.ip"])
    data["_host"] = _coalesce(data, ["host", "agent.name", "hostname"])
    data["_time_label"] = _coalesce(data, ["time_label"])
    data["_event_label"] = _coalesce(data, ["event_label"])

    true_labels = [
        choose_attack_label(event_label, time_label)
        for event_label, time_label in zip(data["_event_label"], data["_time_label"])
    ]
    true_phases = [split_label_list(label) for label in true_labels]
    primary_true_phases = [_primary_phase(items) for items in true_phases]
    inferred_phases = [
        infer_attack_phase(name, short)
        for name, short in zip(data["_name"], data["_short"])
    ]

    out = pd.DataFrame(index=data.index)
    out["alert_id"] = ""
    out["dataset"] = "ait_alert"
    out["scenario"] = scenario
    out["timestamp"] = data["_time"].map(_parse_timestamp)
    out["detector"] = [
        infer_detector(name, short)
        for name, short in zip(data["_name"], data["_short"])
    ]
    out["source_domain"] = None
    out["attack_class"] = inferred_phases
    out["attack_phase"] = inferred_phases
    out["true_attack_phase"] = primary_true_phases
    out["mitre_tactic"] = None
    out["mitre_technique"] = None
    out["severity"] = [
        mapping.severity_for_ait_phases([phase]) if phase != "unknown" else mapping.default_unknown
        for phase in inferred_phases
    ]
    out["true_severity"] = [mapping.severity_for_ait_phases(items) for items in true_phases]
    out["uncertainty_factor"] = [
        mapping.uncertainty_for_ait_phases([phase]) if phase != "unknown" else 0.5
        for phase in inferred_phases
    ]
    out["detector_score"] = None
    out["native_severity"] = [_native_severity(row) for _, row in data.iterrows()]
    out["native_key"] = [
        f"{detector}:{short}:{name}".lower()
        for detector, short, name in zip(out["detector"], data["_short"], data["_name"])
    ]
    out["native_category"] = None
    out["asset_criticality"] = 1.0
    out["is_attack"] = [not is_benign_label(label) for label in true_labels]
    out["is_critical"] = out["true_severity"] >= 8.0
    out["raw_label"] = true_labels
    out["native_name"] = data["_name"].fillna("").astype(str)
    out["native_short"] = data["_short"].fillna("").astype(str)
    out["host"] = data["_host"].fillna("").astype(str)
    out["ip"] = data["_ip"].fillna("").astype(str)
    return out


def infer_detector(name: object, short: object = "") -> str:
    """Infer detector source from AIT alert fields."""

    name_text = str(name or "").lower()
    short_text = str(short or "").lower()
    if name_text.startswith("suricata:") or short_text.startswith("s-"):
        return "suricata"
    if name_text.startswith("aminer:") or short_text.startswith("a-"):
        return "aminer"
    if name_text.startswith("wazuh:") or short_text.startswith("w-"):
        return "wazuh"
    if "suricata" in name_text:
        return "suricata"
    if "aminer" in name_text:
        return "aminer"
    if "wazuh" in name_text:
        return "wazuh"
    return "unknown"


def infer_attack_phase(name: object, short: object = "") -> str:
    """Infer a ranking-time attack phase from detector-native alert metadata.

    This function intentionally does not use AIT ground-truth labels. It is a
    conservative first-pass mapping from alert names/signatures to the severity
    table and will be replaced or extended with a curated rule table after the
    real files are inspected.
    """

    text = f"{short or ''} {name or ''}".lower()
    checks = [
        ("privilege_escalation", ["privilege", "sudo", "root", "shadow", "passwd"]),
        ("data_exfiltration", ["exfil", "data leak", "data transfer"]),
        ("dnsteal", ["dnsteal", "dns tunnel", "dns exfil"]),
        ("reverse_shell", ["reverse shell", "shell session", "netcat", " nc "]),
        ("webshell", ["webshell", "web shell", "cmd shell", "command shell"]),
        ("cracking", ["crack", "brute", "password", "failed login", "authentication failure"]),
        ("wpscan", ["wpscan", "wordpress scan"]),
        ("dirb", ["dirb", "directory brute", "directory scan"]),
        ("service_stop", ["service stop", "stopped service", "systemctl stop"]),
        ("service_scans", ["service scan", "port scan", "nmap", "portsweep"]),
        ("network_scans", ["network scan", "ping sweep", "icmp scan"]),
    ]
    padded = f" {text} "
    for phase, keywords in checks:
        if any(keyword in padded for keyword in keywords):
            return phase
    return "unknown"


def _coalesce(frame: pd.DataFrame, columns: list[str]) -> pd.Series:
    for column in columns:
        if column in frame.columns:
            return frame[column]
    return pd.Series([None] * len(frame), index=frame.index)


def _scenario_from_path(path: Path) -> str:
    stem = path.stem.lower()
    for suffix in ["_alerts", "_labeled", "_wazuh", "_aminer", "_suricata"]:
        stem = stem.replace(suffix, "")
    return stem.strip("_-") or "unknown"


def _detector_from_path(path: Path) -> str:
    stem = path.stem.lower()
    if stem.endswith("_aminer"):
        return "aminer"
    if stem.endswith("_wazuh"):
        return "wazuh"
    if stem.endswith("_suricata"):
        return "suricata"
    return "unknown"


def _parse_timestamp(value: object) -> float:
    if value is None or pd.isna(value):
        return float("nan")
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return float("nan")
    try:
        return float(text)
    except ValueError:
        parsed = pd.to_datetime(text, utc=True, errors="coerce")
        if pd.isna(parsed):
            return float("nan")
        return float(parsed.timestamp())


def _primary_phase(phases: list[str]) -> str:
    meaningful = [phase for phase in phases if not is_benign_label(phase)]
    if not meaningful:
        return "benign"
    return meaningful[0]


def _native_severity(row: pd.Series) -> Optional[float]:
    candidates = ["rule.level", "alert.severity", "severity"]
    for column in candidates:
        if column in row and not pd.isna(row[column]):
            try:
                return float(row[column])
            except (TypeError, ValueError):
                continue
    text = str(row.get("_name", ""))
    match = re.search(r"severity[:=]\s*([0-9]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None

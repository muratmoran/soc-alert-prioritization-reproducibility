"""Native-score provenance for AIT alerts (WP4).

The historical loader wrote a single ``detector_score`` column that pools two score types:

* for alerts inferred as Suricata, ``(5 - data.alert.severity) / 4`` clipped to [0, 1]
  when ``data.alert.severity`` exists, and otherwise the wrapping Wazuh ``rule.level``;
* for Wazuh alerts, ``rule.level``;
* for AMiner alerts, nothing.

This module re-reads the raw JSON in loader order and keeps each raw field separately, so
native references can be built from one score type at a time:

* ``native_rule_level``: the Wazuh ``rule.level`` of every alert delivered through Wazuh
  (Wazuh and Suricata alerts alike); one scale, 0-15.
* ``native_suricata_severity``: raw Suricata signature severity (1 = most severe) where the
  record carries ``data.alert.severity``; ordered by its negation, a label-independent
  monotone transform.
* ``native_record_type``: ``wazuh``; ``suricata_eve_alert`` (Suricata eve.json signature alerts
  delivered by Wazuh rule 86601, carrying ``data.alert.severity`` and rule.level 3);
  ``suricata_fast_log_ids_rule`` (Suricata fast.log lines matched by Wazuh's generic IDS rules
  20100-20162, with no ``data.alert`` and rule levels 6-11); or ``aminer``.

On AIT the loader's "Suricata" group contains both Suricata record types, so within-detector
reporting alone does not separate the two score types; the record type does.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from soc_alert_ranking.loaders import ait_alert as loader

PROVENANCE_COLUMNS = (
    "alert_id", "raw_file", "raw_line", "native_rule_level", "native_suricata_severity", "suricata_event_type",
    "rule_id", "rule_groups", "location", "loader_detector_score_branch",
)


def _float_or_nan(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def extract_provenance(raw_path: str | Path) -> pd.DataFrame:
    """Stream every raw AIT JSON record in the historical loader's order.

    Returns one row per alert with ``alert_id`` identical to ``load_ait_alerts`` and the
    recomputed ``scenario``, ``detector``, ``native_key`` and ``timestamp`` for alignment checks.
    """

    files = loader.discover_ait_files(raw_path)
    rows = []
    index = 0
    for path in files:
        if path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        scenario = loader._scenario_from_path(path)
        default_detector = loader._detector_from_path(path)
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                obj = json.loads(line)
                extracted = loader._extract_json_alert(obj)
                detector = loader.infer_detector_from_json(obj, extracted["name"], extracted["short"], default_detector=default_detector)
                rule = obj.get("rule") or {}
                data = obj.get("data") or {}
                alert = data.get("alert") or {}
                rule_level = _float_or_nan(rule.get("level"))
                severity = _float_or_nan(alert.get("severity"))
                if detector == "suricata":
                    branch = "suricata_inverted_alert_severity" if not np.isnan(severity) else "suricata_rule_level_fallback"
                elif detector == "wazuh":
                    branch = "wazuh_rule_level"
                else:
                    branch = "none"
                rows.append({
                    "alert_id": f"ait-{index}",
                    "raw_file": path.name,
                    "raw_line": line_number,
                    "scenario": scenario,
                    "detector": detector,
                    "native_key": loader._native_key_from_json(obj, detector),
                    "timestamp": loader._parse_timestamp(extracted["time"]),
                    "native_rule_level": rule_level,
                    "native_suricata_severity": severity,
                    "suricata_event_type": str(data.get("event_type") or ""),
                    "rule_id": str(rule.get("id") or ""),
                    "rule_groups": ",".join(str(g) for g in rule.get("groups", [])),
                    "location": str(obj.get("location") or ""),
                    "loader_detector_score_branch": branch,
                })
                index += 1
    return pd.DataFrame(rows)


def recompute_historical_detector_score(provenance: pd.DataFrame) -> np.ndarray:
    """Re-derive the loader's pooled ``detector_score`` from the separated raw fields."""

    branch = provenance["loader_detector_score_branch"].to_numpy()
    level = provenance["native_rule_level"].to_numpy(float)
    severity = provenance["native_suricata_severity"].to_numpy(float)
    inverted = np.clip((5.0 - severity) / 4.0, 0.0, 1.0)
    return np.select(
        [branch == "wazuh_rule_level", branch == "suricata_rule_level_fallback", branch == "suricata_inverted_alert_severity"],
        [level, level, inverted],
        default=np.nan,
    )


def record_types(detector: pd.Series, provenance: pd.DataFrame) -> np.ndarray:
    """Label-free record type from detector, raw severity presence and raw log location."""

    severity_present = provenance["native_suricata_severity"].notna().to_numpy()
    location = provenance["location"].astype(str).to_numpy()
    detector = np.asarray(detector).astype(str)
    eve = np.char.find(location.astype(str), "eve.json") >= 0
    fast = np.char.find(location.astype(str), "fast.log") >= 0
    suricata = detector == "suricata"
    if np.any(suricata & (eve != severity_present)) or np.any(suricata & ~(eve | fast)):
        raise ValueError("Suricata record location and raw severity presence disagree")
    return np.select([detector == "wazuh", suricata & eve, suricata & fast, detector == "aminer"],
                     ["wazuh", "suricata_eve_alert", "suricata_fast_log_ids_rule", "aminer"], default="unknown")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_revised_alerts(cache: str | Path, provenance_cache: str | Path) -> tuple[pd.DataFrame, dict[str, object]]:
    """Canonical alerts plus separated native-score provenance, with identity checks.

    Evaluation-label columns of the canonical cache are returned untouched; callers that
    rank or fit must select ranking-time columns only.
    """

    cache, provenance_cache = Path(cache), Path(provenance_cache)
    identity = json.loads(cache.with_suffix(".json").read_text())
    provenance_identity = json.loads(provenance_cache.with_suffix(".json").read_text())
    if _sha256(cache) != identity["sha256"]:
        raise ValueError("canonical cache does not match its identity record")
    if _sha256(provenance_cache) != provenance_identity["sha256"]:
        raise ValueError("provenance cache does not match its identity record")
    if provenance_identity["canonical_cache_sha256"] != identity["sha256"]:
        raise ValueError("provenance cache was built from a different canonical cache")
    alerts = pd.read_pickle(cache, compression="gzip")
    provenance = pd.read_pickle(provenance_cache, compression="gzip")
    if not np.array_equal(alerts["alert_id"].to_numpy(), provenance["alert_id"].to_numpy()):
        raise ValueError("provenance rows are not aligned with canonical alerts")
    alerts = alerts.assign(
        native_rule_level=provenance["native_rule_level"].to_numpy(float),
        native_suricata_severity=provenance["native_suricata_severity"].to_numpy(float),
        native_record_type=record_types(alerts["detector"], provenance),
    )
    return alerts, {"canonical_cache_sha256": identity["sha256"], "provenance_cache_sha256": provenance_identity["sha256"]}

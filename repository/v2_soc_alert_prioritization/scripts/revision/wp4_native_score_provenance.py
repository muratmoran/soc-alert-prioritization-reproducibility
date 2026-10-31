#!/usr/bin/env python
"""WP4: trace AIT native-score values to raw fields and parser branches (label-free).

Streams the 16 verified raw JSON files in loader order, checks alignment with the canonical
cache for every alert (detector, native_key, timestamp), re-derives the historical pooled
``detector_score`` from the separated raw fields, and tabulates value provenance by detector,
parser branch, rule identifier and Suricata event type. Writes a provenance cache next to
the canonical cache and docs/revision/wp4/native_score_provenance.json.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.revision.native_scores import extract_provenance, recompute_historical_detector_score  # noqa: E402

RAW = Path.home() / "soc_revision_data/ait_alert"
CACHE = Path.home() / "soc_revision_data/cache/ait_canonical_original_labels.pkl.gz"
PROVENANCE = Path.home() / "soc_revision_data/cache/ait_native_score_provenance.pkl.gz"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    started = time.perf_counter()
    identity = json.loads(CACHE.with_suffix(".json").read_text())
    if sha256(CACHE) != identity["sha256"]:
        raise SystemExit("cache identity mismatch")
    for name, digest in identity["raw_input_sha256"].items():
        if name.endswith(".json") and sha256(RAW / name) != digest:
            raise SystemExit(f"raw file {name} changed")
    cache = pd.read_pickle(CACHE, compression="gzip")
    provenance = extract_provenance(RAW)

    alignment = {
        "rows_cache": int(len(cache)), "rows_raw": int(len(provenance)),
        "alert_id_equal": bool((cache["alert_id"].to_numpy() == provenance["alert_id"].to_numpy()).all()),
        "scenario_equal": bool((cache["scenario"].to_numpy() == provenance["scenario"].to_numpy()).all()),
        "detector_equal": bool((cache["detector"].to_numpy() == provenance["detector"].to_numpy()).all()),
        "native_key_equal": bool((cache["native_key"].to_numpy() == provenance["native_key"].to_numpy()).all()),
        "timestamp_equal": bool(np.array_equal(cache["timestamp"].to_numpy(float), provenance["timestamp"].to_numpy(float))),
    }
    historical = cache["detector_score"].to_numpy(float)
    rederived = recompute_historical_detector_score(provenance)
    alignment["historical_detector_score_rederived"] = bool(np.array_equal(historical, rederived, equal_nan=True))

    frame = provenance.assign(historical_detector_score=historical)
    by_branch = (frame.groupby(["detector", "loader_detector_score_branch"])
                 .agg(alerts=("alert_id", "size"), keys=("native_key", "nunique"),
                      rule_level_missing=("native_rule_level", lambda s: int(s.isna().sum())),
                      severity_missing=("native_suricata_severity", lambda s: int(s.isna().sum())))
                 .reset_index())
    values = {}
    for (detector, branch), part in frame.groupby(["detector", "loader_detector_score_branch"]):
        values[f"{detector}|{branch}"] = {
            "historical_detector_score": part["historical_detector_score"].value_counts(dropna=False).sort_index().to_dict(),
            "raw_rule_level": part["native_rule_level"].value_counts(dropna=False).sort_index().to_dict(),
            "raw_suricata_severity": part["native_suricata_severity"].value_counts(dropna=False).sort_index().to_dict(),
            "suricata_event_type": part["suricata_event_type"].value_counts().head(10).to_dict(),
            "raw_files": part["raw_file"].str.replace(r"^[a-z]+_", "", regex=True).value_counts().to_dict(),
        }
    suricata_keys = (frame[frame["detector"] == "suricata"]
                     .groupby(["native_key", "loader_detector_score_branch", "rule_id", "rule_groups", "suricata_event_type"])
                     .agg(alerts=("alert_id", "size"), rule_levels=("native_rule_level", lambda s: sorted(s.dropna().unique().tolist())),
                          severities=("native_suricata_severity", lambda s: sorted(s.dropna().unique().tolist())),
                          locations=("location", lambda s: sorted(s.unique().tolist())[:3]))
                     .reset_index().sort_values("alerts", ascending=False))
    wazuh_wrapped = {
        "suricata_alerts_with_rule_level": int(frame.loc[frame["detector"] == "suricata", "native_rule_level"].notna().sum()),
        "suricata_alerts": int((frame["detector"] == "suricata").sum()),
        "wazuh_alerts_with_rule_level": int(frame.loc[frame["detector"] == "wazuh", "native_rule_level"].notna().sum()),
        "wazuh_alerts": int((frame["detector"] == "wazuh").sum()),
        "aminer_alerts_with_rule_level": int(frame.loc[frame["detector"] == "aminer", "native_rule_level"].notna().sum()),
        "wazuh_alerts_with_suricata_severity": int(frame.loc[frame["detector"] == "wazuh", "native_suricata_severity"].notna().sum()),
        "rule_level_by_detector": {d: sorted(p["native_rule_level"].dropna().unique().tolist())
                                   for d, p in frame.groupby("detector")},
        "suricata_severity_values": sorted(frame["native_suricata_severity"].dropna().unique().tolist()),
    }

    keep = provenance.drop(columns=["scenario", "detector", "native_key", "timestamp"])
    keep.to_pickle(PROVENANCE, compression="gzip")
    record = {"path": str(PROVENANCE), "sha256": sha256(PROVENANCE), "rows": int(len(keep)),
              "canonical_cache_sha256": identity["sha256"], "columns": list(keep.columns)}
    PROVENANCE.with_suffix(".json").write_text(json.dumps(record, indent=2))

    report = {
        "analysis_role": "WP4 native-score provenance; label-free, no scores of methods",
        "raw_files_verified": True,
        "alignment_with_canonical_cache": alignment,
        "by_detector_and_branch": by_branch.to_dict(orient="records"),
        "value_provenance": values,
        "suricata_keys": suricata_keys.to_dict(orient="records"),
        "wazuh_wrapper_fields": wazuh_wrapped,
        "provenance_cache": record,
        "runtime_seconds": round(time.perf_counter() - started, 1),
    }
    out = PROJECT_ROOT / "docs/revision/wp4/native_score_provenance.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"alignment": alignment, "by_branch": report["by_detector_and_branch"], "wrapper": wazuh_wrapped}, indent=1, default=str))
    print(suricata_keys.head(40).to_string())
    return 0 if all(alignment[k] for k in alignment if k.endswith(("equal", "rederived"))) else 1


if __name__ == "__main__":
    raise SystemExit(main())

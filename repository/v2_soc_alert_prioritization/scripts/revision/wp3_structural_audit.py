#!/usr/bin/env python
"""WP3: label-free structural audit of real AIT queues (no labels, no fitting, no scores).

Reads only ranking-time columns and reports:

1. Native-score availability and distinct values by detector and raw record type, separately for
   Wazuh rule.level and Suricata signature severity (WP4 provenance; the historical pooled
   detector_score is reported only as provenance).
2. Within-key variation of every per-alert input under each input policy. Under the flat
   context, c, u, h and h_key are key-level by construction; under asset_profile, c = s * q
   varies within a key exactly when q does, because every s is positive. The derived
   classification says, per family and per candidate, whether its score is guaranteed
   constant within keys under each policy.
3. Key-block sizes: the largest possible score blocks for key-constant scores.
4. Exact timestamp ties within scenarios (where the hash key decides order among equal scores).
5. Duplicate-cluster structure for 60, 300 and 900 s windows.

Writes docs/revision/wp3/structural_audit.json.
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
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.duplicates import WINDOWS_SECONDS, assign_clusters  # noqa: E402
from soc_alert_ranking.revision.features import RANKING_TIME_COLUMNS, RankingFrame  # noqa: E402
from soc_alert_ranking.revision.native_scores import load_revised_alerts  # noqa: E402
from soc_alert_ranking.revision.ties import candidate_inputs, guaranteed_constant_within_key, within_group_constancy  # noqa: E402

CACHE = Path.home() / "soc_revision_data/cache/ait_canonical_original_labels.pkl.gz"
PROVENANCE = Path.home() / "soc_revision_data/cache/ait_native_score_provenance.pkl.gz"


def main() -> int:
    alerts, identity = load_revised_alerts(CACHE, PROVENANCE)
    identity = {"sha256": identity["canonical_cache_sha256"], "provenance_sha256": identity["provenance_cache_sha256"]}
    alerts = alerts.loc[:, list(RANKING_TIME_COLUMNS)]
    ranking = RankingFrame.from_alerts(alerts)
    frame = ranking.frame
    config = load_comparison_config(PROJECT_ROOT / "configs/revision_wp2.yaml")
    severity = SeverityMapping.from_file()
    group = frame["scenario"].astype(str) + "|" + frame["key_id"].astype(str)

    # 1. native scores, one raw scale at a time
    def availability(values: pd.Series, by: list[str]) -> dict:
        out = {}
        for name, part in values.groupby([frame[c] for c in by]):
            label = "|".join(name) if isinstance(name, tuple) else str(name)
            out[label] = {"alerts": int(len(part)), "missing": int(part.isna().sum()), "missing_rate": float(part.isna().mean()),
                          "distinct_values": int(part.dropna().nunique()),
                          "values": sorted(float(v) for v in part.dropna().unique())[:20]}
        return out

    native_scales = {name: pd.to_numeric(frame[name], errors="coerce")
                     for name in ("native_rule_level", "native_suricata_severity")}
    native_by_detector = {name: {"by_detector": availability(values, ["detector"]),
                                 "by_detector_and_record_type": availability(values, ["detector", "native_record_type"])}
                          for name, values in native_scales.items()}
    native_by_detector["historical_pooled_detector_score_provenance_only"] = {
        "by_detector_and_record_type": availability(pd.to_numeric(frame["detector_score"], errors="coerce"),
                                                    ["detector", "native_record_type"])}
    native_key_constancy = {name: within_group_constancy(values.to_numpy(float), group.to_numpy())
                            for name, values in native_scales.items()}
    record_type_constancy = within_group_constancy(pd.factorize(frame["native_record_type"])[0].astype(float), group.to_numpy())
    native_varying = {name for name, stats in native_key_constancy.items() if stats["varying_groups"]}

    # 2. within-key input variation
    q = frame["q_asset_profile"].to_numpy(float)
    q_constancy = within_group_constancy(q, group.to_numpy())
    positive_severities = min(min(severity.ait_phase_severity.values()), severity.default_unknown) > 0
    timestamp_constancy = within_group_constancy(frame["timestamp"].to_numpy(float), group.to_numpy())
    varying = {
        "flat+table": {"timestamp"} | native_varying,
        "asset_profile+ambiguity_aware": {"timestamp"} | native_varying
        | ({"c"} if q_constancy["varying_groups"] and positive_severities else set()),
    }
    if timestamp_constancy["varying_groups"] == 0:
        for policy in varying:
            varying[policy].discard("timestamp")
    classification = {}
    for policy, inputs_varying in varying.items():
        families = {}
        for name, spec in config.families.items():
            flags = [guaranteed_constant_within_key(candidate_inputs(c.family, c.params_dict), inputs_varying) for c in spec.candidates]
            families[name] = {"candidates": len(flags), "guaranteed_constant_within_key": int(sum(flags)),
                              "may_vary_within_key": int(len(flags) - sum(flags))}
        classification[policy] = {"inputs_varying_within_keys": sorted(inputs_varying), "families": families}
    q_by_scenario = {}
    for scenario, part in frame.groupby("scenario"):
        stats = within_group_constancy(part["q_asset_profile"].to_numpy(float), part["key_id"].to_numpy())
        q_by_scenario[scenario] = {k: stats[k] for k in ("groups", "varying_groups", "share_alerts_in_varying_groups",
                                                           "max_distinct_scores_in_group")}
    q_by_detector = {}
    for detector, part in frame.groupby("detector"):
        stats = within_group_constancy(part["q_asset_profile"].to_numpy(float),
                                       (part["scenario"].astype(str) + "|" + part["key_id"].astype(str)).to_numpy())
        q_by_detector[detector] = {k: stats[k] for k in ("groups", "varying_groups", "share_alerts_in_varying_groups")}

    # 3. key blocks, 4. timestamp ties
    blocks = {}
    timestamp_ties = {}
    for scenario, part in frame.groupby("scenario"):
        sizes = part.groupby("key_id").size().sort_values(ascending=False)
        blocks[scenario] = {"alerts": int(len(part)), "keys_present": int(len(sizes)), "largest_key_block": int(sizes.iloc[0]),
                            "largest_key_share": float(sizes.iloc[0] / len(part)),
                            "keys_with_more_than_100_alerts": int((sizes > 100).sum()),
                            "share_alerts_in_keys_over_100": float(sizes[sizes > 100].sum() / len(part))}
        per_key_time = part.groupby(["key_id", "timestamp"]).size()
        timestamp_ties[scenario] = {"alerts_sharing_key_and_timestamp": int(per_key_time[per_key_time > 1].sum()),
                                    "share": float(per_key_time[per_key_time > 1].sum() / len(part)),
                                    "largest_same_key_same_timestamp_group": int(per_key_time.max())}

    # 5. duplicate clusters
    clusters = {}
    for window in WINDOWS_SECONDS:
        counts, sizes = 0, []
        for scenario, part in frame.groupby("scenario"):
            result = assign_clusters(part["detector"].to_numpy(), part["native_key"].to_numpy(), part["host"].to_numpy(),
                                     part["timestamp"].to_numpy(float), part["hash_key"].to_numpy(np.uint64), window)
            counts += result.n_clusters
            sizes.append(np.bincount(result.cluster_id))
        sizes = np.concatenate(sizes)
        clusters[f"{window}s"] = {"clusters": int(counts), "representative_share": float(counts / len(frame)),
                                  "max_cluster_size": int(sizes.max()), "median_cluster_size": float(np.median(sizes)),
                                  "singleton_clusters": int((sizes == 1).sum())}

    report = {
        "analysis_role": "WP3 label-free structural audit; no labels read, nothing fitted, no scores or metrics",
        "cache_sha256": identity["sha256"],
        "rows": int(len(frame)),
        "native_score_by_detector": native_by_detector,
        "native_score_within_key": native_key_constancy,
        "native_record_type_within_key": record_type_constancy,
        "provenance_cache_sha256": identity["provenance_sha256"],
        "asset_profile_q_within_key": {"all": q_constancy, "by_scenario": q_by_scenario, "by_detector": q_by_detector},
        "timestamp_within_key": timestamp_constancy,
        "family_within_key_constancy": classification,
        "key_blocks": blocks,
        "timestamp_ties_within_key": timestamp_ties,
        "duplicate_clusters": clusters,
    }
    out = PROJECT_ROOT / "docs/revision/wp3/structural_audit.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("native_score_by_detector", "native_score_within_key", "family_within_key_constancy", "duplicate_clusters")}, indent=1))
    print(json.dumps(report["asset_profile_q_within_key"]["all"]), json.dumps(report["asset_profile_q_within_key"]["by_detector"]))
    print(json.dumps(blocks, indent=0)[:1500]); print(json.dumps(timestamp_ties)[:900])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

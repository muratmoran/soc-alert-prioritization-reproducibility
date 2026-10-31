#!/usr/bin/env python
"""WP4 stage 2: gated AIT comparison runs R1–R7 with per-fold evaluation.

Implements docs/revision/wp4/stage2_reporting_specification.md (v1.0, declared before any
comparative result). Refuses to start unless the WP3 metric record and the WP4 fitting-boundary
record are both verified, neither is stale, the WP4 record pins the current stage-2
specification, and the config reproduces the frozen grid registry.

Each fold is executed with the nested pipeline, its trace is verified (a failure stops the run),
and the declared evaluations E1–E12 are computed in the same worker. Runs proceed in the
declared order: R1, R2, R3, R4, R5, R6, R7. Outer scores and features are stored for R1 and R2
only (disk budget); every other run stores its evaluation tables.

Outputs: results/revision_cose_04000/wp4/stage2/<run>/<split>/*.csv.gz, run_manifest.json.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import math
import multiprocessing as mp
import os
import platform
import sys
import time
import traceback
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.context import _asset_factor  # noqa: E402
from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.duplicates import WINDOWS_SECONDS, assign_clusters, static_cluster_labels  # noqa: E402
from soc_alert_ranking.revision.evaluation import full_order, top_k_order  # noqa: E402
from soc_alert_ranking.revision.features import RANKING_TIME_COLUMNS, InputPolicy, RankingFrame  # noqa: E402
from soc_alert_ranking.revision.labels import LabelStore, load_label_intervals, phase_order  # noqa: E402
from soc_alert_ranking.revision.metrics import (  # noqa: E402
    K_GRID, metrics_at_k, queue_report, restrict_queue, score_availability, subgroup_in_mixed_queue,
)
from soc_alert_ranking.revision.native_scores import load_revised_alerts  # noqa: E402
from soc_alert_ranking.revision.pipeline import ComparisonPipeline, verify_fold_trace  # noqa: E402
from soc_alert_ranking.revision.splits import (  # noqa: E402
    OuterSplit, forward_chaining_splits, identifier_holdout_splits, loso_splits, unseen_identifier_mask,
)
from soc_alert_ranking.revision.ties import (  # noqa: E402
    block_ids_along_order, expected_under_random_ties, near_tie_order, permutation_distribution,
    summarize_permutations, tie_diagnostics,
)

DATA = Path.home() / "soc_revision_data"
CACHE = DATA / "cache/ait_canonical_original_labels.pkl.gz"
PROVENANCE = DATA / "cache/ait_native_score_provenance.pkl.gz"
LABELS = DATA / "ait_alert/labels.csv"
OUT = PROJECT_ROOT / "results/revision_cose_04000/wp4/stage2"
SPEC = "docs/revision/wp4/stage2_reporting_specification.md"
GATES = ["docs/revision/wp3/metric_verification.json", "docs/revision/wp4/fitting_boundary_verification.json"]
SCRIPT_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

PRIMARY_RULE, SECONDARY_RULE = "primary_coverage_fp_ndcg", "secondary_ndcg"
RUN_ORDER = ["R1", "R2", "R3", "R4", "R5", "R6", "R7"]


def run_definitions(config) -> dict[str, list[tuple[str, InputPolicy, str]]]:
    """Run group -> [(run_id, policy, split kind)] in declared order."""

    return {
        "R1": [("R1", config.primary_policy, "loso")],
        "R2": [("R2", config.secondary_policy, "loso")],
        "R3": [(f"R3_{r}", InputPolicy(reliability=r), "loso") for r in ("global_class", "detector_only", "native_key", "none")],
        "R4": [(f"R4_{name}", InputPolicy(uncertainty=u), "loso") for name, u in (
            ("constant_0.5", "constant_0.5"), ("purity_only", "purity_only"), ("precision_only", "precision_only"),
            ("historical_combined", "ambiguity_aware"), ("zero", "zero"))],
        "R5": [("R5_asset_profile", InputPolicy(context="asset_profile"), "loso")],
        "R6": [("R6", config.primary_policy, "holdout")],
        "R7": [("R7", config.primary_policy, "forward")],
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_gates(config) -> dict[str, object]:
    identities = {}
    for gate in GATES:
        path = PROJECT_ROOT / gate
        if not path.exists():
            raise SystemExit(f"refusing to run: {gate} is missing")
        record = json.loads(path.read_text())
        if not record.get("verified"):
            raise SystemExit(f"refusing to run: {gate} is not verified")
        pinned = record.get("code_identity", {}).get("file_sha256", {})
        if not pinned:
            raise SystemExit(f"refusing to run: {gate} pins no files")
        stale = [p for p, d in pinned.items() if not (PROJECT_ROOT / p).exists() or sha256(PROJECT_ROOT / p) != d]
        if stale:
            raise SystemExit(f"refusing to run: {gate} is stale for {stale[:5]}")
        identities[gate] = {"sha256": sha256(path), "generated_at": record["generated_at"]}
    wp4 = json.loads((PROJECT_ROOT / GATES[1]).read_text())
    if wp4["code_identity"]["file_sha256"].get(SPEC) != sha256(PROJECT_ROOT / SPEC):
        raise SystemExit("refusing to run: the WP4 record does not pin the current stage-2 specification")
    frozen = json.loads((PROJECT_ROOT / "docs/revision/wp2/grid_registry.json").read_text())
    if frozen["registry_sha256"] != config.registry()["registry_sha256"] or frozen["revised_results_seen"]:
        raise SystemExit("refusing to run: grid registry mismatch")
    identities["registry_sha256"] = frozen["registry_sha256"]
    identities["stage2_specification_sha256"] = sha256(PROJECT_ROOT / SPEC)
    return identities


def load_everything():
    config = load_comparison_config(PROJECT_ROOT / "configs/revision_wp2.yaml")
    severity = SeverityMapping.from_file()
    manifest = json.loads((PROJECT_ROOT / "docs/revision/provenance_manifest.json").read_text())
    expected_md5 = manifest["raw_data_verification"]["ait_alert"]["details"]["published_md5"]["labels.csv"]["expected"]
    if hashlib.md5(LABELS.read_bytes()).hexdigest() != expected_md5:
        raise SystemExit("labels.csv does not match the published MD5")
    alerts, identity = load_revised_alerts(CACHE, PROVENANCE)
    ranking = RankingFrame.from_alerts(alerts.loc[:, list(RANKING_TIME_COLUMNS)])
    del alerts
    intervals = load_label_intervals(LABELS, severity, config.tau)
    store = LabelStore.from_alerts(ranking.frame, intervals, phase_order(severity), config.tau)
    return config, severity, ranking, store, identity


def splits_for(kind: str, ranking: RankingFrame) -> list[OuterSplit]:
    if kind == "loso":
        return loso_splits(ranking)
    if kind == "holdout":
        return identifier_holdout_splits(ranking)
    if kind == "forward":
        return forward_chaining_splits(ranking)[0]
    raise ValueError(kind)


# ------------------------------------------------------------------ worker
_STATE: dict[str, object] = {}


def _init_worker():
    config, severity, ranking, store, identity = load_everything()
    _STATE.update(config=config, ranking=ranking, store=store, pipeline=ComparisonPipeline(ranking, store, severity, config))


def write_frames(directory: Path, frames: dict[str, pd.DataFrame]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, frame in frames.items():
        frame.to_csv(directory / f"{name}.csv.gz", index=False, compression="gzip")


def candidate_roles(result, config) -> dict[str, dict[str, object]]:
    roles: dict[str, dict[str, object]] = {}
    for name, spec in config.families.items():
        if not spec.tuned:
            for candidate in spec.candidates:
                roles[candidate.candidate_id] = {"family": name, "rules": "untuned"}
    for row in result.selections.itertuples(index=False):
        cid = getattr(row, "selected_candidate")
        if cid is None or (isinstance(cid, float) and math.isnan(cid)):
            continue
        entry = roles.setdefault(cid, {"family": row.family, "rules": ""})
        tag = "primary" if row.rule == PRIMARY_RULE else "secondary"
        entry["rules"] = tag if not entry["rules"] else "+".join(sorted(set(entry["rules"].split("+")) | {tag}))
    return roles


def selected_by_primary(result) -> dict[str, str]:
    part = result.selections[result.selections["rule"] == PRIMARY_RULE]
    return {row.family: row.selected_candidate for row in part.itertuples(index=False)}


def curve_ranks(n: int) -> np.ndarray:
    ranks = set(np.unique(np.ceil(np.logspace(0, math.log10(n), 200)).astype(np.int64)).tolist())
    ranks |= {k for k in K_GRID if k <= n} | {n}
    return np.array(sorted(r for r in ranks if 1 <= r <= n), dtype=np.int64)


def curves(order, labels, ranks) -> pd.DataFrame:
    z = labels.z[order]
    y = labels.y[order]
    membership = labels.critical_membership[order]
    defined = labels.defined_critical_intervals
    first = np.array([np.flatnonzero(membership[:, c])[0] + 1 if membership[:, c].any() else np.iinfo(np.int64).max
                      for c in range(membership.shape[1])], dtype=np.int64)
    cz, cy = np.cumsum(z), np.cumsum(y)
    return pd.DataFrame({
        "rank": ranks,
        "critical_recall": cz[ranks - 1] / z.sum() if z.sum() else np.nan,
        "attack_recall": cy[ranks - 1] / y.sum() if y.sum() else np.nan,
        "coverage_all": np.array([(first <= r).sum() for r in ranks]) / defined if defined else np.nan,
    })


def gamma(candidate_family: str, params: dict, features) -> np.ndarray | None:
    kappa = params.get("kappa")
    if candidate_family.startswith(("S0_", "S1_")):
        h = features.h_key if candidate_family.endswith("_key") else features.h
        return 1.0 + kappa * features.u * np.log(h)
    if candidate_family.startswith("S2_"):
        h = features.h_key if candidate_family.endswith("_key") else features.h
        return np.power(h, kappa * features.u)
    return None


def evaluate_fold(run_id: str, run_group: str, split: OuterSplit, policy: InputPolicy, result, features, labels,
                  pipeline: ComparisonPipeline) -> dict[str, pd.DataFrame]:
    config = pipeline.config
    ranking = pipeline.ranking
    held_out = split.held_out
    rows = ranking.rows(held_out)
    n = len(rows)
    ts = rows["timestamp"].to_numpy(float)
    hk = rows["hash_key"].to_numpy(np.uint64)
    detector = rows["detector"].astype(str).to_numpy()
    record_type = rows["native_record_type"].astype(str).to_numpy()
    key_ids = rows["key_id"].to_numpy()
    base = {"run": run_id, "split": split.name, "held_out": held_out, "policy": policy.name}
    roles = candidate_roles(result, config)
    candidates = {c.candidate_id: c for c in result.outer_candidates}
    scores = result.outer_scores
    orders = {cid: full_order(scores[cid], ts, hk) for cid in scores}
    tag = lambda cid: {**base, "candidate_id": cid, **roles.get(cid, {"family": candidates[cid].family, "rules": "?"})}  # noqa: E731
    frames: dict[str, list[dict]] = defaultdict(list)

    # E1 and E2
    for cid, order in orders.items():
        report = queue_report(order, labels)
        for budget in report["budgets"]:
            frames["e1_budgets"].append({**tag(cid), **budget})
        frames["e1_first_critical"].append({**tag(cid), **report["first_critical"]})
        for effort in report["effort"]:
            frames["e1_efforts"].append({**tag(cid), **effort})
        diagnostics = tie_diagnostics(scores[cid], order, K_GRID)
        frames["e2_ties"].append({**tag(cid), **{k: v for k, v in diagnostics.items() if k != "cutoffs"}})
        for cutoff in diagnostics["cutoffs"]:
            frames["e2_tie_cutoffs"].append({**tag(cid), **cutoff})
        for k in K_GRID:
            frames["e2_expected"].append({**tag(cid), **expected_under_random_ties(scores[cid], labels, k).to_record()})

    # E3 and E4
    if run_group in {"R1", "R2"}:
        for cid in orders:
            distribution = permutation_distribution(scores[cid], labels, K_GRID, range(100))
            for record in summarize_permutations(distribution).to_dict(orient="records"):
                frames["e3_permutation_summary"].append({**tag(cid), **record})
            at100 = distribution[distribution["k"] == 100]
            for record in at100.itertuples(index=False):
                covered = None if record.coverage_all is None or pd.isna(record.coverage_all) else \
                    int(round(record.coverage_all * labels.defined_critical_intervals))
                frames["e3_seed_k100"].append({**tag(cid), "seed": record.seed, "covered_intervals": covered,
                                               "negatives_in_top": record.negatives_in_top,
                                               "critical_recall": record.critical_recall})
            near = near_tie_order(scores[cid], ts, hk, 4)
            for k in K_GRID:
                frames["e4_near_ties"].append({**tag(cid), **metrics_at_k(near, labels, k).to_record()})

    # E5: within-detector queues and native availability
    if run_group == "R1":
        subsets = [("detector", "wazuh", detector == "wazuh"), ("detector", "suricata", detector == "suricata")]
        native = {"O_native_rule_level", "O_native_suricata_severity"}
        for cid in orders:
            extra = [("record_type", t, record_type == t) for t in ("suricata_eve_alert", "suricata_fast_log_ids_rule")] \
                if cid in native else []
            for kind, value, mask in subsets + extra:
                availability = score_availability(scores[cid][mask])
                entry = {**tag(cid), "subset_kind": kind, "subset": value, **availability.to_record()}
                if not availability.ordering_defined or not mask.any():
                    frames["e5_within_subset"].append({**entry, "budget": None})
                    continue
                sub = restrict_queue(labels, mask)
                sub_order = full_order(scores[cid][mask], ts[mask], hk[mask])
                report = queue_report(sub_order, sub)
                for budget in report["budgets"]:
                    frames["e5_within_subset"].append({**entry, **budget})
                frames["e5_within_subset_first_critical"].append({**entry, **report["first_critical"]})
                for effort in report["effort"]:
                    frames["e5_within_subset_efforts"].append({**entry, **effort})
            if cid in native:
                for kind, values in (("detector", detector), ("record_type", record_type)):
                    for value in sorted(set(values)):
                        frames["e5_native_availability"].append({**tag(cid), "subset_kind": kind, "subset": value,
                                                                 **score_availability(scores[cid][values == value]).to_record()})

        # E6: duplicate units
        for window in WINDOWS_SECONDS:
            clusters = assign_clusters(detector, rows["native_key"].astype(str).to_numpy(), rows["host"].astype(str).to_numpy(),
                                       ts, hk, window)
            reps = np.flatnonzero(clusters.representative)
            own_labels = restrict_queue(labels, clusters.representative)
            static_labels, static_reps, summary = static_cluster_labels(labels, clusters)
            if not np.array_equal(reps, static_reps):
                raise RuntimeError("representative order mismatch")
            frames["e6_cluster_summary"].append({**base, "window_seconds": window, "alerts": n, **vars(summary)})
            for cid in orders:
                rep_order = full_order(scores[cid][reps], ts[reps], hk[reps])
                for unit, unit_labels in (("representative_own", own_labels), ("static_cluster", static_labels)):
                    for k in K_GRID:
                        frames["e6_duplicates"].append({**tag(cid), "window_seconds": window, "unit": unit,
                                                        **metrics_at_k(rep_order, unit_labels, k).to_record()})

    # E7: subgroups
    subgroups = []
    if run_group == "R1":
        unseen = unseen_identifier_mask(ranking, held_out, split.training)
        subgroups = [("mapped", features.mapped), ("unmapped", ~features.mapped), ("unseen_identifier", unseen),
                     ("seen_identifier", ~unseen)]
    elif run_group == "R6":
        subgroups = [("held_out_group_identifier", features.excluded_identifier), ("other_identifiers", ~features.excluded_identifier)]
    for name, mask in subgroups:
        sub = restrict_queue(labels, mask)
        for cid, order in orders.items():
            sub_order = full_order(scores[cid][mask], ts[mask], hk[mask])
            for k in K_GRID:
                frames["e7_subgroup_mixed_queue"].append({**tag(cid), "subgroup": name,
                                                          **subgroup_in_mixed_queue(order, labels, mask, k).to_record()})
                frames["e7_subgroup_within"].append({**tag(cid), "subgroup": name, "subgroup_n": int(mask.sum()),
                                                     **metrics_at_k(sub_order, sub, k).to_record()})

    # E8: deferral audit
    per_key = pd.DataFrame(result.fit_records["per_key"])
    primary_selected = selected_by_primary(result)
    gamma_candidates = ["S0_linear_log_historical[kappa=1]", "S0_linear_log_historical_key[kappa=1]"] + [
        primary_selected[f] for f in ("S1_linear_log_constrained", "S1_linear_log_constrained_key",
                                      "S2_exponential_discount", "S2_exponential_discount_key") if f in primary_selected]
    gammas = {}
    for cid in gamma_candidates:
        g = gamma(candidates[cid].family, candidates[cid].params_dict, features)
        gammas[cid] = g
        frame = pd.DataFrame({"detector": detector, "mapped": features.mapped, "z": labels.z, "g0": g <= 0, "g01": g <= 0.1})
        for (det, mapped, z), part in frame.groupby(["detector", "mapped", "z"]):
            frames["e8_coefficients"].append({**tag(cid), "detector": det, "mapped": bool(mapped), "z": bool(z),
                                              "alerts": int(len(part)), "gamma_le_0": int(part["g0"].sum()),
                                              "gamma_le_0_1": int(part["g01"].sum()),
                                              "share_le_0": float(part["g0"].mean()), "share_le_0_1": float(part["g01"].mean())})
    deferral_candidates = ["P_probability_proxy", "H_weighted", "S0_linear_log_historical[kappa=1]", "O_severity"] + [
        primary_selected[f] for f in ("W_weighted", "A_additive", "S1_linear_log_constrained", "S2_exponential_discount")
        if f in primary_selected]
    n_half = math.ceil(n / 2)
    accepted = per_key["accepted"].to_numpy(bool)
    precision = per_key["precision"].to_numpy(float)
    support = per_key["support"].to_numpy(float)
    positives = per_key["positives"].to_numpy(float)
    purity = per_key["purity"].to_numpy(float)
    height = per_key["height"].to_numpy(float)
    height_fallback = per_key["height_fallback"].to_numpy(int)
    benign_key = (precision < 0.5) & (support >= 1000)
    for cid in dict.fromkeys(deferral_candidates):
        order = orders[cid]
        rank = np.empty(n, dtype=np.int64)
        rank[order] = np.arange(1, n + 1)
        z = labels.z
        critical_fraction = rank[z] / n
        deep = z & (rank > n_half)
        keys_deep = key_ids[deep]
        blocks = block_ids_along_order(scores[cid], order)
        cutoff_block = blocks[n_half - 1]
        crosses = n_half < n and blocks[n_half] == cutoff_block
        displaced = crosses & (blocks[rank[deep] - 1] == cutoff_block)
        unmapped = ~accepted[keys_deep]
        own_gamma = gammas.get(cid)
        top = order[:n_half]
        record = {
            **tag(cid), "n": n, "n_half": n_half, "critical_total": int(z.sum()), "deep_deferred": int(deep.sum()),
            "deep_deferred_share": float(deep.sum() / z.sum()) if z.sum() else None,
            "critical_rank_fraction_p10": float(np.percentile(critical_fraction, 10)) if z.sum() else None,
            "critical_rank_fraction_p50": float(np.percentile(critical_fraction, 50)) if z.sum() else None,
            "critical_rank_fraction_p90": float(np.percentile(critical_fraction, 90)) if z.sum() else None,
            "cause_mapping_rejection": int(unmapped.sum()),
            "cause_mapping_rejection_support_lt_5": int((unmapped & (support[keys_deep] < 5)).sum()),
            "cause_mapping_rejection_positives_lt_3": int((unmapped & (positives[keys_deep] < 3)).sum()),
            "cause_mapping_rejection_precision_lt_0_5": int((unmapped & (precision[keys_deep] < 0.5)).sum()),
            "cause_mapping_rejection_purity_lt_0_7": int((unmapped & (purity[keys_deep] < 0.7)).sum()),
            "cause_mapping_rejection_no_positives": int((unmapped & (positives[keys_deep] == 0)).sum()),
            "cause_low_reliability": int((~unmapped & (height[keys_deep] <= 0.2)).sum()),
            "cause_low_reliability_clipped_at_min": int((~unmapped & (height[keys_deep] == config.settings.height_min)).sum()),
            "cause_low_reliability_fallback_detector": int((~unmapped & (height[keys_deep] <= 0.2) & (height_fallback[keys_deep] == 1)).sum()),
            "cause_low_reliability_fallback_global": int((~unmapped & (height[keys_deep] <= 0.2) & (height_fallback[keys_deep] == 2)).sum()),
            "cause_severity_reversal": int((own_gamma[deep] <= 0).sum()) if own_gamma is not None and candidates[cid].family.startswith(("S0_", "S1_")) else None,
            "cause_tie_rule_displacement": int(displaced.sum()),
            "top_half_share_recurring_benign_negatives": float(np.mean(~labels.y[top] & benign_key[key_ids[top]])) if n_half else None,
        }
        frames["e8_deep_deferral"].append(record)

    # E9: calibration
    if run_group in {"R1", "R3"}:
        h = features.h
        y = labels.y.astype(float)
        frames["e9_calibration"].append({**base, "reliability": policy.reliability, "alerts": n,
                                         "brier": float(np.mean((h - y) ** 2)), "mean_h": float(h.mean()), "y_share": float(y.mean()),
                                         "mapping_coverage": float(features.mapped.mean()),
                                         "class_height_fallback_alerts": int((features.h_fallback > 0).sum())})
        edges = np.arange(11) / 10
        bins = np.minimum(np.searchsorted(edges, h, side="right") - 1, 9)
        for b in range(10):
            mask = bins == b
            frames["e9_reliability_bins"].append({**base, "reliability": policy.reliability, "bin": b, "lower": edges[b],
                                                  "upper": edges[b + 1], "alerts": int(mask.sum()),
                                                  "mean_h": float(h[mask].mean()) if mask.any() else None,
                                                  "y_share": float(y[mask].mean()) if mask.any() else None})
        for record in result.fit_records["per_key"]:
            frames["e9_key_heights"].append({**base, "reliability": policy.reliability, **record})
        for record in result.fit_records["class_heights"]:
            frames["e9_class_heights"].append({**base, "reliability": policy.reliability, **record})

    # E10: agreement with R1 and curves (reference curves are computed in R1)
    agreement_families = [f for f, spec in config.families.items() if spec.tuned]
    agreement_untuned = ["P_probability_proxy", "H_weighted", "S0_linear_log_historical[kappa=1]"]
    if run_group in {"R1", "R3", "R4", "R5"}:
        ranks = curve_ranks(n)
        chosen = {f: primary_selected.get(f) for f in agreement_families} | {c: c for c in agreement_untuned}
        for label, cid in chosen.items():
            if cid is None or cid not in orders:
                continue
            curve = curves(orders[cid], labels, ranks)
            curve.insert(0, "agreement_label", label)
            for key, value in tag(cid).items():
                curve[key] = value
            frames["e10_curves"].extend(curve.to_dict(orient="records"))
        if run_group != "R1":
            from scipy.stats import spearmanr

            reference_dir = OUT / "R1" / split.name.replace(":", "_")
            reference_scores = np.load(reference_dir / "outer_scores.npz", allow_pickle=False)
            reference_selections = pd.read_csv(reference_dir / "e12_selections.csv.gz")
            reference_primary = reference_selections[reference_selections["rule"] == PRIMARY_RULE]
            reference_chosen = dict(zip(reference_primary["family"], reference_primary["selected_candidate"])) | {c: c for c in agreement_untuned}
            if not np.array_equal(reference_scores["alert_ids"], result.outer_alert_ids.astype(str)):
                raise RuntimeError("R1 reference alert order differs")
            for label, cid in chosen.items():
                ref_cid = reference_chosen.get(label)
                if cid is None or ref_cid is None or cid not in scores or ref_cid not in reference_scores.files:
                    continue
                a, b = scores[cid], reference_scores[ref_cid]
                constant = np.nanmin(a) == np.nanmax(a) or np.nanmin(b) == np.nanmax(b)
                rho = None if constant else float(spearmanr(a, b, nan_policy="omit").statistic)
                top_a = set(top_k_order(a, ts, hk, 100).tolist())
                top_b = set(top_k_order(b, ts, hk, 100).tolist())
                frames["e10_agreement"].append({**base, "agreement_label": label, "candidate_id": cid, "r1_candidate_id": ref_cid,
                                                "spearman": rho, "top100_overlap": len(top_a & top_b) / 100})

    # E11: context token audit
    if run_group == "R5":
        combos = rows[["detector", "host", "ip", "native_key", "native_category"]].astype(str).drop_duplicates()
        audit = []
        for combo in combos.itertuples(index=False):
            full = _asset_factor(combo.host, combo.ip, combo.native_key, combo.native_category)
            host_ip = _asset_factor(combo.host, combo.ip, "", "")
            key_category = _asset_factor("", "", combo.native_key, combo.native_category)
            source = ("both" if host_ip == full and key_category == full else "host_ip" if host_ip == full
                      else "key_category" if key_category == full else "combined_text_only")
            audit.append({"detector": combo.detector, "host": combo.host, "ip": combo.ip, "native_key": combo.native_key,
                          "native_category": combo.native_category, "q": full, "source": source})
        audit = pd.DataFrame(audit)
        merged = rows[["detector", "host", "ip", "native_key", "native_category"]].astype(str).merge(
            audit, on=["detector", "host", "ip", "native_key", "native_category"], how="left")
        counts = merged[merged["q"] != 1.0].groupby(["detector", "q", "source"]).size().reset_index(name="alerts")
        for record in counts.to_dict(orient="records"):
            frames["e11_context_tokens"].append({**base, **record, "alerts_q_not_1_total": int((merged["q"] != 1.0).sum()), "n": n})

    # E12: selection and execution records
    selections = result.selections.copy()
    for key, value in base.items():
        selections[key] = value
    output = {name: pd.DataFrame(records) for name, records in frames.items()}
    output["e12_selections"] = selections
    output["e12_inner_metrics"] = result.inner_metrics
    output["e12_learner_diagnostics"] = pd.DataFrame([{**base, **{k: (json.dumps(v) if isinstance(v, (list, dict)) else v)
                                                                   for k, v in d.items()}} for d in result.learner_diagnostics])
    output["e12_fit_fallbacks"] = pd.DataFrame([{**base, **result.fit_records["outer_target_fallback_alerts"]}])
    return output


def run_fold(job) -> dict:
    run_id, run_group, split_record, policy_fields = job
    pipeline: ComparisonPipeline = _STATE["pipeline"]
    ranking: RankingFrame = _STATE["ranking"]
    store: LabelStore = _STATE["store"]
    split = OuterSplit(**{**split_record, "training": tuple(split_record["training"]),
                          "excluded_key_ids": tuple(split_record["excluded_key_ids"])})
    policy = InputPolicy(**policy_fields)
    fold_dir = OUT / run_id / split.name.replace(":", "_")
    done = fold_dir / "done.json"
    if done.exists() and json.loads(done.read_text()).get("script_sha256") == SCRIPT_SHA:
        return json.loads(done.read_text())
    started = time.perf_counter()
    pipeline.builder.clear_cache()
    pipeline.builder.trace.clear()
    pipeline.builder.manifest.clear()
    store.access_log.clear()
    try:
        result = pipeline.run_outer_fold(split, policy)
        verification = verify_fold_trace(result, ranking)
        if not verification.passed:
            raise RuntimeError(f"trace verification failed for {run_id} {split.name}: {verification.violations[:3]}")
        run_seconds = time.perf_counter() - started
        with store.locked([split.held_out]):
            features = pipeline.builder.alert_features(split.held_out, split.training, policy,
                                                       role=f"{split.name}:stage2_evaluation_features",
                                                       excluded_key_ids=split.excluded_key_ids)
        labels = store.get(split.held_out, purpose=f"{split.name}:outer_evaluation")
        frames = evaluate_fold(run_id, run_group, split, policy, result, features, labels, pipeline)
    except Exception as error:
        return {"run": run_id, "split": split.name, "error": repr(error), "traceback": traceback.format_exc()}
    write_frames(fold_dir, frames)
    if run_group in {"R1", "R2"}:
        np.savez_compressed(fold_dir / "outer_scores.npz", alert_ids=result.outer_alert_ids.astype(str), **result.outer_scores)
        np.savez_compressed(fold_dir / "outer_features.npz", c=features.c, u=features.u, h=features.h, h_key=features.h_key,
                            mapped=features.mapped, h_fallback=features.h_fallback, h_key_fallback=features.h_key_fallback)
    with gzip.open(fold_dir / "trace.json.gz", "wt", encoding="utf-8") as handle:
        json.dump({"split": split.to_record(), "policy": policy.name, "verification": vars(verification),
                   "feature_requests": result.manifest, "trace": result.trace, "label_access_log": result.label_access_log,
                   "fit_records": result.fit_records}, handle, default=str)
    summary = {"run": run_id, "split": split.name, "held_out": split.held_out, "policy": policy.name,
               "trace_verification_passed": True, "outer_candidates": len(result.outer_scores),
               "run_seconds": round(run_seconds, 1), "total_seconds": round(time.perf_counter() - started, 1),
               "script_sha256": SCRIPT_SHA, "tables": sorted(frames)}
    done.write_text(json.dumps(summary, indent=1))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--groups", nargs="+", default=RUN_ORDER, choices=RUN_ORDER)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--omp-threads", type=int, default=3)
    args = parser.parse_args()
    if args.groups != [g for g in RUN_ORDER if g in args.groups]:
        raise SystemExit("run groups must follow the declared order")
    os.environ["OMP_NUM_THREADS"] = str(args.omp_threads)
    config = load_comparison_config(PROJECT_ROOT / "configs/revision_wp2.yaml")
    identities = check_gates(config)
    ranking_config, _, ranking, _, data_identity = load_everything()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest_path = OUT / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"invocations": []}
    import numpy, pandas, scipy, sklearn  # noqa: E401
    invocation = {"started_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "groups": args.groups,
                  "gates": identities, "script_sha256": SCRIPT_SHA, "data": data_identity,
                  "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": numpy.__version__,
                                  "pandas": pandas.__version__, "scipy": scipy.__version__, "sklearn": sklearn.__version__},
                  "folds": []}
    manifest["invocations"].append(invocation)
    definitions = run_definitions(config)
    context = mp.get_context("spawn")
    status = 0
    with context.Pool(args.workers, initializer=_init_worker) as pool:
        for group in args.groups:
            jobs = [(run_id, group, split.to_record(), vars(policy))
                    for run_id, policy, kind in definitions[group] for split in splits_for(kind, ranking)]
            print(f"{group}: {len(jobs)} folds", flush=True)
            for summary in pool.imap(run_fold, jobs):
                invocation["folds"].append(summary)
                manifest_path.write_text(json.dumps(manifest, indent=1, default=str))
                if "error" in summary:
                    print(f"FAILED {summary['run']} {summary['split']}: {summary['error']}", flush=True)
                    print(summary["traceback"], flush=True)
                    status = 1
                else:
                    print(f"{summary['run']} {summary['split']}: {summary['total_seconds']}s", flush=True)
            if status:
                print(f"stopping after failures in {group}", flush=True)
                break
    invocation["finished_at"] = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    manifest_path.write_text(json.dumps(manifest, indent=1, default=str))
    return status


if __name__ == "__main__":
    raise SystemExit(main())

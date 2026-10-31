#!/usr/bin/env python
"""WP4 stage 1: real-data fitting-boundary and provenance checks (no scores, no metrics).

On the real AIT alerts and interval labels this script:

1. Builds label-free split manifests: LOSO, forward-chaining eligibility from alert-timestamp
   extents, strict identifier-holdout groups, and seen/unseen identifier counts per LOSO fold.
2. Executes the fitting chain (``ComparisonPipeline.run_fitting_chain``: every mapping,
   reliability estimate, key height, learned training sample and learned model of every inner
   and outer fold, but no candidate scoring and no metric) for every declared split and input
   policy, verifies each executed trace against the split's intended exclusion sets, and checks
   that the fit sets observed in the trace equal the fit sets the protocol requires.
3. Recomputes, with an independent pandas implementation, the numerators, denominators,
   shrinkage, clipping and fallbacks of every mapping and height used by the LOSO folds (and by
   every identifier-holdout exclusion), and compares them with production.
4. Runs real-data adversarial and cache spot checks on fitted components: held-out label
   mutation, excluded-identifier label mutation, excluded-row deletion, and label replacement.
5. Reports label-free held-out mapping coverage and fallback counts, kept separate from any
   calibration-quality measure (none is computed here).

Held-out candidate scores and all performance metrics are never computed. Writes
docs/revision/wp4/real_data_fitting_check.json, docs/revision/wp4/split_manifests.json and
full per-chain traces under results/revision_cose_04000/wp4/fitting_chain_traces/.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import multiprocessing as mp
import os
import sys
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.features import RANKING_TIME_COLUMNS, InputPolicy, RankingFrame  # noqa: E402
from soc_alert_ranking.revision.labels import LabelStore, load_label_intervals, phase_order  # noqa: E402
from soc_alert_ranking.revision.native_scores import load_revised_alerts  # noqa: E402
from soc_alert_ranking.revision.pipeline import ComparisonPipeline, verify_fold_trace  # noqa: E402
from soc_alert_ranking.revision.splits import (  # noqa: E402
    OuterSplit, forward_chaining_splits, identifier_groups, identifier_holdout_splits, loso_splits, unseen_identifier_mask,
)

DATA = Path.home() / "soc_revision_data"
CACHE = DATA / "cache/ait_canonical_original_labels.pkl.gz"
PROVENANCE = DATA / "cache/ait_native_score_provenance.pkl.gz"
LABELS = DATA / "ait_alert/labels.csv"
TRACE_DIR = PROJECT_ROOT / "results/revision_cose_04000/wp4/fitting_chain_traces"
HASHED = [
    "src/soc_alert_ranking/revision/features.py", "src/soc_alert_ranking/revision/pipeline.py",
    "src/soc_alert_ranking/revision/splits.py", "src/soc_alert_ranking/revision/labels.py",
    "src/soc_alert_ranking/revision/families.py", "src/soc_alert_ranking/revision/native_scores.py",
    "src/soc_alert_ranking/revision/config.py", "configs/revision_wp2.yaml", "configs/severity_mapping.yaml",
    "scripts/revision/wp4_fitting_boundary_check.py",
]
ABLATION_POLICIES = {
    "calibration:global_class": InputPolicy(reliability="global_class"),
    "calibration:detector_only": InputPolicy(reliability="detector_only"),
    "calibration:native_key": InputPolicy(reliability="native_key"),
    "calibration:none": InputPolicy(reliability="none"),
    "uncertainty:constant_0.5": InputPolicy(uncertainty="constant_0.5"),
    "uncertainty:purity_only": InputPolicy(uncertainty="purity_only"),
    "uncertainty:precision_only": InputPolicy(uncertainty="precision_only"),
    "uncertainty:historical_combined": InputPolicy(uncertainty="ambiguity_aware"),
    "uncertainty:zero": InputPolicy(uncertainty="zero"),
    "context:asset_profile": InputPolicy(context="asset_profile"),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    return config, severity, ranking, intervals, store, identity


# ------------------------------------------------------------------ worker side
_STATE: dict[str, object] = {}


def _init_worker():
    config, severity, ranking, _, store, _ = load_everything()
    _STATE.update(config=config, ranking=ranking, store=store,
                  pipeline=ComparisonPipeline(ranking, store, severity, config))


def expected_fit_sets(split: OuterSplit) -> set[frozenset[str]]:
    training = frozenset(split.training)
    sets = {training} | {training - {g} for g in training}          # outer validation; outer learned training features
    for inner in training:
        inner_training = training - {inner}
        sets.add(inner_training)                                      # inner validation
        if split.learned_estimable:
            sets |= {inner_training - {g} for g in inner_training}    # inner learned training features
    return sets


def run_chain(job: tuple[str, dict, str, dict]) -> dict:
    policy_label, split_record, _, policy_fields = job
    pipeline: ComparisonPipeline = _STATE["pipeline"]
    ranking: RankingFrame = _STATE["ranking"]
    split = OuterSplit(**{**split_record, "training": tuple(split_record["training"]),
                          "excluded_key_ids": tuple(split_record["excluded_key_ids"])})
    policy = InputPolicy(**policy_fields)
    started = time.perf_counter()
    pipeline.builder.clear_cache()          # every chain fits from scratch, so its trace is complete on its own
    pipeline.builder.trace.clear()
    pipeline.builder.manifest.clear()
    pipeline.store.access_log.clear()
    try:
        result = pipeline.run_fitting_chain(split, policy)
    except Exception as error:  # a failed fit is recorded, never dropped
        return {"policy_label": policy_label, "split": split.name, "policy": policy.name, "error": repr(error),
                "traceback": traceback.format_exc(), "passed": False}
    verification = verify_fold_trace(result, ranking)
    observed = {frozenset(r["fit_set"]) for r in result.manifest}
    expected = expected_fit_sets(split)
    reads = [e for e in result.trace if e["event"] == "table_read"]
    fits = [e for e in result.trace if e["event"] == "fit"]
    samples = [e for e in result.trace if e["event"] == "learned_sample"]
    queues = [e for e in result.trace if e["event"] == "inner_queue"]
    roles = [r["role"] for r in result.manifest]
    summary = {
        "policy_label": policy_label, "split": split.name, "policy": policy.name, "held_out": split.held_out,
        "training": list(split.training), "excluded_identifiers": len(split.excluded_key_ids),
        "learned_estimable": split.learned_estimable,
        "trace_verification_passed": verification.passed, "violations": verification.violations,
        "fit_sets_expected": len(expected), "fit_sets_observed": len(observed),
        "fit_sets_match": observed == expected,
        "cached_feature_requests": sum(bool(r["cached"]) for r in result.manifest),
        "fit_sets_missing": sorted(sorted(s) for s in expected - observed)[:5],
        "fit_sets_unexpected": sorted(sorted(s) for s in observed - expected)[:5],
        "feature_requests": len(result.manifest),
        "feature_requests_by_role": {kind: sum(kind in r for r in roles)
                                     for kind in (":validation", ":training_features", ":outer_validation")},
        "table_reads": len(reads), "fits": {c: sum(e["component"] == c for e in fits) for c in ("mapping", "class_heights", "key_heights")},
        "table_reads_of_held_out": sum(e["scenario"] == split.held_out for e in reads),
        "learned_samples": len(samples),
        "learned_sample_rows": int(sum(sum(e["rows_by_scenario"].values()) for e in samples)),
        "excluded_identifier_rows_in_learned_samples": int(sum(e["excluded_key_rows_in_sample"] for e in samples)),
        "inner_queue_alerts_removed": int(sum(e["excluded_identifier_alerts_removed"] for e in queues)),
        "held_out_label_reads": sum(s == split.held_out for s, _ in result.label_access_log),
        "learner_fallbacks": sorted({d["fallback"] for d in result.learner_diagnostics if d.get("fallback")}),
        "learned_selection_fallbacks": (result.selections.get("selection_fallback", pd.Series(dtype=object)).dropna().unique().tolist()
                                        if not result.selections.empty else []),
        "outer_target_fallback_alerts": result.fit_records["outer_target_fallback_alerts"],
        "runtime_seconds": round(time.perf_counter() - started, 1),
    }
    summary["passed"] = bool(summary["trace_verification_passed"] and summary["fit_sets_match"]
                             and summary["table_reads_of_held_out"] == 0 and summary["held_out_label_reads"] == 0
                             and summary["excluded_identifier_rows_in_learned_samples"] == 0)
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"{policy_label.replace(':', '_')}__{split.name.replace(':', '_')}"
    with gzip.open(TRACE_DIR / f"{stem}.json.gz", "wt", encoding="utf-8") as handle:
        json.dump({"split": split.to_record(), "policy": policy.name, "summary": summary, "feature_requests": result.manifest,
                   "trace": result.trace, "learner_diagnostics": result.learner_diagnostics,
                   "label_access_log": result.label_access_log, "fit_records": result.fit_records,
                   "selections": result.selections.to_dict(orient="records")}, handle, default=str)
    return summary


# ------------------------------------------------------------------ independent arithmetic (parent)
def aggregate_counts(ranking: RankingFrame, store: LabelStore, phases: tuple[str, ...]) -> pd.DataFrame:
    parts = []
    for scenario in ranking.scenarios:
        rows = ranking.rows(scenario)
        labels = store.get(scenario, "wp4_independent_arithmetic_check")
        frame = pd.DataFrame({"detector": rows["detector"].astype(str).to_numpy(),
                              "native_key": rows["native_key"].astype(str).to_numpy(), "y": labels.y.astype(np.int64)})
        for p, phase in enumerate(phases):
            frame[phase] = labels.phase_membership[:, p].astype(np.int64)
        grouped = frame.groupby(["detector", "native_key"], sort=True).agg(n=("y", "size"), pos=("y", "sum"),
                                                                           **{p: (p, "sum") for p in phases})
        parts.append(grouped.reset_index().assign(scenario=scenario))
    return pd.concat(parts, ignore_index=True)


def independent_mapping(agg, fit_set, phases, settings) -> dict[tuple[str, str], str]:
    sub = agg[agg["scenario"].isin(list(fit_set))]
    if sub.empty:
        return {}
    g = sub.groupby(["detector", "native_key"])[["n", "pos", *phases]].sum()
    top = g[list(phases)].max(axis=1)
    top_phase = g[list(phases)].idxmax(axis=1)                        # first maximum in alphabetical phase order
    precision = g["pos"] / g["n"]
    purity = (top / g["pos"].where(g["pos"] > 0)).fillna(0.0)
    accepted = ((g["n"] >= settings.min_support) & (g["pos"] >= settings.min_positive)
                & (precision >= settings.min_precision) & (purity >= settings.min_phase_purity) & (g["pos"] > 0))
    return {key: (str(top_phase[key]) if accepted[key] else "unknown") for key in g.index}


def independent_fit(agg, fit_set, phases, settings, grouping):
    rows = []
    for j in sorted(fit_set):
        classes = independent_mapping(agg, set(fit_set) - {j}, phases, settings)
        part = agg[agg["scenario"] == j][["detector", "native_key", "n", "pos"]].copy()
        part["class"] = [classes.get(key, "unknown") for key in zip(part["detector"], part["native_key"])]
        rows.append(part)
    rows = pd.concat(rows, ignore_index=True)
    if grouping == "detector_class":
        cells = rows.groupby(["detector", "class"])[["n", "pos"]].sum()
    elif grouping == "global_class":
        cells = rows.assign(detector="__all__").groupby(["detector", "class"])[["n", "pos"]].sum()
    else:
        cells = rows.assign(**{"class": "all_classes"}).groupby(["detector", "class"])[["n", "pos"]].sum()
    detector_prior = rows.groupby("detector")[["n", "pos"]].sum()
    global_prior = (float(rows["pos"].sum()), float(rows["n"].sum()))
    out = {}
    for (detector, cls), cell in cells.iterrows():
        prior_pos, prior_n = ((detector_prior.loc[detector, "pos"], detector_prior.loc[detector, "n"])
                              if grouping == "detector_class" else global_prior)
        w = cell["n"] / (cell["n"] + settings.class_lambda)
        unclipped = w * cell["pos"] / cell["n"] + (1 - w) * prior_pos / prior_n
        out[(detector, cls)] = (float(cell["pos"]), float(cell["n"]), float(prior_pos), float(prior_n), unclipped,
                                min(max(unclipped, settings.height_min), settings.height_max))
    return out, detector_prior, global_prior


def check_arithmetic(pipeline, ranking, agg_all, fit_sets, phases, settings, excluded_names=frozenset(),
                     groupings=("detector_class",)) -> dict:
    mismatches, checked_cells, checked_keys = [], 0, 0
    agg = agg_all[[(d, k) not in excluded_names for d, k in zip(agg_all["detector"], agg_all["native_key"])]]
    names = [(str(d), str(k)) for d, k in zip(ranking.key_detector, ranking.key_name)]
    excluded_ids = ranking.key_ids_for(excluded_names)
    for fit_set in fit_sets:
        final = independent_mapping(agg, fit_set, phases, settings)
        for grouping in groupings:
            keys = pipeline.builder.key_features(fit_set, excluded_ids, grouping)
            reference, detector_prior, global_prior = independent_fit(agg, fit_set, phases, settings, grouping)
            table = keys.heights.table
            if len(table) != len(reference):
                mismatches.append(f"{sorted(fit_set)} {grouping}: {len(table)} cells vs {len(reference)}")
            for row in table.itertuples(index=False):
                expected = reference.get((row.detector, row._1))
                checked_cells += 1
                if expected is None or (row.positives, row.n, row.prior_positives, row.prior_n) != expected[:4] \
                        or abs(row.unclipped - expected[4]) > 1e-12 or abs(row.height - expected[5]) > 1e-12:
                    mismatches.append(f"{sorted(fit_set)} {grouping} cell {row.detector}/{row._1}")
            for k, key in enumerate(names):
                cls = final.get(key, "unknown")
                if keys.heights.grouping == "detector_class":
                    cell = (key[0], cls)
                elif keys.heights.grouping == "global_class":
                    cell = ("__all__", cls)
                else:
                    cell = (key[0], "all_classes")
                if cell in reference:
                    height, code = reference[cell][5], 0
                elif grouping == "detector_class" and key[0] in detector_prior.index:
                    pos, n = detector_prior.loc[key[0], "pos"], detector_prior.loc[key[0], "n"]
                    height, code = min(max(pos / n, settings.height_min), settings.height_max), 1
                else:
                    height, code = min(max(global_prior[0] / global_prior[1], settings.height_min), settings.height_max), 2
                checked_keys += 1
                if pipeline.builder.class_names[keys.classes[k]] != cls or abs(keys.height[k] - height) > 1e-12 \
                        or int(keys.height_fallback[k]) != code:
                    mismatches.append(f"{sorted(fit_set)} {grouping} key {key}")
        # key-level reliability (identifier granularity)
        keys = pipeline.builder.key_features(fit_set, excluded_ids, "native_key")
        sub = agg[agg["scenario"].isin(list(fit_set))]
        per_key = sub.groupby(["detector", "native_key"])[["n", "pos"]].sum()
        det = sub.groupby("detector")[["n", "pos"]].sum()
        total = (float(sub["pos"].sum()), float(sub["n"].sum()))
        for k, key in enumerate(names):
            if key in per_key.index and per_key.loc[key, "n"] > 0:
                n, pos = per_key.loc[key, "n"], per_key.loc[key, "pos"]
                w = n / (n + settings.key_lambda)
                height = w * pos / n + (1 - w) * det.loc[key[0], "pos"] / det.loc[key[0], "n"]
                height, code = min(max(height, settings.height_min), settings.height_max), 0
            elif key[0] in det.index:
                height, code = min(max(det.loc[key[0], "pos"] / det.loc[key[0], "n"], settings.height_min), settings.height_max), 1
            else:
                height, code = min(max(total[0] / total[1], settings.height_min), settings.height_max), 2
            checked_keys += 1
            if abs(keys.key_heights.heights[k] - height) > 1e-12 or int(keys.key_heights.fallback[k]) != code:
                mismatches.append(f"{sorted(fit_set)} key height {key}")
    return {"fit_sets": len(fit_sets), "cells_checked": checked_cells, "keys_checked": checked_keys,
            "mismatches": mismatches[:20], "mismatch_count": len(mismatches), "passed": not mismatches}


# ------------------------------------------------------------------ adversarial spot checks (parent)
def key_signature(pipeline, fit_set, excluded_names=frozenset(), reliability="detector_class"):
    ranking = pipeline.ranking
    keys = pipeline.builder.key_features(fit_set, ranking.key_ids_for(excluded_names), reliability)
    per_key = {(str(d), str(n)): (int(keys.classes[k]), float(keys.height[k]), int(keys.height_fallback[k]),
                                  float(keys.key_heights.heights[k]), int(keys.key_heights.fallback[k]),
                                  tuple(float(keys.u_by_policy[p][k]) for p in sorted(keys.u_by_policy)))
               for k, (d, n) in enumerate(zip(ranking.key_detector, ranking.key_name))}
    if keys.heights is None:
        return per_key, None, None, None
    return per_key, keys.heights.table.to_dict(orient="records"), keys.heights.detector_prior, keys.heights.global_prior


def randomize_rows(store, scenario, mask, rng):
    labels = store.labels[scenario]
    m = int(mask.sum())
    phases = labels.phase_membership.copy()
    phases[mask] = rng.random((m, phases.shape[1])) < 0.3
    y = labels.y.copy()
    y[mask] = phases[mask].any(axis=1)
    s_star = labels.s_star.copy()
    s_star[mask] = np.where(y[mask], rng.uniform(2.0, 9.5, m), 0.0)
    critical = labels.critical_membership.copy()
    critical[mask] = rng.random((m, critical.shape[1])) < 0.1
    store.replace(scenario, labels.replace_arrays(y=y, s_star=s_star, z=y & (s_star >= labels.tau), r=np.where(y, s_star, 0.0),
                                                  phase_membership=phases, critical_membership=critical))


def adversarial_checks(config, severity, ranking, intervals, store, groups) -> dict:
    rng = np.random.default_rng(42)
    checks = {}
    scenarios = list(ranking.scenarios)
    held_out = scenarios[0]
    training = frozenset(scenarios[1:])
    fit_sets = [training, training - {scenarios[1]}, training - {scenarios[1], scenarios[2]}]

    pipeline = ComparisonPipeline(ranking, store, severity, config)
    reference = {tuple(sorted(fs)): key_signature(pipeline, fs) for fs in fit_sets}
    original = store.labels[held_out]
    randomize_rows(store, held_out, np.ones(len(original.y), dtype=bool), rng)
    pipeline.builder.clear_cache()
    after = {tuple(sorted(fs)): key_signature(pipeline, fs) for fs in fit_sets}
    store.replace(held_out, original)
    checks["held_out_label_mutation_leaves_fits_unchanged"] = reference == after

    original = store.labels[scenarios[1]]
    randomize_rows(store, scenarios[1], np.ones(len(original.y), dtype=bool), rng)
    pipeline.builder.clear_cache()
    checks["sensitivity_training_label_mutation_changes_fits"] = key_signature(pipeline, training) != reference[tuple(sorted(training))]
    store.replace(scenarios[1], original)
    pipeline.builder.clear_cache()

    # excluded identifiers: the group with the most training alerts
    alerts_per_group = {g: int(np.isin(ranking.frame.loc[ranking.frame["scenario"].isin(training), "key_id"],
                                       groups.loc[groups["group"] == g, "key_id"]).sum()) for g in range(5)}
    group = max(alerts_per_group, key=alerts_per_group.get)
    names = frozenset((str(d), str(k)) for d, k in groups.loc[groups["group"] == group, ["detector", "native_key"]].itertuples(index=False))
    for grouping in ("detector_class", "native_key"):
        pipeline = ComparisonPipeline(ranking, store, severity, config)
        reference = {tuple(sorted(fs)): key_signature(pipeline, fs, names, grouping) for fs in fit_sets}
        saved = {s: store.labels[s] for s in training}
        for s in training:
            rows = ranking.rows(s)
            mask = np.array([(d, k) in names for d, k in zip(rows["detector"], rows["native_key"])])
            randomize_rows(store, s, mask, rng)
        after = {tuple(sorted(fs)): key_signature(pipeline, fs, names, grouping) for fs in fit_sets}
        for s, labels in saved.items():
            store.replace(s, labels)
        checks[f"excluded_identifier_label_mutation_leaves_fits_unchanged[{grouping}]"] = reference == after

    pipeline = ComparisonPipeline(ranking, store, severity, config)
    reference = {tuple(sorted(fs)): key_signature(pipeline, fs, names) for fs in fit_sets}
    frame = ranking.frame
    keep = ~(frame["scenario"].isin(training) & [(d, k) in names for d, k in zip(frame["detector"], frame["native_key"])])
    reduced = RankingFrame.from_alerts(frame.loc[keep, list(RANKING_TIME_COLUMNS)].reset_index(drop=True))
    reduced_store = LabelStore.from_alerts(reduced.frame, intervals, phase_order(severity), config.tau)
    reduced_pipeline = ComparisonPipeline(reduced, reduced_store, severity, config)
    deleted = {tuple(sorted(fs)): key_signature(reduced_pipeline, fs, names) for fs in fit_sets}
    same = True
    for fs, (per_key, cells, det, glob) in reference.items():
        d_key, d_cells, d_det, d_glob = deleted[fs]
        same &= {k: v for k, v in per_key.items() if k in d_key} == {k: d_key[k] for k in per_key if k in d_key}
        same &= (cells, det, glob) == (d_cells, d_det, d_glob)
    checks["excluded_identifier_row_deletion_leaves_fits_unchanged"] = bool(same)
    checks["excluded_identifier_rows_deleted"] = int((~keep).sum())
    checks["excluded_identifier_group"] = {"group": int(group), "identifiers": len(names), "training_alerts": alerts_per_group[group]}

    pipeline = ComparisonPipeline(ranking, store, severity, config)
    first = pipeline.builder.key_features(training)
    unrelated = pipeline.builder.key_features(training - {scenarios[1]})
    labels = store.labels[scenarios[1]]
    store.replace(scenarios[1], labels.replace_arrays())                  # new version, identical content
    checks["cache_label_version_invalidates_dependent_fit"] = pipeline.builder.key_features(training) is not first
    checks["cache_label_version_keeps_independent_fit"] = pipeline.builder.key_features(training - {scenarios[1]}) is unrelated
    checks["cache_exclusion_set_is_a_key"] = pipeline.builder.key_features(training, ranking.key_ids_for(names)) is not first
    checks["cache_reliability_is_a_key"] = pipeline.builder.key_features(training, (), "global_class") is not first
    checks["passed"] = all(v for k, v in checks.items() if isinstance(v, bool))
    return checks


# ------------------------------------------------------------------ main
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--omp-threads", type=int, default=3)
    args = parser.parse_args()
    started = time.perf_counter()
    os.environ["OMP_NUM_THREADS"] = str(args.omp_threads)

    config, severity, ranking, intervals, store, identity = load_everything()
    phases = phase_order(severity)
    settings = config.settings

    # 1. split manifests (label-free)
    loso = loso_splits(ranking)
    forward, forward_table = forward_chaining_splits(ranking)
    groups = identifier_groups(ranking)
    holdout = identifier_holdout_splits(ranking)
    frame = ranking.frame
    group_table = []
    for g in range(5):
        key_ids = groups.loc[groups["group"] == g, "key_id"].to_numpy()
        in_group = np.isin(frame["key_id"].to_numpy(), key_ids)
        group_table.append({"group": g, "identifiers": sorted(groups.loc[groups["group"] == g, "identifier"]),
                            "keys": int(len(key_ids)),
                            "keys_by_detector": groups.loc[groups["group"] == g, "detector"].value_counts().to_dict(),
                            "alerts_by_scenario": {s: int(in_group[ranking.scenario_rows[s]].sum()) for s in ranking.scenarios}})
    near_equivalent = [("suricata:20151", "suricata:20161"), ("suricata:20152", "suricata:20162"),
                       ("suricata:2016149", "suricata:2016150")]
    group_of = dict(zip(groups["identifier"], groups["group"]))
    seen_unseen = []
    for split in loso:
        mask = unseen_identifier_mask(ranking, split.held_out, split.training)
        rows = ranking.rows(split.held_out)
        seen_unseen.append({"held_out": split.held_out, "held_out_keys": int(rows["key_id"].nunique()),
                            "unseen_keys": int(rows.loc[mask, "key_id"].nunique()), "unseen_alerts": int(mask.sum()),
                            "unseen_alert_share": float(mask.mean()),
                            "unseen_alerts_by_detector": rows.loc[mask, "detector"].value_counts().to_dict(),
                            "unseen_identifiers": sorted(set(f"{d}:{str(k).split(':')[1]}" for d, k in
                                                             zip(rows.loc[mask, "detector"], rows.loc[mask, "native_key"])))})
    manifests = {
        "note": "Label-free split manifests computed from alert timestamps, detectors and native keys only.",
        "cache_sha256": identity["canonical_cache_sha256"], "provenance_cache_sha256": identity["provenance_cache_sha256"],
        "loso": [s.to_record() for s in loso],
        "forward_chaining_eligibility": forward_table.assign(
            start=forward_table["start"].astype(float), end=forward_table["end"].astype(float)).to_dict(orient="records"),
        "forward_chaining_splits": [s.to_record() for s in forward],
        "identifier_groups": {"rule": "SHA-256(detector:identifier) mod 5", "groups": group_table,
                              "near_equivalent_identifier_pairs": [{"pair": list(p), "groups": [int(group_of.get(i, -1)) for i in p]}
                                                                   for p in near_equivalent]},
        "identifier_holdout_splits": [{"name": s.name, "held_out": s.held_out, "excluded_keys": len(s.excluded_key_ids)} for s in holdout],
        "seen_unseen_by_loso_fold": seen_unseen,
    }
    out_dir = PROJECT_ROOT / "docs/revision/wp4"
    (out_dir / "split_manifests.json").write_text(json.dumps(manifests, indent=2, default=str), encoding="utf-8")
    print(f"split manifests written ({time.perf_counter() - started:.0f}s); forward eligible: {[s.name for s in forward]}", flush=True)

    # 3. independent arithmetic over every fit set the LOSO folds use
    agg = aggregate_counts(ranking, store, phases)
    scenarios = list(ranking.scenarios)
    loso_fit_sets = sorted({fs for split in loso for fs in expected_fit_sets(split)}, key=lambda s: (len(s), sorted(s)))
    pipeline = ComparisonPipeline(ranking, store, severity, config)
    arithmetic = {"loso_all_fit_sets": check_arithmetic(pipeline, ranking, agg, loso_fit_sets, phases, settings)}
    outer_sets = [frozenset(s.training) for s in loso]
    arithmetic["loso_outer_fit_sets_all_groupings"] = check_arithmetic(
        pipeline, ranking, agg, outer_sets, phases, settings, groupings=("detector_class", "global_class", "detector_only"))
    for g in range(5):
        names = frozenset((str(d), str(k)) for d, k in groups.loc[groups["group"] == g, ["detector", "native_key"]].itertuples(index=False))
        arithmetic[f"holdout_group_{g}_all_fit_sets"] = check_arithmetic(pipeline, ranking, agg, loso_fit_sets, phases, settings, names)
    forward_sets = sorted({fs for split in forward for fs in expected_fit_sets(split) if fs}, key=lambda s: (len(s), sorted(s)))
    if forward_sets:
        arithmetic["forward_chaining_fit_sets"] = check_arithmetic(pipeline, ranking, agg, forward_sets, phases, settings)
    print(f"independent arithmetic: {[(k, v['passed'], v['fit_sets']) for k, v in arithmetic.items()]} "
          f"({time.perf_counter() - started:.0f}s)", flush=True)

    # 5. label-free held-out mapping coverage (production features, held-out labels locked)
    coverage = []
    for split in loso:
        reads_before = len(store.access_log)
        with store.locked([split.held_out]):
            features = pipeline.builder.alert_features(split.held_out, split.training, config.primary_policy,
                                                       role=f"{split.name}:coverage_report")
        reads_during = store.access_log[reads_before:]
        rows = ranking.rows(split.held_out)
        coverage.append({"held_out": split.held_out, "alerts": int(len(rows)), "mapped_share": float(features.mapped.mean()),
                         "mapped_share_by_detector": {d: float(features.mapped[(rows["detector"] == d).to_numpy()].mean())
                                                      for d in sorted(rows["detector"].unique())},
                         "class_height_fallback_alerts": {"detector_prior": int((features.h_fallback == 1).sum()),
                                                          "global_prior": int((features.h_fallback == 2).sum())},
                         "key_height_fallback_alerts": {"detector_prior": int((features.h_key_fallback == 1).sum()),
                                                        "global_prior": int((features.h_key_fallback == 2).sum())},
                         "held_out_label_reads": sum(s == split.held_out for s, _ in reads_during)})

    # 4. adversarial and cache spot checks on real data
    adversarial = adversarial_checks(config, severity, ranking, intervals, store, groups)
    print(f"adversarial: {adversarial} ({time.perf_counter() - started:.0f}s)", flush=True)
    del pipeline, agg

    # 2. fitting chains
    jobs = []
    for split in loso:
        jobs.append(("primary", split.to_record(), split.name, vars(config.primary_policy)))
        jobs.append(("secondary", split.to_record(), split.name, vars(config.secondary_policy)))
    for label, policy in ABLATION_POLICIES.items():
        for split in loso:
            jobs.append((label, split.to_record(), split.name, vars(policy)))
    for split in holdout:
        jobs.append(("holdout:primary", split.to_record(), split.name, vars(config.primary_policy)))
    for split in forward:
        jobs.append(("forward:primary", split.to_record(), split.name, vars(config.primary_policy)))
    context = mp.get_context("spawn")
    chains = []
    with context.Pool(args.workers, initializer=_init_worker) as pool:
        for i, summary in enumerate(pool.imap_unordered(run_chain, jobs)):
            chains.append(summary)
            print(f"[{i + 1}/{len(jobs)}] {summary['policy_label']} {summary['split']} passed={summary['passed']} "
                  f"{summary.get('runtime_seconds')}s", flush=True)
    chains.sort(key=lambda s: (s["policy_label"], s["split"]))

    record = {
        "work_package": "WP4 stage 1 real-data fitting-boundary check",
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "scope": "Fitting chains, independent arithmetic, split manifests and adversarial checks on real AIT data. "
                 "No candidate was scored and no performance metric was computed.",
        "inputs": {"canonical_cache_sha256": identity["canonical_cache_sha256"],
                   "provenance_cache_sha256": identity["provenance_cache_sha256"],
                   "labels_csv_md5_verified": True, "alerts": int(len(ranking.frame)), "keys": int(ranking.n_keys),
                   "intervals": int(len(intervals)), "critical_intervals": int(intervals["critical"].sum())},
        "code_sha256": {path: sha256_file(PROJECT_ROOT / path) for path in HASHED},
        "fitting_chains": {"total": len(chains), "passed": sum(c["passed"] for c in chains),
                           "failed": [c for c in chains if not c["passed"]],
                           "by_policy_label": {label: {"chains": sum(c["policy_label"] == label for c in chains),
                                                       "passed": sum(c["passed"] for c in chains if c["policy_label"] == label)}
                                               for label in sorted({c["policy_label"] for c in chains})},
                           "summaries": chains},
        "independent_arithmetic": arithmetic,
        "adversarial_and_cache_checks": adversarial,
        "held_out_mapping_coverage_label_free": coverage,
        "calibration_quality": "not computed in stage 1 (requires held-out labels; reported in stage 2, separately from mapping coverage)",
        "runtime_seconds": round(time.perf_counter() - started, 1),
    }
    record["passed"] = bool(chains and all(c["passed"] for c in chains) and all(v["passed"] for v in arithmetic.values())
                            and adversarial["passed"] and all(c["held_out_label_reads"] == 0 for c in coverage))
    (out_dir / "real_data_fitting_check.json").write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"passed": record["passed"], "chains": record["fitting_chains"]["total"],
                      "chains_passed": record["fitting_chains"]["passed"], "runtime_seconds": record["runtime_seconds"]}))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

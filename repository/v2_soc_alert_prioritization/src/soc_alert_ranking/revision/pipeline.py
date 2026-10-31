"""Nested comparison pipeline with traced fitting isolation (protocol v1.1 §6; WP4).

For an outer split with held-out scenario v, training scenarios S and excluded identifiers G:

1. v's labels are locked for the whole fold.
2. For each inner validation scenario i in S (inner training set T = S minus {i}), i's labels
   are locked while its features are built, learned candidates are trained and every tuned
   candidate is scored. Learned candidates train on rows of T whose features come from fit
   sets T minus {g}. Only then are i's labels read for selection metrics.
3. Alerts with identifiers in G are removed from every fitting table, every learned training
   sample and every inner validation queue. The outer held-out queue keeps all alerts.
4. Each tuned family is selected by the primary rule and, separately, by the secondary rule.
5. v is scored by every untuned and every selected candidate with features fitted on S.
   Outer evaluation is a separate step.

``run_fitting_chain`` executes steps 1-3 and the outer feature and learned-model fits without
any inner evaluation or scoring, for verifying traces before comparative runs.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from soc_alert_ranking.mappings.severity import SeverityMapping
from soc_alert_ranking.revision.config import ComparisonConfig
from soc_alert_ranking.revision.evaluation import selection_metrics, top_k_order
from soc_alert_ranking.revision.families import (
    LEARNED_FAMILIES, Candidate, FittedLearner, TrainingSample, draw_training_rows, equalizing_weights,
    fit_learner, score_candidate,
)
from soc_alert_ranking.revision.features import FeatureBuilder, InputPolicy, KeyTableProvider, RankingFrame
from soc_alert_ranking.revision.labels import LabelStore, phase_order
from soc_alert_ranking.revision.metrics import restrict_queue
from soc_alert_ranking.revision.splits import OuterSplit
from soc_alert_ranking.revision.tuning import PRIMARY, SECONDARY, select_candidate


@dataclass
class OuterFoldResult:
    split: OuterSplit
    policy: str
    inner_metrics: pd.DataFrame
    selections: pd.DataFrame
    outer_candidates: list[Candidate]
    outer_alert_ids: np.ndarray
    outer_scores: dict[str, np.ndarray]
    fit_records: dict[str, object]
    learner_diagnostics: list[dict[str, object]]
    manifest: list[dict[str, object]]
    trace: list[dict[str, object]]
    runtime_seconds: dict[str, float]
    label_access_log: list[tuple[str, str]] = field(default_factory=list)

    @property
    def held_out(self) -> str:
        return self.split.held_out

    @property
    def training_scenarios(self) -> list[str]:
        return list(self.split.training)

    def selected(self, rule: str) -> dict[str, str]:
        part = self.selections[self.selections["rule"] == rule]
        return dict(zip(part["family"], part["selected_candidate"]))


def simplest_candidate(candidates: list[Candidate]) -> Candidate:
    """Fewest nonzero parameters, then declared grid order (the protocol's simplicity order)."""

    return min(candidates, key=lambda c: (c.n_nonzero, c.grid_index))


class ComparisonPipeline:
    def __init__(self, ranking: RankingFrame, store: LabelStore, severity: SeverityMapping, config: ComparisonConfig):
        self.ranking = ranking
        self.store = store
        self.severity = severity
        self.config = config
        self.phases = phase_order(severity)
        self.provider = KeyTableProvider(ranking, store, self.phases)
        self.builder = FeatureBuilder(ranking, self.provider, severity, config.settings)
        self.candidates = {spec.name: list(spec.candidates) for spec in config.families.values()}

    # ------------------------------------------------------------------ helpers
    def _tuned_families(self, learned_estimable: bool = True) -> list[str]:
        return [name for name, spec in self.config.families.items()
                if spec.tuned and (learned_estimable or not spec.learned)]

    def _untuned_candidates(self) -> list[Candidate]:
        return [c for name, spec in self.config.families.items() if not spec.tuned for c in spec.candidates]

    def training_sample(self, fit_scenarios: list[str], policy: InputPolicy, role: str,
                        excluded_key_ids: tuple[int, ...] = ()) -> TrainingSample:
        """Learned-ranker training rows; features of g come from fit set (fit_scenarios minus g)."""

        excluded = np.array(sorted(excluded_key_ids), dtype=np.int64)
        keep = {s: ~np.isin(self.ranking.rows(s)["key_id"].to_numpy(), excluded) for s in fit_scenarios}
        ids = {s: self.ranking.rows(s)["alert_id"].to_numpy()[keep[s]] for s in fit_scenarios}
        hashes = {s: self.ranking.rows(s)["hash_key"].to_numpy(np.uint64)[keep[s]] for s in fit_scenarios}
        positions = draw_training_rows(ids, hashes, self.config.max_training_alerts, self.config.seed)
        X, y, r, scen, alert_ids = [], [], [], [], []
        for g in sorted(fit_scenarios):
            chosen = np.flatnonzero(keep[g])[positions[g]]
            if not len(chosen):
                continue
            features = self.builder.alert_features(g, set(fit_scenarios) - {g}, policy, role=f"{role}:training_features",
                                                   excluded_key_ids=excluded_key_ids)
            labels = self.store.get(g, purpose=f"{role}:learned_training_targets")
            X.append(np.column_stack([features.c[chosen], features.u[chosen], features.h[chosen]]))
            y.append(labels.y[chosen])
            r.append(labels.r[chosen])
            scen.append(np.full(len(chosen), g))
            alert_ids.append(features.alert_ids[chosen])
        scenarios = np.concatenate(scen)
        sample = TrainingSample(
            X=np.concatenate(X), y=np.concatenate(y), r=np.concatenate(r), weights=equalizing_weights(scenarios),
            scenarios=scenarios, alert_ids=np.concatenate(alert_ids),
            sampled_from=int(sum(len(v) for v in ids.values())),
        )
        key_of = dict(zip(self.ranking.frame["alert_id"], self.ranking.frame["key_id"]))
        self.builder.trace.append({
            "event": "learned_sample", "role": role, "fit_scenarios": sorted(fit_scenarios),
            "rows_by_scenario": {s: int((scenarios == s).sum()) for s in sorted(set(scenarios))},
            "excluded_key_rows_in_sample": int(np.isin([key_of[a] for a in sample.alert_ids], excluded).sum()),
            "standardization_scope": sorted(set(scenarios)),
        })
        return sample

    def _fit_learners(self, candidates: list[Candidate], fit_scenarios: list[str], policy: InputPolicy,
                      role: str, diagnostics: list[dict[str, object]], excluded_key_ids: tuple[int, ...]) -> dict[str, FittedLearner]:
        learned = [c for c in candidates if c.family in LEARNED_FAMILIES]
        if not learned:
            return {}
        sample = self.training_sample(fit_scenarios, policy, role, excluded_key_ids)
        fitted = {}
        for candidate in learned:
            learner = fit_learner(candidate, sample, self.config.seed, self.config.learned_fixed, policy.height_domain_max)
            fitted[candidate.candidate_id] = learner
            diagnostics.append({"role": role, "candidate_id": candidate.candidate_id,
                                "training_scenarios": sorted(fit_scenarios), "fallback": learner.fallback,
                                "sampled_rows": len(sample.y), "population_rows": sample.sampled_from,
                                **learner.diagnostics})
        return fitted

    def _inner_queue_mask(self, scenario: str, excluded_key_ids: tuple[int, ...]) -> np.ndarray:
        return ~np.isin(self.ranking.rows(scenario)["key_id"].to_numpy(), np.array(sorted(excluded_key_ids), dtype=np.int64))

    # ------------------------------------------------------------------ fold
    def run_outer_fold(self, split: OuterSplit | str, policy: InputPolicy, evaluate_inner: bool = True) -> OuterFoldResult:
        if isinstance(split, str):
            split = OuterSplit(f"loso:{split}", split, tuple(s for s in self.ranking.scenarios if s != split))
        if split.held_out not in self.ranking.scenarios or split.held_out in split.training:
            raise ValueError("invalid outer split")
        training = list(split.training)
        excluded = tuple(split.excluded_key_ids)
        tuned_candidates = [c for name in self._tuned_families(split.learned_estimable) for c in self.candidates[name]]
        runtime: dict[str, float] = defaultdict(float)
        learner_diagnostics: list[dict[str, object]] = []
        manifest_start, trace_start, access_start = len(self.builder.manifest), len(self.builder.trace), len(self.store.access_log)
        inner_rows = []
        self.builder.trace.append({"event": "fold_start", "split": split.name, "held_out": split.held_out,
                                   "training": training, "excluded_keys": len(excluded), "policy": policy.name})

        with self.store.locked([split.held_out]):
            for inner_scenario in training:
                inner_training = [s for s in training if s != inner_scenario]
                role = f"{split.name}|inner={inner_scenario}"
                orders: dict[str, np.ndarray] = {}
                with self.store.locked([inner_scenario]):
                    started = time.perf_counter()
                    features = self.builder.alert_features(inner_scenario, inner_training, policy, role=f"{role}:validation",
                                                           excluded_key_ids=excluded)
                    mask = self._inner_queue_mask(inner_scenario, excluded)
                    runtime["features"] += time.perf_counter() - started
                    started = time.perf_counter()
                    learners = self._fit_learners(tuned_candidates, inner_training, policy, role, learner_diagnostics, excluded)
                    runtime["learned_fit"] += time.perf_counter() - started
                    if evaluate_inner:
                        for candidate in tuned_candidates:
                            started = time.perf_counter()
                            scores = score_candidate(candidate, features, learners.get(candidate.candidate_id))[mask]
                            orders[candidate.candidate_id] = top_k_order(scores, features.timestamp[mask],
                                                                         features.hash_key[mask], self.config.k)
                            runtime[f"score:{candidate.family}"] += time.perf_counter() - started
                self.builder.trace.append({"event": "inner_queue", "role": role, "scenario": inner_scenario,
                                           "alerts": int(len(mask)), "kept": int(mask.sum()),
                                           "excluded_identifier_alerts_removed": int((~mask).sum())})
                if not evaluate_inner:
                    continue
                labels = restrict_queue(self.store.get(inner_scenario, purpose=f"{role}:inner_evaluation"), mask)
                for candidate in tuned_candidates:
                    metrics = selection_metrics(orders[candidate.candidate_id], labels, self.config.k)
                    inner_rows.append({
                        "split": split.name, "outer_held_out": split.held_out, "policy": policy.name,
                        "inner_scenario": inner_scenario, **candidate.to_record(),
                        "coverage": metrics.coverage, "coverage_all_defined": metrics.coverage_all_defined,
                        "fp": metrics.fp, "ndcg": metrics.ndcg, "covered_intervals": metrics.covered_intervals,
                        "eligible_intervals": metrics.eligible_intervals, "defined_intervals": metrics.defined_intervals,
                        "queue_length": metrics.queue_length, "queue_shorter_than_k": metrics.queue_shorter_than_k,
                        "multi_interval_alerts_in_top_k": metrics.multi_interval_alerts_in_top_k,
                    })
            inner = pd.DataFrame(inner_rows)

            selections = []
            if evaluate_inner:
                for family in self._tuned_families(split.learned_estimable):
                    part = inner[inner["family"] == family]
                    for rule in (PRIMARY, SECONDARY):
                        selections.append(select_candidate(part, rule, self.config.tolerance).to_record())
            fallback_candidates = []
            for name, spec in self.config.families.items():
                if spec.learned and not split.learned_estimable:
                    simplest = simplest_candidate(self.candidates[name])
                    fallback_candidates.append(simplest)
                    for rule in (PRIMARY, SECONDARY):
                        selections.append({"rule": rule, "family": name, "selected_candidate": simplest.candidate_id,
                                           "selection_fallback": "inner_fit_failure_simplest_grid_point",
                                           "not_estimable_reason": split.note})
            selections = pd.DataFrame(selections)

            by_id = {c.candidate_id: c for c in tuned_candidates + fallback_candidates}
            chosen_ids = sorted({cid for cid in selections.get("selected_candidate", pd.Series(dtype=object)).dropna()})
            outer_candidates = self._untuned_candidates() + [by_id[cid] for cid in chosen_ids]
            if not evaluate_inner:
                outer_candidates = (self._untuned_candidates() + fallback_candidates
                                    + [c for c in tuned_candidates if c.family in LEARNED_FAMILIES])
            role = split.name
            started = time.perf_counter()
            outer_features = self.builder.alert_features(split.held_out, training, policy, role=f"{role}:outer_validation",
                                                         excluded_key_ids=excluded)
            outer_learners = self._fit_learners(outer_candidates, training, policy, role, learner_diagnostics, excluded)
            outer_scores = {}
            if evaluate_inner:
                outer_scores = {
                    candidate.candidate_id: score_candidate(candidate, outer_features, outer_learners.get(candidate.candidate_id))
                    for candidate in outer_candidates
                }
            runtime["outer"] += time.perf_counter() - started
            fit_records = self._fit_records(training, outer_features, policy, excluded)

        return OuterFoldResult(
            split=split, policy=policy.name, inner_metrics=inner, selections=selections, outer_candidates=outer_candidates,
            outer_alert_ids=outer_features.alert_ids, outer_scores=outer_scores, fit_records=fit_records,
            learner_diagnostics=learner_diagnostics, manifest=self.builder.manifest[manifest_start:],
            trace=self.builder.trace[trace_start:], runtime_seconds=dict(runtime),
            label_access_log=self.store.access_log[access_start:],
        )

    def run_fitting_chain(self, split: OuterSplit, policy: InputPolicy) -> OuterFoldResult:
        return self.run_outer_fold(split, policy, evaluate_inner=False)

    def _fit_records(self, training: list[str], outer_features, policy: InputPolicy, excluded: tuple[int, ...]) -> dict[str, object]:
        keys = self.builder.key_features(training, excluded, policy.reliability)
        mapping = keys.mapping
        per_key = pd.DataFrame({
            "detector": self.ranking.key_detector, "native_key": self.ranking.key_name,
            "support": mapping.support, "positives": mapping.positives, "precision": mapping.precision,
            "purity": mapping.purity, "accepted": mapping.accepted,
            "class": [self.builder.class_names[c] for c in keys.classes],
            "severity": keys.severity, "u": keys.u_by_policy[policy.uncertainty],
            "height": keys.height, "height_fallback": keys.height_fallback,
            "key_height": keys.key_heights.heights, "key_height_fallback": keys.key_heights.fallback,
            "key_n": keys.key_heights.n, "key_positives": keys.key_heights.positives,
            "key_height_unclipped": keys.key_heights.unclipped, "excluded": np.isin(np.arange(self.ranking.n_keys), excluded),
        })
        return {
            "fit_set": sorted(training),
            "reliability": policy.reliability,
            "per_key": per_key.to_dict(orient="records"),
            "class_heights": keys.heights.table.to_dict(orient="records") if keys.heights is not None else [],
            "detector_prior": ({d: {"positives": p, "n": n} for d, (p, n) in keys.heights.detector_prior.items()}
                               if keys.heights is not None else {}),
            "global_prior": ({"positives": keys.heights.global_prior[0], "n": keys.heights.global_prior[1]}
                             if keys.heights is not None else {}),
            "outer_target_fallback_alerts": {
                "class_height_detector_prior": int((outer_features.h_fallback == 1).sum()),
                "class_height_global_prior": int((outer_features.h_fallback == 2).sum()),
                "key_height_detector_prior": int((outer_features.h_key_fallback == 1).sum()),
                "key_height_global_prior": int((outer_features.h_key_fallback == 2).sum()),
                "unmapped": int((~outer_features.mapped).sum()),
                "excluded_identifier_alerts": int(outer_features.excluded_identifier.sum()),
                "alerts": int(len(outer_features)),
            },
        }


# ------------------------------------------------------------------ trace verification

@dataclass
class TraceVerification:
    split: str
    policy: str
    checks: dict[str, bool]
    violations: list[str]

    @property
    def passed(self) -> bool:
        return not self.violations and all(self.checks.values())


def verify_fold_trace(result: OuterFoldResult, ranking: RankingFrame) -> TraceVerification:
    """Check the executed trace of one fold against the intended exclusion sets."""

    split = result.split
    held_out, training, excluded = split.held_out, set(split.training), set(split.excluded_key_ids)
    violations: list[str] = []

    def violate(message: str) -> None:
        if len(violations) < 50:
            violations.append(message)

    for request in result.manifest:
        target, fit_set = request["target"], set(request["fit_set"])
        role = request["role"]
        if target in fit_set:
            violate(f"{role}: target in own fit set")
        if held_out in fit_set or held_out in request["mapping_fit_set"] or held_out in request["key_height_fit_set"]:
            violate(f"{role}: held-out scenario used in fitting")
        if set(request["mapping_fit_set"]) != fit_set or set(request["key_height_fit_set"]) != fit_set:
            violate(f"{role}: mapping or key-height fit set differs from feature fit set")
        if set(request["excluded_keys"]) != excluded:
            violate(f"{role}: excluded identifiers differ from split")
        for source in request["height_row_sources"]:
            if source["rows_from"] not in fit_set or set(source["mapped_with"]) != fit_set - {source["rows_from"]}:
                violate(f"{role}: height rows from {source['rows_from']} mapped with {source['mapped_with']}")
            if target in source["mapped_with"] or held_out in source["mapped_with"]:
                violate(f"{role}: target or held-out scenario in a mapping used for its reliability")
        if not fit_set <= training:
            violate(f"{role}: fit set outside outer training scenarios")
        if ":validation" in role:
            inner = role.split("|inner=")[1].split(":")[0]
            if target != inner or fit_set != training - {inner}:
                violate(f"{role}: inner validation fit set is not training minus the inner scenario")
        if ":training_features" in role:
            base = role.split(":training_features")[0]
            fit_scenarios = training - {base.split("|inner=")[1]} if "|inner=" in base else training
            if fit_set != fit_scenarios - {target}:
                violate(f"{role}: training features for {target} not fitted on fit scenarios minus {target}")
        if ":outer_validation" in role and (target != held_out or fit_set != training):
            violate(f"{role}: outer features not fitted on the outer training scenarios")

    for event in result.trace:
        if event["event"] == "table_read":
            if event["scenario"] == held_out:
                violate(f"table read of held-out scenario {held_out}")
            if event["excluded_keys"] != len(excluded):
                violate(f"table read of {event['scenario']} without the split's identifier exclusion")
            fit_scope = set(event.get("feature_fit_set", []))
            if event["scenario"] not in fit_scope:
                violate(f"table read of {event['scenario']} outside the feature fit set {sorted(fit_scope)}")
            if "mapped_with" in event and event["scenario"] in event["mapped_with"]:
                violate(f"height rows of {event['scenario']} mapped with a mapping that used them")
        if event["event"] == "learned_sample":
            if event["excluded_key_rows_in_sample"]:
                violate(f"{event['role']}: excluded identifiers in learned training sample")
            if held_out in event["rows_by_scenario"] or not set(event["rows_by_scenario"]) <= training:
                violate(f"{event['role']}: learned sample outside training scenarios")
            role = event["role"]
            expected = training - {role.split("|inner=")[1]} if "|inner=" in role else training
            if set(event["fit_scenarios"]) != expected or set(event["standardization_scope"]) - expected:
                violate(f"{role}: learned sample or standardization scope differs from {sorted(expected)}")
        if event["event"] == "inner_queue" and excluded:
            keys = ranking.rows(event["scenario"])["key_id"].to_numpy()
            if event["excluded_identifier_alerts_removed"] != int(np.isin(keys, list(excluded)).sum()):
                violate(f"{event['role']}: inner queue did not remove every excluded identifier alert")

    # Completeness: every fit that happened in this fold is backed by logged table reads, and every
    # feature request that was not served from cache has its fits in this fold's trace.
    reads_logged = {(e["scenario"], e.get("component"), tuple(e.get("mapped_with", ())), tuple(e.get("feature_fit_set", ())))
                    for e in result.trace if e["event"] == "table_read"}
    fitted = defaultdict(set)
    for event in result.trace:
        if event["event"] != "fit":
            continue
        fit_set = tuple(event["fit_set"])
        fitted[event["component"]].add(tuple(event.get("feature_fit_set", fit_set)))
        if event["component"] == "class_heights":
            for source in event["row_sources"]:
                if (source["rows_from"], "class_heights", tuple(source["mapped_with"]), fit_set) not in reads_logged:
                    violate(f"class-height rows of {source['rows_from']} for {list(fit_set)} have no logged table read")
        if event["component"] == "key_heights":
            for scenario in fit_set:
                if (scenario, "key_heights", (), fit_set) not in reads_logged:
                    violate(f"key-height table of {scenario} for {list(fit_set)} has no logged table read")
        if event["component"] == "mapping":
            for scenario in fit_set:
                if not any(r[0] == scenario and r[1] == "mapping" for r in reads_logged):
                    violate(f"mapping table of {scenario} has no logged table read")
    for request in result.manifest:
        if not request["cached"] and tuple(request["fit_set"]) not in fitted["key_heights"]:
            violate(f"{request['role']}: uncached feature request without logged fits")
    sampled_roles = {e["role"] for e in result.trace if e["event"] == "learned_sample"}
    for diagnostic in result.learner_diagnostics:
        if diagnostic["role"] not in sampled_roles:
            violate(f"{diagnostic['role']}: learned fit without a logged training sample")

    reads = [(s, p) for s, p in result.label_access_log]
    if any(s == held_out for s, _ in reads):
        violate("held-out labels read during the fold")
    for inner in training:
        own = [i for i, (s, p) in enumerate(reads) if s == inner and f"|inner={inner}:" in p]
        if any(not reads[i][1].endswith("inner_evaluation") for i in own):
            violate(f"inner scenario {inner} read for fitting inside its own validation fold")
    checks = {"manifest_requests": bool(result.manifest), "trace_events": bool(result.trace)}
    return TraceVerification(split.name, result.policy, checks, violations)


def evaluate_outer_selection_metrics(result: OuterFoldResult, store: LabelStore, pipeline: ComparisonPipeline) -> pd.DataFrame:
    """Selection metrics on the outer held-out queue (for synthetic checks; final WP3 metrics replace this)."""

    labels = store.get(result.held_out, purpose=f"{result.split.name}:outer_evaluation")
    rows = pipeline.ranking.rows(result.held_out)
    if not np.array_equal(rows["alert_id"].to_numpy(), result.outer_alert_ids):
        raise ValueError("outer scores are not aligned with ranking rows")
    records = []
    for candidate in result.outer_candidates:
        order = top_k_order(result.outer_scores[candidate.candidate_id], rows["timestamp"].to_numpy(float),
                            rows["hash_key"].to_numpy(np.uint64), pipeline.config.k)
        metrics = selection_metrics(order, labels, pipeline.config.k)
        records.append({"outer_held_out": result.held_out, "policy": result.policy, **candidate.to_record(),
                        "coverage": metrics.coverage, "fp": metrics.fp, "ndcg": metrics.ndcg})
    return pd.DataFrame(records)


def write_fold_outputs(result: OuterFoldResult, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{result.policy.replace('+', '_')}_{result.split.name.replace(':', '_')}"
    result.inner_metrics.to_csv(out_dir / f"{stem}_inner_metrics.csv", index=False)
    result.selections.to_csv(out_dir / f"{stem}_selections.csv", index=False)
    np.savez_compressed(out_dir / f"{stem}_outer_scores.npz", alert_ids=result.outer_alert_ids,
                        **{cid: scores for cid, scores in result.outer_scores.items()})
    (out_dir / f"{stem}_fit_records.json").write_text(json.dumps(result.fit_records, indent=1, default=float))
    (out_dir / f"{stem}_manifest.json").write_text(json.dumps({
        "split": result.split.to_record(), "policy": result.policy,
        "feature_requests": result.manifest, "trace": result.trace, "learner_diagnostics": result.learner_diagnostics,
        "runtime_seconds": result.runtime_seconds, "label_access_log": result.label_access_log,
    }, indent=1, default=str))

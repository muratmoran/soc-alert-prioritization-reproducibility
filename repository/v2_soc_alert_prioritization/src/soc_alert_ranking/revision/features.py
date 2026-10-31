"""Ranking-time inputs (c, u, h) with explicit, traced fitting isolation (protocol v1.1 §6; WP4).

Every fitted quantity is a function of a *fit specification*: a fit set F of scenarios, a
set of excluded native identifiers, the fitting settings, the severity table and the input
policy. It is only ever applied to scenarios outside F.

* The native-key mapping M(F) is fitted on the key tables of F.
* Class reliability heights H(F) are fitted on the rows of each j in F mapped with
  M(F minus {j}) (cross-fitted), pooled over j. Every mapping used for a height therefore
  excludes the target and everything outside F, not just the final aggregation.
* Key-level reliability K(F) is fitted on the key tables of F.
* Excluded identifiers contribute nothing to any table: their counts are zeroed before
  mapping, heights, key heights and priors are computed.

Features for a validation scenario v with training set S use F = S. Features for a training
scenario g (learned-ranker inputs) use F = S minus {g}. The same construction repeats inside
every inner fold.

Caches are keyed by fit set, label versions of every contributing scenario, excluded
identifiers, settings, severity table and reliability variant, so changing any of them
recomputes the fit. Every table read and fit is appended to ``FeatureBuilder.trace``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Iterable

import numpy as np
import pandas as pd

from soc_alert_ranking.mappings.context import apply_asset_context
from soc_alert_ranking.mappings.severity import SeverityMapping
from soc_alert_ranking.revision.labels import LabelStore


RANKING_TIME_COLUMNS = (
    "alert_id", "scenario", "timestamp", "detector", "native_key", "native_category",
    "native_name", "native_short", "host", "ip", "detector_score", "native_rule_level", "native_suricata_severity", "native_record_type",
)
EVALUATION_COLUMNS = ("is_attack", "is_critical", "true_attack_phase", "true_severity", "raw_label")
TIE_SALT = "cose04000|"
UNKNOWN = "unknown"

FALLBACK_NONE, FALLBACK_DETECTOR, FALLBACK_GLOBAL = 0, 1, 2

CONTEXT_POLICIES = ("flat", "asset_profile")
UNCERTAINTY_POLICIES = ("table", "ambiguity_aware", "constant_0.5", "purity_only", "precision_only", "zero")
RELIABILITY_POLICIES = ("detector_class", "global_class", "detector_only", "native_key", "none")


class FitFailure(RuntimeError):
    """No usable training labels for a required estimate."""


@dataclass(frozen=True)
class FittingSettings:
    min_support: int = 5
    min_positive: int = 3
    min_precision: float = 0.5
    min_phase_purity: float = 0.7
    class_lambda: float = 50.0
    key_lambda: float = 50.0
    height_min: float = 0.05
    height_max: float = 0.95
    ambiguity_precision_weight: float = 0.20
    ambiguity_purity_weight: float = 0.15
    uncertainty_max: float = 0.5
    unmapped_uncertainty: float = 0.5
    single_term_uncertainty_weight: float = 0.35

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class InputPolicy:
    context: str = "flat"
    uncertainty: str = "table"
    reliability: str = "detector_class"

    def __post_init__(self) -> None:
        if self.context not in CONTEXT_POLICIES:
            raise ValueError(f"unknown context policy {self.context!r}")
        if self.uncertainty not in UNCERTAINTY_POLICIES:
            raise ValueError(f"unknown uncertainty policy {self.uncertainty!r}")
        if self.reliability not in RELIABILITY_POLICIES:
            raise ValueError(f"unknown reliability policy {self.reliability!r}")

    @property
    def name(self) -> str:
        base = f"{self.context}+{self.uncertainty}"
        return base if self.reliability == "detector_class" else f"{base}+{self.reliability}"

    @property
    def height_domain_max(self) -> float:
        """h = 1 is admitted only by the 'none' reliability ablation."""

        return 1.0 if self.reliability == "none" else 0.95


def stable_hash_keys(alert_ids: Iterable[str], salt: str = TIE_SALT) -> np.ndarray:
    """First 8 bytes of SHA-256(salt + alert_id) as unsigned 64-bit integers."""

    return np.fromiter(
        (int.from_bytes(hashlib.sha256(f"{salt}{alert_id}".encode()).digest()[:8], "big") for alert_id in alert_ids),
        dtype=np.uint64,
    )


def normalized_identifier(detector: str, native_key: str) -> str:
    """Detector plus rule/signature/component identifier: the first identifier field of the key."""

    parts = str(native_key).split(":")
    return f"{detector}:{parts[1] if len(parts) > 1 else ''}"


@dataclass
class RankingFrame:
    """Label-free alert data with key identities, hash keys and context factors."""

    frame: pd.DataFrame
    key_detector: np.ndarray
    key_name: np.ndarray
    detectors: tuple[str, ...]
    scenario_rows: dict[str, np.ndarray]

    @classmethod
    def from_alerts(cls, alerts: pd.DataFrame) -> "RankingFrame":
        missing = set(RANKING_TIME_COLUMNS) - set(alerts.columns)
        if missing:
            raise ValueError(f"alert frame lacks ranking-time columns {sorted(missing)}")
        frame = alerts.loc[:, list(RANKING_TIME_COLUMNS)].copy().reset_index(drop=True)
        if not frame["alert_id"].is_unique:
            raise ValueError("alert_id must be unique")
        if frame["timestamp"].isna().any():
            raise ValueError("timestamps must be present")
        pairs = pd.MultiIndex.from_arrays([frame["detector"].astype(str), frame["native_key"].astype(str)])
        codes, uniques = pd.factorize(pairs, sort=True)
        frame["key_id"] = codes.astype(np.int64)
        frame["hash_key"] = stable_hash_keys(frame["alert_id"].astype(str))
        for scenario, part in frame.groupby("scenario"):
            if part["hash_key"].duplicated().any():
                raise ValueError(f"tie hash collision within scenario {scenario}")
        frame["q_asset_profile"] = apply_asset_context(frame, "asset_profile")["asset_criticality"].to_numpy(float)
        key_detector = np.array([pair[0] for pair in uniques])
        return cls(
            frame=frame,
            key_detector=key_detector,
            key_name=np.array([pair[1] for pair in uniques]),
            detectors=tuple(sorted(set(key_detector))),
            scenario_rows={str(s): part.index.to_numpy() for s, part in frame.groupby("scenario", sort=True)},
        )

    @property
    def n_keys(self) -> int:
        return len(self.key_name)

    @property
    def scenarios(self) -> tuple[str, ...]:
        return tuple(self.scenario_rows)

    def rows(self, scenario: str) -> pd.DataFrame:
        return self.frame.iloc[self.scenario_rows[scenario]]

    def key_ids_for(self, identifiers: Iterable[tuple[str, str]]) -> np.ndarray:
        wanted = set(identifiers)
        return np.array([k for k in range(self.n_keys) if (self.key_detector[k], self.key_name[k]) in wanted], dtype=np.int64)


@dataclass(frozen=True)
class KeyTable:
    """Per-key counts of one scenario: alerts, observed positives, positives per phase."""

    scenario: str
    n: np.ndarray
    positives: np.ndarray
    phase_positives: np.ndarray  # (n_keys, n_phases)

    def without_keys(self, key_ids: np.ndarray) -> "KeyTable":
        if not len(key_ids):
            return self
        n, positives, phases = self.n.copy(), self.positives.copy(), self.phase_positives.copy()
        n[key_ids] = 0.0
        positives[key_ids] = 0.0
        phases[key_ids] = 0.0
        return KeyTable(self.scenario, n, positives, phases)


class KeyTableProvider:
    """Builds key tables through the label store, checking locks on every request."""

    def __init__(self, ranking: RankingFrame, store: LabelStore, phases: tuple[str, ...]):
        self.ranking = ranking
        self.store = store
        self.phases = phases
        self._cache: dict[tuple[str, int], KeyTable] = {}

    def version(self, scenario: str) -> int:
        return self.store.version(scenario)

    def get(self, scenario: str, purpose: str = "fitting") -> KeyTable:
        labels = self.store.get(scenario, purpose)  # raises if locked, logs otherwise
        cache_key = (scenario, self.store.version(scenario))
        table = self._cache.get(cache_key)
        if table is None:
            rows = self.ranking.rows(scenario)
            if not np.array_equal(rows["alert_id"].to_numpy(), labels.alert_ids):
                raise ValueError(f"label rows are not aligned with ranking rows for {scenario}")
            key_ids = rows["key_id"].to_numpy()
            k = self.ranking.n_keys
            table = KeyTable(
                scenario=scenario,
                n=np.bincount(key_ids, minlength=k).astype(float),
                positives=np.bincount(key_ids, weights=labels.y.astype(float), minlength=k),
                phase_positives=np.stack(
                    [np.bincount(key_ids, weights=labels.phase_membership[:, p].astype(float), minlength=k)
                     for p in range(len(self.phases))],
                    axis=1,
                ) if len(self.phases) else np.zeros((k, 0)),
            )
            self._cache[cache_key] = table
        return table

    def invalidate(self) -> None:
        self._cache.clear()


@dataclass(frozen=True)
class MappingFit:
    fit_set: frozenset[str]
    support: np.ndarray
    positives: np.ndarray
    precision: np.ndarray
    purity: np.ndarray
    top_phase: np.ndarray
    accepted: np.ndarray

    def classes(self, n_phases: int) -> np.ndarray:
        """Class index per key: accepted phase index, or n_phases for unknown."""

        return np.where(self.accepted, self.top_phase, n_phases)


def fit_mapping(tables: list[KeyTable], n_keys: int, n_phases: int, settings: FittingSettings,
                fit_set: frozenset[str]) -> MappingFit:
    support = np.zeros(n_keys)
    positives = np.zeros(n_keys)
    phase_counts = np.zeros((n_keys, n_phases))
    for table in tables:
        support += table.n
        positives += table.positives
        phase_counts += table.phase_positives
    with np.errstate(divide="ignore", invalid="ignore"):
        precision = np.where(support > 0, positives / support, 0.0)
        top_count = phase_counts.max(axis=1) if n_phases else np.zeros(n_keys)
        purity = np.where(positives > 0, top_count / np.where(positives > 0, positives, 1.0), 0.0)
    top_phase = np.where(positives > 0, phase_counts.argmax(axis=1) if n_phases else -1, -1)
    accepted = (
        (support >= settings.min_support)
        & (positives >= settings.min_positive)
        & (precision >= settings.min_precision)
        & (purity >= settings.min_phase_purity)
        & (top_phase >= 0)
    )
    return MappingFit(fit_set, support, positives, precision, purity, top_phase, accepted)


@dataclass(frozen=True)
class HeightFit:
    """Shrunk heights per (group, class) with full numerators and denominators for auditing."""

    fit_set: frozenset[str]
    grouping: str                # detector_class | global_class | detector_only
    table: pd.DataFrame          # detector, class, class_index, n, positives, prior_n, prior_positives, unclipped, height
    detector_prior: dict[str, tuple[float, float]]
    global_prior: tuple[float, float]


def _shrink(positives: float, n: float, prior: float, lam: float) -> float:
    weight = n / (n + lam)
    return weight * (positives / n) + (1.0 - weight) * prior


GLOBAL = "__all__"


def fit_class_heights(
    sources: list[tuple[KeyTable, np.ndarray]],
    key_detector: np.ndarray,
    class_names: list[str],
    settings: FittingSettings,
    fit_set: frozenset[str],
    grouping: str = "detector_class",
) -> HeightFit:
    """Fit heights on cross-fitted mapped rows; sources pair a scenario table with its classes.

    grouping 'detector_class' pools by (detector, class) with a detector prior; 'global_class'
    pools by class across detectors with the global prior; 'detector_only' pools by detector
    (ignoring classes) with the global prior.
    """

    counts: dict[tuple[str, int], list[float]] = {}
    detector_totals: dict[str, list[float]] = {}
    for table, classes in sources:
        for key in np.flatnonzero(table.n > 0):
            detector = str(key_detector[key])
            if grouping == "detector_class":
                cell_key = (detector, int(classes[key]))
            elif grouping == "global_class":
                cell_key = (GLOBAL, int(classes[key]))
            elif grouping == "detector_only":
                cell_key = (detector, -1)
            else:
                raise ValueError(f"unknown grouping {grouping!r}")
            cell = counts.setdefault(cell_key, [0.0, 0.0])
            cell[0] += table.positives[key]
            cell[1] += table.n[key]
            total = detector_totals.setdefault(detector, [0.0, 0.0])
            total[0] += table.positives[key]
            total[1] += table.n[key]
    global_positives = sum(v[0] for v in detector_totals.values())
    global_n = sum(v[1] for v in detector_totals.values())
    rows = []
    for (group, class_index), (pos, n) in sorted(counts.items()):
        if grouping == "detector_class":
            prior_pos, prior_n = detector_totals[group]
        else:
            prior_pos, prior_n = global_positives, global_n
        unclipped = _shrink(pos, n, prior_pos / prior_n, settings.class_lambda)
        rows.append({
            "detector": group, "class": class_names[class_index] if class_index >= 0 else "all_classes",
            "class_index": class_index, "n": n, "positives": pos, "prior_n": prior_n, "prior_positives": prior_pos,
            "unclipped": unclipped, "height": float(np.clip(unclipped, settings.height_min, settings.height_max)),
        })
    return HeightFit(
        fit_set=fit_set,
        grouping=grouping,
        table=pd.DataFrame(rows, columns=["detector", "class", "class_index", "n", "positives", "prior_n",
                                          "prior_positives", "unclipped", "height"]),
        detector_prior={d: (v[0], v[1]) for d, v in detector_totals.items()},
        global_prior=(global_positives, global_n),
    )


def apply_class_heights(fit: HeightFit, classes: np.ndarray, key_detector: np.ndarray,
                        settings: FittingSettings) -> tuple[np.ndarray, np.ndarray]:
    """Height per key and fallback code (0 fitted cell, 1 detector prior, 2 global prior)."""

    lookup = {(row.detector, int(row.class_index)): row.height for row in fit.table.itertuples(index=False)}
    heights = np.empty(len(classes))
    fallback = np.zeros(len(classes), dtype=np.int8)
    for key, class_index in enumerate(classes):
        detector = str(key_detector[key])
        if fit.grouping == "detector_class":
            cell_key = (detector, int(class_index))
        elif fit.grouping == "global_class":
            cell_key = (GLOBAL, int(class_index))
        else:
            cell_key = (detector, -1)
        value = lookup.get(cell_key)
        if value is not None:
            heights[key] = value
            continue
        use_detector_prior = fit.grouping == "detector_class"
        heights[key], fallback[key] = _prior_height(fit.detector_prior if use_detector_prior else {}, fit.global_prior,
                                                    detector, settings)
    return heights, fallback


def _prior_height(detector_prior, global_prior, detector, settings) -> tuple[float, int]:
    pos, n = detector_prior.get(detector, (0.0, 0.0))
    if n > 0:
        return float(np.clip(pos / n, settings.height_min, settings.height_max)), FALLBACK_DETECTOR
    pos, n = global_prior
    if n > 0:
        return float(np.clip(pos / n, settings.height_min, settings.height_max)), FALLBACK_GLOBAL
    raise FitFailure("no permitted training labels are available for a reliability estimate")


@dataclass(frozen=True)
class KeyHeightFit:
    fit_set: frozenset[str]
    heights: np.ndarray
    fallback: np.ndarray
    n: np.ndarray
    positives: np.ndarray
    unclipped: np.ndarray


def fit_key_heights(tables: list[KeyTable], key_detector: np.ndarray, settings: FittingSettings,
                    fit_set: frozenset[str]) -> KeyHeightFit:
    """Per-key observed-positive frequency shrunk to the pooled detector prior."""

    n_keys = len(key_detector)
    n = np.zeros(n_keys)
    positives = np.zeros(n_keys)
    for table in tables:
        n += table.n
        positives += table.positives
    detector_prior = {}
    for detector in sorted(set(key_detector)):
        mask = key_detector == detector
        detector_prior[str(detector)] = (positives[mask].sum(), n[mask].sum())
    global_prior = (positives.sum(), n.sum())
    heights = np.empty(n_keys)
    unclipped = np.full(n_keys, np.nan)
    fallback = np.zeros(n_keys, dtype=np.int8)
    for key in range(n_keys):
        detector = str(key_detector[key])
        if n[key] > 0:
            prior_pos, prior_n = detector_prior[detector]
            unclipped[key] = _shrink(positives[key], n[key], prior_pos / prior_n, settings.key_lambda)
            heights[key] = np.clip(unclipped[key], settings.height_min, settings.height_max)
        else:
            heights[key], fallback[key] = _prior_height(detector_prior, global_prior, detector, settings)
    return KeyHeightFit(fit_set, heights, fallback, n, positives, unclipped)


@dataclass(frozen=True)
class KeyFeatures:
    """Everything fitted on one fit specification, expressed per key."""

    fit_set: frozenset[str]
    excluded_key_ids: frozenset[int]
    reliability: str
    mapping: MappingFit
    classes: np.ndarray
    severity: np.ndarray
    u_by_policy: dict[str, np.ndarray]
    height: np.ndarray
    height_fallback: np.ndarray
    heights: HeightFit | None
    key_heights: KeyHeightFit
    crossfit_mapping_sets: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass
class AlertFeatures:
    """Per-alert arrays for one target scenario under one input policy."""

    scenario: str
    fit_set: frozenset[str]
    policy: InputPolicy
    alert_ids: np.ndarray
    timestamp: np.ndarray
    hash_key: np.ndarray
    detector: np.ndarray
    native_score: np.ndarray             # historical pooled score (provenance only)
    native_rule_level: np.ndarray
    native_suricata_severity: np.ndarray
    native_record_type: np.ndarray
    c: np.ndarray
    u: np.ndarray
    h: np.ndarray
    h_key: np.ndarray
    mapped: np.ndarray
    h_fallback: np.ndarray
    h_key_fallback: np.ndarray
    excluded_identifier: np.ndarray
    height_domain_max: float = 0.95

    def __len__(self) -> int:
        return len(self.alert_ids)


class FeatureBuilder:
    """Fits and caches mappings and heights per fit specification, with a complete trace."""

    def __init__(self, ranking: RankingFrame, provider: KeyTableProvider, severity: SeverityMapping,
                 settings: FittingSettings = FittingSettings()):
        self.ranking = ranking
        self.provider = provider
        self.severity = severity
        self.settings = settings
        self.phases = provider.phases
        self.class_names = list(self.phases) + [UNKNOWN]
        self.manifest: list[dict[str, object]] = []
        self.trace: list[dict[str, object]] = []
        self._mapping_cache: dict[tuple, MappingFit] = {}
        self._feature_cache: dict[tuple, KeyFeatures] = {}

    # ------------------------------------------------------------------ identities
    def _severity_digest(self) -> str:
        payload = {"phase": self.severity.ait_phase_severity, "default": self.severity.default_unknown,
                   "uncertainty": self.severity.ait_phase_uncertainty, "factors": self.severity.uncertainty_factor}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]

    def _base_key(self, fit_set: frozenset[str], excluded: frozenset[int]) -> tuple:
        versions = tuple((s, self.provider.version(s)) for s in sorted(fit_set))
        return (fit_set, versions, excluded, self.settings.digest(), self._severity_digest(), self.ranking.n_keys)

    def clear_cache(self) -> None:
        self._mapping_cache.clear()
        self._feature_cache.clear()
        self.provider.invalidate()

    # ------------------------------------------------------------------ fitting
    def _table(self, scenario: str, purpose: str, excluded: frozenset[int], context: dict) -> KeyTable:
        table = self.provider.get(scenario, purpose).without_keys(np.array(sorted(excluded), dtype=np.int64))
        self.trace.append({"event": "table_read", "scenario": scenario, "purpose": purpose,
                           "version": self.provider.version(scenario), "excluded_keys": len(excluded), **context})
        return table

    def mapping(self, fit_set: frozenset[str], excluded: frozenset[int] = frozenset(), context: dict | None = None) -> MappingFit:
        context = dict(context or {})
        cache_key = self._base_key(fit_set, excluded)
        fit = self._mapping_cache.get(cache_key)
        if fit is None:
            tables = [self._table(s, "mapping", excluded, {**context, "component": "mapping", "component_fit_set": sorted(fit_set)})
                      for s in sorted(fit_set)]
            fit = fit_mapping(tables, self.ranking.n_keys, len(self.phases), self.settings, fit_set)
            self._mapping_cache[cache_key] = fit
            self.trace.append({"event": "fit", "component": "mapping", "fit_set": sorted(fit_set),
                               "tables": sorted(fit_set), "excluded_keys": len(excluded), **context})
        return fit

    def key_features(self, fit_set: Iterable[str], excluded_key_ids: Iterable[int] = (),
                     reliability: str = "detector_class") -> KeyFeatures:
        fit_set = frozenset(fit_set)
        excluded = frozenset(int(k) for k in excluded_key_ids)
        cache_key = (*self._base_key(fit_set, excluded), reliability)
        cached = self._feature_cache.get(cache_key)
        if cached is not None:
            return cached
        if not fit_set:
            raise FitFailure("empty fit set")
        if reliability not in RELIABILITY_POLICIES:
            raise ValueError(f"unknown reliability policy {reliability!r}")
        n_phases = len(self.phases)
        context = {"feature_fit_set": sorted(fit_set)}
        mapping = self.mapping(fit_set, excluded, {**context, "role_in_features": "final_mapping"})
        classes = mapping.classes(n_phases)

        crossfit = []
        heights = None
        if reliability in {"detector_class", "global_class", "detector_only"}:
            sources = []
            for scenario in sorted(fit_set):
                inner = fit_set - {scenario}
                inner_classes = self.mapping(inner, excluded, {**context, "role_in_features": "crossfit_mapping",
                                                              "rows_from": scenario}).classes(n_phases)
                sources.append((self._table(scenario, "class_heights", excluded,
                                            {**context, "component": "class_heights", "mapped_with": sorted(inner)}),
                                inner_classes))
                crossfit.append((scenario, tuple(sorted(inner))))
            heights = fit_class_heights(sources, self.ranking.key_detector, self.class_names, self.settings, fit_set,
                                        grouping=reliability)
            self.trace.append({"event": "fit", "component": "class_heights", "grouping": reliability,
                               "fit_set": sorted(fit_set), "row_sources": [{"rows_from": s, "mapped_with": list(m)} for s, m in crossfit],
                               "excluded_keys": len(excluded), **context})
        key_heights = fit_key_heights(
            [self._table(s, "key_heights", excluded, {**context, "component": "key_heights"}) for s in sorted(fit_set)],
            self.ranking.key_detector, self.settings, fit_set)
        self.trace.append({"event": "fit", "component": "key_heights", "fit_set": sorted(fit_set),
                           "excluded_keys": len(excluded), **context})

        if heights is not None:
            height, fallback = apply_class_heights(heights, classes, self.ranking.key_detector, self.settings)
        elif reliability == "native_key":
            height, fallback = key_heights.heights.copy(), key_heights.fallback.copy()
        else:  # none
            height, fallback = np.ones(self.ranking.n_keys), np.zeros(self.ranking.n_keys, dtype=np.int8)

        mapped = classes < n_phases
        safe_phase = np.where(mapped, classes, 0)
        phase_severity = np.array([float(self.severity.ait_phase_severity[p]) for p in self.phases])
        phase_uncertainty = np.array([
            float(self.severity.uncertainty_factor.get(self.severity.ait_phase_uncertainty.get(p, "novel_or_ambiguous"), 0.5))
            for p in self.phases])
        severity = np.where(mapped, phase_severity[safe_phase], self.severity.default_unknown)
        unmapped_u = self.settings.unmapped_uncertainty
        table_u = np.where(mapped, phase_uncertainty[safe_phase], unmapped_u)
        w = self.settings.single_term_uncertainty_weight
        u_by_policy = {
            "table": table_u,
            "ambiguity_aware": np.where(mapped, np.clip(
                table_u + self.settings.ambiguity_precision_weight * (1.0 - mapping.precision)
                + self.settings.ambiguity_purity_weight * (1.0 - mapping.purity), 0.0, self.settings.uncertainty_max), unmapped_u),
            "constant_0.5": np.full(self.ranking.n_keys, 0.5),
            "purity_only": np.where(mapped, w * (1.0 - mapping.purity), unmapped_u),
            "precision_only": np.where(mapped, w * (1.0 - mapping.precision), unmapped_u),
            "zero": np.zeros(self.ranking.n_keys),
        }
        features = KeyFeatures(fit_set, excluded, reliability, mapping, classes, severity, u_by_policy, height, fallback,
                               heights, key_heights, tuple(crossfit))
        self._feature_cache[cache_key] = features
        return features

    def alert_features(self, target: str, fit_set: Iterable[str], policy: InputPolicy, role: str,
                       excluded_key_ids: Iterable[int] = ()) -> AlertFeatures:
        fit_set = frozenset(fit_set)
        excluded = frozenset(int(k) for k in excluded_key_ids)
        if target in fit_set:
            raise ValueError(f"target scenario {target!r} must not be in its own fit set")
        trace_start = len(self.trace)
        keys = self.key_features(fit_set, excluded, policy.reliability)
        rows = self.ranking.rows(target)
        key_ids = rows["key_id"].to_numpy()
        q = rows["q_asset_profile"].to_numpy(float) if policy.context == "asset_profile" else np.ones(len(rows))
        self.manifest.append({
            "role": role, "target": target, "fit_set": sorted(fit_set), "policy": policy.name,
            "reliability": policy.reliability, "excluded_keys": sorted(excluded),
            "mapping_fit_set": sorted(keys.mapping.fit_set),
            "height_row_sources": [{"rows_from": s, "mapped_with": list(m)} for s, m in keys.crossfit_mapping_sets],
            "key_height_fit_set": sorted(keys.key_heights.fit_set),
            "cached": len(self.trace) == trace_start,
        })
        return AlertFeatures(
            scenario=target,
            fit_set=fit_set,
            policy=policy,
            alert_ids=rows["alert_id"].to_numpy(),
            timestamp=rows["timestamp"].to_numpy(float),
            hash_key=rows["hash_key"].to_numpy(np.uint64),
            detector=rows["detector"].to_numpy(),
            native_score=pd.to_numeric(rows["detector_score"], errors="coerce").to_numpy(float),
            native_rule_level=pd.to_numeric(rows["native_rule_level"], errors="coerce").to_numpy(float),
            native_suricata_severity=pd.to_numeric(rows["native_suricata_severity"], errors="coerce").to_numpy(float),
            native_record_type=rows["native_record_type"].astype(str).to_numpy(),
            c=keys.severity[key_ids] * q,
            u=keys.u_by_policy[policy.uncertainty][key_ids],
            h=keys.height[key_ids],
            h_key=keys.key_heights.heights[key_ids],
            mapped=(keys.classes < len(self.phases))[key_ids],
            h_fallback=keys.height_fallback[key_ids],
            h_key_fallback=keys.key_heights.fallback[key_ids],
            excluded_identifier=np.isin(key_ids, np.array(sorted(excluded), dtype=np.int64)),
            height_domain_max=policy.height_domain_max,
        )

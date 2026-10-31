"""Evaluation labels under protocol v1.1 and guarded access to them.

Labels are interval annotations: an alert is labelled with *every* interval
containing its timestamp (half-open [start, end)). They are evaluation-only for
held-out scenarios and fitting data only for permitted training scenarios. All
access goes through :class:`LabelStore`, which can lock scenarios and logs every
request so tests can prove that locked labels were never read.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType
from pathlib import Path
from typing import Iterable, Iterator

import numpy as np
import pandas as pd

from soc_alert_ranking.mappings.severity import SeverityMapping, normalize_label


class LabelAccessError(RuntimeError):
    """Raised when labels of a locked scenario are requested."""


def load_label_intervals(path: str | Path, severity: SeverityMapping, tau: float) -> pd.DataFrame:
    """Read labels.csv into de-duplicated intervals with severity and criticality.

    Exact duplicate (scenario, phase, start, end) rows count once; distinct
    repetitions of the same phase are separate intervals.
    """

    return intervals_from_frame(pd.read_csv(path), severity, tau)


def intervals_from_frame(raw: pd.DataFrame, severity: SeverityMapping, tau: float) -> pd.DataFrame:
    """Same as :func:`load_label_intervals` for an in-memory labels table."""

    required = {"scenario", "attack", "start", "end"}
    if not required.issubset(raw.columns):
        raise ValueError(f"labels file needs columns {sorted(required)}")
    frame = pd.DataFrame({
        "scenario": raw["scenario"].map(normalize_label),
        "phase": raw["attack"].map(normalize_label),
        "start": raw["start"].astype(float),
        "end": raw["end"].astype(float),
    })
    if (frame["end"] <= frame["start"]).any():
        raise ValueError("every label interval must have end > start")
    unknown = sorted(set(frame["phase"]) - set(severity.ait_phase_severity))
    if unknown:
        raise ValueError(f"label phases missing from the severity policy: {unknown}")
    frame = frame.drop_duplicates(["scenario", "phase", "start", "end"]).sort_values(
        ["scenario", "start", "end", "phase"]
    ).reset_index(drop=True)
    frame["severity"] = frame["phase"].map(lambda phase: float(severity.ait_phase_severity[phase]))
    frame["critical"] = frame["severity"] >= tau
    frame["interval_id"] = [
        f"{row.scenario}|{row.phase}|{row.start:.3f}|{row.end:.3f}" for row in frame.itertuples(index=False)
    ]
    return frame


@dataclass(frozen=True)
class ScenarioLabels:
    """Per-alert evaluation labels for one scenario, aligned to ``alert_ids``."""

    scenario: str
    alert_ids: np.ndarray
    y: np.ndarray                    # bool: inside any attack interval
    s_star: np.ndarray               # float: max interval severity, 0 if none
    z: np.ndarray                    # bool: y and s_star >= tau
    r: np.ndarray                    # float: y * s_star (linear relevance)
    phase_membership: np.ndarray     # bool (n_alerts, n_phases), phases in PHASE_ORDER
    critical_membership: np.ndarray  # bool (n_alerts, n_critical_intervals)
    critical_interval_ids: tuple[str, ...]
    defined_critical_intervals: int
    tau: float

    def __post_init__(self) -> None:
        # Label arrays are read-only: a change must go through LabelStore.replace, which versions
        # the scenario and so invalidates every cached fit that used it.
        for name in ("alert_ids", "y", "s_star", "z", "r", "phase_membership", "critical_membership"):
            getattr(self, name).flags.writeable = False

    def replace_arrays(self, **arrays: np.ndarray) -> "ScenarioLabels":
        values = {name: getattr(self, name) for name in self.__dataclass_fields__}
        values.update(arrays)
        return ScenarioLabels(**values)


def phase_order(severity: SeverityMapping) -> tuple[str, ...]:
    """Alphabetical phase order; also the deterministic tie order in mapping."""

    return tuple(sorted(severity.ait_phase_severity))


def build_scenario_labels(
    scenario: str,
    alert_ids: np.ndarray,
    timestamps: np.ndarray,
    intervals: pd.DataFrame,
    phases: tuple[str, ...],
    tau: float,
) -> ScenarioLabels:
    """Assign every containing interval to each alert of one scenario."""

    own = intervals[intervals["scenario"] == scenario].reset_index(drop=True)
    t = np.asarray(timestamps, dtype=float)
    if np.isnan(t).any():
        raise ValueError("timestamps must be finite to assign interval labels")
    n = len(t)
    member = np.zeros((n, len(own)), dtype=bool)
    for j, row in enumerate(own.itertuples(index=False)):
        member[:, j] = (t >= row.start) & (t < row.end)
    severities = own["severity"].to_numpy(float)
    y = member.any(axis=1)
    s_star = np.where(y, np.max(np.where(member, severities, 0.0), axis=1, initial=0.0), 0.0)
    z = y & (s_star >= tau)
    phase_index = {phase: k for k, phase in enumerate(phases)}
    phase_membership = np.zeros((n, len(phases)), dtype=bool)
    for j, phase in enumerate(own["phase"]):
        phase_membership[:, phase_index[phase]] |= member[:, j]
    critical_columns = np.flatnonzero(own["critical"].to_numpy(bool))
    return ScenarioLabels(
        scenario=scenario,
        alert_ids=np.asarray(alert_ids),
        y=y,
        s_star=s_star,
        z=z,
        r=np.where(y, s_star, 0.0),
        phase_membership=phase_membership,
        critical_membership=member[:, critical_columns],
        critical_interval_ids=tuple(own.loc[critical_columns, "interval_id"]),
        defined_critical_intervals=int(len(critical_columns)),
        tau=tau,
    )


class LabelStore:
    """Holds per-scenario labels; enforces locks, versions replacements and records every access.

    ``labels`` is read-only. Replacing a scenario's labels goes through :meth:`replace`, which
    increments that scenario's version so every cached fit that used it is invalidated.
    """

    def __init__(self, labels: dict[str, ScenarioLabels]):
        self._labels = dict(labels)
        self._versions = {scenario: 0 for scenario in self._labels}
        self._locked: set[str] = set()
        self.access_log: list[tuple[str, str]] = []

    @classmethod
    def from_alerts(
        cls,
        ranking_frame: pd.DataFrame,
        intervals: pd.DataFrame,
        phases: tuple[str, ...],
        tau: float,
    ) -> "LabelStore":
        labels = {}
        for scenario, part in ranking_frame.groupby("scenario", sort=True):
            labels[str(scenario)] = build_scenario_labels(
                str(scenario), part["alert_id"].to_numpy(), part["timestamp"].to_numpy(), intervals, phases, tau
            )
        return cls(labels)

    @property
    def labels(self) -> MappingProxyType:
        return MappingProxyType(self._labels)

    @property
    def scenarios(self) -> tuple[str, ...]:
        return tuple(sorted(self._labels))

    def version(self, scenario: str) -> int:
        return self._versions[scenario]

    def replace(self, scenario: str, labels: ScenarioLabels) -> None:
        self._labels[scenario] = labels
        self._versions[scenario] += 1

    def is_locked(self, scenario: str) -> bool:
        return scenario in self._locked

    def get(self, scenario: str, purpose: str) -> ScenarioLabels:
        if scenario in self._locked:
            raise LabelAccessError(f"labels of {scenario!r} are locked (requested for {purpose})")
        self.access_log.append((scenario, purpose))
        return self._labels[scenario]

    @contextmanager
    def locked(self, scenarios: Iterable[str]) -> Iterator[None]:
        added = {s for s in scenarios if s not in self._locked}
        self._locked |= added
        try:
            yield
        finally:
            self._locked -= added

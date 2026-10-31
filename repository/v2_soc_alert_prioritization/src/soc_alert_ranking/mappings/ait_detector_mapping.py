"""Calibration-learned detector metadata mappings for AIT."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pandas as pd

from soc_alert_ranking.mappings.severity import SeverityMapping, is_benign_label


@dataclass(frozen=True)
class MappingThresholds:
    """Thresholds for accepting a native-key to attack-phase mapping."""

    min_support: int = 5
    min_positive: int = 3
    min_precision: float = 0.5
    min_phase_purity: float = 0.7


def learn_native_key_mapping(
    alerts: pd.DataFrame,
    thresholds: MappingThresholds | None = None,
    detector_col: str = "detector",
    key_col: str = "native_key",
    true_phase_col: str = "true_attack_phase",
) -> pd.DataFrame:
    """Learn native detector-key mappings from labeled calibration alerts.

    The mapping is trained only from calibration data. It estimates, for each
    detector-native key, the most frequent non-benign attack phase observed
    during labeled attack intervals and keeps the mapping only if support,
    precision, and phase-purity thresholds are satisfied.
    """

    params = thresholds or MappingThresholds()
    required = {detector_col, key_col, true_phase_col}
    missing = required.difference(alerts.columns)
    if missing:
        raise ValueError(f"Missing columns for mapping learning: {sorted(missing)}")

    rows = []
    grouped = alerts.groupby([detector_col, key_col], dropna=False)
    for (detector, native_key), group in grouped:
        support = int(len(group))
        phase_counts = group[true_phase_col].fillna("benign").value_counts()
        attack_counts = phase_counts[
            [phase for phase in phase_counts.index if not is_benign_label(phase)]
        ]
        positive = int(attack_counts.sum())
        if attack_counts.empty:
            mapped_phase = "unknown"
            top_count = 0
            phase_purity = 0.0
        else:
            mapped_phase = str(attack_counts.idxmax())
            top_count = int(attack_counts.max())
            phase_purity = float(top_count / positive) if positive else 0.0
        precision = float(positive / support) if support else 0.0
        accepted = (
            support >= params.min_support
            and positive >= params.min_positive
            and precision >= params.min_precision
            and phase_purity >= params.min_phase_purity
        )
        rows.append(
            {
                "detector": str(detector),
                "native_key": str(native_key),
                "mapped_phase": mapped_phase if accepted else "unknown",
                "accepted": bool(accepted),
                "support": support,
                "positive": positive,
                "precision": precision,
                "phase_purity": phase_purity,
                "top_count": top_count,
            }
        )
    mapping = pd.DataFrame(rows)
    if mapping.empty:
        return pd.DataFrame(
            columns=[
                "detector",
                "native_key",
                "mapped_phase",
                "accepted",
                "support",
                "positive",
                "precision",
                "phase_purity",
                "top_count",
            ]
        )
    return mapping.sort_values(
        ["accepted", "positive", "support", "precision"],
        ascending=[False, False, False, False],
    ).reset_index(drop=True)


def apply_native_key_mapping(
    alerts: pd.DataFrame,
    mapping: pd.DataFrame,
    severity_mapping: SeverityMapping | None = None,
) -> pd.DataFrame:
    """Apply a learned native-key mapping to alerts."""

    sev = severity_mapping or SeverityMapping.from_file()
    mapped = alerts.merge(
        mapping[["detector", "native_key", "mapped_phase", "precision", "phase_purity"]],
        on=["detector", "native_key"],
        how="left",
    )
    mapped["mapped_phase"] = mapped["mapped_phase"].fillna("unknown")
    mapped["mapped_precision"] = mapped["precision"].fillna(0.0)
    mapped["mapped_phase_purity"] = mapped["phase_purity"].fillna(0.0)
    mapped = mapped.drop(columns=["precision", "phase_purity"])
    mapped["attack_class"] = mapped["mapped_phase"]
    mapped["attack_phase"] = mapped["mapped_phase"]
    mapped["severity"] = [
        sev.severity_for_ait_phases([phase]) if phase != "unknown" else sev.default_unknown
        for phase in mapped["mapped_phase"]
    ]
    mapped["uncertainty_factor"] = [
        sev.uncertainty_for_ait_phases([phase]) if phase != "unknown" else 0.5
        for phase in mapped["mapped_phase"]
    ]
    return mapped


def evaluate_phase_mapping(
    alerts: pd.DataFrame,
    mapped_phase_col: str = "attack_phase",
    true_phase_col: str = "true_attack_phase",
) -> dict[str, float | int]:
    """Evaluate mapping coverage and phase accuracy on labeled alerts."""

    total = int(len(alerts))
    if total == 0:
        return {
            "rows": 0,
            "coverage": 0.0,
            "attack_coverage": 0.0,
            "critical_coverage": 0.0,
            "mapped_attack_precision": 0.0,
            "phase_accuracy_when_mapped": 0.0,
        }
    mapped_mask = alerts[mapped_phase_col].fillna("unknown") != "unknown"
    attack_mask = alerts["is_attack"].astype(bool)
    critical_mask = alerts["is_critical"].astype(bool)
    correct_phase = mapped_mask & (alerts[mapped_phase_col] == alerts[true_phase_col])
    mapped_attack_precision = (
        float(alerts.loc[mapped_mask, "is_attack"].mean()) if mapped_mask.any() else 0.0
    )
    return {
        "rows": total,
        "coverage": float(mapped_mask.mean()),
        "attack_coverage": float(mapped_mask[attack_mask].mean()) if attack_mask.any() else 0.0,
        "critical_coverage": float(mapped_mask[critical_mask].mean()) if critical_mask.any() else 0.0,
        "mapped_attack_precision": mapped_attack_precision,
        "phase_accuracy_when_mapped": float(correct_phase.sum() / mapped_mask.sum())
        if mapped_mask.any()
        else 0.0,
    }


def leave_one_scenario_out_splits(scenarios: Iterable[str]) -> list[tuple[list[str], str]]:
    """Return deterministic leave-one-scenario-out splits."""

    ordered = sorted({str(scenario) for scenario in scenarios})
    return [([scenario for scenario in ordered if scenario != held_out], held_out) for held_out in ordered]

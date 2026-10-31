"""Canonical alert schema used across heterogeneous datasets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional


@dataclass(frozen=True)
class CanonicalAlert:
    """Normalized alert record passed to rankers and metrics."""

    alert_id: str
    dataset: str
    scenario: Optional[str]
    timestamp: float
    detector: str
    source_domain: Optional[str]
    attack_class: str
    attack_phase: Optional[str]
    true_attack_phase: Optional[str]
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    severity: float
    true_severity: float
    uncertainty_factor: float
    detector_score: Optional[float]
    native_severity: Optional[float]
    native_key: str
    native_category: Optional[str]
    asset_criticality: float
    is_attack: bool
    is_critical: bool
    raw: Mapping[str, object]

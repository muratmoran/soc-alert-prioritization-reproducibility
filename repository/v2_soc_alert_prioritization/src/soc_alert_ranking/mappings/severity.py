"""Severity and uncertainty mapping utilities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from soc_alert_ranking.config import CONFIG_DIR, load_yaml


BENIGN_LABELS = {"", "-", "benign", "normal", "false_positive", "false positive", "none"}


@dataclass(frozen=True)
class SeverityMapping:
    """Lookup tables used to convert labels into severity inputs."""

    severity_scale: Dict[str, float]
    ait_phase_severity: Dict[str, float]
    ait_phase_uncertainty: Dict[str, str]
    nf_uq_category_severity: Dict[str, float]
    nf_uq_category_uncertainty: Dict[str, str]
    mitre_tactic_severity: Dict[str, float]
    mitre_tactic_uncertainty: Dict[str, str]
    ait_phase_to_mitre_tactic: Dict[str, str]
    uncertainty_factor: Dict[str, float]

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "SeverityMapping":
        data = load_yaml(path or CONFIG_DIR / "severity_mapping.yaml")
        return cls(
            severity_scale=data.get("severity_scale", {}),
            ait_phase_severity=data.get("ait_attack_phase_severity", {}),
            ait_phase_uncertainty=data.get("ait_attack_phase_uncertainty", {}),
            nf_uq_category_severity=data.get("nf_uq_attack_category_severity", {}),
            nf_uq_category_uncertainty=data.get("nf_uq_attack_category_uncertainty", {}),
            mitre_tactic_severity=data.get("mitre_tactic_severity", {}),
            mitre_tactic_uncertainty=data.get("mitre_tactic_uncertainty", {}),
            ait_phase_to_mitre_tactic=data.get("ait_phase_to_mitre_tactic", {}),
            uncertainty_factor=data.get("uncertainty_factor", {}),
        )

    @property
    def default_unknown(self) -> float:
        return float(self.severity_scale.get("default_unknown", 5.0))

    def severity_for_ait_phases(self, phases: Iterable[str]) -> float:
        """Return the maximum configured severity over one or more AIT phases."""

        values = [
            float(self.ait_phase_severity.get(phase, self.default_unknown))
            for phase in phases
            if not is_benign_label(phase)
        ]
        return max(values) if values else 0.0

    def uncertainty_for_ait_phases(self, phases: Iterable[str]) -> float:
        """Return the highest configured uncertainty factor over AIT phases."""

        values = []
        for phase in phases:
            if is_benign_label(phase):
                continue
            bucket = self.ait_phase_uncertainty.get(phase, "novel_or_ambiguous")
            values.append(float(self.uncertainty_factor.get(bucket, 0.5)))
        return max(values) if values else 0.0

    def severity_for_nf_uq_category(self, category: str) -> float:
        """Return configured severity for a canonical NF-UQ attack category."""

        if is_benign_label(category):
            return 0.0
        return float(self.nf_uq_category_severity.get(category, self.default_unknown))

    def uncertainty_for_nf_uq_category(self, category: str) -> float:
        """Return configured uncertainty for a canonical NF-UQ category."""

        if is_benign_label(category):
            return 0.0
        bucket = self.nf_uq_category_uncertainty.get(category, "novel_or_ambiguous")
        return float(self.uncertainty_factor.get(bucket, 0.5))

    def severity_for_mitre_tactic(self, tactic: str) -> float:
        """Return configured severity for a MITRE ATT&CK tactic label."""

        canonical = canonical_mitre_tactic(tactic)
        if not canonical:
            return 0.0
        return float(self.mitre_tactic_severity.get(canonical, self.default_unknown))

    def uncertainty_for_mitre_tactic(self, tactic: str) -> float:
        """Return configured uncertainty for a MITRE ATT&CK tactic label."""

        canonical = canonical_mitre_tactic(tactic)
        if not canonical:
            return 0.0
        bucket = self.mitre_tactic_uncertainty.get(canonical, "moderate")
        return float(self.uncertainty_factor.get(bucket, 0.2))

    def tactic_for_ait_phase(self, phase: str) -> str:
        """Return the configured MITRE tactic for an AIT attack phase."""

        return self.ait_phase_to_mitre_tactic.get(normalize_label(phase), "")


def normalize_label(value: Any) -> str:
    """Normalize dataset labels while preserving underscore-separated names."""

    if value is None:
        return ""
    return str(value).strip().lower().replace(" ", "_")


def is_benign_label(value: Any) -> bool:
    """Return whether a label means benign/no attack."""

    return normalize_label(value) in BENIGN_LABELS


def canonical_mitre_tactic(value: Any) -> str:
    """Normalize MITRE ATT&CK tactic labels to configured title-case keys."""

    label = normalize_label(value)
    if label in BENIGN_LABELS or label in {"false", "duplicate"}:
        return ""
    aliases = {
        "reconnaissance": "Reconnaissance",
        "resource_development": "Resource Development",
        "initial_access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege_escalation": "Privilege Escalation",
        "defense_evasion": "Defense Evasion",
        "credential_access": "Credential Access",
        "discovery": "Discovery",
        "lateral_movement": "Lateral Movement",
        "collection": "Collection",
        "command_and_control": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }
    return aliases.get(label, str(value).strip())


def split_label_list(value: Any) -> list[str]:
    """Split labels that may contain multiple attack phases."""

    label = normalize_label(value)
    if not label:
        return []
    parts = []
    current = []
    for char in label:
        if char in ";,|":
            part = "".join(current).strip("_")
            if part:
                parts.append(part)
            current = []
        else:
            current.append(char)
    part = "".join(current).strip("_")
    if part:
        parts.append(part)
    return parts


def choose_attack_label(event_label: Any, time_label: Any) -> str:
    """Prefer event labels, with time labels as fallback."""

    event = normalize_label(event_label)
    if event and event != "-":
        return event
    return normalize_label(time_label)

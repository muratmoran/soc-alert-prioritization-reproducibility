"""Severity-policy and criticality sensitivity variants (protocol v1.1 §4.4; WP3 contract §9).

A variant returns a new SeverityMapping used for *both* ranking inputs (mapped-phase
severity s, default_unknown) and evaluation labels (s*), plus the threshold tau.
Variants are declared here before any comparative result exists.
"""

from __future__ import annotations

import dataclasses

from soc_alert_ranking.mappings.severity import SeverityMapping

PRIMARY_TAU = 8.0


def _with_phase_severity(severity: SeverityMapping, values: dict[str, float]) -> SeverityMapping:
    return dataclasses.replace(severity, ait_phase_severity=dict(values))


def shift_all(severity: SeverityMapping, delta: float) -> SeverityMapping:
    """(a) Every AIT phase severity shifted by delta and clipped to [0, 10]; order is preserved."""

    return _with_phase_severity(severity, {p: min(10.0, max(0.0, float(s) + delta))
                                           for p, s in severity.ait_phase_severity.items()})


def swap_two_lowest_critical_levels(severity: SeverityMapping, tau: float = PRIMARY_TAU) -> SeverityMapping:
    """(b) Swap the two lowest *distinct* severity levels among critical phases (s >= tau).

    With the configured table the critical levels are 8.5 (webshell) and 9.0 (reverse_shell,
    dnsteal, data_exfiltration); phases at 8.5 become 9.0 and phases at 9.0 become 8.5.
    Resolving ties by level, not by phase name, keeps the variant well defined.
    """

    levels = sorted({float(s) for s in severity.ait_phase_severity.values() if float(s) >= tau})
    if len(levels) < 2:
        raise ValueError("fewer than two distinct critical severity levels")
    low, second = levels[0], levels[1]
    swapped = {}
    for phase, value in severity.ait_phase_severity.items():
        value = float(value)
        swapped[phase] = second if value == low else low if value == second else value
    return _with_phase_severity(severity, swapped)


def default_unknown(severity: SeverityMapping, value: float = 3.0) -> SeverityMapping:
    """(c) Severity assigned to unmapped alerts; ranking-only (s* never uses it)."""

    scale = dict(severity.severity_scale)
    scale["default_unknown"] = float(value)
    return dataclasses.replace(severity, severity_scale=scale)


VARIANTS = {
    "primary": (lambda s: s, PRIMARY_TAU),
    "severity_plus_0.5": (lambda s: shift_all(s, 0.5), PRIMARY_TAU),
    "severity_minus_0.5": (lambda s: shift_all(s, -0.5), PRIMARY_TAU),
    "swap_lowest_critical_levels": (swap_two_lowest_critical_levels, PRIMARY_TAU),
    "default_unknown_3.0": (default_unknown, PRIMARY_TAU),
    "tau_7": (lambda s: s, 7.0),
    "tau_9": (lambda s: s, 9.0),
}


def variant(severity: SeverityMapping, name: str) -> tuple[SeverityMapping, float]:
    build, tau = VARIANTS[name]
    return build(severity), tau

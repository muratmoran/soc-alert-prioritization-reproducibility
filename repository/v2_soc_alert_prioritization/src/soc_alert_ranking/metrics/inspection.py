"""Dataset inspection summaries."""

from __future__ import annotations

from typing import Dict

import pandas as pd


def summarize_alert_frame(alerts: pd.DataFrame) -> Dict[str, object]:
    """Create a compact summary for a canonical alert frame."""

    if alerts.empty:
        return {
            "rows": 0,
            "detectors": {},
            "scenarios": {},
        "labels": {},
        "inferred_classes": {},
        "attack_rate": 0.0,
        "critical_rate": 0.0,
        }
    return {
        "rows": int(len(alerts)),
        "detectors": alerts["detector"].value_counts(dropna=False).to_dict(),
        "scenarios": alerts["scenario"].value_counts(dropna=False).to_dict(),
        "labels": alerts["true_attack_phase"].value_counts(dropna=False).head(20).to_dict(),
        "inferred_classes": alerts["attack_phase"].value_counts(dropna=False).head(20).to_dict(),
        "attack_rate": float(alerts["is_attack"].mean()),
        "critical_rate": float(alerts["is_critical"].mean()),
    }

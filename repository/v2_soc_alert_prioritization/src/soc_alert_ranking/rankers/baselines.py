"""Baseline and SGFN score construction."""

from __future__ import annotations

import numpy as np
import pandas as pd


def add_ranking_scores(alerts: pd.DataFrame, kappa: float = 1.0) -> pd.DataFrame:
    """Add ranking score columns used in AIT experiments."""

    scored = alerts.copy()
    core = scored["severity"].fillna(0.0).astype(float) * scored["asset_criticality"].fillna(1.0).astype(float)
    uncertainty = scored["uncertainty_factor"].fillna(0.5).astype(float)
    spread = core * uncertainty
    height = scored["height"].fillna(0.5).astype(float).clip(lower=1e-9, upper=1.0)
    native = scored["native_severity"].fillna(0.0).astype(float)
    detector_score = scored["detector_score"].fillna(height).astype(float)

    scored["score_severity"] = core
    scored["score_reliability"] = height
    scored["score_native"] = native
    scored["score_weighted"] = 0.7 * core + 0.3 * (10.0 * height)
    scored["score_detector"] = detector_score
    scored["score_sgfn"] = core + kappa * spread * np.log(height)
    scored["score_recency"] = scored["timestamp"].fillna(0.0).astype(float)
    return scored

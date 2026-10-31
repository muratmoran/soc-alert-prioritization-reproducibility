"""Subnormal Gaussian fuzzy number ranking."""

from __future__ import annotations

import math


def risk_aware_score(core: float, spread: float, height: float, kappa: float = 1.0) -> float:
    """Compute the benefit-type SGFN ranking score.

    Higher scores receive higher alert priority. Height is clipped away from zero
    to keep the logarithm finite.
    """

    clipped_height = min(1.0, max(1e-9, height))
    return core + kappa * spread * math.log(clipped_height)

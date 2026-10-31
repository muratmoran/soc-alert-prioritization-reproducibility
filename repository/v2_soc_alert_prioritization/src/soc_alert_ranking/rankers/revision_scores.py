"""Scalar scoring primitives for the revision; historical runners are unchanged.

Input construction, imputation, and calibration belong upstream. These functions
reject invalid values rather than silently clipping or substituting inputs.
The names describe algebraic rules, not a derivation from fuzzy membership.
"""

import math


def _finite(name: str, value: float) -> None:
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")


def _validate(core: float, uncertainty: float, height: float, kappa: float) -> None:
    for name, value in (("core", core), ("uncertainty", uncertainty),
                        ("height", height), ("kappa", kappa)):
        _finite(name, value)
    if core < 0 or uncertainty < 0 or kappa < 0:
        raise ValueError("core, uncertainty, and kappa must be nonnegative")
    if not 0 < height <= 1:
        raise ValueError("height must be in (0, 1]")


def penalty_strength(uncertainty: float, height: float, kappa: float) -> float:
    """Return t = kappa*u*ln(1/h), avoiding reciprocal overflow."""
    _validate(0.0, uncertainty, height, kappa)
    value = -kappa * uncertainty * math.log(height)
    _finite("penalty strength", value)
    return value


def severity_coefficient(uncertainty: float, height: float, kappa: float) -> float:
    """Total derivative dR/dc when spread is u*c and u,h,kappa are fixed."""
    return 1.0 - penalty_strength(uncertainty, height, kappa)


def monotone_kappa_limit(uncertainty_max: float = 0.5,
                        height_min: float = 0.05) -> float:
    """Nondecreasing-severity bound on the declared rectangular input domain.

    Strict monotonicity uses a strictly smaller kappa when the limit is finite.
    A zero uncertainty bound or a unit height floor removes the penalty.
    """
    _validate(0.0, uncertainty_max, height_min, 0.0)
    if uncertainty_max == 0 or height_min == 1:
        return math.inf
    return 1.0 / (-uncertainty_max * math.log(height_min))


def linear_log_score(core: float, uncertainty: float, height: float,
                     kappa: float) -> float:
    """Historical algebraic rule, including its possible negative scores."""
    _validate(core, uncertainty, height, kappa)
    result = core * severity_coefficient(uncertainty, height, kappa)
    _finite("score", result)
    return result


def constrained_linear_log_score(core: float, uncertainty: float, height: float,
                                 kappa: float, *, uncertainty_max: float = 0.5,
                                 height_min: float = 0.05) -> float:
    """Strictly severity-increasing rule over a prespecified global domain.

    The exact zero-slope endpoint is excluded. No score clipping is performed.
    This property does not guarantee critical-alert or attack-step coverage.
    """
    _validate(core, uncertainty, height, kappa)
    limit = monotone_kappa_limit(uncertainty_max, height_min)
    if uncertainty > uncertainty_max or height < height_min:
        raise ValueError("input outside the declared global domain")
    if kappa >= limit:
        raise ValueError("kappa must be strictly below the monotonicity limit")
    if severity_coefficient(uncertainty, height, kappa) <= 0:
        raise ValueError("strictly positive severity coefficient required")
    return linear_log_score(core, uncertainty, height, kappa)


def exponential_discount_score(core: float, uncertainty: float, height: float,
                               kappa: float) -> float:
    """Multiplicative heuristic c*exp(-t); not a Gaussian ranking derivation."""
    _validate(core, uncertainty, height, kappa)
    discount = math.exp(-penalty_strength(uncertainty, height, kappa))
    result = core * discount
    if core > 0 and result == 0:
        raise ValueError("discount underflows; narrow the declared parameter range")
    return result


def gaussian_membership(x: float, core: float, spread: float, height: float) -> float:
    """Gaussian membership with an explicit pointwise zero-spread extension.

    At zero spread membership is h at the core and zero elsewhere. This is a
    fuzzy singleton, not a probability density or a normalized Dirac density.
    """
    for name, value in (("x", x), ("core", core), ("spread", spread), ("height", height)):
        _finite(name, value)
    if spread < 0 or not 0 < height <= 1:
        raise ValueError("spread must be nonnegative and height in (0, 1]")
    if spread == 0:
        return height if x == core else 0.0
    standardized = (x - core) / spread
    return height * math.exp(-0.5 * standardized * standardized)

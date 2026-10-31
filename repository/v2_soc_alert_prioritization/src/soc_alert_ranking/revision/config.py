"""Configuration schema for WP2 comparisons, validated against protocol v1.1.

The protocol values are restated here so that a configuration cannot drift from the
frozen protocol without failing validation. Changing any of them requires a protocol
change-log entry and an update of this module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from soc_alert_ranking.config import load_yaml
from soc_alert_ranking.revision.families import FamilySpec, build_families, grid_registry
from soc_alert_ranking.revision.features import FittingSettings, InputPolicy
from soc_alert_ranking.rankers.revision_scores import monotone_kappa_limit


PROTOCOL_V1_1 = {
    "schema_version": 1,
    "policies": {"primary": {"context": "flat", "uncertainty": "table"},
                 "secondary": {"context": "asset_profile", "uncertainty": "ambiguity_aware"}},
    "mapping_thresholds": {"min_support": 5, "min_positive": 3, "min_precision": 0.5, "min_phase_purity": 0.7},
    "reliability": {"target": "observed_interval_label", "class_lambda": 50, "key_lambda": 50,
                    "height_min": 0.05, "height_max": 0.95},
    "uncertainty": {"unmapped": 0.5, "maximum": 0.5, "ambiguity_precision_weight": 0.20,
                    "ambiguity_purity_weight": 0.15},
    "evaluation": {"tau": 8.0, "selection_k": 100, "tie_salt": "cose04000|"},
    "selection": {"primary": ["max_macro_coverage", "min_macro_fp", "max_macro_ndcg", "min_nonzero_params", "grid_order"],
                  "secondary": ["max_macro_ndcg", "min_nonzero_params", "grid_order"], "tolerance": 1e-12},
    "learned": {"max_training_alerts": 300000, "seed": 42, "weights": "equalize_scenarios"},
    "grids": {
        "W": {"alpha": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]},
        "A": {"simplex_step": 0.1},
        "M": {"a": [0.0, 0.25, 0.5, 1.0, 2.0, 4.0], "b": [0.0, 1.0, 2.0, 4.0, 8.0]},
        "C": {"c_fp": [0.0, 1.0, 2.5, 5.0, 10.0]},
        "L1": {"C": [0.01, 1.0, 100.0]},
        "L2": {"max_depth": [2, 3], "learning_rate": 0.1, "max_iter": 200, "l2_regularization": 1.0},
        "S0": {"kappa": 1.0},
        "S1": {"kappa": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.6676]},
        "S2": {"kappa": [0.0, 0.5, 1.0, 2.0, 4.0, 8.0]},
    },
}
EXPECTED_TUNED_SIZES = {
    "W_weighted": 11, "A_additive": 66, "M_multiplicative": 30, "C_cost_sensitive": 5, "L1_logistic": 3,
    "L2_gradient_boosting": 2, "S1_linear_log_constrained": 8, "S2_exponential_discount": 6,
    "S1_linear_log_constrained_key": 8, "S2_exponential_discount_key": 6,
}


class ConfigError(ValueError):
    """Configuration does not satisfy the schema or deviates from protocol v1.1."""


@dataclass(frozen=True)
class ComparisonConfig:
    raw: dict
    sha256: str
    settings: FittingSettings
    primary_policy: InputPolicy
    secondary_policy: InputPolicy
    tau: float
    k: int
    tolerance: float
    max_training_alerts: int
    seed: int
    learned_fixed: dict[str, float]
    families: dict[str, FamilySpec]

    def registry(self) -> dict[str, object]:
        rows = grid_registry(self.families)
        body = json.dumps(rows, sort_keys=True)
        return {"config_sha256": self.sha256, "registry_sha256": hashlib.sha256(body.encode()).hexdigest(),
                "candidates": rows,
                "tuned_candidates_per_inner_fold": sum(len(f.candidates) for f in self.families.values() if f.tuned)}


def _compare(expected, actual, path: str) -> None:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise ConfigError(f"{path} must be a mapping")
        missing = set(expected) - set(actual)
        extra = set(actual) - set(expected) - {"protocol"}
        if missing or extra:
            raise ConfigError(f"{path}: missing {sorted(missing)}, unexpected {sorted(extra)}")
        for key in expected:
            _compare(expected[key], actual[key], f"{path}.{key}")
    elif isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            raise ConfigError(f"{path} must be a list of length {len(expected)}")
        for index, (e, a) in enumerate(zip(expected, actual)):
            _compare(e, a, f"{path}[{index}]")
    elif isinstance(expected, str):
        if actual != expected:
            raise ConfigError(f"{path} must be {expected!r}, got {actual!r}")
    else:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)) or float(actual) != float(expected):
            raise ConfigError(f"{path} must be {expected!r}, got {actual!r}")


def validate_raw(raw: dict) -> None:
    _compare(PROTOCOL_V1_1, raw, "config")
    if raw.get("protocol") != "docs/revision/protocol_v1_1.md":
        raise ConfigError("config.protocol must name docs/revision/protocol_v1_1.md")
    limit = monotone_kappa_limit(raw["uncertainty"]["maximum"], raw["reliability"]["height_min"])
    if max(raw["grids"]["S1"]["kappa"]) >= limit:
        raise ConfigError("S1 grid reaches the monotonicity limit")


def load_comparison_config(path: str | Path) -> ComparisonConfig:
    path = Path(path)
    raw = load_yaml(path)
    validate_raw(raw)
    families = build_families(raw["grids"])
    sizes = {name: len(spec.candidates) for name, spec in families.items() if spec.tuned}
    if sizes != EXPECTED_TUNED_SIZES:
        raise ConfigError(f"tuned grid sizes {sizes} differ from protocol {EXPECTED_TUNED_SIZES}")
    thresholds = raw["mapping_thresholds"]
    reliability = raw["reliability"]
    uncertainty = raw["uncertainty"]
    settings = FittingSettings(
        min_support=int(thresholds["min_support"]), min_positive=int(thresholds["min_positive"]),
        min_precision=float(thresholds["min_precision"]), min_phase_purity=float(thresholds["min_phase_purity"]),
        class_lambda=float(reliability["class_lambda"]), key_lambda=float(reliability["key_lambda"]),
        height_min=float(reliability["height_min"]), height_max=float(reliability["height_max"]),
        ambiguity_precision_weight=float(uncertainty["ambiguity_precision_weight"]),
        ambiguity_purity_weight=float(uncertainty["ambiguity_purity_weight"]),
        uncertainty_max=float(uncertainty["maximum"]), unmapped_uncertainty=float(uncertainty["unmapped"]),
    )
    l2 = raw["grids"]["L2"]
    return ComparisonConfig(
        raw=raw,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        settings=settings,
        primary_policy=InputPolicy(**raw["policies"]["primary"]),
        secondary_policy=InputPolicy(**raw["policies"]["secondary"]),
        tau=float(raw["evaluation"]["tau"]),
        k=int(raw["evaluation"]["selection_k"]),
        tolerance=float(raw["selection"]["tolerance"]),
        max_training_alerts=int(raw["learned"]["max_training_alerts"]),
        seed=int(raw["learned"]["seed"]),
        learned_fixed={"learning_rate": l2["learning_rate"], "max_iter": l2["max_iter"],
                       "l2_regularization": l2["l2_regularization"]},
        families=families,
    )

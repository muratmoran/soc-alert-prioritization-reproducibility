"""Comparison families of protocol v1.1 §6.3 with declared grids and vectorized scores.

Scores are functions of the common inputs (c, u, h) or, for identifier-granularity
families, of (c, u, h_key). Inputs are validated against the declared domain and
never clipped or imputed here. Families S0, S1 and S2 (and their key variants) are
heuristics: S1 is the constrained linear-log rule and S2 the exponential-discount
rule; neither is derived from Gaussian membership.
"""

from __future__ import annotations

import json
import math
import warnings
from dataclasses import dataclass, field
from typing import Callable

import numpy as np

from soc_alert_ranking.revision.features import AlertFeatures
from soc_alert_ranking.rankers.revision_scores import monotone_kappa_limit


SEVERITY_MAX = 10.0
UNCERTAINTY_MAX = 0.5
HEIGHT_MIN = 0.05
HEIGHT_MAX = 0.95


class DomainError(ValueError):
    """Inputs or parameters fall outside the declared domain."""


@dataclass(frozen=True)
class Candidate:
    family: str
    params: tuple[tuple[str, float], ...]
    grid_index: int
    n_nonzero: int

    @property
    def params_dict(self) -> dict[str, float]:
        return dict(self.params)

    @property
    def candidate_id(self) -> str:
        if not self.params:
            return self.family
        return self.family + "[" + ",".join(f"{k}={v:g}" for k, v in self.params) + "]"

    def to_record(self) -> dict[str, object]:
        return {"family": self.family, "candidate_id": self.candidate_id, "params": json.dumps(self.params_dict),
                "grid_index": self.grid_index, "n_nonzero": self.n_nonzero}


@dataclass(frozen=True)
class FamilySpec:
    name: str
    description: str
    tuned: bool
    learned: bool
    granularity: str               # class | key | none
    candidates: tuple[Candidate, ...]
    heuristic_label: str = ""


def _decimal_grid(values) -> list[float]:
    return [float(v) for v in values]


def build_families(grids: dict[str, object]) -> dict[str, FamilySpec]:
    """Expand the configured grids into ordered candidates (declared grid order)."""

    def single(name, description, granularity="class", heuristic_label="", params=()):
        return FamilySpec(name, description, tuned=False, learned=False, granularity=granularity,
                          candidates=(Candidate(name, tuple(params), 0, sum(1 for _, v in params if v != 0)),),
                          heuristic_label=heuristic_label)

    families: dict[str, FamilySpec] = {}
    families["O_oldest_first"] = single("O_oldest_first", "Oldest alert first (FIFO)", "none")
    families["O_newest_first"] = single("O_newest_first", "Newest alert first", "none")
    families["O_native_rule_level"] = single(
        "O_native_rule_level", "Wazuh rule.level of alerts delivered through Wazuh (Wazuh and Suricata); AMiner missing and ordered last", "none")
    families["O_native_suricata_severity"] = single(
        "O_native_suricata_severity", "Negated raw Suricata signature severity (1 = most severe); alerts without it missing and ordered last", "none")
    families["O_severity"] = single("O_severity", "Severity core c", "class")
    families["O_reliability"] = single("O_reliability", "Class reliability height h", "class")
    families["H_weighted"] = single("H_weighted", "Historical fixed weighted score 0.7c + 3h", "class")

    alphas = _decimal_grid(grids["W"]["alpha"])
    families["W_weighted"] = FamilySpec("W_weighted", "alpha*c/10 + (1-alpha)*h", True, False, "class", tuple(
        Candidate("W_weighted", (("alpha", a),), i, int(a != 0) + int((1 - a) != 0)) for i, a in enumerate(alphas)))

    step = int(round(1.0 / float(grids["A"]["simplex_step"])))
    additive = []
    for i in range(step + 1):
        for j in range(step + 1 - i):
            a, b, d = i / step, j / step, (step - i - j) / step
            additive.append(Candidate("A_additive", (("a", a), ("b", b), ("d", d)), len(additive),
                                      int(a != 0) + int(b != 0) + int(d != 0)))
    families["A_additive"] = FamilySpec("A_additive", "a*c/10 + b*h - d*u/0.5, a+b+d=1", True, False, "class", tuple(additive))

    mult = []
    for a in _decimal_grid(grids["M"]["a"]):
        for b in _decimal_grid(grids["M"]["b"]):
            mult.append(Candidate("M_multiplicative", (("a", a), ("b", b)), len(mult), int(a != 0) + int(b != 0)))
    families["M_multiplicative"] = FamilySpec("M_multiplicative", "c * h**a * exp(-b*u)", True, False, "class", tuple(mult))

    families["P_probability_proxy"] = single("P_probability_proxy", "h*c (interval-label probability proxy x policy severity)")
    families["C_cost_sensitive"] = FamilySpec("C_cost_sensitive", "h*c - (1-h)*C_FP (rank-equivalent to h*(c+C_FP))", True, False, "class", tuple(
        Candidate("C_cost_sensitive", (("c_fp", v),), i, int(v != 0)) for i, v in enumerate(_decimal_grid(grids["C"]["c_fp"]))))
    families["L1_logistic"] = FamilySpec("L1_logistic", "L2 logistic regression for y on standardized (c,u,h); score p_hat*c", True, True, "class", tuple(
        Candidate("L1_logistic", (("C", v),), i, 0) for i, v in enumerate(_decimal_grid(grids["L1"]["C"]))))
    families["L2_gradient_boosting"] = FamilySpec("L2_gradient_boosting", "HistGradientBoostingRegressor on r/10 with (c,u,h)", True, True, "class", tuple(
        Candidate("L2_gradient_boosting", (("max_depth", v),), i, 0) for i, v in enumerate(_decimal_grid(grids["L2"]["max_depth"]))))
    families["R_key_reliability"] = single("R_key_reliability", "Key-level shrunk observed-positive frequency rho(key)", "key")
    families["R_severity_key_reliability"] = single("R_severity_key_reliability", "c*rho(key); identical to P with key-level h", "key")

    kappa_limit = monotone_kappa_limit(UNCERTAINTY_MAX, HEIGHT_MIN)
    s1_grid = _decimal_grid(grids["S1"]["kappa"])
    if any(k >= kappa_limit for k in s1_grid):
        raise DomainError("S1 kappa grid must lie strictly below the monotonicity limit")
    s2_grid = _decimal_grid(grids["S2"]["kappa"])
    for suffix, granularity in (("", "class"), ("_key", "key")):
        families[f"S0_linear_log_historical{suffix}"] = single(
            f"S0_linear_log_historical{suffix}", "c + kappa*u*c*ln(h), kappa=1 (outside the monotone domain)", granularity,
            "historical linear-log heuristic", params=(("kappa", float(grids["S0"]["kappa"])),))
        families[f"S1_linear_log_constrained{suffix}"] = FamilySpec(
            f"S1_linear_log_constrained{suffix}", "c*(1 + kappa*u*ln(h)), kappa strictly inside the monotone domain", True, False, granularity,
            tuple(Candidate(f"S1_linear_log_constrained{suffix}", (("kappa", k),), i, int(k != 0)) for i, k in enumerate(s1_grid)),
            "constrained linear-log heuristic")
        families[f"S2_exponential_discount{suffix}"] = FamilySpec(
            f"S2_exponential_discount{suffix}", "c * h**(kappa*u)", True, False, granularity,
            tuple(Candidate(f"S2_exponential_discount{suffix}", (("kappa", k),), i, int(k != 0)) for i, k in enumerate(s2_grid)),
            "exponential-discount heuristic (not a Gaussian derivation)")
    return families


def validate_inputs(c: np.ndarray, u: np.ndarray, h: np.ndarray, h_max: float = HEIGHT_MAX) -> None:
    """Declared domain: c in [0, 10], u in [0, 0.5], h in [0.05, h_max]; h_max = 1 only for the no-reliability ablation."""

    for name, values in (("c", c), ("u", u), ("h", h)):
        if not np.all(np.isfinite(values)):
            raise DomainError(f"{name} contains non-finite values")
    if np.any(c < 0) or np.any(c > SEVERITY_MAX):
        raise DomainError("c must lie in [0, 10]")
    if np.any(u < 0) or np.any(u > UNCERTAINTY_MAX):
        raise DomainError("u must lie in [0, 0.5]")
    if h_max not in (HEIGHT_MAX, 1.0):
        raise DomainError("h_max must be 0.95 or 1.0")
    if np.any(h < HEIGHT_MIN) or np.any(h > h_max):
        raise DomainError(f"h must lie in [0.05, {h_max:g}]")


def score_closed_form(candidate: Candidate, features: AlertFeatures) -> np.ndarray:
    """Score one non-learned candidate on one target scenario."""

    family = candidate.family
    p = candidate.params_dict
    if family == "O_oldest_first":
        return -features.timestamp
    if family == "O_newest_first":
        return features.timestamp.copy()
    if family == "O_native_rule_level":
        return features.native_rule_level.copy()          # NaN stays NaN and is ordered last
    if family == "O_native_suricata_severity":
        return -features.native_suricata_severity          # lower raw severity = more severe

    key_level = family.startswith("R_") or family.endswith("_key")
    h = features.h_key if key_level else features.h
    c, u = features.c, features.u
    validate_inputs(c, u, h, HEIGHT_MAX if key_level else features.height_domain_max)
    if family == "O_severity":
        return c.copy()
    if family == "O_reliability":
        return h.copy()
    if family == "H_weighted":
        return 0.7 * c + 0.3 * (10.0 * h)
    if family == "W_weighted":
        return p["alpha"] * c / SEVERITY_MAX + (1.0 - p["alpha"]) * h
    if family == "A_additive":
        return p["a"] * c / SEVERITY_MAX + p["b"] * h - p["d"] * u / UNCERTAINTY_MAX
    if family == "M_multiplicative":
        return c * np.power(h, p["a"]) * np.exp(-p["b"] * u)
    if family in {"P_probability_proxy", "R_severity_key_reliability"}:
        return h * c
    if family == "R_key_reliability":
        return h.copy()
    if family == "C_cost_sensitive":
        return h * c - (1.0 - h) * p["c_fp"]
    if family.startswith("S0_"):
        return c + p["kappa"] * u * c * np.log(h)
    if family.startswith("S1_"):
        kappa = p["kappa"]
        if kappa >= monotone_kappa_limit(UNCERTAINTY_MAX, HEIGHT_MIN):
            raise DomainError("S1 kappa must be strictly below the monotonicity limit")
        coefficient = 1.0 + kappa * u * np.log(h)
        if np.any(coefficient <= 0):
            raise DomainError("S1 requires a strictly positive severity coefficient")
        return c * coefficient
    if family.startswith("S2_"):
        result = c * np.exp(p["kappa"] * u * np.log(h))
        if np.any((c > 0) & (result == 0)):
            raise DomainError("S2 discount underflows for a positive core")
        return result
    raise KeyError(f"no closed-form score for family {family}")


# ---------------------------------------------------------------- learned families

@dataclass
class TrainingSample:
    """Label-independent subsample of training alerts with scenario-equalizing weights."""

    X: np.ndarray                   # (n, 3) columns c, u, h
    y: np.ndarray                   # observed interval label
    r: np.ndarray                   # linear relevance
    weights: np.ndarray
    scenarios: np.ndarray
    alert_ids: np.ndarray
    sampled_from: int


def draw_training_rows(alert_ids_by_scenario: dict[str, np.ndarray], hash_by_scenario: dict[str, np.ndarray],
                       max_rows: int, seed: int) -> dict[str, np.ndarray]:
    """Uniform subsample without labels: order rows by tie hash, then draw with a seeded RNG.

    Returns, per scenario, the selected positions into that scenario's rows.
    """

    scenario_order = sorted(alert_ids_by_scenario)
    positions = []
    for index, scenario in enumerate(scenario_order):
        n = len(alert_ids_by_scenario[scenario])
        order = np.argsort(hash_by_scenario[scenario], kind="mergesort")
        positions.append(np.stack([np.full(n, index), order], axis=1))
    stacked = np.concatenate(positions) if positions else np.zeros((0, 2), dtype=int)
    if len(stacked) > max_rows:
        chosen = np.sort(np.random.default_rng(seed).choice(len(stacked), size=max_rows, replace=False))
        stacked = stacked[chosen]
    return {scenario: np.sort(stacked[stacked[:, 0] == index, 1]) for index, scenario in enumerate(scenario_order)}


def equalizing_weights(scenarios: np.ndarray) -> np.ndarray:
    """Weights giving each scenario equal total weight, normalized to mean 1."""

    values, counts = np.unique(scenarios, return_counts=True)
    per = dict(zip(values, 1.0 / (len(values) * counts)))
    weights = np.array([per[s] for s in scenarios])
    return weights * (len(weights) / weights.sum())


@dataclass
class FittedLearner:
    candidate: Candidate
    model: object
    mean: np.ndarray | None = None
    scale: np.ndarray | None = None
    fallback: str | None = None
    constant_probability: float | None = None
    diagnostics: dict[str, object] = field(default_factory=dict)

    def score(self, features: AlertFeatures) -> np.ndarray:
        validate_inputs(features.c, features.u, features.h, features.height_domain_max)
        X = np.column_stack([features.c, features.u, features.h])
        if self.candidate.family == "L1_logistic":
            if self.constant_probability is not None:
                return self.constant_probability * features.c
            probability = self.model.predict_proba((X - self.mean) / self.scale)[:, 1]
            return probability * features.c
        return self.model.predict(X)


def fit_learner(candidate: Candidate, sample: TrainingSample, seed: int, fixed: dict[str, float],
                h_max: float = HEIGHT_MAX) -> FittedLearner:
    validate_inputs(sample.X[:, 0], sample.X[:, 1], sample.X[:, 2], h_max)
    if candidate.family == "L1_logistic":
        from sklearn.linear_model import LogisticRegression

        if len(np.unique(sample.y)) < 2:
            rate = float(np.average(sample.y, weights=sample.weights)) if len(sample.y) else 0.0
            return FittedLearner(candidate, None, fallback="single_class_constant_probability",
                                 constant_probability=rate, diagnostics={"training_rows": len(sample.y)})
        mean = sample.X.mean(axis=0)
        scale = sample.X.std(axis=0)
        scale = np.where(scale > 0, scale, 1.0)
        model = LogisticRegression(C=candidate.params_dict["C"], penalty="l2", solver="lbfgs", max_iter=1000,
                                   random_state=seed)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            model.fit((sample.X - mean) / scale, sample.y.astype(int), sample_weight=sample.weights)
        return FittedLearner(candidate, model, mean, scale, diagnostics={
            "training_rows": len(sample.y), "converged": not any("converge" in str(w.message).lower() for w in caught),
            "coef": model.coef_.ravel().tolist(), "intercept": float(model.intercept_[0])})
    if candidate.family == "L2_gradient_boosting":
        from sklearn.ensemble import HistGradientBoostingRegressor

        model = HistGradientBoostingRegressor(
            max_depth=int(candidate.params_dict["max_depth"]), learning_rate=float(fixed["learning_rate"]),
            max_iter=int(fixed["max_iter"]), l2_regularization=float(fixed["l2_regularization"]),
            early_stopping=False, random_state=seed)
        model.fit(sample.X, sample.r / SEVERITY_MAX, sample_weight=sample.weights)
        return FittedLearner(candidate, model, diagnostics={"training_rows": len(sample.y)})
    raise KeyError(f"{candidate.family} is not a learned family")


LEARNED_FAMILIES = frozenset({"L1_logistic", "L2_gradient_boosting"})


def score_candidate(candidate: Candidate, features: AlertFeatures, learner: FittedLearner | None = None) -> np.ndarray:
    if candidate.family in LEARNED_FAMILIES:
        if learner is None or learner.candidate != candidate:
            raise ValueError("learned candidates need their fitted learner")
        return learner.score(features)
    return score_closed_form(candidate, features)


def grid_registry(families: dict[str, FamilySpec]) -> list[dict[str, object]]:
    rows = []
    for spec in families.values():
        for candidate in spec.candidates:
            record = candidate.to_record()
            record.update({"tuned": spec.tuned, "learned": spec.learned, "granularity": spec.granularity,
                           "heuristic_label": spec.heuristic_label, "description": spec.description})
            rows.append(record)
    return rows


def is_close(a: float, b: float, tolerance: float) -> bool:
    return math.isclose(a, b, rel_tol=0.0, abs_tol=tolerance)

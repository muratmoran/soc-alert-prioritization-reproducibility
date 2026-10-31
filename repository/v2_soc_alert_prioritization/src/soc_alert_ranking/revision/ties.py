"""Tie structure and ordering-sensitivity analyses (WP3 metric contract §6).

Three ordering interpretations are kept separate:

1. **Declared order** (protocol v1.1 §5): score descending, timestamp ascending, tie hash.
   This is the operational policy and the only order used for primary results.
2. **Expected tie-averaged metrics**: exact expectations when every score block is ordered
   uniformly at random (linear metrics only: counts, precision, recalls, DCG/NDCG).
3. **Seeded within-score-block permutations** (seeds 0-99): the distribution of every
   metric, including coverage and first-critical rank, when each score block is shuffled.

Interpretations 2 and 3 discard the chronological order inside a block. They diagnose how
much a result depends on the tie rule; they do not reproduce the operational policy, and
permutation seeds are not independent experimental replicates.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

from soc_alert_ranking.revision.evaluation import full_order, top_k_order
from soc_alert_ranking.revision.labels import ScenarioLabels
from soc_alert_ranking.revision.metrics import K_GRID, discounts, first_critical_rank, metrics_at_k


# ------------------------------------------------------------------ score blocks

def _block_starts(sorted_scores: np.ndarray) -> np.ndarray:
    """True where a new score block starts along a score-sorted sequence (NaN equals NaN)."""

    if len(sorted_scores) == 0:
        return np.zeros(0, dtype=bool)
    previous, current = sorted_scores[:-1], sorted_scores[1:]
    same = (previous == current) | (np.isnan(previous) & np.isnan(current))
    return np.concatenate([[True], ~same])


def block_ids_along_order(scores: np.ndarray, order: np.ndarray) -> np.ndarray:
    """Block index (0, 1, ...) of each rank position of an order sorted by score."""

    ordered = np.asarray(scores, dtype=float)[np.asarray(order, dtype=np.int64)]
    return np.cumsum(_block_starts(ordered)) - 1


@dataclass(frozen=True)
class CutoffTies:
    k: int
    k_eff: int
    cutoff_block_size: int
    crosses_cutoff: bool
    positions_in_tied_blocks: int      # top-k positions whose occupant is decided among >= 2 equal scores
    order_share: float | None          # positions_in_tied_blocks / k_eff
    members_selected_by_tie_rule: int  # top-k members of a cutoff-crossing block
    membership_share: float | None     # members_selected_by_tie_rule / k_eff

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def tie_diagnostics(scores: np.ndarray, order: np.ndarray, k_grid=K_GRID) -> dict[str, object]:
    scores = np.asarray(scores, dtype=float)
    n = len(scores)
    blocks = block_ids_along_order(scores, order)
    sizes = np.bincount(blocks) if n else np.zeros(0, dtype=int)
    size_at_position = sizes[blocks] if n else np.zeros(0, dtype=int)
    cutoffs = []
    for k in k_grid:
        k_eff = min(k, n)
        if k_eff == 0:
            cutoffs.append(CutoffTies(k, 0, 0, False, 0, None, 0, None).to_record())
            continue
        cutoff_block = blocks[k_eff - 1]
        crosses = k_eff < n and blocks[k_eff] == cutoff_block
        members = int((blocks[:k_eff] == cutoff_block).sum()) if crosses else 0
        tied_positions = int((size_at_position[:k_eff] > 1).sum())
        cutoffs.append(CutoffTies(k, k_eff, int(sizes[cutoff_block]), bool(crosses), tied_positions,
                                  tied_positions / k_eff, members, members / k_eff).to_record())
    finite = scores[~np.isnan(scores)]
    return {
        "n": n,
        "distinct_finite_scores": int(len(np.unique(finite))),
        "missing_scores": int(np.isnan(scores).sum()),
        "blocks": int(len(sizes)),
        "tied_blocks": int((sizes > 1).sum()),
        "alerts_in_tied_blocks": int(sizes[sizes > 1].sum()),
        "share_in_tied_blocks": float(sizes[sizes > 1].sum() / n) if n else None,
        "max_block_size": int(sizes.max()) if n else 0,
        "median_block_size": float(np.median(sizes)) if n else None,
        "cutoffs": cutoffs,
    }


# ------------------------------------------------------------------ expectations under random ties

@dataclass(frozen=True)
class ExpectedAtK:
    k: int
    k_eff: int
    expected_positives_in_top: float
    expected_negatives_in_top: float
    expected_precision: float | None
    expected_attack_recall: float | None
    expected_critical_recall: float | None
    expected_ndcg_linear: float | None
    expected_ndcg_exponential: float | None

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def expected_under_random_ties(scores: np.ndarray, labels: ScenarioLabels, k: int) -> ExpectedAtK:
    """Exact expectations of linear metrics when each score block is uniformly shuffled.

    A block occupying rank positions [a, b] contributes (mean value over its members) times
    the number of its positions within the top k (counts), or times the sum of those
    positions' discounts (DCG). Ideal DCG is unchanged by ties.
    """

    scores = np.asarray(scores, dtype=float)
    n = len(scores)
    k_eff = min(k, n)
    order = np.lexsort((np.arange(n), np.where(np.isnan(scores), np.inf, -scores)))
    blocks = block_ids_along_order(scores, order)
    gain = np.power(2.0, labels.r) - 1.0
    frame = pd.DataFrame({"block": blocks, "y": labels.y[order].astype(float), "z": labels.z[order].astype(float),
                          "r": labels.r[order], "g": gain[order], "position": np.arange(1, n + 1)})
    means = frame.groupby("block")[["y", "z", "r", "g"]].mean()
    d = discounts(n)
    in_top = frame["position"].to_numpy() <= k_eff
    slots = pd.Series(in_top.astype(float)).groupby(frame["block"]).sum()
    discount_mass = pd.Series(np.where(in_top, d, 0.0)).groupby(frame["block"]).sum()
    expected_y = float((means["y"] * slots).sum()) if n else 0.0
    expected_z = float((means["z"] * slots).sum()) if n else 0.0
    expected_dcg = float((means["r"] * discount_mass).sum()) if n else 0.0
    expected_dcg_exp = float((means["g"] * discount_mass).sum()) if n else 0.0
    idcg = float(np.sum(np.sort(labels.r)[::-1][:k_eff] * d[:k_eff]))
    idcg_exp = float(np.sum(np.sort(gain)[::-1][:k_eff] * d[:k_eff]))
    positives, critical = int(labels.y.sum()), int(labels.z.sum())
    return ExpectedAtK(
        k=k, k_eff=k_eff, expected_positives_in_top=expected_y, expected_negatives_in_top=k_eff - expected_y,
        expected_precision=expected_y / k_eff if k_eff else None,
        expected_attack_recall=expected_y / positives if positives else None,
        expected_critical_recall=expected_z / critical if critical else None,
        expected_ndcg_linear=expected_dcg / idcg if idcg else None,
        expected_ndcg_exponential=expected_dcg_exp / idcg_exp if idcg_exp else None,
    )


# ------------------------------------------------------------------ seeded within-block permutations

def permuted_order(scores: np.ndarray, seed: int) -> np.ndarray:
    """Score-descending order with each score block (NaN last) shuffled by ``seed``."""

    scores = np.asarray(scores, dtype=float)
    shuffle_key = np.random.default_rng(seed).random(len(scores))
    return np.lexsort((shuffle_key, np.where(np.isnan(scores), np.inf, -scores)))


def permutation_distribution(scores: np.ndarray, labels: ScenarioLabels, k_grid=K_GRID,
                             seeds=range(100)) -> pd.DataFrame:
    """Per-seed metrics under within-score-block permutation (one row per seed and budget)."""

    rows = []
    for seed in seeds:
        order = permuted_order(scores, seed)
        first = first_critical_rank(order, labels)
        for k in k_grid:
            m = metrics_at_k(order, labels, k)
            rows.append({"seed": seed, "k": k, "negatives_in_top": m.negatives_in_top,
                         "critical_recall": m.critical_recall, "attack_recall": m.attack_recall,
                         "coverage_eligible": m.coverage_eligible, "coverage_all": m.coverage_all,
                         "ndcg_linear": m.ndcg_linear, "first_critical_position": first.position})
    return pd.DataFrame(rows)


def summarize_permutations(distribution: pd.DataFrame) -> pd.DataFrame:
    """Median, 2.5th and 97.5th percentiles (linear interpolation), min and max per budget."""

    metrics = ["negatives_in_top", "critical_recall", "attack_recall", "coverage_eligible", "coverage_all",
               "ndcg_linear", "first_critical_position"]
    records = []
    for k, part in distribution.groupby("k"):
        for metric in metrics:
            values = part[metric].dropna().to_numpy(float)
            record = {"k": k, "metric": metric, "seeds": int(len(part)), "defined": int(len(values))}
            if len(values):
                record.update({"median": float(np.median(values)), "p2_5": float(np.percentile(values, 2.5)),
                               "p97_5": float(np.percentile(values, 97.5)), "min": float(values.min()),
                               "max": float(values.max())})
            records.append(record)
    return pd.DataFrame(records)


# ------------------------------------------------------------------ near ties and within-key constancy

def round_significant(scores: np.ndarray, digits: int = 4) -> np.ndarray:
    """Correctly rounded significant digits via Python's ``g`` format; NaN, inf and 0 unchanged."""

    values = np.asarray(scores, dtype=float)
    out = values.copy()
    finite = np.isfinite(values) & (values != 0)
    out[finite] = [float(f"{v:.{digits}g}") for v in values[finite]]
    return out


def near_tie_order(scores: np.ndarray, timestamps: np.ndarray, hash_keys: np.ndarray, digits: int = 4) -> np.ndarray:
    return full_order(round_significant(scores, digits), timestamps, hash_keys)


def within_group_constancy(scores: np.ndarray, groups: np.ndarray) -> dict[str, object]:
    """Groups (e.g. native keys within a scenario) whose members do not all share one score."""

    frame = pd.DataFrame({"group": np.asarray(groups), "score": np.asarray(scores, dtype=float)})
    frame["token"] = np.where(frame["score"].isna(), "nan", frame["score"].map(repr))
    distinct = frame.groupby("group")["token"].nunique()
    sizes = frame.groupby("group").size()
    varying = distinct[distinct > 1].index
    return {"groups": int(len(distinct)), "varying_groups": int(len(varying)),
            "alerts_in_varying_groups": int(sizes[varying].sum()),
            "share_alerts_in_varying_groups": float(sizes[varying].sum() / len(frame)) if len(frame) else None,
            "max_distinct_scores_in_group": int(distinct.max()) if len(distinct) else 0}


# Per-alert inputs each family can depend on. Class-level inputs c, u, h and key-level h_key are
# constant within a (scenario, native key) group under the flat context; c varies within a key
# only through the asset-profile factor q.
FAMILY_INPUTS = {
    "O_oldest_first": {"timestamp"}, "O_newest_first": {"timestamp"},
    "O_native_rule_level": {"native_rule_level"}, "O_native_suricata_severity": {"native_suricata_severity"},
    "O_severity": {"c"}, "O_reliability": {"h"}, "H_weighted": {"c", "h"}, "W_weighted": {"c", "h"},
    "A_additive": {"c", "u", "h"}, "M_multiplicative": {"c", "u", "h"}, "P_probability_proxy": {"c", "h"},
    "C_cost_sensitive": {"c", "h"}, "L1_logistic": {"c", "u", "h"}, "L2_gradient_boosting": {"c", "u", "h"},
    "R_key_reliability": {"h_key"}, "R_severity_key_reliability": {"c", "h_key"},
    "S0_linear_log_historical": {"c", "u", "h"}, "S1_linear_log_constrained": {"c", "u", "h"},
    "S2_exponential_discount": {"c", "u", "h"}, "S0_linear_log_historical_key": {"c", "u", "h_key"},
    "S1_linear_log_constrained_key": {"c", "u", "h_key"}, "S2_exponential_discount_key": {"c", "u", "h_key"},
}


def candidate_inputs(family: str, params: dict[str, float]) -> set[str]:
    """Inputs a candidate actually uses once zero-weight terms are removed."""

    inputs = set(FAMILY_INPUTS[family])
    if family == "W_weighted":
        if params["alpha"] == 0:
            inputs.discard("c")
        if params["alpha"] == 1:
            inputs.discard("h")
    elif family == "A_additive":
        for name, symbol in (("a", "c"), ("b", "h"), ("d", "u")):
            if params[name] == 0:
                inputs.discard(symbol)
    elif family == "M_multiplicative":
        if params["a"] == 0:
            inputs.discard("h")
        if params["b"] == 0:
            inputs.discard("u")
    elif family.startswith(("S1_", "S2_")) and params["kappa"] == 0:
        inputs -= {"u", "h", "h_key"}
    return inputs


def varying_inputs(inputs: dict[str, np.ndarray], groups: np.ndarray) -> set[str]:
    """Names of per-alert inputs that take more than one value within at least one group."""

    return {name for name, values in inputs.items() if within_group_constancy(values, groups)["varying_groups"] > 0}


def guaranteed_constant_within_key(inputs: set[str], varying_inputs: set[str]) -> bool:
    """A score is guaranteed constant within a key if none of its inputs varies within that key."""

    return not (inputs & varying_inputs)

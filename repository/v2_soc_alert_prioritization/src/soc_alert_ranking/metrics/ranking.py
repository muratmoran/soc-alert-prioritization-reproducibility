"""SOC-facing ranking metrics."""

from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd


def rank_alerts(alerts: pd.DataFrame, score_column: str) -> pd.DataFrame:
    """Return alerts sorted by descending score and ascending timestamp."""

    ranked = alerts.copy()
    ranked["_score_for_sort"] = ranked[score_column].fillna(float("-inf"))
    ranked["_timestamp_for_sort"] = ranked["timestamp"].fillna(float("inf"))
    ranked = ranked.sort_values(
        ["_score_for_sort", "_timestamp_for_sort", "alert_id"],
        ascending=[False, True, True],
        kind="mergesort",
    ).reset_index(drop=True)
    ranked["rank"] = np.arange(1, len(ranked) + 1)
    return ranked.drop(columns=["_score_for_sort", "_timestamp_for_sort"])


def compute_ranking_metrics(
    alerts: pd.DataFrame,
    score_column: str,
    k_values: Iterable[int] = (10, 25, 50, 100, 250, 500, 1000),
    relevance_column: str = "true_severity",
    critical_column: str = "is_critical",
    attack_column: str = "is_attack",
) -> dict[str, float | int]:
    """Compute ranking metrics for one score column."""

    ranked = rank_alerts(alerts, score_column)
    relevance = ranked[relevance_column].fillna(0.0).to_numpy(dtype=float)
    critical = ranked[critical_column].fillna(False).to_numpy(dtype=bool)
    attack = ranked[attack_column].fillna(False).to_numpy(dtype=bool)

    total_critical = int(critical.sum())
    total_attack = int(attack.sum())
    metrics: dict[str, float | int] = {
        "rows": int(len(ranked)),
        "total_attack": total_attack,
        "total_critical": total_critical,
        "score_mean": float(ranked[score_column].fillna(0.0).mean()) if len(ranked) else 0.0,
    }

    ideal_relevance = np.sort(relevance)[::-1]
    for k_raw in k_values:
        k = min(int(k_raw), len(ranked))
        if k <= 0:
            continue
        top_relevance = relevance[:k]
        top_critical = critical[:k]
        top_attack = attack[:k]
        metrics[f"ndcg@{k_raw}"] = _ndcg_at_k(top_relevance, ideal_relevance[:k])
        metrics[f"critical_recall@{k_raw}"] = (
            float(top_critical.sum() / total_critical) if total_critical else 0.0
        )
        metrics[f"attack_recall@{k_raw}"] = (
            float(top_attack.sum() / total_attack) if total_attack else 0.0
        )
        metrics[f"false_positives@{k_raw}"] = int((~top_attack).sum())
        metrics[f"critical_found@{k_raw}"] = int(top_critical.sum())

    for target in (0.5, 0.8, 0.9, 0.95):
        metrics[f"effort_for_critical_recall_{target:g}"] = _effort_for_recall(critical, target)

    first_critical = np.flatnonzero(critical)
    metrics["rank_first_critical"] = int(first_critical[0] + 1) if len(first_critical) else 0
    return metrics


def _ndcg_at_k(relevance: np.ndarray, ideal_relevance: np.ndarray) -> float:
    dcg = _dcg(relevance)
    idcg = _dcg(ideal_relevance)
    return float(dcg / idcg) if idcg > 0 else 0.0


def _dcg(relevance: np.ndarray) -> float:
    if len(relevance) == 0:
        return 0.0
    discounts = np.log2(np.arange(2, len(relevance) + 2))
    return float(np.sum(relevance / discounts))


def _effort_for_recall(critical: np.ndarray, target: float) -> int:
    total = int(critical.sum())
    if total == 0:
        return 0
    needed = int(np.ceil(total * target))
    cumulative = np.cumsum(critical)
    positions = np.flatnonzero(cumulative >= needed)
    return int(positions[0] + 1) if len(positions) else len(critical)

"""Candidate selection rules of protocol v1.1 §6.4.

Primary (D1): maximize macro critical-step interval coverage@100, then minimize macro
FP@100, then maximize macro linear NDCG@100, then prefer fewer nonzero parameters,
then declared grid order. Secondary: maximize macro NDCG@100, then simplicity.
Ties use an absolute tolerance of 1e-12 for floating-point roundoff only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd


PRIMARY = "primary_coverage_fp_ndcg"
SECONDARY = "secondary_ndcg"


@dataclass(frozen=True)
class SelectionRecord:
    rule: str
    family: str
    selected_candidate: str
    macro_coverage: float | None
    macro_fp: float
    macro_ndcg: float | None
    coverage_scenarios: int
    fp_scenarios: int
    ndcg_scenarios: int
    candidates_considered: int
    remaining_after_steps: dict[str, int]
    coverage_fallback: bool
    ndcg_fallback: bool

    def to_record(self) -> dict[str, object]:
        record = asdict(self)
        record["remaining_after_steps"] = ";".join(f"{k}={v}" for k, v in self.remaining_after_steps.items())
        return record


def _common_eligible(frame: pd.DataFrame, column: str) -> list[str]:
    """Scenarios where the metric is defined; eligibility must not depend on the candidate."""

    defined = frame.assign(_defined=frame[column].notna()).groupby("inner_scenario")["_defined"].agg(["all", "any"])
    inconsistent = defined[defined["all"] != defined["any"]]
    if len(inconsistent):
        raise ValueError(f"{column} eligibility differs across candidates in {list(inconsistent.index)}")
    return sorted(defined.index[defined["all"]])


def select_candidate(inner: pd.DataFrame, rule: str = PRIMARY, tolerance: float = 1e-12) -> SelectionRecord:
    """Select one candidate of one family from its inner-fold metric table.

    ``inner`` has one row per (candidate_id, inner_scenario) with columns family,
    candidate_id, grid_index, n_nonzero, coverage, fp, ndcg.
    """

    families = inner["family"].unique()
    if len(families) != 1:
        raise ValueError("select_candidate works on one family at a time")
    scenarios = sorted(inner["inner_scenario"].unique())
    per_candidate = inner.groupby("candidate_id")["inner_scenario"].nunique()
    if (per_candidate != len(scenarios)).any():
        raise ValueError("every candidate needs metrics for every inner scenario")

    coverage_scenarios = _common_eligible(inner, "coverage")
    ndcg_scenarios = _common_eligible(inner, "ndcg")
    summary = inner.groupby("candidate_id").agg(grid_index=("grid_index", "first"), n_nonzero=("n_nonzero", "first"))
    summary["macro_fp"] = inner.groupby("candidate_id")["fp"].mean()
    summary["macro_coverage"] = (
        inner[inner["inner_scenario"].isin(coverage_scenarios)].groupby("candidate_id")["coverage"].mean()
        if coverage_scenarios else np.nan
    )
    summary["macro_ndcg"] = (
        inner[inner["inner_scenario"].isin(ndcg_scenarios)].groupby("candidate_id")["ndcg"].mean()
        if ndcg_scenarios else np.nan
    )

    remaining = summary
    steps: dict[str, int] = {}

    def keep_best(frame: pd.DataFrame, column: str, maximize: bool) -> pd.DataFrame:
        best = frame[column].max() if maximize else frame[column].min()
        mask = frame[column] >= best - tolerance if maximize else frame[column] <= best + tolerance
        return frame[mask]

    if rule == PRIMARY:
        if coverage_scenarios:
            remaining = keep_best(remaining, "macro_coverage", maximize=True)
        steps["coverage"] = len(remaining)
        remaining = keep_best(remaining, "macro_fp", maximize=False)
        steps["fp"] = len(remaining)
        if ndcg_scenarios:
            remaining = keep_best(remaining, "macro_ndcg", maximize=True)
        steps["ndcg"] = len(remaining)
    elif rule == SECONDARY:
        if ndcg_scenarios:
            remaining = keep_best(remaining, "macro_ndcg", maximize=True)
        steps["ndcg"] = len(remaining)
    else:
        raise ValueError(f"unknown selection rule {rule!r}")
    remaining = remaining[remaining["n_nonzero"] == remaining["n_nonzero"].min()]
    steps["simplicity"] = len(remaining)
    chosen_id = remaining.sort_values("grid_index").index[0]
    chosen = summary.loc[chosen_id]
    return SelectionRecord(
        rule=rule,
        family=str(families[0]),
        selected_candidate=str(chosen_id),
        macro_coverage=None if pd.isna(chosen["macro_coverage"]) else float(chosen["macro_coverage"]),
        macro_fp=float(chosen["macro_fp"]),
        macro_ndcg=None if pd.isna(chosen["macro_ndcg"]) else float(chosen["macro_ndcg"]),
        coverage_scenarios=len(coverage_scenarios),
        fp_scenarios=len(scenarios),
        ndcg_scenarios=len(ndcg_scenarios),
        candidates_considered=len(summary),
        remaining_after_steps=steps,
        coverage_fallback=rule == PRIMARY and not coverage_scenarios,
        ndcg_fallback=not ndcg_scenarios,
    )

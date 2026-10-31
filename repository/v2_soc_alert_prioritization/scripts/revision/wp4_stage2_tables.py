#!/usr/bin/env python
"""WP4 stage 2: build the declared tables T1–T5 and secondary tables from per-fold outputs.

Implements Section 6 of docs/revision/wp4/stage2_reporting_specification.md. Reads
results/revision_cose_04000/wp4/stage2/<run>/<split>/*.csv.gz and writes CSV tables plus a
markdown rendering of T1–T5 to docs/revision/wp4/stage2_tables/. No statistical test is computed
(paired tests are WP7).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = PROJECT_ROOT / "results/revision_cose_04000/wp4/stage2"
DEFAULT_OUT = PROJECT_ROOT / "docs/revision/wp4/stage2_tables"


def load(root: Path, run_prefix: str, table: str) -> pd.DataFrame:
    """Concatenate one table over runs; ``analysis_unit`` is the scenario, or the split for identifier hold-out."""

    frame = _load(root, run_prefix, table)
    if not frame.empty and "split" in frame:
        frame["analysis_unit"] = np.where(frame["split"].astype(str).str.startswith("holdout_group"), frame["split"], frame["held_out"])
    return frame


def _load(root: Path, run_prefix: str, table: str) -> pd.DataFrame:
    parts = []
    for run_dir in sorted(root.glob(f"{run_prefix}*")):
        if not run_dir.is_dir():
            continue
        for path in sorted(run_dir.glob(f"*/{table}.csv.gz")):
            if path.stat().st_size:
                try:
                    parts.append(pd.read_csv(path))
                except pd.errors.EmptyDataError:
                    continue
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def headline(frame: pd.DataFrame) -> pd.DataFrame:
    """Untuned references and primary-rule selections."""

    return frame[frame["rules"].astype(str).str.contains("untuned|primary")]


def label(frame: pd.DataFrame) -> pd.Series:
    return np.where(frame["rules"] == "untuned", frame["candidate_id"], frame["family"] + " (primary rule)")


def t1_primary(budgets: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    at100 = headline(budgets[budgets["budget"] == "k=100"]).copy()
    at100["method"] = label(at100)
    long = at100[["run", "split", "analysis_unit", "method", "candidate_id", "covered_intervals", "eligible_intervals",
                  "defined_intervals", "negatives_in_top", "coverage_eligible", "coverage_all"]]
    wide = long.assign(cell=lambda d: d["covered_intervals"].astype(int).astype(str) + "/" + d["defined_intervals"].astype(int).astype(str)
                       + " · FP " + d["negatives_in_top"].astype(int).astype(str))
    table = wide.pivot_table(index="method", columns="analysis_unit", values="cell", aggfunc="first")
    summary = long.groupby("method").agg(
        units=("analysis_unit", "nunique"),
        macro_coverage_eligible=("coverage_eligible", "mean"),
        macro_coverage_all=("coverage_all", "mean"),
        fp_median=("negatives_in_top", "median"), fp_min=("negatives_in_top", "min"), fp_max=("negatives_in_top", "max"),
    )
    for covered in range(5):
        summary[f"units_covering_{covered}"] = long.groupby("method")["covered_intervals"].apply(lambda s: int((s == covered).sum()))
    summary["selected_candidates"] = long.groupby("method")["candidate_id"].apply(lambda s: "; ".join(sorted(set(s))))
    return long, table.join(summary)


def t2_ties(cutoffs, seeds, expected, near) -> pd.DataFrame:
    c = headline(cutoffs[cutoffs["k"] == 100]).copy()
    c["method"] = label(c)
    out = c[["method", "analysis_unit", "order_share", "crosses_cutoff", "cutoff_block_size", "members_selected_by_tie_rule"]]
    if not seeds.empty:
        s = headline(seeds).copy()
        s["method"] = label(s)
        g = s.groupby(["method", "analysis_unit"])["covered_intervals"]
        perm = pd.DataFrame({"perm_covered_p2_5": g.quantile(0.025), "perm_covered_p97_5": g.quantile(0.975),
                             "perm_covered_min": g.min(), "perm_covered_max": g.max()}).reset_index()
        f = s.groupby(["method", "analysis_unit"])["negatives_in_top"]
        perm["perm_fp_p2_5"] = f.quantile(0.025).to_numpy()
        perm["perm_fp_p97_5"] = f.quantile(0.975).to_numpy()
        out = out.merge(perm, on=["method", "analysis_unit"], how="left")
    e = headline(expected[expected["k"] == 100]).copy()
    e["method"] = label(e)
    out = out.merge(e[["method", "analysis_unit", "expected_negatives_in_top", "expected_critical_recall"]], on=["method", "analysis_unit"], how="left")
    if not near.empty:
        nt = headline(near[near["budget"] == "k=100"]).copy()
        nt["method"] = label(nt)
        out = out.merge(nt[["method", "analysis_unit", "covered_intervals", "negatives_in_top"]].rename(
            columns={"covered_intervals": "near_tie_covered", "negatives_in_top": "near_tie_fp"}), on=["method", "analysis_unit"], how="left")
    return out.sort_values(["method", "analysis_unit"])


def t3_deep(budgets, efforts, first) -> pd.DataFrame:
    b = headline(budgets[budgets["budget"].isin(["k=100", "k=1000"])]).copy()
    b["method"] = label(b)
    out = b.pivot_table(index=["method", "analysis_unit"], columns="budget", values="critical_recall", aggfunc="first")
    out.columns = [f"critical_recall_{c.replace('=', '')}" for c in out.columns]
    e = headline(efforts[efforts["kind"] == "critical_recall"]).copy()
    e["method"] = label(e)
    ep = e.pivot_table(index=["method", "analysis_unit"], columns="target", values="queue_fraction", aggfunc="first")
    ep.columns = [f"effort_critical_recall_{c.replace('/', '_')}_queue_fraction" for c in ep.columns]
    f = headline(first).copy()
    f["method"] = label(f)
    fp = f.set_index(["method", "analysis_unit"])[["position", "critical_total"]].rename(columns={"position": "first_critical_rank"})
    return out.join(ep).join(fp).reset_index()


def t4_failures(root: Path, budgets, selections, learners, fallbacks) -> pd.DataFrame:
    rows = []
    for run, part in budgets.groupby("run"):
        rows.append({"run": run, "metric_rows": len(part), "coverage_eligible_na": int(part["coverage_eligible"].isna().sum()),
                     "ndcg_na": int(part["ndcg_linear"].isna().sum()), "critical_recall_na": int(part["critical_recall"].isna().sum()),
                     "empty_queues": int(part["empty_queue"].astype(bool).sum())})
    out = pd.DataFrame(rows)
    if not selections.empty:
        flags = selections.groupby("run").agg(coverage_selection_fallbacks=("coverage_fallback", lambda s: int(s.fillna(False).astype(bool).sum())),
                                              ndcg_selection_fallbacks=("ndcg_fallback", lambda s: int(s.fillna(False).astype(bool).sum())))
        if "selection_fallback" in selections:
            flags["learned_simplest_grid_point_fallbacks"] = selections.groupby("run")["selection_fallback"].apply(lambda s: int(s.notna().sum()))
        out = out.merge(flags.reset_index(), on="run", how="left")
    if not learners.empty:
        out = out.merge(learners.groupby("run")["fallback"].apply(lambda s: int(s.notna().sum())).rename("learner_fit_fallbacks").reset_index(),
                        on="run", how="left")
    if not fallbacks.empty:
        sums = fallbacks.groupby("run")[["class_height_detector_prior", "class_height_global_prior", "key_height_detector_prior",
                                         "key_height_global_prior", "unmapped", "excluded_identifier_alerts", "alerts"]].sum()
        out = out.merge(sums.reset_index(), on="run", how="left")
    manifest = root / "run_manifest.json"
    errors = []
    if manifest.exists():
        for invocation in json.loads(manifest.read_text())["invocations"]:
            errors += [f"{f['run']} {f['split']}: {f['error']}" for f in invocation["folds"] if "error" in f]
    out["fold_errors_logged"] = len(errors)
    return out


def t5_deferral(deep, coefficients) -> tuple[pd.DataFrame, pd.DataFrame]:
    d = deep.copy()
    d["method"] = np.where(d["rules"] == "untuned", d["candidate_id"], d["family"] + " (primary rule)")
    cause_cols = [c for c in d.columns if c.startswith("cause_")]
    agg = d.groupby(["run", "method"]).agg(folds=("analysis_unit", "nunique"), critical_total=("critical_total", "sum"),
                                           deep_deferred=("deep_deferred", "sum"),
                                           median_rank_fraction_p50=("critical_rank_fraction_p50", "median"),
                                           top_half_recurring_benign_share_median=("top_half_share_recurring_benign_negatives", "median"),
                                           **{c: (c, "sum") for c in cause_cols})
    agg["deep_deferred_share"] = agg["deep_deferred"] / agg["critical_total"]
    c = coefficients.copy()
    c["method"] = np.where(c["rules"] == "untuned", c["candidate_id"], c["family"] + " (primary rule)")
    coef = c.groupby(["run", "method", "z"])[["alerts", "gamma_le_0", "gamma_le_0_1"]].sum().reset_index()
    coef["share_le_0"] = coef["gamma_le_0"] / coef["alerts"]
    coef["share_le_0_1"] = coef["gamma_le_0_1"] / coef["alerts"]
    return agg.reset_index(), coef


def markdown(frame: pd.DataFrame, digits: int = 3) -> str:
    """Plain pipe table (no external dependency)."""

    def cell(value) -> str:
        if value is None or (isinstance(value, float) and np.isnan(value)):
            return "NA"
        if isinstance(value, (float, np.floating)):
            return f"{value:.{digits}f}".rstrip("0").rstrip(".") if not float(value).is_integer() else str(int(value))
        return str(value).replace("|", "\\|")

    header = "| " + " | ".join(map(str, frame.columns)) + " |"
    rule = "| " + " | ".join("---" for _ in frame.columns) + " |"
    body = ["| " + " | ".join(cell(v) for v in row) + " |" for row in frame.itertuples(index=False)]
    return "\n".join([header, rule, *body])


def render(out: Path, tags: list[str]) -> None:
    """Markdown rendering of T1, T2 (k = 100), T3, T4 and T5 for every run present."""

    lines = ["# WP4 stage 2 tables (generated)", "",
             "Generated by `scripts/revision/wp4_stage2_tables.py` from per-fold outputs. Coverage cells are covered/defined critical "
             "intervals at k = 100 with FP@100; with 4 critical intervals per AIT scenario, coverage moves in 25-point steps. "
             "Units are scenarios (identifier hold-out: scenario × group). No statistical test is reported here.", ""]
    for tag in tags:
        t1 = out / f"{tag}_t1_primary.csv"
        if not t1.exists():
            continue
        lines += [f"## {tag.upper()}", "", "### T1 primary endpoint (untuned references and primary-rule selections)", ""]
        frame = pd.read_csv(t1)
        units = [c for c in frame.columns if c not in {"method", "units", "macro_coverage_eligible", "macro_coverage_all", "fp_median",
                                                          "fp_min", "fp_max", "selected_candidates"} and not c.startswith("units_covering_")]
        summary = frame[["method", "units", "macro_coverage_eligible", "fp_median", "fp_min", "fp_max"]
                        + [f"units_covering_{i}" for i in range(5)]]
        if len(units) <= 10:
            lines += [markdown(frame[["method", *units]]), ""]
        lines += [markdown(summary.sort_values(["macro_coverage_eligible", "fp_median"], ascending=[False, True])), ""]
        t2 = pd.read_csv(out / f"{tag}_t2_ties.csv")
        agg = {"order_share_k100_median": ("order_share", "median"), "cutoff_crossed_units": ("crosses_cutoff", "sum"),
               "median_cutoff_block": ("cutoff_block_size", "median"), "tie_selected_members_median": ("members_selected_by_tie_rule", "median"),
               "expected_fp_median": ("expected_negatives_in_top", "median")}
        if "perm_covered_min" in t2:
            agg |= {"perm_covered_min_sum": ("perm_covered_min", "sum"), "perm_covered_max_sum": ("perm_covered_max", "sum"),
                    "near_tie_covered_sum": ("near_tie_covered", "sum")}
        lines += ["### T2 ties at k = 100 (summed or median over units; per-unit rows in the CSV)", "",
                  markdown(t2.groupby("method").agg(**agg).reset_index()), ""]
        t3 = pd.read_csv(out / f"{tag}_t3_deep_queue.csv")
        cols = [c for c in t3.columns if c.startswith(("critical_recall_", "effort_critical_recall_"))] + ["first_critical_rank"]
        lines += ["### T3 deep queue (median over units)", "", markdown(t3.groupby("method")[cols].median().reset_index()), ""]
        t5 = pd.read_csv(out / f"{tag}_t5_deferral.csv")
        keep = ["method", "critical_total", "deep_deferred", "deep_deferred_share", "cause_mapping_rejection", "cause_low_reliability",
                "cause_severity_reversal", "cause_tie_rule_displacement", "top_half_recurring_benign_share_median"]
        lines += ["### T5 deep deferral (critical alerts ranked beyond half the queue)", "", markdown(t5[keep]), ""]
    t4 = out / "t4_failures.csv"
    if t4.exists():
        lines += ["## T4 failures, fallbacks and NA counts", "", markdown(pd.read_csv(t4)), ""]
    (out / "stage2_tables.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(DEFAULT_ROOT))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()
    root, out = Path(args.root), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    written = {}

    def save(name: str, frame: pd.DataFrame) -> None:
        path = out / f"{name}.csv"
        frame.to_csv(path, index=False)
        written[name] = {"rows": len(frame), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    for run_prefix, tag in (("R1", "r1"), ("R2", "r2"), ("R3_", "r3"), ("R4_", "r4"), ("R5_", "r5"), ("R6", "r6"), ("R7", "r7")):
        budgets = load(root, run_prefix, "e1_budgets")
        if budgets.empty:
            continue
        budgets = budgets[budgets["run"].astype(str).str.startswith(run_prefix.rstrip("_"))]
        long, t1 = t1_primary(budgets)
        save(f"{tag}_t1_primary_long", long)
        save(f"{tag}_t1_primary", t1.reset_index())
        t2 = t2_ties(load(root, run_prefix, "e2_tie_cutoffs"), load(root, run_prefix, "e3_seed_k100"),
                     load(root, run_prefix, "e2_expected"), load(root, run_prefix, "e4_near_ties"))
        save(f"{tag}_t2_ties", t2)
        save(f"{tag}_t3_deep_queue", t3_deep(budgets, load(root, run_prefix, "e1_efforts"), load(root, run_prefix, "e1_first_critical")))
        deep, coefficients = t5_deferral(load(root, run_prefix, "e8_deep_deferral"), load(root, run_prefix, "e8_coefficients"))
        save(f"{tag}_t5_deferral", deep)
        save(f"{tag}_t5_coefficients", coefficients)
        secondary = budgets[(budgets["budget"] == "k=100") & budgets["rules"].astype(str).str.contains("secondary")]
        save(f"{tag}_secondary_rule_k100", secondary)
        for table in ("e5_within_subset", "e6_duplicates", "e6_cluster_summary", "e7_subgroup_mixed_queue", "e7_subgroup_within",
                      "e9_calibration", "e9_reliability_bins", "e10_agreement", "e11_context_tokens", "e12_selections"):
            frame = load(root, run_prefix, table)
            if not frame.empty:
                if table in {"e5_within_subset", "e6_duplicates", "e7_subgroup_mixed_queue", "e7_subgroup_within"} and "budget" in frame:
                    frame = frame[frame["budget"].isin(["k=100", None]) | frame["budget"].isna()]
                save(f"{tag}_{table}", frame)
    failures = t4_failures(root, load(root, "R", "e1_budgets"), load(root, "R", "e12_selections"),
                           load(root, "R", "e12_learner_diagnostics"), load(root, "R", "e12_fit_fallbacks"))
    save("t4_failures", failures)
    render(out, ["r1", "r2", "r3", "r4", "r5", "r6", "r7"])
    (out / "index.json").write_text(json.dumps({"source_root": str(root), "tables": written}, indent=1))
    print(json.dumps({k: v["rows"] for k, v in written.items()}, indent=0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

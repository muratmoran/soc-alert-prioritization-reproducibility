#!/usr/bin/env python
"""WP7: scenario-level statistical reporting (docs/revision/wp7/analysis_specification.md).

Inputs (hash-checked against their recorded identities):
- WP4 stage-2 tables: ~/soc_revision_data/wp4_stage2_tables, checked against docs/revision/wp4/stage2_tables/index.json.
- WP5 replay outputs: ~/soc_revision_data/wp5_replay, checked against docs/revision/wp5/replay_output_manifest.json.

Outputs (docs/revision/wp7/):
- primary_family.csv (6 prespecified tests, Holm) and exploratory_tests.csv (post hoc, unadjusted);
- per_scenario_effects.csv, descriptives.csv, delay_censoring.csv, replay_rates.csv, holdout_forward.csv;
- figures/*.pdf and wp7_manifest.json.

External data root: $SOC_REVISION_DATA (default ~/soc_revision_data).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.revision.paired_stats import holm_adjust, sign_flip_test  # noqa: E402

DATA = Path(os.environ.get("SOC_REVISION_DATA", Path.home() / "soc_revision_data")).expanduser()
STATIC = DATA / "wp4_stage2_tables"
REPLAY = DATA / "wp5_replay"
OUT = PROJECT_ROOT / "docs/revision/wp7"
SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]
NAMES = {
    "S1_linear_log_constrained (primary rule)": "S1", "A_additive (primary rule)": "A", "M_multiplicative (primary rule)": "M",
    "P_probability_proxy": "P", "S1_linear_log_constrained_key (primary rule)": "S1_key", "S0_linear_log_historical_key[kappa=1]": "S0_key",
    "R_severity_key_reliability": "R_severity_key", "O_severity": "O_severity", "O_oldest_first": "FIFO", "H_weighted": "H",
    "W_weighted (primary rule)": "W", "C_cost_sensitive (primary rule)": "C", "S0_linear_log_historical[kappa=1]": "S0",
    "S2_exponential_discount (primary rule)": "S2", "S2_exponential_discount_key (primary rule)": "S2_key",
    "L1_logistic (primary rule)": "L1", "L2_gradient_boosting (primary rule)": "L2", "O_newest_first": "LIFO", "O_reliability": "O_reliability",
    "R_key_reliability": "R_key", "O_native_rule_level": "O_native_rule_level", "O_native_suricata_severity": "O_native_suricata_severity",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_inputs() -> dict[str, object]:
    index = json.loads((PROJECT_ROOT / "docs/revision/wp4/stage2_tables/index.json").read_text())["tables"]
    for name in ("r1_t1_primary_long", "r1_t3_deep_queue", "r6_t1_primary_long", "r7_t1_primary_long"):
        if sha256(STATIC / f"{name}.csv") != index[name]["sha256"]:
            raise SystemExit(f"stage-2 table {name} does not match its recorded hash")
    manifest = json.loads((PROJECT_ROOT / "docs/revision/wp5/replay_output_manifest.json").read_text())
    if hashlib.sha256((REPLAY / "SHA256SUMS").read_bytes()).hexdigest() != manifest["sha256sums_sha256"]:
        raise SystemExit("replay SHA256SUMS does not match the recorded manifest")
    sums = dict(line.split("  ./")[::-1] for line in (REPLAY / "SHA256SUMS").read_text().splitlines())
    for path in REPLAY.glob("P*/loso_*/summaries.csv.gz"):
        if sha256(path) != sums[str(path.relative_to(REPLAY))]:
            raise SystemExit(f"replay file {path} does not match SHA256SUMS")
    return {"stage2_tables_index_sha256": sha256(PROJECT_ROOT / "docs/revision/wp4/stage2_tables/index.json"),
            "replay_sha256sums_sha256": manifest["sha256sums_sha256"]}


def static_frame() -> pd.DataFrame:
    long = pd.read_csv(STATIC / "r1_t1_primary_long.csv")
    deep = pd.read_csv(STATIC / "r1_t3_deep_queue.csv")
    frame = long.merge(deep[["method", "analysis_unit", "critical_recall_k100", "critical_total", "first_critical_rank"]],
                       on=["method", "analysis_unit"], how="left")
    frame = frame[frame["method"].isin(NAMES)].assign(ranker=lambda d: d["method"].map(NAMES), scenario=lambda d: d["analysis_unit"])
    return frame


def replay_frame() -> pd.DataFrame:
    parts = [pd.read_csv(p) for p in sorted(REPLAY.glob("P*/loso_*/summaries.csv.gz"))]
    frame = pd.concat(parts, ignore_index=True)
    rules = frame["rules"].astype(str)
    frame["method"] = np.where(rules == "untuned", frame["candidate_id"],
                               np.where(rules.str.contains("primary"), frame["family"] + " (primary rule)", frame["family"] + " (secondary rule)"))
    frame = frame[frame["method"].isin(NAMES)].assign(ranker=lambda d: d["method"].map(NAMES), scenario=lambda d: d["held_out"])
    return frame


def paired(values: pd.DataFrame, first: str, second: str, column: str) -> pd.DataFrame:
    wide = values.pivot_table(index="scenario", columns="ranker", values=column, aggfunc="first").reindex(SCENARIOS)
    if wide[[first, second]].isna().any().any():
        raise SystemExit(f"missing scenario values for {first} or {second} on {column}")
    return pd.DataFrame({"scenario": SCENARIOS, "first": wide[first].to_numpy(float), "second": wide[second].to_numpy(float),
                         "difference": (wide[first] - wide[second]).to_numpy(float)})


def test_rows(contrasts, static, replay, family: str) -> tuple[list[dict], list[dict]]:
    tests, effects = [], []
    for contrast_id, first, second, metrics in contrasts:
        for source, column, label in metrics:
            data = static if source == "static" else replay
            pair = paired(data, first, second, column)
            result = sign_flip_test(pair["difference"])
            tests.append({"family": family, "id": contrast_id, "contrast": f"{first} - {second}", "source": source, "metric": label,
                          "unit": "held-out scenario (n = 8)", "first_mean": pair["first"].mean(), "second_mean": pair["second"].mean(),
                          **result.to_record(), "range_min": pair["difference"].min(), "range_max": pair["difference"].max()})
            for row in pair.itertuples(index=False):
                effects.append({"family": family, "id": contrast_id, "contrast": f"{first} - {second}", "source": source, "metric": label,
                                "scenario": row.scenario, "first": row.first, "second": row.second, "difference": row.difference})
    return tests, effects


def descriptives(static: pd.DataFrame, replay: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for ranker, part in static.groupby("ranker"):
        part = part.set_index("scenario").reindex(SCENARIOS)
        rows += [
            {"source": "static k=100", "ranker": ranker, "metric": "critical-interval coverage", "unit_values": ";".join(f"{v:g}" for v in part["coverage_eligible"]),
             "macro_mean": part["coverage_eligible"].mean(), "pooled": part["covered_intervals"].sum() / part["eligible_intervals"].sum(),
             "pooled_numerator": part["covered_intervals"].sum(), "pooled_denominator": part["eligible_intervals"].sum(),
             "median": part["coverage_eligible"].median(), "min": part["coverage_eligible"].min(), "max": part["coverage_eligible"].max()},
            {"source": "static k=100", "ranker": ranker, "metric": "FP@100 (count of 100)", "unit_values": ";".join(f"{v:g}" for v in part["negatives_in_top"]),
             "macro_mean": part["negatives_in_top"].mean(), "pooled": part["negatives_in_top"].sum() / 800, "pooled_numerator": part["negatives_in_top"].sum(),
             "pooled_denominator": 800, "median": part["negatives_in_top"].median(), "min": part["negatives_in_top"].min(), "max": part["negatives_in_top"].max()},
            {"source": "static k=100", "ranker": ranker, "metric": "alert-level critical recall@100", "unit_values": ";".join(f"{v:.4g}" for v in part["critical_recall_k100"]),
             "macro_mean": part["critical_recall_k100"].mean(), "pooled": (part["critical_recall_k100"] * part["critical_total"]).sum() / part["critical_total"].sum(),
             "pooled_numerator": round((part["critical_recall_k100"] * part["critical_total"]).sum()), "pooled_denominator": part["critical_total"].sum(),
             "median": part["critical_recall_k100"].median(), "min": part["critical_recall_k100"].min(), "max": part["critical_recall_k100"].max()},
        ]
    for (policy, rate, ranker), part in replay.groupby(["policy", "rate_per_hour", "ranker"]):
        part = part.set_index("scenario").reindex(SCENARIOS)
        source = f"replay {policy} {rate:g}/h"
        for metric, num, den, ratio in (
            ("critical-interval coverage", "covered_intervals", "defined_intervals", None),
            ("FP investigations share", "fp_investigations", "investigations", None),
            ("critical recall by horizon", "critical_investigations", "critical_total", None),
            ("starved critical share", "starved_critical", "critical_total", None),
        ):
            per_unit = part[num] / part[den]
            rows.append({"source": source, "ranker": ranker, "metric": metric, "unit_values": ";".join(f"{v:.4g}" for v in per_unit),
                         "macro_mean": per_unit.mean(), "pooled": part[num].sum() / part[den].sum(), "pooled_numerator": part[num].sum(),
                         "pooled_denominator": part[den].sum(), "median": per_unit.median(), "min": per_unit.min(), "max": per_unit.max()})
    return pd.DataFrame(rows)


def delay_table(replay: pd.DataFrame) -> pd.DataFrame:
    keep = ["P", "S1", "S0_key", "S1_key", "R_severity_key", "O_severity", "FIFO"]
    part = replay[(replay["policy"] == "P1") & (replay["ranker"].isin(keep))].copy()
    part["critical_investigated_within_24h_share_of_investigated"] = np.where(
        part["critical_investigations"] > 0, part["critical_recall_within_24h"] * part["critical_total"] / part["critical_investigations"], np.nan)
    columns = ["rate_per_hour", "ranker", "scenario", "horizon_hours", "investigations", "defined_intervals", "covered_intervals", "censored_intervals",
               "median_delay_hours_detected", "restricted_mean_delay_hours_lower_bound", "intervals_covered_within_1h", "intervals_covered_within_24h",
               "critical_total", "critical_investigations", "starved_critical", "starved_critical_share", "critical_recall_within_1h",
               "critical_recall_within_24h", "critical_investigated_within_24h_share_of_investigated", "fp_investigations", "positive_investigations"]
    return part[columns].sort_values(["rate_per_hour", "ranker", "scenario"])


def figures(effects: pd.DataFrame, replay: pd.DataFrame, out: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out.mkdir(parents=True, exist_ok=True)
    written = []
    for family, filename in (("primary", "paired_effects_primary.pdf"), ("exploratory", "paired_effects_exploratory.pdf")):
        part = effects[effects["family"] == family]
        panels = list(part.groupby(["contrast", "source", "metric"], sort=False))
        cols = 2 if family == "primary" else 4
        rows = int(np.ceil(len(panels) / cols))
        fig, axes = plt.subplots(rows, cols, figsize=(3.2 * cols, 2.4 * rows), squeeze=False)
        for ax, ((contrast, source, metric), data) in zip(axes.ravel(), panels):
            ax.axhline(0, color="0.6", lw=0.8)
            ax.scatter(range(len(data)), data["difference"], s=18, color="black", zorder=3)
            ax.set_xticks(range(len(data)))
            ax.set_xticklabels([s[:4] for s in data["scenario"]], rotation=90, fontsize=6)
            ax.set_title(f"{contrast}\n{source}: {metric}", fontsize=7)
            ax.tick_params(axis="y", labelsize=6)
        for ax in axes.ravel()[len(panels):]:
            ax.axis("off")
        fig.tight_layout()
        fig.savefig(out / filename, metadata={"CreationDate": None})
        plt.close(fig)
        written.append(filename)
    part = replay[(replay["policy"] == "P1") & (replay["rate_per_hour"] == 12.0) & replay["ranker"].isin(["P", "S1", "S0_key", "S1_key", "R_severity_key", "O_severity", "FIFO"])]
    fig, ax = plt.subplots(figsize=(4.8, 3.4))
    markers = {"P": "o", "S1": "x", "S0_key": "s", "S1_key": "^", "R_severity_key": "D", "O_severity": "v", "FIFO": "*"}
    for ranker, data in part.groupby("ranker"):
        ax.scatter(data["fp_investigations"] / data["investigations"], data["covered_intervals"] + np.linspace(-0.15, 0.15, len(data)),
                   marker=markers[ranker], s=22, label=ranker, facecolors="none" if ranker != "S1" else None, edgecolors="black" if ranker != "S1" else None,
                   color="black")
    ax.set_xlabel("FP investigations / investigations (per scenario)", fontsize=8)
    ax.set_ylabel("critical intervals covered (of 4, jittered)", fontsize=8)
    ax.legend(fontsize=6, frameon=False, ncol=2)
    ax.tick_params(labelsize=7)
    fig.tight_layout()
    fig.savefig(out / "replay_coverage_fp_by_scenario.pdf", metadata={"CreationDate": None})
    plt.close(fig)
    written.append("replay_coverage_fp_by_scenario.pdf")
    return written


def main() -> int:
    identities = verify_inputs()
    static = static_frame()
    replay = replay_frame()
    replay12 = replay[(replay["policy"] == "P1") & (replay["rate_per_hour"] == 12.0)]
    OUT.mkdir(parents=True, exist_ok=True)

    primary_contrasts = [(f"PF{i + 1}", "S1", comparator, [("static", "coverage_eligible", "coverage@100"), ("static", "negatives_in_top", "FP@100")])
                         for i, comparator in enumerate(["A", "M", "P"])]
    primary, effects_primary = test_rows(primary_contrasts, static, replay12, "primary")
    adjusted = holm_adjust([t["p_two_sided"] for t in primary])
    for test, p_holm in zip(primary, adjusted):
        test["p_holm"] = float(p_holm)
        test["reject_at_familywise_0.05"] = bool(p_holm <= 0.05)
    exploratory_contrasts = [
        (cid, first, second, [("static", "covered_intervals", "covered intervals@100"), ("static", "negatives_in_top", "FP@100"),
                              ("replay P1 12/h", "covered_intervals", "replay covered intervals"), ("replay P1 12/h", "fp_investigations", "replay FP investigations")])
        for cid, first, second in (("X1", "S1_key", "S1"), ("X2", "S0_key", "P"), ("X3", "R_severity_key", "P"))
    ]
    static_for_x = static
    exploratory, effects_x = [], []
    for cid, first, second, metrics in exploratory_contrasts:
        for source, column, label in metrics:
            data = static_for_x if source == "static" else replay12
            pair = paired(data, first, second, column)
            result = sign_flip_test(pair["difference"])
            exploratory.append({"family": "exploratory (post hoc, unadjusted)", "id": cid, "contrast": f"{first} - {second}", "source": source,
                                "metric": label, "unit": "held-out scenario (n = 8)", "first_mean": pair["first"].mean(), "second_mean": pair["second"].mean(),
                                **result.to_record(), "range_min": pair["difference"].min(), "range_max": pair["difference"].max()})
            for row in pair.itertuples(index=False):
                effects_x.append({"family": "exploratory", "id": cid, "contrast": f"{first} - {second}", "source": source, "metric": label,
                                  "scenario": row.scenario, "first": row.first, "second": row.second, "difference": row.difference})
    effects = pd.DataFrame(effects_primary + effects_x)
    pd.DataFrame(primary).to_csv(OUT / "primary_family.csv", index=False)
    pd.DataFrame(exploratory).to_csv(OUT / "exploratory_tests.csv", index=False)
    effects.to_csv(OUT / "per_scenario_effects.csv", index=False)
    descriptives(static, replay).to_csv(OUT / "descriptives.csv", index=False)
    delay_table(replay).to_csv(OUT / "delay_censoring.csv", index=False)

    rates = replay[replay["policy"].isin(["P1", "P2"])].groupby(["policy", "rate_per_hour", "ranker"]).agg(
        investigations_total=("investigations", "sum"), covered_intervals_pooled=("covered_intervals", "sum"),
        fp_investigations_pooled=("fp_investigations", "sum"), critical_investigations_pooled=("critical_investigations", "sum"),
        starved_critical_pooled=("starved_critical", "sum"), critical_total_pooled=("critical_total", "sum"),
        scenarios=("scenario", "nunique")).reset_index()
    rates.to_csv(OUT / "replay_rates.csv", index=False)

    holdout = pd.read_csv(STATIC / "r6_t1_primary_long.csv")
    holdout["group"] = holdout["split"].str.extract(r"holdout_group_(\d)")[0].astype(int)
    holdout["held_out"] = holdout["split"].str.split(":").str[-1]
    holdout = holdout[holdout["method"].isin(NAMES)].assign(ranker=lambda d: d["method"].map(NAMES))
    forward = pd.read_csv(STATIC / "r7_t1_primary_long.csv")
    forward["held_out"] = forward["split"].str.split(":").str[-1]
    forward = forward[forward["method"].isin(NAMES)].assign(ranker=lambda d: d["method"].map(NAMES))
    hf = pd.concat([
        holdout.groupby(["ranker", "group"]).agg(units=("held_out", "nunique"), covered_intervals=("covered_intervals", "sum"),
                                                 defined_intervals=("defined_intervals", "sum"), fp_median=("negatives_in_top", "median")).reset_index().assign(experiment="identifier hold-out (R6)"),
        forward.groupby(["ranker"]).agg(units=("held_out", "nunique"), covered_intervals=("covered_intervals", "sum"),
                                        defined_intervals=("defined_intervals", "sum"), fp_median=("negatives_in_top", "median")).reset_index().assign(experiment="forward chaining (R7)", group=np.nan),
    ])
    hf.to_csv(OUT / "holdout_forward.csv", index=False)
    written_figures = figures(effects, replay, OUT / "figures")

    manifest = {"inputs": identities, "script_sha256": sha256(Path(__file__)),
                "stats_module_sha256": sha256(PROJECT_ROOT / "src/soc_alert_ranking/revision/paired_stats.py"),
                "outputs": {p.name: sha256(p) for p in sorted(OUT.glob("*.csv"))},
                "figures": {name: sha256(OUT / "figures" / name) for name in written_figures}}
    (OUT / "wp7_manifest.json").write_text(json.dumps(manifest, indent=1))
    pd.set_option("display.width", 250)
    print(pd.DataFrame(primary)[["id", "contrast", "metric", "first_mean", "second_mean", "mean_difference", "positive", "negative", "zero", "p_two_sided", "p_holm"]].to_string(index=False))
    print(pd.DataFrame(exploratory)[["id", "contrast", "source", "metric", "first_mean", "second_mean", "mean_difference", "positive", "negative", "zero", "p_two_sided"]].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

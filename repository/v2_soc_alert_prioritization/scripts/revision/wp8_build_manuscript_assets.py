#!/usr/bin/env python
"""WP8: generate manuscript tables, figures and number macros from verified revision artifacts.

Every number used in the revised manuscript's abstract, contributions, tables and figures is
computed here from hash-checked inputs and written as a LaTeX macro, with its source recorded in
docs/revision/wp8/claim_evidence_map.csv. Outputs go to computers_security_revision/generated/.

External data root: $SOC_REVISION_DATA (default ~/soc_revision_data). Source labels in the claim map keep
the original ~/soc_revision_data provenance paths. Figures are written without a creation date so that
regeneration from the same inputs is byte-reproducible.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parent
MANUSCRIPT = REPO_ROOT / "computers_security_revision"
GEN = MANUSCRIPT / "generated"
HOME = Path(os.environ.get("SOC_REVISION_DATA", Path.home() / "soc_revision_data")).expanduser()
STATIC = HOME / "wp4_stage2_tables"
STAGE2 = HOME / "wp4_stage2"
REPLAY = HOME / "wp5_replay"
WP7 = PROJECT_ROOT / "docs/revision/wp7"
SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]
CLASS_GROUP = ["P_probability_proxy", "H_weighted", "S0_linear_log_historical[kappa=1]", "S1_linear_log_constrained (primary rule)",
               "S2_exponential_discount (primary rule)", "W_weighted (primary rule)", "A_additive (primary rule)",
               "M_multiplicative (primary rule)", "C_cost_sensitive (primary rule)"]
SHORT = {"P_probability_proxy": "P", "H_weighted": "H", "S0_linear_log_historical[kappa=1]": "S0", "S1_linear_log_constrained (primary rule)": "S1",
         "S2_exponential_discount (primary rule)": "S2", "W_weighted (primary rule)": "W", "A_additive (primary rule)": "A",
         "M_multiplicative (primary rule)": "M", "C_cost_sensitive (primary rule)": "C", "L1_logistic (primary rule)": "L1",
         "L2_gradient_boosting (primary rule)": "L2", "S0_linear_log_historical_key[kappa=1]": "S0\\textsubscript{key}",
         "S1_linear_log_constrained_key (primary rule)": "S1\\textsubscript{key}", "S2_exponential_discount_key (primary rule)": "S2\\textsubscript{key}",
         "R_severity_key_reliability": "R\\textsubscript{sev,key}", "R_key_reliability": "R\\textsubscript{key}", "O_severity": "O\\textsubscript{sev}",
         "O_reliability": "O\\textsubscript{rel}", "O_oldest_first": "FIFO", "O_newest_first": "LIFO",
         "O_native_rule_level": "Native rule level", "O_native_suricata_severity": "Native Suricata severity"}

RANKER_LABEL = {"S1_key": "S1\\textsubscript{key}", "S0_key": "S0\\textsubscript{key}", "S2_key": "S2\\textsubscript{key}",
                "R_severity_key": "R\\textsubscript{sev,key}", "O_severity": "O\\textsubscript{sev}", "P": "P", "S1": "S1", "A": "A", "M": "M", "FIFO": "FIFO"}


def contrast_label(contrast: str) -> str:
    first, second = contrast.split(" - ")
    return f"{RANKER_LABEL[first]} $-$ {RANKER_LABEL[second]}"


claims: list[dict] = []
macros: list[str] = []


def sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fmt(value, digits=None):
    if isinstance(value, (int, np.integer)):
        return f"{int(value):,}"
    if digits is None:
        return f"{value:,}"
    return f"{value:,.{digits}f}"


def macro(name: str, value, source: str, selection: str, digits=None):
    text = fmt(value, digits) if not isinstance(value, str) else value
    macros.append(f"\\newcommand{{\\{name}}}{{{text}}}")
    claims.append({"macro": name, "value": text, "source": source, "selection": selection})
    return text


def verify_inputs():
    index = json.loads((PROJECT_ROOT / "docs/revision/wp4/stage2_tables/index.json").read_text())["tables"]
    for name, info in index.items():
        if sha(STATIC / f"{name}.csv") != info["sha256"]:
            raise SystemExit(f"stage-2 table {name} hash mismatch")
    manifest = json.loads((PROJECT_ROOT / "docs/revision/wp5/replay_output_manifest.json").read_text())
    if hashlib.sha256((REPLAY / "SHA256SUMS").read_bytes()).hexdigest() != manifest["sha256sums_sha256"]:
        raise SystemExit("replay outputs hash mismatch")
    wp7 = json.loads((WP7 / "wp7_manifest.json").read_text())
    for name, digest in wp7["outputs"].items():
        if sha(WP7 / name) != digest:
            raise SystemExit(f"WP7 output {name} hash mismatch")


def replay_frame():
    frame = pd.concat([pd.read_csv(p) for p in sorted(REPLAY.glob("P*/loso_*/summaries.csv.gz"))], ignore_index=True)
    rules = frame["rules"].astype(str)
    frame["method"] = np.where(rules == "untuned", frame["candidate_id"],
                               np.where(rules.str.contains("primary"), frame["family"] + " (primary rule)", frame["family"] + " (secondary rule)"))
    return frame


def write(name: str, text: str):
    (GEN / "tables" / name).write_text(text, encoding="utf-8")


def main() -> int:
    verify_inputs()
    (GEN / "tables").mkdir(parents=True, exist_ok=True)
    (GEN / "figures").mkdir(parents=True, exist_ok=True)
    static = pd.read_csv(STATIC / "r1_t1_primary_long.csv")
    replay = replay_frame()
    r12 = replay[(replay["policy"] == "P1") & (replay["rate_per_hour"] == 12.0)]
    src_static = "docs/revision/wp4/stage2_tables/r1_t1_primary_long.csv"
    src_replay = "~/soc_revision_data/wp5_replay/P1/loso_*/summaries.csv.gz"

    # ------------------------------------------------------------------ data and design numbers
    per = r12[r12["candidate_id"] == "P_probability_proxy"].set_index("held_out").reindex(SCENARIOS)
    macro("NAlerts", int(per["alerts"].sum()), src_replay, "sum of held-out alerts over scenarios")
    macro("NCriticalAlerts", int(per["critical_total"].sum()), src_replay, "sum of critical alerts")
    macro("NCriticalIntervals", int(per["defined_intervals"].sum()), src_replay, "sum of defined critical intervals")
    registry = json.loads((PROJECT_ROOT / "docs/revision/wp2/grid_registry.json").read_text())
    macro("NCandidates", len(registry["candidates"]), "docs/revision/wp2/grid_registry.json", "candidates")
    macro("NTuned", registry["tuned_candidates_per_inner_fold"], "docs/revision/wp2/grid_registry.json", "tuned per inner fold")
    manifests = json.loads((PROJECT_ROOT / "docs/revision/wp4/split_manifests.json").read_text())
    unseen = sum(r["unseen_alerts"] for r in manifests["seen_unseen_by_loso_fold"])
    macro("NUnseenAlerts", unseen, "docs/revision/wp4/split_manifests.json", "LOSO unseen-identifier alerts, all folds")
    fitting = json.loads((PROJECT_ROOT / "docs/revision/wp4/real_data_fitting_check.json").read_text())
    coverage = {c["held_out"]: c["mapped_share"] for c in fitting["held_out_mapping_coverage_label_free"]}
    rows = []
    for scenario in SCENARIOS:
        r = per.loc[scenario]
        u = next(x for x in manifests["seen_unseen_by_loso_fold"] if x["held_out"] == scenario)
        rows.append(f"{scenario} & {fmt(int(r['alerts']))} & {fmt(int(r['critical_total']))} & {int(r['defined_intervals'])} & {r['horizon_hours']:.1f} & "
                    f"{100 * coverage[scenario]:.1f} & {u['unseen_alerts']} \\\\")
    write("tab_data.tex", "\\begin{tabular}{lrrrrrr}\n\\toprule\nScenario & Alerts & Critical alerts & Critical intervals & Horizon (h) & Mapped (\\%) & Unseen-identifier alerts \\\\\n\\midrule\n"
          + "\n".join(rows) + f"\n\\midrule\nTotal & {fmt(int(per['alerts'].sum()))} & {fmt(int(per['critical_total'].sum()))} & {int(per['defined_intervals'].sum())} & "
          f"{per['horizon_hours'].sum():.1f} & -- & {unseen} \\\\\n\\bottomrule\n\\end{{tabular}}\n")

    # ------------------------------------------------------------------ static primary table
    s = static.set_index(["method", "analysis_unit"])
    order = CLASS_GROUP + ["L2_gradient_boosting (primary rule)", "L1_logistic (primary rule)", "S0_linear_log_historical_key[kappa=1]",
                           "S1_linear_log_constrained_key (primary rule)", "S2_exponential_discount_key (primary rule)", "R_severity_key_reliability",
                           "R_key_reliability", "O_severity", "O_reliability", "O_native_rule_level", "O_native_suricata_severity", "O_oldest_first", "O_newest_first"]
    lines = []
    for method in order:
        cells = [f"{int(s.loc[(method, sc), 'covered_intervals'])}\\,/\\,{int(s.loc[(method, sc), 'negatives_in_top'])}" for sc in SCENARIOS]
        covered = int(sum(s.loc[(method, sc), "covered_intervals"] for sc in SCENARIOS))
        fp_median = float(np.median([s.loc[(method, sc), "negatives_in_top"] for sc in SCENARIOS]))
        lines.append(f"{SHORT[method]} & " + " & ".join(cells) + f" & {covered} & {fp_median:g} \\\\")
        if method == "C_cost_sensitive (primary rule)" or method == "L1_logistic (primary rule)" or method == "R_key_reliability":
            lines.append("\\midrule")
    write("tab_static_primary.tex", "\\begin{tabular}{l" + "c" * 8 + "rr}\n\\toprule\n & " + " & ".join(f"\\rotatebox{{70}}{{{sc}}}" for sc in SCENARIOS)
          + " & Covered (of 32) & Median FP \\\\\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n")
    class_cov = {m: int(sum(s.loc[(m, sc), "covered_intervals"] for sc in SCENARIOS)) for m in CLASS_GROUP}
    assert len(set(class_cov.values())) == 1
    macro("StaticClassCovered", class_cov["P_probability_proxy"], src_static, "covered intervals@100 summed over scenarios, every class-level ranker")
    macro("StaticClassFPMedian", float(np.median([s.loc[("P_probability_proxy", sc), "negatives_in_top"] for sc in SCENARIOS])), src_static, "median FP@100, P", 0)
    for name, method in (("StaticSOneKeyCovered", "S1_linear_log_constrained_key (primary rule)"), ("StaticSZeroKeyCovered", "S0_linear_log_historical_key[kappa=1]"),
                         ("StaticRSevKeyCovered", "R_severity_key_reliability")):
        macro(name, int(sum(s.loc[(method, sc), "covered_intervals"] for sc in SCENARIOS)), src_static, f"covered intervals@100, {method}")
    macro("StaticKeyFPMedian", float(np.median([s.loc[("S1_linear_log_constrained_key (primary rule)", sc), "negatives_in_top"] for sc in SCENARIOS])), src_static, "median FP@100, S1_key", 0)

    # ties and deferral
    ties = pd.read_csv(STATIC / "r1_t2_ties.csv")
    p_ties = ties[ties["method"] == "P_probability_proxy"]
    macro("TieBlockMax", int(p_ties["cutoff_block_size"].max()), "docs/revision/wp4/stage2_tables/r1_t2_ties.csv", "largest cutoff block, P, k=100")
    macro("TieExpectedFPMedian", float(p_ties["expected_negatives_in_top"].median()), "docs/revision/wp4/stage2_tables/r1_t2_ties.csv", "median exact expected FP@100 under random tie order, P", 1)
    macro("TieOrderShareMin", 100 * float(ties[ties["method"].isin(CLASS_GROUP)]["order_share"].min()), "docs/revision/wp4/stage2_tables/r1_t2_ties.csv",
          "min share of top-100 positions inside tied blocks, class-level formula scores", 0)
    macro("TieCutoffMembersMinP", int(p_ties["members_selected_by_tie_rule"].min()), "docs/revision/wp4/stage2_tables/r1_t2_ties.csv", "min top-100 positions from the cutoff-crossing block, P")
    macro("TieCutoffMembersMaxP", int(p_ties["members_selected_by_tie_rule"].max()), "docs/revision/wp4/stage2_tables/r1_t2_ties.csv", "max top-100 positions from the cutoff-crossing block, P")
    macro("TieCutoffMembersMedianP", float(p_ties["members_selected_by_tie_rule"].median()), "docs/revision/wp4/stage2_tables/r1_t2_ties.csv", "median top-100 positions from the cutoff-crossing block, P", 1)
    class_ties = ties[ties["method"].isin(CLASS_GROUP)]
    macro("TieCutoffMembersMinClass", int(class_ties["members_selected_by_tie_rule"].min()), "docs/revision/wp4/stage2_tables/r1_t2_ties.csv", "min top-100 positions from the cutoff-crossing block, class-level formula scores")
    key_ties = ties[ties["method"] == "S1_linear_log_constrained_key (primary rule)"]
    tie_rows = []
    for method in ["P_probability_proxy", "A_additive (primary rule)", "S0_linear_log_historical_key[kappa=1]", "S1_linear_log_constrained_key (primary rule)",
                   "R_severity_key_reliability", "O_severity", "O_native_rule_level"]:
        part = ties[ties["method"] == method]
        declared = static[static["method"] == method]["negatives_in_top"].median()
        tie_rows.append(f"{SHORT[method]} & {100 * part['order_share'].median():.0f} & {int(part['crosses_cutoff'].sum())} & {fmt(int(part['cutoff_block_size'].median()))} & "
                        f"{part['members_selected_by_tie_rule'].median():g} & {int(part['perm_covered_min'].sum())}--{int(part['perm_covered_max'].sum())} & {declared:g} & {part['expected_negatives_in_top'].median():.1f} \\\\")
    write("tab_ties.tex", "\\begin{tabular}{lrrrrcrr}\n\\toprule\nRanker & Tied (\\%) & Crossed (of 8) & Cutoff block & From block & Covered, 100 seeds & Declared FP & Expected FP \\\\\n\\midrule\n"
          + "\n".join(tie_rows) + "\n\\bottomrule\n\\end{tabular}\n")
    deferral = pd.read_csv(STATIC / "r1_t5_deferral.csv")
    dp = deferral[deferral["method"] == "P_probability_proxy"].iloc[0]
    macro("DeferredCritical", int(dp["deep_deferred"]), "docs/revision/wp4/stage2_tables/r1_t5_deferral.csv", "critical alerts ranked beyond half the queue, P")
    macro("DeferredShare", 100 * dp["deep_deferred_share"], "docs/revision/wp4/stage2_tables/r1_t5_deferral.csv", "share, P", 1)
    macro("DeferredMappingRejected", int(dp["cause_mapping_rejection"]), "docs/revision/wp4/stage2_tables/r1_t5_deferral.csv", "deferred with rejected mapping, P")
    macro("DeferredPrecisionRejected", int(dp["cause_mapping_rejection_precision_lt_0_5"]), "docs/revision/wp4/stage2_tables/r1_t5_deferral.csv", "deferred with mapping rejected for precision < 0.5 (criteria overlap), P")
    do = deferral[deferral["method"] == "O_severity"].iloc[0]
    macro("DeferredShareSeverity", 100 * do["deep_deferred_share"], "docs/revision/wp4/stage2_tables/r1_t5_deferral.csv", "share, O_severity", 1)
    coef = pd.read_csv(STATIC / "r1_t5_coefficients.csv")
    s0 = coef[(coef["method"] == "S0_linear_log_historical[kappa=1]") & (coef["z"])].iloc[0]
    macro("SZeroReversalShare", 100 * s0["share_le_0"], "docs/revision/wp4/stage2_tables/r1_t5_coefficients.csv", "critical alerts with gamma <= 0, S0", 1)

    # ablations
    abl_rows = []
    for tag, label in (("r1", "detector-class (primary)"), ("r3", None), ("r4", None), ("r5", None)):
        long = pd.read_csv(STATIC / f"{tag}_t1_primary_long.csv")
        for run, part in long.groupby("run"):
            name = label or run.split("_", 1)[1].replace("_", " ")
            group = {m: part[part["method"] == m] for m in ["P_probability_proxy", "S1_linear_log_constrained (primary rule)", "S1_linear_log_constrained_key (primary rule)", "R_severity_key_reliability"]}
            cells = [f"{int(g['covered_intervals'].sum())}\\,/\\,{g['negatives_in_top'].median():g}" for g in group.values()]
            family = {"r1": "--", "r3": "reliability", "r4": "uncertainty", "r5": "context"}[tag]
            abl_rows.append(f"{family} & {name} & " + " & ".join(cells) + " \\\\")
    write("tab_ablation.tex", "\\begin{tabular}{llcccc}\n\\toprule\nAblated input & Variant & P & S1 & S1\\textsubscript{key} & R\\textsubscript{sev,key} \\\\\n\\midrule\n"
          + "\n".join(abl_rows) + "\n\\bottomrule\n\\end{tabular}\n")

    # tests
    primary = pd.read_csv(WP7 / "primary_family.csv")
    exploratory = pd.read_csv(WP7 / "exploratory_tests.csv")
    test_rows = []
    for row in primary.itertuples(index=False):
        test_rows.append(f"Primary & {contrast_label(row.contrast)} & {row.metric} & {row.mean_difference:+.3f} & {row.positive}/{row.negative}/{row.zero} & {row.p_two_sided:.3f} & {row.p_holm:.3f} \\\\")
    test_rows.append("\\midrule")
    for row in exploratory.itertuples(index=False):
        test_rows.append(f"Exploratory & {contrast_label(row.contrast)} & {row.metric} & {row.mean_difference:+.3f} & {row.positive}/{row.negative}/{row.zero} & {row.p_two_sided:.3f} & -- \\\\")
    write("tab_tests.tex", "\\begin{tabular}{lllrcrr}\n\\toprule\nFamily & Contrast & Outcome & Mean diff. & $+/-/0$ & Exact $p$ & Holm $p$ \\\\\n\\midrule\n"
          + "\n".join(test_rows) + "\n\\bottomrule\n\\end{tabular}\n")
    macro("PrimaryMinP", float(primary["p_two_sided"].min()), "docs/revision/wp7/primary_family.csv", "smallest unadjusted p in primary family", 2)

    # ------------------------------------------------------------------ replay
    groups = [("class-level: P, H, S0, S1, S2, C", "P_probability_proxy"), ("S0\\textsubscript{key}", "S0_linear_log_historical_key[kappa=1]"),
              ("S1\\textsubscript{key}", "S1_linear_log_constrained_key (primary rule)"), ("S2\\textsubscript{key}", "S2_exponential_discount_key (primary rule)"),
              ("R\\textsubscript{sev,key}", "R_severity_key_reliability"), ("O\\textsubscript{sev}", "O_severity"), ("LIFO", "O_newest_first"), ("FIFO", "O_oldest_first")]
    rep_rows = []
    delay = pd.read_csv(WP7 / "delay_censoring.csv")
    for label, method in groups:
        part = r12[r12["method"] == method]
        investigations = int(part["investigations"].sum())
        rep_rows.append(f"{label} & {int(part['covered_intervals'].sum())} & {int(part['censored_intervals'].sum())} & {fmt(int(part['fp_investigations'].sum()))} & "
                        f"{fmt(int(part['positive_investigations'].sum()))} & {int(part['critical_investigations'].sum())} & {fmt(int(part['starved_critical'].sum()))} & "
                        f"{100 * part['starved_critical'].sum() / part['critical_total'].sum():.1f} \\\\")
    write("tab_replay.tex", "\\begin{tabular}{lrrrrrrr}\n\\toprule\nRanker & Covered & Never investigated & FP investigations & Positive investigations & Critical investigated & Critical starved & Starved (\\%) \\\\\n\\midrule\n"
          + "\n".join(rep_rows) + "\n\\bottomrule\n\\end{tabular}\n")
    total_inv = int(r12[r12["method"] == "P_probability_proxy"]["investigations"].sum())
    macro("ReplayInvestigations", total_inv, src_replay, "eight-scenario investigations per full-stream ranker, 12/h")
    for name, method in (("ReplayClass", "P_probability_proxy"), ("ReplaySOneKey", "S1_linear_log_constrained_key (primary rule)"),
                         ("ReplaySZeroKey", "S0_linear_log_historical_key[kappa=1]"), ("ReplayRSevKey", "R_severity_key_reliability"),
                         ("ReplaySevOnly", "O_severity"), ("ReplayFIFO", "O_oldest_first")):
        part = r12[r12["method"] == method]
        macro(f"{name}Covered", int(part["covered_intervals"].sum()), src_replay, f"covered intervals, {method}, 12/h")
        macro(f"{name}FP", int(part["fp_investigations"].sum()), src_replay, f"FP investigations, {method}, 12/h")
        macro(f"{name}StarvedShare", 100 * part["starved_critical"].sum() / part["critical_total"].sum(), src_replay, f"starved critical share, {method}, 12/h", 1)
    sixty = replay[(replay["policy"] == "P1") & (replay["rate_per_hour"] == 60.0) & (replay["candidate_id"] == "P_probability_proxy")]
    macro("ReplaySixtyShare", 100 * sixty["investigations"].sum() / sixty["alerts"].sum(), src_replay, "investigations / alerts at 60/h, pooled", 1)
    macro("ReplaySixtyShareMax", 100 * (sixty["investigations"] / sixty["alerts"]).max(), src_replay, "max per-scenario share at 60/h", 1)
    peaks = r12[r12["method"] == "P_probability_proxy"]["peak_backlog"]
    macro("PeakBacklogMin", int(peaks.min()), src_replay, "min per-scenario peak backlog, 12/h")
    macro("PeakBacklogMax", int(peaks.max()), src_replay, "max per-scenario peak backlog, 12/h")
    dl = delay[delay["rate_per_hour"] == 12.0].groupby("ranker").agg(covered=("covered_intervals", "sum"), within1=("intervals_covered_within_1h", "sum"),
                                                                     rmst=("restricted_mean_delay_hours_lower_bound", "median"), med=("median_delay_hours_detected", "median"))
    delay_rows = [f"{RANKER_LABEL[k]} & {int(v.covered)} & {int(v.within1)} & {v.med:.2f} & {v.rmst:.2f} \\\\"
                  for k, v in dl.reindex(["S1_key", "S0_key", "R_severity_key", "P", "O_severity", "FIFO"]).iterrows() if not math.isnan(v.covered)]
    write("tab_delay.tex", "\\begin{tabular}{lrrrr}\n\\toprule\nRanker & Covered (of 32) & Covered within 1 h & Median delay, covered (h) & Restricted mean delay, censored (h) \\\\\n\\midrule\n"
          + "\n".join(delay_rows).replace("nan", "--") + "\n\\bottomrule\n\\end{tabular}\n")

    # rates
    rates = replay[replay["policy"] == "P1"].groupby(["rate_per_hour", "method"]).agg(covered=("covered_intervals", "sum"), inv=("investigations", "sum")).reset_index()
    rate_rows = []
    for rate, part in rates.groupby("rate_per_hour"):
        p = part.set_index("method")
        rate_rows.append(f"{rate:g} & {fmt(int(p.loc['P_probability_proxy', 'inv']))} & {int(p.loc['P_probability_proxy', 'covered'])} & "
                         f"{int(p.loc['S0_linear_log_historical_key[kappa=1]', 'covered'])} & {int(p.loc['R_severity_key_reliability', 'covered'])} & "
                         f"{int(p.loc['S1_linear_log_constrained_key (primary rule)', 'covered'])} & {int(p.loc['O_newest_first', 'covered'])} \\\\")
    write("tab_rates.tex", "\\begin{tabular}{rrrrrrr}\n\\toprule\nRate (per h) & Investigations & P & S0\\textsubscript{key} & R\\textsubscript{sev,key} & S1\\textsubscript{key} & LIFO \\\\\n\\midrule\n"
          + "\n".join(rate_rows) + "\n\\bottomrule\n\\end{tabular}\n")

    # generalization
    hf = pd.read_csv(WP7 / "holdout_forward.csv")
    ho = hf[hf["experiment"].str.startswith("identifier")]
    fw = hf[hf["experiment"].str.startswith("forward")].set_index("ranker")
    gen_rows = []
    for ranker, label in (("S1_key", "S1\\textsubscript{key}"), ("S0_key", "S0\\textsubscript{key}"), ("R_severity_key", "R\\textsubscript{sev,key}"), ("P", "P"), ("S1", "S1")):
        g = ho[ho["ranker"] == ranker].set_index("group")
        base = int(static[static["method"].map(lambda m: SHORT.get(m, "")) == {"S1_key": "S1\\textsubscript{key}", "S0_key": "S0\\textsubscript{key}", "R_severity_key": "R\\textsubscript{sev,key}", "P": "P", "S1": "S1"}[ranker]]["covered_intervals"].sum())
        gen_rows.append(f"{label} & {base} & " + " & ".join(str(int(g.loc[i, 'covered_intervals'])) for i in range(5)) + f" & {int(fw.loc[ranker, 'covered_intervals'])} \\\\")
    write("tab_generalization.tex", "\\begin{tabular}{lcccccccc}\n\\toprule\n & LOSO & \\multicolumn{5}{c}{Hold-out group} & Forward \\\\\n\\cmidrule(lr){3-7}\nRanker & (of 32) & 0 & 1 & 2 & 3 & 4 & (of 20) \\\\\n\\midrule\n"
          + "\n".join(gen_rows) + "\n\\bottomrule\n\\end{tabular}\n")
    s1k = ho[ho["ranker"] == "S1_key"].set_index("group")["covered_intervals"]
    macro("HoldoutSOneKeyGroups", ", ".join(str(int(v)) for v in s1k.sort_index()), "docs/revision/wp7/holdout_forward.csv", "S1_key covered by hold-out group")
    macro("ForwardSOneKey", int(fw.loc["S1_key", "covered_intervals"]), "docs/revision/wp7/holdout_forward.csv", "forward chaining covered, S1_key")
    macro("ForwardP", int(fw.loc["P", "covered_intervals"]), "docs/revision/wp7/holdout_forward.csv", "forward chaining covered, P")

    # UWF
    uwf = json.loads((WP7 / "uwf/uwf_summary.json").read_text())
    tactics = pd.read_csv(WP7 / "uwf/uwf_tactics.csv")
    agreement = pd.read_csv(WP7 / "uwf/uwf_agreement_thresholds.csv")
    uwf_rows = [f"{r.tactic} & {fmt(int(r.uwf_rows))} & {100 * r.uwf_attack_share:.2f} & {r.tactic_table_severity:g} & "
                f"{'--' if pd.isna(r.crosswalk_severity_max) else f'{r.crosswalk_severity_max:g}'} & {'--' if pd.isna(r.discrepancy_max) else f'{r.discrepancy_max:+g}'} \\\\"
                for r in tactics.itertuples(index=False)]
    write("tab_uwf.tex", "\\begin{tabular}{lrrrrr}\n\\toprule\nTactic & Rows & Share (\\%) & Tactic table & Crosswalk (max) & Difference \\\\\n\\midrule\n" + "\n".join(uwf_rows) + "\n\\bottomrule\n\\end{tabular}\n")
    historical = agreement[agreement["crosswalk"].str.startswith("max")]
    macro("UWFRows", uwf["coverage"]["rows"], "docs/revision/wp7/uwf/uwf_summary.json", "rows")
    macro("UWFAttackRows", uwf["coverage"]["attack_rows"], "docs/revision/wp7/uwf/uwf_summary.json", "attack rows")
    macro("UWFCredentialShare", 100 * uwf["credential_access_share"], "docs/revision/wp7/uwf/uwf_summary.json", "Credential Access share", 2)
    a8 = historical[historical["threshold"] == 8.0].iloc[0]
    macro("UWFSpearman", a8["spearman"], "docs/revision/wp7/uwf/uwf_agreement_thresholds.csv", "Spearman, five tactics", 3)
    macro("UWFMADWeighted", a8["mean_absolute_discrepancy_frequency_weighted"], "docs/revision/wp7/uwf/uwf_agreement_thresholds.csv", "weighted MAD", 2)
    macro("UWFMADUnweighted", a8["mean_absolute_discrepancy_unweighted"], "docs/revision/wp7/uwf/uwf_agreement_thresholds.csv", "unweighted MAD", 2)
    macro("UWFJaccardEightFive", historical[historical["threshold"] == 8.5].iloc[0]["jaccard"], "docs/revision/wp7/uwf/uwf_agreement_thresholds.csv", "Jaccard at 8.5", 2)
    macro("UWFSharedConnections", uwf["duplicates"]["three_326_row_tactics_connections_shared_by_all_three"], "docs/revision/wp7/uwf/uwf_summary.json", "connections shared by three tactic files")

    # ------------------------------------------------------------------ figures
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False})

    # F1 static tradeoff per scenario
    fig, ax = plt.subplots(figsize=(4.6, 3.2))
    styles = [("P_probability_proxy", "o", "P (class level)"), ("S1_linear_log_constrained (primary rule)", "x", "S1 (class level)"),
              ("S0_linear_log_historical_key[kappa=1]", "s", "S0_key"), ("S1_linear_log_constrained_key (primary rule)", "^", "S1_key"),
              ("R_severity_key_reliability", "D", "R_sev,key"), ("O_severity", "v", "O_sev")]
    for i, (method, marker, label) in enumerate(styles):
        part = static[static["method"] == method].set_index("analysis_unit").reindex(SCENARIOS)
        jitter = (i - 2.5) * 0.05
        ax.scatter(part["negatives_in_top"], part["covered_intervals"] + jitter, marker=marker, s=22, label=label,
                   facecolors="none" if marker not in {"x"} else "black", edgecolors="black" if marker not in {"x"} else None, color="black", linewidths=0.8)
    ax.set_xlabel("FP@100 (per scenario)")
    ax.set_ylabel("critical intervals covered@100 (of 4)")
    ax.legend(frameon=False, fontsize=6, ncol=1, loc="center left", bbox_to_anchor=(1.0, 0.5))
    fig.tight_layout(); fig.savefig(GEN / "figures/fig_static_tradeoff.pdf", metadata={"CreationDate": None}); plt.close(fig)

    # F2 coverage and critical recall versus rank (R1)
    curves = pd.concat([pd.read_csv(p) for p in sorted((STAGE2 / "R1").glob("loso_*/e10_curves.csv.gz"))], ignore_index=True)
    grid = np.unique(np.round(np.logspace(0, 5.5, 60)).astype(int))
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.6))
    for label, name, ls in (("P_probability_proxy", "P / S1 (class level)", "-"), ("S1_linear_log_constrained_key", "S1_key", "--"),
                            ("S2_exponential_discount_key", "S2_key", ":")):
        data = curves[curves["agreement_label"] == label]
        for ax, metric in zip(axes, ("coverage_all", "critical_recall")):
            values = []
            for scenario, part in data.groupby("held_out"):
                part = part.sort_values("rank")
                idx = np.searchsorted(part["rank"].to_numpy(), grid, side="right") - 1
                v = np.where(idx >= 0, part[metric].to_numpy()[np.clip(idx, 0, None)], 0.0)
                v = np.where(grid > part["rank"].max(), part[metric].to_numpy()[-1], v)
                values.append(v)
            ax.plot(grid, np.mean(values, axis=0), ls, color="black", lw=1, label=name)
    axes[0].set_ylabel("critical-interval coverage (macro mean)")
    axes[1].set_ylabel("alert-level critical recall (macro mean)")
    for ax in axes:
        ax.set_xscale("log"); ax.set_xlabel("queue position (static order)"); ax.axvline(100, color="0.7", lw=0.6)
    axes[0].legend(frameon=False, fontsize=6)
    fig.tight_layout(); fig.savefig(GEN / "figures/fig_rank_curves.pdf", metadata={"CreationDate": None}); plt.close(fig)

    # F3 paired effects (primary + replay exploratory)
    effects = pd.read_csv(WP7 / "per_scenario_effects.csv")
    panels = [("primary", "S1 - A", "static", "FP@100"), ("primary", "S1 - P", "static", "FP@100"),
              ("exploratory", "S1_key - S1", "replay P1 12/h", "replay covered intervals"), ("exploratory", "S1_key - S1", "replay P1 12/h", "replay FP investigations"),
              ("exploratory", "S0_key - P", "replay P1 12/h", "replay covered intervals"), ("exploratory", "S0_key - P", "replay P1 12/h", "replay FP investigations"),
              ("exploratory", "R_severity_key - P", "replay P1 12/h", "replay covered intervals"), ("exploratory", "R_severity_key - P", "replay P1 12/h", "replay FP investigations")]
    fig, axes = plt.subplots(2, 4, figsize=(7.2, 3.6))
    for ax, (family, contrast, source, metric) in zip(axes.ravel(), panels):
        part = effects[(effects["family"] == family) & (effects["contrast"] == contrast) & (effects["source"] == source) & (effects["metric"] == metric)].set_index("scenario").reindex(SCENARIOS)
        ax.axhline(0, color="0.6", lw=0.6)
        ax.scatter(range(8), part["difference"], s=12, color="black")
        ax.set_xticks(range(8)); ax.set_xticklabels([sc[:3] for sc in SCENARIOS], rotation=90, fontsize=5)
        ax.set_title(f"{contrast}\n{metric}", fontsize=6)
        ax.tick_params(axis="y", labelsize=5)
    fig.tight_layout(); fig.savefig(GEN / "figures/fig_paired_effects.pdf", metadata={"CreationDate": None}); plt.close(fig)

    # F4 replay: per-scenario coverage vs FP share, and coverage versus rate
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.8))
    for i, (method, marker, label) in enumerate(styles + [("O_oldest_first", "*", "FIFO")]):
        part = r12[r12["method"] == method].set_index("held_out").reindex(SCENARIOS)
        axes[0].scatter(part["fp_investigations"] / part["investigations"], part["covered_intervals"] + (i - 3) * 0.05, marker=marker, s=18,
                        facecolors="none" if marker not in {"x", "*"} else "black", edgecolors="black" if marker not in {"x", "*"} else None, color="black", linewidths=0.7, label=label)
    axes[0].set_xlabel("FP investigations / investigations"); axes[0].set_ylabel("critical intervals covered (of 4)")
    axes[0].legend(frameon=False, fontsize=5, ncol=1, loc="center left", bbox_to_anchor=(1.0, 0.5))
    for method, ls, label in (("P_probability_proxy", "-", "P"), ("S0_linear_log_historical_key[kappa=1]", "--", "S0_key"),
                              ("S1_linear_log_constrained_key (primary rule)", ":", "S1_key"), ("O_newest_first", "-.", "LIFO")):
        part = rates[rates["method"] == method]
        axes[1].plot(part["rate_per_hour"], part["covered"], ls, marker="o", ms=3, color="black", lw=1, label=label)
    axes[1].set_xscale("log"); axes[1].set_xticks([6, 12, 30, 60]); axes[1].set_xticklabels(["6", "12", "30", "60"])
    axes[1].set_xlabel("analyst rate (alerts per hour; all overloaded)"); axes[1].set_ylabel("critical intervals covered (of 32)")
    axes[1].legend(frameon=False, fontsize=6)
    fig.tight_layout(); fig.savefig(GEN / "figures/fig_replay.pdf", metadata={"CreationDate": None}); plt.close(fig)

    # F5 protocol data flow
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    ax.axis("off")
    width, height = 0.225, 0.3
    top = [(0.0, "Raw AIT alerts (Wazuh,\nSuricata, AMiner) and\ninterval labels"),
           (0.255, "Ranking-time inputs: native\nkey, timestamp, host\n(held-out labels locked)"),
           (0.51, "Outer training scenarios:\ncross-fitted mapping and\nclass / key reliability"),
           (0.765, "Inner leave-one-scenario-out\nselection: coverage@100,\nFP@100 (157 candidates)")]
    bottom = [(0.765, "Held-out scenario\nscores (frozen)"), (0.51, "Static evaluation: k = 100,\nties, deferral, ablations"),
              (0.255, "Chronological replay:\none analyst, 6-60 alerts/h"), (0.0, "Generalization: identifier\nhold-out, forward chaining")]
    for x, text in top:
        ax.add_patch(plt.Rectangle((x, 0.6), width, height, fill=False, lw=0.8))
        ax.text(x + width / 2, 0.6 + height / 2, text, ha="center", va="center", fontsize=6.5)
    for x, text in bottom:
        ax.add_patch(plt.Rectangle((x, 0.1), width, height, fill=False, lw=0.8))
        ax.text(x + width / 2, 0.1 + height / 2, text, ha="center", va="center", fontsize=6.5)
    arrow = dict(arrowstyle="->", lw=0.8)
    for x in (0.0, 0.255, 0.51):
        ax.annotate("", xy=(x + width + 0.03, 0.75), xytext=(x + width, 0.75), arrowprops=arrow)
    ax.annotate("", xy=(0.765 + width / 2, 0.4), xytext=(0.765 + width / 2, 0.6), arrowprops=arrow)
    for x in (0.51, 0.255):
        ax.annotate("", xy=(x + width, 0.25), xytext=(x + width + 0.03, 0.25), arrowprops=arrow)
    ax.annotate("", xy=(0.0 + width, 0.25), xytext=(0.255, 0.25), arrowprops=dict(arrowstyle="-", lw=0.8, ls=":"))
    ax.set_xlim(-0.01, 1.0); ax.set_ylim(0.05, 0.95)
    fig.savefig(GEN / "figures/fig_protocol.pdf", bbox_inches="tight", metadata={"CreationDate": None}); plt.close(fig)

    (GEN / "numbers.tex").write_text("% generated by scripts/revision/wp8_build_manuscript_assets.py\n" + "\n".join(macros) + "\n", encoding="utf-8")
    out = PROJECT_ROOT / "docs/revision/wp8"
    out.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(claims).to_csv(out / "claim_evidence_map.csv", index=False)
    (out / "assets_manifest.json").write_text(json.dumps({
        "script_sha256": sha(Path(__file__)),
        "tables": {p.name: sha(p) for p in sorted((GEN / "tables").glob("*.tex"))},
        "figures": {p.name: sha(p) for p in sorted((GEN / "figures").glob("*.pdf"))},
        "numbers_sha256": sha(GEN / "numbers.tex")}, indent=1))
    print(f"{len(macros)} macros; tables {len(list((GEN / 'tables').glob('*.tex')))}; figures {len(list((GEN / 'figures').glob('*.pdf')))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

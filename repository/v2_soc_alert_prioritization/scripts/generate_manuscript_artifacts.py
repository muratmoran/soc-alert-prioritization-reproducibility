#!/usr/bin/env python
"""Generate manuscript-ready tables and figures from experiment outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANUSCRIPT_DIR = PROJECT_ROOT / "manuscript"
FIGURE_DIR = MANUSCRIPT_DIR / "figures"
TABLE_DIR = MANUSCRIPT_DIR / "generated_tables"
RESULTS_DIR = PROJECT_ROOT / "results"

PALETTE = {
    "blue": "#2f5f8f",
    "green": "#2f7d62",
    "orange": "#c47a28",
    "red": "#b64b4b",
    "gray": "#6f7378",
    "purple": "#74539b",
}


def main() -> int:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    TABLE_DIR.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "font.size": 8,
            "axes.labelsize": 8,
            "axes.titlesize": 9,
            "legend.fontsize": 7,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "figure.dpi": 160,
            "savefig.bbox": "tight",
        }
    )

    artifact_index = {
        "tables": [
            str(generate_ait_headline_table()),
            str(generate_ait_calibration_table()),
            str(generate_ait_reliability_ablation_table()),
            str(generate_ait_paired_improvements_table()),
            str(generate_nf_uq_table()),
            str(generate_uwf_table()),
            str(generate_uwf_tactic_alignment_table()),
            str(generate_ait_stress_table()),
        ],
        "figures": [
            str(generate_ait_headline_figure()),
            str(generate_kappa_figure()),
            str(generate_uwf_figure()),
        ],
    }
    (MANUSCRIPT_DIR / "artifact_index.json").write_text(
        json.dumps(artifact_index, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps(artifact_index, indent=2, sort_keys=True))
    return 0


def generate_ait_headline_table() -> Path:
    summary = load_json(RESULTS_DIR / "ait_alert/ranking_eval_asset_ambiguity/ranking_eval_summary.json")
    means = summary["method_means"]
    rows = []
    for method in ["sgfn", "weighted", "severity", "reliability", "detector_native", "recency"]:
        row = means[method]
        rows.append(
            [
                method_label(method),
                fmt(row["ndcg@10"]),
                fmt(row["ndcg@100"]),
                fmt(row["ndcg@500"]),
                fmt(row["false_positives@100"], digits=2),
                fmt(row["rank_first_critical"], digits=2),
            ]
        )
    path = TABLE_DIR / "table_ait_headline_summary.tex"
    write_latex_table(
        path=path,
        caption="AIT primary ranking results under asset-profile context and ambiguity-aware uncertainty.",
        label="tab:ait_headline",
        columns=["Method", "NDCG 10", "NDCG 100", "NDCG 500", "FP 100", "First critical"],
        rows=rows,
        column_spec=(
            "p{0.18\\textwidth}p{0.13\\textwidth}p{0.13\\textwidth}"
            "p{0.13\\textwidth}p{0.11\\textwidth}p{0.16\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_ait_calibration_table() -> Path:
    calibration = pd.read_csv(
        RESULTS_DIR / "ait_alert/calibration_summary/ait_detector_class_reliability_summary.csv"
    )
    rows = []
    for row in calibration.itertuples(index=False):
        rows.append(
            [
                detector_label(row.detector),
                attack_class_label(row.attack_class),
                str(int(row.folds)),
                fmt_count(row.mean_support),
                fmt_percent(row.mean_detector_share),
                fmt(row.mean_ppv),
                fmt(row.mean_detector_prior),
                fmt(row.mean_height),
            ]
        )
    path = TABLE_DIR / "table_ait_detector_class_reliability.tex"
    write_latex_table(
        path=path,
        caption="AIT detector-class reliability calibration across leave-one-scenario-out folds.",
        label="tab:ait_detector_class_reliability",
        columns=["Detector", "Class", "Folds", "Mean support", "Detector share", "PPV", "Prior", "Height"],
        rows=rows,
        column_spec=(
            "p{0.12\\textwidth}p{0.20\\textwidth}p{0.07\\textwidth}"
            "p{0.13\\textwidth}p{0.13\\textwidth}p{0.08\\textwidth}"
            "p{0.08\\textwidth}p{0.08\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_ait_reliability_ablation_table() -> Path:
    ablation = pd.read_csv(
        RESULTS_DIR / "ait_alert/reliability_ablation/ait_reliability_ablation_summary.csv"
    )
    ablation = ablation.set_index("policy")
    rows = []
    for policy in ["detector_class", "global_class", "detector_only", "native_detector"]:
        row = ablation.loc[policy]
        rows.append(
            [
                str(row["policy_label"]),
                fmt(row["ndcg@100"]),
                fmt(row["false_positives@100"], digits=2),
                fmt(row["rank_first_critical"], digits=2),
            ]
        )
    path = TABLE_DIR / "table_ait_reliability_ablation.tex"
    write_latex_table(
        path=path,
        caption="AIT reliability-calibration ablation. All SGFN rows use the same severity, asset context, uncertainty policy, and kappa; only the reliability-height policy changes.",
        label="tab:ait_reliability_ablation",
        columns=["Calibration policy", "NDCG 100", "FP 100", "First critical"],
        rows=rows,
        column_spec=(
            "p{0.34\\textwidth}p{0.16\\textwidth}p{0.14\\textwidth}"
            "p{0.18\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_ait_paired_improvements_table() -> Path:
    summary = pd.read_csv(
        RESULTS_DIR / "ait_alert/paired_improvements/ait_paired_improvement_summary.csv"
    )
    pivot = summary.pivot(index="baseline", columns="metric")
    rows = []
    for baseline in ["severity", "detector_native", "weighted"]:
        rows.append(
            [
                method_label(baseline),
                format_ci_cell(pivot, baseline, "ndcg@100", digits=4),
                p_value_cell(pivot.loc[baseline, ("wilcoxon_p_greater", "ndcg@100")]),
                format_ci_cell(pivot, baseline, "false_positives@100", digits=2),
                p_value_cell(pivot.loc[baseline, ("wilcoxon_p_greater", "false_positives@100")]),
                format_ci_cell(pivot, baseline, "rank_first_critical", digits=2),
                p_value_cell(pivot.loc[baseline, ("wilcoxon_p_greater", "rank_first_critical")]),
            ]
        )
    path = TABLE_DIR / "table_ait_paired_improvements.tex"
    write_latex_table(
        path=path,
        caption="Paired AIT fold-level SGFN improvements over baselines. Cells report mean [95% bootstrap CI]; p is a one-sided Wilcoxon signed-rank p-value. Positive values are better for all three metrics.",
        label="tab:ait_paired_improvements",
        columns=[
            "Baseline",
            "NDCG@100 improvement",
            "p",
            "FP@100 reduction",
            "p",
            "First-critical-rank reduction",
            "p",
        ],
        rows=rows,
        column_spec=(
            "p{0.14\\textwidth}p{0.17\\textwidth}p{0.08\\textwidth}"
            "p{0.17\\textwidth}p{0.08\\textwidth}p{0.18\\textwidth}"
            "p{0.08\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_nf_uq_table() -> Path:
    metrics = pd.read_csv(RESULTS_DIR / "nf_uq_nids_v2/robustness_shared/nf_uq_robustness_metrics.csv")
    detector = (
        metrics[metrics["method"] == "detector_generation"]
        .groupby("model")["detector_f1"]
        .mean()
    )
    ranking = metrics[metrics["method"].isin(["sgfn", "severity", "weighted", "detector"])]
    pivot = ranking.groupby(["model", "method"]).mean(numeric_only=True).reset_index()
    rows = []
    for model in ["logistic_regression"]:
        model_rows = pivot[pivot["model"] == model].set_index("method")
        rows.append(
            [
                model_label(model),
                fmt(detector.get(model, 0.0)),
                fmt(model_rows.loc["sgfn", "ndcg@100"]),
                fmt(model_rows.loc["severity", "ndcg@100"]),
                fmt(model_rows.loc["detector", "ndcg@100"]),
                fmt(model_rows.loc["sgfn", "false_positives@100"], digits=2),
            ]
        )
    path = TABLE_DIR / "table_nf_uq_robustness_summary.tex"
    write_latex_table(
        path=path,
        caption="NF-UQ-NIDS-v2 shared-category robustness for the generated-alert stream that meets the detector-quality threshold.",
        label="tab:nf_uq_robustness",
        columns=["Generated detector", "F1", "SGFN NDCG 100", "Severity NDCG 100", "Detector NDCG 100", "SGFN FP 100"],
        rows=rows,
        column_spec=(
            "p{0.24\\textwidth}p{0.08\\textwidth}p{0.15\\textwidth}"
            "p{0.15\\textwidth}p{0.15\\textwidth}p{0.13\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_nf_uq_category_breakdown_table() -> Path:
    summary = pd.read_csv(
        RESULTS_DIR / "nf_uq_nids_v2/category_breakdown_shared/nf_uq_category_breakdown_summary.csv"
    )
    rows = []
    for category in ["DoS", "DDoS", "Reconnaissance", "Backdoor"]:
        row = summary[summary["category"] == category].iloc[0]
        rows.append(
            [
                category_label(category),
                domain_count_label(row["source_domain_count"]),
                format_range_percent(row["prevalence_min"], row["prevalence_max"]),
                format_range(row["detector_f1_min"], row["detector_f1_max"]),
                fmt(row["sgfn_target_ndcg@100"]),
                baseline_short_label(str(row["best_baseline"])),
                fmt(row["best_baseline_target_ndcg@100"]),
                fmt(row["sgfn_delta_vs_best_baseline"], digits=4),
                fmt(row["sgfn_target_false_positives@100"], digits=2),
            ]
        )
    path = TABLE_DIR / "table_nf_uq_category_breakdown.tex"
    write_latex_table(
        path=path,
        caption="NF-UQ-NIDS-v2 category/domain robustness breakdown. Target NDCG@100 uses binary relevance for the named category over the generated-alert queue.",
        label="tab:nf_uq_category_breakdown",
        columns=[
            "Cat.",
            "Dom.",
            "Prev. range",
            "F1 range",
            "SGFN NDCG 100",
            "Best base.",
            "Base. NDCG 100",
            "Delta",
            "SGFN FP 100",
        ],
        rows=rows,
        column_spec=(
            "p{0.12\\textwidth}p{0.07\\textwidth}p{0.11\\textwidth}"
            "p{0.11\\textwidth}p{0.12\\textwidth}p{0.09\\textwidth}"
            "p{0.11\\textwidth}p{0.09\\textwidth}p{0.08\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_uwf_table() -> Path:
    summary = load_json(RESULTS_DIR / "uwf_zeekdata24/uwf_mapping_validation_summary.json")
    agreement = summary["agreement"]
    rows = [
        ["CSV subset rows", f"{summary['rows']:,}"],
        ["Attack-labelled rows", f"{summary['attack_rows']:,}"],
        ["Observed attack tactics", str(summary["observed_attack_tactics"])],
        ["AIT-overlap tactics", str(summary["overlap_tactics_with_ait"])],
        ["Mapped tactic rate", fmt(summary["mapped_tactic_rate"])],
        ["Valid technique rate", fmt(summary["valid_technique_rate"])],
        ["Spearman correlation", fmt(agreement["spearman"])],
        ["Top-risk Jaccard", fmt(agreement["top_risk_jaccard"])],
    ]
    path = TABLE_DIR / "table_uwf_mapping_summary.tex"
    write_latex_table(
        path=path,
        caption="UWF-ZeekData24 ATT&CK mapping-validation summary.",
        label="tab:uwf_mapping_validation",
        columns=["Statistic", "Value"],
        rows=rows,
        column_spec="p{0.68\\textwidth}p{0.20\\textwidth}",
        star=True,
    )
    return path


def generate_uwf_tactic_alignment_table() -> Path:
    table = pd.read_csv(RESULTS_DIR / "uwf_zeekdata24/uwf_tactic_mapping_validation.csv")
    overlap = table[table["overlap_with_ait"].astype(bool)].copy()
    overlap["severity_delta"] = (
        overlap["mitre_table_severity"].astype(float)
        - overlap["ait_phase_max_severity"].astype(float)
    )
    overlap = overlap.sort_values(["mitre_table_severity", "uwf_rows"], ascending=[False, False])
    rows = []
    for row in overlap.itertuples(index=False):
        rows.append(
            [
                tactic_short_label(row.mitre_tactic),
                fmt_percent(row.uwf_attack_share),
                compact_semicolon_list(row.distinct_techniques),
                compact_semicolon_list(row.ait_phases),
                fmt(row.mitre_table_severity, digits=1),
                fmt(row.ait_phase_max_severity, digits=1),
                fmt(row.severity_delta, digits=1),
            ]
        )
    path = TABLE_DIR / "table_uwf_tactic_alignment.tex"
    write_latex_table(
        path=path,
        caption="UWF-ZeekData24 tactic-level severity alignment on tactics that overlap with the AIT phase-to-tactic bridge. Delta is UWF ATT&CK-table severity minus AIT-derived maximum phase severity.",
        label="tab:uwf_tactic_alignment",
        columns=["Tactic", "UWF share", "UWF tech.", "AIT phases", "UWF sev.", "AIT sev.", "Delta"],
        rows=rows,
        column_spec=(
            "p{0.15\\textwidth}p{0.10\\textwidth}p{0.13\\textwidth}"
            "p{0.20\\textwidth}p{0.09\\textwidth}p{0.09\\textwidth}"
            "p{0.08\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_ait_stress_table() -> Path:
    stress = pd.read_csv(RESULTS_DIR / "ait_alert/stress_tests/ait_stress_summary.csv")
    sgfn = stress[stress["method"] == "sgfn"].copy()
    order = [
        "baseline",
        "reliability_overconfidence",
        "asset_criticality_shuffle",
        "duplicate_false_positive_pressure",
    ]
    sgfn = sgfn[sgfn["stress"].isin(order)].copy()
    sgfn["stress"] = pd.Categorical(sgfn["stress"], categories=order, ordered=True)
    rows = []
    for _, row in sgfn.sort_values("stress").iterrows():
        rows.append(
            [
                stress_label(row["stress"]),
                fmt(row["ndcg@100"]),
                fmt(row["false_positives@100"], digits=2),
                fmt(row["rank_first_critical"], digits=2),
            ]
        )
    path = TABLE_DIR / "table_ait_stress_summary.tex"
    write_latex_table(
        path=path,
        caption="AIT stress-test results for SGFN ranking.",
        label="tab:ait_stress",
        columns=["Stress condition", "NDCG@100", "FP@100", "First critical"],
        rows=rows,
        column_spec=(
            "p{0.36\\textwidth}p{0.14\\textwidth}"
            "p{0.12\\textwidth}p{0.16\\textwidth}"
        ),
        star=True,
    )
    return path


def generate_ait_headline_figure() -> Path:
    summary = load_json(RESULTS_DIR / "ait_alert/ranking_eval_asset_ambiguity/ranking_eval_summary.json")
    means = summary["method_means"]
    methods = ["sgfn", "weighted", "severity", "reliability", "detector_native", "recency"]
    labels = [method_label(method) for method in methods]
    ndcg = [means[method]["ndcg@100"] for method in methods]
    fp = [means[method]["false_positives@100"] for method in methods]

    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.6))
    colors = [PALETTE["green"], PALETTE["blue"], PALETTE["orange"], PALETTE["purple"], PALETTE["gray"], PALETTE["red"]]
    axes[0].bar(labels, ndcg, color=colors)
    axes[0].set_ylabel("NDCG@100")
    axes[0].set_ylim(0, max(ndcg) * 1.25 if ndcg else 1)
    axes[0].set_title("Ranking quality")
    axes[0].tick_params(axis="x", rotation=35)
    axes[1].bar(labels, fp, color=colors)
    axes[1].set_ylabel("False positives@100")
    axes[1].set_title("Top-100 burden")
    axes[1].tick_params(axis="x", rotation=35)
    for axis in axes:
        axis.grid(axis="y", color="#d9d9d9", linewidth=0.6)
        axis.set_axisbelow(True)
    fig.tight_layout()
    path = FIGURE_DIR / "fig_ait_headline.pdf"
    fig.savefig(path)
    plt.close(fig)
    return path


def generate_kappa_figure() -> Path:
    kappa = pd.read_csv(RESULTS_DIR / "ait_alert/kappa_sweep_asset_ambiguity/sgfn_kappa_summary.csv")
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.4))
    axes[0].plot(kappa["kappa"], kappa["ndcg@100"], marker="o", color=PALETTE["green"])
    axes[0].set_xlabel("Kappa")
    axes[0].set_ylabel("NDCG@100")
    axes[0].set_title("Risk attitude threshold")
    axes[1].plot(kappa["kappa"], kappa["false_positives@100"], marker="o", color=PALETTE["red"])
    axes[1].set_xlabel("Kappa")
    axes[1].set_ylabel("False positives@100")
    axes[1].set_title("Top-100 false positives")
    for axis in axes:
        axis.grid(True, color="#d9d9d9", linewidth=0.6)
    fig.tight_layout()
    path = FIGURE_DIR / "fig_ait_kappa_sensitivity.pdf"
    fig.savefig(path)
    plt.close(fig)
    return path


def generate_nf_uq_figure() -> Path:
    metrics = pd.read_csv(RESULTS_DIR / "nf_uq_nids_v2/robustness_shared/nf_uq_robustness_metrics.csv")
    ranking = metrics[metrics["method"].isin(["sgfn", "severity", "detector"])]
    means = ranking.groupby(["model", "method"])["ndcg@100"].mean().unstack("method").fillna(0.0)
    models = ["logistic_regression"]
    methods = ["sgfn", "severity", "detector"]
    x = np.arange(len(models))
    width = 0.24
    fig, axis = plt.subplots(figsize=(5.4, 2.8))
    for offset, method in enumerate(methods):
        axis.bar(
            x + (offset - 1) * width,
            [means.loc[model, method] for model in models],
            width=width,
            label=method_label(method),
            color=[PALETTE["green"], PALETTE["orange"], PALETTE["blue"]][offset],
        )
    axis.set_xticks(x)
    axis.set_xticklabels([model_label(model) for model in models])
    axis.set_ylabel("Mean NDCG@100")
    axis.set_title("NF-UQ leave-one-domain-out robustness")
    axis.grid(axis="y", color="#d9d9d9", linewidth=0.6)
    axis.set_axisbelow(True)
    axis.legend(frameon=False, ncols=3, loc="upper right")
    fig.tight_layout()
    path = FIGURE_DIR / "fig_nf_uq_robustness.pdf"
    fig.savefig(path)
    plt.close(fig)
    return path


def generate_uwf_figure() -> Path:
    table = pd.read_csv(RESULTS_DIR / "uwf_zeekdata24/uwf_tactic_mapping_validation.csv")
    overlap = table[table["overlap_with_ait"].astype(bool)].copy()
    fig, axis = plt.subplots(figsize=(4.4, 3.0))
    axis.scatter(
        overlap["mitre_table_severity"],
        overlap["ait_phase_max_severity"],
        s=np.clip(overlap["uwf_rows"] / max(overlap["uwf_rows"].max(), 1) * 220, 28, 220),
        color=PALETTE["green"],
        alpha=0.78,
        edgecolor="#303030",
        linewidth=0.5,
    )
    for row in overlap.itertuples(index=False):
        axis.annotate(
            tactic_short_label(row.mitre_tactic),
            (row.mitre_table_severity, row.ait_phase_max_severity),
            xytext=(4, 4),
            textcoords="offset points",
        )
    axis.plot([2, 10], [2, 10], color=PALETTE["gray"], linewidth=0.8, linestyle="--")
    axis.set_xlim(2, 10)
    axis.set_ylim(2, 10)
    axis.set_xlabel("MITRE tactic severity table")
    axis.set_ylabel("AIT-derived tactic severity")
    axis.set_title("UWF/AIT severity-order agreement")
    axis.grid(True, color="#d9d9d9", linewidth=0.6)
    fig.tight_layout()
    path = FIGURE_DIR / "fig_uwf_mapping_validation.pdf"
    fig.savefig(path)
    plt.close(fig)
    return path


def write_latex_table(
    path: Path,
    caption: str,
    label: str,
    columns: list[str],
    rows: Iterable[list[str]],
    column_spec: str,
    star: bool,
) -> None:
    env = "table*" if star else "table"
    lines = [
        f"\\begin{{{env}}}[ht]",
        f"\\caption{{{latex_escape(caption)}}}",
        f"\\label{{{label}}}",
        "\\centering",
    ]
    if star:
        lines.extend(["\\begingroup", "\\setlength{\\tabcolsep}{1pt}", "\\renewcommand{\\arraystretch}{1.05}"])
    lines.extend([
        f"\\begin{{tabular}}{{{column_spec}}}",
        "\\toprule",
        " & ".join(tex_cell(column) for column in columns) + " \\\\",
        "\\midrule",
    ])
    for row in rows:
        lines.append(" & ".join(tex_cell(value) for value in row) + " \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}"])
    if star:
        lines.append("\\endgroup")
    lines.extend([f"\\end{{{env}}}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def tex_cell(value: object) -> str:
    return latex_escape(str(value))


def latex_escape(value: str) -> str:
    replacements = {
        "&": "\\&",
        "%": "\\%",
        "$": "\\$",
        "#": "\\#",
        "_": "\\_",
    }
    output = value
    for old, new in replacements.items():
        output = output.replace(old, new)
    return output


def fmt(value: object, digits: int = 4) -> str:
    if value is None or pd.isna(value):
        return "--"
    numeric = float(value)
    return f"{numeric:.{digits}f}"


def fmt_count(value: object) -> str:
    if value is None or pd.isna(value):
        return "--"
    return f"{float(value):,.0f}"


def fmt_percent(value: object) -> str:
    if value is None or pd.isna(value):
        return "--"
    percent = float(value) * 100
    if 0 < percent < 0.01:
        return "<0.01%"
    return f"{percent:.2f}%"


def compact_semicolon_list(value: object, max_items: int = 3) -> str:
    if value is None or pd.isna(value) or str(value).strip() == "":
        return "--"
    items = [item.strip().replace("_", " ") for item in str(value).split(";") if item.strip()]
    if len(items) <= max_items:
        return ", ".join(items)
    return ", ".join(items[:max_items]) + ", ..."


def fmt_fraction_as_percent(value: object) -> str:
    if value is None or pd.isna(value):
        return "--"
    return f"{float(value) * 100:.2f}%"


def format_range(low: object, high: object, digits: int = 4) -> str:
    return f"{float(low):.{digits}f}-{float(high):.{digits}f}"


def format_range_percent(low: object, high: object) -> str:
    return f"{float(low) * 100:.2f}%-{float(high) * 100:.2f}%"


def domain_count_label(value: object) -> str:
    count = int(value)
    return f"{count} dom."


def category_label(category: str) -> str:
    return {
        "Reconnaissance": "Recon.",
    }.get(category, category)


def baseline_short_label(method: str) -> str:
    return {
        "severity": "Sev.",
        "detector": "Det.",
        "weighted": "Weighted",
    }.get(method, method_label(method))


def format_ci_cell(pivot: pd.DataFrame, baseline: str, metric: str, digits: int) -> str:
    mean = float(pivot.loc[baseline, ("mean_improvement", metric)])
    low = float(pivot.loc[baseline, ("ci95_low", metric)])
    high = float(pivot.loc[baseline, ("ci95_high", metric)])
    return f"{mean:.{digits}f} [{low:.{digits}f}, {high:.{digits}f}]"


def p_value_cell(value: object) -> str:
    if value is None or pd.isna(value):
        return "--"
    p_value = float(value)
    if p_value < 0.001:
        return "<0.001"
    return f"{p_value:.4f}"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def detector_label(detector: str) -> str:
    return {
        "aminer": "AMiner",
        "suricata": "Suricata",
        "wazuh": "Wazuh",
    }.get(detector, detector)


def attack_class_label(attack_class: str) -> str:
    return {
        "dirb": "Dirb",
        "privilege_escalation": "Privilege escalation",
        "service_scans": "Service scans",
        "unknown": "Unknown",
        "wpscan": "WPScan",
    }.get(attack_class, attack_class)


def method_label(method: str) -> str:
    return {
        "sgfn": "SGFN",
        "weighted": "Weighted",
        "severity": "Severity",
        "reliability": "Reliability",
        "detector_native": "Detector-native",
        "detector": "Detector",
        "recency": "Newest-first",
    }.get(method, method)


def model_label(model: str) -> str:
    return {
        "logistic_regression": "Logistic regression",
    }.get(model, model)


def stress_label(stress: str) -> str:
    return {
        "baseline": "Baseline",
        "reliability_overconfidence": "Reliability overconfidence",
        "asset_criticality_shuffle": "Asset criticality shuffle",
        "duplicate_false_positive_pressure": "Duplicate benign pressure",
    }.get(stress, stress)


def tactic_short_label(tactic: str) -> str:
    return {
        "Credential Access": "Cred. Access",
        "Exfiltration": "Exfil.",
        "Persistence": "Persist.",
        "Privilege Escalation": "Priv. Esc.",
        "Reconnaissance": "Recon.",
    }.get(tactic, tactic)


if __name__ == "__main__":
    raise SystemExit(main())

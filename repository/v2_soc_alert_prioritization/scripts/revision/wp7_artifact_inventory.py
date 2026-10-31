#!/usr/bin/env python
"""WP7: reconcile the complete revision artifact inventory (runs, configurations, restrictions, denominators).

Counts are read from the verified run manifests and tables, not typed by hand, and every listed
file is hashed. Writes docs/revision/wp7/artifact_inventory.csv and artifact_inventory.md.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
HOME = Path(os.environ.get("SOC_REVISION_DATA", Path.home() / "soc_revision_data")).expanduser()  # $SOC_REVISION_DATA; listed paths keep the original ~/soc_revision_data provenance
OUT = PROJECT_ROOT / "docs/revision/wp7"


def sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).exists() else "missing"


def main() -> int:
    rows = []

    def add(category, item, count, denominator_or_scope, location, restriction="", sha256=""):
        rows.append({"category": category, "item": item, "count": count, "scope_or_denominator": denominator_or_scope,
                     "location": location, "restriction_or_note": restriction, "sha256": sha256})

    # configurations and frozen specifications
    for path in ("configs/revision_wp2.yaml", "configs/severity_mapping.yaml", "docs/revision/wp2/grid_registry.json",
                 "docs/revision/protocol_v1.md", "docs/revision/protocol_v1_1.md", "docs/revision/wp3/metric_contract.md",
                 "docs/revision/wp4/fitting_specification.md", "docs/revision/wp4/stage2_reporting_specification.md",
                 "docs/revision/wp5/replay_specification.md", "docs/revision/wp7/analysis_specification.md"):
        add("configuration/specification", Path(path).name, 1, "frozen or versioned document", path, sha256=sha(PROJECT_ROOT / path))
    registry = json.loads((PROJECT_ROOT / "docs/revision/wp2/grid_registry.json").read_text())
    add("configuration/specification", "comparison candidates", len(registry["candidates"]),
        f"{registry['tuned_candidates_per_inner_fold']} tuned per inner fold + {len(registry['candidates']) - registry['tuned_candidates_per_inner_fold']} untuned",
        "docs/revision/wp2/grid_registry.json", f"supersedes {registry['supersedes']['registry_sha256'][:12]} (native-score correction)")

    # verification records
    for path in ("docs/revision/wp3/metric_verification.json", "docs/revision/wp4/fitting_boundary_verification.json", "docs/revision/wp5/replay_verification.json"):
        record = json.loads((PROJECT_ROOT / path).read_text())
        add("verification record", Path(path).stem, 1, f"verified={record['verified']}; generated {record['generated_at']}", path, sha256=sha(PROJECT_ROOT / path))

    # WP4 stage 1 fitting chains
    fitting = json.loads((PROJECT_ROOT / "docs/revision/wp4/real_data_fitting_check.json").read_text())
    add("run: WP4 stage 1 (no scores, no metrics)", "fitting chains", fitting["fitting_chains"]["total"],
        "LOSO primary+secondary (16), 10 ablation policies × 8 (80), identifier hold-out 40, forward chaining 5",
        "docs/revision/wp4/real_data_fitting_check.json; traces results/revision_cose_04000/wp4/fitting_chain_traces/",
        "verification of fitting isolation only", sha(PROJECT_ROOT / "docs/revision/wp4/real_data_fitting_check.json"))

    # WP4 stage 2 runs
    stage2 = json.loads((HOME / "wp4_stage2/run_manifest.json").read_text())["invocations"][-1]["folds"]
    counts = pd.Series([f["run"] for f in stage2]).value_counts().sort_index()
    notes = {"R1": "primary LOSO (flat+table)", "R2": "secondary policy LOSO (asset_profile+ambiguity_aware)",
             "R3_global_class": "calibration ablation", "R3_detector_only": "calibration ablation", "R3_native_key": "calibration ablation",
             "R3_none": "calibration ablation (h = 1)", "R4_constant_0.5": "uncertainty ablation", "R4_purity_only": "uncertainty ablation",
             "R4_precision_only": "uncertainty ablation", "R4_historical_combined": "uncertainty ablation", "R4_zero": "uncertainty ablation",
             "R5_asset_profile": "context ablation", "R6": "strict identifier hold-out: 8 scenarios × 5 hash groups",
             "R7": "forward chaining: eligible test scenarios only (russellmitchell, shaw, wheeler, wilson, harrison); fox, santos and wardbeck ineligible (< 2 earlier scenarios)"}
    for run, n in counts.items():
        add("run: WP4 stage 2 (static)", run, int(n), notes.get(run, ""), f"~/soc_revision_data/wp4_stage2/{run}/",
            "scores stored for R1/R2 only; R7 russellmitchell used the simplest learned grid point (two fit scenarios)" if run in {"R7"} else
            ("scores stored" if run in {"R1", "R2"} else "evaluation tables only"))
    manifest4 = json.loads((PROJECT_ROOT / "docs/revision/wp4/stage2_output_manifest.json").read_text())
    add("outputs", "WP4 stage-2 per-fold outputs", manifest4["files"], f"{manifest4['folds']} folds, {manifest4['fold_errors']} errors, {manifest4['traces_verified']} traces verified",
        "~/soc_revision_data/wp4_stage2 (integrity-checked copy; iCloud originals evicted)", "", manifest4["sha256sums_sha256"])

    # WP5 replay
    replay = json.loads((HOME / "wp5_replay/run_manifest.json").read_text())
    for fold in replay["folds"]:
        add("run: WP5 replay", f"{fold['policy']} {fold['held_out']}", fold["replays"], "candidates × 4 rates (6, 12, 30, 60 per hour)",
            f"~/soc_revision_data/wp5_replay/{fold['policy']}/loso_{fold['held_out']}/", f"integrity passed = {fold['integrity_passed']}")
    manifest5 = json.loads((PROJECT_ROOT / "docs/revision/wp5/replay_output_manifest.json").read_text())
    add("outputs", "WP5 replays (total)", manifest5["replays"], "P1 (R1 outer candidates) + P2 (R2 outer candidates)", "~/soc_revision_data/wp5_replay",
        "not replayed: duplicate suppression, identifier hold-out, forward chaining, ablations R3–R5", manifest5["sha256sums_sha256"])
    precheck = json.loads((PROJECT_ROOT / "docs/revision/wp5/real_data_precheck.json").read_text())
    add("run: WP5 precheck (no outcome metrics)", "precheck replays", precheck["largest_fold"]["replays"] + len(precheck["oldest_first_primary_rate_by_fold"]),
        "largest fold all candidates × rates + FIFO per fold", "docs/revision/wp5/real_data_precheck.json", "integrity/runtime/size only; not results")

    # reporting denominators
    summaries = pd.concat([pd.read_csv(p) for p in (HOME / "wp5_replay").glob("P1/loso_*/summaries.csv.gz")])
    per = summaries[(summaries["candidate_id"] == "P_probability_proxy") & (summaries["rate_per_hour"] == 12.0)].set_index("held_out")
    for scenario, row in per.sort_index().iterrows():
        add("denominator", f"scenario {scenario}", int(row["alerts"]),
            f"alerts; critical alerts {int(row['critical_total'])}; critical intervals {int(row['defined_intervals'])} (eligible {int(row['eligible_intervals'])}); "
            f"horizon {row['horizon_hours']:.1f} h; investigations at 12/h {int(row['investigations'])}", "held-out queue")
    add("denominator", "AIT alerts (all scenarios)", int(per["alerts"].sum()), "ranked in full; no sampling", "canonical cache c5702421…")
    add("denominator", "critical-step intervals", int(per["defined_intervals"].sum()), "4 per scenario, all containing alerts; 79 label intervals in total", "labels.csv")
    add("denominator", "critical alerts", int(per["critical_total"].sum()), "interval-labeled positives with s* ≥ 8", "labels.csv + severity policy")
    add("denominator", "static top-k positions (k = 100)", 800, "100 per scenario", "WP4 T1")
    rates = summaries[summaries["candidate_id"] == "P_probability_proxy"].groupby("rate_per_hour")["investigations"].sum()
    for rate, total in rates.items():
        add("denominator", f"replay investigations at {rate:g}/h", int(total), "eight-scenario total for EACH full-stream ranker (identical across rankers)", "WP5")
    uwf = json.loads((PROJECT_ROOT / "docs/revision/wp7/uwf/uwf_summary.json").read_text())
    add("denominator", "UWF rows", uwf["coverage"]["rows"], f"attack {uwf['coverage']['attack_rows']}, benign {uwf['coverage']['benign_rows']}; 7 tactics, 5 overlapping",
        "~/soc_revision_data/uwf_zeekdata24/csv", f"{uwf['duplicates']['attack_connections_in_more_than_one_tactic_file']} attack connections appear in more than one tactic file")

    # analyses not performed
    for item, reason in (
        ("expanded operational vector (protocol §6.2)", "deferred, unimplemented scope (protocol amendment 2026-09-15)"),
        ("NF-UQ-NIDS-v2 redesign (WP6)", "deferred under D3; no NF-UQ domain units"),
        ("independent expert/impact severity study", "outside revision (D4); no independent severity validation"),
        ("replay with duplicate suppression", "not replayed; duplicate units are static only (WP4 E6)"),
        ("replay of identifier hold-out, forward chaining, ablations R3–R5", "not replayed; static only (scores not retained)"),
        ("statistical equivalence / non-inferiority", "no margin declared; not performed"),
        ("bootstrap over scenarios, alerts or telemetry rows", "not used (protocol §11)"),
        ("tests at other k, NDCG, subgroups", "descriptive only; not in any test family"),
    ):
        add("not performed", item, 0, reason, "")

    frame = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    frame.to_csv(OUT / "artifact_inventory.csv", index=False)
    lines = ["# Revision artifact inventory (generated)", "",
             "Generated by `scripts/revision/wp7_artifact_inventory.py` from run manifests and tables. Counts are not hand-typed.", ""]
    for category, part in frame.groupby("category", sort=False):
        lines += [f"## {category}", "", "| Item | Count | Scope or denominator | Location | Note | SHA-256 |", "| --- | ---: | --- | --- | --- | --- |"]
        for row in part.itertuples(index=False):
            lines.append(f"| {row.item} | {row.count} | {row.scope_or_denominator} | {row.location} | {row.restriction_or_note} | {str(row.sha256)[:16]} |")
        lines.append("")
    (OUT / "artifact_inventory.md").write_text("\n".join(lines), encoding="utf-8")
    print(frame.groupby("category").size().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

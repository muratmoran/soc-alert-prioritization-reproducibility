#!/usr/bin/env python
"""WP5: build the declared replay tables (replay_specification.md §4) from replay outputs.

Reads ~/soc_revision_data/wp5_replay/<policy>/loso_*/{summaries,intervals,integrity,samples}.csv.gz
and the WP4 static primary table, and writes CSV tables and tables.md. No statistical test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ROOT = Path.home() / "soc_revision_data/wp5_replay"
OUT = Path.home() / "soc_revision_data/wp5_replay_tables"
STATIC = Path.home() / "soc_revision_data/wp4_stage2_tables/r1_t1_primary_long.csv"


def load(root: Path, name: str) -> pd.DataFrame:
    parts = [pd.read_csv(p) for p in sorted(root.glob(f"P*/loso_*/{name}.csv.gz")) if p.stat().st_size]
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def method(frame: pd.DataFrame) -> pd.Series:
    rules = frame["rules"].astype(str)
    return np.where(rules == "untuned", frame["candidate_id"],
                    np.where(rules.str.contains("primary"), frame["family"] + " (primary rule)", frame["family"] + " (secondary rule)"))


def markdown(frame: pd.DataFrame, digits: int = 3) -> str:
    def cell(value) -> str:
        if value is None or (isinstance(value, float) and np.isnan(value)):
            return "NA"
        if isinstance(value, (float, np.floating)):
            return str(int(value)) if float(value).is_integer() else f"{value:.{digits}f}"
        return str(value).replace("|", "\\|")
    lines = ["| " + " | ".join(map(str, frame.columns)) + " |", "| " + " | ".join("---" for _ in frame.columns) + " |"]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in frame.itertuples(index=False)]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--out", default=str(OUT))
    parser.add_argument("--static", default=str(STATIC))
    args = parser.parse_args()
    root, out = Path(args.root), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    summaries, intervals, integrity, samples = (load(root, n) for n in ("summaries", "intervals", "integrity", "samples"))
    summaries["method"] = method(summaries)
    intervals["method"] = method(intervals)
    headline = summaries[summaries["rules"].astype(str).str.contains("untuned|primary")]
    written = {}

    def save(name: str, frame: pd.DataFrame) -> pd.DataFrame:
        path = out / f"{name}.csv"
        frame.to_csv(path, index=False)
        written[name] = {"rows": int(len(frame)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        return frame

    # 1. primary replay table (P1, rate 12)
    p1 = headline[(headline["policy"] == "P1") & (headline["rate_per_hour"] == 12.0)].copy()
    p1["cell"] = (p1["covered_intervals"].astype(int).astype(str) + "/" + p1["defined_intervals"].astype(int).astype(str)
                  + " · FP " + p1["fp_investigations"].astype(int).astype(str)
                  + " · rec " + p1["critical_recall_by_horizon"].map(lambda v: "NA" if pd.isna(v) else f"{v:.3f}")
                  + " · starved " + p1["starved_critical"].astype(int).astype(str))
    cells = p1.pivot_table(index="method", columns="held_out", values="cell", aggfunc="first")
    summary = p1.groupby("method").agg(
        intervals_covered=("covered_intervals", "sum"), intervals_defined=("defined_intervals", "sum"),
        censored_intervals=("censored_intervals", "sum"), investigations_median=("investigations", "median"),
        fp_investigations_median=("fp_investigations", "median"), fp_investigation_share_median=("fp_investigation_share", "median"),
        critical_recall_by_horizon_median=("critical_recall_by_horizon", "median"),
        starved_critical_share_median=("starved_critical_share", "median"),
        median_delay_hours_detected_median=("median_delay_hours_detected", "median"),
        tie_decided_share_median=("tie_decided_share", "median"))
    save("primary_replay_cells", cells.reset_index())
    save("primary_replay_summary", summary.reset_index().sort_values(["intervals_covered", "fp_investigations_median"], ascending=[False, True]))

    # 2. capacity response
    capacity = headline.groupby(["policy", "method", "rate_per_hour"]).agg(
        intervals_covered=("covered_intervals", "sum"), censored_intervals=("censored_intervals", "sum"),
        covered_within_1h=("intervals_covered_within_1h", "sum"), covered_within_4h=("intervals_covered_within_4h", "sum"),
        covered_within_24h=("intervals_covered_within_24h", "sum"),
        fp_investigations_median=("fp_investigations", "median"), critical_recall_by_horizon_median=("critical_recall_by_horizon", "median"),
        critical_recall_within_1h_median=("critical_recall_within_1h", "median"), critical_recall_within_24h_median=("critical_recall_within_24h", "median"),
        starved_critical_share_median=("starved_critical_share", "median"), peak_backlog_median=("peak_backlog", "median"),
        time_average_backlog_median=("time_average_backlog", "median"), tie_decided_share_median=("tie_decided_share", "median")).reset_index()
    save("capacity_response", capacity)

    # 3. delay table (with censoring)
    delay = intervals[intervals["rules"].astype(str).str.contains("untuned|primary") & intervals["eligible"].astype(bool)]
    delay_summary = delay.groupby(["policy", "method", "rate_per_hour"]).agg(
        eligible=("eligible", "size"), detected=("detected", "sum"), censored=("censored", "sum"),
        median_delay_hours_detected=("delay_hours", "median"), max_delay_hours=("delay_hours", "max"),
        median_censoring_hours=("censoring_hours", "median")).reset_index()
    save("delay_summary", delay_summary)
    save("delay_intervals_primary_rate", delay[delay["rate_per_hour"] == 12.0])

    # 4. backlog and queue age
    backlog = headline.groupby(["policy", "method", "rate_per_hour"]).agg(
        peak_backlog_median=("peak_backlog", "median"), backlog_at_horizon_median=("backlog_at_horizon", "median"),
        time_average_backlog_median=("time_average_backlog", "median"), wait_median_hours=("wait_median_seconds", lambda s: s.median() / 3600),
        wait_p90_hours=("wait_p90_seconds", lambda s: s.median() / 3600), wait_max_hours=("wait_max_seconds", lambda s: s.max() / 3600),
        uninvestigated_age_median_hours=("uninvestigated_age_median_seconds", lambda s: s.median() / 3600),
        utilization_median=("utilization", "median")).reset_index()
    save("backlog_queue_age", backlog)

    # starvation of low-confidence critical alerts
    starvation = headline.groupby(["policy", "method", "rate_per_hour"])[
        ["critical_total", "starved_critical", "low_confidence_critical", "starved_low_confidence_critical", "other_critical", "starved_other_critical"]].sum().reset_index()
    starvation["starved_low_confidence_share"] = starvation["starved_low_confidence_critical"] / starvation["low_confidence_critical"].replace(0, np.nan)
    starvation["starved_other_share"] = starvation["starved_other_critical"] / starvation["other_critical"].replace(0, np.nan)
    save("starvation", starvation)

    # 5. static versus replay (descriptive)
    static_path = Path(args.static)
    if static_path.exists():
        static = pd.read_csv(static_path).rename(columns={"analysis_unit": "held_out", "covered_intervals": "static_covered_k100",
                                                          "negatives_in_top": "static_fp_k100"})
        replay_p1 = headline[headline["policy"] == "P1"].pivot_table(index=["method", "held_out"], columns="rate_per_hour",
                                                                     values=["covered_intervals", "fp_investigations", "investigations"], aggfunc="first")
        replay_p1.columns = [f"replay_{metric}_rate_{rate:g}" for metric, rate in replay_p1.columns]
        joined = static[["method", "held_out", "static_covered_k100", "static_fp_k100"]].merge(replay_p1.reset_index(), on=["method", "held_out"], how="inner")
        save("static_vs_replay", joined)
        totals = joined.groupby("method").sum(numeric_only=True).reset_index()
        save("static_vs_replay_totals", totals)

    # 6. tie-decided selections, 7. trace samples, 8. integrity
    save("tie_decided", headline.groupby(["policy", "method", "rate_per_hour"])["tie_decided_share"].median().reset_index())
    if not samples.empty:
        save("trace_samples_fox", samples[(samples["held_out"] == "fox") & (samples["policy"] == "P1")])
    save("integrity", integrity.groupby(["policy", "rate_per_hour"]).agg(replays=("passed", "size"), passed=("passed", "sum"),
                                                                         checked_selections=("checked_selections", "sum")).reset_index())
    save("secondary_rule_summary", summaries[summaries["rules"].astype(str) == "secondary"])

    lines = ["# WP5 replay tables (generated)", "",
             "Generated by `scripts/revision/wp5_tables.py`. Coverage is temporal coverage of critical-step intervals by investigated alerts; "
             "rates are simulation assumptions; scenarios are the units; no statistical test.", "",
             "## Primary replay (P1, 12 alerts/hour)", "", markdown(cells.reset_index()), "",
             markdown(pd.read_csv(out / "primary_replay_summary.csv")), "",
             "## Capacity response", "", markdown(capacity), "", "## Delay (with censoring)", "", markdown(delay_summary), "",
             "## Backlog and queue age", "", markdown(backlog), "", "## Starvation", "", markdown(starvation), "",
             "## Integrity", "", markdown(pd.read_csv(out / "integrity.csv")), ""]
    if (out / "static_vs_replay_totals.csv").exists():
        lines += ["## Static top-100 versus replay (P1, totals over scenarios; descriptive)", "", markdown(pd.read_csv(out / "static_vs_replay_totals.csv")), ""]
    (out / "tables.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "index.json").write_text(json.dumps({"source_root": str(root), "tables": written}, indent=1))
    print(json.dumps({k: v["rows"] for k, v in written.items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

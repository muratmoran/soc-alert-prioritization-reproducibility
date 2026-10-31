#!/usr/bin/env python
"""WP4: verify fitting boundaries and input provenance, and write fitting_boundary_verification.json.

The record is ``verified: true`` only if every item below holds for the files as they are now:

* the full unit-test suite passes with exactly the one declared expected failure (this includes
  the WP4 adversarial, cache, reliability, split and trace-verification tests);
* every WP4 negative control is detected (rerun here);
* native-score provenance: exact raw/cache alignment and re-derivation, and both cache identities;
* the real-data fitting check passed: every declared split and policy executed, every trace
  verified against its exclusion sets, observed fit sets equal the required ones, independent
  arithmetic and adversarial checks passed, and no held-out label was read. The check must
  have been run on the current code: its recorded code hashes must equal the files now;
* the grid registry is reproduced by the config, has not seen revised results, and records
  what it supersedes;
* the WP3 metric verification record is verified and not stale.

The record pins SHA-256 hashes of the fitting specification, implementation, tests, negative
controls, split machinery, protocols, registry and evidence files. The gated comparison runner
re-hashes them and refuses a stale record. Checks existing in the code are not sufficient:
actual executions are verified.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parent
PY = sys.executable
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402

DATA = Path.home() / "soc_revision_data/cache"
PINNED = sorted({
    *(str(p.relative_to(PROJECT_ROOT)) for p in (PROJECT_ROOT / "src/soc_alert_ranking/revision").glob("*.py")),
    "src/soc_alert_ranking/mappings/severity.py",
    "src/soc_alert_ranking/mappings/context.py",
    "src/soc_alert_ranking/loaders/ait_alert.py",
    "configs/severity_mapping.yaml",
    "configs/revision_wp2.yaml",
    "tests/test_wp4_fitting_boundaries.py",
    "tests/wp4_reference_fitting.py",
    "tests/test_wp2_fitting_isolation.py",
    "tests/test_wp2_pipeline.py",
    "tests/wp2_fixtures.py",
    "scripts/revision/wp4_native_score_provenance.py",
    "scripts/revision/wp4_negative_controls.py",
    "scripts/revision/wp4_fitting_boundary_check.py",
    "scripts/revision/wp4_write_verification_record.py",
    "docs/revision/wp4/stage2_reporting_specification.md",
    "scripts/revision/wp2_run_comparison.py",
    "scripts/revision/wp2_freeze_grid_registry.py",
    "docs/revision/wp4/fitting_specification.md",
    "docs/revision/wp4/negative_controls.json",
    "docs/revision/wp4/native_score_provenance.json",
    "docs/revision/wp4/real_data_fitting_check.json",
    "docs/revision/wp4/split_manifests.json",
    "docs/revision/wp2/grid_registry.json",
    "docs/revision/wp3/metric_verification.json",
    "docs/revision/wp3/metric_contract.md",
    "docs/revision/protocol_v1_1.md",
    "docs/revision/protocol_v1.md",
})


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(args: list[str]) -> tuple[int, str]:
    completed = subprocess.run(args, cwd=PROJECT_ROOT, capture_output=True, text=True)
    return completed.returncode, completed.stdout + completed.stderr


def expected_chain_count(manifests: dict) -> int:
    loso = len(manifests["loso"])
    return loso * 2 + loso * 10 + len(manifests["identifier_holdout_splits"]) + len(manifests["forward_chaining_splits"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rerun-real-data", action="store_true", help="rerun wp4_fitting_boundary_check.py first (~20 min)")
    args = parser.parse_args()
    checks: dict[str, dict] = {}

    code, output = run([PY, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests"])
    ran = re.search(r"Ran (\d+) tests", output)
    expected_failures = re.search(r"expected failures=(\d+)", output)
    wp4_code, wp4_output = run([PY, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-p", "test_wp4_fitting_boundaries.py"])
    wp4_ran = re.search(r"Ran (\d+) tests", wp4_output)
    checks["unit_tests"] = {
        "exit_code": code, "tests_run": int(ran.group(1)) if ran else None,
        "expected_failures": int(expected_failures.group(1)) if expected_failures else 0,
        "wp4_tests_run": int(wp4_ran.group(1)) if wp4_ran else None, "wp4_exit_code": wp4_code,
        "passed": code == 0 and bool(expected_failures) and int(expected_failures.group(1)) == 1 and wp4_code == 0,
        "expected_failure_meaning": "historical NF-UQ sample inclusion uses true categories (known violation N1)",
    }

    code, _ = run([PY, "-W", "ignore", "scripts/revision/wp4_negative_controls.py"])
    controls = json.loads((PROJECT_ROOT / "docs/revision/wp4/negative_controls.json").read_text())
    checks["negative_controls"] = {
        "exit_code": code, "controls": len(controls["controls"]), "detected": sum(c["detected"] for c in controls["controls"]),
        "not_visible_in_traces": controls["undetectable_from_trace_alone"],
        "test_module_matches": controls["test_module_sha256"] == sha256(PROJECT_ROOT / "tests/test_wp4_fitting_boundaries.py"),
    }
    checks["negative_controls"]["passed"] = code == 0 and controls["all_detected"] and checks["negative_controls"]["test_module_matches"]

    provenance = json.loads((PROJECT_ROOT / "docs/revision/wp4/native_score_provenance.json").read_text())
    alignment = provenance["alignment_with_canonical_cache"]
    canonical_identity = json.loads((DATA / "ait_canonical_original_labels.pkl.json").read_text())
    provenance_identity = json.loads((DATA / "ait_native_score_provenance.pkl.json").read_text())
    checks["native_score_provenance"] = {
        **{k: v for k, v in alignment.items()},
        "canonical_cache_identity": sha256(DATA / "ait_canonical_original_labels.pkl.gz") == canonical_identity["sha256"],
        "provenance_cache_identity": sha256(DATA / "ait_native_score_provenance.pkl.gz") == provenance_identity["sha256"],
        "provenance_built_from_canonical_cache": provenance_identity["canonical_cache_sha256"] == canonical_identity["sha256"],
        "raw_files_verified": provenance["raw_files_verified"],
        "resolution": "separate single-scale native references (O_native_rule_level, O_native_suricata_severity); pooled score provenance only",
    }
    checks["native_score_provenance"]["passed"] = all(v for k, v in checks["native_score_provenance"].items()
                                                      if isinstance(v, bool))

    if args.rerun_real_data:
        run([PY, "-W", "ignore", "scripts/revision/wp4_fitting_boundary_check.py", "--workers", "4"])
    real = json.loads((PROJECT_ROOT / "docs/revision/wp4/real_data_fitting_check.json").read_text())
    manifests = json.loads((PROJECT_ROOT / "docs/revision/wp4/split_manifests.json").read_text())
    stale = [path for path, digest in real["code_sha256"].items() if sha256(PROJECT_ROOT / path) != digest]
    chains = real["fitting_chains"]
    summaries = chains["summaries"]
    checks["real_data_fitting_chains"] = {
        "chains": chains["total"], "expected_chains": expected_chain_count(manifests), "passed_chains": chains["passed"],
        "by_policy_label": chains["by_policy_label"],
        "trace_verifications_passed": sum(s.get("trace_verification_passed", False) for s in summaries),
        "fit_sets_matched": sum(s.get("fit_sets_match", False) for s in summaries),
        "held_out_table_reads": sum(s.get("table_reads_of_held_out", 1) for s in summaries),
        "held_out_label_reads": sum(s.get("held_out_label_reads", 1) for s in summaries),
        "excluded_rows_in_learned_samples": sum(s.get("excluded_identifier_rows_in_learned_samples", 1) for s in summaries),
        "holdout_inner_queue_alerts_removed": sum(s.get("inner_queue_alerts_removed", 0) for s in summaries
                                                  if s["policy_label"] == "holdout:primary"),
        "feature_requests": sum(s.get("feature_requests", 0) for s in summaries),
        "table_reads": sum(s.get("table_reads", 0) for s in summaries),
        "cached_feature_requests": sum(s.get("cached_feature_requests", 0) for s in summaries),
        "learned_selection_fallbacks": sorted({f"{s['split']}: {f}" for s in summaries for f in s.get("learned_selection_fallbacks", [])}),
        "scores_or_metrics_computed": False,
        "code_hashes_current": not stale, "stale_files": stale,
        "generated_at": real["generated_at"],
    }
    rc = checks["real_data_fitting_chains"]
    rc["passed"] = bool(real["passed"] and not stale and rc["chains"] == rc["expected_chains"] == rc["passed_chains"]
                        == rc["trace_verifications_passed"] == rc["fit_sets_matched"] and rc["held_out_table_reads"] == 0
                        and rc["held_out_label_reads"] == 0 and rc["excluded_rows_in_learned_samples"] == 0)
    arithmetic = real["independent_arithmetic"]
    checks["real_data_independent_arithmetic"] = {
        name: {k: v[k] for k in ("fit_sets", "cells_checked", "keys_checked", "mismatch_count")} for name, v in arithmetic.items()}
    checks["real_data_independent_arithmetic"]["passed"] = all(v["passed"] for v in arithmetic.values()) and not stale
    checks["real_data_adversarial_and_cache"] = {**real["adversarial_and_cache_checks"]}
    checks["real_data_adversarial_and_cache"]["passed"] = bool(real["adversarial_and_cache_checks"]["passed"] and not stale)
    checks["label_free_mapping_coverage"] = {
        "folds": len(real["held_out_mapping_coverage_label_free"]),
        "held_out_label_reads": sum(c["held_out_label_reads"] for c in real["held_out_mapping_coverage_label_free"]),
        "calibration_quality": real["calibration_quality"],
    }
    checks["label_free_mapping_coverage"]["passed"] = checks["label_free_mapping_coverage"]["held_out_label_reads"] == 0

    config = load_comparison_config(PROJECT_ROOT / "configs/revision_wp2.yaml")
    registry = json.loads((PROJECT_ROOT / "docs/revision/wp2/grid_registry.json").read_text())
    checks["grid_registry"] = {
        "registry_sha256": registry["registry_sha256"], "candidates": len(registry["candidates"]),
        "tuned_per_inner_fold": registry["tuned_candidates_per_inner_fold"],
        "reproduced_by_config": config.registry()["registry_sha256"] == registry["registry_sha256"],
        "revised_results_seen": registry["revised_results_seen"],
        "supersedes": registry.get("supersedes"),
        "superseded_archive_exists": bool(registry.get("supersedes")) and (PROJECT_ROOT / registry["supersedes"]["archived_as"]).exists(),
    }
    checks["grid_registry"]["passed"] = (checks["grid_registry"]["reproduced_by_config"] and not registry["revised_results_seen"]
                                         and checks["grid_registry"]["superseded_archive_exists"])

    wp3 = json.loads((PROJECT_ROOT / "docs/revision/wp3/metric_verification.json").read_text())
    wp3_stale = [path for path, digest in wp3["code_identity"]["file_sha256"].items()
                 if not (PROJECT_ROOT / path).exists() or sha256(PROJECT_ROOT / path) != digest]
    checks["wp3_metric_record"] = {"verified": wp3["verified"], "contract_version": wp3["contract"]["version"],
                                   "generated_at": wp3["generated_at"], "stale_files": wp3_stale,
                                   "passed": bool(wp3["verified"] and not wp3_stale)}

    verified = all(check["passed"] for check in checks.values())
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip()
    import numpy, pandas, scipy, sklearn  # noqa: E401

    record = {
        "work_package": "WP4 stage 1: fitting boundaries and input provenance",
        "verified": verified,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "scope": "Fitting isolation verified by synthetic fault injection and by executed real-data fitting chains for every declared "
                 "split and input policy; native-score provenance resolved from raw data. No candidate was scored on AIT and no "
                 "comparative metric was computed.",
        "gate_note": "Together with a verified, non-stale docs/revision/wp3/metric_verification.json this record opens the "
                     "comparison gate in scripts/revision/wp2_run_comparison.py.",
        "protocol": {"active": "docs/revision/protocol_v1_1.md", "sha256": sha256(PROJECT_ROOT / "docs/revision/protocol_v1_1.md")},
        "fitting_specification": {"path": "docs/revision/wp4/fitting_specification.md", "version": "1.0",
                                  "sha256": sha256(PROJECT_ROOT / "docs/revision/wp4/fitting_specification.md")},
        "registry_sha256": registry["registry_sha256"],
        "code_identity": {
            "git_head": head,
            "working_tree_note": "revision code is uncommitted; identity is established by the file hashes below",
            "file_sha256": {path: sha256(PROJECT_ROOT / path) for path in PINNED},
        },
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": numpy.__version__,
                        "pandas": pandas.__version__, "scipy": scipy.__version__, "sklearn": sklearn.__version__},
        "checks": checks,
        "deferred_scope": ["protocol §6.2 expanded operational vector: deferred, unimplemented (protocol amendment 2026-09-15); not a completed or prespecified comparison"],
    }
    out = PROJECT_ROOT / "docs/revision/wp4/fitting_boundary_verification.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"verified": verified, **{k: v["passed"] for k, v in checks.items()}}, indent=2))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

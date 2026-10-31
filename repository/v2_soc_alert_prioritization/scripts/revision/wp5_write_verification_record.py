#!/usr/bin/env python
"""WP5: verify the replay implementation before full runs and write replay_verification.json.

``verified: true`` only if all of these hold for the files as they are now:

* the full unit-test suite passes with exactly the one declared expected failure, including the
  WP5 hand examples, the independent reference agreement, integrity and label-invariance tests;
* every WP5 negative control is detected (rerun here);
* the real-data precheck passed and was run on the current replay code;
* the local stage-2 score copy matches its pinned SHA256SUMS hash;
* the WP3 and WP4 verification records are verified and not stale.

It pins the replay specification, implementation, tests, controls, precheck and score
identities. The full-replay runner re-hashes them and refuses a stale record.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parent
PY = sys.executable
sys.path.insert(0, str(PROJECT_ROOT / "scripts/revision"))

from wp5_common import sha256, verify_stage2_copy  # noqa: E402

PINNED = sorted([
    "docs/revision/wp5/replay_specification.md",
    "src/soc_alert_ranking/revision/replay.py",
    "src/soc_alert_ranking/revision/evaluation.py",
    "src/soc_alert_ranking/revision/labels.py",
    "src/soc_alert_ranking/revision/metrics.py",
    "tests/test_wp5_replay.py",
    "tests/wp5_reference_replay.py",
    "tests/wp3_support.py",
    "tests/wp2_fixtures.py",
    "scripts/revision/wp5_common.py",
    "scripts/revision/wp5_real_data_precheck.py",
    "scripts/revision/wp5_negative_controls.py",
    "scripts/revision/wp5_run_replay.py",
    "scripts/revision/wp5_write_verification_record.py",
    "docs/revision/wp5/negative_controls.json",
    "docs/revision/wp5/real_data_precheck.json",
    "docs/revision/wp4/stage2_output_manifest.json",
    "docs/revision/wp3/metric_verification.json",
    "docs/revision/wp4/fitting_boundary_verification.json",
    "docs/revision/protocol_v1_1.md",
    "docs/revision/protocol_v1.md",
])


def run(args: list[str]) -> tuple[int, str]:
    completed = subprocess.run(args, cwd=PROJECT_ROOT, capture_output=True, text=True)
    return completed.returncode, completed.stdout + completed.stderr


def record_current(gate: str) -> dict[str, object]:
    record = json.loads((PROJECT_ROOT / gate).read_text())
    stale = [p for p, d in record["code_identity"]["file_sha256"].items() if not (PROJECT_ROOT / p).exists() or sha256(PROJECT_ROOT / p) != d]
    return {"verified": record["verified"], "generated_at": record["generated_at"], "stale_files": stale,
            "passed": bool(record["verified"] and not stale)}


def main() -> int:
    checks: dict[str, dict] = {}
    code, output = run([PY, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests"])
    ran = re.search(r"Ran (\d+) tests", output)
    expected = re.search(r"expected failures=(\d+)", output)
    wp5_code, wp5_output = run([PY, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-p", "test_wp5_replay.py"])
    wp5_ran = re.search(r"Ran (\d+) tests", wp5_output)
    checks["unit_tests"] = {"exit_code": code, "tests_run": int(ran.group(1)) if ran else None,
                            "expected_failures": int(expected.group(1)) if expected else 0,
                            "wp5_tests_run": int(wp5_ran.group(1)) if wp5_ran else None, "wp5_exit_code": wp5_code,
                            "passed": code == 0 and bool(expected) and int(expected.group(1)) == 1 and wp5_code == 0}

    code, _ = run([PY, "-W", "ignore", "scripts/revision/wp5_negative_controls.py"])
    controls = json.loads((PROJECT_ROOT / "docs/revision/wp5/negative_controls.json").read_text())
    checks["negative_controls"] = {"exit_code": code, "controls": len(controls["controls"]),
                                   "detected": sum(c["detected"] for c in controls["controls"]),
                                   "test_module_matches": controls["test_module_sha256"] == sha256(PROJECT_ROOT / "tests/test_wp5_replay.py")}
    checks["negative_controls"]["passed"] = code == 0 and controls["all_detected"] and checks["negative_controls"]["test_module_matches"]

    precheck = json.loads((PROJECT_ROOT / "docs/revision/wp5/real_data_precheck.json").read_text())
    stale = [p for p, d in precheck["code_sha256"].items() if sha256(PROJECT_ROOT / p) != d]
    checks["real_data_precheck"] = {"passed_record": precheck["passed"], "stale_files": stale,
                                    "score_alignment_all_folds": precheck["score_alignment_all_folds"],
                                    "largest_fold": {k: precheck["largest_fold"][k] for k in ("held_out", "replays", "all_integrity_passed",
                                                                                              "identical_arrivals_across_candidates")},
                                    "label_mutation_invariance_real_data": precheck["label_mutation_invariance_real_data"],
                                    "projection": precheck["projection"],
                                    "passed": bool(precheck["passed"] and not stale)}

    stage2 = verify_stage2_copy()
    checks["stage2_scores"] = {"sha256sums_sha256": stage2["sha256sums_sha256"], "files": len(stage2["files"]),
                               "matches_precheck": stage2["sha256sums_sha256"] == precheck["stage2_sha256sums_sha256"]}
    checks["stage2_scores"]["passed"] = checks["stage2_scores"]["matches_precheck"]
    checks["wp3_metric_record"] = record_current("docs/revision/wp3/metric_verification.json")
    checks["wp4_fitting_record"] = record_current("docs/revision/wp4/fitting_boundary_verification.json")

    free = shutil.disk_usage(Path.home() / "soc_revision_data").free
    verified = all(c["passed"] for c in checks.values())
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip()
    import numpy, pandas  # noqa: E401
    record = {
        "work_package": "WP5 chronological replay (verification before full runs)",
        "verified": verified,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "scope": "Replay semantics verified by hand examples, an independent reference simulator, integrity and label-invariance tests, "
                 "injected faults and a label-free real-data precheck. No label-dependent replay outcome was computed on AIT.",
        "specification": {"path": "docs/revision/wp5/replay_specification.md", "version": "1.0",
                          "sha256": sha256(PROJECT_ROOT / "docs/revision/wp5/replay_specification.md")},
        "capacity_assessment": {"free_bytes_now": free, "projected_output_bytes": precheck["projection"]["projected_output_bytes"],
                                "reserve_bytes": 5 * 1024 ** 3, "output_root": "~/soc_revision_data/wp5_replay (outside iCloud)",
                                "adequate": free - precheck["projection"]["projected_output_bytes"] >= 5 * 1024 ** 3},
        "code_identity": {"git_head": head, "working_tree_note": "revision code is uncommitted; identity is established by file hashes",
                          "file_sha256": {path: sha256(PROJECT_ROOT / path) for path in PINNED}},
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": numpy.__version__, "pandas": pandas.__version__},
        "checks": checks,
    }
    out = PROJECT_ROOT / "docs/revision/wp5/replay_verification.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"verified": verified, **{k: v["passed"] for k, v in checks.items()}, "capacity": record["capacity_assessment"]}, indent=1))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

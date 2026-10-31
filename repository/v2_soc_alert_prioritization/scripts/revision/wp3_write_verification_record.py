#!/usr/bin/env python
"""WP3: rerun every metric verification step and write docs/revision/wp3/metric_verification.json.

The record is ``verified: true`` only if all of these hold:

* the full unit-test suite passes, with exactly the one declared expected failure;
* every WP3 negative control is detected;
* the real-data label construction check passes;
* the label-free structural audit completes.

It pins SHA-256 hashes of the code, tests, scripts, configs, contract, reference examples and
protocols. The gated comparison runner re-hashes these files and refuses a stale record.
This record alone does not open the comparison gate: WP4 verification is also required.
"""

from __future__ import annotations

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

PINNED = sorted({
    *(str(p.relative_to(PROJECT_ROOT)) for p in (PROJECT_ROOT / "src/soc_alert_ranking/revision").glob("*.py")),
    "src/soc_alert_ranking/mappings/severity.py",
    "src/soc_alert_ranking/mappings/context.py",
    "src/soc_alert_ranking/rankers/revision_scores.py",
    "configs/severity_mapping.yaml",
    "configs/revision_wp2.yaml",
    *(str(p.relative_to(PROJECT_ROOT)) for p in (PROJECT_ROOT / "tests").glob("test_wp3_*.py")),
    "tests/wp3_reference_metrics.py",
    "tests/wp3_support.py",
    *(str(p.relative_to(PROJECT_ROOT)) for p in (PROJECT_ROOT / "scripts/revision").glob("wp3_*.py")),
    "docs/revision/wp3/metric_contract.md",
    "docs/revision/wp3/reference_examples.json",
    "docs/revision/protocol_v1_1.md",
    "docs/revision/protocol_v1.md",
})


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: list[str]) -> tuple[int, str]:
    completed = subprocess.run(args, cwd=PROJECT_ROOT, capture_output=True, text=True)
    return completed.returncode, completed.stdout + completed.stderr


def main() -> int:
    checks: dict[str, object] = {}

    code, output = run([PY, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests"])
    ran = re.search(r"Ran (\d+) tests", output)
    expected_failures = re.search(r"expected failures=(\d+)", output)
    checks["unit_tests"] = {
        "exit_code": code, "tests_run": int(ran.group(1)) if ran else None,
        "expected_failures": int(expected_failures.group(1)) if expected_failures else 0,
        "passed": code == 0 and bool(expected_failures) and int(expected_failures.group(1)) == 1,
        "expected_failure_meaning": "historical NF-UQ sample inclusion uses true categories (known violation N1)",
    }

    code, _ = run([PY, "-W", "ignore", "scripts/revision/wp3_negative_controls.py"])
    controls = json.loads((PROJECT_ROOT / "docs/revision/wp3/negative_controls.json").read_text())
    checks["negative_controls"] = {"exit_code": code, "controls": len(controls["controls"]),
                                   "detected": sum(c["detected"] for c in controls["controls"]),
                                   "passed": code == 0 and controls["all_detected"]}

    code, _ = run([PY, "-W", "ignore", "scripts/revision/wp3_label_verification.py"])
    labels = json.loads((PROJECT_ROOT / "docs/revision/wp3/label_verification.json").read_text())
    checks["real_data_label_construction"] = {"exit_code": code, **labels["checks"], "passed": code == 0 and labels["passed"]}

    code, _ = run([PY, "-W", "ignore", "scripts/revision/wp3_structural_audit.py"])
    checks["real_data_structural_audit"] = {"exit_code": code, "passed": code == 0}

    verified = all(check["passed"] for check in checks.values())
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip()
    import numpy, pandas, scipy, sklearn  # noqa: E401

    record = {
        "work_package": "WP3 metric contract",
        "verified": verified,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "scope": "Metrics fully specified and independently checked on hand-built, randomized and synthetic data; real AIT data used only for method-independent label construction and label-free structure. No comparative AIT result was produced.",
        "gate_note": "This record does not open the comparison gate by itself; docs/revision/wp4/fitting_boundary_verification.json must also be verified.",
        "regeneration_note": "Regenerated in WP4 stage 1 after the native-score correction (two single-scale native references, registry of 157 candidates), metric contract v1.1 (§9 provenance, §9a subgroup retrieval in the mixed queue) and fitting-code changes; no comparative result had been produced.",
        "protocol": {"active": "docs/revision/protocol_v1_1.md", "sha256": sha256(PROJECT_ROOT / "docs/revision/protocol_v1_1.md"),
                     "frozen_v1_sha256": sha256(PROJECT_ROOT / "docs/revision/protocol_v1.md")},
        "contract": {"path": "docs/revision/wp3/metric_contract.md", "version": "1.1",
                     "sha256": sha256(PROJECT_ROOT / "docs/revision/wp3/metric_contract.md")},
        "code_identity": {
            "git_head": head,
            "working_tree_note": "revision code is uncommitted; identity is established by the file hashes below",
            "file_sha256": {path: sha256(PROJECT_ROOT / path) for path in PINNED},
        },
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "numpy": numpy.__version__,
                        "pandas": pandas.__version__, "scipy": scipy.__version__, "sklearn": sklearn.__version__},
        "checks": checks,
        "errata_preserved": ["claim_evidence_audit.md Errata (79 non-overlapping intervals)", "protocol_v1_1.md change log erratum"],
    }
    out = PROJECT_ROOT / "docs/revision/wp3/metric_verification.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps({"verified": verified, "checks": checks}, indent=2))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python
"""WP2: record the comparison grids before any comparative run.

Writes docs/revision/wp2/grid_registry.json (all candidates in declared grid order,
config and registry SHA-256) and grid_registry.csv. Refuses to overwrite an
existing registry whose hash differs, so a grid change cannot silently replace the
frozen record.

A registry can be superseded only with ``--supersede-reason`` and only if the active protocol's
change log already names the new candidate count (e.g. "157 candidates"). The previous
registry and CSV are archived under docs/revision/wp2/superseded/ with their hash in the file
name, and the new record points to the archive. Superseding is refused once
``revised_results_seen`` is true.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(PROJECT_ROOT / "configs/revision_wp2.yaml"))
    parser.add_argument("--out-dir", default=str(PROJECT_ROOT / "docs/revision/wp2"))
    parser.add_argument("--supersede-reason", default=None,
                        help="replace a differing frozen registry; requires a matching protocol change-log entry")
    args = parser.parse_args()

    config = load_comparison_config(args.config)
    registry = config.registry()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "grid_registry.json"
    supersedes = None
    if target.exists():
        previous = json.loads(target.read_text())
        if previous["registry_sha256"] == registry["registry_sha256"]:
            print(f"Registry unchanged: {registry['registry_sha256']}")
            return 0
        if not args.supersede_reason:
            raise SystemExit("grid registry differs from the frozen record; amend the protocol change log first")
        if previous.get("revised_results_seen", True):
            raise SystemExit("refusing to supersede a registry after revised results were seen")
        change_log = (PROJECT_ROOT / "docs/revision/protocol_v1_1.md").read_text().split("## 14. Change log", 1)[-1]
        if f"{len(registry['candidates'])} candidates" not in change_log:
            raise SystemExit(f"protocol change log does not record the new registry size ({len(registry['candidates'])} candidates)")
        archive = out_dir / "superseded"
        archive.mkdir(exist_ok=True)
        stem = f"grid_registry_{previous['registry_sha256'][:12]}"
        shutil.copy2(target, archive / f"{stem}.json")
        if (out_dir / "grid_registry.csv").exists():
            shutil.copy2(out_dir / "grid_registry.csv", archive / f"{stem}.csv")
        supersedes = {"registry_sha256": previous["registry_sha256"], "candidates": len(previous["candidates"]),
                      "frozen_at": previous.get("frozen_at"), "archived_as": str((archive / f"{stem}.json").relative_to(PROJECT_ROOT)),
                      "reason": args.supersede_reason}
    registry.update({
        "frozen_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "config_path": str(Path(args.config).resolve().relative_to(PROJECT_ROOT)),
        "protocol": "docs/revision/protocol_v1_1.md",
        "revised_results_seen": False,
        "supersedes": supersedes,
        "families": {name: {"tuned": spec.tuned, "learned": spec.learned, "granularity": spec.granularity,
                            "candidates": len(spec.candidates), "heuristic_label": spec.heuristic_label}
                     for name, spec in config.families.items()},
    })
    target.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    pd.DataFrame(registry["candidates"]).to_csv(out_dir / "grid_registry.csv", index=False)
    print(f"Froze {len(registry['candidates'])} candidates ({registry['tuned_candidates_per_inner_fold']} tuned per inner fold)")
    print(f"registry_sha256={registry['registry_sha256']} config_sha256={registry['config_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

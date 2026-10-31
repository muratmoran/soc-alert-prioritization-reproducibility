"""Shared helpers for WP3 tests: build production and reference objects from example dicts."""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path

import numpy as np
import pandas as pd

import wp2_fixtures  # noqa: F401  (sets sys.path)
from soc_alert_ranking.mappings.severity import SeverityMapping
from soc_alert_ranking.revision.evaluation import full_order
from soc_alert_ranking.revision.features import stable_hash_keys
from soc_alert_ranking.revision.labels import build_scenario_labels, intervals_from_frame, phase_order

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_PATH = PROJECT_ROOT / "docs/revision/wp3/reference_examples.json"
SEVERITY = SeverityMapping.from_file()
PHASES = phase_order(SEVERITY)


def load_examples() -> dict[str, dict]:
    payload = json.loads(EXAMPLES_PATH.read_text())
    return {example["name"]: example for example in payload["examples"]}


def fraction(text: str) -> Fraction:
    return Fraction(text)


def production_labels(example: dict, tau: float | None = None, intervals: list[dict] | None = None):
    tau = example["tau"] if tau is None else tau
    rows = intervals if intervals is not None else example["intervals"]
    frame = intervals_from_frame(pd.DataFrame(rows, columns=["scenario", "attack", "start", "end"]), SEVERITY, tau)
    alerts = example["alerts"]
    ids = np.array([a["id"] for a in alerts], dtype=object)
    timestamps = np.array([a["t"] for a in alerts], dtype=float)
    labels = build_scenario_labels("ex", ids, timestamps, frame, PHASES, tau)
    return labels, frame


def production_scores(example: dict) -> np.ndarray:
    return np.array([np.nan if a["score"] is None else a["score"] for a in example["alerts"]], dtype=float)


def production_order(example: dict) -> np.ndarray:
    alerts = example["alerts"]
    return full_order(production_scores(example), np.array([a["t"] for a in alerts], dtype=float),
                      stable_hash_keys([a["id"] for a in alerts]))


def reference_intervals(example: dict) -> list[dict]:
    return [{"scenario": row["scenario"], "phase": row["attack"], "start": row["start"], "end": row["end"]}
            for row in example["intervals"]]


def reference_severity_table() -> dict[str, float]:
    return {phase: float(value) for phase, value in SEVERITY.ait_phase_severity.items()}

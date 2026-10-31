"""Shared synthetic fixtures for WP2 tests (no real AIT data)."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from soc_alert_ranking.mappings.severity import SeverityMapping  # noqa: E402
from soc_alert_ranking.revision.config import load_comparison_config  # noqa: E402
from soc_alert_ranking.revision.features import AlertFeatures, InputPolicy, RankingFrame  # noqa: E402
from soc_alert_ranking.revision.labels import LabelStore, intervals_from_frame, phase_order  # noqa: E402
from soc_alert_ranking.revision.pipeline import ComparisonPipeline  # noqa: E402
from soc_alert_ranking.revision.synthetic import make_synthetic_alerts  # noqa: E402

CONFIG_PATH = PROJECT_ROOT / "configs/revision_wp2.yaml"


def synthetic_setup(n_scenarios: int = 4, alerts_per_scenario: int = 500, seed: int = 1):
    config = load_comparison_config(CONFIG_PATH)
    severity = SeverityMapping.from_file()
    alerts, labels = make_synthetic_alerts(n_scenarios, alerts_per_scenario, seed=seed)
    ranking = RankingFrame.from_alerts(alerts)
    intervals = intervals_from_frame(labels, severity, config.tau)
    store = LabelStore.from_alerts(ranking.frame, intervals, phase_order(severity), config.tau)
    pipeline = ComparisonPipeline(ranking, store, severity, config)
    return config, severity, ranking, store, pipeline


def mutate_scenario_labels(store: LabelStore, scenario: str, seed: int) -> None:
    """Replace a scenario's labels with random (internally consistent) ones."""

    rng = np.random.default_rng(seed)
    labels = store.labels[scenario]
    n = len(labels.y)
    phase_membership = rng.random(labels.phase_membership.shape) < 0.3
    y = phase_membership.any(axis=1)
    s_star = np.where(y, rng.uniform(2.0, 9.5, n), 0.0)
    critical = rng.random(labels.critical_membership.shape) < 0.2
    store.replace(scenario, labels.replace_arrays(
        y=y, s_star=s_star, z=y & (s_star >= labels.tau), r=np.where(y, s_star, 0.0),
        phase_membership=phase_membership, critical_membership=critical,
    ))


def toy_features(**overrides) -> AlertFeatures:
    values = dict(
        scenario="toy", fit_set=frozenset({"a"}), policy=InputPolicy(),
        alert_ids=np.array(["t0", "t1", "t2"]), timestamp=np.array([10.0, 20.0, 30.0]),
        hash_key=np.array([3, 2, 1], dtype=np.uint64), detector=np.array(["aminer", "wazuh", "suricata"]),
        native_score=np.array([np.nan, 7.0, 0.75]),
        native_rule_level=np.array([np.nan, 7.0, 6.0]), native_suricata_severity=np.array([np.nan, np.nan, 2.0]),
        native_record_type=np.array(["aminer", "wazuh", "suricata_eve_alert"]),
        c=np.array([5.0, 3.0, 0.0]), u=np.array([0.5, 0.1, 0.35]), h=np.array([0.05, 0.95, 0.5]),
        h_key=np.array([0.2, 0.9, 0.6]), mapped=np.array([False, True, True]),
        h_fallback=np.zeros(3, dtype=np.int8), h_key_fallback=np.zeros(3, dtype=np.int8),
        excluded_identifier=np.zeros(3, dtype=bool),
    )
    values.update(overrides)
    return AlertFeatures(**values)

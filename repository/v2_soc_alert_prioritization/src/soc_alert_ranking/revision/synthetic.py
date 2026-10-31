"""Synthetic AIT-like alerts and label intervals for correctness and isolation tests.

The generator mimics the structures that matter for the pipeline, not AIT's
statistics: a small set of detector-native keys shared across scenarios, keys that
fire mostly inside one attack phase, background keys that fire everywhere (so
interval labels include benign-looking alerts), an overlapping dirb/wpscan window,
critical phases, a key absent from one scenario, a key present in only one
scenario, and AMiner alerts without a native score. It is vectorized so it can
also produce AIT-scale inputs for runtime checks.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


PHASE_WINDOWS = [
    ("network_scans", 1000.0, 1500.0),
    ("dirb", 1500.0, 2500.0),
    ("wpscan", 2000.0, 2300.0),          # overlaps dirb
    ("webshell", 3000.0, 3100.0),
    ("cracking", 4000.0, 4600.0),
    ("privilege_escalation", 5000.0, 5100.0),
    ("dnsteal", 7000.0, 8000.0),
]
TIMELINE = 10000.0
HOSTS = np.array(["web-01", "dns-server", "mail", "wazuh-client", ""])

# (detector, key suffix, phase it follows or None for background, relative rate)
KEY_SPECS = [
    ("wazuh", "scan", "network_scans", 3.0),
    ("wazuh", "dirb", "dirb", 4.0),
    ("aminer", "wpscan", "wpscan", 3.0),
    ("wazuh", "webshell", "webshell", 2.0),
    ("suricata", "brute", "cracking", 2.0),
    ("wazuh", "sudo", "privilege_escalation", 2.0),
    ("suricata", "dns", "dnsteal", 3.0),
    ("wazuh", "syslog", None, 3.0),
    ("suricata", "policy", None, 4.0),
    ("aminer", "value", None, 2.0),
]


def synthetic_label_frame(scenarios: list[str]) -> pd.DataFrame:
    rows = []
    for index, scenario in enumerate(scenarios):
        offset = 100.0 * index
        for phase, start, end in PHASE_WINDOWS:
            rows.append({"scenario": scenario, "attack": phase, "start": start + offset, "end": end + offset})
    return pd.DataFrame(rows)


def make_synthetic_alerts(n_scenarios: int = 4, alerts_per_scenario: int = 800, seed: int = 0) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (alerts with ranking-time columns, labels table in labels.csv format)."""

    rng = np.random.default_rng(seed)
    scenarios = [f"scn{index}" for index in range(n_scenarios)]
    labels = synthetic_label_frame(scenarios)
    windows = {phase: (start, end) for phase, start, end in PHASE_WINDOWS}
    frames = []
    for s_index, scenario in enumerate(scenarios):
        offset = 100.0 * s_index
        specs = [spec for k, spec in enumerate(KEY_SPECS) if not (s_index == n_scenarios - 1 and k == 3)]
        if s_index == 0:
            specs.append(("suricata", "rare", None, 0.5))   # key seen only in the first scenario
        weights = np.array([spec[3] for spec in specs])
        n = alerts_per_scenario
        choice = rng.choice(len(specs), size=n, p=weights / weights.sum())
        detector = np.array([spec[0] for spec in specs])[choice]
        suffix = np.array([spec[1] for spec in specs])[choice]
        phase = np.array([spec[2] or "" for spec in specs])[choice]
        start = np.array([windows[p][0] if p else 0.0 for _, _, p, _ in specs])[choice] + offset
        end = np.array([windows[p][1] if p else TIMELINE for _, _, p, _ in specs])[choice] + offset
        in_window = (phase != "") & (rng.random(n) < 0.85)
        timestamp = np.where(in_window, rng.uniform(start, end), rng.uniform(0.0, TIMELINE, n))
        # Native fields mirror AIT provenance: every Wazuh-delivered alert (Wazuh and Suricata) has a
        # rule level; only Suricata signature alerts carry a raw severity; AMiner has neither.
        rule_level = np.where(detector == "aminer", np.nan, rng.integers(3, 13, n).astype(float))
        signature_key = np.isin(suffix, ["brute", "rare"])
        suricata_severity = np.where((detector == "suricata") & signature_key, rng.integers(1, 4, n).astype(float), np.nan)
        score = np.where(detector == "wazuh", rule_level,
                         np.where(detector == "suricata",
                                  np.where(np.isnan(suricata_severity), rule_level, np.clip((5.0 - suricata_severity) / 4.0, 0, 1)),
                                  np.nan))
        keys = np.char.add(np.char.add(detector, ":"), suffix)
        frames.append(pd.DataFrame({
            "alert_id": np.char.add(f"{scenario}-", np.arange(n).astype(str)),
            "scenario": scenario,
            "timestamp": np.round(timestamp, 3),
            "detector": detector,
            "native_key": keys,
            "native_category": np.char.add(detector, "-group"),
            "native_name": suffix,
            "native_short": suffix,
            "host": HOSTS[rng.integers(0, len(HOSTS), n)],
            "ip": "",
            "detector_score": score,
            "native_rule_level": rule_level,
            "native_suricata_severity": suricata_severity,
            "native_record_type": np.where(detector == "wazuh", "wazuh",
                                           np.where(detector == "aminer", "aminer",
                                                    np.where(np.isnan(suricata_severity), "suricata_fast_log_ids_rule",
                                                             "suricata_eve_alert"))),
        }))
    return pd.concat(frames, ignore_index=True), labels

"""Split machinery for the declared AIT experiments (protocol v1.1 §6.1, §7.2–7.4).

All split decisions here use ranking-time fields only (scenario, timestamp, detector,
native_key). No label is read.

* LOSO: each scenario held out once; inner selection is leave-one-training-scenario-out.
* Forward chaining: a test scenario is fitted only on scenarios whose alert-timestamp extent
  ends before the test scenario's extent starts. It is eligible with at least two such
  scenarios. Inner selection of learned families needs a non-empty role-T fit set inside every
  inner fold, which requires at least three fit scenarios. With exactly two, learned inner fits
  fail by construction; protocol §12 then uses the family's simplest grid point, fitted on the
  outer fit scenarios (role-T fit sets of size one), and the fallback is logged.
* Strict identifier holdout: native keys are grouped by normalized identifier
  (detector plus rule/signature/component identifier) and assigned to one of five groups by
  the SHA-256 of the identifier string modulo 5 (protocol §7.3). Group g's keys are removed
  from every fitting source of the fold (mapping, heights, priors, key heights, learned
  samples and inner validation queues); the outer held-out queue keeps all alerts.
* Seen/unseen identifiers: a held-out alert is unseen when its (detector, native_key) never
  occurs in the outer training scenarios.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

from soc_alert_ranking.revision.features import RankingFrame, normalized_identifier

HOLDOUT_GROUPS = 5
HOLDOUT_SALT = ""  # protocol §7.3 hashes the identifier string itself


@dataclass(frozen=True)
class OuterSplit:
    name: str
    held_out: str
    training: tuple[str, ...]
    excluded_key_ids: tuple[int, ...] = ()
    learned_estimable: bool = True
    note: str = ""

    def to_record(self) -> dict[str, object]:
        return asdict(self)


def loso_splits(ranking: RankingFrame) -> list[OuterSplit]:
    scenarios = list(ranking.scenarios)
    return [OuterSplit(f"loso:{v}", v, tuple(s for s in scenarios if s != v)) for v in scenarios]


def scenario_extents(ranking: RankingFrame) -> pd.DataFrame:
    frame = ranking.frame.groupby("scenario")["timestamp"].agg(["min", "max"]).rename(columns={"min": "start", "max": "end"})
    return frame.sort_values("start")


def forward_chaining_splits(ranking: RankingFrame) -> tuple[list[OuterSplit], pd.DataFrame]:
    extents = scenario_extents(ranking)
    records, splits = [], []
    for test, row in extents.iterrows():
        fit = tuple(sorted(s for s, other in extents.iterrows() if other["end"] < row["start"]))
        eligible = len(fit) >= 2
        learned = len(fit) >= 3
        records.append({"test_scenario": test, "start": row["start"], "end": row["end"], "fit_scenarios": list(fit),
                        "eligible": eligible, "learned_estimable": learned})
        if eligible:
            note = "" if learned else "learned inner selection not estimable (inner role-T fit sets empty); simplest grid point used"
            splits.append(OuterSplit(f"forward:{test}", test, fit, learned_estimable=learned, note=note))
    return splits, pd.DataFrame(records)


def identifier_groups(ranking: RankingFrame) -> pd.DataFrame:
    identifiers = [normalized_identifier(d, k) for d, k in zip(ranking.key_detector, ranking.key_name)]
    groups = [int(hashlib.sha256(f"{HOLDOUT_SALT}{i}".encode()).hexdigest(), 16) % HOLDOUT_GROUPS for i in identifiers]
    return pd.DataFrame({"key_id": np.arange(ranking.n_keys), "detector": ranking.key_detector, "native_key": ranking.key_name,
                         "identifier": identifiers, "group": groups})


def identifier_holdout_splits(ranking: RankingFrame) -> list[OuterSplit]:
    groups = identifier_groups(ranking)
    splits = []
    for base in loso_splits(ranking):
        for group in range(HOLDOUT_GROUPS):
            excluded = tuple(int(k) for k in groups.loc[groups["group"] == group, "key_id"])
            splits.append(OuterSplit(f"holdout_group_{group}:{base.held_out}", base.held_out, base.training, excluded))
    return splits


def unseen_identifier_mask(ranking: RankingFrame, held_out: str, training: tuple[str, ...]) -> np.ndarray:
    training_keys = set(np.concatenate([ranking.rows(s)["key_id"].to_numpy() for s in training]).tolist())
    return ~np.isin(ranking.rows(held_out)["key_id"].to_numpy(), np.array(sorted(training_keys), dtype=np.int64))

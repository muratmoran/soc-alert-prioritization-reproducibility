"""Detector-conditioned reliability calibration."""

from __future__ import annotations

from dataclasses import dataclass
import pandas as pd

@dataclass(frozen=True)
class ReliabilityStats:
    """Reliability statistics for a detector and attack class."""

    detector: str
    attack_class: str
    support: int
    precision: float
    recall: float
    f1: float
    detector_prior_f1: float


def shrink_reliability(
    stats: ReliabilityStats,
    shrinkage_lambda: float = 50.0,
    height_min: float = 0.05,
    height_max: float = 0.95,
) -> float:
    """Shrink sparse detector-class F1 toward detector-level reliability."""

    weight = stats.support / (stats.support + shrinkage_lambda)
    shrunk = weight * stats.f1 + (1.0 - weight) * stats.detector_prior_f1
    return min(height_max, max(height_min, shrunk))


def calibrate_alert_precision_reliability(
    alerts: pd.DataFrame,
    class_column: str = "attack_class",
    detector_column: str = "detector",
    label_column: str = "is_attack",
    shrinkage_lambda: float = 50.0,
    height_min: float = 0.05,
    height_max: float = 0.95,
) -> pd.DataFrame:
    """Estimate detector-conditioned alert reliability from labeled alerts.

    Alert-native datasets such as AIT contain generated alerts and labels that
    identify whether each alert corresponds to attack activity. They do not, by
    themselves, define all non-alert attack events needed for recall. For this
    setting, the reliability height is therefore calibrated as a shrunk
    positive-predictive value per detector and inferred alert class.
    """

    required = {detector_column, class_column, label_column}
    missing = required.difference(alerts.columns)
    if missing:
        raise ValueError(f"Missing columns for reliability calibration: {sorted(missing)}")

    working = alerts[list(required)].copy()
    working[label_column] = working[label_column].astype(bool)
    detector_prior = working.groupby(detector_column)[label_column].mean().rename("detector_prior")
    grouped = (
        working.groupby([detector_column, class_column])[label_column]
        .agg(["count", "mean"])
        .rename(columns={"count": "support", "mean": "precision"})
        .reset_index()
    )
    grouped = grouped.merge(detector_prior, on=detector_column, how="left")
    weights = grouped["support"] / (grouped["support"] + shrinkage_lambda)
    grouped["height"] = weights * grouped["precision"] + (1.0 - weights) * grouped["detector_prior"]
    grouped["height"] = grouped["height"].clip(lower=height_min, upper=height_max)
    return grouped.rename(
        columns={
            detector_column: "detector",
            class_column: "attack_class",
        }
    )


def apply_reliability_heights(
    alerts: pd.DataFrame,
    reliability: pd.DataFrame,
    default_height: float = 0.5,
) -> pd.DataFrame:
    """Attach detector-class reliability heights to an alert frame."""

    required = {"detector", "attack_class", "height"}
    missing = required.difference(reliability.columns)
    if missing:
        raise ValueError(f"Missing reliability columns: {sorted(missing)}")
    merged = alerts.merge(
        reliability[["detector", "attack_class", "height"]],
        on=["detector", "attack_class"],
        how="left",
    )
    detector_prior = (
        reliability.groupby("detector")["height"].mean().rename("detector_height_prior")
    )
    merged = merged.merge(detector_prior, on="detector", how="left")
    merged["height"] = (
        merged["height"]
        .fillna(merged["detector_height_prior"])
        .fillna(default_height)
        .clip(lower=0.05, upper=0.95)
    )
    return merged.drop(columns=["detector_height_prior"])


def calibrate_prediction_reliability(
    predictions: pd.DataFrame,
    true_column: str,
    predicted_column: str,
    detector_column: str = "detector",
    shrinkage_lambda: float = 50.0,
    height_min: float = 0.05,
    height_max: float = 0.95,
) -> pd.DataFrame:
    """Estimate detector-class reliability from predicted and true classes.

    This calibration is used for generated-alert experiments such as
    NF-UQ-NIDS-v2. The reliability target is class-correctness conditioned on
    the detector and predicted attack class, shrunk toward the detector-level
    correctness prior.
    """

    required = {detector_column, predicted_column, true_column}
    missing = required.difference(predictions.columns)
    if missing:
        raise ValueError(f"Missing columns for prediction reliability: {sorted(missing)}")

    working = predictions[list(required)].copy()
    working["_correct"] = working[predicted_column].astype(str) == working[true_column].astype(str)
    detector_prior = working.groupby(detector_column)["_correct"].mean().rename("detector_prior")
    grouped = (
        working.groupby([detector_column, predicted_column])["_correct"]
        .agg(["count", "mean"])
        .rename(columns={"count": "support", "mean": "precision"})
        .reset_index()
    )
    grouped = grouped.merge(detector_prior, on=detector_column, how="left")
    weights = grouped["support"] / (grouped["support"] + shrinkage_lambda)
    grouped["height"] = weights * grouped["precision"] + (1.0 - weights) * grouped["detector_prior"]
    grouped["height"] = grouped["height"].clip(lower=height_min, upper=height_max)
    return grouped.rename(
        columns={
            detector_column: "detector",
            predicted_column: "attack_class",
        }
    )

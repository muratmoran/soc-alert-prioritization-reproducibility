#!/usr/bin/env python
"""Run NF-UQ-NIDS-v2 leave-one-source-domain-out robustness experiments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from soc_alert_ranking.config import load_config
from soc_alert_ranking.loaders.nf_uq_nids import (
    discover_nf_uq_files,
    extract_nf_uq_metadata,
)
from soc_alert_ranking.mappings.reliability import (
    apply_reliability_heights,
    calibrate_prediction_reliability,
)
from soc_alert_ranking.mappings.severity import SeverityMapping, is_benign_label
from soc_alert_ranking.metrics.ranking import compute_ranking_metrics
from soc_alert_ranking.rankers.baselines import add_ranking_scores


LABEL_COLUMNS = {
    "label",
    "binarylabel",
    "attacklabel",
    "isattack",
    "attack",
    "attackcategory",
    "attack_category",
    "attackcat",
    "category",
    "class",
    "dataset",
    "source",
    "sourcedomain",
    "source_domain",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-path",
        default=str(PROJECT_ROOT / "data/raw/nf_uq_nids_v2"),
        help="Path containing staged NF-UQ-NIDS-v2 CSV files.",
    )
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument(
        "--max-per-domain-category",
        type=int,
        default=5000,
        help="Reservoir sample size per source-domain/attack-category group.",
    )
    parser.add_argument(
        "--category-mode",
        choices=["shared", "all"],
        default="shared",
        help="Use only pre-specified shared categories or all staged categories.",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=["logistic_regression", "random_forest"],
        choices=["logistic_regression", "random_forest"],
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--kappa", type=float, default=1.0)
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "results/nf_uq_nids_v2/robustness"))
    parser.add_argument(
        "--sample-cache",
        default=None,
        help="Optional CSV path used to save or reuse the bounded domain/category sample.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_path = Path(args.raw_path)
    files = discover_nf_uq_files(raw_path)
    if not files:
        print(f"No NF-UQ-NIDS-v2 CSV files found under {raw_path}")
        print("Run scripts/inspect_nf_uq.py after staging the merged or source-domain CSV files.")
        return 1

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sample_cache = Path(args.sample_cache) if args.sample_cache else out_dir / "nf_uq_domain_category_sample.csv"
    if sample_cache.exists():
        sample = pd.read_csv(sample_cache)
    else:
        config = load_config("nf_uq_nids_v2")
        shared_categories = set(config["robustness_categories"]["primary_shared"])
        categories = shared_categories if args.category_mode == "shared" else None
        sample = build_domain_category_sample(
            files=files,
            chunksize=args.chunksize,
            max_per_group=args.max_per_domain_category,
            categories=categories,
            seed=args.seed,
        )
        sample_cache.parent.mkdir(parents=True, exist_ok=True)
        sample.to_csv(sample_cache, index=False)
    if sample.empty:
        print("No usable NF-UQ rows remained after category filtering.")
        return 1

    feature_columns = infer_numeric_feature_columns(sample)
    if not feature_columns:
        print("No numeric feature columns available for generated-alert detectors.")
        return 1

    severity_mapping = SeverityMapping.from_file()
    metrics_rows = []
    alert_samples = []
    for model_name in args.models:
        for held_out_domain in sorted(sample["source_domain"].unique()):
            fold = run_one_fold(
                sample=sample,
                feature_columns=feature_columns,
                held_out_domain=held_out_domain,
                model_name=model_name,
                severity_mapping=severity_mapping,
                seed=args.seed,
                kappa=args.kappa,
            )
            metrics_rows.extend(fold["metrics"])
            if not fold["ranked_alerts"].empty:
                alert_samples.append(fold["ranked_alerts"].head(200))

    metrics = pd.DataFrame(metrics_rows)
    metrics.to_csv(out_dir / "nf_uq_robustness_metrics.csv", index=False)
    if alert_samples:
        pd.concat(alert_samples, ignore_index=True).to_csv(
            out_dir / "nf_uq_ranked_alert_samples.csv",
            index=False,
        )
    metadata = {
        "raw_path": str(raw_path),
        "files": [str(path) for path in files],
        "rows_sampled": int(len(sample)),
        "feature_columns": feature_columns,
        "category_mode": args.category_mode,
        "max_per_domain_category": args.max_per_domain_category,
        "sample_cache": str(sample_cache),
        "seed": args.seed,
        "kappa": args.kappa,
        "models": args.models,
    }
    (out_dir / "nf_uq_robustness_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(metrics.groupby(["model", "method"]).mean(numeric_only=True).round(4).to_string())
    return 0


def build_domain_category_sample(
    files: Iterable[Path],
    chunksize: int,
    max_per_group: int,
    categories: set[str] | None,
    seed: int,
) -> pd.DataFrame:
    """Build a bounded random sample per source-domain/category group."""

    rng = np.random.default_rng(seed)
    reservoirs: dict[tuple[str, str], pd.DataFrame] = {}
    for path in files:
        for chunk in pd.read_csv(path, chunksize=chunksize):
            metadata = extract_nf_uq_metadata(chunk, path)
            candidate = chunk.copy()
            candidate["source_domain"] = metadata["source_domain"]
            candidate["true_attack_class"] = metadata["attack_class"]
            candidate["is_attack"] = metadata["is_attack"]
            candidate.loc[~candidate["is_attack"], "true_attack_class"] = "Benign"
            if categories is not None:
                keep = candidate["true_attack_class"].isin(categories) | (candidate["true_attack_class"] == "Benign")
                candidate = candidate.loc[keep]
            if candidate.empty:
                continue
            candidate["_sample_priority"] = rng.random(len(candidate))
            for group, group_frame in candidate.groupby(["source_domain", "true_attack_class"], dropna=False):
                current = reservoirs.get(group)
                combined = group_frame if current is None else pd.concat([current, group_frame], ignore_index=True)
                reservoirs[group] = combined.nlargest(max_per_group, "_sample_priority")
    if not reservoirs:
        return pd.DataFrame()
    return pd.concat(reservoirs.values(), ignore_index=True).drop(columns=["_sample_priority"])


def infer_numeric_feature_columns(sample: pd.DataFrame) -> list[str]:
    """Infer numeric NetFlow features while excluding labels and metadata."""

    columns: list[str] = []
    for column in sample.columns:
        normalized = _normalize_column(column)
        if normalized in LABEL_COLUMNS:
            continue
        if column in {"source_domain", "true_attack_class", "is_attack"}:
            continue
        if pd.api.types.is_numeric_dtype(sample[column]):
            columns.append(column)
    return columns


def run_one_fold(
    sample: pd.DataFrame,
    feature_columns: list[str],
    held_out_domain: str,
    model_name: str,
    severity_mapping: SeverityMapping,
    seed: int,
    kappa: float,
) -> dict[str, object]:
    train = sample[sample["source_domain"] != held_out_domain].copy()
    test = sample[sample["source_domain"] == held_out_domain].copy()
    if train.empty or test.empty:
        return {"metrics": [], "ranked_alerts": pd.DataFrame()}

    y_train = train["true_attack_class"].astype(str)
    y_test = test["true_attack_class"].astype(str)
    x_train = clean_feature_frame(train[feature_columns])
    x_test = clean_feature_frame(test[feature_columns])
    model = make_model(model_name, seed)
    model.fit(x_train, y_train)

    train_predictions = predict_with_confidence(model, x_train)
    test_predictions = predict_with_confidence(model, x_test)
    reliability = calibrate_prediction_reliability(
        pd.DataFrame(
            {
                "detector": model_name,
                "attack_class": train_predictions["predicted_class"],
                "true_attack_class": y_train.to_numpy(),
            }
        ),
        true_column="true_attack_class",
        predicted_column="attack_class",
        detector_column="detector",
        shrinkage_lambda=100,
    )
    alerts = build_generated_alerts(
        test=test,
        predictions=test_predictions,
        model_name=model_name,
        held_out_domain=held_out_domain,
        severity_mapping=severity_mapping,
    )
    alerts = alerts[~alerts["attack_class"].map(is_benign_label)].copy()
    if alerts.empty:
        detector_metrics = detector_summary(
            y_true=y_test,
            y_pred=test_predictions["predicted_class"],
            model_name=model_name,
            held_out_domain=held_out_domain,
        )
        return {"metrics": [detector_metrics], "ranked_alerts": pd.DataFrame()}

    alerts = apply_reliability_heights(alerts, reliability, default_height=0.5)
    scored = add_ranking_scores(alerts, kappa=kappa)
    metrics_rows = [detector_summary(y_test, test_predictions["predicted_class"], model_name, held_out_domain)]
    for method, score_column in {
        "sgfn": "score_sgfn",
        "severity": "score_severity",
        "weighted": "score_weighted",
        "detector": "score_detector",
    }.items():
        row = compute_ranking_metrics(scored, score_column)
        row.update(
            {
                "dataset": "nf_uq_nids_v2",
                "model": model_name,
                "held_out_domain": held_out_domain,
                "method": method,
                "score_column": score_column,
            }
        )
        metrics_rows.append(row)
    ranked = scored.sort_values("score_sgfn", ascending=False).copy()
    ranked.insert(0, "held_out_domain", held_out_domain)
    ranked.insert(0, "model", model_name)
    return {"metrics": metrics_rows, "ranked_alerts": ranked}


def make_model(model_name: str, seed: int):
    if model_name == "logistic_regression":
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.impute import SimpleImputer
        from sklearn.preprocessing import StandardScaler

        return make_pipeline(
            SimpleImputer(strategy="median"),
            StandardScaler(),
            LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed),
        )
    if model_name == "random_forest":
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import make_pipeline

        return make_pipeline(
            SimpleImputer(strategy="median"),
            RandomForestClassifier(
                n_estimators=100,
                max_depth=16,
                class_weight="balanced_subsample",
                random_state=seed,
                n_jobs=-1,
            ),
        )
    raise ValueError(f"Unsupported model: {model_name}")


def clean_feature_frame(features: pd.DataFrame) -> pd.DataFrame:
    """Replace non-finite numeric values before model fitting or prediction."""

    numeric = features.apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    return numeric.clip(lower=-1e12, upper=1e12)


def predict_with_confidence(model, features: pd.DataFrame) -> pd.DataFrame:
    predicted = model.predict(features)
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)
        confidence = probabilities.max(axis=1)
    else:
        confidence = np.ones(len(predicted), dtype=float)
    return pd.DataFrame({"predicted_class": predicted, "confidence": confidence}, index=features.index)


def build_generated_alerts(
    test: pd.DataFrame,
    predictions: pd.DataFrame,
    model_name: str,
    held_out_domain: str,
    severity_mapping: SeverityMapping,
) -> pd.DataFrame:
    predicted = predictions["predicted_class"].astype(str).tolist()
    true_category = test["true_attack_class"].astype(str).tolist()
    severity = [severity_mapping.severity_for_nf_uq_category(category) for category in predicted]
    true_severity = [severity_mapping.severity_for_nf_uq_category(category) for category in true_category]
    confidence = predictions["confidence"].astype(float).clip(lower=0.0, upper=1.0).to_numpy()
    rows = pd.DataFrame(
        {
            "alert_id": [f"nf-uq-{model_name}-{held_out_domain}-{idx}" for idx in range(len(test))],
            "dataset": "nf_uq_nids_v2",
            "scenario": held_out_domain,
            "timestamp": np.arange(len(test), dtype=float),
            "detector": model_name,
            "source_domain": held_out_domain,
            "attack_class": predicted,
            "attack_phase": predicted,
            "true_attack_phase": true_category,
            "mitre_tactic": None,
            "mitre_technique": None,
            "severity": severity,
            "true_severity": true_severity,
            "uncertainty_factor": [
                severity_mapping.uncertainty_for_nf_uq_category(category)
                for category in predicted
            ],
            "detector_score": confidence,
            "native_severity": confidence * 10.0,
            "native_key": [f"{model_name}:{category}" for category in predicted],
            "native_category": predicted,
            "asset_criticality": 1.0,
            "is_attack": [not is_benign_label(category) for category in true_category],
            "is_critical": [value >= 8.0 for value in true_severity],
        }
    )
    return rows


def detector_summary(
    y_true: pd.Series,
    y_pred: pd.Series,
    model_name: str,
    held_out_domain: str,
) -> dict[str, object]:
    true_attack = ~y_true.map(is_benign_label).to_numpy(dtype=bool)
    pred_attack = ~pd.Series(y_pred).map(is_benign_label).to_numpy(dtype=bool)
    tp = int((true_attack & pred_attack).sum())
    fp = int((~true_attack & pred_attack).sum())
    fn = int((true_attack & ~pred_attack).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "dataset": "nf_uq_nids_v2",
        "model": model_name,
        "held_out_domain": held_out_domain,
        "method": "detector_generation",
        "rows": int(len(y_true)),
        "generated_alerts": int(pred_attack.sum()),
        "detector_precision": precision,
        "detector_recall": recall,
        "detector_f1": f1,
    }


def _normalize_column(column: object) -> str:
    return "".join(char for char in str(column).lower() if char.isalnum())


if __name__ == "__main__":
    raise SystemExit(main())

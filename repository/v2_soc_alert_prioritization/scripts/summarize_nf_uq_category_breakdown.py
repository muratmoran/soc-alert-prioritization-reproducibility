#!/usr/bin/env python
"""Summarize NF-UQ category/domain robustness under prevalence shift."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
SCRIPT_ROOT = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(SCRIPT_ROOT))

from soc_alert_ranking.config import load_config
from soc_alert_ranking.mappings.reliability import (
    apply_reliability_heights,
    calibrate_prediction_reliability,
)
from soc_alert_ranking.mappings.severity import SeverityMapping, is_benign_label
from soc_alert_ranking.rankers.baselines import add_ranking_scores

from run_nf_uq_robustness import (  # noqa: E402
    build_generated_alerts,
    clean_feature_frame,
    infer_numeric_feature_columns,
    make_model,
    predict_with_confidence,
)


DEFAULT_SAMPLE_CACHE = (
    PROJECT_ROOT
    / "results/nf_uq_nids_v2/robustness_shared/nf_uq_domain_category_sample.csv"
)
DEFAULT_OUT_DIR = PROJECT_ROOT / "results/nf_uq_nids_v2/category_breakdown_shared"
METHODS = {
    "sgfn": "score_sgfn",
    "severity": "score_severity",
    "weighted": "score_weighted",
    "detector": "score_detector",
}
BASELINES = ["severity", "weighted", "detector"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-cache", default=str(DEFAULT_SAMPLE_CACHE))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument(
        "--models",
        nargs="+",
        default=["logistic_regression", "random_forest"],
        choices=["logistic_regression", "random_forest"],
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--kappa", type=float, default=1.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sample_path = Path(args.sample_cache)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sample = pd.read_csv(sample_path)
    if sample.empty:
        print(f"Empty NF-UQ sample cache: {sample_path}")
        return 1

    config = load_config("nf_uq_nids_v2")
    categories = list(config["robustness_categories"]["primary_shared"])
    source_counts = config["source_domain_category_counts"]
    prevalence = official_prevalence_frame(source_counts, categories)
    feature_columns = infer_numeric_feature_columns(sample)
    severity_mapping = SeverityMapping.from_file()

    detector_rows = []
    ranking_rows = []
    for model_name in args.models:
        for held_out_domain in sorted(sample["source_domain"].unique()):
            print(f"NF-UQ category breakdown: {model_name}, held out {held_out_domain}")
            train = sample[sample["source_domain"] != held_out_domain].copy()
            test = sample[sample["source_domain"] == held_out_domain].copy()
            if train.empty or test.empty:
                continue

            x_train = clean_feature_frame(train[feature_columns])
            x_test = clean_feature_frame(test[feature_columns])
            y_train = train["true_attack_class"].astype(str)
            y_test = test["true_attack_class"].astype(str)

            model = make_model(model_name, args.seed)
            model.fit(x_train, y_train)
            train_predictions = predict_with_confidence(model, x_train)
            test_predictions = predict_with_confidence(model, x_test)

            for category in categories:
                if official_count(source_counts, held_out_domain, category) <= 0:
                    continue
                detector_rows.append(
                    target_detector_metrics(
                        y_true=y_test,
                        y_pred=test_predictions["predicted_class"],
                        category=category,
                        model_name=model_name,
                        held_out_domain=held_out_domain,
                    )
                )

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
                continue
            alerts = apply_reliability_heights(alerts, reliability, default_height=0.5)
            scored = add_ranking_scores(alerts, kappa=args.kappa)

            for category in categories:
                if official_count(source_counts, held_out_domain, category) <= 0:
                    continue
                for method, score_column in METHODS.items():
                    row = target_ranking_metrics(scored, score_column, category)
                    row.update(
                        {
                            "model": model_name,
                            "held_out_domain": held_out_domain,
                            "category": category,
                            "method": method,
                            "score_column": score_column,
                        }
                    )
                    ranking_rows.append(row)

    detector = pd.DataFrame(detector_rows)
    ranking = pd.DataFrame(ranking_rows)
    summary = category_summary(prevalence, detector, ranking)

    prevalence_path = out_dir / "nf_uq_category_prevalence.csv"
    detector_path = out_dir / "nf_uq_category_detector_metrics.csv"
    ranking_path = out_dir / "nf_uq_category_ranking_metrics.csv"
    summary_path = out_dir / "nf_uq_category_breakdown_summary.csv"
    metadata_path = out_dir / "nf_uq_category_breakdown_summary.json"
    prevalence.to_csv(prevalence_path, index=False)
    detector.to_csv(detector_path, index=False)
    ranking.to_csv(ranking_path, index=False)
    summary.to_csv(summary_path, index=False)

    metadata = {
        "sample_cache": str(sample_path),
        "rows_sampled": int(len(sample)),
        "categories": categories,
        "models": args.models,
        "seed": args.seed,
        "kappa": args.kappa,
        "prevalence_output": str(prevalence_path),
        "detector_output": str(detector_path),
        "ranking_output": str(ranking_path),
        "summary_output": str(summary_path),
        "metric_note": "Category target NDCG@100 uses binary relevance for one attack category over the generated alert queue.",
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(summary.to_string(index=False))
    return 0


def official_prevalence_frame(source_counts: dict, categories: list[str]) -> pd.DataFrame:
    rows = []
    for domain, counts in source_counts.items():
        total = sum(int(value) for value in counts.values())
        for category in categories:
            count = int(counts.get(category, 0))
            if count <= 0:
                continue
            rows.append(
                {
                    "source_domain": domain,
                    "category": category,
                    "official_count": count,
                    "domain_total": total,
                    "prevalence": count / total if total else 0.0,
                }
            )
    return pd.DataFrame(rows)


def official_count(source_counts: dict, domain: str, category: str) -> int:
    return int(source_counts.get(domain, {}).get(category, 0))


def target_detector_metrics(
    y_true: pd.Series,
    y_pred: pd.Series,
    category: str,
    model_name: str,
    held_out_domain: str,
) -> dict[str, float | int | str]:
    truth = y_true.astype(str).to_numpy() == category
    predicted = pd.Series(y_pred).astype(str).to_numpy() == category
    tp = int((truth & predicted).sum())
    fp = int((~truth & predicted).sum())
    fn = int((truth & ~predicted).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "model": model_name,
        "held_out_domain": held_out_domain,
        "category": category,
        "test_category_rows": int(truth.sum()),
        "predicted_category_rows": int(predicted.sum()),
        "target_precision": precision,
        "target_recall": recall,
        "target_f1": f1,
    }


def target_ranking_metrics(
    alerts: pd.DataFrame,
    score_column: str,
    category: str,
    k: int = 100,
) -> dict[str, float | int]:
    ranked = alerts.sort_values(
        [score_column, "timestamp", "alert_id"],
        ascending=[False, True, True],
        kind="mergesort",
    )
    target = ranked["true_attack_phase"].astype(str).to_numpy() == category
    total_target = int(target.sum())
    top_k = min(k, len(ranked))
    top_target = target[:top_k]
    first = np.flatnonzero(target)
    return {
        "generated_alerts": int(len(ranked)),
        "generated_target_alerts": total_target,
        f"target_ndcg@{k}": target_ndcg_at_k(target, k),
        f"target_recall@{k}": float(top_target.sum() / total_target) if total_target else 0.0,
        f"target_false_positives@{k}": int((~top_target).sum()),
        "rank_first_target": int(first[0] + 1) if len(first) else 0,
    }


def target_ndcg_at_k(target: np.ndarray, k: int) -> float:
    if len(target) == 0:
        return 0.0
    k = min(k, len(target))
    relevance = target[:k].astype(float)
    ideal = np.sort(target.astype(float))[::-1][:k]
    return _dcg(relevance) / _dcg(ideal) if _dcg(ideal) > 0 else 0.0


def _dcg(relevance: np.ndarray) -> float:
    if len(relevance) == 0:
        return 0.0
    discounts = np.log2(np.arange(2, len(relevance) + 2))
    return float(np.sum(relevance / discounts))


def category_summary(
    prevalence: pd.DataFrame,
    detector: pd.DataFrame,
    ranking: pd.DataFrame,
) -> pd.DataFrame:
    rows = []
    for category in prevalence["category"].drop_duplicates():
        prev = prevalence[prevalence["category"] == category]
        det = detector[detector["category"] == category]
        rank = ranking[ranking["category"] == category]
        method_means = (
            rank.groupby("method")["target_ndcg@100"].mean().to_dict()
            if not rank.empty
            else {}
        )
        baseline_scores = {method: method_means.get(method, 0.0) for method in BASELINES}
        best_baseline = max(baseline_scores, key=baseline_scores.get)
        sgfn_score = method_means.get("sgfn", 0.0)
        sgfn_rows = rank[rank["method"] == "sgfn"]
        rows.append(
            {
                "category": category,
                "source_domains": "; ".join(sorted(prev["source_domain"].unique())),
                "source_domain_count": int(prev["source_domain"].nunique()),
                "prevalence_min": float(prev["prevalence"].min()),
                "prevalence_max": float(prev["prevalence"].max()),
                "detector_f1_min": float(det["target_f1"].min()) if not det.empty else 0.0,
                "detector_f1_max": float(det["target_f1"].max()) if not det.empty else 0.0,
                "detector_f1_mean": float(det["target_f1"].mean()) if not det.empty else 0.0,
                "sgfn_target_ndcg@100": float(sgfn_score),
                "best_baseline": best_baseline,
                "best_baseline_target_ndcg@100": float(baseline_scores[best_baseline]),
                "sgfn_delta_vs_best_baseline": float(sgfn_score - baseline_scores[best_baseline]),
                "sgfn_target_false_positives@100": float(sgfn_rows["target_false_positives@100"].mean())
                if not sgfn_rows.empty
                else 0.0,
                "sgfn_rank_first_target": float(sgfn_rows["rank_first_target"].replace(0, np.nan).mean())
                if not sgfn_rows.empty
                else 0.0,
            }
        )
    return pd.DataFrame(rows)


if __name__ == "__main__":
    raise SystemExit(main())

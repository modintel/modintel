"""
Miss Model Training Pipeline (Layer 2)
Optimized False Negative Detection using Regex Signature Features

This pipeline trains a specialized model to catch attacks that bypass the primary WAF.
It uses regex signature matching features combined with request characteristics.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

try:
    from xgboost import XGBClassifier

    _HAS_XGB = True
except ImportError:
    _HAS_XGB = False

try:
    from lightgbm import LGBMClassifier

    _HAS_LGB = True
except ImportError:
    _HAS_LGB = False

from miss_feature_extractor import MissModelFeatureExtractor

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_DATA_DIR", os.path.join(REPO_ROOT, "data"))
)

PARQUET_PATH = os.path.abspath(
    os.environ.get(
        "ML_PIPELINE_PARQUET_PATH",
        os.path.join(DATA_BASE_DIR, "processed", "waf_dataset_v1.parquet"),
    )
)

REGEX_SIGNATURES_PATH = os.path.abspath(
    os.environ.get(
        "REGEX_SIGNATURES_PATH",
        os.path.join(DATA_BASE_DIR, "processed", "modintel_regex.signatures"),
    )
)

MODELS_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_MODELS_DIR", os.path.join(REPO_ROOT, "models"))
)

RANDOM_STATE = 42
CALIBRATION_METHOD = "isotonic"

# Miss model focuses heavily on recall (catching FNs) while maintaining precision
W_RECALL = 0.50  # Primary focus: catch false negatives
W_PRECISION = 0.25  # Maintain reasonable precision
W_F1 = 0.15  # Balance metric
W_AUROC = 0.10  # Overall discrimination

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def sha256_file(path: str) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def next_model_version(base_dir: str, prefix: str = "miss_v") -> int:
    """Determine the next version number for miss models."""
    os.makedirs(base_dir, exist_ok=True)
    existing = [
        d
        for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d)) and d.startswith(prefix)
    ]
    versions = []
    for name in existing:
        try:
            versions.append(int(name[len(prefix) :]))
        except ValueError:
            pass
    return max(versions, default=0) + 1


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
) -> Dict[str, Any]:
    """Compute comprehensive evaluation metrics."""
    # Compute confusion matrix components
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tp = int(((y_pred == 1) & (y_true == 1)).sum())

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0  # Specificity

    metrics: Dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "auroc": float(roc_auc_score(y_true, y_prob))
        if len(np.unique(y_true)) > 1
        else 0.0,
        "pr_auc": float(average_precision_score(y_true, y_prob))
        if len(np.unique(y_true)) > 1
        else 0.0,
        "fpr": fpr,
        "fnr": fnr,
        "tnr": tnr,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }
    return metrics


def composite_score(metrics: Dict[str, Any]) -> float:
    """
    Compute composite score optimized for miss detection.
    Heavily weights recall to catch false negatives.
    """
    return (
        W_RECALL * metrics["recall"]
        + W_PRECISION * metrics["precision"]
        + W_F1 * metrics["f1"]
        + W_AUROC * metrics["auroc"]
    )


def build_miss_candidates() -> List[Tuple[str, Any]]:
    """
    Build candidate classifiers optimized for miss detection.
    Focus on models that can handle high-dimensional sparse features well.
    """
    candidates: List[Tuple[str, Any]] = []

    # XGBoost: Excellent for sparse features and imbalanced data
    if _HAS_XGB:
        candidates.append(
            (
                "xgboost_miss",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=8,
                    learning_rate=0.05,
                    eval_metric="logloss",
                    scale_pos_weight=3,  # Bias toward catching attacks
                    subsample=0.8,
                    colsample_bytree=0.8,
                    min_child_weight=1,
                    gamma=0.1,
                    random_state=RANDOM_STATE,
                    verbosity=0,
                ),
            )
        )
    else:
        log.warning("xgboost not installed — skipping XGBoost candidate.")

    # LightGBM: Fast and efficient for high-dimensional data
    if _HAS_LGB:
        candidates.append(
            (
                "lightgbm_miss",
                LGBMClassifier(
                    n_estimators=300,
                    max_depth=8,
                    learning_rate=0.05,
                    num_leaves=64,
                    min_child_samples=20,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                    verbose=-1,
                ),
            )
        )
    else:
        log.warning("lightgbm not installed — skipping LightGBM candidate.")

    # Gradient Boosting: Strong baseline for miss detection
    candidates.append(
        (
            "gradient_boosting_miss",
            GradientBoostingClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.05,
                subsample=0.8,
                min_samples_split=20,
                min_samples_leaf=10,
                random_state=RANDOM_STATE,
            ),
        )
    )

    # Random Forest: Good for feature importance and robustness
    candidates.append(
        (
            "random_forest_miss",
            RandomForestClassifier(
                n_estimators=300,
                max_depth=12,
                min_samples_split=10,
                min_samples_leaf=5,
                class_weight="balanced_subsample",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        )
    )

    # Logistic Regression with L1: Good for sparse features
    candidates.append(
        (
            "logistic_l1_miss",
            LogisticRegression(
                penalty="l1",
                C=0.5,
                solver="saga",
                max_iter=2000,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        )
    )

    return candidates


def identify_false_negatives(
    df: pd.DataFrame, primary_model_path: str
) -> pd.DataFrame:
    """
    Identify false negatives from the primary model.
    These are attacks that the primary WAF missed.
    """
    log.info("Loading primary model from %s", primary_model_path)

    try:
        from feature_extractor import WAFFeatureExtractor

        primary_extractor = WAFFeatureExtractor.load(
            os.path.join(primary_model_path, "feature_extractor.joblib")
        )
        primary_model = joblib.load(
            os.path.join(primary_model_path, "calibrator.joblib")
        )
    except Exception as e:
        log.error("Failed to load primary model: %s", e)
        raise

    log.info("Extracting features with primary model...")
    X_primary = primary_extractor.transform(df)
    y_primary_pred = primary_model.predict(X_primary)

    # Identify false negatives: actual attacks that primary model missed
    y_true = (df["label"] == "attack").astype(int).values
    false_negatives = (y_true == 1) & (y_primary_pred == 0)

    log.info(
        "Identified %d false negatives out of %d attacks (%.2f%%)",
        false_negatives.sum(),
        y_true.sum(),
        100 * false_negatives.sum() / max(y_true.sum(), 1),
    )

    # Add FN indicator to dataframe
    df = df.copy()
    df["is_false_negative"] = false_negatives
    df["primary_prediction"] = y_primary_pred

    return df


def load_splits_for_miss_model(
    parquet_path: str,
    regex_signatures_path: str,
    primary_model_path: str,
) -> Tuple[
    pd.DataFrame,
    pd.DataFrame,
    pd.DataFrame,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    MissModelFeatureExtractor,
]:
    """Load data and prepare for miss model training."""
    log.info("Loading dataset from %s", parquet_path)
    df = pd.read_parquet(parquet_path)

    # Rename Coraza columns if needed
    rename_map = {
        "coraza_fired_rule_ids": "fired_rule_ids",
        "coraza_rule_severities": "rule_severities",
        "coraza_rule_messages": "rule_messages",
        "coraza_anomaly_score": "anomaly_score",
        "coraza_inbound_threshold": "inbound_threshold",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    # Split data
    df_train = df[df["split"] == "train"].copy()
    df_val = df[df["split"] == "validation"].copy()
    df_test = df[df["split"] == "test"].copy()

    log.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(df_train),
        len(df_val),
        len(df_test),
    )

    # Identify false negatives using primary model
    df_train = identify_false_negatives(df_train, primary_model_path)
    df_val = identify_false_negatives(df_val, primary_model_path)
    df_test = identify_false_negatives(df_test, primary_model_path)

    # Initialize miss model feature extractor
    extractor = MissModelFeatureExtractor(regex_signatures_path)

    log.info("Fitting MissModelFeatureExtractor on training split...")
    X_train = extractor.fit_transform(df_train)
    X_val = extractor.transform(df_val)
    X_test = extractor.transform(df_test)

    # Labels: 1 if attack (regardless of primary model), 0 if benign
    y_train = (df_train["label"] == "attack").astype(int).values
    y_val = (df_val["label"] == "attack").astype(int).values
    y_test = (df_test["label"] == "attack").astype(int).values

    return (
        df_train,
        df_val,
        df_test,
        X_train,
        X_val,
        X_test,
        y_train,
        y_val,
        y_test,
        extractor,
    )


def train_and_evaluate_miss_models(
    candidates: List[Tuple[str, Any]],
    X_train: np.ndarray,
    X_val: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_val: np.ndarray,
    y_test: np.ndarray,
    df_test: pd.DataFrame,
) -> List[Dict[str, Any]]:
    """Train and evaluate miss model candidates."""
    results: List[Dict[str, Any]] = []

    for name, base_estimator in candidates:
        log.info("Training miss model candidate: %s", name)

        base_estimator.fit(X_train, y_train)

        log.info("Calibrating %s on validation split...", name)
        calibrated = CalibratedClassifierCV(
            estimator=base_estimator,
            method=CALIBRATION_METHOD,
            cv="prefit",
        )
        calibrated.fit(X_val, y_val)

        y_pred = calibrated.predict(X_test)
        y_prob = calibrated.predict_proba(X_test)[:, 1]

        metrics = compute_metrics(y_test, y_pred, y_prob)
        score = composite_score(metrics)

        # Compute miss-specific metrics
        fn_mask = df_test["is_false_negative"].values
        if fn_mask.sum() > 0:
            fn_recall = recall_score(y_test[fn_mask], y_pred[fn_mask], zero_division=0)
            fn_caught = (y_pred[fn_mask] == 1).sum()
            fn_total = fn_mask.sum()
            metrics["fn_recovery_rate"] = float(fn_recall)
            metrics["fn_caught"] = int(fn_caught)
            metrics["fn_total"] = int(fn_total)
        else:
            metrics["fn_recovery_rate"] = 0.0
            metrics["fn_caught"] = 0
            metrics["fn_total"] = 0

        log.info(
            "%s — Recall=%.4f Precision=%.4f F1=%.4f AUROC=%.4f FN_Recovery=%.4f composite=%.4f",
            name,
            metrics["recall"],
            metrics["precision"],
            metrics["f1"],
            metrics["auroc"],
            metrics["fn_recovery_rate"],
            score,
        )

        results.append(
            {
                "name": name,
                "base_estimator": base_estimator,
                "calibrated_model": calibrated,
                "metrics": metrics,
                "composite_score": score,
            }
        )

    results.sort(key=lambda r: r["composite_score"], reverse=True)
    return results


def export_miss_model_artifacts(
    best: Dict[str, Any],
    extractor: MissModelFeatureExtractor,
    version: int,
    parquet_path: str,
    regex_signatures_path: str,
    training_config: Dict[str, Any],
    all_results: List[Dict[str, Any]],
) -> str:
    """Export miss model artifacts."""
    out_dir = os.path.join(MODELS_BASE_DIR, f"miss_v{version}")
    os.makedirs(out_dir, exist_ok=True)
    log.info("Exporting miss model artifacts to %s", out_dir)

    # Save base model
    joblib.dump(best["base_estimator"], os.path.join(out_dir, "miss_model.joblib"))

    # Save calibrated model
    joblib.dump(
        best["calibrated_model"], os.path.join(out_dir, "miss_calibrator.joblib")
    )

    # Save feature extractor
    joblib.dump(extractor, os.path.join(out_dir, "miss_feature_extractor.joblib"))

    # Save all candidate calibrators
    for r in all_results:
        joblib.dump(
            r["calibrated_model"],
            os.path.join(out_dir, f"miss_calibrator_{r['name']}.joblib"),
        )

    # Compile all candidate metrics
    all_candidate_metrics = [
        {
            "name": r["name"],
            "metrics": r["metrics"],
            "composite_score": r["composite_score"],
        }
        for r in all_results
    ]

    # Create metadata
    metadata = {
        "model_version": version,
        "model_type": "miss_model",
        "model_name": best["name"],
        "composite_score": best["composite_score"],
        "metrics": best["metrics"],
        "all_candidates": all_candidate_metrics,
        "training_config": training_config,
        "dataset_sha256": sha256_file(parquet_path),
        "regex_signatures_sha256": sha256_file(regex_signatures_path),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "composite_weights": {
            "recall": W_RECALL,
            "precision": W_PRECISION,
            "f1": W_F1,
            "auroc": W_AUROC,
        },
    }

    with open(os.path.join(out_dir, "miss_model_metadata.json"), "w") as fh:
        json.dump(metadata, fh, indent=2, default=_json_default)

    return out_dir


def _json_default(obj: Any) -> Any:
    """JSON serialization helper."""
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def main() -> None:
    """Main training pipeline for miss model."""
    # Determine primary model path (use latest version)
    primary_versions = [
        d
        for d in os.listdir(MODELS_BASE_DIR)
        if os.path.isdir(os.path.join(MODELS_BASE_DIR, d)) and d.startswith("v")
    ]
    if not primary_versions:
        log.error("No primary model found. Train primary model first.")
        raise RuntimeError("No primary model found.")

    primary_version = max(int(v[1:]) for v in primary_versions)
    primary_model_path = os.path.join(MODELS_BASE_DIR, f"v{primary_version}")
    log.info("Using primary model: %s", primary_model_path)

    # Load data and identify false negatives
    (
        df_train,
        df_val,
        df_test,
        X_train,
        X_val,
        X_test,
        y_train,
        y_val,
        y_test,
        extractor,
    ) = load_splits_for_miss_model(
        PARQUET_PATH, REGEX_SIGNATURES_PATH, primary_model_path
    )

    # Build and train candidates
    candidates = build_miss_candidates()
    if not candidates:
        log.error("No candidate classifiers available.")
        raise RuntimeError("No candidate classifiers available.")

    results = train_and_evaluate_miss_models(
        candidates,
        X_train,
        X_val,
        X_test,
        y_train,
        y_val,
        y_test,
        df_test,
    )

    best = results[0]
    log.info(
        "Best miss model: %s (composite score=%.4f)",
        best["name"],
        best["composite_score"],
    )

    # Export artifacts
    version = next_model_version(MODELS_BASE_DIR, prefix="miss_v")

    training_config = {
        "random_state": RANDOM_STATE,
        "calibration_method": CALIBRATION_METHOD,
        "primary_model_version": primary_version,
        "composite_weights": {
            "recall": W_RECALL,
            "precision": W_PRECISION,
            "f1": W_F1,
            "auroc": W_AUROC,
        },
        "candidates_trained": [r["name"] for r in results],
    }

    out_dir = export_miss_model_artifacts(
        best=best,
        extractor=extractor,
        version=version,
        parquet_path=PARQUET_PATH,
        regex_signatures_path=REGEX_SIGNATURES_PATH,
        training_config=training_config,
        all_results=results,
    )

    print("\n=== Miss Model Training Summary ===")
    print(f"  Best model        : {best['name']}")
    print(f"  Version           : miss_v{version}")
    print(f"  Composite score   : {best['composite_score']:.4f}")
    print(f"  Recall            : {best['metrics']['recall']:.4f}")
    print(f"  Precision         : {best['metrics']['precision']:.4f}")
    print(f"  F1                : {best['metrics']['f1']:.4f}")
    print(f"  AUROC             : {best['metrics']['auroc']:.4f}")
    print(f"  FNR               : {best['metrics']['fnr']:.4f}")
    print(f"  FN Recovery Rate  : {best['metrics']['fn_recovery_rate']:.4f}")
    print(
        f"  FN Caught         : {best['metrics']['fn_caught']}/{best['metrics']['fn_total']}"
    )
    print(f"  Artifacts         : {out_dir}")
    print("====================================\n")

    print("All candidates:")
    for r in results:
        print(
            f"  {r['name']:25s}  composite={r['composite_score']:.4f}"
            f"  Recall={r['metrics']['recall']:.4f}"
            f"  Precision={r['metrics']['precision']:.4f}"
            f"  FN_Recovery={r['metrics']['fn_recovery_rate']:.4f}"
        )


if __name__ == "__main__":
    main()

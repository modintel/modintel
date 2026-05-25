from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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
from sklearn.model_selection import train_test_split

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

try:
    import optuna

    _HAS_OPTUNA = True
except ImportError:
    _HAS_OPTUNA = False

try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    _HAS_ONNX = True
except ImportError:
    _HAS_ONNX = False

from miss_feature_extractor import MissModelFeatureExtractor

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB_NAME", "modintel")
DATA_DIR = os.getenv("ML_PIPELINE_DATA_DIR", "/app/data")
MODELS_DIR = os.getenv("ML_PIPELINE_MODELS_DIR", "/app/models")
REGEX_SIGNATURES_PATH = os.getenv(
    "REGEX_SIGNATURES_PATH",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "services",
        "log-collector",
        "signatures",
        "modintel_regex.signatures",
    ),
)

RANDOM_STATE = 42
CALIBRATION_METHOD = "isotonic"
TEST_SPLIT = 0.15
VAL_SPLIT = 0.15

W_RECALL = 0.35
W_PRECISION = 0.30
W_F1 = 0.15
W_AUROC = 0.20

OPTUNA_TRIALS = int(os.getenv("OPTUNA_TRIALS", "30"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def next_model_version(base_dir: str, prefix: str = "miss_v") -> int:
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
    y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray
) -> Dict[str, Any]:
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tp = int(((y_pred == 1) & (y_true == 1)).sum())

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
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
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def composite_score(metrics: Dict[str, Any]) -> float:
    return (
        W_RECALL * metrics["recall"]
        + W_PRECISION * metrics["precision"]
        + W_F1 * metrics["f1"]
        + W_AUROC * metrics["auroc"]
    )


def _optuna_objective(
    trial: optuna.Trial, model_type: str, X_train, y_train, X_val, y_val
) -> float:
    params: Dict[str, Any] = {"random_state": RANDOM_STATE}

    if model_type == "xgboost_miss":
        params.update(
            {
                "n_estimators": trial.suggest_int("n_estimators", 100, 500, step=50),
                "max_depth": trial.suggest_int("max_depth", 4, 16),
                "learning_rate": trial.suggest_float(
                    "learning_rate", 0.01, 0.3, log=True
                ),
                "subsample": trial.suggest_float("subsample", 0.6, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
                "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
                "gamma": trial.suggest_float("gamma", 0.0, 1.0),
                "scale_pos_weight": trial.suggest_float("scale_pos_weight", 1.0, 5.0),
                "eval_metric": "logloss",
                "verbosity": 0,
            }
        )
        model = XGBClassifier(**params)

    elif model_type == "lightgbm_miss":
        params.update(
            {
                "n_estimators": trial.suggest_int("n_estimators", 100, 500, step=50),
                "max_depth": trial.suggest_int("max_depth", 4, 16),
                "learning_rate": trial.suggest_float(
                    "learning_rate", 0.01, 0.3, log=True
                ),
                "num_leaves": trial.suggest_int("num_leaves", 16, 128, step=16),
                "min_child_samples": trial.suggest_int("min_child_samples", 10, 50),
                "subsample": trial.suggest_float("subsample", 0.6, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
                "class_weight": "balanced",
            }
        )
        model = LGBMClassifier(**params, verbose=-1)

    elif model_type == "gradient_boosting_miss":
        params.update(
            {
                "n_estimators": trial.suggest_int("n_estimators", 100, 400, step=50),
                "max_depth": trial.suggest_int("max_depth", 3, 10),
                "learning_rate": trial.suggest_float(
                    "learning_rate", 0.01, 0.3, log=True
                ),
                "subsample": trial.suggest_float("subsample", 0.6, 1.0),
                "min_samples_split": trial.suggest_int("min_samples_split", 10, 50),
                "min_samples_leaf": trial.suggest_int("min_samples_leaf", 5, 30),
            }
        )
        model = GradientBoostingClassifier(**params)

    elif model_type == "random_forest_miss":
        params.update(
            {
                "n_estimators": trial.suggest_int("n_estimators", 100, 500, step=50),
                "max_depth": trial.suggest_int("max_depth", 6, 20),
                "min_samples_split": trial.suggest_int("min_samples_split", 5, 30),
                "min_samples_leaf": trial.suggest_int("min_samples_leaf", 2, 20),
                "class_weight": "balanced_subsample",
            }
        )
        model = RandomForestClassifier(**params, n_jobs=-1)

    elif model_type == "logistic_l1_miss":
        params.update(
            {
                "C": trial.suggest_float("C", 0.01, 10.0, log=True),
                "max_iter": trial.suggest_int("max_iter", 1000, 5000, step=500),
                "class_weight": "balanced",
            }
        )
        model = LogisticRegression(
            penalty="l1",
            solver="saga",
            **params,
            n_jobs=-1,
        )
    else:
        raise ValueError(f"Unknown model type: {model_type}")

    model.fit(X_train, y_train)
    calibrated = CalibratedClassifierCV(
        estimator=model,
        method=CALIBRATION_METHOD,
        cv="prefit",
    )
    calibrated.fit(X_val, y_val)

    y_prob = calibrated.predict_proba(X_val)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    metrics = compute_metrics(y_val, y_pred, y_prob)

    return composite_score(metrics)


def build_miss_candidates_with_optuna(
    X_train,
    y_train,
    X_val,
    y_val,
) -> List[Tuple[str, Any, Dict[str, Any]]]:
    candidate_names = []
    if _HAS_XGB:
        candidate_names.append("xgboost_miss")
    if _HAS_LGB:
        candidate_names.append("lightgbm_miss")
    candidate_names.extend(
        [
            "gradient_boosting_miss",
            "random_forest_miss",
            "logistic_l1_miss",
        ]
    )

    all_results = []
    for name in candidate_names:
        log.info("Optuna tuning for %s (%d trials)", name, OPTUNA_TRIALS)
        study = optuna.create_study(
            direction="maximize",
            sampler=optuna.samplers.TPESampler(seed=RANDOM_STATE),
        )
        study.optimize(
            lambda trial: _optuna_objective(
                trial, name, X_train, y_train, X_val, y_val
            ),
            n_trials=OPTUNA_TRIALS,
            show_progress_bar=False,
        )
        log.info(
            "  Best %s score=%.4f with params=%s",
            name,
            study.best_value,
            study.best_params,
        )

        all_results.append(
            {
                "name": name,
                "best_params": study.best_params,
                "best_value": study.best_value,
            }
        )

    return all_results


def _instantiate_with_params(name: str, params: Dict[str, Any]) -> Any:
    p = dict(params)
    p["random_state"] = RANDOM_STATE

    if name == "xgboost_miss":
        p.setdefault("eval_metric", "logloss")
        p.setdefault("verbosity", 0)
        return XGBClassifier(**p)
    elif name == "lightgbm_miss":
        p.setdefault("class_weight", "balanced")
        return LGBMClassifier(**p, verbose=-1)
    elif name == "gradient_boosting_miss":
        return GradientBoostingClassifier(**p)
    elif name == "random_forest_miss":
        p.setdefault("class_weight", "balanced_subsample")
        return RandomForestClassifier(**p, n_jobs=-1)
    elif name == "logistic_l1_miss":
        p.setdefault("penalty", "l1")
        p.setdefault("solver", "saga")
        return LogisticRegression(**p, n_jobs=-1)
    raise ValueError(f"Unknown model type: {name}")


def build_miss_candidates_default() -> List[Tuple[str, Any]]:
    candidates: List[Tuple[str, Any]] = []

    if _HAS_XGB:
        candidates.append(
            (
                "xgboost_miss",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=8,
                    learning_rate=0.05,
                    eval_metric="logloss",
                    scale_pos_weight=3,
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


def load_reviewed_alerts_from_mongo() -> pd.DataFrame:
    log.info("Connecting to MongoDB at %s", MONGO_URI)
    try:
        from pymongo import MongoClient
    except ImportError:
        log.error("pymongo not installed — cannot load from MongoDB")
        raise

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db["alerts"]

    query = {"human_label": {"$in": ["true_positive", "false_positive"]}}
    projection = {
        "method": 1,
        "uri": 1,
        "body": 1,
        "headers": 1,
        "human_label": 1,
        "source": 1,
        "timestamp": 1,
        "anomaly_score": 1,
        "triggered_rules": 1,
        "ai_score": 1,
        "_id": 0,
    }

    cursor = collection.find(query, projection).limit(100000)
    rows = list(cursor)
    client.close()

    log.info("Loaded %d reviewed alerts from MongoDB", len(rows))

    if not rows:
        raise RuntimeError(
            "No reviewed alerts found in MongoDB. "
            "Analysts must label alerts (TP/FP) via the Review page first."
        )

    df = pd.DataFrame(rows)

    df["label"] = df["human_label"].map(
        {
            "true_positive": "attack",
            "false_positive": "benign",
        }
    )

    if "body" in df.columns:
        df["body"] = df["body"].fillna("")
    else:
        df["body"] = ""
    if "headers" in df.columns:

        def _norm_headers(h):
            if isinstance(h, dict):
                return h
            if isinstance(h, str):
                try:
                    return json.loads(h)
                except Exception:
                    return {}
            return {}

        df["headers"] = df["headers"].apply(_norm_headers)
    else:
        df["headers"] = [{}] * len(df)
    df["method"] = df["method"].fillna("GET")
    df["uri"] = df["uri"].fillna("/")

    attack_count = (df["label"] == "attack").sum()
    benign_count = (df["label"] == "benign").sum()
    log.info("Label distribution — attacks: %d, benign: %d", attack_count, benign_count)

    return df


def load_reviewed_alerts_from_parquets() -> pd.DataFrame:
    processed_dir = os.path.join(DATA_DIR, "processed")
    if not os.path.isdir(processed_dir):
        raise RuntimeError(f"Processed data directory not found: {processed_dir}")

    parquet_files = [f for f in os.listdir(processed_dir) if f.endswith(".parquet")]
    all_dfs = []

    for fname in parquet_files:
        fpath = os.path.join(processed_dir, fname)
        try:
            df = pd.read_parquet(fpath)
            if "human_label" not in df.columns:
                continue
            labeled = df[df["human_label"].isin(["true_positive", "false_positive"])]
            if len(labeled) == 0:
                continue

            labeled = labeled.copy()
            labeled["_source_file"] = fname
            labeled["label"] = labeled["human_label"].map(
                {
                    "true_positive": "attack",
                    "false_positive": "benign",
                }
            )
            if "body" in labeled.columns:
                labeled["body"] = labeled["body"].fillna("")
            else:
                labeled["body"] = ""
            if "headers" in labeled.columns:

                def _norm_headers(h):
                    if isinstance(h, dict):
                        return h
                    if isinstance(h, str):
                        try:
                            return json.loads(h)
                        except Exception:
                            return {}
                    return {}

                labeled["headers"] = labeled["headers"].apply(_norm_headers)
            else:
                labeled["headers"] = [{}] * len(labeled)
            labeled["method"] = labeled["method"].fillna("GET")
            labeled["uri"] = labeled["uri"].fillna("/")

            all_dfs.append(labeled)
            log.info(
                "  %s: %d labeled rows (%d attack, %d benign)",
                fname,
                len(labeled),
                (labeled["label"] == "attack").sum(),
                (labeled["label"] == "benign").sum(),
            )
        except Exception as e:
            log.warning("  %s: skipped (%s)", fname, e)

    if not all_dfs:
        raise RuntimeError(
            "No reviewed alerts found in parquet files. "
            "Use the Review page to label alerts and export them first."
        )

    combined = pd.concat(all_dfs, ignore_index=True)

    log.info(
        "Total: %d reviewed alerts (%d attack, %d benign)",
        len(combined),
        (combined["label"] == "attack").sum(),
        (combined["label"] == "benign").sum(),
    )
    return combined


def train_and_evaluate_candidate(
    name: str,
    base_estimator: Any,
    X_train: np.ndarray,
    X_val: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_val: np.ndarray,
    y_test: np.ndarray,
) -> Dict[str, Any]:
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

    log.info(
        "%s — Recall=%.4f Precision=%.4f F1=%.4f AUROC=%.4f composite=%.4f",
        name,
        metrics["recall"],
        metrics["precision"],
        metrics["f1"],
        metrics["auroc"],
        score,
    )

    return {
        "name": name,
        "base_estimator": base_estimator,
        "calibrated_model": calibrated,
        "metrics": metrics,
        "composite_score": score,
    }


def export_miss_model_artifacts(
    best: Dict[str, Any],
    extractor: MissModelFeatureExtractor,
    version: int,
    regex_signatures_path: str,
    training_config: Dict[str, Any],
    all_results: List[Dict[str, Any]],
    optuna_results: Optional[List[Dict[str, Any]]] = None,
) -> str:
    out_dir = os.path.join(MODELS_DIR, f"miss_v{version}")
    os.makedirs(out_dir, exist_ok=True)
    log.info("Exporting miss model artifacts to %s", out_dir)

    joblib.dump(best["base_estimator"], os.path.join(out_dir, "miss_model.joblib"))
    joblib.dump(
        best["calibrated_model"], os.path.join(out_dir, "miss_calibrator.joblib")
    )
    joblib.dump(extractor, os.path.join(out_dir, "miss_feature_extractor.joblib"))

    for r in all_results:
        joblib.dump(
            r["calibrated_model"],
            os.path.join(out_dir, f"miss_calibrator_{r['name']}.joblib"),
        )

    if _HAS_ONNX:
        _export_onnx(
            best["base_estimator"],
            X_dim=training_config.get("feature_dim", 57),
            out_dir=out_dir,
            name=best["name"],
        )

    all_candidate_metrics = [
        {
            "name": r["name"],
            "metrics": r["metrics"],
            "composite_score": r["composite_score"],
            "best_params": r.get("best_params"),
        }
        for r in all_results
    ]

    metadata = {
        "model_version": version,
        "model_type": "miss_model",
        "model_name": best["name"],
        "composite_score": best["composite_score"],
        "metrics": best["metrics"],
        "all_candidates": all_candidate_metrics,
        "training_config": training_config,
        "regex_signatures_sha256": sha256_file(regex_signatures_path),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "composite_weights": {
            "recall": W_RECALL,
            "precision": W_PRECISION,
            "f1": W_F1,
            "auroc": W_AUROC,
        },
    }

    if optuna_results:
        metadata["optuna_results"] = [
            {
                "name": r["name"],
                "best_params": r["best_params"],
                "best_value": r["best_value"],
            }
            for r in optuna_results
        ]
        metadata["training_config"]["optuna_enabled"] = True
        metadata["training_config"]["optuna_trials"] = OPTUNA_TRIALS

    with open(os.path.join(out_dir, "miss_model_metadata.json"), "w") as fh:
        json.dump(metadata, fh, indent=2, default=_json_default)

    return out_dir


def _export_onnx(model: Any, X_dim: int, out_dir: str, name: str) -> None:
    try:
        initial_types = [("float_input", FloatTensorType([None, X_dim]))]

        if hasattr(model, "get_booster"):
            bst = model.get_booster()
            onx = convert_sklearn(bst, initial_types=initial_types)
        else:
            onx = convert_sklearn(model, initial_types=initial_types)

        onnx_path = os.path.join(out_dir, "miss_model.onnx")
        with open(onnx_path, "wb") as f:
            f.write(onx.SerializeToString())

        cal_path = os.path.join(out_dir, "miss_calibrator.onnx")
        cal_model = joblib.load(os.path.join(out_dir, "miss_calibrator.joblib"))
        cal_onx = convert_sklearn(cal_model, initial_types=initial_types)
        with open(cal_path, "wb") as f:
            f.write(cal_onx.SerializeToString())

        log.info("ONNX models exported: %s, %s", onnx_path, cal_path)
    except Exception as exc:
        log.warning(
            "ONNX export failed for %s: %s — joblib will be used instead", name, exc
        )


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _resolve_signatures_path() -> str:
    if os.path.exists(REGEX_SIGNATURES_PATH):
        return REGEX_SIGNATURES_PATH
    alt_path = os.path.join(DATA_DIR, "processed", "modintel_regex.signatures")
    if os.path.exists(alt_path):
        return alt_path
    log.error(
        "Regex signatures file not found at %s or %s", REGEX_SIGNATURES_PATH, alt_path
    )
    raise RuntimeError("Regex signatures file not found")


def main() -> None:
    log.info("=== Miss Model Training from Reviewed Alerts ===")

    use_optuna = _HAS_OPTUNA and os.getenv("OPTUNA_ENABLED", "1").lower() in (
        "1",
        "true",
        "yes",
    )

    regex_path = _resolve_signatures_path()

    source = os.getenv("MISS_TRAIN_SOURCE", "mongo").lower()
    if source == "parquet":
        df = load_reviewed_alerts_from_parquets()
    else:
        df = load_reviewed_alerts_from_mongo()

    log.info("Loaded %d total reviewed alerts", len(df))

    extractor = MissModelFeatureExtractor(regex_path)
    log.info("Fitting MissModelFeatureExtractor...")
    X = extractor.fit_transform(df)
    y = (df["label"] == "attack").astype(int).values

    attack_count = y.sum()
    benign_count = len(y) - attack_count
    log.info(
        "Feature matrix shape: %s (attack=%d, benign=%d)",
        str(X.shape),
        attack_count,
        benign_count,
    )

    if attack_count < 3 or benign_count < 1:
        log.error(
            "Insufficient labeled data: attack=%d, benign=%d",
            attack_count,
            benign_count,
        )
        raise RuntimeError(
            "Not enough reviewed alerts to train. "
            f"Need at least 3 attacks and 1 benign (attack={attack_count}, benign={benign_count})."
        )

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=(TEST_SPLIT + VAL_SPLIT),
        random_state=RANDOM_STATE,
        stratify=y,
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=0.5,
        random_state=RANDOM_STATE,
        stratify=y_temp,
    )

    log.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(X_train),
        len(X_val),
        len(X_test),
    )
    log.info("Train attack ratio: %.2f%%", y_train.mean() * 100)

    optuna_results = None
    optuna_best_params = {}

    if use_optuna:
        log.info("Optuna tuning enabled — %d trials per candidate", OPTUNA_TRIALS)
        optuna_results = build_miss_candidates_with_optuna(
            X_train,
            y_train,
            X_val,
            y_val,
        )
        for r in optuna_results:
            optuna_best_params[r["name"]] = r["best_params"]

    candidates: List[Tuple[str, Any]] = []

    if use_optuna and optuna_best_params:
        for name, params in optuna_best_params.items():
            model = _instantiate_with_params(name, params)
            candidates.append((name, model))
    else:
        candidates = build_miss_candidates_default()

    if not candidates:
        log.error("No candidate classifiers available.")
        raise RuntimeError("No candidate classifiers available.")

    results: List[Dict[str, Any]] = []
    for name, base_estimator in candidates:
        r = train_and_evaluate_candidate(
            name,
            base_estimator,
            X_train,
            X_val,
            X_test,
            y_train,
            y_val,
            y_test,
        )
        results.append(r)

    results.sort(key=lambda r: r["composite_score"], reverse=True)

    best = results[0]
    log.info(
        "Best miss model: %s (composite=%.4f)", best["name"], best["composite_score"]
    )

    version = next_model_version(MODELS_DIR, prefix="miss_v")
    training_config = {
        "random_state": RANDOM_STATE,
        "calibration_method": CALIBRATION_METHOD,
        "source": source,
        "total_samples": len(df),
        "attack_count": int(attack_count),
        "benign_count": int(benign_count),
        "feature_dim": X.shape[1],
        "composite_weights": {
            "recall": W_RECALL,
            "precision": W_PRECISION,
            "f1": W_F1,
            "auroc": W_AUROC,
        },
        "candidates_trained": [r["name"] for r in results],
        "optuna_enabled": use_optuna,
        "optuna_trials": OPTUNA_TRIALS if use_optuna else 0,
    }

    if use_optuna and optuna_results:
        for r in results:
            for o in optuna_results:
                if o["name"] == r["name"]:
                    r["best_params"] = o["best_params"]
                    break

    out_dir = export_miss_model_artifacts(
        best=best,
        extractor=extractor,
        version=version,
        regex_signatures_path=regex_path,
        training_config=training_config,
        all_results=results,
        optuna_results=optuna_results,
    )

    print("\n=== Miss Model Training Summary ===")
    print(f"  Best model        : {best['name']}")
    print(f"  Version           : miss_v{version}")
    print(
        f"  Training samples  : {len(df)} ({int(attack_count)} attack, {int(benign_count)} benign)"
    )
    print(f"  Composite score   : {best['composite_score']:.4f}")
    print(f"  Recall            : {best['metrics']['recall']:.4f}")
    print(f"  Precision         : {best['metrics']['precision']:.4f}")
    print(f"  F1                : {best['metrics']['f1']:.4f}")
    print(f"  AUROC             : {best['metrics']['auroc']:.4f}")
    print(f"  FPR               : {best['metrics']['fpr']:.4f}")
    print(f"  FNR               : {best['metrics']['fnr']:.4f}")
    print(
        f"  Optuna            : {'Yes (%d trials)' % OPTUNA_TRIALS if use_optuna else 'No'}"
    )
    print(
        f"  ONNX export       : {'Yes' if _HAS_ONNX else 'No (skl2onnx not installed)'}"
    )
    print(f"  Artifacts         : {out_dir}")
    print("====================================\n")

    print("All candidates:")
    for r in results:
        print(
            f"  {r['name']:30s}  composite={r['composite_score']:.4f}"
            f"  Recall={r['metrics']['recall']:.4f}"
            f"  Precision={r['metrics']['precision']:.4f}"
        )

    result_json = json.dumps(
        {
            "version": f"miss_v{version}",
            "model_name": best["name"],
            "composite_score": best["composite_score"],
            "metrics": {
                k: v for k, v in best["metrics"].items() if k != "confusion_matrix"
            },
            "samples": len(df),
            "attacks": int(attack_count),
            "benign": int(benign_count),
            "artifacts_dir": out_dir,
            "optuna_enabled": use_optuna,
            "onnx_exported": _HAS_ONNX,
        },
        default=_json_default,
    )

    print(f"\nTRAINING_RESULT={result_json}")


if __name__ == "__main__":
    main()

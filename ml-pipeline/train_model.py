from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
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

from feature_extractor import WAFFeatureExtractor

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
FEATURE_SCHEMA_SRC = os.path.join(SCRIPT_DIR, "feature_schema.json")
MODELS_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_MODELS_DIR", os.path.join(REPO_ROOT, "models"))
)

BOOTSTRAP_B = 200
BOOTSTRAP_SEED = 42
ECE_BINS = 10
RANDOM_STATE = 42

W_F1 = 0.4
W_ECE = 0.3
W_AUROC = 0.2
W_FPR = 0.1

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


def next_model_version(base_dir: str) -> int:

    os.makedirs(base_dir, exist_ok=True)
    existing = [
        d
        for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d)) and d.startswith("v")
    ]
    versions = []
    for name in existing:
        try:
            versions.append(int(name[1:]))
        except ValueError:
            pass
    return max(versions, default=0) + 1


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(y_true)
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_prob >= lo) & (y_prob < hi)
        if i == n_bins - 1:
            mask = (y_prob >= lo) & (y_prob <= hi)
        if mask.sum() == 0:
            continue
        mean_pred = y_prob[mask].mean()
        frac_pos = y_true[mask].mean()
        ece += (mask.sum() / n) * abs(mean_pred - frac_pos)
    return float(ece)


def compute_fpr_fnr(y_true: np.ndarray, y_pred: np.ndarray) -> Tuple[float, float]:

    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return float(fpr), float(fnr)


def per_family_fpr_fnr(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    families: np.ndarray,
) -> Dict[str, Dict[str, float]]:

    result: Dict[str, Dict[str, float]] = {}
    for family in np.unique(families):
        mask = families == family
        if mask.sum() == 0:
            continue
        fpr, fnr = compute_fpr_fnr(y_true[mask], y_pred[mask])
        result[str(family)] = {"fpr": fpr, "fnr": fnr}
    return result


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    families: np.ndarray,
) -> Dict[str, Any]:

    fpr, fnr = compute_fpr_fnr(y_true, y_pred)
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
        "ece": compute_ece(y_true, y_prob, n_bins=ECE_BINS),
        "brier_score": float(brier_score_loss(y_true, y_prob)),
        "per_family": per_family_fpr_fnr(y_true, y_pred, families),
    }
    return metrics


def composite_score(metrics: Dict[str, Any]) -> float:

    return (
        W_F1 * metrics["f1"]
        + W_ECE * (1.0 - metrics["ece"])
        + W_AUROC * metrics["auroc"]
        + W_FPR * (1.0 - metrics["fpr"])
    )


def bootstrap_quantiles(
    calibrated_model: Any,
    X_cal: np.ndarray,
    B: int = BOOTSTRAP_B,
    seed: int = BOOTSTRAP_SEED,
) -> Dict[str, Any]:

    rng = np.random.default_rng(seed)
    n = len(X_cal)
    mean_probs: List[float] = []

    for _ in range(B):
        idx = rng.integers(0, n, size=n)
        X_boot = X_cal[idx]
        probs = calibrated_model.predict_proba(X_boot)[:, 1]
        mean_probs.append(float(probs.mean()))

    arr = np.array(mean_probs)
    return {
        "b": B,
        "ci_level": 0.95,
        "quantile_low": float(np.percentile(arr, 2.5)),
        "quantile_high": float(np.percentile(arr, 97.5)),
        "bootstrap_mean_probs": [round(p, 6) for p in mean_probs],
    }


def build_candidates() -> List[Tuple[str, Any]]:

    candidates: List[Tuple[str, Any]] = []

    if _HAS_XGB:
        candidates.append(
            (
                "xgboost",
                XGBClassifier(
                    n_estimators=200,
                    max_depth=6,
                    learning_rate=0.1,
                    eval_metric="logloss",
                    scale_pos_weight=5,
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
                "lightgbm",
                LGBMClassifier(
                    n_estimators=200,
                    max_depth=6,
                    learning_rate=0.1,
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
            "random_forest",
            RandomForestClassifier(
                n_estimators=200,
                max_depth=None,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        )
    )

    candidates.append(
        (
            "logistic_regression",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                solver="lbfgs",
            ),
        )
    )

    return candidates


def load_splits(
    parquet_path: str,
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
    WAFFeatureExtractor,
]:

    log.info("Loading dataset from %s", parquet_path)
    df = pd.read_parquet(parquet_path)

    rename_map = {
        "coraza_fired_rule_ids": "fired_rule_ids",
        "coraza_rule_severities": "rule_severities",
        "coraza_rule_messages": "rule_messages",
        "coraza_anomaly_score": "anomaly_score",
        "coraza_inbound_threshold": "inbound_threshold",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    df_train = df[df["split"] == "train"].copy()
    df_val = df[df["split"] == "validation"].copy()
    df_test = df[df["split"] == "test"].copy()

    log.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(df_train),
        len(df_val),
        len(df_test),
    )

    extractor = WAFFeatureExtractor()
    log.info("Fitting WAFFeatureExtractor on training split...")
    X_train = extractor.fit_transform(df_train)
    X_val = extractor.transform(df_val)
    X_test = extractor.transform(df_test)

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


def train_and_evaluate(
    candidates: List[Tuple[str, Any]],
    X_train: np.ndarray,
    X_val: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_val: np.ndarray,
    y_test: np.ndarray,
    df_test: pd.DataFrame,
) -> List[Dict[str, Any]]:

    results: List[Dict[str, Any]] = []

    for name, base_estimator in candidates:
        log.info("Training candidate: %s", name)

        base_estimator.fit(X_train, y_train)

        log.info("Calibrating %s on validation split...", name)
        calibrated = CalibratedClassifierCV(
            estimator=base_estimator,
            method="isotonic",
            cv="prefit",
        )
        calibrated.fit(X_val, y_val)

        y_pred = calibrated.predict(X_test)
        y_prob = calibrated.predict_proba(X_test)[:, 1]

        families = df_test.get(
            "attack_family", pd.Series(["unknown"] * len(df_test))
        ).values

        metrics = compute_metrics(y_test, y_pred, y_prob, families)
        score = composite_score(metrics)

        log.info(
            "%s — F1=%.4f ECE=%.4f AUROC=%.4f FPR=%.4f composite=%.4f",
            name,
            metrics["f1"],
            metrics["ece"],
            metrics["auroc"],
            metrics["fpr"],
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


def export_artifacts(
    best: Dict[str, Any],
    extractor: WAFFeatureExtractor,
    bootstrap_q: Dict[str, Any],
    version: int,
    parquet_path: str,
    training_config: Dict[str, Any],
    all_results: List[Dict[str, Any]],
) -> str:

    out_dir = os.path.join(MODELS_BASE_DIR, f"v{version}")
    os.makedirs(out_dir, exist_ok=True)
    log.info("Exporting artifacts to %s", out_dir)

    joblib.dump(best["base_estimator"], os.path.join(out_dir, "model.joblib"))

    joblib.dump(best["calibrated_model"], os.path.join(out_dir, "calibrator.joblib"))

    for r in all_results:
        joblib.dump(
            r["calibrated_model"],
            os.path.join(out_dir, f"calibrator_{r['name']}.joblib"),
        )

    joblib.dump(extractor, os.path.join(out_dir, "feature_extractor.joblib"))

    shutil.copy2(FEATURE_SCHEMA_SRC, os.path.join(out_dir, "feature_schema.json"))

    with open(os.path.join(out_dir, "bootstrap_quantiles.json"), "w") as fh:
        json.dump(bootstrap_q, fh, indent=2)

    all_candidate_metrics = [
        {
            "name": r["name"],
            "metrics": r["metrics"],
            "composite_score": r["composite_score"],
        }
        for r in all_results
    ]

    metadata = {
        "model_version": version,
        "model_name": best["name"],
        "composite_score": best["composite_score"],
        "metrics": best["metrics"],
        "all_candidates": all_candidate_metrics,
        "training_config": training_config,
        "dataset_sha256": sha256_file(parquet_path),
        "feature_schema_version": _load_schema_version(),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "bootstrap": {
            "b": bootstrap_q["b"],
            "ci_level": bootstrap_q["ci_level"],
            "quantile_low": bootstrap_q["quantile_low"],
            "quantile_high": bootstrap_q["quantile_high"],
        },
    }

    with open(os.path.join(out_dir, "model_metadata.json"), "w") as fh:
        json.dump(metadata, fh, indent=2, default=_json_default)

    return out_dir


def _load_schema_version() -> str:
    try:
        with open(FEATURE_SCHEMA_SRC) as fh:
            schema = json.load(fh)
        return schema.get("version", "unknown")
    except Exception:
        return "unknown"


def _json_default(obj: Any) -> Any:

    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def main() -> None:
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
    ) = load_splits(PARQUET_PATH)

    candidates = build_candidates()
    if not candidates:
        log.error(
            "No candidate classifiers available. Install xgboost and/or lightgbm."
        )
        raise RuntimeError("No candidate classifiers available.")

    results = train_and_evaluate(
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
        "Best model: %s (composite score=%.4f)",
        best["name"],
        best["composite_score"],
    )

    log.info("Computing bootstrap CI (B=%d) on validation set...", BOOTSTRAP_B)
    bootstrap_q = bootstrap_quantiles(best["calibrated_model"], X_val, B=BOOTSTRAP_B)
    log.info(
        "Bootstrap 95%% CI: [%.4f, %.4f]",
        bootstrap_q["quantile_low"],
        bootstrap_q["quantile_high"],
    )

    version = next_model_version(MODELS_BASE_DIR)

    training_config = {
        "bootstrap_b": BOOTSTRAP_B,
        "ece_bins": ECE_BINS,
        "random_state": RANDOM_STATE,
        "composite_weights": {
            "f1": W_F1,
            "ece": W_ECE,
            "auroc": W_AUROC,
            "fpr": W_FPR,
        },
        "calibration_method": "isotonic",
        "candidates_trained": [r["name"] for r in results],
    }

    out_dir = export_artifacts(
        best=best,
        extractor=extractor,
        bootstrap_q=bootstrap_q,
        version=version,
        parquet_path=PARQUET_PATH,
        training_config=training_config,
        all_results=results,
    )

    print("\n=== Training Summary ===")
    print(f"  Best model     : {best['name']}")
    print(f"  Version        : v{version}")
    print(f"  Composite score: {best['composite_score']:.4f}")
    print(f"  F1             : {best['metrics']['f1']:.4f}")
    print(f"  AUROC          : {best['metrics']['auroc']:.4f}")
    print(f"  ECE            : {best['metrics']['ece']:.4f}")
    print(f"  FPR            : {best['metrics']['fpr']:.4f}")
    print(f"  FNR            : {best['metrics']['fnr']:.4f}")
    print(f"  Brier score    : {best['metrics']['brier_score']:.4f}")
    print(
        f"  Bootstrap CI   : [{bootstrap_q['quantile_low']:.4f}, {bootstrap_q['quantile_high']:.4f}]"
    )
    print(f"  Artifacts      : {out_dir}")
    print("========================\n")

    print("All candidates:")
    for r in results:
        print(
            f"  {r['name']:20s}  composite={r['composite_score']:.4f}"
            f"  F1={r['metrics']['f1']:.4f}"
            f"  AUROC={r['metrics']['auroc']:.4f}"
            f"  ECE={r['metrics']['ece']:.4f}"
        )


if __name__ == "__main__":
    main()

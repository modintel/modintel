"""
evaluate_model.py
Multi-model evaluation script — generates a self-contained HTML comparison report.

Usage:
    python evaluate_model.py ../models/v2

Outputs:
    reports/model_evaluation_v{N}.html

Requirements: 6.1, 6.2, 6.3
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import logging
import os
import sys
from typing import Any, Dict

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score,
    auc,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_DATA_DIR", os.path.join(REPO_ROOT, "data"))
)
DEFAULT_PARQUET_PATH = os.path.join(DATA_BASE_DIR, "processed", "waf_dataset_v1.parquet")
ECE_BINS = 10
COLORS = ["steelblue", "darkorange", "green", "crimson"]
CANDIDATE_NAMES = ["xgboost", "lightgbm", "random_forest", "logistic_regression"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fig_to_b64(fig: plt.Figure) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=110)
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded


def _img_tag(b64: str, alt: str = "") -> str:
    return f'<img src="data:image/png;base64,{b64}" alt="{alt}" style="max-width:100%;height:auto;" />'


def compute_ece(
    y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = ECE_BINS
) -> float:
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
        ece += (mask.sum() / n) * abs(y_prob[mask].mean() - y_true[mask].mean())
    return float(ece)


def compute_fpr_fnr(y_true, y_pred):
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return float(fpr), float(fnr)


def evaluate_model(calibrator, X_test, y_test, df_test) -> Dict[str, Any]:
    y_pred = calibrator.predict(X_test)
    y_prob = calibrator.predict_proba(X_test)[:, 1]
    fpr, fnr = compute_fpr_fnr(y_test, y_pred)
    families = df_test.get(
        "attack_family", pd.Series(["unknown"] * len(df_test))
    ).values
    per_family = {}
    for fam in sorted(np.unique(families)):
        mask = families == fam
        f, fn_ = compute_fpr_fnr(y_test[mask], y_pred[mask])
        per_family[str(fam)] = {
            "fpr": round(f, 4),
            "fnr": round(fn_, 4),
            "count": int(mask.sum()),
        }
    return {
        "y_pred": y_pred,
        "y_prob": y_prob,
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "auroc": float(roc_auc_score(y_test, y_prob))
        if len(np.unique(y_test)) > 1
        else 0.0,
        "pr_auc": float(average_precision_score(y_test, y_prob))
        if len(np.unique(y_test)) > 1
        else 0.0,
        "fpr": fpr,
        "fnr": fnr,
        "ece": compute_ece(y_test, y_prob),
        "brier_score": float(brier_score_loss(y_test, y_prob)),
        "per_family": per_family,
    }


# ---------------------------------------------------------------------------
# Multi-model plots
# ---------------------------------------------------------------------------


def plot_roc_comparison(results: Dict[str, Dict]) -> str:
    fig, ax = plt.subplots(figsize=(7, 6))
    for i, (name, r) in enumerate(results.items()):
        fpr_vals, tpr_vals, _ = roc_curve(r["_y_test"], r["y_prob"])
        roc_auc = auc(fpr_vals, tpr_vals)
        ax.plot(
            fpr_vals,
            tpr_vals,
            color=COLORS[i % len(COLORS)],
            lw=2,
            label=f"{name} (AUC={roc_auc:.4f})",
        )
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — All Models")
    ax.legend(loc="lower right", fontsize=9)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    fig.tight_layout()
    return _fig_to_b64(fig)


def plot_pr_comparison(results: Dict[str, Dict]) -> str:
    fig, ax = plt.subplots(figsize=(7, 6))
    for i, (name, r) in enumerate(results.items()):
        prec, rec, _ = precision_recall_curve(r["_y_test"], r["y_prob"])
        pr_auc = auc(rec, prec)
        ax.plot(
            rec,
            prec,
            color=COLORS[i % len(COLORS)],
            lw=2,
            label=f"{name} (AUC={pr_auc:.4f})",
        )
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curves — All Models")
    ax.legend(loc="lower left", fontsize=9)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.05)
    fig.tight_layout()
    return _fig_to_b64(fig)


def plot_reliability_comparison(results: Dict[str, Dict]) -> str:
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Perfect")
    for i, (name, r) in enumerate(results.items()):
        try:
            frac_pos, mean_pred = calibration_curve(
                r["_y_test"], r["y_prob"], n_bins=ECE_BINS, strategy="uniform"
            )
            ax.plot(
                mean_pred,
                frac_pos,
                "s-",
                color=COLORS[i % len(COLORS)],
                lw=2,
                label=name,
            )
        except Exception:
            pass
    ax.set_xlabel("Mean predicted probability")
    ax.set_ylabel("Fraction of positives")
    ax.set_title("Reliability Curves — All Models")
    ax.legend(fontsize=9)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    fig.tight_layout()
    return _fig_to_b64(fig)


def plot_metrics_bar(results: Dict[str, Dict]) -> str:
    metrics = ["accuracy", "precision", "recall", "f1", "auroc"]
    names = list(results.keys())
    x = np.arange(len(metrics))
    width = 0.8 / len(names)
    fig, ax = plt.subplots(figsize=(10, 5))
    for i, name in enumerate(names):
        vals = [results[name][m] for m in metrics]
        ax.bar(
            x + i * width,
            vals,
            width,
            label=name,
            color=COLORS[i % len(COLORS)],
            alpha=0.85,
        )
    ax.set_xticks(x + width * (len(names) - 1) / 2)
    ax.set_xticklabels(metrics)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Score")
    ax.set_title("Metric Comparison — All Models")
    ax.legend(fontsize=9)
    fig.tight_layout()
    return _fig_to_b64(fig)


def plot_confusion_matrix(y_true, y_pred, name: str) -> str:
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(4, 3.5))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    fig.colorbar(im, ax=ax)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Benign", "Attack"])
    ax.set_yticklabels(["Benign", "Attack"])
    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                format(cm[i, j], "d"),
                ha="center",
                va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=9,
            )
    ax.set_ylabel("True")
    ax.set_xlabel("Predicted")
    ax.set_title(f"Confusion Matrix\n{name}")
    fig.tight_layout()
    return _fig_to_b64(fig)


def plot_confidence_distribution(results: Dict[str, Dict]) -> str:
    fig, axes = plt.subplots(
        1, len(results), figsize=(4 * len(results), 4), sharey=False
    )
    if len(results) == 1:
        axes = [axes]
    for ax, (name, r) in zip(axes, results.items()):
        ax.hist(r["y_prob"], bins=50, color="steelblue", edgecolor="white", alpha=0.85)
        ax.set_title(name, fontsize=9)
        ax.set_xlabel("Predicted prob")
        ax.set_ylabel("Count")
        ax.set_xlim(0, 1)
    fig.suptitle("Confidence Distribution — All Models")
    fig.tight_layout()
    return _fig_to_b64(fig)


def plot_per_family_heatmap(results: Dict[str, Dict], metric: str = "fnr") -> str:
    names = list(results.keys())
    first = list(results.values())[0]
    families = sorted(first["per_family"].keys())
    data = np.array(
        [
            [results[n]["per_family"].get(f, {}).get(metric, 0.0) for f in families]
            for n in names
        ]
    )
    fig, ax = plt.subplots(
        figsize=(max(8, len(families) * 1.2), max(3, len(names) * 0.8))
    )
    im = ax.imshow(data, aspect="auto", cmap="RdYlGn_r", vmin=0, vmax=1)
    fig.colorbar(im, ax=ax)
    ax.set_xticks(range(len(families)))
    ax.set_xticklabels(families, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=9)
    for i in range(len(names)):
        for j in range(len(families)):
            ax.text(
                j,
                i,
                f"{data[i, j]:.2f}",
                ha="center",
                va="center",
                fontsize=7,
                color="white" if data[i, j] > 0.6 else "black",
            )
    ax.set_title(f"Per-Family {metric.upper()} Heatmap — All Models")
    fig.tight_layout()
    return _fig_to_b64(fig)


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------


def generate_html(
    version: int,
    metadata: Dict,
    results: Dict[str, Dict],
    img_roc,
    img_pr,
    img_reliability,
    img_metrics_bar,
    img_conf_dist,
    img_fpr_heatmap,
    img_fnr_heatmap,
    cm_images: Dict[str, str],
) -> str:

    best_name = metadata.get("model_name", "unknown")
    trained_at = metadata.get("trained_at", "unknown")
    composite = metadata.get("composite_score", 0.0)

    css = """
    body{font-family:Arial,sans-serif;margin:40px;background:#f9f9f9;color:#222}
    h1{color:#2c3e50}h2{color:#34495e;border-bottom:1px solid #ccc;padding-bottom:4px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
    .grid4{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px}
    .card{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.1)}
    .full{grid-column:1/-1}
    table{border-collapse:collapse;width:100%}
    th,td{border:1px solid #ddd;padding:7px 10px;text-align:left;font-size:13px}
    th{background:#2c3e50;color:#fff}tr:nth-child(even){background:#f2f2f2}
    .meta{font-size:.9em;color:#555;margin-bottom:20px}
    .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold}
    .best{background:#27ae60;color:#fff}
    """

    # Summary comparison table
    metric_keys = [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "auroc",
        "pr_auc",
        "fpr",
        "fnr",
        "ece",
        "brier_score",
    ]
    header = (
        "<tr><th>Metric</th>"
        + "".join(
            f"<th>{n} {'<span class=badge best>best</span>' if n == best_name else ''}</th>"
            for n in results.keys()
        )
        + "</tr>"
    )
    rows = ""
    for m in metric_keys:
        vals = {n: results[n][m] for n in results}
        best_val = (
            min(vals.values())
            if m in ("fpr", "fnr", "ece", "brier_score")
            else max(vals.values())
        )
        row = f"<tr><td>{m}</td>"
        for n in results:
            v = vals[n]
            style = (
                " style='background:#d5f5e3;font-weight:bold'"
                if abs(v - best_val) < 1e-9
                else ""
            )
            row += f"<td{style}>{v:.4f}</td>"
        rows += row + "</tr>"
    comparison_table = f"<table>{header}{rows}</table>"

    # Per-family tables per model
    family_sections = ""
    for name, r in results.items():
        fam_header = "<tr><th>Family</th><th>FPR</th><th>FNR</th><th>Count</th></tr>"
        fam_rows = "".join(
            f"<tr><td>{f}</td><td>{d['fpr']:.4f}</td><td>{d['fnr']:.4f}</td><td>{d['count']}</td></tr>"
            for f, d in sorted(r["per_family"].items())
        )
        family_sections += f"""
        <div class="card">
          <h3>{name}</h3>
          <table>{fam_header}{fam_rows}</table>
        </div>"""

    cm_section = "".join(
        f'<div class="card"><h3>{n}</h3>{_img_tag(img, f"CM {n}")}</div>'
        for n, img in cm_images.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/>
<title>Model Evaluation Report — v{version}</title>
<style>{css}</style>
</head>
<body>
<h1>Model Evaluation Report — v{version}</h1>
<div class="meta">
  <strong>Best model:</strong> {best_name} &nbsp;|&nbsp;
  <strong>Trained at:</strong> {trained_at} &nbsp;|&nbsp;
  <strong>Composite score:</strong> {composite:.4f}
</div>

<h2>Metric Comparison — All Models</h2>
<div class="card">{comparison_table}</div>

<h2>Metric Bar Chart</h2>
<div class="card">{_img_tag(img_metrics_bar, "Metrics Bar")}</div>

<h2>ROC &amp; Precision-Recall Curves</h2>
<div class="grid">
  <div class="card">{_img_tag(img_roc, "ROC")}</div>
  <div class="card">{_img_tag(img_pr, "PR")}</div>
</div>

<h2>Reliability Curves</h2>
<div class="card">{_img_tag(img_reliability, "Reliability")}</div>

<h2>Confidence Distributions</h2>
<div class="card">{_img_tag(img_conf_dist, "Confidence")}</div>

<h2>Confusion Matrices</h2>
<div class="grid4">{cm_section}</div>

<h2>Per-Family FPR Heatmap</h2>
<div class="card">{_img_tag(img_fpr_heatmap, "FPR Heatmap")}</div>

<h2>Per-Family FNR Heatmap</h2>
<div class="card">{_img_tag(img_fnr_heatmap, "FNR Heatmap")}</div>

<h2>Per-Family Breakdown — All Models</h2>
<div class="grid">{family_sections}</div>

</body></html>"""
    return html


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "model_dir", help="Path to model version directory, e.g. ../models/v2"
    )
    args = parser.parse_args()

    model_dir = os.path.abspath(args.model_dir)
    if not os.path.isdir(model_dir):
        log.error("Model directory not found: %s", model_dir)
        sys.exit(1)

    dir_name = os.path.basename(model_dir)
    version = (
        int(dir_name[1:]) if dir_name.startswith("v") and dir_name[1:].isdigit() else 0
    )

    # Load metadata and feature extractor
    with open(os.path.join(model_dir, "model_metadata.json")) as f:
        metadata = json.load(f)
    feature_extractor = joblib.load(os.path.join(model_dir, "feature_extractor.joblib"))

    # Load test split
    parquet_path = os.path.abspath(
        os.environ.get("ML_PIPELINE_PARQUET_PATH", DEFAULT_PARQUET_PATH)
    )
    if not os.path.exists(parquet_path):
        log.error("Dataset not found: %s", parquet_path)
        sys.exit(1)

    log.info("Loading dataset...")
    df = pd.read_parquet(parquet_path)
    rename_map = {
        "coraza_fired_rule_ids": "fired_rule_ids",
        "coraza_rule_severities": "rule_severities",
        "coraza_rule_messages": "rule_messages",
        "coraza_anomaly_score": "anomaly_score",
        "coraza_inbound_threshold": "inbound_threshold",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})
    df_test = df[df["split"] == "test"].copy()
    log.info("Test split: %d rows", len(df_test))

    X_test = feature_extractor.transform(df_test)
    y_test = (df_test["label"] == "attack").astype(int).values

    # Load all available candidate calibrators
    results: Dict[str, Dict] = {}
    for name in CANDIDATE_NAMES:
        path = os.path.join(model_dir, f"calibrator_{name}.joblib")
        if not os.path.exists(path):
            # fallback to default calibrator.joblib for best model
            if name == metadata.get("model_name"):
                path = os.path.join(model_dir, "calibrator.joblib")
            else:
                log.warning("Calibrator not found for %s, skipping", name)
                continue
        log.info("Evaluating %s...", name)
        try:
            cal = joblib.load(path)
            r = evaluate_model(cal, X_test, y_test, df_test)
            r["_y_test"] = y_test
            results[name] = r
        except Exception as e:
            log.warning("Failed to evaluate %s: %s", name, e)

    if not results:
        log.error("No models could be evaluated.")
        sys.exit(1)

    # Generate plots
    log.info("Generating plots...")
    img_roc = plot_roc_comparison(results)
    img_pr = plot_pr_comparison(results)
    img_reliability = plot_reliability_comparison(results)
    img_metrics_bar = plot_metrics_bar(results)
    img_conf_dist = plot_confidence_distribution(results)
    img_fpr_heatmap = plot_per_family_heatmap(results, "fpr")
    img_fnr_heatmap = plot_per_family_heatmap(results, "fnr")
    cm_images = {
        name: plot_confusion_matrix(y_test, r["y_pred"], name)
        for name, r in results.items()
    }

    # Generate report
    html = generate_html(
        version,
        metadata,
        results,
        img_roc,
        img_pr,
        img_reliability,
        img_metrics_bar,
        img_conf_dist,
        img_fpr_heatmap,
        img_fnr_heatmap,
        cm_images,
    )

    reports_dir = os.path.join(SCRIPT_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, f"model_evaluation_v{version}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    log.info("Report written to %s", report_path)
    print(f"\nReport: {report_path}")


if __name__ == "__main__":
    main()

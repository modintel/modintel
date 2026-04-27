from __future__ import annotations

import json
import logging
import math
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("inference-engine")

_model_state: Dict[str, Any] = {
    "model": None,
    "calibrator": None,
    "feature_extractor": None,
    "feature_schema": None,
    "bootstrap_quantiles": None,
    "model_metadata": None,
    "model_version": "unknown",
    "loaded": False,
}

_startup_time: float = time.time()
_prediction_count: int = 0
_total_latency_ms: float = 0.0
_recent_latencies: list = []


def _resolve_model_dir() -> Path:
    model_version = os.getenv("MODEL_VERSION", "latest")
    models_root = Path(os.getenv("MODELS_DIR", "/app/models"))
    return models_root / model_version


def _load_artifacts() -> None:
    model_dir = _resolve_model_dir()
    logger.info("Loading model artifacts from %s", model_dir)

    if not model_dir.exists():
        logger.warning(
            "Model directory %s does not exist — running in degraded mode", model_dir
        )
        return

    try:
        _model_state["model"] = joblib.load(model_dir / "model.joblib")
        _model_state["calibrator"] = joblib.load(model_dir / "calibrator.joblib")
        _model_state["feature_extractor"] = joblib.load(
            model_dir / "feature_extractor.joblib"
        )

        with open(model_dir / "feature_schema.json") as f:
            _model_state["feature_schema"] = json.load(f)

        with open(model_dir / "bootstrap_quantiles.json") as f:
            _model_state["bootstrap_quantiles"] = json.load(f)

        with open(model_dir / "model_metadata.json") as f:
            _model_state["model_metadata"] = json.load(f)

        _model_state["model_version"] = _model_state["model_metadata"].get(
            "model_version", "unknown"
        )
        _model_state["loaded"] = True
        logger.info(
            "Model artifacts loaded successfully (version=%s)",
            _model_state["model_version"],
        )
    except Exception as exc:
        logger.error("Failed to load model artifacts: %s", exc)
        _model_state["loaded"] = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_artifacts()
    yield


app = FastAPI(
    title="ModIntel Inference Engine",
    version="1.0.0",
    lifespan=lifespan,
)


class CorazaAuditEvent(BaseModel):
    method: str = Field(..., description="HTTP method (GET, POST, …)")
    uri: str = Field(..., description="Request URI")
    headers: Optional[Any] = Field(
        default=None, description="Request headers (dict or string)"
    )
    body: Optional[str] = Field(default=None, description="Request body")

    fired_rule_ids: Optional[List[Any]] = Field(default_factory=list)
    rule_severities: Optional[Dict[str, str]] = Field(default_factory=dict)
    rule_messages: Optional[Dict[str, str]] = Field(default_factory=dict)
    anomaly_score: Optional[float] = Field(default=0.0)
    inbound_threshold: Optional[float] = Field(default=0.0)

    model_config = {"extra": "allow"}


class ShapContribution(BaseModel):
    name: str
    group: str
    shap_value: float
    direction: str  # "positive" | "negative"


class ConfidenceInterval(BaseModel):
    low: float
    high: float
    level: float = 0.95


class AdvisoryResponse(BaseModel):
    attack_probability: float
    confidence_score: float  # 0–100
    confidence_interval: ConfidenceInterval
    entropy: float
    entropy_normalized: float
    recommended_priority: str  # P1 | P2 | P3
    priority_reasoning: str
    explanation: List[ShapContribution]
    conformal_prediction_set: List[str]
    advisory_only: bool = True  # Req 8.4 — hardcoded, never configurable


def _validate_input(event: CorazaAuditEvent) -> Optional[str]:

    schema = _model_state.get("feature_schema")
    if not schema:
        return None  # No schema loaded — skip validation

    errors: List[str] = []

    if not event.method or not isinstance(event.method, str):
        errors.append("Field 'method' is required and must be a non-empty string.")

    if not event.uri or not isinstance(event.uri, str):
        errors.append("Field 'uri' is required and must be a non-empty string.")

    if event.anomaly_score is not None and event.anomaly_score < 0:
        errors.append(f"Field 'anomaly_score' must be >= 0, got {event.anomaly_score}.")

    if event.inbound_threshold is not None and event.inbound_threshold < 0:
        errors.append(
            f"Field 'inbound_threshold' must be >= 0, got {event.inbound_threshold}."
        )

    return "; ".join(errors) if errors else None


def _compute_ci(prob: float, quantiles: Dict[str, Any]) -> ConfidenceInterval:

    try:
        q025 = float(quantiles.get("q025", 0.0))
        q975 = float(quantiles.get("q975", 0.0))
        low = max(0.0, prob + q025)
        high = min(1.0, prob + q975)
        return ConfidenceInterval(low=round(low, 4), high=round(high, 4), level=0.95)
    except Exception:
        return ConfidenceInterval(
            low=round(max(0.0, prob - 0.1), 4),
            high=round(min(1.0, prob + 0.1), 4),
            level=0.95,
        )


def _compute_entropy(prob: float) -> tuple[float, float]:

    p = max(1e-12, min(1 - 1e-12, prob))
    q = 1.0 - p
    h = -(p * math.log2(p) + q * math.log2(q))
    h_norm = h / 1.0  # normalise by H_max = 1 bit
    return round(h, 6), round(h_norm, 6)


def _assign_priority(prob: float, ci_width: float, h_norm: float) -> tuple[str, str]:

    if prob >= 0.90 and ci_width <= 0.15:
        band = "P1"
        reason = (
            f"P1 assigned: attack_probability={prob:.4f} (>= 0.90) and "
            f"CI_width={ci_width:.4f} (<= 0.15) — high-confidence attack signal."
        )
    elif prob <= 0.10 and ci_width <= 0.15:
        band = "P3"
        reason = (
            f"P3 assigned: attack_probability={prob:.4f} (<= 0.10) and "
            f"CI_width={ci_width:.4f} (<= 0.15) — high-confidence benign signal."
        )
    else:
        band = "P2"
        if ci_width > 0.15:
            reason = (
                f"P2 assigned: attack_probability={prob:.4f}, "
                f"CI_width={ci_width:.4f} (> 0.15) — wide confidence interval indicates uncertainty."
            )
        elif h_norm >= 0.5:
            reason = (
                f"P2 assigned: attack_probability={prob:.4f}, "
                f"CI_width={ci_width:.4f}, entropy_normalized={h_norm:.4f} (>= 0.5) — high entropy indicates uncertainty."
            )
        else:
            reason = (
                f"P2 assigned: attack_probability={prob:.4f}, "
                f"CI_width={ci_width:.4f} — probability in ambiguous range."
            )
    return band, reason


def _top5_shap(
    feature_vector: np.ndarray, feature_names: List[str], schema: Dict
) -> List[ShapContribution]:

    model = _model_state["model"]
    features_dict = schema.get("features", {})

    try:
        import shap  # type: ignore

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(feature_vector)
        if isinstance(shap_values, list):
            sv = np.array(shap_values[1][0])
        else:
            sv = np.array(shap_values[0])
        if sv.ndim > 1:
            sv = sv[0]
    except Exception:
        sv = np.array(feature_vector[0])

    pairs = list(zip(feature_names, sv))
    pairs.sort(key=lambda x: abs(x[1]), reverse=True)
    top5 = pairs[:5]

    contributions: List[ShapContribution] = []
    for name, val in top5:
        feat_meta = features_dict.get(name, {})
        group = feat_meta.get("group", "unknown")
        val_scalar = float(val) if np.ndim(val) > 0 else val
        direction = "positive" if val_scalar >= 0 else "negative"
        contributions.append(
            ShapContribution(
                name=name,
                group=group,
                shap_value=round(float(val_scalar), 6),
                direction=direction,
            )
        )
    return contributions


def _conformal_prediction_set(prob: float) -> List[str]:

    labels: List[str] = []
    if prob >= 0.05:
        labels.append("attack")
    if prob <= 0.95:
        labels.append("benign")
    return labels


@app.post("/predict", response_model=AdvisoryResponse)
async def predict(event: CorazaAuditEvent) -> JSONResponse:

    global _prediction_count, _total_latency_ms, _recent_latencies

    validation_error = _validate_input(event)
    if validation_error:
        raise HTTPException(status_code=422, detail=validation_error)

    if not _model_state["loaded"]:
        return JSONResponse(
            status_code=500,
            content={
                "ai_status": "unavailable",
                "error": "Model artifacts not loaded.",
            },
        )

    t_start = time.perf_counter()

    try:
        extractor = _model_state["feature_extractor"]
        calibrator = _model_state["calibrator"]
        quantiles = _model_state["bootstrap_quantiles"]
        schema = _model_state["feature_schema"]

        record = {
            "method": event.method,
            "uri": event.uri,
            "headers": event.headers,
            "body": event.body or "",
            "fired_rule_ids": event.fired_rule_ids or [],
            "rule_severities": event.rule_severities or {},
            "rule_messages": event.rule_messages or {},
            "anomaly_score": event.anomaly_score or 0.0,
            "inbound_threshold": event.inbound_threshold or 0.0,
        }

        feature_vector = extractor.transform(record)  # shape (1, n_features)
        feature_names: List[str] = extractor.get_feature_names_out()

        prob_raw = calibrator.predict_proba(feature_vector)[0][1]
        attack_probability = float(round(prob_raw, 6))

        ci = _compute_ci(attack_probability, quantiles)
        ci_width = round(ci.high - ci.low, 4)

        entropy, h_norm = _compute_entropy(attack_probability)

        confidence_score = round((1.0 - h_norm) * 100.0, 2)

        band, reasoning = _assign_priority(attack_probability, ci_width, h_norm)

        top5 = _top5_shap(feature_vector, feature_names, schema)

        conf_set = _conformal_prediction_set(attack_probability)

        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        _prediction_count += 1
        _total_latency_ms += elapsed_ms
        _recent_latencies.append(elapsed_ms)
        if len(_recent_latencies) > 1000:
            _recent_latencies = _recent_latencies[-1000:]

        response = AdvisoryResponse(
            attack_probability=attack_probability,
            confidence_score=confidence_score,
            confidence_interval=ci,
            entropy=entropy,
            entropy_normalized=h_norm,
            recommended_priority=band,
            priority_reasoning=reasoning,
            explanation=top5,
            conformal_prediction_set=conf_set,
            advisory_only=True,  # Req 8.4 — hardcoded
        )
        return JSONResponse(content=response.model_dump())

    except Exception as exc:
        logger.error("Inference failure: %s", exc)
        error_msg = "Internal server error"
        if os.getenv("DEBUG", "false").lower() == "true":
            error_msg = str(exc)
        return JSONResponse(
            status_code=500,
            content={"ai_status": "unavailable", "error": error_msg},
        )


@app.post("/predict-miss")
async def predict_miss(event: CorazaAuditEvent) -> JSONResponse:
    global _prediction_count, _total_latency_ms, _recent_latencies

    t_start = time.perf_counter()

    try:
        miss_path = os.getenv("MISS_ONNX_MODEL_PATH", "/app/models/modintel.onnx")
        if miss_path and Path(miss_path).exists():
            from miss_onnx import MissONNXInference

            miss_infer = MissONNXInference(miss_path)
            result = miss_infer.predict(
                {
                    "method": event.method,
                    "uri": event.uri,
                    "headers": event.headers or {},
                    "body": event.body or "",
                }
            )
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            _prediction_count += 1
            _total_latency_ms += elapsed_ms
            _recent_latencies.append(elapsed_ms)
            if len(_recent_latencies) > 1000:
                _recent_latencies = _recent_latencies[-1000:]
            return JSONResponse(content=result)
    except Exception as exc:
        logger.warning("ONNX miss inference failed, falling back: %s", exc)

    try:
        if not _model_state["loaded"]:
            return JSONResponse(
                status_code=500,
                content={"ai_status": "unavailable", "error": "No model loaded."},
            )
        extractor = _model_state["feature_extractor"]
        calibrator = _model_state["calibrator"]
        record = {
            "method": event.method,
            "uri": event.uri,
            "headers": event.headers or {},
            "body": event.body or "",
            "fired_rule_ids": [],
            "rule_severities": {},
            "rule_messages": {},
            "anomaly_score": 0.0,
            "inbound_threshold": 0.0,
        }
        feature_vector = extractor.transform(record)
        prob_raw = calibrator.predict_proba(feature_vector)[0][1]
        attack_probability = float(round(prob_raw, 6))
        entropy, h_norm = _compute_entropy(attack_probability)
        confidence_score = round((1.0 - h_norm) * 100.0, 2)
        band, reasoning = _assign_priority(attack_probability, 0.5, h_norm)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        _prediction_count += 1
        _total_latency_ms += elapsed_ms
        _recent_latencies.append(elapsed_ms)
        if len(_recent_latencies) > 1000:
            _recent_latencies = _recent_latencies[-1000:]
        return JSONResponse(
            content={
                "attack_probability": attack_probability,
                "confidence_score": confidence_score,
                "recommended_priority": band,
                "priority_reasoning": reasoning,
                "entropy": entropy,
                "entropy_normalized": h_norm,
                "advisory_only": True,
                "model_version": _model_state["model_version"],
            }
        )
    except Exception as exc:
        logger.error("Miss inference failure: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"ai_status": "unavailable", "error": "Internal server error"},
        )


@app.get("/health")
async def health() -> JSONResponse:
    uptime = round(time.time() - _startup_time, 2)
    avg_latency = (
        round(_total_latency_ms / _prediction_count, 3)
        if _prediction_count > 0
        else 0.0
    )
    return JSONResponse(
        content={
            "status": "ok" if _model_state["loaded"] else "degraded",
            "model_version": _model_state["model_version"],
            "uptime_seconds": uptime,
            "total_predictions": _prediction_count,
            "avg_inference_latency_ms": avg_latency,
        }
    )


@app.get("/metrics")
async def metrics() -> JSONResponse:

    uptime = round(time.time() - _startup_time, 2)
    avg_latency = (
        round(_total_latency_ms / _prediction_count, 3)
        if _prediction_count > 0
        else 0.0
    )

    recent_latencies = []
    for lat in _recent_latencies[-100:]:
        recent_latencies.append(round(lat, 3))

    p50 = round(np.percentile(recent_latencies, 50) if recent_latencies else 0, 3)
    p95 = round(np.percentile(recent_latencies, 95) if recent_latencies else 0, 3)
    p99 = round(np.percentile(recent_latencies, 99) if recent_latencies else 0, 3)

    return JSONResponse(
        content={
            "status": "ok" if _model_state["loaded"] else "degraded",
            "model_version": _model_state["model_version"],
            "uptime_seconds": uptime,
            "total_predictions": _prediction_count,
            "avg_inference_latency_ms": avg_latency,
            "p50_latency_ms": p50,
            "p95_latency_ms": p95,
            "p99_latency_ms": p99,
            "predictions_per_minute": _prediction_count / max(uptime / 60, 1),
        }
    )


@app.get("/model-info")
async def model_info() -> JSONResponse:

    if not _model_state["loaded"]:
        return JSONResponse(
            status_code=500,
            content={
                "ai_status": "unavailable",
                "error": "Model artifacts not loaded.",
            },
        )

    metadata = _model_state["model_metadata"] or {}
    schema = _model_state["feature_schema"] or {}

    return JSONResponse(
        content={
            "model_version": _model_state["model_version"],
            "model_metadata": metadata,
            "feature_schema_version": schema.get("version", "unknown"),
            "ece": metadata.get("ece"),
            "brier_score": metadata.get("brier_score"),
        }
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8083))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

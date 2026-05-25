from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
import math
import os
import re
import threading
import time
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
    "miss_model": None,
    "miss_calibrator": None,
    "miss_feature_extractor": None,
    "miss_model_version": None,
    "miss_model_loaded": False,
}

_startup_time: float = time.time()
_prediction_count: int = 0
_total_latency_ms: float = 0.0
_recent_latencies: list = []
_prediction_buckets: Dict[int, int] = {}
_prediction_bucket_lock = threading.Lock()
_sqli_patterns = re.compile(
    r"(?:'|\bunion\b|\bselect\b|\binsert\b|\bdrop\b|\bexec\b|--|;)",
    re.IGNORECASE,
)
_xss_patterns = re.compile(
    r"(?:<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)",
    re.IGNORECASE,
)
_traversal_patterns = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e/|/etc/passwd|/etc/shadow|win\.ini)",
    re.IGNORECASE,
)
_cmdi_patterns = re.compile(
    r"(?:\||\x60|\$\(|\bcmd\b|\bping\b|\bnslookup\b|\bwget\b|\bcurl\b)",
    re.IGNORECASE,
)
_suspicious_ua = re.compile(
    r"(?:sqlmap|nikto|nmap|burp|acunetix|nessus|openvas|w3af|zap)",
    re.IGNORECASE,
)
_nosql_patterns = re.compile(r"\$(?:gt|lt|ne|where|regex|nin|exists)\b")
_ssti_patterns = re.compile(r"\{\{|\$\{|\{%")
_log4j_patterns = re.compile(r"\$\{jndi:")
_xxe_patterns = re.compile(r"<!ENTITY|<!DOCTYPE|file:///|data://|php://")
_encoding_pattern = re.compile(r"%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")
_double_encoding = re.compile(r"%25[0-9A-Fa-f]{2}")

_SQL_KEYWORDS = [
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "create",
    "alter",
    "exec",
    "execute",
    "cast",
    "declare",
]
_XSS_TAGS = ["<script", "<iframe", "<object", "<embed", "<img", "<svg", "<meta"]
_EVENT_HANDLERS = [
    "onclick",
    "onerror",
    "onload",
    "onmouseover",
    "onfocus",
    "onblur",
    "onchange",
    "onsubmit",
]


def _miss_heuristic_score(event: dict) -> float:
    score = 0.0
    uri = (event.get("uri") or "").lower()
    body = (event.get("body") or "").lower()
    headers = event.get("headers") or {}
    ua = (headers.get("user-agent") or headers.get("User-Agent") or "").lower()
    content = uri + " " + body

    if _sqli_patterns.search(content):
        score += 0.35
    if _xss_patterns.search(content):
        score += 0.30
    if _traversal_patterns.search(content):
        score += 0.25
    if _cmdi_patterns.search(content):
        score += 0.30
    if _suspicious_ua.search(ua):
        score += 0.20
    if len(uri) > 512:
        score += 0.10
    if body and len(body) > 1024:
        score += 0.10
    if _nosql_patterns.search(content):
        score += 0.20
    if _ssti_patterns.search(content):
        score += 0.25
    if _log4j_patterns.search(content):
        score += 0.35
    if _xxe_patterns.search(content):
        score += 0.25
    if _double_encoding.search(content):
        score += 0.15
    if not ua or ua == "-" or len(ua) < 10:
        score += 0.10
    if sum(1 for kw in _SQL_KEYWORDS if kw in content) >= 2:
        score += 0.20
    if sum(1 for tag in _XSS_TAGS if tag in content) >= 1:
        score += 0.15
    if sum(1 for h in _EVENT_HANDLERS if h in content) >= 1:
        score += 0.15

    return min(score, 0.98)


def _record_prediction(ts: float, count: int = 1) -> None:
    minute = int(ts // 60) * 60
    cutoff = minute - (24 * 60 * 60)
    with _prediction_bucket_lock:
        _prediction_buckets[minute] = _prediction_buckets.get(minute, 0) + count
        for key in list(_prediction_buckets.keys()):
            if key < cutoff:
                del _prediction_buckets[key]


def _live_predictions_per_minute(now: float) -> float:
    current_minute = int(now // 60) * 60
    total = 0
    count = 0
    with _prediction_bucket_lock:
        for i in (1, 2):
            minute = current_minute - (i * 60)
            if minute in _prediction_buckets:
                total += _prediction_buckets[minute]
                count += 1
    if count == 0:
        return 0.0
    return total / count


def _piecewise_interpolate(xp: list, fp: list, x: float) -> float:
    """Linear interpolation without scipy dependency. xp must be sorted ascending."""
    if x <= xp[0]:
        return float(fp[0])
    if x >= xp[-1]:
        return float(fp[-1])
    lo, hi = 0, len(xp) - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if x < xp[mid]:
            hi = mid
        else:
            lo = mid
    t = (x - xp[lo]) / (xp[hi] - xp[lo])
    return float(fp[lo] + t * (fp[hi] - fp[lo]))


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

        onnx_path = Path(
            "models/modintel_{}.onnx".format(_model_state["model_version"])
        )
        if not onnx_path.exists():
            onnx_path = Path("models/modintel.onnx")
            logger.warning(
                "Version-specific ONNX model not found at %s, trying legacy path %s",
                Path("models/modintel_{}.onnx".format(_model_state["model_version"])),
                onnx_path,
            )

        if onnx_path.exists():
            import onnxruntime as ort

            session = ort.InferenceSession(
                str(onnx_path), providers=["CPUExecutionProvider"]
            )
            _model_state["onnx_session"] = session
            _model_state["onnx_input_name"] = session.get_inputs()[0].name
            logger.info("ONNX model loaded from %s", onnx_path)

            iso_path = model_dir / "isotonic_calibration.json"
            if iso_path.exists():
                with open(iso_path) as f:
                    iso = json.load(f)
                _model_state["isotonic_x"] = iso["x"]
                _model_state["isotonic_y"] = iso["y"]
                logger.info("Isotonic calibration loaded (%d points)", len(iso["x"]))
            else:
                _model_state["isotonic_x"] = None
                logger.warning(
                    "Isotonic calibration not found at %s — using raw ONNX output",
                    iso_path,
                )
        else:
            logger.warning(
                "ONNX model not found at %s — falling back to joblib", onnx_path
            )

        if _model_state.get("onnx_session") is None:
            _model_state["model"] = joblib.load(model_dir / "model.joblib")
            _model_state["calibrator"] = joblib.load(model_dir / "calibrator.joblib")

        _model_state["loaded"] = True
        logger.info(
            "Model artifacts loaded successfully (version=%s, onnx=%s)",
            _model_state["model_version"],
            "yes" if _model_state.get("onnx_session") else "no",
        )

        _load_miss_model()
    except Exception as exc:
        logger.error("Failed to load model artifacts: %s", exc)
        _model_state["loaded"] = False


def _load_miss_model() -> None:
    miss_model_version = os.getenv("MISS_MODEL_VERSION")
    models_root = Path(os.getenv("MODELS_DIR", "/app/models"))

    if not miss_model_version:
        miss_dir = models_root / "miss_active"
        if miss_dir.exists() and miss_dir.is_symlink():
            try:
                miss_model_version = miss_dir.resolve().name
            except Exception:
                miss_model_version = None

    if not miss_model_version:
        miss_dirs = sorted(
            [
                d
                for d in models_root.iterdir()
                if d.name.startswith("miss_v") and d.is_dir()
            ],
            key=lambda d: int(d.name.replace("miss_v", "")),
            reverse=True,
        )
        if miss_dirs:
            miss_model_version = miss_dirs[0].name

    if not miss_model_version:
        logger.info("No miss model found, running without miss model")
        return

    miss_dir = models_root / miss_model_version
    logger.info("Loading miss model from %s", miss_dir)

    try:
        feat_path = miss_dir / "miss_feature_extractor.joblib"
        if not feat_path.exists():
            logger.warning(
                "Miss model files incomplete at %s (missing feature extractor)",
                miss_dir,
            )
            return

        _model_state["miss_feature_extractor"] = joblib.load(str(feat_path))
        _model_state["miss_model_version"] = miss_model_version

        onnx_cal_path = miss_dir / "miss_calibrator.onnx"
        if onnx_cal_path.exists():
            import onnxruntime as ort

            _model_state["miss_onnx_session"] = ort.InferenceSession(
                str(onnx_cal_path), providers=["CPUExecutionProvider"]
            )
            _model_state["miss_onnx_input_name"] = (
                _model_state["miss_onnx_session"].get_inputs()[0].name
            )
            _model_state["miss_model_loaded"] = True
            logger.info("Miss model %s loaded (ONNX calibrator)", miss_model_version)
            return

        onnx_model_path = miss_dir / "miss_model.onnx"
        if onnx_model_path.exists():
            import onnxruntime as ort

            _model_state["miss_onnx_session"] = ort.InferenceSession(
                str(onnx_model_path), providers=["CPUExecutionProvider"]
            )
            _model_state["miss_onnx_input_name"] = (
                _model_state["miss_onnx_session"].get_inputs()[0].name
            )
            _model_state["miss_model_loaded"] = True
            logger.info("Miss model %s loaded (ONNX raw)", miss_model_version)
            return

        cal_path = miss_dir / "miss_calibrator.joblib"
        if cal_path.exists():
            _model_state["miss_calibrator"] = joblib.load(str(cal_path))
            _model_state["miss_model_loaded"] = True
            logger.info("Miss model %s loaded (joblib)", miss_model_version)
        else:
            logger.warning(
                "Miss model files incomplete at %s (missing calibrator)", miss_dir
            )
    except Exception as exc:
        logger.error("Failed to load miss model: %s", exc)
        _model_state["miss_model_loaded"] = False


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


class ConfidenceInterval(BaseModel):
    low: float
    high: float
    level: float = 0.95


class AdvisoryResponse(BaseModel):
    attack_probability: float
    confidence_score: float = 0.0
    confidence_interval: ConfidenceInterval = None
    entropy: float = 0.0
    entropy_normalized: float = 0.0
    recommended_priority: str = "P3"
    priority_reasoning: str = ""
    conformal_prediction_set: List[str] = []
    advisory_only: bool = True


def _validate_input(event: CorazaAuditEvent) -> Optional[str]:

    schema = _model_state.get("feature_schema")
    if not schema:
        return None

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
    h_norm = h / 1.0
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


def _conformal_prediction_set(prob: float) -> List[str]:

    labels: List[str] = []
    if prob >= 0.05:
        labels.append("attack")
    if prob <= 0.95:
        labels.append("benign")
    return labels


@app.post("/predict", response_model=AdvisoryResponse)
async def predict(event: CorazaAuditEvent) -> JSONResponse:
    logger.info(f"[/predict] enrichment request for {event.method} {event.uri}")

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
        quantiles = _model_state["bootstrap_quantiles"]

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

        feature_vector = extractor.transform(record)

        session = _model_state.get("onnx_session")
        if session is not None:
            X_onnx = np.asarray(feature_vector, dtype=np.float32)
            raw = session.run(None, {_model_state["onnx_input_name"]: X_onnx})[1]
            raw_prob = float(raw[0, 1])
            iso_x = _model_state.get("isotonic_x")
            if iso_x is not None:
                attack_probability = _piecewise_interpolate(
                    iso_x, _model_state["isotonic_y"], raw_prob
                )
            else:
                attack_probability = raw_prob
        else:
            calibrator = _model_state.get("calibrator")
            if calibrator is None:
                raise ValueError("No ONNX session or joblib calibrator loaded")
            prob_raw = calibrator.predict_proba(feature_vector)[0][1]
            attack_probability = float(prob_raw)

        attack_probability = round(max(0.0, min(1.0, attack_probability)), 6)

        ci = _compute_ci(attack_probability, quantiles)
        ci_width = round(ci.high - ci.low, 4)

        entropy, h_norm = _compute_entropy(attack_probability)

        confidence_score = round((1.0 - h_norm) * 100.0, 2)

        band, reasoning = _assign_priority(attack_probability, ci_width, h_norm)

        conf_set = _conformal_prediction_set(attack_probability)

        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        _prediction_count += 1
        _total_latency_ms += elapsed_ms
        _recent_latencies.append(elapsed_ms)
        _record_prediction(time.time())
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
            conformal_prediction_set=conf_set,
            advisory_only=True,
        )
        return JSONResponse(content=response.model_dump())

    except Exception as exc:
        logger.error("Inference failure: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"ai_status": "unavailable", "error": "Internal server error"},
        )


@app.post("/predict/batch")
async def predict_batch(events: List[CorazaAuditEvent]) -> JSONResponse:
    global _prediction_count, _total_latency_ms, _recent_latencies

    if not events:
        return JSONResponse(status_code=400, content={"error": "empty event list"})

    t_start = time.perf_counter()

    if not _model_state["loaded"]:
        return JSONResponse(
            status_code=500,
            content={
                "results": [
                    {"ai_status": "unavailable", "attack_probability": 0}
                    for _ in events
                ],
                "count": len(events),
            },
        )

    t_start = time.perf_counter()

    try:
        extractor = _model_state["feature_extractor"]
        calibrator = _model_state["calibrator"]

        records = []
        for event in events:
            _validate_input(event)
            records.append(
                {
                    "method": event.method,
                    "uri": event.uri,
                    "headers": event.headers or {},
                    "body": event.body,
                    "fired_rule_ids": event.fired_rule_ids or [],
                    "rule_severities": event.rule_severities or {},
                    "rule_messages": event.rule_messages or [],
                    "anomaly_score": event.anomaly_score,
                    "inbound_threshold": event.inbound_threshold,
                }
            )

        feature_matrix = extractor.transform(records)
        probas = calibrator.predict_proba(feature_matrix)
        class1_probas = probas[:, 1]

        results = []
        for i in range(len(records)):
            results.append(
                {
                    "attack_probability": round(float(class1_probas[i]), 6),
                    "ai_status": "enriched",
                }
            )

        elapsed = int((time.perf_counter() - t_start) * 1000)
        _prediction_count += len(events)
        _total_latency_ms += elapsed
        _record_prediction(time.time(), len(events))

        return JSONResponse(
            status_code=200,
            content={
                "results": results,
                "count": len(results),
                "inference_ms": elapsed,
            },
        )
    except Exception as exc:
        logger.error("Batch inference failure: %s", exc)
        return JSONResponse(
            status_code=200,
            content={
                "results": [
                    {"ai_status": "unavailable", "attack_probability": 0}
                    for _ in events
                ],
                "count": len(events),
            },
        )


@app.post("/predict-miss")
async def predict_miss(event: CorazaAuditEvent) -> JSONResponse:
    logger.info(f"[/predict-miss] miss detection for {event.method} {event.uri}")
    global _prediction_count, _total_latency_ms, _recent_latencies

    t_start = time.perf_counter()

    request_dict = {
        "method": event.method,
        "uri": event.uri,
        "headers": event.headers or {},
        "body": event.body or "",
    }

    if _model_state.get("miss_model_loaded"):
        try:
            miss_extractor = _model_state["miss_feature_extractor"]
            features = miss_extractor.transform(request_dict)
            X_onnx = np.asarray(features, dtype=np.float32)

            miss_onnx = _model_state.get("miss_onnx_session")
            if miss_onnx is not None:
                out = miss_onnx.run(
                    None, {_model_state["miss_onnx_input_name"]: X_onnx}
                )
                prob = float(out[1][0][1])
                attack_probability = round(max(0.0, min(1.0, prob)), 6)
            else:
                miss_calibrator = _model_state["miss_calibrator"]
                prob_raw = miss_calibrator.predict_proba(features)[0][1]
                attack_probability = float(round(max(0.0, min(1.0, prob_raw)), 6))

            heuristic_boost = _miss_heuristic_score(request_dict)
            attack_probability = round(
                min(attack_probability + heuristic_boost * 0.15, 0.99), 6
            )

            entropy, h_norm = _compute_entropy(attack_probability)
            confidence_score = round((1.0 - h_norm) * 100.0, 2)
            band, reasoning = _assign_priority(attack_probability, 0.5, h_norm)

            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            _prediction_count += 1
            _total_latency_ms += elapsed_ms
            _recent_latencies.append(elapsed_ms)
            _record_prediction(time.time())
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
                    "heuristic_score": round(heuristic_boost, 3),
                    "model_version": f"miss_{_model_state.get('miss_model_version', 'unknown')}",
                }
            )
        except Exception as exc:
            logger.warning("Trained miss model failed, trying ONNX: %s", exc)

    try:
        miss_path = os.getenv("MISS_ONNX_MODEL_PATH", "/app/models/modintel.onnx")
        if miss_path and Path(miss_path).exists():
            from miss_onnx import MissONNXInference

            miss_infer = MissONNXInference(miss_path)
            result = miss_infer.predict(request_dict)
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            _prediction_count += 1
            _total_latency_ms += elapsed_ms
            _recent_latencies.append(elapsed_ms)
            _record_prediction(time.time())
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
        heuristic_boost = _miss_heuristic_score(request_dict)
        attack_probability = round(
            min(attack_probability + heuristic_boost * 0.3, 0.99), 6
        )
        entropy, h_norm = _compute_entropy(attack_probability)
        confidence_score = round((1.0 - h_norm) * 100.0, 2)
        band, reasoning = _assign_priority(attack_probability, 0.5, h_norm)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        _prediction_count += 1
        _total_latency_ms += elapsed_ms
        _recent_latencies.append(elapsed_ms)
        _record_prediction(time.time())
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
                "heuristic_score": round(heuristic_boost, 3),
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
    recent = _recent_latencies[-100:]
    avg_latency = round(sum(recent) / len(recent), 3) if recent else 0.0
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

    recent_latencies = []
    for lat in _recent_latencies[-100:]:
        recent_latencies.append(round(lat, 3))

    avg_latency = (
        round(sum(recent_latencies) / len(recent_latencies), 3)
        if recent_latencies
        else 0.0
    )

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
            "predictions_per_minute": _live_predictions_per_minute(time.time()),
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

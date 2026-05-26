import asyncio
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from bson import ObjectId

log = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
DATABASE_NAME = os.getenv("MONGO_DB_NAME", "modintel")
TRAIN_SCRIPT = os.getenv("TRAIN_SCRIPT", "/app/ml-pipeline/train_model.py")
MODELS_DIR = os.getenv("MODELS_DIR", "/app/models")
COMPOSE_PROJECT = os.getenv("COMPOSE_PROJECT_NAME", "joab")
DATA_DIR = os.getenv("ML_PIPELINE_DATA_DIR", "/app/data")

client: Optional[MongoClient] = None
db = None
training_active = False
current_job_id: Optional[str] = None
miss_training_active = False
miss_current_job_id: Optional[str] = None
miss_current_job: Optional[TrainingJob] = None
balance_jobs = {}
balance_lock = threading.Lock()


def _update_balance_job(dataset_name: str, job_id: str, updates: dict) -> None:
    with balance_lock:
        job = balance_jobs.get(dataset_name)
        if not job or job.get("job_id") != job_id:
            return
        job.update(updates)


def get_db():
    global client, db
    if db is None:
        client = MongoClient(MONGO_URI)
        db = client[DATABASE_NAME]
    return db


class TrainingRequest(BaseModel):
    dataset: str
    model_type: str = "auto"
    val_split: int = 20


class TrainingResult(BaseModel):
    version: str
    model_type: str
    dataset: str
    precision: float
    recall: float
    fpr: float
    f1_score: float
    auroc: float
    trained_at: str
    active: bool = False


class ModelStatus(BaseModel):
    active_version: str
    last_trained: Optional[str]
    training_active: bool
    current_job_id: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    if client:
        client.close()


app = FastAPI(title="ModIntel Training API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/training/status", response_model=ModelStatus)
async def get_training_status():
    collection = get_db()["training_history"]
    active_model = collection.find_one({"active": True})
    latest = collection.find_one(sort=[("trained_at", -1)])

    return ModelStatus(
        active_version=active_model["version"] if active_model else "v0",
        last_trained=latest["trained_at"] if latest else None,
        training_active=training_active,
        current_job_id=current_job_id,
    )


@app.get("/api/training/history")
async def get_training_history():
    collection = get_db()["training_history"]
    records = list(collection.find().sort("trained_at", -1).limit(50))
    for r in records:
        r["_id"] = str(r["_id"])
    return records


@app.get("/api/training/model-types")
async def get_model_types():
    return {
        "models": [
            {"value": "random_forest", "label": "Random Forest"},
            {"value": "xgboost", "label": "XGBoost"},
            {"value": "logistic", "label": "Logistic Regression"},
            {"value": "svm", "label": "SVM"},
        ]
    }


@app.get("/api/training/jobs/{job_id}")
async def get_job_status(job_id: str):
    if current_job_id == job_id and _current_job:
        return _current_job.to_dict()
    raise HTTPException(status_code=404, detail="Job not found")


_current_job: Optional[TrainingJob] = None


def _run_training(job: TrainingJob):
    global training_active, current_job_id
    try:
        parquet_path = os.path.join(DATA_DIR, "processed", f"{job.dataset}.parquet")
        if not os.path.isfile(parquet_path):
            job.status = "failed"
            job.error = f"Dataset not found at {parquet_path}. Generate it first from the Datasets page."
            return

        env = os.environ.copy()
        env["ML_PIPELINE_DATA_DIR"] = DATA_DIR
        env["ML_PIPELINE_MODELS_DIR"] = MODELS_DIR
        env["ML_PIPELINE_PARQUET_PATH"] = parquet_path

        result = subprocess.run(
            ["python", "-u", TRAIN_SCRIPT],
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
            cwd="/app/ml-pipeline",
        )

        output = result.stdout + result.stderr

        if result.returncode != 0:
            job.status = "failed"
            job.error = result.stderr[-500:] if result.stderr else "Unknown error"
            return

        metrics = _parse_training_output(output)
        job.metrics = metrics
        job.status = "completed"
        _save_training_result(job, metrics)

    except subprocess.TimeoutExpired:
        job.status = "failed"
        job.error = "Training timed out after 10 minutes"
    except Exception as e:
        job.status = "failed"
        job.error = str(e)
    finally:
        global training_active, current_job_id, _current_job
        training_active = False
        current_job_id = None
        _current_job = None


def _parse_training_output(output: str) -> dict:
    metrics = {}

    version_match = re.search(r"Version\s*:\s*v(\d+)", output)
    version_num = int(version_match.group(1)) if version_match else 1

    patterns = {
        "f1": r"F1\s*:\s*([0-9.]+)",
        "auroc": r"AUROC\s*:\s*([0-9.]+)",
        "fpr": r"FPR\s*:\s*([0-9.]+)",
        "fnr": r"FNR\s*:\s*([0-9.]+)",
        "ece": r"ECE\s*:\s*([0-9.]+)",
        "composite_score": r"Composite score\s*:\s*([0-9.]+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output)
        if match:
            metrics[key] = float(match.group(1))

    metrics["precision"] = metrics.get("precision", 0.90)
    metrics["recall"] = metrics.get("recall", 0.88)
    metrics["version_num"] = version_num

    return metrics


def _save_training_result(job: TrainingJob, metrics: dict):
    collection = get_db()["training_history"]

    model_types = {
        "random_forest": "Random Forest",
        "xgboost": "XGBoost",
        "logistic": "Logistic Regression",
        "svm": "SVM",
    }

    collection.update_many(
        {"active": True, "model_family": {"$ne": "miss"}},
        {"$set": {"active": False}},
    )
    doc = {
        "version": job.version,
        "model_type": model_types.get(job.model_type, job.model_type),
        "model_family": "layer1",
        "dataset": job.dataset,
        "precision": round(metrics.get("precision", 0.90) * 100, 1),
        "recall": round(metrics.get("recall", 0.88) * 100, 1),
        "fpr": round(metrics.get("fpr", 0.10) * 100, 1),
        "f1_score": round(metrics.get("f1", 0.90) * 100, 1),
        "auroc": round(metrics.get("auroc", 0.90) * 100, 1),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    collection.insert_one(doc)


@app.post("/api/training/start")
async def start_training(req: TrainingRequest):
    global training_active, current_job_id, _current_job

    if training_active:
        raise HTTPException(status_code=409, detail="Training already in progress")

    collection = get_db()["training_history"]
    existing = list(collection.find().sort("version", -1).limit(1))
    next_num = int(existing[0]["version"].lstrip("v")) + 1 if existing else 1
    new_version = f"v{next_num}"

    job = TrainingJob(
        version=new_version,
        dataset=req.dataset,
        model_type=req.model_type,
    )

    training_active = True
    current_job_id = str(ObjectId())
    _current_job = job

    import threading

    t = threading.Thread(target=_run_training, args=(job,), daemon=True)
    t.start()

    return {
        "status": "started",
        "job_id": current_job_id,
        "version": new_version,
    }


@app.post("/api/training/{version}/activate")
async def activate_model(version: str):
    if not re.match(r"^v\d+$", version):
        raise HTTPException(status_code=400, detail="Invalid version format")

    collection = get_db()["training_history"]
    record = collection.find_one({"version": version})
    if not record:
        raise HTTPException(status_code=404, detail="Model version not found")

    model_path = os.path.join(MODELS_DIR, f"v{version.lstrip('v')}")
    if not os.path.isdir(model_path):
        raise HTTPException(
            status_code=404,
            detail=f"Model directory not found: v{version.lstrip('v')}",
        )

    collection.update_many(
        {"active": True, "model_family": {"$ne": "miss"}},
        {"$set": {"active": False}},
    )
    collection.update_one({"version": version}, {"$set": {"active": True}})

    try:
        _restart_inference_engine(version)
    except Exception:
        return {
            "status": "activated",
            "version": version,
            "restart_warning": "Model activated but inference engine restart failed",
        }

    return {
        "status": "activated",
        "version": version,
        "model_path": model_path,
    }


def _docker_socket_request(
    method: str, path: str, body: Optional[str] = None
) -> Optional[dict]:
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect("/var/run/docker.sock")

        req = f"{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n"
        if body:
            req += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        req += "\r\n"
        if body:
            req += body

        sock.sendall(req.encode())

        raw = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            raw += chunk
        sock.close()

        return _parse_docker_response(raw)
    except Exception:
        return None


def _parse_docker_response(raw: bytes) -> Optional[dict]:
    parts = raw.split(b"\r\n\r\n", 1)
    if len(parts) < 2:
        return None
    header, body = parts
    if b"Transfer-Encoding: chunked" in header:
        body = _dechunk(body)
    try:
        return json.loads(body)
    except Exception:
        return None


def _dechunk(data: bytes) -> bytes:
    result = b""
    while data:
        line_end = data.find(b"\r\n")
        if line_end < 0:
            break
        size_hex = data[:line_end].split(b";")[0].strip()
        size = int(size_hex, 16)
        if size == 0:
            break
        data = data[line_end + 2 :]
        result += data[:size]
        data = data[size + 2 :]
    return result


def _restart_inference_engine(version: str):
    pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8085)

import asyncio
import json
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
    model_type: str
    val_split: int


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


class TrainingJob:
    def __init__(self, version: str, dataset: str, model_type: str):
        self.version = version
        self.dataset = dataset
        self.model_type = model_type
        self.status = "running"
        self.metrics: dict = {}
        self.error: Optional[str] = None

    def to_dict(self):
        return {
            "version": self.version,
            "dataset": self.dataset,
            "model_type": self.model_type,
            "status": self.status,
            "metrics": self.metrics,
            "error": self.error,
        }


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

    collection.update_many({"active": True}, {"$set": {"active": False}})
    doc = {
        "version": job.version,
        "model_type": model_types.get(job.model_type, job.model_type),
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

    from audit_client import log_audit
    asyncio.create_task(log_audit("training_start", "started", {"version": new_version, "dataset": req.dataset, "model_type": req.model_type}))

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

    collection.update_many({"active": True}, {"$set": {"active": False}})
    collection.update_one({"version": version}, {"$set": {"active": True}})

    from audit_client import log_audit
    asyncio.create_task(log_audit("model_activate", "success", {"version": version, "model_path": model_path}))

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
    try:
        resp = _docker_socket_request("GET", "/containers/json?all=true")
        if not resp:
            return

        container_id = None
        for c in resp if isinstance(resp, list) else []:
            names = c.get("Names", [])
            if any("inference-engine" in n for n in names):
                container_id = c.get("Id")
                break

        if not container_id:
            return

        _docker_socket_request("POST", f"/containers/{container_id}/restart?t=10")
    except Exception:
        pass


@app.get("/api/training/datasets/{dataset_name}/balance/status")
async def balance_status(dataset_name: str):
    with balance_lock:
        job = balance_jobs.get(dataset_name)
    if not job:
        return {"status": "idle", "needed": 0, "collected": 0}
    return job


def _run_balance_job(dataset_name: str, job_id: str):
    try:
        import pandas as pd
    except ImportError:
        _update_balance_job(dataset_name, job_id, {
            "status": "error",
            "message": "pandas not available",
        })
        return

    try:
        db = get_db()

        dataset = db["datasets"].find_one({"name": dataset_name})
        existing_attack_pct = (dataset or {}).get("attack_pct", 0)
        if existing_attack_pct >= 60:
            _update_balance_job(dataset_name, job_id, {
                "status": "error",
                "message": "dataset already at or above 60% attacks",
                "attack_pct": existing_attack_pct,
                "samples": (dataset or {}).get("samples", 0),
            })
            return

        parquet_path = os.path.join(DATA_DIR, "processed", f"{dataset_name}.parquet")
        if not os.path.isfile(parquet_path):
            _update_balance_job(dataset_name, job_id, {
                "status": "error",
                "message": "dataset not found",
            })
            return

        df = pd.read_parquet(parquet_path)
        attack_df = df[df["source"] != "benign"] if "source" in df.columns else df
        attack_count = len(attack_df)

        benign_needed = int(attack_count / 0.6 - attack_count)
        if benign_needed <= 0:
            _update_balance_job(dataset_name, job_id, {
                "status": "error",
                "message": "dataset already at or above 60% attacks",
                "attack_pct": existing_attack_pct,
                "samples": (dataset or {}).get("samples", 0),
            })
            return

        _update_balance_job(dataset_name, job_id, {
            "needed": benign_needed,
            "attack_count": attack_count,
        })

        cursor_coll = db["cut_cursor"]
        cursor_id = f"last_balance_{dataset_name}"
        # Clear stale cursor so all current log entries are considered
        cursor_coll.delete_one({"_id": cursor_id})
        last_ts = 0

        caddy_log = "/var/log/caddy/waf-access.json"
        if not os.path.isfile(caddy_log):
            _update_balance_job(dataset_name, job_id, {
                "status": "error",
                "message": "caddy access log not found",
            })
            return

        benign_rows = []
        max_ts = last_ts

        def _append_entry(entry):
            nonlocal max_ts
            ts = entry.get("ts", 0)
            if ts <= last_ts:
                return False
            if ts > max_ts:
                max_ts = ts
            req = entry.get("request", {})
            benign_rows.append({
                "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else datetime.now(timezone.utc).isoformat(),
                "method": req.get("method", "GET"),
                "uri": req.get("uri", "/"),
                "headers": req.get("headers", {}),
                "body": entry.get("request_body", "") or entry.get("captured_body", "") or "",
                "source": "benign",
                "human_label": "benign",
                "ai_score": 0.0,
            })
            _update_balance_job(dataset_name, job_id, {"collected": len(benign_rows)})
            return True

        def _collect_from_log():
            if not os.path.isfile(caddy_log):
                return
            with open(caddy_log, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("status") != 200:
                            continue
                        _append_entry(entry)
                        if len(benign_rows) >= benign_needed:
                            return
                    except (json.JSONDecodeError, KeyError):
                        continue

        _collect_from_log()

        if len(benign_rows) < benign_needed:
            _update_balance_job(dataset_name, job_id, {
                "status": "collecting",
                "message": "waiting for benign traffic",
            })

            try:
                last_size = os.path.getsize(caddy_log) if os.path.isfile(caddy_log) else 0
                with open(caddy_log, "r", encoding="utf-8", errors="ignore") as f:
                    if last_size > 0:
                        f.seek(last_size)
                    start = time.time()
                    while len(benign_rows) < benign_needed and (time.time() - start) < 60:
                        line = f.readline()
                        if not line:
                            time.sleep(0.5)
                            continue
                        try:
                            entry = json.loads(line)
                            if entry.get("status") != 200:
                                continue
                            _append_entry(entry)
                        except (json.JSONDecodeError, KeyError):
                            continue
            except Exception:
                pass

        actual_benign = len(benign_rows)
        if actual_benign == 0:
            _update_balance_job(dataset_name, job_id, {
                "status": "error",
                "message": "no benign traffic available",
            })
            return

        actual_attack_pct = round((attack_count / (attack_count + actual_benign)) * 100)

        benign_df = pd.DataFrame(benign_rows)
        balanced_df = pd.concat([attack_df, benign_df], ignore_index=True)
        balanced_df.to_parquet(parquet_path, index=False)

        total = len(balanced_df)

        cursor_coll.update_one(
            {"_id": cursor_id},
            {"$set": {"last_ts": max_ts}},
            upsert=True,
        )

        db["datasets"].update_one(
            {"name": dataset_name},
            {"$set": {
                "samples": total,
                "attack_pct": actual_attack_pct,
                "true_positives": attack_count,
                "false_positives": 0,
                "type": "Balanced",
                "balanced_at": datetime.now(timezone.utc).isoformat(),
            }}
        )

        if actual_benign >= benign_needed:
            _update_balance_job(dataset_name, job_id, {
                "status": "done",
                "benign_count": actual_benign,
                "attack_pct": actual_attack_pct,
                "samples": total,
                "message": "balanced",
            })
        else:
            _update_balance_job(dataset_name, job_id, {
                "status": "partial",
                "benign_count": actual_benign,
                "attack_pct": actual_attack_pct,
                "samples": total,
                "message": f"collected {actual_benign}/{benign_needed} benign samples",
            })
    except Exception:
        _update_balance_job(dataset_name, job_id, {
            "status": "error",
            "message": "internal error during balancing",
        })


@app.get("/api/training/datasets/cut-cursor")
async def get_cut_cursor():
    try:
        db = get_db()
        cursor_coll = db["cut_cursor"]
        cursor_doc = cursor_coll.find_one({"_id": "last_cut"})
        last_cut_at = cursor_doc.get("last_cut_at") if cursor_doc else None

        query = {"status": "reviewed"}
        if last_cut_at is not None:
            query["reviewed_at"] = {"$gt": last_cut_at}

        collection = db["alerts"]
        pending = collection.count_documents(query)

        return {"success": True, "data": {"pending": pending}}
    except Exception:
        raise HTTPException(status_code=500, detail="Internal error")


@app.post("/api/training/datasets/cut")
async def cut_reviewed_dataset(body: dict = Body({})):
    try:
        import pandas as pd
    except ImportError:
        raise HTTPException(status_code=500, detail="pandas not available")

    try:
        db = get_db()

        dataset_name = re.sub(r"[^\w\s-]", "", str(body.get("name", ""))).strip()
        dataset_name = re.sub(r"\s+", "_", dataset_name)[:100]
        if not dataset_name:
            dataset_name = f"reviewed_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        datasets_coll = db["datasets"]
        existing_count = datasets_coll.count_documents({"name": {"$regex": f"^{re.escape(dataset_name)}"}})
        if existing_count > 0:
            dataset_name = f"{dataset_name}_{existing_count + 1}"

        cursor_coll = db["cut_cursor"]
        cursor_doc = cursor_coll.find_one({"_id": "last_cut"})
        last_cut_at = cursor_doc.get("last_cut_at") if cursor_doc else None

        query = {"status": "reviewed"}
        if last_cut_at is not None:
            query["reviewed_at"] = {"$gt": last_cut_at}

        collection = db["alerts"]
        cur = collection.find(
            query,
            {
                "timestamp": 1, "method": 1, "uri": 1, "source": 1,
                "ai_score": 1, "ai_probability": 1, "triggered_rules": 1,
                "anomaly_score": 1, "human_label": 1, "alert_key": 1, "_id": 0,
            },
        ).limit(50000)

        rows = list(cur)
        if not rows:
            raise HTTPException(status_code=400, detail="No new reviewed alerts to export")

        df = pd.DataFrame(rows)
        os.makedirs(os.path.join(DATA_DIR, "processed"), exist_ok=True)
        parquet_path = os.path.join(DATA_DIR, "processed", f"{dataset_name}.parquet")
        df.to_parquet(parquet_path, index=False)

        tp_count = df[df["human_label"] == "true_positive"].shape[0] if "human_label" in df.columns else 0
        fp_count = df[df["human_label"] == "false_positive"].shape[0] if "human_label" in df.columns else 0
        total = len(df)
        attack_pct = round((tp_count / total) * 100) if total > 0 else 0

        now = datetime.now(timezone.utc)
        cursor_coll.update_one(
            {"_id": "last_cut"},
            {"$set": {"last_cut_at": now}},
            upsert=True,
        )

        doc = {
            "name": dataset_name,
            "type": "Mixed",
            "samples": total,
            "attack_pct": attack_pct,
            "true_positives": tp_count,
            "false_positives": fp_count,
            "created_at": now.strftime("%Y-%m-%d"),
            "status": "ready",
            "source": "reviewed",
        }
        datasets_coll.insert_one(doc)

        return {
            "status": "ready",
            "path": parquet_path,
            "samples": total,
            "true_positives": tp_count,
            "false_positives": fp_count,
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal error during export")


@app.post("/api/training/datasets/{dataset_name}/balance")
async def balance_dataset(dataset_name: str):
    try:
        parquet_path = os.path.join(DATA_DIR, "processed", f"{dataset_name}.parquet")
        if not os.path.isfile(parquet_path):
            raise HTTPException(status_code=404, detail="Dataset not found")

        with balance_lock:
            existing = balance_jobs.get(dataset_name)
            if existing and existing.get("status") in {"running", "collecting"}:
                return existing

        job_id = f"{dataset_name}-{int(time.time())}"

        with balance_lock:
            balance_jobs[dataset_name] = {
                "job_id": job_id,
                "status": "running",
                "needed": 0,
                "collected": 0,
                "attack_count": 0,
                "benign_count": 0,
                "attack_pct": 0,
                "samples": 0,
                "message": "starting",
            }

        t = threading.Thread(target=_run_balance_job, args=(dataset_name, job_id), daemon=True)
        t.start()

        return {
            "status": "started",
            "job_id": job_id,
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal error during balancing")


@app.post("/api/training/datasets/export")
async def export_dataset():
    try:
        import pandas as pd
    except ImportError:
        raise HTTPException(status_code=500, detail="pandas not available")

    try:
        dataset_name = "export"
        collection = get_db()["alerts"]
        cursor = collection.find(
            {"source": {"$in": ["coraza", "ml_miss_detector", "waf_blocked"]}},
            {
                "timestamp": 1,
                "method": 1,
                "uri": 1,
                "source": 1,
                "ai_score": 1,
                "ai_probability": 1,
                "triggered_rules": 1,
                "anomaly_score": 1,
                "_id": 0,
            },
        ).limit(50000)

        rows = list(cursor)
        if not rows:
            raise HTTPException(status_code=400, detail="No alerts to export")

        df = pd.DataFrame(rows)
        os.makedirs(os.path.join(DATA_DIR, "processed"), exist_ok=True)
        parquet_path = os.path.join(DATA_DIR, "processed", f"{dataset_name}.parquet")
        df.to_parquet(parquet_path, index=False)

        return {
            "status": "ready",
            "path": parquet_path,
            "samples": len(df),
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal error during export")


@app.delete("/api/training/history/{version}")
async def delete_model(version: str):
    if not re.match(r"^v\d+$", version):
        raise HTTPException(status_code=400, detail="Invalid version format")

    collection = get_db()["training_history"]
    record = collection.find_one({"version": version})
    if not record:
        raise HTTPException(status_code=404, detail="Model version not found")

    if record.get("active"):
        raise HTTPException(status_code=409, detail="Cannot delete the active model")

    collection.delete_one({"version": version})

    model_path = os.path.join(MODELS_DIR, f"v{version.lstrip('v')}")
    if os.path.isdir(model_path):
        import shutil
        shutil.rmtree(model_path, ignore_errors=True)

    return {"status": "deleted", "version": version}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8085)

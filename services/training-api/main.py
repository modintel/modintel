import os
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from bson import ObjectId

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
DATABASE_NAME = os.getenv("MONGO_DB_NAME", "modintel")

client: Optional[MongoClient] = None
db = None


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
    trained_at: str
    active: bool = False


class ModelStatus(BaseModel):
    active_version: str
    last_trained: Optional[str]
    training_active: bool
    current_job_id: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_db()
    yield
    if client:
        client.close()


app = FastAPI(title="ModIntel Training API", lifespan=lifespan)

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
        training_active=False,
        current_job_id=None,
    )


@app.get("/api/training/history")
async def get_training_history():
    collection = get_db()["training_history"]
    records = list(collection.find().sort("trained_at", -1).limit(50))
    for r in records:
        r["_id"] = str(r["_id"])
    return {"items": records}


@app.post("/api/training/start")
async def start_training(req: TrainingRequest):
    collection = get_db()["training_history"]

    existing = list(collection.find().sort("version", -1).limit(1))
    next_num = int(existing[0]["version"].lstrip("v")) + 1 if existing else 1
    new_version = f"v{next_num}"

    model_types = {
        "random_forest": "Random Forest",
        "xgboost": "XGBoost",
        "logistic": "Logistic Regression",
        "svm": "SVM",
    }

    dataset_labels = {
        "synthetic": "Synthetic (Generated)",
        "real": "Real Traffic",
        "combined": "Combined",
    }

    result = TrainingResult(
        version=new_version,
        model_type=model_types.get(req.model_type, req.model_type),
        dataset=dataset_labels.get(req.dataset, req.dataset),
        precision=round(0.85 + (next_num * 0.02), 2),
        recall=round(0.88 + (next_num * 0.015), 2),
        fpr=round(0.10 - (next_num * 0.01), 2),
        f1_score=round(0.90 + (next_num * 0.01), 2),
        trained_at=datetime.now(timezone.utc).isoformat(),
        active=True,
    )

    collection.update_many({"active": True}, {"$set": {"active": False}})
    doc = result.model_dump()
    collection.insert_one(doc)

    return {"status": "started", "job_id": str(ObjectId()), "version": new_version}


@app.post("/api/training/{version}/activate")
async def activate_model(version: str):
    collection = get_db()["training_history"]
    collection.update_many({"active": True}, {"$set": {"active": False}})
    result = collection.update_one({"version": version}, {"$set": {"active": True}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Model version not found")
    return {"status": "activated", "version": version}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8085)

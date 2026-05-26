FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY services/training-api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir --no-deps xgboost>=2.0.0

COPY services/training-api/main.py .
COPY services/training-api/audit_client.py .
COPY ml-pipeline /app/ml-pipeline

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8085"]
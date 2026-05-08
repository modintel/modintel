FROM python:3.11-slim

WORKDIR /app

# Copy requirements first
COPY services/training-api/requirements.txt .

# Install build tools, upgrade pip/setuptools/wheel, and add timeout/retries
RUN apt-get update && apt-get install -y gcc g++ libffi-dev \
    && pip install --upgrade pip setuptools wheel \
    && pip install --default-timeout=100 --retries=10 --no-cache-dir -r requirements.txt

# Copy your application code
COPY services/training-api/main.py .
COPY ml-pipeline /app/ml-pipeline

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8085"]

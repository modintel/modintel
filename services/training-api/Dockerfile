FROM python:3.11-slim

WORKDIR /app

# Copy requirements first
COPY services/training-api/requirements.txt .

# Install system build tools
RUN apt-get update && apt-get install -y gcc g++ libffi-dev

# Upgrade pip/setuptools/wheel
RUN pip install --upgrade pip setuptools wheel

# Install Python dependencies with longer timeout/retries
RUN pip install --default-timeout=100 --retries=10 --no-cache-dir -r requirements.txt

# Copy your application code
COPY services/training-api/main.py .
COPY ml-pipeline /app/ml-pipeline

# Run FastAPI with Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8085"]

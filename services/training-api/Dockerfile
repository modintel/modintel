FROM python:3.11-slim

WORKDIR /app

COPY services/training-api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/training-api/main.py .
COPY ml-pipeline /app/ml-pipeline

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8085"]
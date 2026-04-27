FROM python:3.11-slim

RUN for i in $(seq 1 15); do \
    (apt-get update || (sleep 10 && apt-get update)) && \
    apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libgomp1 && \
    break || (echo "Retry $i..." && sleep 20); \
    if [ $i -eq 15 ]; then exit 1; fi; \
    done \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN for i in $(seq 1 15); do \
    pip install --no-cache-dir --default-timeout=2000 -r requirements.txt && break || \
    (echo "Retry $i..." && sleep 20); \
    if [ $i -eq 15 ]; then exit 1; fi; \
    done

COPY . .

EXPOSE 8083

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8083"]

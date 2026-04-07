# ModIntel Project Context

This file serves as the permanent system context for AI agents working on the ModIntel project. Read this before starting any tasks to understand the overarching architecture and goals.

## Project Overview
ModIntel is a **hybrid WAF research system** designed to reduce false positives in rule-based WAFs using Machine Learning. 

**CRITICAL DESIGN CONSTRAINT:** The end product MUST be a production-ready, Dockerized solution. It is designed to act as a "drop-in" reverse proxy and security layer that can be deployed in front of *any* existing web application using Docker/Docker Compose.

The core philosophical idea:
**Rules detect (catch known attacks) → ML judges (handles nuance) → Humans verify (edge cases).**

## Core Architecture
```text
Client
   |
   v
Caddy Reverse Proxy
   |
   v
Coraza WAF (OWASP CRS)
   |
   |----> WAF decision (rules triggered)
   |
Feature Extractor (Go service)
   |
ML Inference Service (Python/Go)
   |
Decision Engine
   |
   |----> allow
   |----> block
   |----> send to review
   |
Backend Web App
```

## Technology Stack
- **Reverse Proxy:** Caddy
- **WAF Engine:** Coraza with OWASP Core Rule Set (CRS)
- **Log Collector/Ingestion:** Go
- **ML Infrastructure:** Python (scikit-learn/XGBoost/etc.), exporting to ONNX
- **Machine Learning Models:** Random Forest (starting point)
- **Database (Logs & Metrics):** MongoDB or PostgreSQL
- **Containerization:** Docker

## Key Components / Services
1. **log-ingestor** (Go): Receives logs from Coraza, normalizes data, stores in DB.
2. **ML Pipeline** (Python): `dataset_builder.py`, `feature_extractor.py`, `train_model.py`, `evaluate_model.py`.
3. **ml-inference-service** (Go or Python): Receives features, loads ONNX model, returns attack probability score.
4. **review-dashboard**: UI for human review of edge cases (flags true attacks vs. false positives to feed back into the training loop).

## Workflow Principles
1. Do not jump to ML prematurely. Ensure Coraza + CRS logging is fully working first.
2. ML features are numerical representations of WAF logs (e.g., triggered rules, anomaly scores, HTTP methods).
3. The ultimate goal is minimizing the False Positive Rate (FPR) of the OWASP CRS while maintaining a high detection rate.

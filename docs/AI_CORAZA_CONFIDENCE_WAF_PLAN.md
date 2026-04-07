# AI-Integrated Coraza WAF Plan

## 1. Objective

Build a hybrid WAF system where Coraza + OWASP CRS remains the deterministic protection layer, and AI acts as an advisory intelligence layer that produces mathematically grounded confidence for every decision.

Primary goals:

1. Reduce false positives (FP) without unacceptable false negatives (FN).
2. Produce confidence and uncertainty metrics for every AI output.
3. Keep AI non-autonomous: AI can only alert and prioritize, never directly block/allow traffic.
4. Build a reproducible training-to-serving pipeline with auditable model behavior.


## 2. Non-Negotiable Governance Rules

1. AI must not enforce traffic decisions. Enforcement is owned by Coraza policy.
2. Every AI prediction must include confidence artifacts and explanation metadata.
3. Critical deterministic rule matches remain high-priority regardless of AI output.
4. If AI is unavailable, system behavior must remain safe and deterministic.


## 3. Target Architecture

```text
Client
  -> Caddy Reverse Proxy
  -> Coraza WAF (CRS + custom rules)
  -> Coraza audit event
  -> Log Collector (Go)
  -> Feature Mapper
  -> Inference Engine (Python)
  -> Advisory Alert (no enforcement)
  -> MongoDB (alerts + metrics + labels)
  -> Review API + Dashboard
  -> Analyst feedback loop -> ML retraining pipeline
```

Design principle:

- Rules detect and enforce baseline policy.
- AI estimates risk/confidence and prioritizes analyst action.
- Humans validate uncertain/high-impact events and improve labels.


## 4. Mathematical Confidence Framework

For each event `x`, the inference service returns:

1. Calibrated attack probability:
   - `p_hat = P(y=attack | x)`
2. Uncertainty interval (95%):
   - `CI_95 = [p_low, p_high]`
3. Prediction entropy:
   - `H(p_hat) = -p_hat*log(p_hat) - (1-p_hat)*log(1-p_hat)`
4. Human-readable confidence score (0-100):
   - `confidence_score = 100 * (1 - H_norm) * calibration_trust_factor`
5. Optional conformal output:
   - prediction set in `{attack}`, `{benign}`, `{attack, benign}`

Global reliability metrics (per model version):

1. Expected Calibration Error (ECE)
2. Brier score
3. AUROC/PR-AUC
4. FPR/FNR by attack family


## 5. Advisory Decision Policy

AI output bands (advisory only):

1. `P1` likely attack:
   - `p_hat >= 0.90` and narrow confidence interval
2. `P2` uncertain:
   - high entropy or wide confidence interval
3. `P3` likely benign anomaly:
   - `p_hat <= 0.10` and high confidence

Notes:

1. Priority is for analyst workflow, not enforcement.
2. Coraza blocking behavior is controlled by WAF rules and anomaly threshold only.
3. AI recommendation can be logged as `recommended_priority` and `review_reason`.


## 6. Data and Feature Contract

### 6.1 Normalized event schema

Minimum event fields:

1. `timestamp`
2. `client_ip`
3. `method`
4. `uri`
5. `triggered_rules[]`
6. `anomaly_score`
7. `request_size`
8. `status_code` (if available)
9. `raw_log`

### 6.2 Model feature groups

1. Rule features:
   - one-hot or hashed representation of triggered rule IDs
2. Protocol/meta features:
   - method class, URI length, parameter counts, encoding indicators
3. Statistical features:
   - anomaly score, number of triggered rules, severity-weighted sum
4. Textual features:
   - char n-grams on normalized payload fragments where available

### 6.3 Label taxonomy

1. `attack` (1)
2. `benign` (0)
3. `uncertain` (review pending)


## 7. Implementation Roadmap

## Phase A: Specification and governance baseline

Deliverables:

1. Final schema and policy document.
2. API contract for advisory inference response.
3. Threshold policy with review bands.

Tasks:

1. Freeze event schema version `v1`.
2. Define confidence field names and units.
3. Add explicit policy statement: AI cannot enforce.


## Phase B: Dataset unification and quality gates

Deliverables:

1. `dataset_builder.py` that merges:
   - Coraza audit data
   - existing ModSecurity training corpus
   - reviewed analyst labels
2. Dataset metadata file with lineage and hashes.

Tasks:

1. Build feature-mapping parity checks between training and runtime.
2. Add train/validation/test splits with stratification by attack family.
3. Add data-quality checks (missingness, duplicates, label conflict).


## Phase C: Model training with calibration

Deliverables:

1. Candidate models and benchmark report.
2. Calibrated model artifacts and metadata.

Tasks:

1. Train baseline candidates:
   - Logistic Regression
   - Random Forest
   - Calibrated Linear SVM
2. Add calibration stage:
   - isotonic or Platt scaling
3. Compute confidence metrics:
   - ECE, Brier, AUROC, FPR, FNR
4. Persist artifacts:
   - model file
   - feature transformer
   - calibration object
   - model metadata JSON


## Phase D: Inference engine productionization

Deliverables:

1. Real `/predict` endpoint in `services/inference-engine/main.py`.
2. Advisory output schema with confidence for each alert.

Tasks:

1. Load model + feature extractor + calibration artifact.
2. Validate incoming schema and feature compatibility.
3. Return output payload:
   - `attack_probability`
   - `confidence_score`
   - `ci_low`, `ci_high`
   - `entropy`
   - `recommended_priority`
   - `explanation`
4. Enforce advisory-only mode in code path.


## Phase E: Integration with collector/review services

Deliverables:

1. Log collector invokes inference and stores advisory results.
2. Review API/dashboard can filter by confidence and uncertainty.

Tasks:

1. Extend alert document model with AI fields.
2. Add indexes for `timestamp`, `recommended_priority`, `confidence_score`.
3. Add dashboard views:
   - most uncertain alerts
   - likely false positives
   - highest-risk likely attacks


## Phase F: Closed-loop learning

Deliverables:

1. Analyst label workflow feeding training data.
2. Scheduled retraining and model promotion gate.

Tasks:

1. Add reviewer label endpoints (`attack`, `benign`, `needs-more-context`).
2. Add retraining trigger and artifact versioning.
3. Add promotion policy requiring metric gates.


## Phase G: Validation and hardening

Deliverables:

1. End-to-end validation report.
2. Operational dashboards and alerts.

Tasks:

1. Replay attack suites and benign traffic traces.
2. Measure latency budget and failover behavior.
3. Add drift monitors:
   - feature drift
   - confidence drift
   - label drift


## 8. Advisory Inference API Contract (Draft)

Request:

```json
{
  "event_id": "uuid",
  "timestamp": "2026-04-01T12:00:00Z",
  "method": "POST",
  "uri": "/api/login",
  "triggered_rules": ["942100", "949110"],
  "anomaly_score": 8,
  "raw": {}
}
```

Response:

```json
{
  "model_version": "2026.04.01-rf-cal-v1",
  "attack_probability": 0.93,
  "confidence_score": 87.4,
  "confidence_interval": {
    "low": 0.88,
    "high": 0.96,
    "level": 0.95
  },
  "entropy": 0.25,
  "recommended_priority": "P1",
  "recommendation": "high-likelihood attack, analyst confirmation advised",
  "explanation": {
    "top_features": [
      {"name": "rule_942100", "weight": 0.31},
      {"name": "anomaly_score", "weight": 0.24},
      {"name": "rule_count", "weight": 0.18}
    ]
  },
  "advisory_only": true
}
```


## 9. Acceptance Criteria

Functional:

1. Every alert has a confidence payload and advisory priority.
2. AI cannot alter block/allow decisions directly.
3. Dashboard supports sorting by uncertainty and confidence.

Quality:

1. Calibration metrics tracked per model release.
2. Measured FP reduction versus Coraza-only baseline.
3. FN increase remains under agreed threshold.

Operational:

1. Inference failure does not break WAF operation.
2. Model artifacts are versioned and traceable.
3. All decisions are auditable with metadata.


## 10. Benchmark Strategy vs Existing Systems

Target differentiation (where this project can outperform):

1. Transparent per-alert mathematical confidence.
2. Explicit uncertainty reporting and analyst prioritization.
3. Governance-first AI posture (non-autonomous by policy and code).
4. Reproducible, auditable model lifecycle.

Benchmark dimensions:

1. Detection quality:
   - recall, precision, FPR, FNR
2. Confidence quality:
   - ECE, Brier, reliability curve
3. Analyst efficiency:
   - precision@top-K alerts
   - mean time to triage
4. Operational safety:
   - behavior under AI outage
   - drift detection responsiveness


## 11. Immediate Execution Sequence

1. Implement Phase A docs and schema validation stubs.
2. Build dataset builder and feature contract checks.
3. Replace mock inference endpoint with calibrated advisory output.
4. Wire collector and dashboard for confidence fields.
5. Add retraining gate and validation report generation.


## 12. Suggested Initial Defaults

1. Priority thresholds:
   - P1: `p_hat >= 0.90`
   - P3: `p_hat <= 0.10`
   - otherwise P2
2. Confidence interval level:
   - `95%`
3. Baseline model:
   - Random Forest + probability calibration
4. First attack families:
   - SQLi, XSS, RCE, LFI

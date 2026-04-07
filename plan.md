What you’re building is essentially a **hybrid WAF research system**:

**Caddy → Coraza (CRS rules) → ML decision layer → human review / logging**

The papers and workflow you uploaded describe the **exact scientific pipeline** for reducing **false positives in rule-based WAFs** using ML. 

The key philosophical idea here is subtle but powerful:

Rule-based systems are **good at catching known attacks**, but **terrible at nuance**.
Machine learning is **good at nuance**, but **dangerous if it blocks things blindly**.

So the architecture becomes:

**Rules detect → ML judges → humans verify edge cases.**

Think of it like airport security:

* metal detector = WAF rules
* trained officer = ML classifier
* manual inspection = human review

Now let's turn that idea into a **real engineering roadmap using Coraza + Caddy + ML**.

---

# Phase 1 — Project Architecture Design

First freeze the architecture before writing code.

### Final architecture

```
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
ML Inference Service
   |
Decision Engine
   |
   |----> allow
   |----> block
   |----> send to review
   |
Backend Web App
```

Supporting services:

```
Log Collector
Dataset Builder
Training Pipeline
Human Review Dashboard
Metrics System
```

---

# Phase 2 — Environment Setup

Before touching ML, build the **security infrastructure**.

### 1 Install base stack

On one machine or docker network.

Install:

* Go
* Docker
* Python
* Caddy
* Coraza
* OWASP CRS
* MongoDB or PostgreSQL (for logs)

---

### 2 Configure Caddy + Coraza

Caddy will be the reverse proxy.

```
Client → Caddy → Coraza middleware → backend
```

Coraza supports **OWASP CRS** just like ModSecurity.

Test rule triggering:

Example attack:

```
?id=1' OR '1'='1
```

Confirm logs show:

```
rule_id
anomaly_score
matched_variables
```

These will become **ML features later**.

---

# Phase 3 — Logging & Data Collection

This phase is **extremely important**.

Your ML model is **only as good as its logs**.

From the paper workflow:

Traffic → WAF → audit logs → features → labels → ML training. 

---

## Step 1 — Enable full WAF logging

Log:

```
timestamp
client_ip
uri
method
headers
rule_ids_triggered
anomaly_score
request_size
response_code
status (generated, classified, reviewed, resolved)
```

Store in database:

```
MongoDB

```

---

## Step 2 — Build a Log Collector

Create a Go service:

```
log-ingestor
```

Responsibilities:

```
receive coraza logs
normalize data
store in DB
```

---

# Phase 4 — Dataset Generation

This is the **research phase**.

You must create:

```
normal traffic
attack traffic
```

As the paper explains, datasets like CSIC 2010 are often unrealistic. 

So you combine:

```
synthetic attacks
real browsing traffic
```

---

## Generate normal traffic

Use:

```
real browsing
curl
browser automation
```

Tools:

```
Selenium
Playwright
```

Capture requests.

Label:

```
label = normal
```

---

## Generate attack traffic

Use security tools:

```
sqlmap
nikto
OWASP ZAP
burp intruder
metasploit
```

Target:

```
DVWA
juice-shop
test apps
```

Label:

```
label = attack
```

---

# Phase 5 — Feature Engineering

The ML model doesn't see HTTP text.

It sees **numerical features**.

The paper suggests using:

```
triggered_rules
anomaly_score
HTTP method
```

Example feature vector:

```
rule_920272 = 1
rule_942100 = 0
rule_933100 = 1
anomaly_score = 10
method = POST
body_size = 320
param_count = 4
```

If CRS has **156 rules**, your feature vector becomes:

```
156 rule features
+ metadata
```

---

# Phase 6 — ML Model Training

Now build a **Python training pipeline**.

Recommended models from the workflow:

```
Logistic Regression
SVM
Decision Tree
Random Forest
XGBoost
```



Start simple:

```
Random Forest
```

Why?

* handles feature interactions
* robust to noise
* interpretable

---

Training pipeline:

```
dataset_builder.py
feature_extractor.py
train_model.py
evaluate_model.py
```

Metrics to compute:

```
precision
recall
false positive rate
F1 score
```

Main objective:

```
minimize false positives
```

---

# Phase 7 — Model Export

After training:

Export model.

Options:

```
ONNX
pickle
JSON
```

Best for Go integration:

```
ONNX
```

Because Go has runtime support.

---

# Phase 8 — ML Inference & Explainability Service

Create service:

```
ml-inference-service
```

Language:

```
Go or Python
```

Responsibilities:

```
receive features
load trained model
predict attack probability
generate human-readable explanation (SHAP/LIME or Rule Fallback)
return score and explanation
```

Example response:

```json
{
  "attack_probability": 0.72,
  "decision": "likely_attack",
  "explanation": "Rule 942100 triggered, but missing SQL keywords reduced risk by 15%."
}
```

---

# Phase 9 — Integrate ML with Coraza

Now the clever part.

When Coraza flags a request:

```
if anomaly_score > threshold:
      send features to ML service
```

Then ML decides:

```
if attack_probability > 0.8
      block
else if attack_probability < 0.3
      allow
else
      send_to_review
```

This becomes your **hybrid decision engine**.

---

# Phase 10 — Human Review System & RBAC

Build a lightweight, dependency-free dashboard using pure **HTML, CSS, and Vanilla JavaScript**. No heavy frameworks (like React or Angular) to keep the system easy to maintain.

```
review-dashboard (served as static files)
```

Show:

```
request
triggered rules
ML prediction & confidence score
ML explanation (SHAP/LIME logic)
current alert status (generated, classified)
```

**Security Analyst Actions:**
Can only review edge-cases and mark labels:
```
true attack
false positive
requires investigation
```

**System Administrator Actions:**
Can manage the entire pipeline:
```
adjust confidence thresholds
deploy/rollback ML models
view training metrics
```

Those labels feed back into training.

This creates a **continuous learning loop**.

---

# Phase 11 — Performance Optimization

Important research metrics:

From the workflow:

```
True Positive Rate
False Positive Rate
Precision
Latency
Human review reduction
```



Measure:

```
WAF latency
ML inference latency
overall request delay
```

Target:

```
< 5ms ML inference
```

---

# Phase 12 — Experimental Evaluation

Run experiments:

Compare:

```
Coraza baseline
vs
Coraza + ML
```

Measure:

```
false positives reduction
attack detection rate
review workload reduction
```

Example result:

```
FPR reduced from 12% → 4%
```

---

# Phase 13 — Deployment Architecture

Production architecture:

```
Internet
   |
Load Balancer
   |
Caddy + Coraza
   |
Feature Extractor
   |
ML Service
   |
Application Servers
```

Add monitoring:

```
Prometheus
Grafana
```

---

# Phase 14 — Final Deliverables

Your final system should contain:

### Code

```
coraza-waf
ml-training
ml-inference-service
log-collector
review-dashboard
```

### Research outputs

```
dataset
trained models
evaluation results
performance graphs
```

---

# Critical Advice

Start **in this order**:

1️⃣ Coraza + CRS working
2️⃣ logging pipeline
3️⃣ dataset collection
4️⃣ ML training
5️⃣ ML inference integration

Most teams fail because they **jump to ML too early**.

No logs = no ML.

---

# One more idea (this will impress professors)

Add **adaptive rule tuning**:

If ML repeatedly says:

```
rule 942100 = false positive
```

System can automatically:

```
lower rule weight
or
suggest rule disable
```

That turns your project from **research prototype → intelligent WAF**.

---

If you want, I can also show you something very useful for this project:

**A full folder structure + microservice architecture for the entire Coraza + ML system.**

That will save your team **weeks of design mistakes**.

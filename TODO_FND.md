# TODO: False Negative Detection (FND) - Catching WAF Misses

## Objective
Build an independent ML model to detect attacks that the Coraza WAF fails to catch (false negatives).

## Data Pipeline

- [ ] Create separate feature extractor without WAF metadata (no `fired_rule_ids`, `anomaly_score`, `rule_severities`)
- [ ] Modify `curate_traffic_sources.py` to generate attacks with varying evasion techniques (bypass attempts)
- [ ] Run replay through Coraza and filter for requests where WAF did NOT fire (label=attack but coraza_fired_rule_ids=empty)
- [ ] Build `fnd_dataset.parquet` with attack records that WAF missed + benign traffic that passed through

## Feature Engineering

- [ ] Raw HTTP features only (exclude WAF-derived features):
  - Request structure: method, URI length/depth, query params, body length, headers
  - Payload statistical: entropy, special char ratio, encoding artifacts, non-printables
  - Header analysis: user-agent patterns, content-type anomalies
- [ ] Add new features for evasion detection:
  - Obfuscation indicators (mixed case, null bytes, unicodehomoglyphs)
  - Payload asymmetry (encoding vs decoded length ratio)
  - Protocol anomalies (HTTP method tampering, header smuggling)

## Model Training

- [ ] Create `train_fnd_model.py` - separate training script for FND model
- [ ] Train on imbalanced dataset (benign >> attacks that WAF missed)
- [ ] Use SMOTE or class weights to handle imbalance
- [ ] Optimize for high recall (catch as many WAF misses as possible, even at cost of some false positives)
- [ ] Export to `models/fnd_v1/`

## Evaluation

- [ ] Test against held-out bypass payloads (not seen during training)
- [ ] Compare FND model recall vs WAF-only detection rate
- [ ] Measure false positive rate on legitimate traffic
- [ ] Per-attack-family breakdown (sqli, xss, cmd_injection, etc.)

## Integration

- [ ] Update `inference-engine` to run both models:
  - Primary: WAF + existing model (reduce false positives)
  - Secondary: FND model (catch WAF misses)
- [ ] Decision logic: if WAF allows AND FND predicts attack → block/review
- [ ] Add confidence threshold configuration for FND alerts

## Metrics Target

- [ ] Achieve >90% recall on WAF-missed attacks
- [ ] Keep FND false positive rate <5% on benign traffic
- [ ] Latency impact <10ms per request
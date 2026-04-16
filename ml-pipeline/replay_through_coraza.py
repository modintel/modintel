"""
replay_through_coraza.py
Replays curated HTTP requests through the Coraza WAF proxy and captures audit log entries.

Input:
  ../data/curated/attack_requests.jsonl
  ../data/curated/benign_requests.jsonl

Output:
  ../data/coraza_enriched/replay_results.jsonl

Environment variables:
  CORAZA_PROXY_URL        — proxy base URL (default: http://localhost:8080)
  CORAZA_AUDIT_LOG        — path to Coraza audit log file (default: ../proxy-waf/coraza_audit.log)
  REQUEST_DELAY_SECONDS   — inter-request delay in seconds (default: 0.05)
"""

import os
import json
import time
import logging
from datetime import datetime

import requests
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_DATA_DIR", os.path.join(REPO_ROOT, "data"))
)

CORAZA_PROXY_URL = os.environ.get("CORAZA_PROXY_URL", "http://localhost:8080")
CORAZA_AUDIT_LOG = os.environ.get(
    "CORAZA_AUDIT_LOG",
    os.path.join(REPO_ROOT, "proxy-waf", "coraza_audit.log"),
)
REQUEST_DELAY_SECONDS = float(os.environ.get("REQUEST_DELAY_SECONDS", "0.05"))

INPUT_FILES = [
    os.path.join(DATA_BASE_DIR, "curated", "attack_requests.jsonl"),
    os.path.join(DATA_BASE_DIR, "curated", "benign_requests.jsonl"),
]
OUTPUT_DIR = os.path.join(DATA_BASE_DIR, "coraza_enriched")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "replay_results.jsonl")

MAX_RETRIES = 3
AUDIT_POLL_TIMEOUT = 5.0  # seconds to wait for a matching audit log entry
AUDIT_POLL_INTERVAL = 0.1  # seconds between polls

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Audit log helpers
# ---------------------------------------------------------------------------


def _read_audit_log_lines(path: str) -> list:
    """Return all lines from the audit log file, or empty list if unavailable."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except (OSError, IOError):
        return []


def _parse_audit_entry(line: str) -> Optional[dict]:
    """Parse a single JSON audit log line. Returns None on parse failure."""
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def _extract_coraza_fields(entry: dict) -> dict:
    """
    Extract Coraza audit fields from a parsed audit log entry.
    Handles both flat and nested Coraza JSON audit formats.
    """
    rule_ids = []
    severities = []
    messages = []
    anomaly_score = 0

    # Coraza JSON audit log format (SecAuditLogFormat JSON)
    # Top-level keys vary by Coraza version; try common structures.
    transaction = entry.get("transaction", entry)

    # Rules may be under "messages" or "matched_rules" or "rules"
    matched = (
        transaction.get("messages")
        or transaction.get("matched_rules")
        or entry.get("messages")
        or []
    )

    for rule_entry in matched:
        if not isinstance(rule_entry, dict):
            continue
        # Rule ID
        rule_id = (
            rule_entry.get("rule_id")
            or rule_entry.get("id")
            or (rule_entry.get("rule", {}) or {}).get("id")
        )
        if rule_id is not None:
            rule_ids.append(int(rule_id))

        # Severity
        severity = (
            rule_entry.get("severity")
            or (rule_entry.get("rule", {}) or {}).get("severity")
            or ""
        )
        severities.append(str(severity))

        # Message
        message = (
            rule_entry.get("message")
            or rule_entry.get("msg")
            or (rule_entry.get("rule", {}) or {}).get("msg")
            or ""
        )
        messages.append(str(message))

    # Anomaly score — may be in producer section or top-level
    producer = transaction.get("producer", {}) or {}
    anomaly_score = int(
        producer.get("anomaly_score")
        or transaction.get("anomaly_score")
        or entry.get("anomaly_score")
        or 0
    )

    return {
        "coraza_fired_rule_ids": rule_ids,
        "coraza_rule_severities": severities,
        "coraza_rule_messages": messages,
        "coraza_anomaly_score": anomaly_score,
        "coraza_matched": True,
    }


def _infer_from_response(status_code: int) -> dict:
    """
    Fallback: infer Coraza fields from HTTP response status when no audit log
    entry is available.
    """
    fired = status_code == 403
    return {
        "coraza_fired_rule_ids": [],
        "coraza_rule_severities": [],
        "coraza_rule_messages": ["inferred from HTTP 403" if fired else ""],
        "coraza_anomaly_score": 100 if fired else 0,
        "coraza_matched": fired,
    }


def _empty_coraza_fields() -> dict:
    """Return empty/zero Coraza fields for unmatched requests."""
    return {
        "coraza_fired_rule_ids": [],
        "coraza_rule_severities": [],
        "coraza_rule_messages": [],
        "coraza_anomaly_score": 0,
        "coraza_matched": False,
    }


# ---------------------------------------------------------------------------
# Audit log polling
# ---------------------------------------------------------------------------


def _poll_audit_log(uri: str, sent_at: float, audit_log_path: str) -> Optional[dict]:
    """
    Poll the audit log file for a new entry matching `uri` with a timestamp
    within AUDIT_POLL_TIMEOUT seconds of `sent_at`.

    Returns the parsed Coraza fields dict, or None if no match found.
    """
    deadline = time.monotonic() + AUDIT_POLL_TIMEOUT
    seen_lines = set()

    # Seed with lines already in the file before we start polling
    initial_lines = _read_audit_log_lines(audit_log_path)
    for line in initial_lines:
        seen_lines.add(line)

    while time.monotonic() < deadline:
        current_lines = _read_audit_log_lines(audit_log_path)
        for line in current_lines:
            if line in seen_lines:
                continue
            seen_lines.add(line)
            entry = _parse_audit_entry(line)
            if entry is None:
                continue

            # Check URI match
            transaction = entry.get("transaction", entry)
            req_section = transaction.get("request", {}) or {}
            entry_uri = (
                req_section.get("uri")
                or transaction.get("uri")
                or entry.get("uri")
                or ""
            )

            # Normalise: strip query string for matching if needed
            if uri.split("?")[0] not in entry_uri and uri not in entry_uri:
                continue

            # Check timestamp proximity
            ts_str = transaction.get("timestamp") or entry.get("timestamp") or ""
            if ts_str:
                try:
                    # Coraza timestamps are ISO-8601; parse and compare
                    ts_str_clean = ts_str.replace("Z", "+00:00")
                    entry_ts = datetime.fromisoformat(ts_str_clean).timestamp()
                    if abs(entry_ts - sent_at) > AUDIT_POLL_TIMEOUT:
                        continue
                except (ValueError, TypeError):
                    pass  # If we can't parse the timestamp, accept the URI match

            return _extract_coraza_fields(entry)

        time.sleep(AUDIT_POLL_INTERVAL)

    return None


# ---------------------------------------------------------------------------
# Request sending
# ---------------------------------------------------------------------------


def _send_request(record: dict) -> tuple[int, dict]:
    """
    Send a single HTTP request to the Coraza proxy.
    Returns (status_code, response_headers).
    Raises requests.RequestException on network failure.
    """
    method = record.get("method", "GET").upper()
    uri = record.get("uri", "/")
    headers = dict(record.get("headers") or {})
    body = record.get("body") or ""

    url = CORAZA_PROXY_URL.rstrip("/") + uri

    resp = requests.request(
        method=method,
        url=url,
        headers=headers,
        data=body.encode("utf-8") if body else None,
        timeout=10,
        allow_redirects=False,
    )
    return resp.status_code, dict(resp.headers)


# ---------------------------------------------------------------------------
# Core replay logic
# ---------------------------------------------------------------------------


def replay_record(record: dict, audit_log_available: bool) -> dict:
    """
    Replay a single request record through Coraza with up to MAX_RETRIES attempts.
    Returns the enriched output dict.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            sent_at = time.time()
            status_code, resp_headers = _send_request(record)

            if audit_log_available:
                coraza_fields = _poll_audit_log(
                    record["uri"], sent_at, CORAZA_AUDIT_LOG
                )
                if coraza_fields is not None:
                    break
                # No match yet — retry
                logger.debug(
                    "Attempt %d/%d: no audit log match for %s %s",
                    attempt,
                    MAX_RETRIES,
                    record["method"],
                    record["uri"],
                )
            else:
                # No audit log — infer from response immediately
                coraza_fields = _infer_from_response(status_code)
                break

        except requests.RequestException as exc:
            logger.warning(
                "Attempt %d/%d failed for %s %s: %s",
                attempt,
                MAX_RETRIES,
                record["method"],
                record["uri"],
                exc,
            )
            coraza_fields = None
            if attempt < MAX_RETRIES:
                time.sleep(REQUEST_DELAY_SECONDS * 2)

    else:
        # Exhausted retries without a match
        coraza_fields = None

    if coraza_fields is None:
        coraza_fields = _empty_coraza_fields()
        matched = False
    else:
        matched = coraza_fields.get("coraza_matched", False)

    output = {
        "request_id": record.get("request_id"),
        "method": record.get("method"),
        "uri": record.get("uri"),
        "headers": record.get("headers"),
        "body": record.get("body"),
        "label": record.get("label"),
        "attack_family": record.get("attack_family"),
        **coraza_fields,
    }

    return output, matched


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_replay():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Determine if audit log file is accessible
    audit_log_path = os.path.normpath(CORAZA_AUDIT_LOG)
    audit_log_available = os.path.isfile(audit_log_path)
    if audit_log_available:
        logger.info("Audit log found at: %s", audit_log_path)
    else:
        logger.warning(
            "Audit log not found at '%s'. Will infer Coraza results from HTTP response status.",
            audit_log_path,
        )

    total = 0
    matched_count = 0
    unmatched_count = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f:
        for input_file in INPUT_FILES:
            if not os.path.isfile(input_file):
                logger.warning("Input file not found, skipping: %s", input_file)
                continue

            logger.info("Replaying requests from: %s", input_file)

            with open(input_file, "r", encoding="utf-8") as in_f:
                for line in in_f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        logger.warning("Skipping malformed JSON line: %s", exc)
                        continue

                    total += 1

                    output, matched = replay_record(record, audit_log_available)

                    if matched:
                        matched_count += 1
                        out_f.write(json.dumps(output) + "\n")
                    else:
                        unmatched_count += 1
                        # Per Req 2.5: exclude unmatched from output
                        logger.debug(
                            "Unmatched (excluded): request_id=%s uri=%s",
                            record.get("request_id"),
                            record.get("uri"),
                        )

                    if total % 1000 == 0:
                        print(
                            f"Progress: {total} requests processed "
                            f"({matched_count} matched, {unmatched_count} unmatched)"
                        )

                    time.sleep(REQUEST_DELAY_SECONDS)

    print("\nReplay complete.")
    print(f"  Total requests processed : {total}")
    print(f"  Matched (written)        : {matched_count}")
    print(f"  Unmatched (excluded)     : {unmatched_count}")
    print(f"  Output file              : {OUTPUT_FILE}")


if __name__ == "__main__":
    run_replay()

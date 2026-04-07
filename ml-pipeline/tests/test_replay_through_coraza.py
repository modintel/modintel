"""
Unit tests for replay_through_coraza.py
Covers: retry logic and unmatched-request handling (Requirements 2.3, 2.5)
"""

import json
import os
import sys
import time
import tempfile
from unittest.mock import MagicMock, patch, call

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import replay_through_coraza as rtc
from replay_through_coraza import (
    replay_record,
    _send_request,
    _parse_audit_entry,
    _extract_coraza_fields,
    _infer_from_response,
    _empty_coraza_fields,
)


# ---------------------------------------------------------------------------
# _parse_audit_entry
# ---------------------------------------------------------------------------

class TestParseAuditEntry:
    def test_valid_json_returns_dict(self):
        line = '{"transaction": {"uri": "/test"}}'
        result = _parse_audit_entry(line)
        assert result == {"transaction": {"uri": "/test"}}

    def test_invalid_json_returns_none(self):
        assert _parse_audit_entry("not json {{{") is None

    def test_empty_line_returns_none(self):
        assert _parse_audit_entry("") is None

    def test_whitespace_only_returns_none(self):
        assert _parse_audit_entry("   ") is None


# ---------------------------------------------------------------------------
# _extract_coraza_fields
# ---------------------------------------------------------------------------

class TestExtractCorazaFields:
    def test_extracts_rule_ids_and_score(self):
        entry = {
            "transaction": {
                "messages": [
                    {"rule_id": 942100, "severity": "CRITICAL", "message": "SQLi detected"},
                    {"rule_id": 942200, "severity": "WARNING", "message": "SQLi pattern"},
                ],
                "producer": {"anomaly_score": 15},
            }
        }
        result = _extract_coraza_fields(entry)
        assert result["coraza_fired_rule_ids"] == [942100, 942200]
        assert result["coraza_anomaly_score"] == 15
        assert result["coraza_matched"] is True
        assert "CRITICAL" in result["coraza_rule_severities"]

    def test_empty_messages_returns_zero_score(self):
        entry = {"transaction": {"messages": [], "producer": {"anomaly_score": 0}}}
        result = _extract_coraza_fields(entry)
        assert result["coraza_fired_rule_ids"] == []
        assert result["coraza_anomaly_score"] == 0

    def test_nested_rule_id_extraction(self):
        entry = {
            "transaction": {
                "messages": [{"rule": {"id": 941100, "severity": "NOTICE", "msg": "XSS"}}],
                "producer": {},
            }
        }
        result = _extract_coraza_fields(entry)
        assert 941100 in result["coraza_fired_rule_ids"]


# ---------------------------------------------------------------------------
# _infer_from_response / _empty_coraza_fields
# ---------------------------------------------------------------------------

class TestInferFromResponse:
    def test_403_sets_matched_true(self):
        result = _infer_from_response(403)
        assert result["coraza_matched"] is True
        assert result["coraza_anomaly_score"] == 100

    def test_200_sets_matched_false(self):
        result = _infer_from_response(200)
        assert result["coraza_matched"] is False
        assert result["coraza_anomaly_score"] == 0

    def test_empty_fields_all_zero(self):
        result = _empty_coraza_fields()
        assert result["coraza_matched"] is False
        assert result["coraza_fired_rule_ids"] == []
        assert result["coraza_anomaly_score"] == 0


# ---------------------------------------------------------------------------
# replay_record — retry logic (Requirement 2.3)
# ---------------------------------------------------------------------------

class TestReplayRecordRetryLogic:
    """Tests that replay_record retries up to MAX_RETRIES on failure."""

    _sample_record = {
        "request_id": "abc-123",
        "method": "GET",
        "uri": "/test",
        "headers": {"Host": "localhost"},
        "body": "",
        "label": "attack",
        "attack_family": "sqli",
    }

    def test_retries_on_request_exception(self):
        """Should retry up to MAX_RETRIES times when network errors occur."""
        call_count = {"n": 0}

        def failing_send(record):
            call_count["n"] += 1
            raise requests.RequestException("connection refused")

        with patch.object(rtc, "_send_request", side_effect=failing_send), \
             patch.object(rtc, "REQUEST_DELAY_SECONDS", 0):
            output, matched = replay_record(self._sample_record, audit_log_available=False)

        assert call_count["n"] == rtc.MAX_RETRIES
        assert not matched

    def test_succeeds_on_second_attempt(self):
        """Should succeed without exhausting retries if second attempt works."""
        attempts = {"n": 0}

        def flaky_send(record):
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise requests.RequestException("transient error")
            return 200, {}

        with patch.object(rtc, "_send_request", side_effect=flaky_send), \
             patch.object(rtc, "REQUEST_DELAY_SECONDS", 0):
            output, matched = replay_record(self._sample_record, audit_log_available=False)

        assert attempts["n"] == 2
        # 200 → inferred as not matched (no 403), but no exception
        assert output["request_id"] == "abc-123"

    def test_no_audit_log_uses_response_inference(self):
        """When audit_log_available=False, result is inferred from HTTP status."""
        with patch.object(rtc, "_send_request", return_value=(403, {})):
            output, matched = replay_record(self._sample_record, audit_log_available=False)
        assert matched is True
        assert output["coraza_anomaly_score"] == 100

    def test_output_contains_all_original_fields(self):
        """Output dict must carry all original request fields."""
        with patch.object(rtc, "_send_request", return_value=(200, {})):
            output, _ = replay_record(self._sample_record, audit_log_available=False)
        for field in ("request_id", "method", "uri", "headers", "body", "label", "attack_family"):
            assert field in output


# ---------------------------------------------------------------------------
# replay_record — unmatched request handling (Requirement 2.5)
# ---------------------------------------------------------------------------

class TestReplayRecordUnmatched:
    """Tests that unmatched requests are excluded from output."""

    _sample_record = {
        "request_id": "xyz-999",
        "method": "POST",
        "uri": "/submit",
        "headers": {},
        "body": "data=test",
        "label": "benign",
        "attack_family": "benign",
    }

    def test_unmatched_after_all_retries_returns_not_matched(self):
        """After MAX_RETRIES with no audit match, matched=False."""
        with patch.object(rtc, "_send_request", return_value=(200, {})), \
             patch.object(rtc, "_poll_audit_log", return_value=None), \
             patch.object(rtc, "REQUEST_DELAY_SECONDS", 0):
            output, matched = replay_record(self._sample_record, audit_log_available=True)
        assert matched is False

    def test_matched_request_returns_matched_true(self):
        """When audit log returns a match, matched=True."""
        fake_coraza = {
            "coraza_fired_rule_ids": [942100],
            "coraza_rule_severities": ["CRITICAL"],
            "coraza_rule_messages": ["SQLi"],
            "coraza_anomaly_score": 5,
            "coraza_matched": True,
        }
        with patch.object(rtc, "_send_request", return_value=(200, {})), \
             patch.object(rtc, "_poll_audit_log", return_value=fake_coraza):
            output, matched = replay_record(self._sample_record, audit_log_available=True)
        assert matched is True
        assert output["coraza_fired_rule_ids"] == [942100]

    def test_unmatched_output_has_empty_coraza_fields(self):
        """Unmatched records still carry empty Coraza fields in the output dict."""
        with patch.object(rtc, "_send_request", return_value=(200, {})), \
             patch.object(rtc, "_poll_audit_log", return_value=None), \
             patch.object(rtc, "REQUEST_DELAY_SECONDS", 0):
            output, matched = replay_record(self._sample_record, audit_log_available=True)
        assert output["coraza_fired_rule_ids"] == []
        assert output["coraza_anomaly_score"] == 0
        assert output["coraza_matched"] is False

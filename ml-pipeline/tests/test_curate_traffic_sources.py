"""
Unit tests for curate_traffic_sources.py
Covers: malformed-row skipping and warning logging (Requirements 1.4)
"""

import io
import logging
import os
import sys
import tempfile

import pandas as pd
import pytest

# Make ml-pipeline importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from curate_traffic_sources import (
    parse_sentence_label_csv,
    parse_csic_csv,
    generate_synthetic_benign,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(tmp_path, filename, content: str) -> str:
    p = os.path.join(tmp_path, filename)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


# ---------------------------------------------------------------------------
# parse_sentence_label_csv — malformed row skipping
# ---------------------------------------------------------------------------

class TestParseSentenceLabelCsv:
    def test_valid_attack_row_yields_record(self, tmp_path):
        path = _write_csv(tmp_path, "test.csv", "Sentence,Label\n' OR 1=1,1\n")
        results = list(parse_sentence_label_csv(str(path), "test.csv", "sqli"))
        assert len(results) == 1
        record, skipped = results[0]
        assert not skipped
        assert record["label"] == "attack"
        assert record["attack_family"] == "sqli"

    def test_valid_benign_row_yields_record(self, tmp_path):
        path = _write_csv(tmp_path, "test.csv", "Sentence,Label\nhello world,0\n")
        results = list(parse_sentence_label_csv(str(path), "test.csv", "sqli"))
        record, skipped = results[0]
        assert not skipped
        assert record["label"] == "benign"
        assert record["attack_family"] == "benign"

    def test_empty_sentence_is_skipped(self, tmp_path, caplog):
        path = _write_csv(tmp_path, "test.csv", "Sentence,Label\n,1\n")
        with caplog.at_level(logging.WARNING):
            results = list(parse_sentence_label_csv(str(path), "test.csv", "sqli"))
        _, skipped = results[0]
        assert skipped
        assert "empty or null Sentence" in caplog.text

    def test_malformed_label_is_skipped(self, tmp_path, caplog):
        path = _write_csv(tmp_path, "test.csv", "Sentence,Label\n' OR 1=1,bad_label\n")
        with caplog.at_level(logging.WARNING):
            results = list(parse_sentence_label_csv(str(path), "test.csv", "sqli"))
        _, skipped = results[0]
        assert skipped
        assert "malformed Label" in caplog.text

    def test_unexpected_label_value_is_skipped(self, tmp_path, caplog):
        path = _write_csv(tmp_path, "test.csv", "Sentence,Label\n' OR 1=1,99\n")
        with caplog.at_level(logging.WARNING):
            results = list(parse_sentence_label_csv(str(path), "test.csv", "sqli"))
        _, skipped = results[0]
        assert skipped
        assert "unexpected Label value" in caplog.text

    def test_mixed_rows_skips_only_bad(self, tmp_path, caplog):
        csv_content = "Sentence,Label\ngood payload,1\n,1\nbad label,xyz\nanother good,0\n"
        path = _write_csv(tmp_path, "test.csv", csv_content)
        with caplog.at_level(logging.WARNING):
            results = list(parse_sentence_label_csv(str(path), "test.csv", "sqli"))
        skipped_count = sum(1 for _, s in results if s)
        good_count = sum(1 for _, s in results if not s)
        assert skipped_count == 2
        assert good_count == 2

    def test_warning_includes_row_index_and_filename(self, tmp_path, caplog):
        path = _write_csv(tmp_path, "myfile.csv", "Sentence,Label\n,1\n")
        with caplog.at_level(logging.WARNING):
            list(parse_sentence_label_csv(str(path), "myfile.csv", "sqli"))
        assert "myfile.csv" in caplog.text

    def test_all_required_fields_present_in_record(self, tmp_path):
        path = _write_csv(tmp_path, "test.csv", "Sentence,Label\n<script>alert(1)</script>,1\n")
        results = list(parse_sentence_label_csv(str(path), "test.csv", "xss"))
        record, skipped = results[0]
        assert not skipped
        for field in ("request_id", "method", "uri", "headers", "body", "label", "attack_family"):
            assert field in record


# ---------------------------------------------------------------------------
# parse_csic_csv — malformed row skipping
# ---------------------------------------------------------------------------

class TestParseCsicCsv:
    def test_valid_attack_row(self, tmp_path):
        csv = "Method,URL,classification\nGET,/index.html?id=1' OR 1=1,Anomalous\n"
        path = _write_csv(tmp_path, "csic.csv", csv)
        results = list(parse_csic_csv(str(path), "csic.csv"))
        record, skipped = results[0]
        assert not skipped
        assert record["label"] == "attack"

    def test_valid_benign_row(self, tmp_path):
        csv = "Method,URL,classification\nGET,/index.html,Normal\n"
        path = _write_csv(tmp_path, "csic.csv", csv)
        results = list(parse_csic_csv(str(path), "csic.csv"))
        record, skipped = results[0]
        assert not skipped
        assert record["label"] == "benign"

    def test_missing_method_is_skipped(self, tmp_path, caplog):
        csv = "Method,URL,classification\n,/index.html,Normal\n"
        path = _write_csv(tmp_path, "csic.csv", csv)
        with caplog.at_level(logging.WARNING):
            results = list(parse_csic_csv(str(path), "csic.csv"))
        _, skipped = results[0]
        assert skipped
        assert "missing Method" in caplog.text

    def test_missing_url_is_skipped(self, tmp_path, caplog):
        csv = "Method,URL,classification\nGET,,Normal\n"
        path = _write_csv(tmp_path, "csic.csv", csv)
        with caplog.at_level(logging.WARNING):
            results = list(parse_csic_csv(str(path), "csic.csv"))
        _, skipped = results[0]
        assert skipped
        assert "missing URL" in caplog.text

    def test_missing_required_columns_skips_file(self, tmp_path, caplog):
        csv = "Method,URL\nGET,/index.html\n"
        path = _write_csv(tmp_path, "csic.csv", csv)
        with caplog.at_level(logging.WARNING):
            results = list(parse_csic_csv(str(path), "csic.csv"))
        assert len(results) == 0
        assert "missing required columns" in caplog.text


# ---------------------------------------------------------------------------
# generate_synthetic_benign
# ---------------------------------------------------------------------------

class TestGenerateSyntheticBenign:
    def test_generates_at_least_requested_count(self):
        records = generate_synthetic_benign(100)
        assert len(records) >= 100

    def test_all_records_are_benign(self):
        records = generate_synthetic_benign(50)
        assert all(r["label"] == "benign" for r in records)
        assert all(r["attack_family"] == "benign" for r in records)

    def test_all_required_fields_present(self):
        records = generate_synthetic_benign(10)
        for r in records:
            for field in ("request_id", "method", "uri", "headers", "body", "label", "attack_family"):
                assert field in r

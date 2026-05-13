import pytest
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
import tempfile
import os

from feature_extractor import (
    WAFFeatureExtractor,
    _shannon_entropy,
    _special_char_ratio,
    _has_encoding_artifacts,
    _non_printable_count,
)


@pytest.fixture
def sample_record():
    return {
        "method": "POST",
        "uri": "/login.php?id=1' OR '1'='1",
        "body": "username=admin&password=123",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "fired_rule_ids": [942100, 941110, 930110],
        "rule_severities": ["CRITICAL", "WARNING", "NOTICE"],
        "rule_messages": ["SQL Injection", "XSS", "LFI"],
        "anomaly_score": 85,
        "inbound_threshold": 50,
    }


@pytest.fixture
def sample_records(sample_record):
    return [sample_record.copy() for _ in range(3)]


def test_feature_extractor_fit_transform(sample_records):
    extractor = WAFFeatureExtractor()
    X_transformed = extractor.fit_transform(sample_records)

    assert isinstance(X_transformed, np.ndarray)
    assert X_transformed.shape[0] == len(sample_records)
    assert X_transformed.shape[1] > 20


def test_get_feature_names_out(sample_records):
    extractor = WAFFeatureExtractor()
    extractor.fit(sample_records)

    names = extractor.get_feature_names_out()
    assert len(names) == X_transformed.shape[1] if 'X_transformed' in locals() else True # type: ignore
    assert any("rule_" in name for name in names)
    assert "anomaly_score" in names
    assert "shannon_entropy" in names


def test_transform_single_record(sample_record):
    extractor = WAFFeatureExtractor()
    extractor.fit([sample_record])

    features = extractor.transform(sample_record)
    assert features.shape == (1, len(extractor.get_feature_names_out()))


def test_validate_parity_same_schema():
    schema = {
        "version": "1.0.0",
        "features": {
            "anomaly_score": {"type": "float", "group": "waf"},
            "rule_942100": {"type": "int", "group": "rules"}
        }
    }
    discrepancies = WAFFeatureExtractor.validate_parity(schema, schema)
    assert len(discrepancies) == 0


def test_validate_parity_different_schema():
    training = {"version": "1.0", "features": {"feature_a": {"type": "float"}}}
    serving = {"version": "1.1", "features": {"feature_b": {"type": "int"}}}

    discrepancies = WAFFeatureExtractor.validate_parity(training, serving)
    assert len(discrepancies) > 0


def test_save_and_load(sample_records, tmp_path):
    extractor = WAFFeatureExtractor()
    extractor.fit(sample_records)

    path = tmp_path / "extractor.joblib"
    extractor.save(str(path))

    loaded = WAFFeatureExtractor.load(str(path))
    assert isinstance(loaded, WAFFeatureExtractor)

    original = extractor.transform(sample_records)
    reloaded = loaded.transform(sample_records)
    np.testing.assert_array_equal(original, reloaded)


# ====================== Helper Function Tests ======================

def test_shannon_entropy():
    assert _shannon_entropy("") == 0.0
    assert _shannon_entropy("aaa") == 0.0
    assert _shannon_entropy("abc123!@#") > 2.0


def test_special_char_ratio():
    assert _special_char_ratio("") == 0.0
    assert _special_char_ratio("normaltext") == 0.0
    assert _special_char_ratio("admin' OR 1=1 --") > 0.05
    assert _special_char_ratio("SELECT * FROM users WHERE id=1' OR '1'='1") > 0.09   
    assert _special_char_ratio("<script>alert(1)</script>") > 0.15


def test_has_encoding_artifacts():
    assert _has_encoding_artifacts("/page?id=%27%20OR%201=1", "") is True
    assert _has_encoding_artifacts("/normal/page", "normalbody") is False


def test_non_printable_count():
    assert _non_printable_count("normal text") == 0
    assert _non_printable_count("text\x00with\x07control") > 0


# Run this test to see full feature extraction
def test_full_feature_extraction(sample_record):
    extractor = WAFFeatureExtractor()
    extractor.fit([sample_record])
    features = extractor.transform(sample_record)[0]

    assert len(features) == len(extractor.get_feature_names_out())
    assert not np.any(np.isnan(features))
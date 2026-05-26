import json
import tempfile
from pathlib import Path

import numpy as np
import pytest

from miss_feature_extractor import MissModelFeatureExtractor


@pytest.fixture
def sample_signatures(tmp_path):
    signatures = [
        {
            "id": "sql_injection",
            "patterns": ["select", "union", "1=1"]
        },
        {
            "id": "xss",
            "patterns": ["<script", "onerror="]
        }
    ]
    
    sig_path = tmp_path / "test_signatures.json"
    sig_path.write_text(json.dumps(signatures))
    return str(sig_path)


@pytest.fixture
def fitted_extractor(sample_signatures):
    extractor = MissModelFeatureExtractor(sample_signatures)
    extractor.fit([])
    return extractor


def test_init():
    extractor = MissModelFeatureExtractor("dummy_path.json")
    assert extractor.regex_signatures_path == "dummy_path.json"
    assert extractor.signatures_ is None


def test_fit_and_feature_names(sample_signatures):
    extractor = MissModelFeatureExtractor(sample_signatures)
    extractor.fit([])
    
    # With 2 categories, we expect exactly 43 features
    assert len(extractor.feature_names_) == 43
    assert "sig_count_sql_injection" in extractor.feature_names_
    assert "req_uri_length" in extractor.feature_names_
    assert "content_entropy" in extractor.feature_names_


def test_transform_single_dict(fitted_extractor):
    record = {
        "method": "POST",
        "uri": "/api/login?user=admin'--",
        "body": "<script>alert(1)</script>",
        "headers": {"User-Agent": "sqlmap"}
    }
    
    features = fitted_extractor.transform(record)
    assert features.shape == (1, len(fitted_extractor.feature_names_))
    assert features.dtype == np.float64


def test_transform_list(fitted_extractor):
    records = [
        {"method": "GET", "uri": "/", "body": "", "headers": {}},
        {"method": "POST", "uri": "/search?q=1' OR '1'='1", "body": "", "headers": {}}
    ]
    
    features = fitted_extractor.transform(records)
    assert features.shape == (2, len(fitted_extractor.feature_names_))


def test_shannon_entropy():
    assert MissModelFeatureExtractor._shannon_entropy("") == 0.0
    # "aaa" has entropy 0 (all same characters)
    assert MissModelFeatureExtractor._shannon_entropy("aaa") == 0.0
    # Different characters should have positive entropy
    assert MissModelFeatureExtractor._shannon_entropy("abc123!@#") > 2.0


def test_evasion_detection():
    text = "admin%27%20OR%20%271%27%3D%271"
    assert MissModelFeatureExtractor._count_url_encoding(text) > 0
    assert MissModelFeatureExtractor._has_double_encoding("%2527") is True


def test_sql_detection():
    text = "SELECT * FROM users WHERE id=1 UNION SELECT"
    assert MissModelFeatureExtractor._count_sql_keywords(text) >= 2


def test_save_load(tmp_path, sample_signatures):
    extractor = MissModelFeatureExtractor(sample_signatures)
    extractor.fit([])
    
    model_path = tmp_path / "extractor.joblib"
    extractor.save(str(model_path))
    
    loaded = MissModelFeatureExtractor.load(str(model_path))
    assert isinstance(loaded, MissModelFeatureExtractor)
    assert loaded.feature_names_ is not None
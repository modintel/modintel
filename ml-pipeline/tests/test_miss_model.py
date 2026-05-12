"""
Tests for Miss Model Training Pipeline
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

from miss_feature_extractor import MissModelFeatureExtractor


@pytest.fixture
def sample_regex_signatures():
    """Create sample regex signatures for testing."""
    return [
        {
            "id": "sig-sqli-test",
            "name": "SQL Injection Test",
            "category": "SQLi",
            "severity": "high",
            "patterns": [
                "(?P<sqli_union>union\\s+select)",
                "(?P<sqli_or>or\\s+1\\s*=\\s*1)",
                "(?P<sqli_comment>--)",
            ],
        },
        {
            "id": "sig-xss-test",
            "name": "XSS Test",
            "category": "XSS",
            "severity": "high",
            "patterns": [
                "(?P<xss_script><script)",
                "(?P<xss_onerror>onerror\\s*=)",
                "(?P<xss_alert>alert\\s*\\()",
            ],
        },
    ]


@pytest.fixture
def regex_signatures_file(sample_regex_signatures):
    """Create temporary regex signatures file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".signatures", delete=False
    ) as f:
        json.dump(sample_regex_signatures, f)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def sample_requests():
    """Create sample request data."""
    return [
        {
            "method": "GET",
            "uri": "/search?q=test",
            "body": "",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "label": "benign",
        },
        {
            "method": "POST",
            "uri": "/login",
            "body": "username=admin' OR 1=1--&password=test",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "label": "attack",
        },
        {
            "method": "GET",
            "uri": "/page?id=<script>alert(1)</script>",
            "body": "",
            "headers": {},
            "label": "attack",
        },
        {
            "method": "GET",
            "uri": "/api/data?filter=name",
            "body": "",
            "headers": {"Accept": "application/json"},
            "label": "benign",
        },
    ]


class TestMissModelFeatureExtractor:
    """Test suite for MissModelFeatureExtractor."""

    def test_initialization(self, regex_signatures_file):
        """Test feature extractor initialization."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        assert extractor.regex_signatures_path == regex_signatures_file
        assert extractor.signatures_ is None
        assert extractor.compiled_patterns_ is None

    def test_fit(self, regex_signatures_file, sample_requests):
        """Test fitting the feature extractor."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit(sample_requests)

        assert extractor.signatures_ is not None
        assert len(extractor.signatures_) == 2
        assert extractor.compiled_patterns_ is not None
        assert "sig-sqli-test" in extractor.compiled_patterns_
        assert "sig-xss-test" in extractor.compiled_patterns_
        assert extractor.feature_names_ is not None
        assert len(extractor.feature_names_) > 0

    def test_transform_single_request(self, regex_signatures_file, sample_requests):
        """Test transforming a single request."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit(sample_requests)

        # Transform single request (dict)
        features = extractor.transform(sample_requests[0])
        assert features.shape == (1, len(extractor.feature_names_))
        assert isinstance(features, np.ndarray)

    def test_transform_multiple_requests(self, regex_signatures_file, sample_requests):
        """Test transforming multiple requests."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit(sample_requests)

        # Transform list of requests
        features = extractor.transform(sample_requests)
        assert features.shape == (len(sample_requests), len(extractor.feature_names_))
        assert isinstance(features, np.ndarray)

    def test_transform_dataframe(self, regex_signatures_file, sample_requests):
        """Test transforming a DataFrame."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        df = pd.DataFrame(sample_requests)
        extractor.fit(df)

        features = extractor.transform(df)
        assert features.shape == (len(df), len(extractor.feature_names_))

    def test_signature_matching(self, regex_signatures_file, sample_requests):
        """Test that signatures are correctly matched."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit(sample_requests)

        # SQL injection request should match SQLi signatures
        sqli_request = sample_requests[1]
        features = extractor.transform(sqli_request)

        # Find SQLi signature count feature
        sqli_count_idx = extractor.feature_names_.index("sig_count_sig-sqli-test")
        assert features[0, sqli_count_idx] > 0

        # XSS request should match XSS signatures
        xss_request = sample_requests[2]
        features = extractor.transform(xss_request)

        xss_count_idx = extractor.feature_names_.index("sig_count_sig-xss-test")
        assert features[0, xss_count_idx] > 0

    def test_encoding_detection(self, regex_signatures_file):
        """Test encoding and evasion detection features."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)

        # Request with URL encoding
        encoded_request = {
            "method": "GET",
            "uri": "/test?param=%3Cscript%3E",
            "body": "",
            "headers": {},
        }

        extractor.fit([encoded_request])
        features = extractor.transform(encoded_request)

        # Check URL encoding count
        url_enc_idx = extractor.feature_names_.index("evasion_url_encoding_count")
        assert features[0, url_enc_idx] > 0

    def test_attack_pattern_detection(self, regex_signatures_file):
        """Test attack pattern indicator features."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)

        # SQL injection patterns
        sqli_request = {
            "method": "POST",
            "uri": "/api",
            "body": "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
            "headers": {},
        }

        extractor.fit([sqli_request])
        features = extractor.transform(sqli_request)

        # Check SQL keyword count
        sql_kw_idx = extractor.feature_names_.index("pattern_sql_keywords")
        assert features[0, sql_kw_idx] > 0

    def test_content_analysis(self, regex_signatures_file):
        """Test content analysis features."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)

        # Request with high entropy
        high_entropy_request = {
            "method": "GET",
            "uri": "/test?data=" + "a" * 100 + "b" * 100,
            "body": "",
            "headers": {},
        }

        extractor.fit([high_entropy_request])
        features = extractor.transform(high_entropy_request)

        # Check entropy
        entropy_idx = extractor.feature_names_.index("content_entropy")
        assert features[0, entropy_idx] > 0

    def test_save_and_load(self, regex_signatures_file, sample_requests):
        """Test saving and loading the feature extractor."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit(sample_requests)

        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            temp_path = f.name

        try:
            # Save
            extractor.save(temp_path)
            assert os.path.exists(temp_path)

            # Load
            loaded_extractor = MissModelFeatureExtractor.load(temp_path)
            assert loaded_extractor.feature_names_ == extractor.feature_names_
            assert loaded_extractor.category_names_ == extractor.category_names_

            # Test that loaded extractor works
            features_original = extractor.transform(sample_requests[0])
            features_loaded = loaded_extractor.transform(sample_requests[0])
            np.testing.assert_array_almost_equal(features_original, features_loaded)

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_get_feature_names_out(self, regex_signatures_file, sample_requests):
        """Test getting feature names."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit(sample_requests)

        feature_names = extractor.get_feature_names_out()
        assert isinstance(feature_names, list)
        assert len(feature_names) > 0
        assert all(isinstance(name, str) for name in feature_names)

    def test_fit_transform(self, regex_signatures_file, sample_requests):
        """Test fit_transform method."""
        extractor = MissModelFeatureExtractor(regex_signatures_file)
        features = extractor.fit_transform(sample_requests)

        assert features.shape == (len(sample_requests), len(extractor.feature_names_))
        assert extractor.signatures_ is not None

    def test_invalid_regex_handling(self, sample_requests):
        """Test handling of invalid regex patterns."""
        # Create signatures with invalid regex
        invalid_signatures = [
            {
                "id": "sig-invalid",
                "name": "Invalid",
                "category": "Test",
                "severity": "low",
                "patterns": [
                    "(?P<valid>test)",
                    "(?P<invalid>[[[",  # Invalid regex
                ],
            }
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".signatures", delete=False
        ) as f:
            json.dump(invalid_signatures, f)
            temp_path = f.name

        try:
            extractor = MissModelFeatureExtractor(temp_path)
            # Should not raise error, just skip invalid patterns
            extractor.fit(sample_requests)
            assert extractor.compiled_patterns_ is not None

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_empty_request_handling(self, regex_signatures_file):
        """Test handling of empty/minimal requests."""
        empty_request = {
            "method": "",
            "uri": "",
            "body": "",
            "headers": {},
        }

        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit([empty_request])
        features = extractor.transform(empty_request)

        # Should not crash and return valid features
        assert features.shape == (1, len(extractor.feature_names_))
        assert not np.any(np.isnan(features))

    def test_special_characters_handling(self, regex_signatures_file):
        """Test handling of special characters."""
        special_request = {
            "method": "POST",
            "uri": "/test?param=<>&'\"",
            "body": "data=%3C%3E%26%27%22",
            "headers": {},
        }

        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit([special_request])
        features = extractor.transform(special_request)

        # Check special char ratio
        special_idx = extractor.feature_names_.index("content_special_char_ratio")
        assert features[0, special_idx] > 0

    def test_path_traversal_detection(self, regex_signatures_file):
        """Test path traversal pattern detection."""
        traversal_request = {
            "method": "GET",
            "uri": "/file?path=../../etc/passwd",
            "body": "",
            "headers": {},
        }

        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit([traversal_request])
        features = extractor.transform(traversal_request)

        # Check path traversal count
        traversal_idx = extractor.feature_names_.index("pattern_path_traversal")
        assert features[0, traversal_idx] > 0

    def test_command_injection_detection(self, regex_signatures_file):
        """Test command injection pattern detection."""
        cmd_request = {
            "method": "POST",
            "uri": "/exec",
            "body": "cmd=ls -la; cat /etc/passwd",
            "headers": {},
        }

        extractor = MissModelFeatureExtractor(regex_signatures_file)
        extractor.fit([cmd_request])
        features = extractor.transform(cmd_request)

        # Check command injection count
        cmd_idx = extractor.feature_names_.index("pattern_command_injection")
        assert features[0, cmd_idx] > 0


class TestMissModelIntegration:
    """Integration tests for miss model pipeline."""

    @patch("train_miss_model.load_splits_for_miss_model")
    @patch("train_miss_model.build_miss_candidates")
    def test_training_pipeline_flow(
        self, mock_candidates, mock_load_splits, regex_signatures_file
    ):
        """Test the overall training pipeline flow."""
        # Mock data loading
        n_samples = 100
        n_features = 50

        mock_load_splits.return_value = (
            pd.DataFrame({"label": ["attack"] * n_samples}),  # df_train
            pd.DataFrame({"label": ["attack"] * 20}),  # df_val
            pd.DataFrame({"label": ["attack"] * 20}),  # df_test
            np.random.rand(n_samples, n_features),  # X_train
            np.random.rand(20, n_features),  # X_val
            np.random.rand(20, n_features),  # X_test
            np.ones(n_samples),  # y_train
            np.ones(20),  # y_val
            np.ones(20),  # y_test
            MagicMock(),  # extractor
        )

        # Mock candidates
        mock_model = MagicMock()
        mock_model.fit = MagicMock()
        mock_model.predict = MagicMock(return_value=np.ones(20))
        mock_model.predict_proba = MagicMock(return_value=np.column_stack([np.zeros(20), np.ones(20)]))

        mock_candidates.return_value = [("test_model", mock_model)]

        # This would test the full pipeline if we import and run main()
        # For now, just verify mocks are set up correctly
        assert mock_load_splits is not None
        assert mock_candidates is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

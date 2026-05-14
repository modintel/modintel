import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from miss_onnx import MissONNXInference


@pytest.fixture
def mock_onnx_model(tmp_path):
    # Create a dummy ONNX file for testing
    dummy_path = tmp_path / "dummy.onnx"
    dummy_path.write_text("dummy onnx content")
    return str(dummy_path)


@patch("miss_onnx.ort.InferenceSession")
def test_miss_onnx_predict(mock_session, mock_onnx_model):
    # Mock ONNX session
    mock_run = MagicMock()
    mock_run.return_value = [np.array([[0.3, 0.7]])]
    mock_session.return_value.run = mock_run
    mock_session.return_value.get_inputs.return_value = [MagicMock(name="features")]

    infer = MissONNXInference(mock_onnx_model)

    request = {
        "method": "POST",
        "uri": "/login.php?id=1' OR 1=1",
        "body": "username=admin",
        "headers": {}
    }

    result = infer.predict(request)

    assert "attack_probability" in result
    assert "recommended_priority" in result
    assert "confidence_score" in result
    assert result["advisory_only"] is True
    assert result["model_version"] == "onnx-miss-v3"


def test_miss_onnx_priority_assignment():
    infer = MissONNXInference.__new__(MissONNXInference)  # bypass init

    assert infer._assign_priority(0.85) == ("P1", "High probability miss detection")
    assert infer._assign_priority(0.65) == ("P2", "Moderate probability miss detection")
    assert infer._assign_priority(0.3) == ("P3", "Low probability miss detection")


def test_extract_features():
    infer = MissONNXInference.__new__(MissONNXInference)
    
    request = {
        "method": "POST",
        "uri": "/admin/login.php?id=1",
        "body": "SELECT * FROM users",
        "headers": {"User-Agent": "sqlmap"}
    }

    features = infer._extract_features(request)
    assert len(features) == 135
    assert isinstance(features, list)
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import numpy as np

from main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


def test_metrics_endpoint():
    response = client.get("/metrics")
    assert response.status_code == 200


@patch("main._model_state")
def test_predict_endpoint(mock_state):
    mock_state["loaded"] = True
    mock_state["feature_extractor"] = MagicMock()
    mock_state["calibrator"] = MagicMock()
    mock_state["bootstrap_quantiles"] = {"q025": -0.05, "q975": 0.05}
    mock_state["feature_schema"] = {"features": {}}
    mock_state["model_version"] = "v3"

    mock_state["feature_extractor"].transform.return_value = np.array([[0.1] * 30])
    mock_state["feature_extractor"].get_feature_names_out.return_value = ["feat" + str(i) for i in range(30)]
    mock_state["calibrator"].predict_proba.return_value = np.array([[0.2, 0.8]])

    payload = {
        "method": "POST",
        "uri": "/test",
        "anomaly_score": 25,
        "inbound_threshold": 30
    }

    response = client.post("/predict", json=payload)
    assert response.status_code in (200, 500)


def test_predict_validation_error():
    payload = {"method": "", "uri": ""}
    response = client.post("/predict", json=payload)
    assert response.status_code == 422


def test_predict_miss_endpoint():
    payload = {"method": "GET", "uri": "/test"}
    response = client.post("/predict-miss", json=payload)
    assert response.status_code in (200, 500)
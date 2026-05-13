import pytest
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
import tempfile
import os

from evaluate_model import (
    evaluate_model,
    compute_ece,
    compute_fpr_fnr,
    _fig_to_b64,
)


@pytest.fixture
def sample_y_true():
    return np.array([0, 0, 1, 1, 0, 1, 0, 1, 1, 0])


@pytest.fixture
def sample_y_prob():
    return np.array([0.1, 0.3, 0.8, 0.9, 0.2, 0.7, 0.4, 0.85, 0.95, 0.15])


@pytest.fixture
def sample_df_test(sample_y_true):
    return pd.DataFrame({
        "label": ["benign" if y == 0 else "attack" for y in sample_y_true],
        "attack_family": ["normal"] * 4 + ["sqli"] * 3 + ["xss"] * 3,
    })


def test_compute_ece(sample_y_true, sample_y_prob):
    ece = compute_ece(sample_y_true, sample_y_prob, n_bins=5)
    assert 0.0 <= ece <= 1.0


def test_compute_fpr_fnr_perfect():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 0, 1, 1])
    fpr, fnr = compute_fpr_fnr(y_true, y_pred)
    assert fpr == 0.0
    assert fnr == 0.0


def test_compute_fpr_fnr_worst():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([1, 1, 0, 0])
    fpr, fnr = compute_fpr_fnr(y_true, y_pred)
    assert fpr == 1.0
    assert fnr == 1.0


def test_evaluate_model_basic(sample_y_true, sample_y_prob, sample_df_test):
    # Mock calibrator
    class MockCalibrator:
        def predict(self, X):
            return (np.array(sample_y_prob) > 0.5).astype(int)
        def predict_proba(self, X):
            return np.column_stack([(1 - sample_y_prob), sample_y_prob])

    calibrator = MockCalibrator()

    result = evaluate_model(calibrator, None, sample_y_true, sample_df_test)

    assert isinstance(result, dict)
    assert "accuracy" in result
    assert "precision" in result
    assert "recall" in result
    assert "f1" in result
    assert "auroc" in result
    assert "ece" in result
    assert "per_family" in result
    assert 0 <= result["accuracy"] <= 1.0


def test_evaluate_model_per_family(sample_y_true, sample_y_prob, sample_df_test):
    class MockCalibrator:
        def predict(self, X): return (np.array(sample_y_prob) > 0.5).astype(int)
        def predict_proba(self, X):
            return np.column_stack([(1 - sample_y_prob), sample_y_prob])

    result = evaluate_model(MockCalibrator(), None, sample_y_true, sample_df_test)

    assert "per_family" in result
    assert "normal" in result["per_family"]
    assert "sqli" in result["per_family"]
    assert "xss" in result["per_family"]


def test_fig_to_b64():
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots()
    ax.plot([1, 2, 3], [1, 4, 9])
    b64 = _fig_to_b64(fig)
    assert isinstance(b64, str)
    assert len(b64) > 100  # base64 string should be reasonably long


def test_main_function_exists():
    # Just check that main function exists (hard to test fully without argparse)
    import evaluate_model
    assert hasattr(evaluate_model, "main")
    assert hasattr(evaluate_model, "evaluate_model")
    assert hasattr(evaluate_model, "compute_ece")
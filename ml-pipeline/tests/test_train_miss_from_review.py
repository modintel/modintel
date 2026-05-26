import numpy as np
import pytest

from train_miss_from_review import (
    compute_metrics,
    composite_score,
    _json_default,
    sha256_file
)


def test_compute_metrics():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 1, 1])
    y_prob = np.array([0.1, 0.6, 0.8, 0.9])
    
    metrics = compute_metrics(y_true, y_pred, y_prob)
    
    assert metrics["accuracy"] == 0.75
    assert abs(metrics["precision"] - 0.6666666666666666) < 0.0001  # Use approximate comparison
    assert metrics["recall"] == 1.0
    assert "f1" in metrics
    assert "auroc" in metrics
    assert "confusion_matrix" in metrics
    assert metrics["confusion_matrix"]["tp"] == 2
    assert metrics["confusion_matrix"]["fp"] == 1
    assert metrics["confusion_matrix"]["tn"] == 1
    assert metrics["confusion_matrix"]["fn"] == 0


def test_composite_score():
    metrics = {
        "recall": 0.9,
        "precision": 0.8,
        "f1": 0.85,
        "auroc": 0.95
    }
    score = composite_score(metrics)
    # Weighted sum: 0.35*0.9 + 0.30*0.8 + 0.15*0.85 + 0.20*0.95
    expected = 0.35*0.9 + 0.30*0.8 + 0.15*0.85 + 0.20*0.95
    assert abs(score - expected) < 0.0001


def test_json_default():
    arr = np.array([1, 2, 3])
    assert _json_default(arr) == [1, 2, 3]
    
    assert _json_default(np.int64(42)) == 42
    assert _json_default(np.float64(3.14)) == 3.14


def test_sha256_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    
    hash_val = sha256_file(str(test_file))
    assert len(hash_val) == 64  # SHA-256 hex digest length
    assert isinstance(hash_val, str)
import pytest
import sys
from pathlib import Path

# Robust path setup
ml_pipeline_path = Path("ml-pipeline").absolute()
if str(ml_pipeline_path) not in sys.path:
    sys.path.insert(0, str(ml_pipeline_path))

try:
    from feature_extractor import WAFFeatureExtractor
    from evaluate_model import compute_ece
    IMPORT_SUCCESS = True
except ImportError:
    IMPORT_SUCCESS = False


def test_ml_modules_can_be_imported():
    """Basic check that ML modules are importable"""
    assert IMPORT_SUCCESS, "Could not import feature_extractor or evaluate_model"


@pytest.mark.skipif(not IMPORT_SUCCESS, reason="ML modules not available")
def test_feature_extractor_smoke_test():
    """Simple smoke test for feature extractor"""
    import numpy as np   # ← Fixed: Import inside the test

    record = {
        "method": "POST",
        "uri": "/test.php?id=1",
        "body": "test=data",
        "fired_rule_ids": [942100],
        "anomaly_score": 45,
        "inbound_threshold": 30,
    }

    extractor = WAFFeatureExtractor()
    extractor.fit([record])
    features = extractor.transform(record)

    assert isinstance(features, np.ndarray)
    assert features.shape[1] > 20


@pytest.mark.skipif(not IMPORT_SUCCESS, reason="ML modules not available")
def test_compute_ece_basic():
    """Test ECE function"""
    import numpy as np

    y_true = np.array([0, 0, 1, 1])
    y_prob = np.array([0.1, 0.2, 0.8, 0.9])
    
    ece = compute_ece(y_true, y_prob, n_bins=4)
    assert 0.0 <= ece <= 1.0


def test_ml_pipeline_files_exist():
    """Check important files exist"""
    ml_path = Path("ml-pipeline")
    assert (ml_path / "feature_extractor.py").exists(), "feature_extractor.py missing"
    assert (ml_path / "evaluate_model.py").exists(), "evaluate_model.py missing"
    assert (ml_path / "train_model.py").exists(), "train_model.py missing"
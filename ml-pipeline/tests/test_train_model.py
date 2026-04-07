"""
Unit tests for train_model.py
Covers: composite score selection logic and metric gate computations (Requirements 5.5, 5.6)
"""

import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from train_model import (
    composite_score,
    compute_ece,
    W_F1,
    W_ECE,
    W_AUROC,
    W_FPR,
)

try:
    from sklearn.metrics import brier_score_loss
except ImportError:
    brier_score_loss = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _metrics(f1=0.0, ece=0.0, auroc=0.0, fpr=0.0):
    """Build a minimal metrics dict for composite_score."""
    return {"f1": f1, "ece": ece, "auroc": auroc, "fpr": fpr}


# ---------------------------------------------------------------------------
# composite_score — selection logic (Requirement 5.5)
# ---------------------------------------------------------------------------

class TestCompositeScore:
    def test_formula_matches_weights(self):
        m = _metrics(f1=0.8, ece=0.1, auroc=0.9, fpr=0.05)
        expected = W_F1 * 0.8 + W_ECE * (1 - 0.1) + W_AUROC * 0.9 + W_FPR * (1 - 0.05)
        assert abs(composite_score(m) - expected) < 1e-9

    def test_perfect_model_scores_one(self):
        m = _metrics(f1=1.0, ece=0.0, auroc=1.0, fpr=0.0)
        assert abs(composite_score(m) - 1.0) < 1e-9

    def test_worst_model_scores_zero(self):
        m = _metrics(f1=0.0, ece=1.0, auroc=0.0, fpr=1.0)
        assert abs(composite_score(m) - 0.0) < 1e-9

    def test_higher_f1_wins_when_other_metrics_equal(self):
        base = dict(ece=0.1, auroc=0.8, fpr=0.1)
        low = composite_score({**base, "f1": 0.6})
        high = composite_score({**base, "f1": 0.9})
        assert high > low

    def test_lower_ece_wins_when_other_metrics_equal(self):
        base = dict(f1=0.8, auroc=0.8, fpr=0.1)
        bad_cal = composite_score({**base, "ece": 0.4})
        good_cal = composite_score({**base, "ece": 0.05})
        assert good_cal > bad_cal

    def test_higher_auroc_wins_when_other_metrics_equal(self):
        base = dict(f1=0.8, ece=0.1, fpr=0.1)
        low = composite_score({**base, "auroc": 0.7})
        high = composite_score({**base, "auroc": 0.95})
        assert high > low

    def test_lower_fpr_wins_when_other_metrics_equal(self):
        base = dict(f1=0.8, ece=0.1, auroc=0.85)
        high_fpr = composite_score({**base, "fpr": 0.3})
        low_fpr = composite_score({**base, "fpr": 0.05})
        assert low_fpr > high_fpr

    def test_selects_best_candidate_from_list(self):
        """Simulates the selection logic: argmax composite_score picks the right candidate."""
        candidates = [
            ("xgboost",  _metrics(f1=0.85, ece=0.08, auroc=0.92, fpr=0.05)),
            ("lgbm",     _metrics(f1=0.80, ece=0.12, auroc=0.88, fpr=0.07)),
            ("rf",       _metrics(f1=0.75, ece=0.15, auroc=0.84, fpr=0.10)),
            ("logreg",   _metrics(f1=0.70, ece=0.20, auroc=0.78, fpr=0.15)),
        ]
        scores = [(name, composite_score(m)) for name, m in candidates]
        best_name = max(scores, key=lambda x: x[1])[0]
        assert best_name == "xgboost"

    def test_selects_best_candidate_when_f1_differs_most(self):
        """Candidate with much higher F1 wins even if slightly worse on other metrics."""
        candidates = [
            ("a", _metrics(f1=0.95, ece=0.15, auroc=0.80, fpr=0.10)),
            ("b", _metrics(f1=0.60, ece=0.05, auroc=0.95, fpr=0.02)),
        ]
        scores = {name: composite_score(m) for name, m in candidates}
        assert scores["a"] > scores["b"]

    def test_score_is_bounded_between_zero_and_one(self):
        """All valid metric inputs should produce a score in [0, 1]."""
        for f1 in [0.0, 0.5, 1.0]:
            for ece in [0.0, 0.5, 1.0]:
                for auroc in [0.0, 0.5, 1.0]:
                    for fpr in [0.0, 0.5, 1.0]:
                        s = composite_score(_metrics(f1=f1, ece=ece, auroc=auroc, fpr=fpr))
                        assert 0.0 <= s <= 1.0, f"Score {s} out of bounds for inputs {f1},{ece},{auroc},{fpr}"


# ---------------------------------------------------------------------------
# compute_ece — metric gate computation (Requirement 5.5)
# ---------------------------------------------------------------------------

class TestComputeECE:
    def test_perfect_calibration_returns_zero(self):
        # Predicted probabilities equal empirical frequencies per bin
        # 10 samples: prob=0.05 → all negative → frac_pos=0.0, mean_pred=0.05 → ECE=0.05
        # Use perfectly calibrated: prob=0 for label=0, prob=1 for label=1
        y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        y_prob = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0])
        ece = compute_ece(y_true, y_prob)
        assert ece == pytest.approx(0.0, abs=1e-9)

    def test_worst_calibration_returns_one(self):
        # All positives predicted as 0, all negatives predicted as 1
        y_true = np.array([1, 1, 1, 1, 1, 0, 0, 0, 0, 0])
        y_prob = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0])
        ece = compute_ece(y_true, y_prob)
        assert ece == pytest.approx(1.0, abs=1e-9)

    def test_known_single_bin_value(self):
        # All samples fall in bin [0.4, 0.5): mean_pred=0.45, frac_pos=0.0 → ECE=0.45
        y_true = np.array([0, 0, 0, 0])
        y_prob = np.array([0.41, 0.42, 0.43, 0.44])
        ece = compute_ece(y_true, y_prob)
        expected = abs(np.mean([0.41, 0.42, 0.43, 0.44]) - 0.0)
        assert ece == pytest.approx(expected, abs=1e-6)

    def test_two_bins_known_value(self):
        # 4 samples in [0.0, 0.1): mean_pred=0.05, frac_pos=0.0 → contribution = 4/8 * 0.05
        # 4 samples in [0.9, 1.0]: mean_pred=0.95, frac_pos=1.0 → contribution = 4/8 * 0.05
        y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        y_prob = np.array([0.04, 0.05, 0.06, 0.05, 0.94, 0.95, 0.96, 0.95])
        ece = compute_ece(y_true, y_prob)
        low_mean = np.mean([0.04, 0.05, 0.06, 0.05])
        high_mean = np.mean([0.94, 0.95, 0.96, 0.95])
        expected = 0.5 * abs(low_mean - 0.0) + 0.5 * abs(high_mean - 1.0)
        assert ece == pytest.approx(expected, abs=1e-6)

    def test_ece_is_non_negative(self):
        rng = np.random.default_rng(0)
        y_true = rng.integers(0, 2, size=100)
        y_prob = rng.uniform(0, 1, size=100)
        assert compute_ece(y_true, y_prob) >= 0.0

    def test_ece_is_at_most_one(self):
        rng = np.random.default_rng(1)
        y_true = rng.integers(0, 2, size=100)
        y_prob = rng.uniform(0, 1, size=100)
        assert compute_ece(y_true, y_prob) <= 1.0

    def test_empty_bins_are_skipped(self):
        # All samples in one bin — should not raise and should return a valid float
        y_true = np.array([0, 1, 0, 1])
        y_prob = np.array([0.55, 0.56, 0.57, 0.58])
        ece = compute_ece(y_true, y_prob)
        assert isinstance(ece, float)
        assert 0.0 <= ece <= 1.0

    def test_last_bin_includes_upper_boundary(self):
        # Probability exactly 1.0 must fall in the last bin (not be excluded)
        y_true = np.array([1])
        y_prob = np.array([1.0])
        ece = compute_ece(y_true, y_prob)
        # mean_pred=1.0, frac_pos=1.0 → ECE=0
        assert ece == pytest.approx(0.0, abs=1e-9)


# ---------------------------------------------------------------------------
# brier_score — metric gate computation (Requirement 5.5)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(brier_score_loss is None, reason="sklearn not available")
class TestBrierScore:
    def test_perfect_predictions_score_zero(self):
        y_true = np.array([0, 0, 1, 1])
        y_prob = np.array([0.0, 0.0, 1.0, 1.0])
        assert brier_score_loss(y_true, y_prob) == pytest.approx(0.0, abs=1e-9)

    def test_worst_predictions_score_one(self):
        y_true = np.array([0, 0, 1, 1])
        y_prob = np.array([1.0, 1.0, 0.0, 0.0])
        assert brier_score_loss(y_true, y_prob) == pytest.approx(1.0, abs=1e-9)

    def test_uniform_half_probability_known_value(self):
        # All predictions = 0.5, half positive → Brier = 0.25
        y_true = np.array([0, 0, 1, 1])
        y_prob = np.array([0.5, 0.5, 0.5, 0.5])
        assert brier_score_loss(y_true, y_prob) == pytest.approx(0.25, abs=1e-9)

    def test_brier_score_is_non_negative(self):
        rng = np.random.default_rng(42)
        y_true = rng.integers(0, 2, size=200)
        y_prob = rng.uniform(0, 1, size=200)
        assert brier_score_loss(y_true, y_prob) >= 0.0

    def test_brier_score_is_at_most_one(self):
        rng = np.random.default_rng(7)
        y_true = rng.integers(0, 2, size=200)
        y_prob = rng.uniform(0, 1, size=200)
        assert brier_score_loss(y_true, y_prob) <= 1.0

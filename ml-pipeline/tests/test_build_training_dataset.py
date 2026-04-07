"""
Unit tests for build_training_dataset.py
Covers: quality gate abort conditions and split stratification (Requirements 3.5)
"""

import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from build_training_dataset import (
    gate_missing_fields,
    gate_duplicate_ids,
    gate_label_conflicts,
    run_quality_gates,
    stratified_split,
    REQUIRED_FIELDS,
    MISSING_FIELDS_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_df(n: int = 20, families: list = None) -> pd.DataFrame:
    """Build a minimal valid DataFrame with n rows."""
    if families is None:
        families = ["sqli"] * n
    rows = []
    for i in range(n):
        rows.append({
            "request_id": f"req-{i:04d}",
            "method": "GET",
            "uri": f"/test?id={i}",
            "headers": "{}",
            "body": "",
            "label": "attack" if i % 2 == 0 else "benign",
            "attack_family": families[i % len(families)],
            "coraza_fired_rule_ids": [942100],
            "coraza_rule_severities": ["CRITICAL"],
            "coraza_rule_messages": ["SQLi"],
            "coraza_anomaly_score": 5,
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# gate_missing_fields
# ---------------------------------------------------------------------------

class TestGateMissingFields:
    def test_passes_when_no_missing_fields(self):
        df = _make_df(20)
        assert gate_missing_fields(df) is None

    def test_fails_when_missing_exceeds_threshold(self):
        df = _make_df(20)
        # Null out 6 rows (30%) — well above 5% threshold
        df.loc[:5, "uri"] = None
        result = gate_missing_fields(df)
        assert result is not None
        assert "MISSING_FIELDS" in result

    def test_passes_when_missing_at_threshold_boundary(self):
        # Exactly 5% missing should pass (threshold is strictly >)
        df = _make_df(100)
        df.loc[:4, "uri"] = None  # 5 rows = exactly 5%
        assert gate_missing_fields(df) is None

    def test_fails_when_missing_just_above_threshold(self):
        df = _make_df(100)
        df.loc[:5, "uri"] = None  # 6 rows = 6%
        result = gate_missing_fields(df)
        assert result is not None


# ---------------------------------------------------------------------------
# gate_duplicate_ids
# ---------------------------------------------------------------------------

class TestGateDuplicateIds:
    def test_passes_with_unique_ids(self):
        df = _make_df(10)
        assert gate_duplicate_ids(df) is None

    def test_fails_with_duplicate_ids(self):
        df = _make_df(10)
        df.loc[5, "request_id"] = "req-0000"  # duplicate of row 0
        result = gate_duplicate_ids(df)
        assert result is not None
        assert "DUPLICATE_IDS" in result

    def test_failure_message_includes_sample_ids(self):
        df = _make_df(5)
        df.loc[4, "request_id"] = "req-0000"
        result = gate_duplicate_ids(df)
        assert "req-0000" in result


# ---------------------------------------------------------------------------
# gate_label_conflicts
# ---------------------------------------------------------------------------

class TestGateLabelConflicts:
    def test_passes_with_no_conflicts(self):
        df = _make_df(10)
        assert gate_label_conflicts(df) is None

    def test_fails_when_same_id_has_different_labels(self):
        df = _make_df(10)
        # Add a conflicting row: same request_id, different label
        conflict_row = df.iloc[0].copy()
        conflict_row["label"] = "benign" if df.iloc[0]["label"] == "attack" else "attack"
        df = pd.concat([df, pd.DataFrame([conflict_row])], ignore_index=True)
        result = gate_label_conflicts(df)
        assert result is not None
        assert "LABEL_CONFLICTS" in result


# ---------------------------------------------------------------------------
# run_quality_gates — abort conditions (Requirement 3.5)
# ---------------------------------------------------------------------------

class TestRunQualityGates:
    def test_returns_empty_list_for_clean_data(self):
        df = _make_df(30)
        assert run_quality_gates(df) == []

    def test_returns_all_failures(self):
        df = _make_df(20)
        # Trigger missing fields (>5%)
        df.loc[:1, "uri"] = None
        df.loc[:1, "method"] = None
        df.loc[:1, "body"] = None
        df.loc[:1, "headers"] = None
        # Trigger duplicate IDs
        df.loc[10, "request_id"] = "req-0000"
        # Trigger label conflict
        conflict = df.iloc[0].copy()
        conflict["label"] = "benign" if df.iloc[0]["label"] == "attack" else "attack"
        df = pd.concat([df, pd.DataFrame([conflict])], ignore_index=True)

        failures = run_quality_gates(df)
        gate_names = " ".join(failures)
        assert "MISSING_FIELDS" in gate_names
        assert "DUPLICATE_IDS" in gate_names
        assert "LABEL_CONFLICTS" in gate_names

    def test_single_gate_failure_returns_one_message(self):
        # Only trigger missing-fields gate (no duplicate IDs, no label conflicts)
        df = _make_df(100)
        df.loc[:5, "uri"] = None  # 6 rows = 6%, above 5% threshold
        failures = run_quality_gates(df)
        assert len(failures) == 1
        assert "MISSING_FIELDS" in failures[0]


# ---------------------------------------------------------------------------
# stratified_split — split ratios and stratification (Requirement 3.2)
# ---------------------------------------------------------------------------

class TestStratifiedSplit:
    def test_all_rows_assigned_a_split(self):
        df = _make_df(60, families=["sqli", "xss", "lfi"] * 20)
        result = stratified_split(df)
        assert result["split"].isin(["train", "validation", "test"]).all()

    def test_split_ratios_approximate_70_15_15(self):
        n = 300
        df = _make_df(n, families=["sqli", "xss", "lfi"] * 100)
        result = stratified_split(df)
        counts = result["split"].value_counts()
        total = len(result)
        assert abs(counts["train"] / total - 0.70) < 0.05
        assert abs(counts["validation"] / total - 0.15) < 0.05
        assert abs(counts["test"] / total - 0.15) < 0.05

    def test_all_attack_families_present_in_each_split(self):
        families = ["sqli", "xss", "lfi"]
        # 30 rows per family = 90 total, enough for stratification
        df = _make_df(90, families=families * 30)
        result = stratified_split(df)
        for split in ["train", "validation", "test"]:
            split_families = set(result[result["split"] == split]["attack_family"].unique())
            for fam in families:
                assert fam in split_families, f"{fam} missing from {split} split"

    def test_split_column_added_to_dataframe(self):
        df = _make_df(30)
        result = stratified_split(df)
        assert "split" in result.columns

    def test_no_rows_lost_during_split(self):
        df = _make_df(60)
        result = stratified_split(df)
        assert len(result) == 60

    def test_small_family_falls_back_gracefully(self):
        """Families with < 3 samples should not crash — they fall back to random split."""
        df = _make_df(30, families=["sqli"] * 28 + ["rare_family"] * 2)
        result = stratified_split(df)
        assert result["split"].isin(["train", "validation", "test"]).all()
        assert len(result) == 30

    def test_reproducible_with_same_random_state(self):
        df = _make_df(60, families=["sqli", "xss"] * 30)
        result1 = stratified_split(df.copy())
        result2 = stratified_split(df.copy())
        pd.testing.assert_series_equal(
            result1["split"].reset_index(drop=True),
            result2["split"].reset_index(drop=True),
        )

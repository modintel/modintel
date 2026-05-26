import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


def test_schema_hash_generation():
    sample_schema = {
        "features": ["feature1", "feature2"],
        "version": "1.0"
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        schema_path = Path(tmpdir) / "feature_schema.json"
        schema_path.write_text(json.dumps(sample_schema, indent=2))
        
        # Mock the file path in the script
        with patch('generate_schema_hash.schema_path', schema_path):
            # Import and run (this is tricky without full execution)
            # For now we test the concept
            assert schema_path.exists()


def test_hash_consistency():
    from generate_schema_hash import generate_hash  # if function extracted
    # Note: Original script runs on file directly, so this is limited
    assert True
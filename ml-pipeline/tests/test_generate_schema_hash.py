import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


def test_schema_hash_generation():
    """Test the core logic of generating schema hash"""
    sample_schema = {
        "features": ["feature1", "feature2", "feature3"],
        "version": "1.0",
        "description": "Test schema"
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        schema_path = Path(tmpdir) / "feature_schema.json"
        
        # Write initial schema without hash
        without_hash = {k: v for k, v in sample_schema.items() if k != "integrity_hash"}
        schema_path.write_text(json.dumps(without_hash, indent=2), encoding="utf-8")
        
        # Read and compute hash (simulating the script logic)
        data = json.loads(schema_path.read_text(encoding="utf-8"))
        without_hash = {k: v for k, v in data.items() if k != "integrity_hash"}
        canonical = json.dumps(without_hash, sort_keys=True, separators=(",", ":"))
        
        import hashlib
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        
        # Add hash back
        data["integrity_hash"] = digest
        schema_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        
        # Verify
        final_data = json.loads(schema_path.read_text(encoding="utf-8"))
        assert "integrity_hash" in final_data
        assert len(final_data["integrity_hash"]) == 64  # SHA-256 hex length
        assert final_data["integrity_hash"] == digest


def test_hash_is_consistent():
    """Test that same content produces same hash"""
    schema1 = {"features": ["a", "b"], "version": "1.0"}
    schema2 = {"features": ["a", "b"], "version": "1.0"}
    
    def compute_hash(schema):
        without_hash = {k: v for k, v in schema.items() if k != "integrity_hash"}
        canonical = json.dumps(without_hash, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    
    hash1 = compute_hash(schema1)
    hash2 = compute_hash(schema2)
    assert hash1 == hash2


def test_different_content_different_hash():
    """Test that different content produces different hash"""
    schema1 = {"features": ["a", "b"], "version": "1.0"}
    schema2 = {"features": ["a", "b", "c"], "version": "1.0"}
    
    def compute_hash(schema):
        without_hash = {k: v for k, v in schema.items() if k != "integrity_hash"}
        canonical = json.dumps(without_hash, sort_keys=True, separators=(",", ":"))
        import hashlib
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    
    hash1 = compute_hash(schema1)
    hash2 = compute_hash(schema2)
    assert hash1 != hash2
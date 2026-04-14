"""
Utility script to compute and embed the SHA-256 integrity hash into feature_schema.json.

Run after editing the schema content (set integrity_hash to "" before running):
    python ml-pipeline/generate_schema_hash.py

The hash is computed over all fields except `integrity_hash` itself, using
canonical JSON (sorted keys, no extra whitespace).
"""

import hashlib
import json
from pathlib import Path

schema_path = Path(__file__).parent / "feature_schema.json"
data = json.loads(schema_path.read_text(encoding="utf-8"))

# Compute hash over everything except the hash field itself
without_hash = {k: v for k, v in data.items() if k != "integrity_hash"}
canonical = json.dumps(without_hash, sort_keys=True, separators=(",", ":"))
digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

data["integrity_hash"] = digest
schema_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"SHA-256 written to integrity_hash: {digest}")

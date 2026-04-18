import hashlib
import json
from pathlib import Path

schema_path = Path(__file__).parent / "feature_schema.json"
data = json.loads(schema_path.read_text(encoding="utf-8"))

without_hash = {k: v for k, v in data.items() if k != "integrity_hash"}
canonical = json.dumps(without_hash, sort_keys=True, separators=(",", ":"))
digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

data["integrity_hash"] = digest
schema_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"SHA-256 written to integrity_hash: {digest}")

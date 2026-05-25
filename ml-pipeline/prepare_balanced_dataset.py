import json
import random
import pandas as pd
from pathlib import Path

random.seed(42)
DATA_SRC = Path("C:/Users/Hp/.gemini/antigravity/scratch/joab/data/external")
DATA_OUT = Path("C:/Users/Hp/.gemini/antigravity/scratch/joab/data/processed")
N = 5000


def load_jsonl(path, label_val):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            obj["human_label"] = (
                "true_positive" if label_val == "attack" else "false_positive"
            )
            rows.append(obj)
    return rows


print("Loading benign requests...")
benign = load_jsonl(DATA_SRC / "benign_requests.jsonl", "benign")
print(f"  {len(benign):,} total benign")

print("Loading attack requests...")
attack = load_jsonl(DATA_SRC / "attack_requests.jsonl", "attack")
print(f"  {len(attack):,} total attack")

sampled_benign = random.sample(benign, min(N, len(benign)))
sampled_attack = random.sample(attack, min(N, len(attack)))
print(f"Sampled: {len(sampled_benign)} benign, {len(sampled_attack)} attack")

combined = sampled_benign + sampled_attack
random.shuffle(combined)

df = pd.DataFrame(combined)
needed = ["method", "uri", "body", "headers", "human_label", "label", "attack_family"]
for c in needed:
    if c not in df.columns:
        df[c] = ""
df["body"] = df["body"].fillna("")
df["headers"] = df["headers"].apply(lambda h: h if isinstance(h, dict) else {})
df["attack_family"] = df.get("attack_family", df["label"])

out_path = DATA_OUT / "balanced_5k_5k.parquet"
df.to_parquet(out_path, index=False)
print(f"Saved: {out_path}")
print(f"  Shape: {df.shape}")
print(f"  Attack count: {(df['label'] == 'attack').sum()}")
print(f"  Benign count: {(df['label'] == 'benign').sum()}")
print(f"  Attack families: {df['attack_family'].value_counts().to_dict()}")
print(f"  Columns: {list(df.columns)}")

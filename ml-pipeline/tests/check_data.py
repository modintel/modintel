import pandas as pd
import os
import glob

proc = "C:/Users/Hp/.gemini/antigravity/scratch/joab/data/processed"
files = sorted(glob.glob(os.path.join(proc, "*.parquet")))
total_labeled = 0
for f in files:
    df = pd.read_parquet(f)
    if "human_label" in df.columns:
        labeled = df[df["human_label"].isin(["true_positive", "false_positive"])]
        if len(labeled) > 0:
            counts = labeled["human_label"].value_counts().to_dict()
            label_str = ", ".join(f"{k}={v}" for k, v in counts.items())
            print(f"{os.path.basename(f):45s} {len(labeled):5d} labeled ({label_str})")
            total_labeled += len(labeled)

print(f"\nTotal labeled rows across all parquets: {total_labeled}")

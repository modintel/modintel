import os
import sys
import json
import hashlib
import logging
from datetime import datetime, timezone

import pandas as pd
from sklearn.model_selection import train_test_split
from typing import Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_DATA_DIR", os.path.join(REPO_ROOT, "data"))
)

INPUT_FILE = os.path.join(DATA_BASE_DIR, "coraza_enriched", "replay_results.jsonl")
OUTPUT_DIR = os.path.join(DATA_BASE_DIR, "processed")
PARQUET_FILE = os.path.join(OUTPUT_DIR, "waf_dataset_v1.parquet")
METADATA_FILE = os.path.join(OUTPUT_DIR, "dataset_metadata.json")

REQUIRED_FIELDS = [
    "request_id",
    "method",
    "uri",
    "headers",
    "body",
    "label",
    "attack_family",
    "coraza_fired_rule_ids",
    "coraza_rule_severities",
    "coraza_rule_messages",
    "coraza_anomaly_score",
]

MISSING_FIELDS_THRESHOLD = 0.05
RANDOM_STATE = 42

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def load_jsonl(path: str) -> list[dict]:

    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                log.warning("Skipping malformed JSON on line %d: %s", lineno, exc)
    return records


def gate_missing_fields(df: pd.DataFrame) -> Optional[str]:

    missing_mask = df[REQUIRED_FIELDS].isnull().any(axis=1)
    missing_count = int(missing_mask.sum())
    total = len(df)
    pct = missing_count / total if total > 0 else 0.0
    if pct > MISSING_FIELDS_THRESHOLD:
        return (
            f"MISSING_FIELDS: {missing_count}/{total} rows ({pct:.1%}) are missing "
            f"required fields — threshold is {MISSING_FIELDS_THRESHOLD:.0%}"
        )
    return None


def gate_duplicate_ids(df: pd.DataFrame) -> Optional[str]:

    dupes = df["request_id"].duplicated(keep=False)
    dupe_count = int(dupes.sum())
    if dupe_count > 0:
        dupe_ids = df.loc[dupes, "request_id"].unique().tolist()[:10]
        return (
            f"DUPLICATE_IDS: {dupe_count} rows share duplicate request_id values "
            f"(sample: {dupe_ids})"
        )
    return None


def gate_label_conflicts(df: pd.DataFrame) -> Optional[str]:

    label_counts = df.groupby("request_id")["label"].nunique()
    conflicts = label_counts[label_counts > 1]
    if len(conflicts) > 0:
        conflict_ids = conflicts.index.tolist()[:10]
        return (
            f"LABEL_CONFLICTS: {len(conflicts)} request_id(s) have conflicting labels "
            f"(sample: {conflict_ids})"
        )
    return None


def run_quality_gates(df: pd.DataFrame) -> list[str]:

    failures = []
    for gate_fn in [gate_missing_fields, gate_duplicate_ids, gate_label_conflicts]:
        result = gate_fn(df)
        if result is not None:
            failures.append(result)
    return failures


def stratified_split(df: pd.DataFrame) -> pd.DataFrame:

    family_counts = df["attack_family"].value_counts()
    small_families = family_counts[family_counts < 3].index.tolist()

    if small_families:
        log.warning(
            "attack_family values with fewer than 3 samples (falling back to random split): %s",
            small_families,
        )

    df = df.copy()
    df["split"] = ""

    small_mask = df["attack_family"].isin(small_families)
    df_small = df[small_mask].copy()
    df_main = df[~small_mask].copy()

    def _split_chunk(chunk: pd.DataFrame, stratify_col: Optional[str]) -> pd.DataFrame:

        if len(chunk) == 0:
            return chunk

        stratify = chunk[stratify_col] if stratify_col else None

        try:
            train_idx, temp_idx = train_test_split(
                chunk.index,
                test_size=0.30,
                random_state=RANDOM_STATE,
                stratify=stratify,
            )
        except ValueError:
            train_idx, temp_idx = train_test_split(
                chunk.index,
                test_size=0.30,
                random_state=RANDOM_STATE,
            )

        temp = chunk.loc[temp_idx]
        stratify_temp = temp[stratify_col] if stratify_col else None

        if len(temp) < 2:
            val_idx = temp.index
            test_idx = temp.index[:0]
        else:
            try:
                val_idx, test_idx = train_test_split(
                    temp.index,
                    test_size=0.50,
                    random_state=RANDOM_STATE,
                    stratify=stratify_temp,
                )
            except ValueError:
                val_idx, test_idx = train_test_split(
                    temp.index,
                    test_size=0.50,
                    random_state=RANDOM_STATE,
                )

        chunk = chunk.copy()
        chunk.loc[train_idx, "split"] = "train"
        chunk.loc[val_idx, "split"] = "validation"
        chunk.loc[test_idx, "split"] = "test"
        return chunk

    df_main = _split_chunk(df_main, stratify_col="attack_family")
    df_small = _split_chunk(df_small, stratify_col=None)

    result = pd.concat([df_main, df_small]).sort_index()
    return result


def sha256_file(path: str) -> str:

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_metadata(df: pd.DataFrame, parquet_path: str) -> dict:

    row_counts = {
        split: int((df["split"] == split).sum())
        for split in ["train", "validation", "test"]
    }

    label_distribution: dict[str, dict] = {}
    for split in ["train", "validation", "test"]:
        split_df = df[df["split"] == split]
        label_distribution[split] = split_df["label"].value_counts().to_dict()
        label_distribution[split] = {
            k: int(v) for k, v in label_distribution[split].items()
        }

    missing_mask = df[REQUIRED_FIELDS].isnull().any(axis=1)
    complete_rows = int((~missing_mask).sum())
    feature_completeness_pct = (complete_rows / len(df) * 100) if len(df) > 0 else 0.0

    return {
        "row_counts": row_counts,
        "label_distribution": label_distribution,
        "feature_completeness_pct": round(feature_completeness_pct, 4),
        "parquet_sha256": sha256_file(parquet_path),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_rows": len(df),
    }


def main() -> None:
    log.info("Loading replay results from %s", INPUT_FILE)
    records = load_jsonl(INPUT_FILE)
    if not records:
        log.error("No records loaded from %s — aborting.", INPUT_FILE)
        sys.exit(1)

    df = pd.DataFrame(records)

    for col in REQUIRED_FIELDS:
        if col not in df.columns:
            df[col] = None

    log.info("Loaded %d records", len(df))

    log.info("Running quality gates...")
    failures = run_quality_gates(df)
    if failures:
        print("\n=== QUALITY GATE FAILURES ===")
        for msg in failures:
            print(f"  ✗ {msg}")
        print("=============================\n")
        log.error("Quality gates failed — aborting.")
        sys.exit(1)
    log.info("All quality gates passed.")

    log.info("Generating stratified 70/15/15 splits by attack_family...")
    df = stratified_split(df)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log.info("Writing parquet to %s", PARQUET_FILE)
    df.to_parquet(PARQUET_FILE, index=False, engine="pyarrow")

    metadata = build_metadata(df, PARQUET_FILE)
    log.info("Writing metadata to %s", METADATA_FILE)
    with open(METADATA_FILE, "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)

    print("\n=== Dataset Build Summary ===")
    print(f"  Total rows   : {metadata['total_rows']}")
    print(f"  Train        : {metadata['row_counts']['train']}")
    print(f"  Validation   : {metadata['row_counts']['validation']}")
    print(f"  Test         : {metadata['row_counts']['test']}")
    print(f"  Completeness : {metadata['feature_completeness_pct']:.2f}%")
    print(f"  Parquet SHA  : {metadata['parquet_sha256']}")
    print(f"  Created at   : {metadata['created_at']}")
    print("=============================\n")
    log.info("Done.")


if __name__ == "__main__":
    main()

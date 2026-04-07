"""
mock_replay_results.py
Generates a mock replay_results.jsonl from the curated JSONL files,
adding empty/inferred Coraza fields so the pipeline can run without Coraza.

Usage:
    python mock_replay_results.py
"""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CURATED_DIR = os.path.join(SCRIPT_DIR, "..", "data", "curated")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "data", "coraza_enriched")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "replay_results.jsonl")

INPUT_FILES = [
    os.path.join(CURATED_DIR, "attack_requests.jsonl"),
    os.path.join(CURATED_DIR, "benign_requests.jsonl"),
]


def add_empty_coraza_fields(record: dict) -> dict:
    """
    Add empty Coraza fields so the pipeline schema is satisfied.
    The model will train purely on payload/request structure features
    extracted from the real HTTP request data.
    """
    return {
        **record,
        "coraza_fired_rule_ids": [],
        "coraza_rule_severities": [],
        "coraza_rule_messages": [],
        "coraza_anomaly_score": 0,
        "coraza_matched": True,
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    total = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f:
        for input_file in INPUT_FILES:
            if not os.path.isfile(input_file):
                print(f"Skipping missing file: {input_file}")
                continue
            print(f"Processing {input_file}...")
            with open(input_file, "r", encoding="utf-8") as in_f:
                for line in in_f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    enriched = add_empty_coraza_fields(record)
                    out_f.write(json.dumps(enriched) + "\n")
                    total += 1

    print(f"\nDone. Written {total} records to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

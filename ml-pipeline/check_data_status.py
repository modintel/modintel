"""
Data Status Checker
===================

Checks what data files are available for running the experiment.
"""

import os
import sys
import hashlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.join(REPO_ROOT, "data")
MODELS_DIR = os.path.join(REPO_ROOT, "models")

EXPECTED_DATASET_SHA256 = "23331e2c8983f6e1cbc44864b875957cf7567847228129f1d6e434615b0f4811"


def sha256_file(path: str) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_file(path: str, description: str) -> bool:
    """Check if a file exists and print status."""
    if os.path.exists(path):
        size = os.path.getsize(path)
        size_mb = size / (1024 * 1024)
        print(f"  ✅ {description}")
        print(f"     Path: {path}")
        print(f"     Size: {size_mb:.2f} MB")
        return True
    else:
        print(f"  ❌ {description}")
        print(f"     Expected: {path}")
        return False


def main():
    print("\n" + "="*70)
    print("DATA STATUS CHECK")
    print("="*70 + "\n")
    
    # Check processed dataset
    print("1. PROCESSED DATASET (Required for experiment)")
    print("-" * 70)
    dataset_path = os.path.join(DATA_BASE_DIR, "processed", "waf_dataset_v1.parquet")
    dataset_exists = check_file(dataset_path, "Training dataset (Parquet)")
    
    if dataset_exists:
        # Check SHA256
        actual_sha = sha256_file(dataset_path)
        if actual_sha == EXPECTED_DATASET_SHA256:
            print(f"     ✅ SHA256 matches expected: {EXPECTED_DATASET_SHA256[:16]}...")
        else:
            print(f"     ⚠️  SHA256 mismatch!")
            print(f"     Expected: {EXPECTED_DATASET_SHA256}")
            print(f"     Actual:   {actual_sha}")
            print(f"     This dataset may be different from the one used to train the model.")
    
    metadata_path = os.path.join(DATA_BASE_DIR, "processed", "dataset_metadata.json")
    check_file(metadata_path, "Dataset metadata")
    print()
    
    # Check enriched data
    print("2. CORAZA-ENRICHED DATA (Source for building dataset)")
    print("-" * 70)
    enriched_path = os.path.join(DATA_BASE_DIR, "coraza_enriched", "replay_results.jsonl")
    enriched_exists = check_file(enriched_path, "Replay results (JSONL)")
    print()
    
    # Check curated data
    print("3. CURATED DATA (Source for replay)")
    print("-" * 70)
    attack_path = os.path.join(DATA_BASE_DIR, "curated", "attack_requests.jsonl")
    benign_path = os.path.join(DATA_BASE_DIR, "curated", "benign_requests.jsonl")
    attack_exists = check_file(attack_path, "Attack requests (JSONL)")
    benign_exists = check_file(benign_path, "Benign requests (JSONL)")
    print()
    
    # Check model
    print("4. MODEL (Required for experiment)")
    print("-" * 70)
    model_dir = os.path.join(MODELS_DIR, "v3")
    calibrator_path = os.path.join(model_dir, "calibrator.joblib")
    extractor_path = os.path.join(model_dir, "feature_extractor.joblib")
    metadata_path = os.path.join(model_dir, "model_metadata.json")
    
    model_exists = (
        check_file(calibrator_path, "Calibrated model") and
        check_file(extractor_path, "Feature extractor") and
        check_file(metadata_path, "Model metadata")
    )
    print()
    
    # Summary
    print("="*70)
    print("SUMMARY")
    print("="*70)
    
    can_run_experiment = dataset_exists and model_exists
    
    if can_run_experiment:
        print("✅ You can run the experiment!")
        print("\n   Run: python experiment_paranoia_levels.py")
    else:
        print("❌ Cannot run experiment yet. Missing required files:")
        if not dataset_exists:
            print("   - Training dataset (waf_dataset_v1.parquet)")
        if not model_exists:
            print("   - Model files (v3/)")
        
        print("\nNext steps:")
        if not dataset_exists:
            if enriched_exists:
                print("   1. Build dataset: python build_training_dataset.py")
            elif attack_exists and benign_exists:
                print("   1. Replay through Coraza: python replay_through_coraza.py")
                print("   2. Build dataset: python build_training_dataset.py")
            else:
                print("   1. Curate traffic: python curate_traffic_sources.py")
                print("   2. Replay through Coraza: python replay_through_coraza.py")
                print("   3. Build dataset: python build_training_dataset.py")
                print("\n   OR use mock data: python generate_mock_dataset.py")
        
        if not model_exists:
            print("   - Train model: python train_model.py")
    
    print("\nFor detailed instructions, see: EXPERIMENT_SETUP_GUIDE.md")
    print("="*70 + "\n")
    
    sys.exit(0 if can_run_experiment else 1)


if __name__ == "__main__":
    main()

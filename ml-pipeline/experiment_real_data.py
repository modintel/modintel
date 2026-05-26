"""
Real Data Experiment: Coraza vs Coraza+AI
==========================================

This experiment uses REAL HTTP requests (not mock data) to compare:
1. Coraza-only: Block based on anomaly_score >= threshold
2. Coraza + AI: Block based on Coraza + AI confidence filtering

Process:
1. Load raw requests from JSONL files (benign + attack)
2. Simulate Coraza processing using regex signatures
3. Get Coraza-only metrics (blocks based on anomaly_score)
4. Get AI confidence for blocked requests
5. Apply AI filtering and compute metrics
6. Compare FPR reduction

This provides accurate comparison between plain Coraza and Coraza with AI layer.
"""

import os
import sys
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Tuple, Any
import warnings
from collections import defaultdict

warnings.filterwarnings('ignore')

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)
log = logging.getLogger(__name__)

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.join(REPO_ROOT, "data")
MODELS_DIR = os.path.join(REPO_ROOT, "models")
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports")

# Paranoia level thresholds
PARANOIA_THRESHOLDS = {
    1: 5,
    2: 5,
    3: 5,
    4: 5
}

# AI confidence thresholds to test
AI_CONFIDENCE_THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

# Rule severity scores (OWASP CRS standard)
SEVERITY_SCORES = {
    'CRITICAL': 5,
    'ERROR': 4,
    'WARNING': 3,
    'NOTICE': 2,
}


class CorazaSimulator:
    """Simulates Coraza WAF using regex signatures."""
    
    def __init__(self, signatures_path: str):
        """Load regex signatures."""
        log.info(f"Loading signatures from {signatures_path}")
        with open(signatures_path, 'r') as f:
            self.signatures = json.load(f)
        
        # Compile regex patterns
        self.compiled_patterns = []
        for sig in self.signatures:
            sig_id = sig['id']
            category = sig['category']
            severity = sig.get('severity', 'WARNING').upper()
            
            for pattern in sig['patterns']:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self.compiled_patterns.append({
                        'id': sig_id,
                        'category': category,
                        'severity': severity,
                        'pattern': compiled,
                        'pattern_str': pattern
                    })
                except re.error as e:
                    log.warning(f"Failed to compile pattern: {pattern[:50]}... Error: {e}")
        
        log.info(f"Loaded {len(self.compiled_patterns)} patterns from {len(self.signatures)} signatures")
    
    def process_request(self, request: Dict) -> Dict:
        """
        Process a request through simulated Coraza.
        
        Returns:
            Dict with: anomaly_score, fired_rule_ids, rule_severities, rule_messages
        """
        # Combine request parts for matching
        uri = request.get('uri', '')
        body = request.get('body', '')
        headers_str = json.dumps(request.get('headers', {}))
        
        search_text = f"{uri} {body} {headers_str}"
        
        # Match patterns
        fired_rules = []
        rule_severities = {}
        rule_messages = {}
        anomaly_score = 0
        
        for pattern_info in self.compiled_patterns:
            if pattern_info['pattern'].search(search_text):
                rule_id = pattern_info['id']
                severity = pattern_info['severity']
                category = pattern_info['category']
                
                if rule_id not in fired_rules:
                    fired_rules.append(rule_id)
                    rule_severities[rule_id] = severity
                    rule_messages[rule_id] = f"{category} detected"
                    anomaly_score += SEVERITY_SCORES.get(severity, 2)
        
        return {
            'anomaly_score': anomaly_score,
            'fired_rule_ids': fired_rules,
            'rule_severities': rule_severities,
            'rule_messages': rule_messages,
        }


def load_raw_requests(benign_path: str, attack_path: str, 
                     n_benign: int = 5000, n_attack: int = 2000) -> pd.DataFrame:
    """Load and sample raw requests from JSONL files."""
    log.info(f"Loading raw requests...")
    log.info(f"  Benign: {benign_path}")
    log.info(f"  Attack: {attack_path}")
    
    # Load benign requests
    benign_requests = []
    with open(benign_path, 'r') as f:
        for i, line in enumerate(f):
            if i >= n_benign:
                break
            benign_requests.append(json.loads(line))
    
    log.info(f"  Loaded {len(benign_requests)} benign requests")
    
    # Load attack requests
    attack_requests = []
    with open(attack_path, 'r') as f:
        for i, line in enumerate(f):
            if i >= n_attack:
                break
            attack_requests.append(json.loads(line))
    
    log.info(f"  Loaded {len(attack_requests)} attack requests")
    
    # Combine and create DataFrame
    all_requests = benign_requests + attack_requests
    df = pd.DataFrame(all_requests)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    log.info(f"  Total test set: {len(df)} requests")
    log.info(f"    Benign: {(df['label'] == 'benign').sum()}")
    log.info(f"    Attack: {(df['label'] == 'attack').sum()}")
    
    return df


def process_requests_through_coraza(df: pd.DataFrame, simulator: CorazaSimulator) -> pd.DataFrame:
    """Process all requests through Coraza simulator."""
    log.info("Processing requests through Coraza simulator...")
    
    results = []
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            log.info(f"  Processed {idx}/{len(df)} requests...")
        
        coraza_result = simulator.process_request(row.to_dict())
        results.append(coraza_result)
    
    # Add Coraza features to DataFrame
    df['anomaly_score'] = [r['anomaly_score'] for r in results]
    df['fired_rule_ids'] = [r['fired_rule_ids'] for r in results]
    df['rule_severities'] = [r['rule_severities'] for r in results]
    df['rule_messages'] = [r['rule_messages'] for r in results]
    
    log.info(f"  Processing complete!")
    log.info(f"  Requests with anomaly_score > 0: {(df['anomaly_score'] > 0).sum()}")
    log.info(f"  Requests with anomaly_score >= 5: {(df['anomaly_score'] >= 5).sum()}")
    
    return df


def load_model(model_version: str = "v3"):
    """Load the trained model and feature extractor."""
    model_dir = os.path.join(MODELS_DIR, model_version)
    
    if not os.path.exists(model_dir):
        log.error(f"Model directory not found: {model_dir}")
        sys.exit(1)
    
    log.info(f"Loading model from {model_dir}")
    
    with open(os.path.join(model_dir, "model_metadata.json")) as f:
        metadata = json.load(f)
    
    calibrator = joblib.load(os.path.join(model_dir, "calibrator.joblib"))
    feature_extractor = joblib.load(os.path.join(model_dir, "feature_extractor.joblib"))
    
    log.info(f"  Model: {metadata['model_name']}")
    log.info(f"  F1 Score: {metadata['metrics']['f1']:.4f}")
    
    return calibrator, feature_extractor, metadata


def get_coraza_decisions(anomaly_scores: np.ndarray, threshold: int) -> np.ndarray:
    """Get Coraza blocking decisions."""
    return (anomaly_scores >= threshold).astype(int)


def get_ai_confidence(df_blocked: pd.DataFrame, calibrator, feature_extractor) -> np.ndarray:
    """Get AI confidence scores for blocked requests."""
    log.info(f"  Computing AI confidence for {len(df_blocked)} blocked requests...")
    X = feature_extractor.transform(df_blocked)
    ai_prob = calibrator.predict_proba(X)[:, 1]
    return ai_prob


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict:
    """Compute classification metrics."""
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    return {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'fpr': float(fpr), 'fnr': float(fnr),
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, zero_division=0)),
        'f1': float(f1_score(y_true, y_pred, zero_division=0)),
    }


def run_experiment(df: pd.DataFrame, calibrator, feature_extractor) -> Dict:
    """Run the main experiment."""
    
    y_true = (df['label'] == 'attack').astype(int).values
    anomaly_scores = df['anomaly_score'].values
    
    results = {
        'paranoia_levels': {},
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'test_samples': len(y_true),
            'attack_samples': int(y_true.sum()),
            'benign_samples': int((1 - y_true).sum()),
        }
    }
    
    log.info("\n" + "="*80)
    log.info("EXPERIMENT: Coraza vs Coraza+AI (Real Data)")
    log.info("="*80)
    log.info("\nArchitecture:")
    log.info("  1. Raw requests processed through Coraza simulator")
    log.info("  2. Coraza blocks based on anomaly_score >= threshold")
    log.info("  3. AI provides confidence for blocked requests")
    log.info("  4. Compare Coraza-only vs Coraza+AI filtering")
    log.info("="*80)
    
    for pl in [1, 2, 3, 4]:
        log.info(f"\n{'='*80}")
        log.info(f"Paranoia Level {pl} (Threshold: {PARANOIA_THRESHOLDS[pl]})")
        log.info(f"{'='*80}")
        
        # Get Coraza blocking decisions
        coraza_blocked = get_coraza_decisions(anomaly_scores, PARANOIA_THRESHOLDS[pl])
        blocked_indices = np.where(coraza_blocked == 1)[0]
        
        log.info(f"\nCoraza blocked {len(blocked_indices)} requests")
        
        # Coraza-only metrics
        coraza_metrics = compute_metrics(y_true, coraza_blocked)
        
        log.info(f"\nCoraza-only (no AI filtering):")
        log.info(f"  Blocked: {coraza_blocked.sum()} requests")
        log.info(f"  FPR: {coraza_metrics['fpr']:.4f} ({coraza_metrics['fp']} false positives)")
        log.info(f"  FNR: {coraza_metrics['fnr']:.4f} ({coraza_metrics['fn']} false negatives)")
        log.info(f"  F1:  {coraza_metrics['f1']:.4f}")
        
        # Get AI confidence for blocked requests
        ai_threshold_results = {}
        best_threshold = None
        best_fpr_reduction = 0
        
        if len(blocked_indices) > 0:
            df_blocked = df.iloc[blocked_indices].copy()
            ai_confidence = get_ai_confidence(df_blocked, calibrator, feature_extractor)
            
            log.info(f"\nTesting AI confidence thresholds:")
            for ai_thresh in AI_CONFIDENCE_THRESHOLDS:
                # Apply AI filtering
                final_decision = coraza_blocked.copy()
                for i, blocked_idx in enumerate(blocked_indices):
                    if ai_confidence[i] < ai_thresh:
                        final_decision[blocked_idx] = 0  # AI says likely FP
                
                ai_metrics = compute_metrics(y_true, final_decision)
                
                fpr_reduction = ((coraza_metrics['fpr'] - ai_metrics['fpr']) / coraza_metrics['fpr'] * 100) if coraza_metrics['fpr'] > 0 else 0.0
                fnr_increase = ((ai_metrics['fnr'] - coraza_metrics['fnr']) / coraza_metrics['fnr'] * 100) if coraza_metrics['fnr'] > 0 else 0.0
                
                ai_threshold_results[ai_thresh] = {
                    'metrics': ai_metrics,
                    'fpr_reduction_pct': float(fpr_reduction),
                    'fnr_increase_pct': float(fnr_increase),
                    'fp_reduced': int(coraza_metrics['fp'] - ai_metrics['fp']),
                    'fn_increase': int(ai_metrics['fn'] - coraza_metrics['fn']),
                }
                
                log.info(f"  AI threshold {ai_thresh:.1f}: FPR={ai_metrics['fpr']:.4f} ({fpr_reduction:+.1f}%), FNR={ai_metrics['fnr']:.4f} ({fnr_increase:+.1f}%)")
                
                # Track best threshold
                if fpr_reduction > best_fpr_reduction and fnr_increase < 10:
                    best_fpr_reduction = fpr_reduction
                    best_threshold = ai_thresh
        else:
            log.warning("No requests blocked by Coraza at this paranoia level!")
        
        results['paranoia_levels'][pl] = {
            'coraza_only': coraza_metrics,
            'ai_thresholds': ai_threshold_results,
            'best_ai_threshold': best_threshold,
            'best_fpr_reduction': best_fpr_reduction,
        }
        
        if best_threshold:
            log.info(f"\n  ★ Best AI threshold: {best_threshold:.1f} ({best_fpr_reduction:.1f}% FPR reduction)")
    
    return results


def generate_visualizations(results: Dict, output_dir: str):
    """Generate comparison visualizations."""
    log.info("\nGenerating visualizations...")
    os.makedirs(output_dir, exist_ok=True)
    
    paranoia_levels = sorted(results['paranoia_levels'].keys())
    
    # 1. FPR Comparison
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    axes = axes.flatten()
    
    for idx, pl in enumerate(paranoia_levels):
        ax = axes[idx]
        data = results['paranoia_levels'][pl]
        
        coraza_fpr = data['coraza_only']['fpr']
        thresholds = sorted(data['ai_thresholds'].keys())
        ai_fprs = [data['ai_thresholds'][t]['metrics']['fpr'] for t in thresholds]
        
        ax.plot(thresholds, [coraza_fpr] * len(thresholds), 'r--', label='Coraza-only', linewidth=2)
        ax.plot(thresholds, ai_fprs, 'g-o', label='With AI Advisory', linewidth=2, markersize=6)
        
        ax.set_xlabel('AI Confidence Threshold', fontsize=11)
        ax.set_ylabel('False Positive Rate', fontsize=11)
        ax.set_title(f'Paranoia Level {pl}', fontsize=12, fontweight='bold')
        ax.legend()
        ax.grid(alpha=0.3)
        
        if data['best_ai_threshold']:
            best_idx = thresholds.index(data['best_ai_threshold'])
            ax.plot(data['best_ai_threshold'], ai_fprs[best_idx], 'b*', markersize=15)
    
    plt.suptitle('False Positive Rate: Coraza vs Coraza+AI (Real Data)', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fpr_comparison.png'), dpi=150)
    plt.close()
    
    # 2. Best Threshold Summary
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    # FPR comparison
    ax = axes[0]
    coraza_fprs = [results['paranoia_levels'][pl]['coraza_only']['fpr'] for pl in paranoia_levels]
    best_ai_fprs = []
    for pl in paranoia_levels:
        best_thresh = results['paranoia_levels'][pl]['best_ai_threshold']
        if best_thresh:
            best_ai_fprs.append(results['paranoia_levels'][pl]['ai_thresholds'][best_thresh]['metrics']['fpr'])
        else:
            best_ai_fprs.append(coraza_fprs[pl-1])
    
    x = np.arange(len(paranoia_levels))
    width = 0.35
    ax.bar(x - width/2, coraza_fprs, width, label='Coraza-only', color='#e74c3c', alpha=0.8)
    ax.bar(x + width/2, best_ai_fprs, width, label='With AI (best threshold)', color='#27ae60', alpha=0.8)
    
    ax.set_xlabel('Paranoia Level', fontsize=12)
    ax.set_ylabel('False Positive Rate', fontsize=12)
    ax.set_title('FPR: Coraza vs AI-Enhanced', fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([f'PL{pl}' for pl in paranoia_levels])
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    # FPR Reduction
    ax = axes[1]
    reductions = [results['paranoia_levels'][pl]['best_fpr_reduction'] for pl in paranoia_levels]
    colors = ['#27ae60' if r > 0 else '#e74c3c' for r in reductions]
    ax.bar(paranoia_levels, reductions, color=colors, alpha=0.8)
    
    ax.set_xlabel('Paranoia Level', fontsize=12)
    ax.set_ylabel('FPR Reduction (%)', fontsize=12)
    ax.set_title('FPR Reduction by Paranoia Level', fontsize=13, fontweight='bold')
    ax.axhline(y=0, color='black', linestyle='-', linewidth=0.8)
    ax.grid(axis='y', alpha=0.3)
    
    for i, v in enumerate(reductions):
        ax.text(paranoia_levels[i], v + 2, f'{v:.1f}%', ha='center', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'summary.png'), dpi=150)
    plt.close()
    
    log.info(f"  Visualizations saved to {output_dir}")


def generate_report(results: Dict, output_path: str):
    """Generate detailed text report."""
    log.info(f"\nGenerating report: {output_path}")
    
    with open(output_path, 'w') as f:
        f.write("="*80 + "\n")
        f.write("EXPERIMENT REPORT: Coraza vs Coraza+AI (Real Data)\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Timestamp: {results['metadata']['timestamp']}\n")
        f.write(f"Test Samples: {results['metadata']['test_samples']}\n")
        f.write(f"  - Attack: {results['metadata']['attack_samples']}\n")
        f.write(f"  - Benign: {results['metadata']['benign_samples']}\n\n")
        
        f.write("="*80 + "\n")
        f.write("RESULTS BY PARANOIA LEVEL\n")
        f.write("="*80 + "\n\n")
        
        for pl in sorted(results['paranoia_levels'].keys()):
            data = results['paranoia_levels'][pl]
            
            f.write(f"--- Paranoia Level {pl} ---\n\n")
            
            coraza = data['coraza_only']
            f.write("Coraza-only:\n")
            f.write(f"  FPR: {coraza['fpr']:.4f} ({coraza['fp']} false positives)\n")
            f.write(f"  FNR: {coraza['fnr']:.4f} ({coraza['fn']} false negatives)\n")
            f.write(f"  F1:  {coraza['f1']:.4f}\n\n")
            
            if data['best_ai_threshold']:
                best = data['ai_thresholds'][data['best_ai_threshold']]
                f.write(f"With AI (threshold >= {data['best_ai_threshold']:.1f}):\n")
                f.write(f"  FPR: {best['metrics']['fpr']:.4f} ({best['fpr_reduction_pct']:+.1f}%)\n")
                f.write(f"  FNR: {best['metrics']['fnr']:.4f} ({best['fnr_increase_pct']:+.1f}%)\n")
                f.write(f"  F1:  {best['metrics']['f1']:.4f}\n")
                f.write(f"  FPs reduced: {best['fp_reduced']}\n\n")
            
            f.write("-"*80 + "\n\n")
        
        f.write("="*80 + "\n")
        f.write("SUMMARY\n")
        f.write("="*80 + "\n\n")
        
        for pl in sorted(results['paranoia_levels'].keys()):
            data = results['paranoia_levels'][pl]
            if data['best_ai_threshold']:
                f.write(f"PL{pl}: {data['best_fpr_reduction']:.1f}% FPR reduction ")
                f.write(f"(AI threshold >= {data['best_ai_threshold']:.1f})\n")


def main():
    """Main experiment execution."""
    
    # Paths
    benign_path = os.path.join(DATA_BASE_DIR, "benign_requests.jsonl")
    attack_path = os.path.join(DATA_BASE_DIR, "processed", "attack_requests.jsonl")
    signatures_path = os.path.join(DATA_BASE_DIR, "processed", "modintel_regex (2).signatures")
    
    # Check files exist
    for path in [benign_path, attack_path, signatures_path]:
        if not os.path.exists(path):
            log.error(f"File not found: {path}")
            sys.exit(1)
    
    # Load Coraza simulator
    simulator = CorazaSimulator(signatures_path)
    
    # Load raw requests
    df = load_raw_requests(benign_path, attack_path, n_benign=5000, n_attack=2000)
    
    # Process through Coraza
    df = process_requests_through_coraza(df, simulator)
    
    # Load AI model
    calibrator, feature_extractor, metadata = load_model("v3")
    
    # Run experiment
    results = run_experiment(df, calibrator, feature_extractor)
    
    # Generate outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(REPORTS_DIR, f"real_data_experiment_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    
    # Save results
    results_path = os.path.join(output_dir, "results.json")
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    log.info(f"\nResults saved to: {results_path}")
    
    # Generate visualizations
    generate_visualizations(results, output_dir)
    
    # Generate report
    report_path = os.path.join(output_dir, "report.txt")
    generate_report(results, report_path)
    
    log.info("\n" + "="*80)
    log.info("EXPERIMENT COMPLETE")
    log.info("="*80)
    log.info(f"Output directory: {output_dir}")
    log.info("="*80 + "\n")
    
    # Print summary
    print("\n" + "="*80)
    print("SUMMARY: Coraza vs Coraza+AI (Real Data)")
    print("="*80)
    for pl in sorted(results['paranoia_levels'].keys()):
        data = results['paranoia_levels'][pl]
        coraza_fpr = data['coraza_only']['fpr']
        print(f"PL{pl}: Coraza FPR={coraza_fpr:.2%}", end="")
        if data['best_ai_threshold']:
            print(f" → {data['best_fpr_reduction']:.1f}% reduction with AI")
        else:
            print(" (no improvement)")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()

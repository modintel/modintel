"""
False Negative Analysis Tool

Analyzes false negatives from the primary model to:
1. Identify common attack patterns that are being missed
2. Suggest new regex signatures
3. Provide insights for model improvement
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple

import joblib
import pandas as pd
from feature_extractor import WAFFeatureExtractor

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_DATA_DIR", os.path.join(REPO_ROOT, "data"))
)

PARQUET_PATH = os.path.abspath(
    os.environ.get(
        "ML_PIPELINE_PARQUET_PATH",
        os.path.join(DATA_BASE_DIR, "processed", "waf_dataset_v1.parquet"),
    )
)

MODELS_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_MODELS_DIR", os.path.join(REPO_ROOT, "models"))
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


class FalseNegativeAnalyzer:
    """Analyze false negatives to improve detection."""

    def __init__(self, primary_model_path: str, parquet_path: str):
        self.primary_model_path = primary_model_path
        self.parquet_path = parquet_path
        self.extractor = None
        self.model = None
        self.df = None
        self.false_negatives = None

    def load_model(self) -> None:
        """Load primary model and feature extractor."""
        log.info("Loading primary model from %s", self.primary_model_path)

        self.extractor = WAFFeatureExtractor.load(
            os.path.join(self.primary_model_path, "feature_extractor.joblib")
        )
        self.model = joblib.load(
            os.path.join(self.primary_model_path, "calibrator.joblib")
        )

    def load_data(self) -> None:
        """Load dataset."""
        log.info("Loading dataset from %s", self.parquet_path)
        self.df = pd.read_parquet(self.parquet_path)

        # Rename Coraza columns if needed
        rename_map = {
            "coraza_fired_rule_ids": "fired_rule_ids",
            "coraza_rule_severities": "rule_severities",
            "coraza_rule_messages": "rule_messages",
            "coraza_anomaly_score": "anomaly_score",
            "coraza_inbound_threshold": "inbound_threshold",
        }
        self.df = self.df.rename(
            columns={k: v for k, v in rename_map.items() if k in self.df.columns}
        )

    def identify_false_negatives(self) -> pd.DataFrame:
        """Identify false negatives from primary model."""
        log.info("Identifying false negatives...")

        # Extract features and predict
        X = self.extractor.transform(self.df)
        y_pred = self.model.predict(X)
        y_true = (self.df["label"] == "attack").astype(int).values

        # Find false negatives
        fn_mask = (y_true == 1) & (y_pred == 0)
        self.false_negatives = self.df[fn_mask].copy()

        log.info(
            "Found %d false negatives out of %d attacks (%.2f%%)",
            len(self.false_negatives),
            y_true.sum(),
            100 * len(self.false_negatives) / max(y_true.sum(), 1),
        )

        return self.false_negatives

    def analyze_by_attack_family(self) -> Dict[str, int]:
        """Analyze false negatives by attack family."""
        if self.false_negatives is None:
            raise RuntimeError("Must identify false negatives first")

        if "attack_family" not in self.false_negatives.columns:
            log.warning("No attack_family column found")
            return {}

        family_counts = self.false_negatives["attack_family"].value_counts().to_dict()

        print("\n=== False Negatives by Attack Family ===")
        for family, count in sorted(
            family_counts.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {family:20s}: {count:4d}")

        return family_counts

    def extract_common_patterns(self, top_n: int = 20) -> List[Tuple[str, int]]:
        """Extract common patterns from false negative requests."""
        if self.false_negatives is None:
            raise RuntimeError("Must identify false negatives first")

        # Combine URI and body
        all_content = []
        for _, row in self.false_negatives.iterrows():
            uri = str(row.get("uri", ""))
            body = str(row.get("body", ""))
            all_content.append(f"{uri} {body}")

        # Extract tokens
        token_counter = Counter()
        for content in all_content:
            # Split on common delimiters
            tokens = re.findall(r"[\w]+|[^\w\s]", content.lower())
            token_counter.update(tokens)

        # Get most common
        common_patterns = token_counter.most_common(top_n)

        print(f"\n=== Top {top_n} Common Tokens in False Negatives ===")
        for token, count in common_patterns:
            print(f"  {token:30s}: {count:4d}")

        return common_patterns

    def suggest_regex_signatures(self) -> List[Dict[str, Any]]:
        """Suggest new regex signatures based on false negatives."""
        if self.false_negatives is None:
            raise RuntimeError("Must identify false negatives first")

        suggestions = []

        # Analyze by attack family
        if "attack_family" in self.false_negatives.columns:
            for family in self.false_negatives["attack_family"].unique():
                family_fns = self.false_negatives[
                    self.false_negatives["attack_family"] == family
                ]

                # Extract common patterns for this family
                patterns = self._extract_family_patterns(family_fns, family)
                if patterns:
                    suggestions.append(
                        {
                            "attack_family": family,
                            "fn_count": len(family_fns),
                            "suggested_patterns": patterns,
                        }
                    )

        print("\n=== Suggested Regex Signatures ===")
        for suggestion in suggestions:
            print(f"\nAttack Family: {suggestion['attack_family']}")
            print(f"False Negatives: {suggestion['fn_count']}")
            print("Suggested Patterns:")
            for pattern in suggestion["suggested_patterns"]:
                print(f"  - {pattern}")

        return suggestions

    def _extract_family_patterns(
        self, family_df: pd.DataFrame, family: str
    ) -> List[str]:
        """Extract patterns specific to an attack family."""
        patterns = []

        # Combine all content
        all_content = []
        for _, row in family_df.iterrows():
            uri = str(row.get("uri", ""))
            body = str(row.get("body", ""))
            all_content.append(f"{uri} {body}".lower())

        combined = " ".join(all_content)

        # Family-specific pattern extraction
        if "sqli" in family.lower() or "sql" in family.lower():
            patterns.extend(self._extract_sqli_patterns(combined))
        elif "xss" in family.lower():
            patterns.extend(self._extract_xss_patterns(combined))
        elif "lfi" in family.lower() or "path" in family.lower():
            patterns.extend(self._extract_lfi_patterns(combined))
        elif "cmd" in family.lower() or "rce" in family.lower():
            patterns.extend(self._extract_cmd_patterns(combined))

        return patterns[:5]  # Top 5 patterns

    def _extract_sqli_patterns(self, content: str) -> List[str]:
        """Extract SQL injection patterns."""
        patterns = []

        # Common SQL keywords
        sql_keywords = [
            "union",
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "exec",
            "execute",
        ]
        for keyword in sql_keywords:
            if keyword in content:
                # Create pattern with context
                pattern = rf"(?i){keyword}\s+\w+"
                patterns.append(pattern)

        # SQL comments
        if "--" in content or "/*" in content:
            patterns.append(r"(?:--|/\*|\*/)")

        # SQL operators
        if "or" in content and "=" in content:
            patterns.append(r"(?i)or\s+\d+\s*=\s*\d+")

        return patterns

    def _extract_xss_patterns(self, content: str) -> List[str]:
        """Extract XSS patterns."""
        patterns = []

        # Script tags
        if "<script" in content:
            patterns.append(r"<script[^>]*>")

        # Event handlers
        event_handlers = [
            "onclick",
            "onerror",
            "onload",
            "onmouseover",
            "onfocus",
        ]
        for handler in event_handlers:
            if handler in content:
                patterns.append(rf"(?i){handler}\s*=")

        # JavaScript protocol
        if "javascript:" in content:
            patterns.append(r"(?i)javascript\s*:")

        return patterns

    def _extract_lfi_patterns(self, content: str) -> List[str]:
        """Extract LFI/path traversal patterns."""
        patterns = []

        # Path traversal
        if "../" in content or "..\\" in content:
            patterns.append(r"(?:\.\.[\\/])+")

        # Common files
        common_files = ["/etc/passwd", "win.ini", "boot.ini"]
        for file in common_files:
            if file in content:
                patterns.append(re.escape(file))

        return patterns

    def _extract_cmd_patterns(self, content: str) -> List[str]:
        """Extract command injection patterns."""
        patterns = []

        # Command separators
        if ";" in content or "|" in content or "&" in content:
            patterns.append(r"[;&|`]")

        # Common commands
        commands = ["cat", "ls", "dir", "wget", "curl", "nc"]
        for cmd in commands:
            if cmd in content:
                patterns.append(rf"(?i)\b{cmd}\b")

        return patterns

    def analyze_missed_signatures(
        self, regex_signatures_path: str
    ) -> Dict[str, List[str]]:
        """Analyze which signature categories are missing matches."""
        if self.false_negatives is None:
            raise RuntimeError("Must identify false negatives first")

        # Load existing signatures
        with open(regex_signatures_path, "r") as f:
            signatures = json.load(f)

        # Compile patterns
        compiled_patterns = {}
        for sig in signatures:
            category = sig["id"]
            patterns = []
            for pattern_str in sig["patterns"]:
                try:
                    match = re.match(r"\(\?P<([^>]+)>(.+)\)", pattern_str)
                    if match:
                        pattern_regex = match.group(2)
                    else:
                        pattern_regex = pattern_str
                    compiled = re.compile(pattern_regex, re.IGNORECASE)
                    patterns.append(compiled)
                except re.error:
                    continue
            compiled_patterns[category] = patterns

        # Check which categories have no matches
        category_matches = defaultdict(int)
        for _, row in self.false_negatives.iterrows():
            uri = str(row.get("uri", ""))
            body = str(row.get("body", ""))
            content = f"{uri} {body}"

            for category, patterns in compiled_patterns.items():
                for pattern in patterns:
                    if pattern.search(content):
                        category_matches[category] += 1
                        break

        # Find categories with low coverage
        total_fns = len(self.false_negatives)
        low_coverage = {}
        for category in compiled_patterns.keys():
            match_count = category_matches.get(category, 0)
            coverage = match_count / total_fns if total_fns > 0 else 0
            if coverage < 0.1:  # Less than 10% coverage
                low_coverage[category] = match_count

        print("\n=== Signature Categories with Low Coverage ===")
        for category, count in sorted(
            low_coverage.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {category:30s}: {count:4d} / {total_fns} ({100*count/total_fns:.1f}%)")

        return low_coverage

    def export_false_negatives(self, output_path: str) -> None:
        """Export false negatives to file for manual review."""
        if self.false_negatives is None:
            raise RuntimeError("Must identify false negatives first")

        # Select relevant columns
        export_cols = ["method", "uri", "body", "label"]
        if "attack_family" in self.false_negatives.columns:
            export_cols.append("attack_family")

        export_df = self.false_negatives[
            [col for col in export_cols if col in self.false_negatives.columns]
        ]

        # Export to JSON for readability
        export_df.to_json(output_path, orient="records", indent=2)
        log.info("Exported %d false negatives to %s", len(export_df), output_path)


def main() -> None:
    """Main analysis pipeline."""
    # Find latest primary model
    primary_versions = [
        d
        for d in os.listdir(MODELS_BASE_DIR)
        if os.path.isdir(os.path.join(MODELS_BASE_DIR, d)) and d.startswith("v")
    ]
    if not primary_versions:
        log.error("No primary model found")
        return

    primary_version = max(int(v[1:]) for v in primary_versions)
    primary_model_path = os.path.join(MODELS_BASE_DIR, f"v{primary_version}")

    # Initialize analyzer
    analyzer = FalseNegativeAnalyzer(primary_model_path, PARQUET_PATH)

    # Load model and data
    analyzer.load_model()
    analyzer.load_data()

    # Identify false negatives
    analyzer.identify_false_negatives()

    # Run analyses
    analyzer.analyze_by_attack_family()
    analyzer.extract_common_patterns(top_n=30)
    analyzer.suggest_regex_signatures()

    # Analyze signature coverage
    regex_signatures_path = os.path.join(
        DATA_BASE_DIR, "processed", "modintel_regex.signatures"
    )
    if os.path.exists(regex_signatures_path):
        analyzer.analyze_missed_signatures(regex_signatures_path)

    # Export for manual review
    output_path = os.path.join(DATA_BASE_DIR, "processed", "false_negatives.json")
    analyzer.export_false_negatives(output_path)

    print(f"\n=== Analysis Complete ===")
    print(f"False negatives exported to: {output_path}")
    print(f"Review the suggestions above to improve detection.")


if __name__ == "__main__":
    main()

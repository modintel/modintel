"""
Miss Model Feature Extractor
Specialized feature engineering for false negative detection using regex signatures.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin


class MissModelFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Feature extractor optimized for miss detection (Layer 2).
    
    Combines:
    1. Regex signature matching features (from modintel_regex.signatures)
    2. Advanced request characteristics
    3. Attack pattern indicators
    4. Evasion technique detection
    """

    def __init__(self, regex_signatures_path: str) -> None:
        self.regex_signatures_path = regex_signatures_path
        self.signatures_: Optional[List[Dict[str, Any]]] = None
        self.compiled_patterns_: Optional[Dict[str, List[Tuple[str, re.Pattern]]]] = (
            None
        )
        self.feature_names_: Optional[List[str]] = None
        self.category_names_: Optional[List[str]] = None

    def fit(
        self, X: Union[List[Dict], pd.DataFrame], y=None
    ) -> "MissModelFeatureExtractor":
        """Fit the feature extractor by loading and compiling regex signatures."""
        # Load regex signatures
        with open(self.regex_signatures_path, "r") as f:
            self.signatures_ = json.load(f)

        # Compile regex patterns for each category
        self.compiled_patterns_ = {}
        self.category_names_ = []

        for sig in self.signatures_:
            category = sig["id"]
            self.category_names_.append(category)
            patterns = []

            for pattern_str in sig["patterns"]:
                try:
                    # Extract pattern name and regex
                    match = re.match(r"\(\?P<([^>]+)>(.+)\)", pattern_str)
                    if match:
                        pattern_name = match.group(1)
                        pattern_regex = match.group(2)
                    else:
                        pattern_name = f"pattern_{len(patterns)}"
                        pattern_regex = pattern_str

                    # Compile with case-insensitive flag
                    compiled = re.compile(pattern_regex, re.IGNORECASE)
                    patterns.append((pattern_name, compiled))
                except re.error as e:
                    # Skip invalid patterns
                    continue

            self.compiled_patterns_[category] = patterns

        # Build feature names
        self.feature_names_ = self._build_feature_names()

        return self

    def transform(self, X: Union[Dict, List[Dict], pd.DataFrame]) -> np.ndarray:
        """Transform requests into feature vectors."""
        if self.compiled_patterns_ is None:
            raise RuntimeError(
                "MissModelFeatureExtractor must be fitted before calling transform()."
            )

        if isinstance(X, dict):
            return self._extract_row(X).reshape(1, -1)

        records = self._to_records(X)
        rows = [self._extract_row(r) for r in records]
        return np.array(rows, dtype=np.float64)

    def fit_transform(
        self, X: Union[List[Dict], pd.DataFrame], y=None, **fit_params
    ) -> np.ndarray:
        """Fit and transform in one step."""
        return self.fit(X, y).transform(X)

    def get_feature_names_out(self) -> List[str]:
        """Get feature names."""
        if self.feature_names_ is None:
            raise RuntimeError("MissModelFeatureExtractor must be fitted first.")
        return list(self.feature_names_)

    def save(self, path: str) -> None:
        """Save the feature extractor."""
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str) -> "MissModelFeatureExtractor":
        """Load a saved feature extractor."""
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(f"Expected MissModelFeatureExtractor, got {type(obj)}")
        return obj

    def _to_records(self, X: Union[List[Dict], pd.DataFrame]) -> List[Dict]:
        """Convert input to list of dictionaries."""
        if isinstance(X, pd.DataFrame):
            return X.to_dict(orient="records")
        if isinstance(X, list):
            return X
        raise TypeError(f"Unsupported input type: {type(X)}")

    def _build_feature_names(self) -> List[str]:
        """Build comprehensive feature names."""
        names: List[str] = []

        # 1. Signature category match counts
        for category in self.category_names_:
            names.append(f"sig_count_{category}")

        # 2. Signature category binary indicators
        for category in self.category_names_:
            names.append(f"sig_has_{category}")

        # 3. Total signature matches
        names.append("sig_total_matches")
        names.append("sig_unique_categories")

        # 4. Request characteristics
        names += [
            "req_method_int",
            "req_uri_length",
            "req_uri_depth",
            "req_query_param_count",
            "req_body_length",
            "req_has_body",
            "req_header_count",
        ]

        # 5. Content analysis
        names += [
            "content_entropy",
            "content_special_char_ratio",
            "content_digit_ratio",
            "content_alpha_ratio",
            "content_space_ratio",
            "content_max_token_length",
        ]

        # 6. Encoding and evasion indicators
        names += [
            "evasion_url_encoding_count",
            "evasion_unicode_encoding_count",
            "evasion_hex_encoding_count",
            "evasion_double_encoding",
            "evasion_null_byte",
            "evasion_comment_injection",
            "evasion_case_variation",
        ]

        # 7. Attack pattern indicators
        names += [
            "pattern_sql_keywords",
            "pattern_xss_tags",
            "pattern_path_traversal",
            "pattern_command_injection",
            "pattern_script_tags",
            "pattern_event_handlers",
        ]

        # 8. Statistical features
        names += [
            "stat_uri_query_ratio",
            "stat_body_uri_ratio",
            "stat_non_printable_count",
            "stat_consecutive_special_chars",
        ]

        return names

    def _extract_row(self, record: Dict) -> np.ndarray:
        """Extract features from a single request record."""
        features: List[float] = []

        # Extract request components
        method = str(record.get("method") or "").upper()
        uri = str(record.get("uri") or "")
        body = str(record.get("body") or "")
        headers = record.get("headers", {})

        # Combine all searchable content
        combined_content = f"{uri} {body}"

        # 1. Signature matching features
        category_matches = self._match_signatures(combined_content)

        # Category match counts
        for category in self.category_names_:
            features.append(float(category_matches.get(category, 0)))

        # Category binary indicators
        for category in self.category_names_:
            features.append(1.0 if category_matches.get(category, 0) > 0 else 0.0)

        # Total matches and unique categories
        total_matches = sum(category_matches.values())
        unique_categories = len([c for c in category_matches.values() if c > 0])
        features.append(float(total_matches))
        features.append(float(unique_categories))

        # 2. Request characteristics
        method_map = {
            "GET": 0,
            "POST": 1,
            "PUT": 2,
            "DELETE": 3,
            "PATCH": 4,
            "HEAD": 5,
            "OPTIONS": 6,
        }
        features.append(float(method_map.get(method, -1)))
        features.append(float(len(uri)))
        features.append(float(self._uri_depth(uri)))
        features.append(float(self._query_param_count(uri)))
        features.append(float(len(body)))
        features.append(1.0 if body else 0.0)
        features.append(float(self._header_count(headers)))

        # 3. Content analysis
        features.append(self._shannon_entropy(combined_content))
        features.append(self._special_char_ratio(combined_content))
        features.append(self._digit_ratio(combined_content))
        features.append(self._alpha_ratio(combined_content))
        features.append(self._space_ratio(combined_content))
        features.append(float(self._max_token_length(combined_content)))

        # 4. Encoding and evasion indicators
        features.append(float(self._count_url_encoding(combined_content)))
        features.append(float(self._count_unicode_encoding(combined_content)))
        features.append(float(self._count_hex_encoding(combined_content)))
        features.append(1.0 if self._has_double_encoding(combined_content) else 0.0)
        features.append(1.0 if self._has_null_byte(combined_content) else 0.0)
        features.append(1.0 if self._has_comment_injection(combined_content) else 0.0)
        features.append(1.0 if self._has_case_variation(combined_content) else 0.0)

        # 5. Attack pattern indicators
        features.append(float(self._count_sql_keywords(combined_content)))
        features.append(float(self._count_xss_tags(combined_content)))
        features.append(float(self._count_path_traversal(combined_content)))
        features.append(float(self._count_command_injection(combined_content)))
        features.append(float(self._count_script_tags(combined_content)))
        features.append(float(self._count_event_handlers(combined_content)))

        # 6. Statistical features
        features.append(self._uri_query_ratio(uri))
        features.append(self._body_uri_ratio(body, uri))
        features.append(float(self._non_printable_count(combined_content)))
        features.append(float(self._consecutive_special_chars(combined_content)))

        return np.array(features, dtype=np.float64)

    def _match_signatures(self, content: str) -> Dict[str, int]:
        """Match content against all regex signatures."""
        matches: Dict[str, int] = {}

        for category, patterns in self.compiled_patterns_.items():
            count = 0
            for pattern_name, compiled_pattern in patterns:
                if compiled_pattern.search(content):
                    count += 1
            matches[category] = count

        return matches

    # ===== Helper Methods =====

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        total = len(text)
        counts: Dict[str, int] = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _special_char_ratio(text: str) -> float:
        """Calculate ratio of special characters."""
        if not text:
            return 0.0
        special_chars = set("%'\"<>{}[]()&|;$`\\")
        special_count = sum(1 for ch in text if ch in special_chars)
        return special_count / len(text)

    @staticmethod
    def _digit_ratio(text: str) -> float:
        """Calculate ratio of digit characters."""
        if not text:
            return 0.0
        digit_count = sum(1 for ch in text if ch.isdigit())
        return digit_count / len(text)

    @staticmethod
    def _alpha_ratio(text: str) -> float:
        """Calculate ratio of alphabetic characters."""
        if not text:
            return 0.0
        alpha_count = sum(1 for ch in text if ch.isalpha())
        return alpha_count / len(text)

    @staticmethod
    def _space_ratio(text: str) -> float:
        """Calculate ratio of whitespace characters."""
        if not text:
            return 0.0
        space_count = sum(1 for ch in text if ch.isspace())
        return space_count / len(text)

    @staticmethod
    def _max_token_length(text: str) -> int:
        """Find maximum token length."""
        if not text:
            return 0
        tokens = re.split(r"[\s&=;,]", text)
        return max((len(t) for t in tokens), default=0)

    @staticmethod
    def _uri_depth(uri: str) -> int:
        """Calculate URI path depth."""
        try:
            path = urlparse(uri).path
            segments = [s for s in path.split("/") if s]
            return len(segments)
        except Exception:
            return 0

    @staticmethod
    def _query_param_count(uri: str) -> int:
        """Count query parameters."""
        try:
            query = urlparse(uri).query
            if not query:
                return 0
            return len(parse_qs(query, keep_blank_values=True))
        except Exception:
            return 0

    @staticmethod
    def _header_count(headers: Any) -> int:
        """Count HTTP headers."""
        if not headers:
            return 0
        if isinstance(headers, dict):
            return len(headers)
        if isinstance(headers, str):
            return sum(1 for line in headers.splitlines() if ":" in line)
        return 0

    @staticmethod
    def _count_url_encoding(text: str) -> int:
        """Count URL-encoded sequences."""
        return len(re.findall(r"%[0-9A-Fa-f]{2}", text))

    @staticmethod
    def _count_unicode_encoding(text: str) -> int:
        """Count Unicode escape sequences."""
        return len(re.findall(r"\\u[0-9A-Fa-f]{4}", text))

    @staticmethod
    def _count_hex_encoding(text: str) -> int:
        """Count hex escape sequences."""
        return len(re.findall(r"\\x[0-9A-Fa-f]{2}", text))

    @staticmethod
    def _has_double_encoding(text: str) -> bool:
        """Detect double encoding."""
        return bool(re.search(r"%25[0-9A-Fa-f]{2}", text))

    @staticmethod
    def _has_null_byte(text: str) -> bool:
        """Detect null byte injection."""
        return "\x00" in text or "%00" in text or "\\x00" in text

    @staticmethod
    def _has_comment_injection(text: str) -> bool:
        """Detect comment injection patterns."""
        patterns = [r"--", r"/\*", r"\*/", r"#", r"<!--", r"-->"]
        return any(re.search(p, text) for p in patterns)

    @staticmethod
    def _has_case_variation(text: str) -> bool:
        """Detect case variation evasion (e.g., SeLeCt)."""
        sql_keywords = ["select", "union", "insert", "update", "delete", "drop"]
        text_lower = text.lower()
        for keyword in sql_keywords:
            if keyword in text_lower:
                # Check if original has mixed case
                for match in re.finditer(re.escape(keyword), text_lower):
                    original = text[match.start() : match.end()]
                    if original != original.lower() and original != original.upper():
                        return True
        return False

    @staticmethod
    def _count_sql_keywords(text: str) -> int:
        """Count SQL keywords."""
        keywords = [
            "select",
            "union",
            "insert",
            "update",
            "delete",
            "drop",
            "create",
            "alter",
            "exec",
            "execute",
            "cast",
            "convert",
            "declare",
            "table",
            "from",
            "where",
            "order",
            "group",
            "having",
        ]
        text_lower = text.lower()
        return sum(1 for kw in keywords if kw in text_lower)

    @staticmethod
    def _count_xss_tags(text: str) -> int:
        """Count XSS-related HTML tags."""
        tags = [
            "script",
            "iframe",
            "object",
            "embed",
            "applet",
            "meta",
            "link",
            "style",
            "img",
            "svg",
        ]
        text_lower = text.lower()
        return sum(1 for tag in tags if f"<{tag}" in text_lower)

    @staticmethod
    def _count_path_traversal(text: str) -> int:
        """Count path traversal patterns."""
        patterns = [r"\.\./", r"\.\.", r"%2e%2e", r"\.\.\\", r"%5c%2e%2e"]
        return sum(len(re.findall(p, text, re.IGNORECASE)) for p in patterns)

    @staticmethod
    def _count_command_injection(text: str) -> int:
        """Count command injection indicators."""
        patterns = [r"[;&|`$]", r"\$\(", r"`.*`", r">\s*/dev/", r"<\s*\("]
        return sum(len(re.findall(p, text)) for p in patterns)

    @staticmethod
    def _count_script_tags(text: str) -> int:
        """Count script tags."""
        return len(re.findall(r"<script[^>]*>", text, re.IGNORECASE))

    @staticmethod
    def _count_event_handlers(text: str) -> int:
        """Count JavaScript event handlers."""
        handlers = [
            "onclick",
            "onerror",
            "onload",
            "onmouseover",
            "onfocus",
            "onblur",
            "onchange",
        ]
        text_lower = text.lower()
        return sum(1 for handler in handlers if handler in text_lower)

    @staticmethod
    def _uri_query_ratio(uri: str) -> float:
        """Calculate ratio of query string to total URI length."""
        if not uri:
            return 0.0
        try:
            query = urlparse(uri).query
            if not query:
                return 0.0
            return len(query) / len(uri)
        except Exception:
            return 0.0

    @staticmethod
    def _body_uri_ratio(body: str, uri: str) -> float:
        """Calculate ratio of body length to URI length."""
        uri_len = len(uri) if uri else 1
        body_len = len(body) if body else 0
        return body_len / uri_len

    @staticmethod
    def _non_printable_count(text: str) -> int:
        """Count non-printable characters."""
        return sum(1 for ch in text if ord(ch) < 32 or ord(ch) == 127)

    @staticmethod
    def _consecutive_special_chars(text: str) -> int:
        """Find maximum consecutive special characters."""
        if not text:
            return 0
        special_chars = set("%'\"<>{}[]()&|;$`\\")
        max_consecutive = 0
        current_consecutive = 0

        for ch in text:
            if ch in special_chars:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0

        return max_consecutive

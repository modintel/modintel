

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin


METHOD_MAP: Dict[str, int] = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "DELETE": 3,
    "PATCH": 4,
    "HEAD": 5,
    "OPTIONS": 6,
}

CONTENT_TYPE_MAP: Dict[str, int] = {
    "application/json": 0,
    "application/x-www-form-urlencoded": 1,
    "multipart/form-data": 2,
    "text/plain": 3,
    "text/html": 4,
}

SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 3,
    "WARNING": 2,
    "NOTICE": 1,
}

SPECIAL_CHARS = set("%'\"<>{}")

_ENCODING_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")




def _shannon_entropy(text: str) -> float:
    
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


def _special_char_ratio(text: str) -> float:
    
    if not text:
        return 0.0
    special_count = sum(1 for ch in text if ch in SPECIAL_CHARS)
    return special_count / len(text)


def _has_encoding_artifacts(uri: str, body: str) -> bool:
    
    combined = (uri or "") + (body or "")
    return bool(_ENCODING_PATTERN.search(combined))


def _non_printable_count(text: str) -> int:
    
    return sum(1 for ch in text if ord(ch) < 32 or ord(ch) == 127)


def _uri_depth(uri: str) -> int:
    
    try:
        path = urlparse(uri).path
        segments = [s for s in path.split("/") if s]
        return len(segments)
    except Exception:
        return 0


def _query_param_count(uri: str) -> int:
    
    try:
        query = urlparse(uri).query
        if not query:
            return 0
        return len(parse_qs(query, keep_blank_values=True))
    except Exception:
        return 0


def _max_param_value_length(uri: str, body: str) -> int:
    
    max_len = 0
    try:
        query = urlparse(uri).query
        if query:
            for values in parse_qs(query, keep_blank_values=True).values():
                for v in values:
                    max_len = max(max_len, len(v))
    except Exception:
        pass
    try:
        if body:
            for values in parse_qs(body, keep_blank_values=True).values():
                for v in values:
                    max_len = max(max_len, len(v))
    except Exception:
        pass
    return max_len


def _encode_content_type(headers: Any) -> int:
    
    if not headers:
        return -2
    ct = ""
    if isinstance(headers, dict):
        ct = headers.get("Content-Type", headers.get("content-type", ""))
    elif isinstance(headers, str):
        for line in headers.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                if key.strip().lower() == "content-type":
                    ct = val.strip()
                    break
    if not ct:
        return -2
    ct_base = ct.split(";")[0].strip().lower()
    return CONTENT_TYPE_MAP.get(ct_base, -1)


def _header_count(headers: Any) -> int:
    
    if not headers:
        return 0
    if isinstance(headers, dict):
        return len(headers)
    if isinstance(headers, str):
        return sum(1 for line in headers.splitlines() if ":" in line)
    return 0


def _is_sqli_rule(rule_id: str, message: str) -> bool:
    rid = str(rule_id).lower()
    msg = (message or "").lower()
    return "sqli" in rid or "942" in rid or "sqli" in msg or "942" in msg


def _is_xss_rule(rule_id: str, message: str) -> bool:
    rid = str(rule_id).lower()
    msg = (message or "").lower()
    return "xss" in rid or "941" in rid or "xss" in msg or "941" in msg


def _is_lfi_rule(rule_id: str, message: str) -> bool:
    rid = str(rule_id).lower()
    msg = (message or "").lower()
    return "lfi" in rid or "930" in rid or "lfi" in msg or "930" in msg


def _is_rce_rule(rule_id: str, message: str) -> bool:
    rid = str(rule_id).lower()
    msg = (message or "").lower()
    return "rce" in rid or "932" in rid or "rce" in msg or "932" in msg




class WAFFeatureExtractor(BaseEstimator, TransformerMixin):
    

    def __init__(self) -> None:
        self.rule_ids_: Optional[List[str]] = None
        self.feature_names_: Optional[List[str]] = None


    def fit(self, X: Union[List[Dict], pd.DataFrame], y=None) -> "WAFFeatureExtractor":
        
        records = self._to_records(X)
        seen_rule_ids: set = set()
        for record in records:
            for rid in record.get("fired_rule_ids", []):
                seen_rule_ids.add(str(rid))
        self.rule_ids_ = sorted(seen_rule_ids)
        self.feature_names_ = self._build_feature_names()
        return self

    def transform(self, X: Union[Dict, List[Dict], pd.DataFrame]) -> np.ndarray:
        
        if self.rule_ids_ is None:
            raise RuntimeError(
                "WAFFeatureExtractor must be fitted before calling transform()."
            )

        if isinstance(X, dict):
            return self._extract_row(X).reshape(1, -1)

        records = self._to_records(X)
        rows = [self._extract_row(r) for r in records]
        return np.array(rows, dtype=np.float64)

    def fit_transform(
        self, X: Union[List[Dict], pd.DataFrame], y=None, **fit_params
    ) -> np.ndarray:
        
        return self.fit(X, y).transform(X)

    def get_feature_names_out(self) -> List[str]:
        
        if self.feature_names_ is None:
            raise RuntimeError("WAFFeatureExtractor must be fitted first.")
        return list(self.feature_names_)


    def save(self, path: str) -> None:
        
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str) -> "WAFFeatureExtractor":
        
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(f"Expected WAFFeatureExtractor, got {type(obj)}")
        return obj


    @staticmethod
    def validate_parity(
        training_schema: Dict[str, Any],
        serving_schema: Dict[str, Any],
    ) -> List[str]:
        
        discrepancies: List[str] = []

        training_features = training_schema.get("features", {})
        serving_features = serving_schema.get("features", {})

        training_keys = set(training_features.keys())
        serving_keys = set(serving_features.keys())

        for key in sorted(training_keys - serving_keys):
            discrepancies.append(
                f"Feature '{key}' present in training schema but missing from serving schema."
            )

        for key in sorted(serving_keys - training_keys):
            discrepancies.append(
                f"Feature '{key}' present in serving schema but missing from training schema."
            )

        for key in sorted(training_keys & serving_keys):
            t_feat = training_features[key]
            s_feat = serving_features[key]

            if t_feat.get("type") != s_feat.get("type"):
                discrepancies.append(
                    f"Feature '{key}' type mismatch: training={t_feat.get('type')!r}, serving={s_feat.get('type')!r}."
                )

            if t_feat.get("group") != s_feat.get("group"):
                discrepancies.append(
                    f"Feature '{key}' group mismatch: training={t_feat.get('group')!r}, serving={s_feat.get('group')!r}."
                )

            t_range = t_feat.get("range")
            s_range = s_feat.get("range")
            if t_range != s_range:
                discrepancies.append(
                    f"Feature '{key}' range mismatch: training={t_range!r}, serving={s_range!r}."
                )

        t_version = training_schema.get("version")
        s_version = serving_schema.get("version")
        if t_version != s_version:
            discrepancies.append(
                f"Schema version mismatch: training={t_version!r}, serving={s_version!r}."
            )

        return discrepancies


    def _to_records(self, X: Union[List[Dict], pd.DataFrame]) -> List[Dict]:
        
        if isinstance(X, pd.DataFrame):
            return X.to_dict(orient="records")
        if isinstance(X, list):
            return X
        raise TypeError(f"Unsupported input type: {type(X)}")

    def _build_feature_names(self) -> List[str]:
        
        names: List[str] = []

        for rid in self.rule_ids_:
            names.append(f"rule_{rid}")

        names += [
            "num_sqli_rules",
            "num_xss_rules",
            "num_lfi_rules",
            "num_rce_rules",
            "severity_weighted_sum",
            "total_rule_count",
        ]

        names += [
            "anomaly_score",
            "anomaly_score_normalized",
            "is_above_threshold",
        ]

        names += [
            "method_int",
            "uri_length",
            "uri_depth",
            "query_param_count",
            "body_length",
            "has_body",
            "content_type_int",
            "header_count",
        ]

        names += [
            "special_char_ratio",
            "shannon_entropy",
            "max_param_value_length",
            "has_encoding_artifacts",
            "non_printable_count",
        ]

        return names

    def _extract_row(self, record: Dict) -> np.ndarray:
        
        features: List[float] = []

        raw_rule_ids = record.get("fired_rule_ids", [])
        try:
            fired_rule_ids = (
                [str(r) for r in raw_rule_ids] if raw_rule_ids is not None else []
            )
        except TypeError:
            fired_rule_ids = []

        raw_sev = record.get("rule_severities")
        if isinstance(raw_sev, dict):
            rule_severities: Dict[str, str] = raw_sev
        elif isinstance(raw_sev, (list, tuple)) and raw_sev is not None:
            rule_severities = {
                str(rid): str(sev) for rid, sev in zip(fired_rule_ids, raw_sev)
            }
        else:
            rule_severities = {}

        raw_msg = record.get("rule_messages")
        if isinstance(raw_msg, dict):
            rule_messages: Dict[str, str] = raw_msg
        elif isinstance(raw_msg, (list, tuple)) and raw_msg is not None:
            rule_messages = {
                str(rid): str(msg) for rid, msg in zip(fired_rule_ids, raw_msg)
            }
        else:
            rule_messages = {}

        raw_score = record.get("anomaly_score", 0)
        anomaly_score = float(raw_score) if raw_score is not None else 0.0

        raw_thresh = record.get("inbound_threshold", 0)
        inbound_threshold = float(raw_thresh) if raw_thresh is not None else 0.0
        method = str(record.get("method") or "").upper()
        uri = str(record.get("uri") or "")
        headers = record.get("headers")
        body = str(record.get("body") or "")

        fired_set = set(fired_rule_ids)

        for rid in self.rule_ids_:
            features.append(1.0 if rid in fired_set else 0.0)

        num_sqli = 0
        num_xss = 0
        num_lfi = 0
        num_rce = 0
        severity_sum = 0.0

        for rid in fired_rule_ids:
            msg = rule_messages.get(rid, "")
            if _is_sqli_rule(rid, msg):
                num_sqli += 1
            if _is_xss_rule(rid, msg):
                num_xss += 1
            if _is_lfi_rule(rid, msg):
                num_lfi += 1
            if _is_rce_rule(rid, msg):
                num_rce += 1
            sev = str(rule_severities.get(rid, "")).upper()
            severity_sum += SEVERITY_WEIGHTS.get(sev, 0)

        features += [
            float(num_sqli),
            float(num_xss),
            float(num_lfi),
            float(num_rce),
            severity_sum,
            float(len(fired_rule_ids)),
        ]

        if inbound_threshold > 0:
            normalized = anomaly_score / inbound_threshold
        else:
            normalized = 0.0
        is_above = 1.0 if anomaly_score > inbound_threshold else 0.0

        features += [anomaly_score, normalized, is_above]

        method_int = float(METHOD_MAP.get(method, -1))
        uri_length = float(len(uri))
        uri_depth = float(_uri_depth(uri))
        query_param_count = float(_query_param_count(uri))
        body_length = float(len(body))
        has_body = 1.0 if body else 0.0
        content_type_int = float(_encode_content_type(headers))
        header_count = float(_header_count(headers))

        features += [
            method_int,
            uri_length,
            uri_depth,
            query_param_count,
            body_length,
            has_body,
            content_type_int,
            header_count,
        ]

        combined = uri + body
        special_ratio = _special_char_ratio(combined)
        entropy = _shannon_entropy(combined)
        max_param_len = float(_max_param_value_length(uri, body))
        encoding_artifacts = 1.0 if _has_encoding_artifacts(uri, body) else 0.0
        non_printable = float(_non_printable_count(combined))

        features += [
            special_ratio,
            entropy,
            max_param_len,
            encoding_artifacts,
            non_printable,
        ]

        return np.array(features, dtype=np.float64)

from __future__ import annotations

import math
import os
import re
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_SQLI_PATTERNS = re.compile(
    r"(?:'|\bunion\b|\bselect\b|\binsert\b|\bdrop\b|\bexec\b|--|;)",
    re.IGNORECASE,
)
_XSS_PATTERNS = re.compile(
    r"(?:<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)",
    re.IGNORECASE,
)
_TRAVERSAL_PATTERNS = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e/|/etc/passwd|/etc/shadow|win\.ini)",
    re.IGNORECASE,
)
_CMDI_PATTERNS = re.compile(
    r"(?:\||\x60|\$\(|\bcmd\b|\bping\b|\bnslookup\b|\bwget\b|\bcurl\b)",
    re.IGNORECASE,
)
_SUSPICIOUS_UA = re.compile(
    r"(?:sqlmap|nikto|nmap|burp|acunetix|nessus|openvas|w3af|zap)",
    re.IGNORECASE,
)
_ENCODING_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")
_DOUBLE_ENCODING = re.compile(r"%25[0-9A-Fa-f]{2}")
_NOSQL_PATTERNS = re.compile(r"\$(?:gt|lt|ne|where|regex|nin|exists)\b")
_SSTI_PATTERNS = re.compile(r"\{\{|\$\{|\{%")
_XXE_PATTERNS = re.compile(r"<!ENTITY|<!DOCTYPE|file:///|data://|php://")
_LOG4J_PATTERNS = re.compile(r"\$\{jndi:")
_PROTO_POLLUTION = re.compile(r"__proto__|constructor\.prototype")
_SQL_KEYWORDS = [
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
    "declare",
]
_XSS_TAGS = ["<script", "<iframe", "<object", "<embed", "<img", "<svg", "<meta"]
_EVENT_HANDLERS = [
    "onclick",
    "onerror",
    "onload",
    "onmouseover",
    "onfocus",
    "onblur",
    "onchange",
    "onsubmit",
]


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
    special_chars = set("%'\"<>{}[]()&|;$`\\")
    special_count = sum(1 for ch in text if ch in special_chars)
    return special_count / len(text)


class MissONNXInference:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.session = None
        self.input_names: List[str] = []
        self._load_model()

    def _load_model(self):
        try:
            import onnxruntime as ort

            self.session = ort.InferenceSession(
                self.model_path,
                providers=["CPUExecutionProvider"],
            )
            self.input_names = [inp.name for inp in self.session.get_inputs()]
        except Exception as exc:
            raise RuntimeError(f"Failed to load ONNX model: {exc}")

    def predict(self, request: Dict[str, any]) -> Dict[str, any]:
        features = self._extract_features(request)
        X = np.array([features], dtype=np.float32)

        text = (request.get("uri", "") + " " + request.get("body", ""))[:256]
        char_list = [ord(c) for c in text] + [0] * max(0, 256 - len(text))
        char_seq = np.array([char_list], dtype=np.int64)

        try:
            feed_dict = {}
            if "features" in self.input_names:
                feed_dict["features"] = X
            if "char_seq" in self.input_names:
                feed_dict["char_seq"] = char_seq

            raw = self.session.run(None, feed_dict)[0]
            if raw.shape[1] == 2:
                logit = float(raw[0][1])
            elif raw.shape[1] == 1:
                logit = float(raw[0][0])
            else:
                logit = float(raw[0][0])
            prob = 1.0 / (1.0 + np.exp(-logit))
        except Exception:
            prob = 0.5

        prob = max(0.0, min(1.0, prob))
        entropy = -(
            prob * math.log2(prob + 1e-9) + (1 - prob) * math.log2(1 - prob + 1e-9)
        )
        h_max = 1.0
        h_norm = entropy / h_max if h_max > 0 else 0.0
        confidence = round((1.0 - h_norm) * 100.0, 2)
        band, reasoning = self._assign_priority(prob)
        return {
            "attack_probability": round(prob, 6),
            "confidence_score": confidence,
            "recommended_priority": band,
            "priority_reasoning": reasoning,
            "entropy": round(entropy, 4),
            "entropy_normalized": round(h_norm, 4),
            "advisory_only": True,
            "model_version": "onnx-miss-v4",
        }

    def _assign_priority(self, prob: float) -> Tuple[str, str]:
        if prob >= 0.8:
            return "P1", "High probability miss detection"
        elif prob >= 0.5:
            return "P2", "Moderate probability miss detection"
        else:
            return "P3", "Low probability miss detection"

    def _extract_features(self, req: Dict[str, any]) -> List[float]:
        method = req.get("method", "")
        uri = req.get("uri", "")
        headers = req.get("headers", {})
        body = req.get("body", "")

        if isinstance(headers, dict):
            pass
        elif isinstance(headers, str):
            try:
                import json

                headers = json.loads(headers)
            except Exception:
                headers = {}
        else:
            headers = {}

        parsed = urlparse(uri)
        path = parsed.path.lower()
        query = parsed.query
        combined = f"{uri} {body}"
        combined_lower = combined.lower()
        ua = (headers.get("user-agent") or headers.get("User-Agent") or "").lower()
        ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()

        features: List[float] = []

        method_vec = [0.0] * 6
        method_map = {"get": 0, "post": 1, "put": 2, "delete": 3, "patch": 4, "head": 5}
        if method.lower() in method_map:
            method_vec[method_map[method.lower()]] = 1.0
        features.extend(method_vec)

        features.append(len(path))
        features.append(path.count("/"))
        features.append(1.0 if ".." in path or "%2e%2e" in path.lower() else 0.0)
        features.append(
            1.0
            if any(
                ext in path for ext in [".php", ".jsp", ".asp", ".py", ".sh", ".cgi"]
            )
            else 0.0
        )
        features.append(
            1.0 if "admin" in path or "login" in path or "auth" in path else 0.0
        )
        features.append(1.0 if "api" in path else 0.0)
        features.append(1.0 if "rest" in path or "graphql" in path else 0.0)
        features.append(1.0 if re.search(r"\d{4,}", path) else 0.0)

        qparams = parse_qs(query)
        features.append(len(qparams))
        features.append(sum(len(v[0]) for v in qparams.values() if v))
        sensitive_params = [
            "id",
            "page",
            "file",
            "path",
            "url",
            "redirect",
            "cmd",
            "exec",
            "command",
            "debug",
            "action",
            "template",
        ]
        features.append(
            1.0 if any(k.lower() in sensitive_params for k in qparams) else 0.0
        )
        features.append(
            1.0
            if any(
                k.lower() in ["__proto__", "constructor", "prototype"] for k in qparams
            )
            else 0.0
        )

        features.append(len(body))
        features.append(1.0 if body else 0.0)
        features.append(_shannon_entropy(body))
        features.append(_special_char_ratio(combined))
        features.append(sum(1 for c in body if ord(c) < 32 or ord(c) == 127))
        features.append(len(re.findall(r"%[0-9A-Fa-f]{2}", body)))

        features.append(1.0 if _SQLI_PATTERNS.search(combined) else 0.0)
        features.append(sum(1 for kw in _SQL_KEYWORDS if kw in combined_lower))
        features.append(1.0 if _XSS_PATTERNS.search(combined) else 0.0)
        features.append(sum(1 for tag in _XSS_TAGS if tag in combined_lower))
        features.append(sum(1 for h in _EVENT_HANDLERS if h in combined_lower))
        features.append(1.0 if _TRAVERSAL_PATTERNS.search(combined) else 0.0)
        features.append(1.0 if _CMDI_PATTERNS.search(combined) else 0.0)
        features.append(1.0 if _NOSQL_PATTERNS.search(combined) else 0.0)
        features.append(1.0 if _SSTI_PATTERNS.search(combined) else 0.0)
        features.append(1.0 if _XXE_PATTERNS.search(combined) else 0.0)
        features.append(1.0 if _LOG4J_PATTERNS.search(combined) else 0.0)
        features.append(1.0 if _PROTO_POLLUTION.search(combined) else 0.0)

        features.append(1.0 if _SUSPICIOUS_UA.search(ua) else 0.0)
        features.append(
            1.0 if "powershell" in ua or "curl" in ua or "wget" in ua else 0.0
        )
        features.append(
            1.0 if "bot" in ua or "crawler" in ua or "spider" in ua else 0.0
        )
        features.append(1.0 if not ua or ua == "-" or len(ua) < 10 else 0.0)

        features.append(1.0 if "xml" in ct else 0.0)
        features.append(1.0 if "json" in ct else 0.0)
        features.append(1.0 if "form" in ct or "x-www-form" in ct else 0.0)

        encodings = _ENCODING_PATTERN.findall(combined)
        features.append(len(encodings))
        features.append(len(_DOUBLE_ENCODING.findall(combined)))
        features.append(1.0 if "\x00" in combined or "%00" in combined else 0.0)
        features.append(
            1.0 if "--" in combined or "/*" in combined or "#" in combined else 0.0
        )
        features.append(1.0 if "<!--" in combined or "-->" in combined else 0.0)
        features.append(sum(1 for c in combined if c in "'<>`\"|;$&\\"))
        features.append(1.0 if _has_case_variation(combined_lower, body) else 0.0)

        features.append(len(re.findall(r"\w+", combined)))
        features.append(len(re.findall(r"[^\w\s]", combined)))
        features.append(sum(1 for c in combined if c.isdigit()))
        features.append(_shannon_entropy(uri))
        features.append(len(body) / max(len(uri), 1))

        while len(features) < 135:
            features.append(0.0)

        return features[:135]


def _has_case_variation(text_lower: str, original: str) -> bool:
    for keyword in ["select", "union", "insert", "update", "delete", "drop"]:
        if keyword in text_lower:
            idx = text_lower.find(keyword)
            if idx >= 0:
                segment = original[idx : idx + len(keyword)]
                if segment != segment.lower() and segment != segment.upper():
                    return True
    return False

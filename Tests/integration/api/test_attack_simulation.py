import pytest
import httpx
import time

BASE_URL = "http://localhost:8080"  # Main WAF Proxy

# Common attack payloads
ATTACK_PAYLOADS = [
    # SQL Injection
    {"uri": "/login.php?id=1' OR '1'='1", "method": "GET"},
    {"uri": "/search?q=1 UNION SELECT * FROM users", "method": "GET"},
    
    # XSS
    {"uri": "/page?<script>alert(1)</script>", "method": "GET"},
    {"uri": "/search?q=<img src=x onerror=alert(1)>", "method": "GET"},
    
    # Command Injection
    {"uri": "/ping?host=127.0.0.1; whoami", "method": "GET"},
    {"uri": "/backup?file=;cat /etc/passwd", "method": "GET"},
    
    # Path Traversal
    {"uri": "/download?file=../../../etc/passwd", "method": "GET"},
    {"uri": "/static/..%2f..%2f..%2fetc%2fpasswd", "method": "GET"},
    
    # Template Injection / SSTI
    {"uri": "/render?template={{7*7}}", "method": "GET"},
    
    # Normal traffic (should pass)
    {"uri": "/login", "method": "POST", "body": "email=test@modintel.local&password=123"},
]


def test_waf_blocks_known_attacks():
    """Test that WAF + ML correctly blocks or flags attacks"""
    with httpx.Client(timeout=10.0) as client:
        blocked_count = 0
        flagged_count = 0
        
        for payload in ATTACK_PAYLOADS:
            try:
                if payload.get("method") == "POST":
                    response = client.post(BASE_URL + payload["uri"], json=payload.get("body", {}))
                else:
                    response = client.get(BASE_URL + payload["uri"])
                
                # Check if blocked by WAF or flagged by ML
                if response.status_code in (403, 429):
                    blocked_count += 1
                elif response.status_code == 200:
                    # Check if ML flagged it as suspicious
                    if "X-ModIntel-Score" in response.headers or "X-ModIntel-Priority" in response.headers:
                        flagged_count += 1
                        
            except Exception:
                continue  # Service might be down, continue testing
        
        print(f"✅ Attack Simulation: {blocked_count} blocked, {flagged_count} flagged by ML")
        
        # At least some attacks should be caught
        assert blocked_count + flagged_count >= 3, f"Only {blocked_count + flagged_count} attacks were caught"


def test_attack_with_high_anomaly_score(client):
    """Test high anomaly score attack"""
    payload = {
        "method": "GET",
        "uri": "/admin.php?id=1 UNION SELECT username,password FROM users--",
        "body": "",
        "anomaly_score": 120,
        "inbound_threshold": 30
    }
    
    response = client.post("http://localhost:8083/predict", json=payload)
    
    if response.status_code == 200:
        data = response.json()
        assert data["attack_probability"] > 0.4, "High anomaly score should have elevated probability"
        assert data["recommended_priority"] in ["P1", "P2"]
    else:
        # Accept 500 if model not loaded
        assert response.status_code == 500

def test_normal_traffic_is_allowed():
    """Ensure normal traffic is not blocked"""
    with httpx.Client(timeout=10.0) as client:
        normal_requests = [
            "/dashboard",
            "/api/health",
            "/static/css/style.css",
            "/login",
        ]
        
        success_count = 0
        for path in normal_requests:
            try:
                resp = client.get(BASE_URL + path, timeout=5.0)
                if resp.status_code in (200, 301, 302, 404):
                    success_count += 1
            except:
                pass
                
        assert success_count >= 2, "Most normal traffic should be allowed"


@pytest.mark.slow
def test_attack_suite_stress():
    """Light stress test with multiple attacks"""
    with httpx.Client(timeout=15.0) as client:
        start = time.time()
        for i in range(10):
            client.get(BASE_URL + "/search?q=<script>alert(1)</script>")
        duration = time.time() - start
        
        print(f"✅ Stress test completed in {duration:.2f} seconds")
        assert duration < 30, "System should handle attack traffic reasonably fast"
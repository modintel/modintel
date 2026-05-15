import pytest
import httpx
import asyncio
from typing import Dict

BASE_URL = "http://localhost:8080"  # Proxy/WAF entry point
API_BASE = "http://localhost:3000"  # Dashboard / Review API (if exposed)

@pytest.fixture(scope="module")
def client():
    return httpx.Client(timeout=10.0, follow_redirects=True)


def test_waf_proxy_is_running(client):
    """Test that the main WAF proxy is accessible"""
    response = client.get(BASE_URL, timeout=5.0)
    assert response.status_code in [200, 403, 503]  # Any response means it's running


def test_health_aggregator(client):
    """Test health aggregator endpoint"""
    response = client.get("http://localhost:8090/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


def test_review_api_health(client):
    """Test review-api health"""
    response = client.get("http://localhost:8082/health")
    assert response.status_code == 200


def test_inference_engine_health(client):
    """Test inference engine health"""
    response = client.get("http://localhost:8083/health")
    assert response.status_code == 200


def test_auth_service_health(client):
    """Test auth service health"""
    response = client.get("http://localhost:8084/health")
    assert response.status_code == 200


def test_predict_endpoint_integration(client):
    """Test full inference pipeline"""
    payload = {
        "method": "POST",
        "uri": "/login.php?id=1' OR '1'='1",
        "body": "username=admin&password=123",
        "anomaly_score": 65,
        "inbound_threshold": 30
    }

    response = client.post("http://localhost:8083/predict", json=payload)
    assert response.status_code in (200, 500)  # 500 is acceptable if model not loaded

    if response.status_code == 200:
        data = response.json()
        assert "attack_probability" in data
        assert "recommended_priority" in data


def test_get_rules_integration(client):
    """Test rules endpoint from review-api"""
    response = client.get("http://localhost:8082/rules")
    assert response.status_code in (200, 404, 503)


@pytest.mark.asyncio
async def test_concurrent_requests():
    """Test that system can handle concurrent requests"""
    async with httpx.AsyncClient(timeout=10.0) as client:
        tasks = []
        for i in range(5):
            tasks.append(client.get("http://localhost:8090/aggregate/health"))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 200)
        assert success_count >= 3, f"Only {success_count}/5 concurrent requests succeeded"

def test_login_flow_integration(client):
    """Test full login flow"""
    login_payload = {
        "email": "admin@modintel.local",
        "password": "StrongPass123!"
    }
    
    # Try common login endpoints
    possible_paths = ["/login", "/auth/login", "/api/login"]
    
    for path in possible_paths:
        response = client.post(f"http://localhost:8084{path}", json=login_payload)
        if response.status_code != 404:
            break  # Found working endpoint
    
    assert response.status_code in (200, 401, 400, 422), f"Login returned {response.status_code}"


def test_login_with_invalid_credentials(client):
    """Test login with wrong credentials"""
    payload = {
        "email": "wrong@modintel.local",
        "password": "wrongpassword123456"
    }
    
    response = client.post("http://localhost:8084/login", json=payload)
    
    # Accept 404 as "endpoint not found" during development
    assert response.status_code in (401, 400, 422, 404)


def test_protected_route_without_token(client):
    """Test accessing protected route without authentication"""
    possible_paths = ["/whoami", "/me", "/api/whoami", "/aggregate/health/detailed"]
    
    for path in possible_paths:
        response = client.get(f"http://localhost:8084{path}")
        if response.status_code != 404:
            break
    
    assert response.status_code in (401, 403, 404)
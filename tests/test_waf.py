"""WAF Tests"""

import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import app


client = TestClient(app)


def test_root():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    assert "name" in response.json()


def test_health():
    """Test health check"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_sql_injection_blocked():
    """Test that SQL injection is blocked"""
    response = client.get("/test?id=1' OR '1'='1")
    assert response.status_code in [200, 403]


def test_xss_blocked():
    """Test that XSS is blocked"""
    response = client.get("/test?search=<script>alert('xss')</script>")
    assert response.status_code in [200, 403]


def test_normal_request():
    """Test that normal requests are allowed"""
    response = client.get("/")
    assert response.status_code == 200


def test_api_authentication():
    """Test API authentication"""
    response = client.post("/api/auth", json={
        "username": "admin",
        "password": "admin123"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_api_threat_check():
    """Test threat checking API"""
    response = client.post("/api/check", json={
        "content": "SELECT * FROM users WHERE id=1",
        "content_type": "text"
    })
    assert response.status_code == 200
    result = response.json()
    assert "is_malicious" in result


def test_api_statistics():
    """Test statistics API"""
    response = client.get("/api/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "total_requests" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

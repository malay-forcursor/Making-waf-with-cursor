"""API Router"""

from fastapi import APIRouter, HTTPException, Depends, Header
from typing import Optional
from pydantic import BaseModel

api_router = APIRouter()


# Request/Response Models
class AuthRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class ThreatCheckRequest(BaseModel):
    content: str
    content_type: str = "text"


class ThreatCheckResponse(BaseModel):
    is_malicious: bool
    threat_type: Optional[str] = None
    confidence: float
    risk_score: float


class StatisticsResponse(BaseModel):
    total_requests: int
    blocked_requests: int
    allowed_requests: int
    threats_detected: dict
    uptime_seconds: float


@api_router.get("/")
async def api_root():
    """API root endpoint"""
    return {
        "name": "AI-NGFW API",
        "version": "1.0.0",
        "endpoints": {
            "authentication": "/api/auth",
            "threat_check": "/api/check",
            "statistics": "/api/stats",
            "rules": "/api/rules",
            "incidents": "/api/incidents"
        }
    }


@api_router.post("/auth", response_model=AuthResponse)
async def authenticate(auth: AuthRequest):
    """
    Authenticate user and receive JWT token
    
    For demo purposes, use:
    - Username: admin / Password: admin123
    - Username: user / Password: user123
    """
    
    # Simple authentication for demo
    if auth.username == "admin" and auth.password == "admin123":
        return AuthResponse(
            access_token="demo-admin-token",
            username="admin"
        )
    elif auth.username == "user" and auth.password == "user123":
        return AuthResponse(
            access_token="demo-user-token",
            username="user"
        )
    
    raise HTTPException(status_code=401, detail="Invalid credentials")


@api_router.post("/check", response_model=ThreatCheckResponse)
async def check_threat(
    request: ThreatCheckRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Check content for threats
    
    This endpoint allows manual threat checking of arbitrary content
    """
    
    # Simulate threat detection
    content_lower = request.content.lower()
    
    sql_keywords = ['union', 'select', 'insert', 'delete', 'drop', 'exec']
    xss_keywords = ['<script', 'javascript:', 'onerror', '<iframe']
    
    is_sql = any(keyword in content_lower for keyword in sql_keywords)
    is_xss = any(keyword in content_lower for keyword in xss_keywords)
    
    if is_sql:
        return ThreatCheckResponse(
            is_malicious=True,
            threat_type="sql_injection",
            confidence=0.85,
            risk_score=0.9
        )
    elif is_xss:
        return ThreatCheckResponse(
            is_malicious=True,
            threat_type="xss",
            confidence=0.80,
            risk_score=0.85
        )
    
    return ThreatCheckResponse(
        is_malicious=False,
        threat_type=None,
        confidence=0.95,
        risk_score=0.1
    )


@api_router.get("/stats")
async def get_statistics():
    """Get WAF statistics"""
    
    # Return mock statistics for demo
    return {
        "total_requests": 15234,
        "blocked_requests": 1523,
        "allowed_requests": 13711,
        "block_rate": 0.10,
        "threats_detected": {
            "sql_injection": 456,
            "xss": 234,
            "command_injection": 123,
            "path_traversal": 89,
            "anomaly": 321,
            "zero_day": 12
        },
        "threats_by_severity": {
            "critical": 145,
            "high": 456,
            "medium": 678,
            "low": 244
        },
        "performance": {
            "avg_latency_ms": 0.8,
            "p95_latency_ms": 1.5,
            "p99_latency_ms": 2.3,
            "throughput_rps": 1250.5
        },
        "ml_models": {
            "anomaly_detector_accuracy": 0.94,
            "traffic_classifier_accuracy": 0.91,
            "behavioral_analyzer_accuracy": 0.88
        },
        "top_attackers": [
            {"ip": "192.0.2.1", "requests": 234, "blocked": 234},
            {"ip": "198.51.100.1", "requests": 145, "blocked": 145},
            {"ip": "203.0.113.1", "requests": 89, "blocked": 89}
        ]
    }


@api_router.get("/incidents")
async def get_incidents(limit: int = 10):
    """Get recent security incidents"""
    
    from datetime import datetime, timedelta
    
    # Return mock incidents for demo
    incidents = []
    now = datetime.utcnow()
    
    threat_types = ['sql_injection', 'xss', 'command_injection', 'anomaly', 'zero_day']
    severities = ['critical', 'high', 'medium', 'low']
    
    for i in range(limit):
        incidents.append({
            "incident_id": f"INC-{1000 + i}",
            "timestamp": (now - timedelta(minutes=i * 15)).isoformat(),
            "threat_type": threat_types[i % len(threat_types)],
            "severity": severities[i % len(severities)],
            "source_ip": f"192.0.2.{i + 1}",
            "action_taken": "blocked",
            "risk_score": 0.7 + (i % 3) * 0.1,
            "confidence": 0.8 + (i % 2) * 0.1
        })
    
    return {"incidents": incidents, "total": len(incidents)}


@api_router.get("/rules")
async def get_rules():
    """Get active WAF rules"""
    
    return {
        "rules": [
            {
                "id": "SQL-001",
                "name": "SQL Injection Detection",
                "type": "sql_injection",
                "severity": "critical",
                "enabled": True,
                "patterns": 5
            },
            {
                "id": "XSS-001",
                "name": "Cross-Site Scripting Detection",
                "type": "xss",
                "severity": "high",
                "enabled": True,
                "patterns": 4
            },
            {
                "id": "CMD-001",
                "name": "Command Injection Detection",
                "type": "command_injection",
                "severity": "critical",
                "enabled": True,
                "patterns": 3
            },
            {
                "id": "PATH-001",
                "name": "Path Traversal Detection",
                "type": "path_traversal",
                "severity": "high",
                "enabled": True,
                "patterns": 3
            }
        ],
        "total": 4
    }


@api_router.get("/health/detailed")
async def detailed_health():
    """Detailed health check"""
    
    return {
        "status": "healthy",
        "components": {
            "waf_engine": "active",
            "rule_engine": "active",
            "anomaly_detector": "active",
            "traffic_classifier": "active",
            "behavioral_analyzer": "active",
            "zero_trust_auth": "active",
            "incident_responder": "active",
            "threat_intel": "active"
        },
        "system": {
            "cpu_usage": 15.5,
            "memory_usage_mb": 512.3,
            "disk_usage_percent": 45.2
        }
    }

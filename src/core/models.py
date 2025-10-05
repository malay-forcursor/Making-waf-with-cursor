"""Data Models"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum
import uuid


class ThreatType(str, Enum):
    """Types of threats"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    ZERO_DAY = "zero_day"
    ANOMALY = "anomaly"
    DDoS = "ddos"
    MALWARE = "malware"
    UNKNOWN = "unknown"


class ActionType(str, Enum):
    """Action types"""
    ALLOW = "allow"
    BLOCK = "block"
    MONITOR = "monitor"
    SANDBOX = "sandbox"


class SeverityLevel(str, Enum):
    """Severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InspectionResult(BaseModel):
    """Result of request inspection"""
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Request details
    source_ip: str
    destination_ip: Optional[str] = None
    method: str
    path: str
    headers: Dict[str, str]
    
    # Detection results
    threat_type: ThreatType
    threat_detected: bool
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: SeverityLevel
    
    # Analysis
    rule_matches: List[str] = []
    ml_predictions: Dict[str, Any] = {}
    anomaly_score: Optional[float] = None
    
    # Action
    action: ActionType
    reason: str
    
    # Additional context
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    geolocation: Optional[Dict[str, str]] = None
    mitre_tactics: List[str] = []


class ThreatIntelligence(BaseModel):
    """Threat intelligence data"""
    ioc_type: str  # ip, domain, url, hash
    ioc_value: str
    threat_type: str
    severity: SeverityLevel
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = []


class UserSession(BaseModel):
    """User session for Zero Trust"""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    
    # Authentication
    auth_method: str
    mfa_verified: bool = False
    device_fingerprint: str
    
    # Context
    ip_address: str
    user_agent: str
    geolocation: Optional[Dict[str, str]] = None
    
    # Risk assessment
    risk_score: float = Field(ge=0.0, le=100.0)
    trust_level: str  # low, medium, high
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    
    # Access control
    permissions: List[str] = []
    allowed_resources: List[str] = []


class SecurityEvent(BaseModel):
    """Security event for logging and analysis"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    event_type: str
    severity: SeverityLevel
    source: str
    
    description: str
    details: Dict[str, Any]
    
    # Context
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # Response
    action_taken: Optional[str] = None
    automated_response: bool = False


class MLModelMetrics(BaseModel):
    """ML model performance metrics"""
    model_name: str
    model_version: str
    
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    
    false_positive_rate: float
    false_negative_rate: float
    
    inference_time_ms: float
    
    last_trained: datetime
    training_samples: int
    
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class WAFStatistics(BaseModel):
    """WAF statistics"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Traffic
    total_requests: int = 0
    allowed_requests: int = 0
    blocked_requests: int = 0
    monitored_requests: int = 0
    
    # Threats
    threats_detected: Dict[str, int] = {}
    threats_by_severity: Dict[str, int] = {}
    
    # Performance
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    
    throughput_rps: float = 0.0
    
    # ML Models
    model_accuracy: Dict[str, float] = {}
    anomaly_detection_rate: float = 0.0
    
    # System
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    
    # Top attackers
    top_source_ips: List[Dict[str, Any]] = []
    top_target_paths: List[Dict[str, Any]] = []

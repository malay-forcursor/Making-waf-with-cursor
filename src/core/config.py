"""Configuration Management"""

import os
from typing import Optional
from pydantic import BaseModel
from dotenv import load_dotenv
import yaml

load_dotenv()


class Settings(BaseModel):
    """Application settings"""
    
    # Application
    app_name: str = os.getenv("APP_NAME", "AI-NGFW")
    app_version: str = os.getenv("APP_VERSION", "1.0.0")
    environment: str = os.getenv("ENVIRONMENT", "production")
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # API
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    api_workers: int = int(os.getenv("API_WORKERS", "4"))
    
    # Security
    secret_key: str = os.getenv("SECRET_KEY", "change-this-in-production")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_expiration_minutes: int = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))
    
    # Database
    mongodb_url: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    mongodb_db: str = os.getenv("MONGODB_DB", "ai_ngfw")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # ML Models
    ml_model_path: str = os.getenv("ML_MODEL_PATH", "./models")
    model_update_interval: int = int(os.getenv("MODEL_UPDATE_INTERVAL", "3600"))
    anomaly_threshold: float = float(os.getenv("ANOMALY_THRESHOLD", "0.75"))
    confidence_threshold: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.85"))
    
    # Zero Trust
    zero_trust_enabled: bool = os.getenv("ZERO_TRUST_ENABLED", "true").lower() == "true"
    mfa_enabled: bool = os.getenv("MFA_ENABLED", "true").lower() == "true"
    session_timeout: int = int(os.getenv("SESSION_TIMEOUT", "1800"))
    max_login_attempts: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "3"))
    
    # Threat Intelligence
    threat_intel_enabled: bool = os.getenv("THREAT_INTEL_ENABLED", "true").lower() == "true"
    threat_feed_update_interval: int = int(os.getenv("THREAT_FEED_UPDATE_INTERVAL", "300"))
    mitre_attack_enabled: bool = os.getenv("MITRE_ATTACK_ENABLED", "true").lower() == "true"
    
    # Performance
    max_requests_per_second: int = int(os.getenv("MAX_REQUESTS_PER_SECOND", "1000"))
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "30"))
    max_packet_size: int = int(os.getenv("MAX_PACKET_SIZE", "65535"))
    
    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_file: str = os.getenv("LOG_FILE", "./logs/ai_ngfw.log")
    elasticsearch_url: Optional[str] = os.getenv("ELASTICSEARCH_URL")
    
    # Dashboard
    dashboard_port: int = int(os.getenv("DASHBOARD_PORT", "8050"))
    dashboard_enabled: bool = os.getenv("DASHBOARD_ENABLED", "true").lower() == "true"
    
    # Monitoring
    prometheus_port: int = int(os.getenv("PROMETHEUS_PORT", "9090"))
    metrics_enabled: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}


# Global configuration
CONFIG = load_config()

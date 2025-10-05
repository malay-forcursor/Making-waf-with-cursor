"""
Configuration management for the NGFW system
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

@dataclass
class MLConfig:
    """Machine Learning configuration"""
    model_path: str = "models/"
    batch_size: int = 32
    learning_rate: float = 0.001
    epochs: int = 100
    confidence_threshold: float = 0.8
    anomaly_threshold: float = 0.7
    federated_learning: bool = True
    federated_rounds: int = 10
    privacy_budget: float = 1.0

@dataclass
class NetworkConfig:
    """Network configuration"""
    interface: str = "eth0"
    promiscuous_mode: bool = True
    buffer_size: int = 65536
    capture_timeout: int = 1000
    max_packet_size: int = 1500
    ssl_inspection: bool = True
    tls_version: str = "1.3"

@dataclass
class SecurityConfig:
    """Security configuration"""
    sql_injection_detection: bool = True
    xss_detection: bool = True
    zero_day_detection: bool = True
    anomaly_detection: bool = True
    rate_limiting: bool = True
    max_requests_per_minute: int = 1000
    block_duration: int = 3600  # seconds

@dataclass
class ZeroTrustConfig:
    """Zero Trust configuration"""
    enabled: bool = True
    micro_segmentation: bool = True
    continuous_verification: bool = True
    risk_based_auth: bool = True
    behavioral_biometrics: bool = True
    device_trust_score: float = 0.8
    user_trust_score: float = 0.8

@dataclass
class DatabaseConfig:
    """Database configuration"""
    type: str = "postgresql"
    host: str = "localhost"
    port: int = 5432
    name: str = "ngfw"
    user: str = "ngfw_user"
    password: str = "ngfw_pass"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

@dataclass
class APIConfig:
    """API configuration"""
    host: str = "0.0.0.0"
    port: int = 8000
    dashboard_port: int = 8050
    cors_origins: list = field(default_factory=lambda: ["*"])
    api_key_header: str = "X-API-Key"
    rate_limit: int = 1000

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = "logs/ngfw.log"
    max_size: int = 10485760  # 10MB
    backup_count: int = 5

class Config:
    """Main configuration class"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config/ngfw.yaml"
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file and environment variables"""
        # Load from YAML file if it exists
        if Path(self.config_path).exists():
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f)
        else:
            config_data = {}
        
        # Load from environment variables with defaults
        self.ml = MLConfig(
            model_path=os.getenv('ML_MODEL_PATH', config_data.get('ml', {}).get('model_path', 'models/')),
            batch_size=int(os.getenv('ML_BATCH_SIZE', config_data.get('ml', {}).get('batch_size', 32))),
            learning_rate=float(os.getenv('ML_LEARNING_RATE', config_data.get('ml', {}).get('learning_rate', 0.001))),
            epochs=int(os.getenv('ML_EPOCHS', config_data.get('ml', {}).get('epochs', 100))),
            confidence_threshold=float(os.getenv('ML_CONFIDENCE_THRESHOLD', config_data.get('ml', {}).get('confidence_threshold', 0.8))),
            anomaly_threshold=float(os.getenv('ML_ANOMALY_THRESHOLD', config_data.get('ml', {}).get('anomaly_threshold', 0.7))),
            federated_learning=os.getenv('ML_FEDERATED_LEARNING', 'true').lower() == 'true',
            federated_rounds=int(os.getenv('ML_FEDERATED_ROUNDS', config_data.get('ml', {}).get('federated_rounds', 10))),
            privacy_budget=float(os.getenv('ML_PRIVACY_BUDGET', config_data.get('ml', {}).get('privacy_budget', 1.0)))
        )
        
        self.network = NetworkConfig(
            interface=os.getenv('NETWORK_INTERFACE', config_data.get('network', {}).get('interface', 'eth0')),
            promiscuous_mode=os.getenv('NETWORK_PROMISCUOUS', 'true').lower() == 'true',
            buffer_size=int(os.getenv('NETWORK_BUFFER_SIZE', config_data.get('network', {}).get('buffer_size', 65536))),
            capture_timeout=int(os.getenv('NETWORK_CAPTURE_TIMEOUT', config_data.get('network', {}).get('capture_timeout', 1000))),
            max_packet_size=int(os.getenv('NETWORK_MAX_PACKET_SIZE', config_data.get('network', {}).get('max_packet_size', 1500))),
            ssl_inspection=os.getenv('NETWORK_SSL_INSPECTION', 'true').lower() == 'true',
            tls_version=os.getenv('NETWORK_TLS_VERSION', config_data.get('network', {}).get('tls_version', '1.3'))
        )
        
        self.security = SecurityConfig(
            sql_injection_detection=os.getenv('SECURITY_SQL_INJECTION', 'true').lower() == 'true',
            xss_detection=os.getenv('SECURITY_XSS', 'true').lower() == 'true',
            zero_day_detection=os.getenv('SECURITY_ZERO_DAY', 'true').lower() == 'true',
            anomaly_detection=os.getenv('SECURITY_ANOMALY', 'true').lower() == 'true',
            rate_limiting=os.getenv('SECURITY_RATE_LIMITING', 'true').lower() == 'true',
            max_requests_per_minute=int(os.getenv('SECURITY_MAX_REQUESTS', config_data.get('security', {}).get('max_requests_per_minute', 1000))),
            block_duration=int(os.getenv('SECURITY_BLOCK_DURATION', config_data.get('security', {}).get('block_duration', 3600)))
        )
        
        self.zero_trust = ZeroTrustConfig(
            enabled=os.getenv('ZERO_TRUST_ENABLED', 'true').lower() == 'true',
            micro_segmentation=os.getenv('ZERO_TRUST_MICRO_SEGMENTATION', 'true').lower() == 'true',
            continuous_verification=os.getenv('ZERO_TRUST_CONTINUOUS_VERIFICATION', 'true').lower() == 'true',
            risk_based_auth=os.getenv('ZERO_TRUST_RISK_BASED_AUTH', 'true').lower() == 'true',
            behavioral_biometrics=os.getenv('ZERO_TRUST_BEHAVIORAL_BIOMETRICS', 'true').lower() == 'true',
            device_trust_score=float(os.getenv('ZERO_TRUST_DEVICE_TRUST_SCORE', config_data.get('zero_trust', {}).get('device_trust_score', 0.8))),
            user_trust_score=float(os.getenv('ZERO_TRUST_USER_TRUST_SCORE', config_data.get('zero_trust', {}).get('user_trust_score', 0.8)))
        )
        
        self.database = DatabaseConfig(
            type=os.getenv('DB_TYPE', config_data.get('database', {}).get('type', 'postgresql')),
            host=os.getenv('DB_HOST', config_data.get('database', {}).get('host', 'localhost')),
            port=int(os.getenv('DB_PORT', config_data.get('database', {}).get('port', 5432))),
            name=os.getenv('DB_NAME', config_data.get('database', {}).get('name', 'ngfw')),
            user=os.getenv('DB_USER', config_data.get('database', {}).get('user', 'ngfw_user')),
            password=os.getenv('DB_PASSWORD', config_data.get('database', {}).get('password', 'ngfw_pass')),
            redis_host=os.getenv('REDIS_HOST', config_data.get('database', {}).get('redis_host', 'localhost')),
            redis_port=int(os.getenv('REDIS_PORT', config_data.get('database', {}).get('redis_port', 6379))),
            redis_db=int(os.getenv('REDIS_DB', config_data.get('database', {}).get('redis_db', 0)))
        )
        
        self.api = APIConfig(
            host=os.getenv('API_HOST', config_data.get('api', {}).get('host', '0.0.0.0')),
            port=int(os.getenv('API_PORT', config_data.get('api', {}).get('port', 8000))),
            dashboard_port=int(os.getenv('DASHBOARD_PORT', config_data.get('api', {}).get('dashboard_port', 8050))),
            cors_origins=os.getenv('API_CORS_ORIGINS', config_data.get('api', {}).get('cors_origins', '["*"]')).split(','),
            api_key_header=os.getenv('API_KEY_HEADER', config_data.get('api', {}).get('api_key_header', 'X-API-Key')),
            rate_limit=int(os.getenv('API_RATE_LIMIT', config_data.get('api', {}).get('rate_limit', 1000)))
        )
        
        self.logging = LoggingConfig(
            level=os.getenv('LOG_LEVEL', config_data.get('logging', {}).get('level', 'INFO')),
            format=os.getenv('LOG_FORMAT', config_data.get('logging', {}).get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')),
            file=os.getenv('LOG_FILE', config_data.get('logging', {}).get('file', 'logs/ngfw.log')),
            max_size=int(os.getenv('LOG_MAX_SIZE', config_data.get('logging', {}).get('max_size', 10485760))),
            backup_count=int(os.getenv('LOG_BACKUP_COUNT', config_data.get('logging', {}).get('backup_count', 5)))
        )
    
    def get_database_url(self) -> str:
        """Get database connection URL"""
        return f"{self.database.type}://{self.database.user}:{self.database.password}@{self.database.host}:{self.database.port}/{self.database.name}"
    
    def get_redis_url(self) -> str:
        """Get Redis connection URL"""
        return f"redis://{self.database.redis_host}:{self.database.redis_port}/{self.database.redis_db}"
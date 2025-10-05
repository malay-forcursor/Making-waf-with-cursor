"""
Logging configuration for the NGFW system
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
from utils.config import Config

def setup_logging(config: Optional[Config] = None, log_level: Optional[str] = None):
    """Setup logging configuration"""
    if config is None:
        config = Config()
    
    # Determine log level
    level = log_level or config.logging.level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(config.logging.format)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if config.logging.file:
        # Create logs directory if it doesn't exist
        log_file = Path(config.logging.file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            config.logging.file,
            maxBytes=config.logging.max_size,
            backupCount=config.logging.backup_count
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Setup specific loggers
    _setup_module_loggers()
    
    return root_logger

def _setup_module_loggers():
    """Setup specific module loggers with appropriate levels"""
    
    # Network capture logger
    network_logger = logging.getLogger('traffic_capture')
    network_logger.setLevel(logging.DEBUG)
    
    # ML model logger
    ml_logger = logging.getLogger('ml')
    ml_logger.setLevel(logging.DEBUG)
    
    # Security logger
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    
    # Zero Trust logger
    zero_trust_logger = logging.getLogger('zero_trust')
    zero_trust_logger.setLevel(logging.INFO)
    
    # API logger
    api_logger = logging.getLogger('api')
    api_logger.setLevel(logging.INFO)
    
    # Firewall engine logger
    firewall_logger = logging.getLogger('firewall_engine')
    firewall_logger.setLevel(logging.INFO)

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self, name: str = 'security_events'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create a separate handler for security events
        if not self.logger.handlers:
            handler = logging.FileHandler('logs/security_events.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def log_threat_detected(self, threat_type: str, source_ip: str, 
                          destination_ip: str, details: dict):
        """Log a detected threat"""
        self.logger.warning(
            f"THREAT_DETECTED: {threat_type} from {source_ip} to {destination_ip} - {details}"
        )
    
    def log_blocked_connection(self, source_ip: str, destination_ip: str, 
                             reason: str, rule_id: str = None):
        """Log a blocked connection"""
        self.logger.info(
            f"CONNECTION_BLOCKED: {source_ip} -> {destination_ip} - Reason: {reason} - Rule: {rule_id}"
        )
    
    def log_policy_violation(self, user_id: str, resource: str, 
                           action: str, severity: str = "medium"):
        """Log a policy violation"""
        self.logger.warning(
            f"POLICY_VIOLATION: User {user_id} attempted {action} on {resource} - Severity: {severity}"
        )
    
    def log_zero_trust_event(self, event_type: str, user_id: str, 
                           device_id: str, trust_score: float, details: dict):
        """Log a Zero Trust event"""
        self.logger.info(
            f"ZERO_TRUST_EVENT: {event_type} - User: {user_id}, Device: {device_id}, "
            f"Trust Score: {trust_score:.2f} - {details}"
        )
    
    def log_ml_model_update(self, model_name: str, accuracy: float, 
                          training_samples: int, federated_round: int = None):
        """Log ML model updates"""
        self.logger.info(
            f"ML_MODEL_UPDATE: {model_name} - Accuracy: {accuracy:.4f}, "
            f"Samples: {training_samples}, Round: {federated_round}"
        )

class PerformanceLogger:
    """Specialized logger for performance metrics"""
    
    def __init__(self, name: str = 'performance'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create a separate handler for performance metrics
        if not self.logger.handlers:
            handler = logging.FileHandler('logs/performance.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def log_throughput(self, packets_per_second: float, bytes_per_second: float):
        """Log throughput metrics"""
        self.logger.info(
            f"THROUGHPUT: {packets_per_second:.2f} pps, {bytes_per_second:.2f} bps"
        )
    
    def log_latency(self, component: str, latency_ms: float):
        """Log latency metrics"""
        self.logger.info(f"LATENCY: {component} - {latency_ms:.2f}ms")
    
    def log_detection_time(self, threat_type: str, detection_time_ms: float):
        """Log threat detection time"""
        self.logger.info(
            f"DETECTION_TIME: {threat_type} - {detection_time_ms:.2f}ms"
        )
    
    def log_memory_usage(self, component: str, memory_mb: float):
        """Log memory usage"""
        self.logger.info(f"MEMORY_USAGE: {component} - {memory_mb:.2f}MB")
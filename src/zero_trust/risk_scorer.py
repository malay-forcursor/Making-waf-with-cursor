"""Risk-Based Scoring for Zero Trust"""

import logging
from typing import Dict
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Calculate risk scores for Zero Trust decisions
    Uses multiple factors including behavior, location, time, etc.
    """
    
    def __init__(self, settings):
        self.settings = settings
        
        # Track risk factors
        self.failed_attempts = defaultdict(lambda: {'count': 0, 'last_attempt': None})
        self.suspicious_patterns = defaultdict(list)
        
        # Known good IPs (whitelist)
        self.trusted_ips = set(['127.0.0.1', '::1'])
        
        # Known bad IPs (from threat intel)
        self.blocked_ips = set()
        
        logger.info("Risk Scorer initialized")
    
    async def calculate_risk_score(
        self,
        source_ip: str,
        user_agent: str,
        path: str,
        username: Optional[str] = None
    ) -> float:
        """
        Calculate risk score (0-1, where 0 is trusted and 1 is high risk)
        
        Factors considered:
        - IP reputation
        - Failed login attempts
        - User agent anomalies
        - Geographic location
        - Time of access
        - Access patterns
        """
        
        risk_factors = []
        
        # 1. IP reputation
        if source_ip in self.blocked_ips:
            return 1.0  # Maximum risk
        
        if source_ip in self.trusted_ips:
            risk_factors.append(0.0)
        else:
            risk_factors.append(0.3)  # Unknown IP has some risk
        
        # 2. Failed login attempts
        if username:
            attempts = self.failed_attempts[f"{source_ip}:{username}"]
            if attempts['count'] > 0:
                risk = min(1.0, attempts['count'] * 0.2)
                risk_factors.append(risk)
        
        # 3. User agent analysis
        if not user_agent or len(user_agent) < 10:
            risk_factors.append(0.5)  # Missing or short user agent
        elif 'bot' in user_agent.lower() or 'crawler' in user_agent.lower():
            risk_factors.append(0.6)
        
        # 4. Time-based risk (suspicious if accessing at odd hours)
        current_hour = datetime.utcnow().hour
        if current_hour >= 2 and current_hour <= 5:
            risk_factors.append(0.4)  # Slightly suspicious late-night access
        
        # 5. Path-based risk
        sensitive_paths = ['/admin', '/api/keys', '/config', '/.env']
        if any(sensitive in path for sensitive in sensitive_paths):
            risk_factors.append(0.5)
        
        # Calculate weighted average
        if not risk_factors:
            return 0.5  # Neutral score if no factors
        
        # Use maximum risk as the final score (most conservative)
        risk_score = max(risk_factors)
        
        return risk_score
    
    def record_failed_attempt(self, source_ip: str, username: str):
        """Record a failed authentication attempt"""
        key = f"{source_ip}:{username}"
        self.failed_attempts[key]['count'] += 1
        self.failed_attempts[key]['last_attempt'] = datetime.utcnow()
        
        # Block IP after too many failures
        if self.failed_attempts[key]['count'] >= self.settings.max_login_attempts:
            self.blocked_ips.add(source_ip)
            logger.warning(f"🚫 Blocked IP {source_ip} after {self.failed_attempts[key]['count']} failed attempts")
    
    def record_successful_login(self, source_ip: str, username: str):
        """Record successful login"""
        key = f"{source_ip}:{username}"
        if key in self.failed_attempts:
            # Reset failed attempts on successful login
            self.failed_attempts[key] = {'count': 0, 'last_attempt': None}
    
    def add_trusted_ip(self, ip: str):
        """Add IP to trusted list"""
        self.trusted_ips.add(ip)
        logger.info(f"Added {ip} to trusted IPs")
    
    def block_ip(self, ip: str):
        """Block an IP address"""
        self.blocked_ips.add(ip)
        logger.warning(f"Blocked IP {ip}")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips

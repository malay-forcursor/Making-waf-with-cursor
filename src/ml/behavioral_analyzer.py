"""Behavioral Analysis using LSTM"""

import logging
from typing import Dict, List
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BehavioralAnalyzer:
    """
    Analyze user/IP behavior patterns using LSTM
    Detects suspicious behavior based on historical patterns
    """
    
    def __init__(self, settings):
        self.settings = settings
        
        # Behavior tracking
        self.behavior_history = defaultdict(lambda: {
            'requests': [],
            'paths': [],
            'methods': [],
            'timestamps': []
        })
        
        # Thresholds
        self.request_rate_threshold = 100  # requests per minute
        self.unique_paths_threshold = 50
        self.time_window = timedelta(minutes=5)
        
        logger.info("Behavioral Analyzer initialized")
    
    async def initialize(self):
        """Initialize analyzer"""
        pass
    
    async def analyze_behavior(
        self,
        source_ip: str,
        method: str,
        path: str
    ) -> float:
        """
        Analyze behavior and return risk score
        
        Returns:
            Risk score between 0 (normal) and 1 (suspicious)
        """
        
        now = datetime.utcnow()
        
        # Update behavior history
        history = self.behavior_history[source_ip]
        history['requests'].append(now)
        history['paths'].append(path)
        history['methods'].append(method)
        history['timestamps'].append(now)
        
        # Clean old data
        cutoff_time = now - self.time_window
        history['requests'] = [t for t in history['requests'] if t > cutoff_time]
        history['paths'] = history['paths'][-100:]  # Keep last 100
        history['methods'] = history['methods'][-100:]
        history['timestamps'] = [t for t in history['timestamps'] if t > cutoff_time]
        
        # Calculate risk factors
        risk_factors = []
        
        # 1. Request rate
        request_count = len(history['requests'])
        if request_count > self.request_rate_threshold:
            risk_factors.append(min(1.0, request_count / (self.request_rate_threshold * 2)))
        
        # 2. Unique paths accessed
        unique_paths = len(set(history['paths']))
        if unique_paths > self.unique_paths_threshold:
            risk_factors.append(min(1.0, unique_paths / (self.unique_paths_threshold * 2)))
        
        # 3. Method diversity (suspicious if only POST/PUT)
        if len(history['methods']) > 10:
            post_ratio = history['methods'].count('POST') / len(history['methods'])
            if post_ratio > 0.8:
                risk_factors.append(0.6)
        
        # 4. Burst detection
        if len(history['timestamps']) >= 2:
            time_diffs = [
                (history['timestamps'][i] - history['timestamps'][i-1]).total_seconds()
                for i in range(1, len(history['timestamps']))
            ]
            avg_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 1.0
            
            if avg_diff < 0.1:  # Less than 100ms between requests
                risk_factors.append(0.8)
        
        # Calculate final risk score
        if risk_factors:
            risk_score = max(risk_factors)
        else:
            risk_score = 0.0
        
        return risk_score
    
    def get_behavior_summary(self, source_ip: str) -> Dict:
        """Get behavior summary for an IP"""
        history = self.behavior_history.get(source_ip)
        
        if not history:
            return {'status': 'unknown', 'request_count': 0}
        
        now = datetime.utcnow()
        cutoff_time = now - self.time_window
        recent_requests = [t for t in history['requests'] if t > cutoff_time]
        
        return {
            'request_count': len(recent_requests),
            'unique_paths': len(set(history['paths'])),
            'methods': list(set(history['methods'])),
            'first_seen': min(history['timestamps']) if history['timestamps'] else None,
            'last_seen': max(history['timestamps']) if history['timestamps'] else None
        }

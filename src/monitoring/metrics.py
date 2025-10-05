"""Metrics Collection"""

import logging
from typing import Dict
from collections import defaultdict
from datetime import datetime
import time
from src.core.models import InspectionResult

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Collect and expose metrics for monitoring
    Compatible with Prometheus
    """
    
    def __init__(self):
        # Request metrics
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.monitored_requests = 0
        
        # Threat metrics
        self.threats_by_type = defaultdict(int)
        self.threats_by_severity = defaultdict(int)
        
        # Performance metrics
        self.latencies = []
        self.max_latency = 0.0
        
        # System metrics
        self.start_time = time.time()
        
        logger.info("Metrics Collector initialized")
    
    async def record_request(self, result: InspectionResult):
        """Record metrics from inspection result"""
        
        self.total_requests += 1
        
        # Count by action
        if result.action.value == "block":
            self.blocked_requests += 1
        elif result.action.value == "allow":
            self.allowed_requests += 1
        elif result.action.value == "monitor":
            self.monitored_requests += 1
        
        # Count threats
        if result.threat_detected:
            self.threats_by_type[result.threat_type.value] += 1
            self.threats_by_severity[result.severity.value] += 1
    
    async def get_prometheus_metrics(self) -> str:
        """
        Generate Prometheus-compatible metrics
        
        Returns:
            Metrics in Prometheus text format
        """
        
        uptime = time.time() - self.start_time
        
        metrics = []
        
        # Request metrics
        metrics.append(f"# HELP ai_ngfw_requests_total Total number of requests processed")
        metrics.append(f"# TYPE ai_ngfw_requests_total counter")
        metrics.append(f"ai_ngfw_requests_total {self.total_requests}")
        
        metrics.append(f"# HELP ai_ngfw_requests_blocked Total number of blocked requests")
        metrics.append(f"# TYPE ai_ngfw_requests_blocked counter")
        metrics.append(f"ai_ngfw_requests_blocked {self.blocked_requests}")
        
        metrics.append(f"# HELP ai_ngfw_requests_allowed Total number of allowed requests")
        metrics.append(f"# TYPE ai_ngfw_requests_allowed counter")
        metrics.append(f"ai_ngfw_requests_allowed {self.allowed_requests}")
        
        # Threat metrics
        metrics.append(f"# HELP ai_ngfw_threats_detected Threats detected by type")
        metrics.append(f"# TYPE ai_ngfw_threats_detected counter")
        for threat_type, count in self.threats_by_type.items():
            metrics.append(f'ai_ngfw_threats_detected{{type="{threat_type}"}} {count}')
        
        # Performance metrics
        block_rate = (self.blocked_requests / self.total_requests * 100) if self.total_requests > 0 else 0
        
        metrics.append(f"# HELP ai_ngfw_block_rate_percent Percentage of blocked requests")
        metrics.append(f"# TYPE ai_ngfw_block_rate_percent gauge")
        metrics.append(f"ai_ngfw_block_rate_percent {block_rate:.2f}")
        
        # System metrics
        metrics.append(f"# HELP ai_ngfw_uptime_seconds Uptime in seconds")
        metrics.append(f"# TYPE ai_ngfw_uptime_seconds gauge")
        metrics.append(f"ai_ngfw_uptime_seconds {uptime:.2f}")
        
        return "\n".join(metrics) + "\n"
    
    def get_summary(self) -> Dict:
        """Get metrics summary"""
        
        uptime = time.time() - self.start_time
        
        return {
            "requests": {
                "total": self.total_requests,
                "blocked": self.blocked_requests,
                "allowed": self.allowed_requests,
                "monitored": self.monitored_requests,
                "block_rate": (self.blocked_requests / self.total_requests) if self.total_requests > 0 else 0
            },
            "threats": {
                "by_type": dict(self.threats_by_type),
                "by_severity": dict(self.threats_by_severity)
            },
            "system": {
                "uptime_seconds": uptime,
                "uptime_human": self._format_uptime(uptime)
            }
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format"""
        
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {secs}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"

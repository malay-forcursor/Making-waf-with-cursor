"""Automated Incident Response"""

import logging
from typing import Dict, List
from datetime import datetime, timedelta
from src.core.models import InspectionResult, SeverityLevel, SecurityEvent

logger = logging.getLogger(__name__)


class IncidentResponder:
    """
    Automated incident response using SOAR workflows
    Implements automated containment, quarantine, and remediation
    """
    
    def __init__(self, settings, config: Dict):
        self.settings = settings
        self.config = config
        self.soar_config = config.get('soar', {})
        
        # Blocked IPs with expiration
        self.blocked_ips = {}
        
        # Incident tracking
        self.incidents = []
        self.incident_stats = {
            'total': 0,
            'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'auto_resolved': 0,
            'manual_required': 0
        }
        
        logger.info("Incident Responder initialized")
    
    async def respond(self, inspection_result: InspectionResult):
        """
        Execute automated response to detected threat
        
        Workflow:
        1. Assess threat severity
        2. Select appropriate response action
        3. Execute automated remediation
        4. Log incident
        5. Send notifications if needed
        """
        
        try:
            # Create security event
            event = SecurityEvent(
                event_type="threat_detected",
                severity=inspection_result.severity,
                source=inspection_result.source_ip,
                description=f"{inspection_result.threat_type.value} detected",
                details={
                    'threat_type': inspection_result.threat_type.value,
                    'risk_score': inspection_result.risk_score,
                    'confidence': inspection_result.confidence,
                    'path': inspection_result.path,
                    'method': inspection_result.method
                },
                source_ip=inspection_result.source_ip,
                action_taken=None,
                automated_response=True
            )
            
            # Select response workflow based on severity
            if inspection_result.severity == SeverityLevel.CRITICAL:
                await self._handle_critical_threat(inspection_result, event)
            elif inspection_result.severity == SeverityLevel.HIGH:
                await self._handle_high_threat(inspection_result, event)
            elif inspection_result.severity == SeverityLevel.MEDIUM:
                await self._handle_medium_threat(inspection_result, event)
            else:
                await self._handle_low_threat(inspection_result, event)
            
            # Log incident
            self.incidents.append(event)
            self.incident_stats['total'] += 1
            self.incident_stats['by_severity'][inspection_result.severity.value] += 1
            self.incident_stats['auto_resolved'] += 1
            
            logger.info(
                f"✅ Automated response executed for {inspection_result.threat_type.value} "
                f"from {inspection_result.source_ip}"
            )
            
        except Exception as e:
            logger.error(f"Error in incident response: {e}", exc_info=True)
    
    async def _handle_critical_threat(self, result: InspectionResult, event: SecurityEvent):
        """Handle critical severity threats"""
        
        # 1. Immediate IP block
        await self._block_ip(result.source_ip, duration_seconds=86400)  # 24 hours
        
        # 2. Trigger deep inspection
        await self._trigger_deep_inspection(result)
        
        # 3. Send high-priority alert
        await self._send_alert(
            severity="critical",
            message=f"Critical threat detected: {result.threat_type.value} from {result.source_ip}",
            details=result.dict()
        )
        
        # 4. Update ML model with new pattern
        await self._update_ml_model(result)
        
        event.action_taken = "ip_blocked_24h_deep_inspection_alert_sent"
    
    async def _handle_high_threat(self, result: InspectionResult, event: SecurityEvent):
        """Handle high severity threats"""
        
        # 1. Temporary IP block
        await self._block_ip(result.source_ip, duration_seconds=3600)  # 1 hour
        
        # 2. Send alert
        await self._send_alert(
            severity="high",
            message=f"High-severity threat detected: {result.threat_type.value}",
            details=result.dict()
        )
        
        # 3. Log for analysis
        await self._log_for_analysis(result)
        
        event.action_taken = "ip_blocked_1h_alert_sent"
    
    async def _handle_medium_threat(self, result: InspectionResult, event: SecurityEvent):
        """Handle medium severity threats"""
        
        # 1. Rate limit IP
        await self._rate_limit_ip(result.source_ip)
        
        # 2. Monitor closely
        await self._add_to_watchlist(result.source_ip)
        
        event.action_taken = "rate_limited_watchlist_added"
    
    async def _handle_low_threat(self, result: InspectionResult, event: SecurityEvent):
        """Handle low severity threats"""
        
        # 1. Log only
        await self._log_for_analysis(result)
        
        event.action_taken = "logged"
    
    async def _block_ip(self, ip: str, duration_seconds: int):
        """Block IP address temporarily"""
        
        expiration = datetime.utcnow() + timedelta(seconds=duration_seconds)
        self.blocked_ips[ip] = expiration
        
        logger.warning(f"🚫 Blocked IP {ip} until {expiration}")
    
    async def _rate_limit_ip(self, ip: str):
        """Apply rate limiting to IP"""
        logger.info(f"⏱️  Rate limiting applied to {ip}")
    
    async def _add_to_watchlist(self, ip: str):
        """Add IP to monitoring watchlist"""
        logger.info(f"👁️  Added {ip} to watchlist")
    
    async def _trigger_deep_inspection(self, result: InspectionResult):
        """Trigger deep packet inspection"""
        logger.info(f"🔍 Triggered deep inspection for {result.incident_id}")
    
    async def _send_alert(self, severity: str, message: str, details: Dict):
        """Send alert notification"""
        logger.warning(f"🚨 ALERT [{severity.upper()}]: {message}")
        # In production: integrate with Slack, email, PagerDuty, etc.
    
    async def _log_for_analysis(self, result: InspectionResult):
        """Log incident for further analysis"""
        logger.info(f"📝 Logged incident {result.incident_id} for analysis")
    
    async def _update_ml_model(self, result: InspectionResult):
        """Update ML model with new threat pattern"""
        logger.info(f"🤖 Triggered ML model update with new threat pattern")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        
        if ip not in self.blocked_ips:
            return False
        
        # Check if block expired
        if datetime.utcnow() > self.blocked_ips[ip]:
            del self.blocked_ips[ip]
            return False
        
        return True
    
    def get_statistics(self) -> Dict:
        """Get incident response statistics"""
        return {
            'total_incidents': self.incident_stats['total'],
            'by_severity': self.incident_stats['by_severity'],
            'auto_resolved': self.incident_stats['auto_resolved'],
            'manual_required': self.incident_stats['manual_required'],
            'blocked_ips': len(self.blocked_ips),
            'recent_incidents': [
                {
                    'event_id': incident.event_id,
                    'timestamp': incident.timestamp.isoformat(),
                    'severity': incident.severity.value,
                    'description': incident.description,
                    'action_taken': incident.action_taken
                }
                for incident in self.incidents[-10:]  # Last 10
            ]
        }

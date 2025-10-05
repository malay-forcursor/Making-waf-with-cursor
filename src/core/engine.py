"""Core WAF Engine"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from fastapi import Request

from src.core.config import Settings, CONFIG
from src.core.models import (
    InspectionResult, ThreatType, ActionType, SeverityLevel, SecurityEvent
)
from src.detection.rule_engine import RuleEngine
from src.ml.anomaly_detector import AnomalyDetector
from src.ml.traffic_classifier import TrafficClassifier
from src.ml.behavioral_analyzer import BehavioralAnalyzer
from src.zero_trust.authenticator import ZeroTrustAuthenticator
from src.zero_trust.risk_scorer import RiskScorer
from src.soar.incident_responder import IncidentResponder
from src.threat_intel.feed_manager import ThreatIntelManager
from src.utils.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


class WAFEngine:
    """Main WAF Engine orchestrating all components"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.config = CONFIG
        
        # Components
        self.rule_engine: Optional[RuleEngine] = None
        self.anomaly_detector: Optional[AnomalyDetector] = None
        self.traffic_classifier: Optional[TrafficClassifier] = None
        self.behavioral_analyzer: Optional[BehavioralAnalyzer] = None
        self.zero_trust_auth: Optional[ZeroTrustAuthenticator] = None
        self.risk_scorer: Optional[RiskScorer] = None
        self.incident_responder: Optional[IncidentResponder] = None
        self.threat_intel_manager: Optional[ThreatIntelManager] = None
        self.db_manager: Optional[DatabaseManager] = None
        
        # State
        self.is_initialized = False
        self.blocked_ips: Dict[str, datetime] = {}
        
        logger.info("WAF Engine created")
    
    async def initialize(self):
        """Initialize all components"""
        try:
            logger.info("Initializing WAF Engine components...")
            
            # Initialize database manager
            self.db_manager = DatabaseManager(self.settings)
            await self.db_manager.connect()
            
            # Initialize rule-based detection
            self.rule_engine = RuleEngine(self.config)
            logger.info("✅ Rule Engine initialized")
            
            # Initialize ML-based detection
            self.anomaly_detector = AnomalyDetector(self.settings)
            await self.anomaly_detector.initialize()
            logger.info("✅ Anomaly Detector initialized")
            
            self.traffic_classifier = TrafficClassifier(self.settings)
            await self.traffic_classifier.load_model()
            logger.info("✅ Traffic Classifier initialized")
            
            self.behavioral_analyzer = BehavioralAnalyzer(self.settings)
            await self.behavioral_analyzer.initialize()
            logger.info("✅ Behavioral Analyzer initialized")
            
            # Initialize Zero Trust components
            if self.settings.zero_trust_enabled:
                self.zero_trust_auth = ZeroTrustAuthenticator(self.settings)
                self.risk_scorer = RiskScorer(self.settings)
                logger.info("✅ Zero Trust components initialized")
            
            # Initialize SOAR
            self.incident_responder = IncidentResponder(self.settings, self.config)
            logger.info("✅ Incident Responder initialized")
            
            # Initialize Threat Intelligence
            if self.settings.threat_intel_enabled:
                self.threat_intel_manager = ThreatIntelManager(self.settings, self.config)
                await self.threat_intel_manager.initialize()
                logger.info("✅ Threat Intelligence Manager initialized")
            
            self.is_initialized = True
            logger.info("🎉 WAF Engine fully initialized!")
            
        except Exception as e:
            logger.error(f"Failed to initialize WAF Engine: {e}", exc_info=True)
            raise
    
    async def inspect_request(self, request: Request) -> InspectionResult:
        """
        Inspect incoming HTTP request
        
        This is the main entry point for request inspection.
        It orchestrates multiple detection engines:
        1. Rule-based detection (signatures)
        2. ML-based anomaly detection
        3. Traffic classification
        4. Behavioral analysis
        5. Threat intelligence lookup
        6. Zero Trust verification
        """
        
        start_time = datetime.utcnow()
        
        try:
            # Extract request data
            source_ip = request.client.host if request.client else "unknown"
            method = request.method
            path = request.url.path
            headers = dict(request.headers)
            
            # Check if IP is blocked
            if source_ip in self.blocked_ips:
                return InspectionResult(
                    source_ip=source_ip,
                    method=method,
                    path=path,
                    headers=headers,
                    threat_type=ThreatType.UNKNOWN,
                    threat_detected=True,
                    risk_score=1.0,
                    confidence=1.0,
                    severity=SeverityLevel.HIGH,
                    action=ActionType.BLOCK,
                    reason="IP address is blocked"
                )
            
            # Read request body if present
            body = None
            if method in ["POST", "PUT", "PATCH"]:
                try:
                    body = await request.body()
                    if body:
                        body = body.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.warning(f"Could not read request body: {e}")
            
            # 1. Rule-based detection
            rule_result = await self.rule_engine.check_request(
                method=method,
                path=path,
                headers=headers,
                body=body
            )
            
            # 2. Threat Intelligence lookup
            threat_intel_match = None
            if self.threat_intel_manager:
                threat_intel_match = await self.threat_intel_manager.check_ioc(source_ip)
            
            # 3. ML-based anomaly detection
            anomaly_score = 0.0
            if self.anomaly_detector:
                features = self._extract_features(request, headers, body)
                anomaly_score = await self.anomaly_detector.detect(features)
            
            # 4. Traffic classification
            ml_predictions = {}
            if self.traffic_classifier:
                traffic_features = self._extract_traffic_features(request, headers, body)
                ml_predictions = await self.traffic_classifier.classify(traffic_features)
            
            # 5. Behavioral analysis
            behavioral_risk = 0.0
            if self.behavioral_analyzer:
                behavioral_risk = await self.behavioral_analyzer.analyze_behavior(
                    source_ip, method, path
                )
            
            # 6. Zero Trust verification
            trust_score = 1.0
            if self.zero_trust_auth and self.risk_scorer:
                trust_score = await self.risk_scorer.calculate_risk_score(
                    source_ip=source_ip,
                    user_agent=headers.get('user-agent', ''),
                    path=path
                )
            
            # Aggregate results and make decision
            result = self._make_decision(
                source_ip=source_ip,
                method=method,
                path=path,
                headers=headers,
                rule_result=rule_result,
                threat_intel_match=threat_intel_match,
                anomaly_score=anomaly_score,
                ml_predictions=ml_predictions,
                behavioral_risk=behavioral_risk,
                trust_score=trust_score
            )
            
            # Log to database
            if self.db_manager:
                await self.db_manager.log_inspection(result)
            
            # Trigger automated response if threat detected
            if result.threat_detected and self.incident_responder:
                await self.incident_responder.respond(result)
            
            # Calculate latency
            latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            logger.debug(f"Inspection completed in {latency_ms:.2f}ms")
            
            return result
            
        except Exception as e:
            logger.error(f"Error inspecting request: {e}", exc_info=True)
            
            # Fail-open: allow request on error
            return InspectionResult(
                source_ip=request.client.host if request.client else "unknown",
                method=request.method,
                path=request.url.path,
                headers=dict(request.headers),
                threat_type=ThreatType.UNKNOWN,
                threat_detected=False,
                risk_score=0.0,
                confidence=0.0,
                severity=SeverityLevel.LOW,
                action=ActionType.ALLOW,
                reason="Error during inspection - fail-open"
            )
    
    def _extract_features(self, request: Request, headers: Dict, body: Optional[str]) -> Dict[str, Any]:
        """Extract features for anomaly detection"""
        return {
            'method': request.method,
            'path_length': len(request.url.path),
            'header_count': len(headers),
            'body_length': len(body) if body else 0,
            'has_query_params': bool(request.url.query),
            'user_agent_length': len(headers.get('user-agent', '')),
            'content_type': headers.get('content-type', ''),
        }
    
    def _extract_traffic_features(self, request: Request, headers: Dict, body: Optional[str]) -> Dict[str, Any]:
        """Extract features for traffic classification"""
        return {
            'method': request.method,
            'path': request.url.path,
            'headers': headers,
            'body': body or "",
            'query_params': str(request.url.query)
        }
    
    def _make_decision(
        self,
        source_ip: str,
        method: str,
        path: str,
        headers: Dict,
        rule_result: Dict,
        threat_intel_match: Optional[Dict],
        anomaly_score: float,
        ml_predictions: Dict,
        behavioral_risk: float,
        trust_score: float
    ) -> InspectionResult:
        """Make final decision based on all detection results"""
        
        # Determine threat type and severity
        threat_type = ThreatType.UNKNOWN
        severity = SeverityLevel.LOW
        threat_detected = False
        reason = "Request passed all checks"
        action = ActionType.ALLOW
        
        rule_matches = []
        
        # Check rule-based detection
        if rule_result.get('matched'):
            threat_detected = True
            threat_type = ThreatType[rule_result.get('threat_type', 'UNKNOWN').upper()]
            severity = SeverityLevel[rule_result.get('severity', 'MEDIUM').upper()]
            rule_matches = rule_result.get('matched_rules', [])
            reason = f"Rule-based detection: {rule_result.get('reason', 'Pattern matched')}"
            action = ActionType.BLOCK
        
        # Check threat intelligence
        elif threat_intel_match:
            threat_detected = True
            threat_type = ThreatType.MALWARE
            severity = SeverityLevel.CRITICAL
            reason = f"IP matched threat intelligence: {threat_intel_match.get('source', 'unknown')}"
            action = ActionType.BLOCK
        
        # Check anomaly score
        elif anomaly_score > self.settings.anomaly_threshold:
            threat_detected = True
            threat_type = ThreatType.ANOMALY
            severity = SeverityLevel.MEDIUM if anomaly_score > 0.9 else SeverityLevel.HIGH
            reason = f"Anomaly detected (score: {anomaly_score:.2f})"
            action = ActionType.MONITOR
        
        # Check ML predictions
        elif ml_predictions.get('is_malicious', False):
            threat_detected = True
            threat_type = ThreatType[ml_predictions.get('threat_type', 'UNKNOWN').upper()]
            severity = SeverityLevel.HIGH
            reason = f"ML classification: {ml_predictions.get('reason', 'Malicious pattern')}"
            action = ActionType.BLOCK if ml_predictions.get('confidence', 0) > 0.9 else ActionType.MONITOR
        
        # Check behavioral risk
        elif behavioral_risk > 0.7:
            threat_detected = True
            threat_type = ThreatType.ANOMALY
            severity = SeverityLevel.MEDIUM
            reason = f"Suspicious behavior pattern (risk: {behavioral_risk:.2f})"
            action = ActionType.MONITOR
        
        # Check Zero Trust score
        elif trust_score < 0.3:
            threat_detected = True
            threat_type = ThreatType.UNKNOWN
            severity = SeverityLevel.MEDIUM
            reason = f"Low trust score (score: {trust_score:.2f})"
            action = ActionType.MONITOR
        
        # Calculate overall risk score
        risk_score = max(
            anomaly_score,
            behavioral_risk,
            1.0 - trust_score,
            1.0 if rule_result.get('matched') else 0.0,
            1.0 if threat_intel_match else 0.0,
            ml_predictions.get('confidence', 0.0) if ml_predictions.get('is_malicious') else 0.0
        )
        
        # Calculate confidence
        confidence = 0.9 if rule_result.get('matched') or threat_intel_match else \
                    ml_predictions.get('confidence', 0.5)
        
        return InspectionResult(
            source_ip=source_ip,
            method=method,
            path=path,
            headers=headers,
            threat_type=threat_type,
            threat_detected=threat_detected,
            risk_score=risk_score,
            confidence=confidence,
            severity=severity,
            rule_matches=rule_matches,
            ml_predictions=ml_predictions,
            anomaly_score=anomaly_score,
            action=action,
            reason=reason,
            user_agent=headers.get('user-agent')
        )
    
    async def shutdown(self):
        """Shutdown all components"""
        logger.info("Shutting down WAF Engine...")
        
        if self.db_manager:
            await self.db_manager.disconnect()
        
        if self.threat_intel_manager:
            await self.threat_intel_manager.shutdown()
        
        logger.info("WAF Engine shutdown complete")

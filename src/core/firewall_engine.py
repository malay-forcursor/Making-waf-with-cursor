"""
Core Firewall Engine for the NGFW system
Handles packet processing, rule evaluation, and threat response
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import logging

from utils.config import Config
from utils.logger import SecurityLogger, PerformanceLogger

logger = logging.getLogger(__name__)

class Action(Enum):
    """Firewall actions"""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    LOG = "log"
    RATE_LIMIT = "rate_limit"

class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class PacketInfo:
    """Packet information structure"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes
    timestamp: float
    size: int
    flags: Dict[str, Any] = None

@dataclass
class ThreatInfo:
    """Threat information structure"""
    threat_type: str
    confidence: float
    severity: ThreatLevel
    description: str
    source_ip: str
    destination_ip: str
    payload_snippet: str
    timestamp: float
    rule_id: Optional[str] = None

@dataclass
class FirewallRule:
    """Firewall rule structure"""
    rule_id: str
    name: str
    priority: int
    conditions: Dict[str, Any]
    action: Action
    threat_level: ThreatLevel
    enabled: bool = True
    created_at: float = None
    updated_at: float = None

class FirewallEngine:
    """Main firewall engine"""
    
    def __init__(self, config: Config, threat_detector, zero_trust_controller):
        self.config = config
        self.threat_detector = threat_detector
        self.zero_trust_controller = zero_trust_controller
        self.security_logger = SecurityLogger()
        self.performance_logger = PerformanceLogger()
        
        # State management
        self.rules: List[FirewallRule] = []
        self.blocked_ips: Dict[str, float] = {}  # IP -> block_until_timestamp
        self.rate_limits: Dict[str, List[float]] = {}  # IP -> list of request timestamps
        self.quarantined_ips: Dict[str, float] = {}  # IP -> quarantine_until_timestamp
        
        # Performance metrics
        self.packets_processed = 0
        self.threats_detected = 0
        self.blocks_performed = 0
        self.start_time = time.time()
        
        # Initialize default rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default firewall rules"""
        default_rules = [
            FirewallRule(
                rule_id="default_allow",
                name="Default Allow",
                priority=1000,
                conditions={},
                action=Action.ALLOW,
                threat_level=ThreatLevel.LOW,
                created_at=time.time()
            ),
            FirewallRule(
                rule_id="block_private_scan",
                name="Block Private Network Scans",
                priority=100,
                conditions={
                    "src_ip_range": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                    "dst_port_range": [1, 1024],
                    "protocol": "tcp"
                },
                action=Action.BLOCK,
                threat_level=ThreatLevel.MEDIUM,
                created_at=time.time()
            ),
            FirewallRule(
                rule_id="rate_limit_http",
                name="Rate Limit HTTP Requests",
                priority=200,
                conditions={
                    "dst_port": 80,
                    "protocol": "tcp"
                },
                action=Action.RATE_LIMIT,
                threat_level=ThreatLevel.LOW,
                created_at=time.time()
            )
        ]
        
        self.rules.extend(default_rules)
        logger.info(f"Initialized {len(default_rules)} default rules")
    
    async def initialize(self):
        """Initialize the firewall engine"""
        logger.info("Initializing Firewall Engine...")
        
        # Load rules from configuration
        await self._load_rules()
        
        # Initialize threat detector
        if self.threat_detector:
            await self.threat_detector.initialize()
        
        # Initialize zero trust controller
        if self.zero_trust_controller:
            await self.zero_trust_controller.initialize()
        
        logger.info("Firewall Engine initialized successfully")
    
    async def start(self):
        """Start the firewall engine"""
        logger.info("Starting Firewall Engine...")
        
        # Start background tasks
        asyncio.create_task(self._cleanup_expired_blocks())
        asyncio.create_task(self._update_performance_metrics())
        
        logger.info("Firewall Engine started")
    
    async def stop(self):
        """Stop the firewall engine"""
        logger.info("Stopping Firewall Engine...")
        logger.info("Firewall Engine stopped")
    
    async def process_packet(self, packet_info: PacketInfo) -> Tuple[Action, Optional[ThreatInfo]]:
        """Process a network packet and determine action"""
        start_time = time.time()
        
        try:
            # Check if IP is blocked
            if self._is_ip_blocked(packet_info.src_ip):
                self.blocks_performed += 1
                self.security_logger.log_blocked_connection(
                    packet_info.src_ip, packet_info.dst_ip, "IP Blocked"
                )
                return Action.BLOCK, None
            
            # Check rate limiting
            if self._is_rate_limited(packet_info.src_ip):
                self.blocks_performed += 1
                self.security_logger.log_blocked_connection(
                    packet_info.src_ip, packet_info.dst_ip, "Rate Limited"
                )
                return Action.RATE_LIMIT, None
            
            # Zero Trust verification
            if self.zero_trust_controller:
                trust_result = await self.zero_trust_controller.verify_connection(
                    packet_info.src_ip, packet_info.dst_ip
                )
                if not trust_result.allowed:
                    self.blocks_performed += 1
                    self.security_logger.log_blocked_connection(
                        packet_info.src_ip, packet_info.dst_ip, 
                        f"Zero Trust Violation: {trust_result.reason}"
                    )
                    return Action.BLOCK, None
            
            # Threat detection
            threat_info = None
            if self.threat_detector:
                threat_info = await self.threat_detector.analyze_packet(packet_info)
                if threat_info:
                    self.threats_detected += 1
                    self.security_logger.log_threat_detected(
                        threat_info.threat_type,
                        threat_info.source_ip,
                        threat_info.destination_ip,
                        {
                            "confidence": threat_info.confidence,
                            "severity": threat_info.severity.name,
                            "description": threat_info.description
                        }
                    )
                    
                    # Determine action based on threat
                    action = self._determine_threat_action(threat_info)
                    if action != Action.ALLOW:
                        self.blocks_performed += 1
                        self._apply_threat_response(threat_info, action)
                        return action, threat_info
            
            # Apply firewall rules
            action = await self._evaluate_rules(packet_info)
            
            # Update performance metrics
            processing_time = (time.time() - start_time) * 1000  # Convert to ms
            self.performance_logger.log_latency("packet_processing", processing_time)
            
            self.packets_processed += 1
            return action, threat_info
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return Action.BLOCK, None
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        current_time = time.time()
        if ip in self.blocked_ips:
            if current_time < self.blocked_ips[ip]:
                return True
            else:
                # Block expired, remove it
                del self.blocked_ips[ip]
        return False
    
    def _is_rate_limited(self, ip: str) -> bool:
        """Check if IP is rate limited"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean old timestamps
        if ip in self.rate_limits:
            self.rate_limits[ip] = [
                ts for ts in self.rate_limits[ip] if ts > minute_ago
            ]
            
            # Check if over limit
            if len(self.rate_limits[ip]) >= self.config.security.max_requests_per_minute:
                return True
        
        return False
    
    def _update_rate_limit(self, ip: str):
        """Update rate limit tracking for IP"""
        current_time = time.time()
        if ip not in self.rate_limits:
            self.rate_limits[ip] = []
        self.rate_limits[ip].append(current_time)
    
    async def _evaluate_rules(self, packet_info: PacketInfo) -> Action:
        """Evaluate firewall rules against packet"""
        # Sort rules by priority (lower number = higher priority)
        sorted_rules = sorted(self.rules, key=lambda r: r.priority)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
                
            if self._rule_matches(rule, packet_info):
                # Update rate limiting if needed
                if rule.action == Action.RATE_LIMIT:
                    self._update_rate_limit(packet_info.src_ip)
                
                return rule.action
        
        # Default action if no rules match
        return Action.ALLOW
    
    def _rule_matches(self, rule: FirewallRule, packet_info: PacketInfo) -> bool:
        """Check if a rule matches the packet"""
        conditions = rule.conditions
        
        # Check source IP
        if "src_ip" in conditions:
            if packet_info.src_ip != conditions["src_ip"]:
                return False
        
        if "src_ip_range" in conditions:
            if not self._ip_in_ranges(packet_info.src_ip, conditions["src_ip_range"]):
                return False
        
        # Check destination IP
        if "dst_ip" in conditions:
            if packet_info.dst_ip != conditions["dst_ip"]:
                return False
        
        # Check ports
        if "src_port" in conditions:
            if packet_info.src_port != conditions["src_port"]:
                return False
        
        if "dst_port" in conditions:
            if packet_info.dst_port != conditions["dst_port"]:
                return False
        
        if "dst_port_range" in conditions:
            port_range = conditions["dst_port_range"]
            if not (port_range[0] <= packet_info.dst_port <= port_range[1]):
                return False
        
        # Check protocol
        if "protocol" in conditions:
            if packet_info.protocol.lower() != conditions["protocol"].lower():
                return False
        
        return True
    
    def _ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """Check if IP is in any of the given CIDR ranges"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
        except ValueError:
            pass
        return False
    
    def _determine_threat_action(self, threat_info: ThreatInfo) -> Action:
        """Determine action based on threat information"""
        if threat_info.severity == ThreatLevel.CRITICAL:
            return Action.QUARANTINE
        elif threat_info.severity == ThreatLevel.HIGH:
            return Action.BLOCK
        elif threat_info.severity == ThreatLevel.MEDIUM:
            return Action.RATE_LIMIT
        else:
            return Action.LOG
    
    def _apply_threat_response(self, threat_info: ThreatInfo, action: Action):
        """Apply response to detected threat"""
        current_time = time.time()
        
        if action == Action.BLOCK:
            # Block IP for configured duration
            self.blocked_ips[threat_info.source_ip] = (
                current_time + self.config.security.block_duration
            )
        elif action == Action.QUARANTINE:
            # Quarantine IP for longer duration
            self.quarantined_ips[threat_info.source_ip] = (
                current_time + (self.config.security.block_duration * 2)
            )
    
    async def _load_rules(self):
        """Load rules from configuration or database"""
        # This would typically load from a database or configuration file
        # For now, we'll use the default rules
        pass
    
    async def _cleanup_expired_blocks(self):
        """Clean up expired IP blocks and rate limits"""
        while True:
            try:
                current_time = time.time()
                
                # Clean expired blocks
                expired_blocks = [
                    ip for ip, expiry in self.blocked_ips.items()
                    if current_time >= expiry
                ]
                for ip in expired_blocks:
                    del self.blocked_ips[ip]
                
                # Clean expired quarantines
                expired_quarantines = [
                    ip for ip, expiry in self.quarantined_ips.items()
                    if current_time >= expiry
                ]
                for ip in expired_quarantines:
                    del self.quarantined_ips[ip]
                
                # Clean old rate limit entries
                minute_ago = current_time - 60
                for ip in list(self.rate_limits.keys()):
                    self.rate_limits[ip] = [
                        ts for ts in self.rate_limits[ip] if ts > minute_ago
                    ]
                    if not self.rate_limits[ip]:
                        del self.rate_limits[ip]
                
                await asyncio.sleep(60)  # Run every minute
                
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(60)
    
    async def _update_performance_metrics(self):
        """Update and log performance metrics"""
        while True:
            try:
                current_time = time.time()
                uptime = current_time - self.start_time
                
                # Calculate throughput
                if uptime > 0:
                    packets_per_second = self.packets_processed / uptime
                    self.performance_logger.log_throughput(packets_per_second, 0)  # Bytes per second would need additional tracking
                
                # Log statistics
                logger.info(
                    f"Firewall Stats - Packets: {self.packets_processed}, "
                    f"Threats: {self.threats_detected}, Blocks: {self.blocks_performed}, "
                    f"Uptime: {uptime:.1f}s"
                )
                
                await asyncio.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                logger.error(f"Error updating performance metrics: {e}")
                await asyncio.sleep(30)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current firewall statistics"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        return {
            "packets_processed": self.packets_processed,
            "threats_detected": self.threats_detected,
            "blocks_performed": self.blocks_performed,
            "uptime_seconds": uptime,
            "packets_per_second": self.packets_processed / uptime if uptime > 0 else 0,
            "blocked_ips_count": len(self.blocked_ips),
            "quarantined_ips_count": len(self.quarantined_ips),
            "active_rules_count": len([r for r in self.rules if r.enabled])
        }
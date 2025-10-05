#!/usr/bin/env python3
"""
AI-Driven Next-Generation Firewall (NGFW)
Main entry point for the firewall system
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from core.firewall_engine import FirewallEngine
from core.traffic_capture import TrafficCapture
from ml.threat_detector import ThreatDetector
from zero_trust.controller import ZeroTrustController
from api.rest_api import create_app
from utils.config import Config
from utils.logger import setup_logging

logger = logging.getLogger(__name__)

class NGFWSystem:
    """Main NGFW system orchestrator"""
    
    def __init__(self):
        self.config = Config()
        self.firewall_engine = None
        self.traffic_capture = None
        self.threat_detector = None
        self.zero_trust_controller = None
        self.api_app = None
        self.running = False
        
    async def initialize(self):
        """Initialize all system components"""
        try:
            logger.info("Initializing AI-Driven NGFW System...")
            
            # Initialize core components
            self.threat_detector = ThreatDetector(self.config)
            await self.threat_detector.initialize()
            
            self.zero_trust_controller = ZeroTrustController(self.config)
            await self.zero_trust_controller.initialize()
            
            self.firewall_engine = FirewallEngine(
                self.config, 
                self.threat_detector, 
                self.zero_trust_controller
            )
            await self.firewall_engine.initialize()
            
            self.traffic_capture = TrafficCapture(
                self.config, 
                self.firewall_engine
            )
            await self.traffic_capture.initialize()
            
            # Initialize API
            self.api_app = create_app(self.firewall_engine)
            
            logger.info("NGFW System initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize NGFW System: {e}")
            raise
    
    async def start(self):
        """Start the NGFW system"""
        try:
            logger.info("Starting NGFW System...")
            self.running = True
            
            # Start traffic capture
            await self.traffic_capture.start()
            
            # Start threat detection
            await self.threat_detector.start()
            
            # Start zero trust controller
            await self.zero_trust_controller.start()
            
            # Start firewall engine
            await self.firewall_engine.start()
            
            logger.info("NGFW System started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start NGFW System: {e}")
            raise
    
    async def stop(self):
        """Stop the NGFW system"""
        logger.info("Stopping NGFW System...")
        self.running = False
        
        if self.traffic_capture:
            await self.traffic_capture.stop()
        
        if self.threat_detector:
            await self.threat_detector.stop()
        
        if self.zero_trust_controller:
            await self.zero_trust_controller.stop()
        
        if self.firewall_engine:
            await self.firewall_engine.stop()
        
        logger.info("NGFW System stopped")

async def main():
    """Main entry point"""
    # Setup logging
    setup_logging()
    
    # Create and initialize system
    ngfw = NGFWSystem()
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(ngfw.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize and start system
        await ngfw.initialize()
        await ngfw.start()
        
        # Keep running until stopped
        while ngfw.running:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        await ngfw.stop()

if __name__ == "__main__":
    asyncio.run(main())
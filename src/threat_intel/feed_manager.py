"""Threat Intelligence Feed Manager"""

import logging
import asyncio
from typing import Dict, Optional, List
from datetime import datetime
import aiohttp

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    """
    Manage threat intelligence feeds
    Supports STIX/TAXII, custom feeds, and MITRE ATT&CK
    """
    
    def __init__(self, settings, config: Dict):
        self.settings = settings
        self.config = config
        self.threat_intel_config = config.get('threat_intelligence', {})
        
        # Threat indicators database
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.malicious_urls = set()
        self.malicious_hashes = set()
        
        # MITRE ATT&CK TTPs
        self.mitre_ttps = {}
        
        # Feed update task
        self.update_task = None
        
        logger.info("Threat Intel Manager initialized")
    
    async def initialize(self):
        """Initialize and start feed updates"""
        
        # Load initial threat data
        await self._load_threat_feeds()
        
        # Start periodic updates
        if self.settings.threat_intel_enabled:
            self.update_task = asyncio.create_task(self._periodic_update())
            logger.info("Started periodic threat feed updates")
    
    async def _load_threat_feeds(self):
        """Load threat intelligence from configured feeds"""
        
        feeds = self.threat_intel_config.get('feeds', [])
        
        for feed in feeds:
            if not feed.get('enabled', True):
                continue
            
            try:
                await self._load_feed(feed)
            except Exception as e:
                logger.error(f"Error loading feed {feed.get('name')}: {e}")
        
        logger.info(
            f"Loaded threat intelligence: "
            f"{len(self.malicious_ips)} IPs, "
            f"{len(self.malicious_domains)} domains, "
            f"{len(self.malicious_urls)} URLs"
        )
    
    async def _load_feed(self, feed: Dict):
        """Load specific threat feed"""
        
        feed_name = feed.get('name')
        feed_type = feed.get('type')
        feed_url = feed.get('url')
        
        if not feed_url:
            # Use mock data for demonstration
            self._load_mock_data(feed_name)
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(feed_url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        await self._process_feed_data(feed_name, feed_type, data)
                        logger.info(f"✅ Loaded feed: {feed_name}")
        except Exception as e:
            logger.error(f"Error fetching feed {feed_name}: {e}")
            self._load_mock_data(feed_name)
    
    def _load_mock_data(self, feed_name: str):
        """Load mock threat data for demonstration"""
        
        # Add some example malicious IPs (these are reserved/documentation IPs)
        mock_malicious_ips = [
            '192.0.2.1',    # TEST-NET-1
            '198.51.100.1',  # TEST-NET-2
            '203.0.113.1',   # TEST-NET-3
        ]
        
        self.malicious_ips.update(mock_malicious_ips)
        
        # Add example malicious domains
        mock_malicious_domains = [
            'evil.example.com',
            'malware.example.net',
            'phishing.example.org'
        ]
        
        self.malicious_domains.update(mock_malicious_domains)
        
        logger.info(f"Loaded mock data for {feed_name}")
    
    async def _process_feed_data(self, feed_name: str, feed_type: str, data: Dict):
        """Process and extract IOCs from feed data"""
        
        # Process based on feed type
        if feed_type == 'url':
            urls = data.get('urls', [])
            for url_data in urls:
                if isinstance(url_data, dict):
                    url = url_data.get('url', '')
                    self.malicious_urls.add(url)
        
        elif feed_type == 'ioc':
            # Process various IOC types
            if 'indicators' in data:
                for indicator in data['indicators']:
                    ioc_type = indicator.get('type')
                    value = indicator.get('value')
                    
                    if ioc_type == 'ipv4' and value:
                        self.malicious_ips.add(value)
                    elif ioc_type == 'domain' and value:
                        self.malicious_domains.add(value)
                    elif ioc_type == 'url' and value:
                        self.malicious_urls.add(value)
                    elif ioc_type in ['md5', 'sha1', 'sha256'] and value:
                        self.malicious_hashes.add(value)
        
        elif feed_type == 'ttps':
            # Process MITRE ATT&CK TTPs
            if 'objects' in data:
                for obj in data['objects']:
                    if obj.get('type') == 'attack-pattern':
                        self.mitre_ttps[obj.get('id')] = obj
    
    async def check_ioc(self, value: str, ioc_type: str = 'ip') -> Optional[Dict]:
        """
        Check if indicator of compromise exists in threat intel
        
        Args:
            value: IOC value to check
            ioc_type: Type of IOC (ip, domain, url, hash)
        
        Returns:
            Threat intelligence data if match found, None otherwise
        """
        
        if ioc_type == 'ip' and value in self.malicious_ips:
            return {
                'matched': True,
                'ioc_type': 'ip',
                'value': value,
                'source': 'threat_feed',
                'severity': 'high'
            }
        
        elif ioc_type == 'domain' and value in self.malicious_domains:
            return {
                'matched': True,
                'ioc_type': 'domain',
                'value': value,
                'source': 'threat_feed',
                'severity': 'high'
            }
        
        elif ioc_type == 'url' and value in self.malicious_urls:
            return {
                'matched': True,
                'ioc_type': 'url',
                'value': value,
                'source': 'threat_feed',
                'severity': 'high'
            }
        
        return None
    
    async def _periodic_update(self):
        """Periodically update threat feeds"""
        
        interval = self.settings.threat_feed_update_interval
        
        while True:
            try:
                await asyncio.sleep(interval)
                logger.info("Updating threat intelligence feeds...")
                await self._load_threat_feeds()
            except Exception as e:
                logger.error(f"Error in periodic feed update: {e}")
    
    def add_ioc(self, ioc_type: str, value: str):
        """Manually add IOC to database"""
        
        if ioc_type == 'ip':
            self.malicious_ips.add(value)
        elif ioc_type == 'domain':
            self.malicious_domains.add(value)
        elif ioc_type == 'url':
            self.malicious_urls.add(value)
        elif ioc_type == 'hash':
            self.malicious_hashes.add(value)
        
        logger.info(f"Added {ioc_type} IOC: {value}")
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            'malicious_ips': len(self.malicious_ips),
            'malicious_domains': len(self.malicious_domains),
            'malicious_urls': len(self.malicious_urls),
            'malicious_hashes': len(self.malicious_hashes),
            'mitre_ttps': len(self.mitre_ttps),
            'last_update': datetime.utcnow().isoformat()
        }
    
    async def shutdown(self):
        """Shutdown threat intel manager"""
        if self.update_task:
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Threat Intel Manager shutdown complete")

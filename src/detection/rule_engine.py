"""Rule-based Detection Engine"""

import re
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class RuleEngine:
    """Rule-based signature detection for common attacks"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.attack_signatures = config.get('firewall', {}).get('attack_signatures', {})
        self.compiled_patterns = {}
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
        logger.info(f"Rule Engine initialized with {len(self.attack_signatures)} attack types")
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance"""
        for attack_type, config in self.attack_signatures.items():
            if config.get('enabled', False):
                patterns = config.get('patterns', [])
                self.compiled_patterns[attack_type] = [
                    re.compile(pattern) for pattern in patterns
                ]
    
    async def check_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check request against signature database
        
        Returns:
            Dict with detection results
        """
        
        # Prepare content to scan
        scan_content = [
            path,
            str(headers),
        ]
        
        if body:
            scan_content.append(body)
        
        full_content = " ".join(scan_content)
        
        # Check each attack type
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(full_content):
                    attack_config = self.attack_signatures[attack_type]
                    
                    logger.warning(
                        f"🚨 {attack_type.upper()} detected in {method} {path}"
                    )
                    
                    return {
                        'matched': True,
                        'threat_type': attack_type,
                        'severity': attack_config.get('severity', 'medium'),
                        'matched_rules': [pattern.pattern],
                        'reason': f"{attack_type.replace('_', ' ').title()} pattern detected"
                    }
        
        # No threats detected
        return {
            'matched': False,
            'threat_type': None,
            'severity': None,
            'matched_rules': [],
            'reason': None
        }
    
    def add_custom_rule(self, attack_type: str, pattern: str):
        """Add a custom detection rule"""
        if attack_type not in self.compiled_patterns:
            self.compiled_patterns[attack_type] = []
        
        try:
            compiled_pattern = re.compile(pattern)
            self.compiled_patterns[attack_type].append(compiled_pattern)
            logger.info(f"Added custom rule for {attack_type}: {pattern}")
        except re.error as e:
            logger.error(f"Invalid regex pattern: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rule engine statistics"""
        return {
            'total_attack_types': len(self.attack_signatures),
            'enabled_attack_types': len(self.compiled_patterns),
            'total_patterns': sum(len(patterns) for patterns in self.compiled_patterns.values()),
            'attack_types': list(self.compiled_patterns.keys())
        }

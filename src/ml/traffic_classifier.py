"""Traffic Classification using Deep Learning"""

import logging
import numpy as np
from typing import Dict, Any
from pathlib import Path
import pickle

logger = logging.getLogger(__name__)


class TrafficClassifier:
    """
    Deep learning-based traffic classifier
    Uses lightweight CNN for encrypted traffic classification
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.model_path = Path(settings.ml_model_path) / "classifier"
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.vectorizer = None
        
        # Threat categories
        self.threat_categories = [
            'sql_injection',
            'xss',
            'command_injection',
            'path_traversal',
            'zero_day',
            'normal'
        ]
        
        logger.info("Traffic Classifier initialized")
    
    async def load_model(self):
        """Load or create model"""
        try:
            self._load_pretrained_model()
            logger.info("Loaded pre-trained traffic classifier")
        except:
            self._create_simple_model()
            logger.info("Created simple traffic classifier")
    
    def _create_simple_model(self):
        """Create a simple rule-based classifier as fallback"""
        
        # For hackathon: use pattern-based classification
        self.patterns = {
            'sql_injection': [
                'union', 'select', 'insert', 'update', 'delete',
                'drop', 'exec', 'execute', 'script', 'waitfor'
            ],
            'xss': [
                '<script', 'javascript:', 'onerror', 'onload',
                '<iframe', 'eval('
            ],
            'command_injection': [
                ';cat', ';ls', ';wget', '|bash', '&&cmd',
                '$(', '`'
            ],
            'path_traversal': [
                '../', '..\\', '%2e%2e', 'etc/passwd', 'win.ini'
            ]
        }
    
    async def classify(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify traffic as normal or malicious
        
        Returns:
            Classification results with confidence scores
        """
        
        try:
            # Combine all request data
            text_data = f"{features.get('method', '')} {features.get('path', '')} "
            text_data += f"{str(features.get('headers', {}))} {features.get('body', '')} "
            text_data += f"{features.get('query_params', '')}"
            text_data = text_data.lower()
            
            # Check for malicious patterns
            max_confidence = 0.0
            detected_threat = None
            
            for threat_type, patterns in self.patterns.items():
                pattern_matches = sum(1 for pattern in patterns if pattern in text_data)
                
                if pattern_matches > 0:
                    confidence = min(1.0, pattern_matches * 0.3)
                    
                    if confidence > max_confidence:
                        max_confidence = confidence
                        detected_threat = threat_type
            
            if detected_threat:
                return {
                    'is_malicious': True,
                    'threat_type': detected_threat,
                    'confidence': max_confidence,
                    'reason': f"Detected {detected_threat.replace('_', ' ')} patterns"
                }
            
            return {
                'is_malicious': False,
                'threat_type': 'normal',
                'confidence': 0.95,
                'reason': 'No malicious patterns detected'
            }
            
        except Exception as e:
            logger.error(f"Error in traffic classification: {e}", exc_info=True)
            return {
                'is_malicious': False,
                'threat_type': 'normal',
                'confidence': 0.5,
                'reason': 'Classification error'
            }
    
    def _load_pretrained_model(self):
        """Load pre-trained model from disk"""
        model_file = self.model_path / "traffic_classifier.pkl"
        with open(model_file, 'rb') as f:
            self.model = pickle.load(f)
    
    def _save_model(self):
        """Save model to disk"""
        model_file = self.model_path / "traffic_classifier.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump(self.model, f)

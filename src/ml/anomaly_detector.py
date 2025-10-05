"""Anomaly Detection using Unsupervised Learning"""

import logging
import numpy as np
from typing import Dict, Any, List
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Multi-model anomaly detection using:
    - Isolation Forest
    - DBSCAN clustering
    - Local Outlier Factor (LOF)
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.model_path = Path(settings.ml_model_path) / "anomaly"
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Models
        self.isolation_forest = None
        self.dbscan = None
        self.lof = None
        self.scaler = StandardScaler()
        
        # Training data buffer
        self.training_buffer: List[np.ndarray] = []
        self.max_buffer_size = 10000
        
        # Feature configuration
        self.feature_names = [
            'path_length',
            'header_count',
            'body_length',
            'has_query_params',
            'user_agent_length',
            'hour_of_day',
            'day_of_week'
        ]
        
        logger.info("Anomaly Detector initialized")
    
    async def initialize(self):
        """Initialize or load models"""
        try:
            # Try to load existing models
            self._load_models()
            logger.info("Loaded pre-trained anomaly detection models")
        except:
            # Initialize new models
            self._create_models()
            logger.info("Created new anomaly detection models")
    
    def _create_models(self):
        """Create new anomaly detection models"""
        
        # Isolation Forest - good for detecting outliers
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        
        # DBSCAN - density-based clustering
        self.dbscan = DBSCAN(
            eps=0.5,
            min_samples=5,
            n_jobs=-1
        )
        
        # Local Outlier Factor
        self.lof = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.1,
            novelty=True,
            n_jobs=-1
        )
        
        # Train on synthetic normal data
        self._train_on_synthetic_data()
    
    def _train_on_synthetic_data(self):
        """Train models on synthetic normal traffic patterns"""
        
        # Generate synthetic normal traffic
        n_samples = 1000
        normal_data = np.random.normal(loc=0, scale=1, size=(n_samples, len(self.feature_names)))
        
        # Fit scaler
        self.scaler.fit(normal_data)
        scaled_data = self.scaler.transform(normal_data)
        
        # Train models
        self.isolation_forest.fit(scaled_data)
        self.lof.fit(scaled_data)
        
        logger.info(f"Models trained on {n_samples} synthetic samples")
    
    async def detect(self, features: Dict[str, Any]) -> float:
        """
        Detect anomalies in request features
        
        Returns:
            Anomaly score between 0 (normal) and 1 (anomalous)
        """
        
        try:
            # Extract and normalize features
            feature_vector = self._extract_feature_vector(features)
            scaled_features = self.scaler.transform([feature_vector])
            
            # Get predictions from all models
            scores = []
            
            # Isolation Forest (returns -1 for outliers, 1 for inliers)
            if_score = self.isolation_forest.predict(scaled_features)[0]
            if_anomaly = self.isolation_forest.score_samples(scaled_features)[0]
            scores.append(1.0 if if_score == -1 else max(0, -if_anomaly))
            
            # Local Outlier Factor (returns -1 for outliers, 1 for inliers)
            lof_score = self.lof.predict(scaled_features)[0]
            lof_anomaly = -self.lof.score_samples(scaled_features)[0]
            scores.append(1.0 if lof_score == -1 else max(0, lof_anomaly / 10))
            
            # Aggregate anomaly scores (max voting)
            final_score = max(scores)
            
            # Add to training buffer for continuous learning
            self.training_buffer.append(feature_vector)
            if len(self.training_buffer) > self.max_buffer_size:
                self.training_buffer.pop(0)
            
            return min(1.0, final_score)
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}", exc_info=True)
            return 0.0
    
    def _extract_feature_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """Extract numerical feature vector from features dict"""
        
        import datetime
        now = datetime.datetime.now()
        
        vector = [
            features.get('path_length', 0),
            features.get('header_count', 0),
            features.get('body_length', 0),
            1.0 if features.get('has_query_params', False) else 0.0,
            features.get('user_agent_length', 0),
            now.hour,
            now.weekday()
        ]
        
        return np.array(vector, dtype=float)
    
    async def update_models(self):
        """Retrain models with accumulated data"""
        
        if len(self.training_buffer) < 100:
            logger.info("Insufficient data for model update")
            return
        
        try:
            logger.info(f"Updating models with {len(self.training_buffer)} samples")
            
            training_data = np.array(self.training_buffer)
            
            # Refit scaler and transform data
            self.scaler.fit(training_data)
            scaled_data = self.scaler.transform(training_data)
            
            # Retrain models
            self.isolation_forest.fit(scaled_data)
            self.lof.fit(scaled_data)
            
            # Save updated models
            self._save_models()
            
            logger.info("Models updated successfully")
            
        except Exception as e:
            logger.error(f"Error updating models: {e}", exc_info=True)
    
    def _save_models(self):
        """Save models to disk"""
        try:
            with open(self.model_path / "isolation_forest.pkl", 'wb') as f:
                pickle.dump(self.isolation_forest, f)
            
            with open(self.model_path / "lof.pkl", 'wb') as f:
                pickle.dump(self.lof, f)
            
            with open(self.model_path / "scaler.pkl", 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logger.info("Models saved successfully")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load models from disk"""
        with open(self.model_path / "isolation_forest.pkl", 'rb') as f:
            self.isolation_forest = pickle.load(f)
        
        with open(self.model_path / "lof.pkl", 'rb') as f:
            self.lof = pickle.load(f)
        
        with open(self.model_path / "scaler.pkl", 'rb') as f:
            self.scaler = pickle.load(f)

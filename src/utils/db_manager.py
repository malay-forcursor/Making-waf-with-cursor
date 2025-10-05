"""Database Manager"""

import logging
from typing import Optional
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as aioredis
from src.core.models import InspectionResult

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manage database connections and operations
    Supports MongoDB for persistent storage and Redis for caching
    """
    
    def __init__(self, settings):
        self.settings = settings
        
        # MongoDB
        self.mongo_client: Optional[AsyncIOMotorClient] = None
        self.mongo_db = None
        
        # Redis
        self.redis_client: Optional[aioredis.Redis] = None
        
        logger.info("Database Manager initialized")
    
    async def connect(self):
        """Connect to databases"""
        
        try:
            # Connect to MongoDB
            self.mongo_client = AsyncIOMotorClient(
                self.settings.mongodb_url,
                serverSelectionTimeoutMS=5000
            )
            self.mongo_db = self.mongo_client[self.settings.mongodb_db]
            
            # Test connection
            await self.mongo_client.server_info()
            logger.info("✅ Connected to MongoDB")
            
        except Exception as e:
            logger.warning(f"Could not connect to MongoDB: {e}")
            self.mongo_client = None
        
        try:
            # Connect to Redis
            self.redis_client = await aioredis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            
            # Test connection
            await self.redis_client.ping()
            logger.info("✅ Connected to Redis")
            
        except Exception as e:
            logger.warning(f"Could not connect to Redis: {e}")
            self.redis_client = None
    
    async def log_inspection(self, result: InspectionResult):
        """Log inspection result to database"""
        
        if not self.mongo_client:
            return
        
        try:
            collection = self.mongo_db.inspection_logs
            
            document = result.dict()
            document['timestamp'] = datetime.utcnow()
            
            await collection.insert_one(document)
            
        except Exception as e:
            logger.error(f"Error logging inspection to database: {e}")
    
    async def get_recent_inspections(self, limit: int = 100):
        """Get recent inspection results"""
        
        if not self.mongo_client:
            return []
        
        try:
            collection = self.mongo_db.inspection_logs
            
            cursor = collection.find().sort('timestamp', -1).limit(limit)
            results = await cursor.to_list(length=limit)
            
            return results
            
        except Exception as e:
            logger.error(f"Error fetching inspections: {e}")
            return []
    
    async def get_statistics(self, start_time: Optional[datetime] = None):
        """Get WAF statistics from database"""
        
        if not self.mongo_client:
            return {}
        
        try:
            collection = self.mongo_db.inspection_logs
            
            # Build query
            query = {}
            if start_time:
                query['timestamp'] = {'$gte': start_time}
            
            # Get aggregated stats
            total = await collection.count_documents(query)
            
            blocked_query = {**query, 'action': 'block'}
            blocked = await collection.count_documents(blocked_query)
            
            allowed_query = {**query, 'action': 'allow'}
            allowed = await collection.count_documents(allowed_query)
            
            return {
                'total_requests': total,
                'blocked_requests': blocked,
                'allowed_requests': allowed,
                'block_rate': blocked / total if total > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Error fetching statistics: {e}")
            return {}
    
    async def cache_set(self, key: str, value: str, expiration: int = 3600):
        """Set value in Redis cache"""
        
        if not self.redis_client:
            return
        
        try:
            await self.redis_client.set(key, value, ex=expiration)
        except Exception as e:
            logger.error(f"Error setting cache: {e}")
    
    async def cache_get(self, key: str) -> Optional[str]:
        """Get value from Redis cache"""
        
        if not self.redis_client:
            return None
        
        try:
            return await self.redis_client.get(key)
        except Exception as e:
            logger.error(f"Error getting cache: {e}")
            return None
    
    async def disconnect(self):
        """Disconnect from databases"""
        
        if self.mongo_client:
            self.mongo_client.close()
            logger.info("Disconnected from MongoDB")
        
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Disconnected from Redis")

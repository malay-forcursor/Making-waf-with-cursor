#!/usr/bin/env python3
"""
AI-Driven Next-Generation Firewall (AI-NGFW)
Main application entry point
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.core.engine import WAFEngine
from src.core.config import Settings
from src.api import router
from src.monitoring.metrics import MetricsCollector
from src.monitoring.dashboard import start_dashboard

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ai_ngfw.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(
    title="AI-Driven Next-Generation Firewall",
    description="Advanced WAF with AI/ML-based threat detection and Zero Trust",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
settings = Settings()
waf_engine: Optional[WAFEngine] = None
metrics_collector: Optional[MetricsCollector] = None


@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    global waf_engine, metrics_collector
    
    logger.info("🚀 Starting AI-NGFW...")
    
    # Create necessary directories
    Path("logs").mkdir(exist_ok=True)
    Path("models").mkdir(exist_ok=True)
    Path("data").mkdir(exist_ok=True)
    
    # Initialize WAF Engine
    logger.info("Initializing WAF Engine...")
    waf_engine = WAFEngine(settings)
    await waf_engine.initialize()
    
    # Initialize Metrics Collector
    logger.info("Initializing Metrics Collector...")
    metrics_collector = MetricsCollector()
    
    # Start dashboard in background
    if settings.dashboard_enabled:
        logger.info("Starting Real-time Dashboard...")
        asyncio.create_task(start_dashboard())
    
    logger.info("✅ AI-NGFW started successfully!")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 Shutting down AI-NGFW...")
    if waf_engine:
        await waf_engine.shutdown()
    logger.info("✅ AI-NGFW stopped successfully!")


@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    """Main WAF inspection middleware"""
    
    if not waf_engine:
        return await call_next(request)
    
    # Skip inspection for health and metrics endpoints
    if request.url.path in ["/health", "/metrics", "/api/docs", "/api/redoc"]:
        return await call_next(request)
    
    try:
        # Inspect incoming request
        inspection_result = await waf_engine.inspect_request(request)
        
        # Record metrics
        if metrics_collector:
            await metrics_collector.record_request(inspection_result)
        
        # Block malicious requests
        if inspection_result.action == "block":
            logger.warning(
                f"🚫 Blocked {inspection_result.threat_type} from "
                f"{request.client.host}: {inspection_result.reason}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by AI-NGFW",
                    "threat_type": inspection_result.threat_type,
                    "risk_score": inspection_result.risk_score,
                    "incident_id": inspection_result.incident_id
                }
            )
        
        # Log suspicious activity
        elif inspection_result.action == "monitor":
            logger.info(
                f"⚠️  Suspicious activity from {request.client.host}: "
                f"{inspection_result.threat_type}"
            )
        
        # Allow request
        response = await call_next(request)
        return response
        
    except Exception as e:
        logger.error(f"Error in WAF middleware: {e}", exc_info=True)
        return await call_next(request)


# Include API routes
app.include_router(router.api_router, prefix="/api")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "AI-Driven Next-Generation Firewall",
        "version": "1.0.0",
        "status": "active",
        "features": [
            "AI/ML-based threat detection",
            "Zero Trust architecture",
            "Real-time anomaly detection",
            "Automated incident response",
            "Federated learning",
            "Deep packet inspection"
        ]
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "waf_engine": "active" if waf_engine else "inactive",
        "metrics_collector": "active" if metrics_collector else "inactive"
    }


@app.get("/metrics")
async def get_metrics():
    """Prometheus-compatible metrics endpoint"""
    if not metrics_collector:
        return Response(content="", media_type="text/plain")
    
    metrics = await metrics_collector.get_prometheus_metrics()
    return Response(content=metrics, media_type="text/plain")


def main():
    """Main entry point"""
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    logger.info("=" * 80)
    logger.info("AI-DRIVEN NEXT-GENERATION FIREWALL")
    logger.info("Advanced WAF with AI/ML-based Threat Detection")
    logger.info("=" * 80)
    
    # Start the server
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        workers=1,  # Use 1 worker for async tasks
        log_level="info",
        access_log=True
    )


if __name__ == "__main__":
    main()

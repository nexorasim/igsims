"""
iGSIM AI Agent Platform - FastAPI Web API
RESTful API for AI Agent and eSIM services
"""

import asyncio
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.ai_agent_service import AIAgentService
from services.esim_service import eSIMService
from config.settings import PLATFORM_CONFIG, FIREBASE_CONFIG
from utils.logger import setup_logger
from api.auth import router as auth_router
from utils.auth_utils import rate_limit_middleware

logger = setup_logger(__name__)

# Global service instances
ai_service: Optional[AIAgentService] = None
esim_service: Optional[eSIMService] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global ai_service, esim_service
    
    # Startup
    logger.info("Initializing services...")
    
    ai_service = AIAgentService()
    esim_service = eSIMService()
    
    ai_success = ai_service.initialize()
    esim_success = esim_service.initialize()
    
    if ai_success and esim_success:
        logger.info("All services initialized successfully")
    else:
        logger.warning("Some services failed to initialize")
    
    yield
    
    # Shutdown
    logger.info("Shutting down services...")

# Create FastAPI app
app = FastAPI(
    title=PLATFORM_CONFIG["name"],
    description=PLATFORM_CONFIG["description"],
    version=PLATFORM_CONFIG["version"],
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
app.middleware("http")(rate_limit_middleware)

# Include authentication router
app.include_router(auth_router)

# Pydantic models
class AIRequest(BaseModel):
    prompt: str = Field(..., description="The AI prompt")
    provider: str = Field("auto", description="AI provider (auto, gemini, xai, groq)")
    type: str = Field("general", description="Request type")
    params: Dict[str, Any] = Field(default_factory=dict, description="Additional parameters")

class eSIMProvisionRequest(BaseModel):
    device_id: str = Field(..., description="Device ID")
    operator: str = Field("eSIM Myanmar", description="Operator name")
    country: str = Field("MM", description="Country code")
    network_type: str = Field("4G/5G", description="Network type")
    data_plan: str = Field("5GB", description="Data plan")

class M2MDeviceRequest(BaseModel):
    device_id: str = Field(..., description="Device ID")
    action: str = Field(..., description="Action to perform")
    params: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")

# Dependency to get services
def get_ai_service() -> AIAgentService:
    if ai_service is None:
        raise HTTPException(status_code=503, detail="AI service not initialized")
    return ai_service

def get_esim_service() -> eSIMService:
    if esim_service is None:
        raise HTTPException(status_code=503, detail="eSIM service not initialized")
    return esim_service

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with platform information"""
    return {
        "platform": PLATFORM_CONFIG["name"],
        "version": PLATFORM_CONFIG["version"],
        "description": PLATFORM_CONFIG["description"],
        "status": "running",
        "endpoints": {
            "auth": "/auth/",
            "ai": "/ai/",
            "esim": "/esim/",
            "m2m": "/m2m/",
            "health": "/health",
            "docs": "/docs"
        }
    }

# Health check endpoint
@app.get("/health")
async def health_check(ai_svc: AIAgentService = Depends(get_ai_service)):
    """Health check endpoint"""
    try:
        health_status = await ai_svc.health_check()
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Health check failed")

# AI Agent endpoints
@app.post("/ai/request")
async def ai_request(request: AIRequest, ai_svc: AIAgentService = Depends(get_ai_service)):
    """Process AI request"""
    try:
        result = await ai_svc.process_request({
            "prompt": request.prompt,
            "provider": request.provider,
            "type": request.type,
            "params": request.params,
            "id": f"api_request_{asyncio.current_task().get_name() if asyncio.current_task() else 'unknown'}"
        })
        return result
    except Exception as e:
        logger.error(f"AI request failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ai/status")
async def ai_status(ai_svc: AIAgentService = Depends(get_ai_service)):
    """Get AI service status"""
    return ai_svc.get_status()

# eSIM endpoints
@app.post("/esim/provision")
async def provision_esim(request: eSIMProvisionRequest, esim_svc: eSIMService = Depends(get_esim_service)):
    """Provision new eSIM profile"""
    try:
        result = await esim_svc.provision_esim(request.device_id, {
            "operator": request.operator,
            "country": request.country,
            "network_type": request.network_type,
            "data_plan": request.data_plan
        })
        return result
    except Exception as e:
        logger.error(f"eSIM provisioning failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/esim/devices")
async def list_esim_devices(esim_svc: eSIMService = Depends(get_esim_service)):
    """List active eSIM devices"""
    return {
        "devices": esim_svc.list_active_devices(),
        "count": len(esim_svc.list_active_devices())
    }

@app.get("/esim/device/{device_id}")
async def get_esim_device(device_id: str, esim_svc: eSIMService = Depends(get_esim_service)):
    """Get eSIM device status"""
    result = esim_svc.get_device_status(device_id)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail="Device not found")
    return result

# M2M endpoints
@app.post("/m2m/manage")
async def manage_m2m_device(request: M2MDeviceRequest, esim_svc: eSIMService = Depends(get_esim_service)):
    """Manage M2M device"""
    try:
        result = await esim_svc.manage_m2m_device(request.device_id, request.action, request.params)
        return result
    except Exception as e:
        logger.error(f"M2M management failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/m2m/devices")
async def list_m2m_devices(esim_svc: eSIMService = Depends(get_esim_service)):
    """List M2M devices"""
    return {
        "devices": esim_svc.list_m2m_devices(),
        "count": len(esim_svc.list_m2m_devices())
    }

@app.post("/m2m/register")
async def register_m2m_device(
    device_id: str,
    device_type: str = "generic",
    manufacturer: str = "unknown",
    model: str = "unknown",
    esim_svc: eSIMService = Depends(get_esim_service)
):
    """Register new M2M device"""
    try:
        result = await esim_svc.manage_m2m_device(device_id, "register", {
            "device_type": device_type,
            "manufacturer": manufacturer,
            "model": model
        })
        return result
    except Exception as e:
        logger.error(f"M2M registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Analytics endpoints
@app.get("/analytics")
async def get_analytics(esim_svc: eSIMService = Depends(get_esim_service)):
    """Get platform analytics"""
    try:
        analytics = await esim_svc.get_analytics()
        return analytics
    except Exception as e:
        logger.error(f"Analytics failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket endpoint for real-time updates (future enhancement)
# @app.websocket("/ws")
# async def websocket_endpoint(websocket: WebSocket):
#     await websocket.accept()
#     # Implementation for real-time updates

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "platform": PLATFORM_CONFIG["name"]
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "platform": PLATFORM_CONFIG["name"]
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
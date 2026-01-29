from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import asyncio
import logging
import os
import ssl
import uvicorn

from .auth import FirebaseAuth, require_auth, require_role
from .mcp_server import MCPServer
from .esim_agent import DeviceManager, eSIMProvisioner, DeviceAuthenticator
from .m2m_service import M2MDeviceManager, M2MMessageRouter
from .models.mcp_models import MCPRequest, MCPResponse
from .repositories import DeviceRepository, eSIMRepository
from ..config.settings import get_settings
from ..utils.secure_api_manager import get_secret_manager

# Initialize settings
settings = get_settings()
secret_manager = get_secret_manager()

app = FastAPI(
    title="iGSIM AI Agent API",
    description="Comprehensive AI Agent platform with eSIM AI Agent M2M and Smart Website services",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None
)

# Security middleware
security = HTTPBearer()

# Add trusted host middleware for production
if settings.is_production():
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["bamboo-reason-483913-i4.web.app", "localhost", "127.0.0.1"]
    )

# CORS middleware with security considerations
cors_origins = ["https://bamboo-reason-483913-i4.web.app"]
if settings.debug:
    cors_origins.extend(["http://localhost:3000", "http://localhost:8000"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"]
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Add security headers
    security_headers = settings.get_security_headers()
    for header, value in security_headers.items():
        response.headers[header] = value
    
    # Add request ID for tracking
    import uuid
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    
    return response

@app.middleware("http")
async def enforce_https(request: Request, call_next):
    """Enforce HTTPS in production"""
    if settings.security.enforce_https and settings.is_production():
        if request.url.scheme != "https":
            https_url = request.url.replace(scheme="https")
            return Response(
                status_code=301,
                headers={"Location": str(https_url)}
            )
    
    return await call_next(request)

# Initialize services
mcp_server = MCPServer()
device_manager = DeviceManager()
esim_provisioner = eSIMProvisioner()
device_authenticator = DeviceAuthenticator()
m2m_manager = M2MDeviceManager()
m2m_router = M2MMessageRouter()

class AIRequest(BaseModel):
    message: str
    context: Optional[str] = None
    service: Optional[str] = None

class DeviceRegistration(BaseModel):
    user_id: str
    device_type: str
    credentials: Dict[str, str]
    metadata: Optional[Dict[str, Any]] = {}

class M2MDeviceRegistration(BaseModel):
    user_id: str
    device_name: Optional[str] = None
    protocol: str = "mqtt"
    endpoint: Optional[str] = None
    capabilities: List[str] = []
    metadata: Optional[Dict[str, Any]] = {}

@app.get("/")
async def root():
    return {"message": "iGSIM AI Agent API - powered by eSIM Myanmar"}

@app.get("/health")
async def health_check():
    ai_health = await mcp_server.health_check()
    return {
        "status": "healthy",
        "services": {
            "ai_services": ai_health,
            "database": "connected",
            "authentication": "active",
            "encryption": "enabled" if settings.encryption.data_encryption_enabled else "disabled",
            "tls": "enabled" if settings.tls.enabled else "disabled"
        }
    }

# AI Agent Endpoints
@app.post("/ai/request")
async def process_ai_request(request: AIRequest):
    try:
        mcp_request = MCPRequest(
            message=request.message,
            context=request.context,
            service_preference=request.service
        )
        
        response = await mcp_server.process_request(mcp_request)
        return {
            "request_id": response.request_id,
            "response": response.response,
            "service_used": response.service_used,
            "timestamp": response.timestamp
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ai/status")
async def get_ai_status():
    return await mcp_server.health_check()

# eSIM Management Endpoints
@app.post("/esim/provision")
@require_auth
async def provision_esim(device_id: str, plan_type: str = "standard", user: dict = Depends(require_auth)):
    try:
        profile = await esim_provisioner.provision_esim(device_id, plan_type)
        return {
            "profile_id": profile.profile_id,
            "iccid": profile.iccid,
            "activation_code": profile.activation_code,
            "status": profile.status,
            "expires_at": profile.expires_at
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/esim/devices")
@require_auth
async def get_esim_devices(user: dict = Depends(require_auth)):
    try:
        device_repo = DeviceRepository()
        devices = await device_repo.get_devices_by_user(user['uid'])
        return {"devices": [device.to_dict() for device in devices]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/esim/device/{device_id}")
@require_auth
async def get_device_status(device_id: str, user: dict = Depends(require_auth)):
    try:
        status = await device_manager.get_device_status(device_id)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/esim/device/register")
async def register_device(registration: DeviceRegistration):
    try:
        device_id = await device_authenticator.register_device(registration.dict())
        return {"device_id": device_id, "status": "registered"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# M2M Device Endpoints
@app.post("/m2m/register")
@require_auth
async def register_m2m_device(registration: M2MDeviceRegistration, user: dict = Depends(require_auth)):
    try:
        device_data = registration.dict()
        device_data['user_id'] = user['uid']
        device_id = await m2m_manager.register_m2m_device(device_data)
        return {"device_id": device_id, "status": "registered"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/m2m/activate/{device_id}")
@require_auth
async def activate_m2m_device(device_id: str, user: dict = Depends(require_auth)):
    try:
        success = await m2m_manager.activate_m2m_device(device_id)
        if success:
            return {"device_id": device_id, "status": "activated"}
        else:
            raise HTTPException(status_code=400, detail="Failed to activate device")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/m2m/devices")
@require_auth
async def get_m2m_devices(user: dict = Depends(require_auth)):
    try:
        devices = await m2m_manager.get_m2m_devices(user['uid'])
        return {"devices": devices}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/m2m/command/{device_id}")
@require_auth
async def send_m2m_command(device_id: str, command: Dict[str, Any], user: dict = Depends(require_auth)):
    try:
        success = await m2m_manager.send_command(device_id, command)
        if success:
            return {"status": "command_sent", "device_id": device_id}
        else:
            raise HTTPException(status_code=400, detail="Failed to send command")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/m2m/data/{device_id}")
@require_auth
async def get_device_data(device_id: str, data_type: Optional[str] = None, user: dict = Depends(require_auth)):
    try:
        data = await m2m_manager.get_device_data(device_id, data_type)
        return {"device_id": device_id, "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Analytics Endpoints
@app.get("/analytics")
@require_auth
async def get_analytics(user: dict = Depends(require_auth)):
    try:
        device_repo = DeviceRepository()
        esim_repo = eSIMRepository()
        
        # Get basic statistics
        user_devices = await device_repo.get_devices_by_user(user['uid'])
        m2m_devices = await m2m_manager.get_m2m_devices(user['uid'])
        
        analytics = {
            "total_devices": len(user_devices),
            "total_m2m_devices": len(m2m_devices),
            "active_devices": len([d for d in user_devices if d.status == 'active']),
            "device_types": {},
            "recent_activity": []
        }
        
        # Count device types
        for device in user_devices:
            device_type = device.device_type
            analytics["device_types"][device_type] = analytics["device_types"].get(device_type, 0) + 1
        
        return analytics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Admin Endpoints
@app.get("/admin/users")
@require_role("admin")
async def get_all_users(user: dict = Depends(require_auth)):
    try:
        # This would typically fetch from user management system
        return {"message": "Admin endpoint - user list would be here"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def create_ssl_context():
    """Create SSL context for HTTPS"""
    if not settings.tls.enabled:
        return None
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Set minimum TLS version
    if settings.tls.min_version == "TLSv1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    elif settings.tls.min_version == "TLSv1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Set maximum TLS version
    if settings.tls.max_version == "TLSv1.2":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif settings.tls.max_version == "TLSv1.3":
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Load certificates if provided
    if settings.tls.cert_file and settings.tls.key_file:
        context.load_cert_chain(settings.tls.cert_file, settings.tls.key_file)
    
    # Set cipher suites if specified
    if settings.tls.ciphers:
        context.set_ciphers(settings.tls.ciphers)
    
    return context

if __name__ == "__main__":
    ssl_context = create_ssl_context()
    
    uvicorn_config = {
        "app": app,
        "host": "0.0.0.0",
        "port": 8000 if not settings.tls.enabled else 8443,
        "log_level": settings.log_level.lower(),
        "access_log": True,
        "server_header": False,  # Hide server header for security
        "date_header": False     # Hide date header for security
    }
    
    if ssl_context:
        uvicorn_config["ssl_context"] = ssl_context
    
    uvicorn.run(**uvicorn_config)
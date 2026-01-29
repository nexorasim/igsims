from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import asyncio
import logging
import os

from .auth import FirebaseAuth, require_auth, require_role
from .mcp_server import MCPServer
from .esim_agent import DeviceManager, eSIMProvisioner, DeviceAuthenticator
from .m2m_service import M2MDeviceManager, M2MMessageRouter
from .models.mcp_models import MCPRequest, MCPResponse
from .repositories import DeviceRepository, eSIMRepository

app = FastAPI(
    title="iGSIM AI Agent API",
    description="Comprehensive AI Agent platform with eSIM AI Agent M2M and Smart Website services",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
            "authentication": "active"
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
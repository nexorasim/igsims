"""
eSIM AI Agent M2M Service
Handles eSIM operations and M2M communications
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from config.settings import PLATFORM_CONFIG, FIREBASE_CONFIG
from utils.logger import setup_logger

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
except ImportError:
    firebase_admin = None
    firestore = None

logger = setup_logger(__name__)

class eSIMService:
    """eSIM AI Agent M2M service"""
    
    def __init__(self):
        self.platform_name = PLATFORM_CONFIG["name"]
        self.active_connections = {}
        self.m2m_devices = {}
        self.db = None
        
    def initialize(self) -> bool:
        """Initialize eSIM service"""
        try:
            logger.info("Initializing eSIM AI Agent M2M service")
            
            # Initialize Firebase
            self._initialize_firebase()
            
            # Initialize eSIM management
            self._initialize_esim_management()
            
            # Initialize M2M communications
            self._initialize_m2m_communications()
            
            logger.info("eSIM service initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize eSIM service: {e}")
            return False
    
    def _initialize_firebase(self):
        """Initialize Firebase connection"""
        if not firebase_admin:
            logger.warning("Firebase Admin SDK not available")
            return
            
        try:
            # Initialize Firebase app if not already done
            if not firebase_admin._apps:
                # Use default credentials or service account
                firebase_admin.initialize_app()
            
            self.db = firestore.client()
            logger.info("Firebase Firestore initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {e}")
    
    def _initialize_esim_management(self):
        """Initialize eSIM management system"""
        logger.info("Setting up eSIM management")
        
        # Initialize eSIM profiles collection
        self.esim_profiles = {}
        self.profile_templates = {
            "myanmar_local": {
                "operator": "eSIM Myanmar",
                "country": "MM",
                "network_type": "4G/5G",
                "data_plans": ["1GB", "5GB", "10GB", "Unlimited"]
            },
            "international": {
                "operator": "eSIM Myanmar International",
                "country": "Global",
                "network_type": "4G/5G",
                "data_plans": ["1GB", "3GB", "5GB", "10GB"]
            }
        }
        
    def _initialize_m2m_communications(self):
        """Initialize M2M communication protocols"""
        logger.info("Setting up M2M communications")
        
        # Initialize M2M protocols
        self.m2m_protocols = {
            "mqtt": {"enabled": True, "port": 1883, "secure_port": 8883},
            "coap": {"enabled": True, "port": 5683, "secure_port": 5684},
            "http": {"enabled": True, "port": 80, "secure_port": 443}
        }
        
        # Initialize device registry
        self.device_registry = {}
    
    async def provision_esim(self, device_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Provision new eSIM profile"""
        logger.info(f"Provisioning eSIM for device: {device_id}")
        
        try:
            # Generate unique profile ID
            profile_id = f"esim_{device_id}_{uuid.uuid4().hex[:8]}"
            
            # Create eSIM profile
            profile = {
                "profile_id": profile_id,
                "device_id": device_id,
                "operator": profile_data.get("operator", "eSIM Myanmar"),
                "country": profile_data.get("country", "MM"),
                "network_type": profile_data.get("network_type", "4G/5G"),
                "data_plan": profile_data.get("data_plan", "5GB"),
                "status": "provisioned",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "activation_code": f"LPA:1$activation.esim.myanmar${profile_id}",
                "qr_code": f"LPA:1$activation.esim.myanmar${profile_id}",
                "iccid": f"89860{uuid.uuid4().hex[:15]}",
                "msisdn": f"+95{uuid.randint(100000000, 999999999)}"
            }
            
            # Store in memory
            self.active_connections[device_id] = profile
            self.esim_profiles[profile_id] = profile
            
            # Store in Firebase if available
            if self.db:
                await self._store_profile_firebase(profile)
            
            logger.info(f"eSIM provisioned successfully for {device_id}")
            return {
                "status": "success",
                "profile": profile,
                "message": "eSIM profile provisioned successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to provision eSIM: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _store_profile_firebase(self, profile: Dict[str, Any]):
        """Store eSIM profile in Firebase"""
        try:
            doc_ref = self.db.collection('esim_profiles').document(profile['profile_id'])
            await asyncio.to_thread(doc_ref.set, profile)
        except Exception as e:
            logger.error(f"Failed to store profile in Firebase: {e}")
    
    async def manage_m2m_device(self, device_id: str, action: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Manage M2M device operations"""
        logger.info(f"Managing M2M device {device_id}: {action}")
        
        try:
            if params is None:
                params = {}
            
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Handle different M2M actions
            if action == "register":
                result = await self._register_m2m_device(device_id, params)
            elif action == "activate":
                result = await self._activate_m2m_device(device_id, params)
            elif action == "deactivate":
                result = await self._deactivate_m2m_device(device_id, params)
            elif action == "update_config":
                result = await self._update_device_config(device_id, params)
            elif action == "get_status":
                result = await self._get_device_status(device_id)
            elif action == "send_command":
                result = await self._send_device_command(device_id, params)
            else:
                result = {
                    "status": "error",
                    "message": f"Unknown action: {action}"
                }
            
            # Add common metadata
            result.update({
                "device_id": device_id,
                "action": action,
                "timestamp": timestamp,
                "platform": self.platform_name
            })
            
            # Store operation in device history
            if device_id not in self.m2m_devices:
                self.m2m_devices[device_id] = {"history": []}
            
            self.m2m_devices[device_id]["history"].append(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to manage M2M device: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _register_m2m_device(self, device_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Register new M2M device"""
        device_info = {
            "device_id": device_id,
            "device_type": params.get("device_type", "generic"),
            "manufacturer": params.get("manufacturer", "unknown"),
            "model": params.get("model", "unknown"),
            "firmware_version": params.get("firmware_version", "1.0.0"),
            "protocol": params.get("protocol", "mqtt"),
            "status": "registered",
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        
        self.device_registry[device_id] = device_info
        
        return {
            "status": "success",
            "message": "Device registered successfully",
            "device_info": device_info
        }
    
    async def _activate_m2m_device(self, device_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Activate M2M device"""
        if device_id not in self.device_registry:
            return {"status": "error", "message": "Device not registered"}
        
        self.device_registry[device_id]["status"] = "active"
        self.device_registry[device_id]["activated_at"] = datetime.now(timezone.utc).isoformat()
        
        return {
            "status": "success",
            "message": "Device activated successfully"
        }
    
    async def _deactivate_m2m_device(self, device_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Deactivate M2M device"""
        if device_id not in self.device_registry:
            return {"status": "error", "message": "Device not registered"}
        
        self.device_registry[device_id]["status"] = "inactive"
        self.device_registry[device_id]["deactivated_at"] = datetime.now(timezone.utc).isoformat()
        
        return {
            "status": "success",
            "message": "Device deactivated successfully"
        }
    
    async def _update_device_config(self, device_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Update device configuration"""
        if device_id not in self.device_registry:
            return {"status": "error", "message": "Device not registered"}
        
        config_updates = params.get("config", {})
        if "config" not in self.device_registry[device_id]:
            self.device_registry[device_id]["config"] = {}
        
        self.device_registry[device_id]["config"].update(config_updates)
        self.device_registry[device_id]["config_updated_at"] = datetime.now(timezone.utc).isoformat()
        
        return {
            "status": "success",
            "message": "Device configuration updated",
            "config": self.device_registry[device_id]["config"]
        }
    
    async def _get_device_status(self, device_id: str) -> Dict[str, Any]:
        """Get device status"""
        if device_id not in self.device_registry:
            return {"status": "error", "message": "Device not registered"}
        
        return {
            "status": "success",
            "device_status": self.device_registry[device_id]
        }
    
    async def _send_device_command(self, device_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send command to device"""
        if device_id not in self.device_registry:
            return {"status": "error", "message": "Device not registered"}
        
        command = params.get("command")
        if not command:
            return {"status": "error", "message": "No command specified"}
        
        # Simulate command sending
        command_id = uuid.uuid4().hex[:8]
        
        return {
            "status": "success",
            "message": f"Command '{command}' sent to device",
            "command_id": command_id,
            "command": command
        }
    
    def get_device_status(self, device_id: str) -> Dict[str, Any]:
        """Get device connection status"""
        if device_id in self.active_connections:
            return {
                "status": "success",
                "device": self.active_connections[device_id]
            }
        
        return {"device_id": device_id, "status": "not_found"}
    
    def list_active_devices(self) -> List[Dict[str, Any]]:
        """List all active eSIM devices"""
        return list(self.active_connections.values())
    
    def list_m2m_devices(self) -> List[Dict[str, Any]]:
        """List all registered M2M devices"""
        return list(self.device_registry.values())
    
    async def get_analytics(self) -> Dict[str, Any]:
        """Get eSIM and M2M analytics"""
        return {
            "platform": self.platform_name,
            "esim_stats": {
                "total_profiles": len(self.esim_profiles),
                "active_connections": len(self.active_connections),
                "profile_types": list(self.profile_templates.keys())
            },
            "m2m_stats": {
                "total_devices": len(self.device_registry),
                "active_devices": len([d for d in self.device_registry.values() if d.get("status") == "active"]),
                "protocols": self.m2m_protocols
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
import asyncio
import uuid
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import hashlib
import secrets

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.device import Device
from models.esim_profile import eSIMProfile
from repositories import DeviceRepository, eSIMProfileRepository
from encryption import SecureStorage

logger = logging.getLogger(__name__)

class DeviceAuthenticator:
    def __init__(self):
        self.storage = SecureStorage()
        self.device_repo = DeviceRepository()
    
    async def authenticate_device(self, device_id: str, credentials: Dict[str, str]) -> bool:
        try:
            device = await self.device_repo.get_device(device_id)
            if not device:
                return False
            
            stored_hash = device.credential_hash
            provided_hash = self._hash_credentials(credentials)
            
            return stored_hash == provided_hash
        except Exception as e:
            logger.error(f"Device authentication error: {e}")
            return False
    
    def _hash_credentials(self, credentials: Dict[str, str]) -> str:
        credential_string = ''.join(f"{k}:{v}" for k, v in sorted(credentials.items()))
        return hashlib.sha256(credential_string.encode()).hexdigest()
    
    async def register_device(self, device_data: Dict[str, Any]) -> str:
        try:
            device_id = str(uuid.uuid4())
            credentials = device_data.get('credentials', {})
            credential_hash = self._hash_credentials(credentials)
            
            device = Device(
                device_id=device_id,
                user_id=device_data['user_id'],
                device_type=device_data['device_type'],
                status='pending',
                created_at=datetime.utcnow(),
                credential_hash=credential_hash,
                metadata=device_data.get('metadata', {})
            )
            
            await self.device_repo.create_device(device)
            return device_id
        except Exception as e:
            logger.error(f"Device registration error: {e}")
            raise

class eSIMProvisioner:
    def __init__(self):
        self.esim_repo = eSIMProfileRepository()
        self.device_repo = DeviceRepository()
        self.storage = SecureStorage()
    
    async def provision_esim(self, device_id: str, plan_type: str = 'standard') -> eSIMProfile:
        try:
            device = await self.device_repo.get_device(device_id)
            if not device:
                raise ValueError("Device not found")
            
            if device.status != 'active':
                raise ValueError("Device not active")
            
            profile_id = str(uuid.uuid4())
            iccid = self._generate_iccid()
            activation_code = self._generate_activation_code()
            
            profile = eSIMProfile(
                profile_id=profile_id,
                device_id=device_id,
                iccid=iccid,
                status='provisioned',
                plan_type=plan_type,
                activation_code=activation_code,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(days=30)
            )
            
            await self.esim_repo.create_profile(profile)
            
            await self.device_repo.update('devices', device_id, {
                'esim_profile_id': profile_id,
                'updated_at': datetime.utcnow()
            })
            
            return profile
        except Exception as e:
            logger.error(f"eSIM provisioning error: {e}")
            raise
    
    def _generate_iccid(self) -> str:
        return f"89001{secrets.randbelow(10**15):015d}"
    
    def _generate_activation_code(self) -> str:
        return f"LPA:1$rsp-prod.oberthur.net${secrets.token_hex(16)}"

class DeviceManager:
    def __init__(self):
        self.device_repo = DeviceRepository()
        self.authenticator = DeviceAuthenticator()
        self.provisioner = eSIMProvisioner()
    
    async def get_device_status(self, device_id: str) -> Dict[str, Any]:
        try:
            device = await self.device_repo.get_device(device_id)
            if not device:
                return {'error': 'Device not found'}
            
            return {
                'device_id': device.device_id,
                'status': device.status,
                'device_type': device.device_type,
                'last_seen': device.last_seen,
                'signal_strength': device.signal_strength,
                'battery_level': device.battery_level,
                'data_usage': device.data_usage
            }
        except Exception as e:
            logger.error(f"Error getting device status: {e}")
            return {'error': str(e)}
    
    async def update_device_status(self, device_id: str, status_data: Dict[str, Any]) -> bool:
        try:
            update_data = {
                'last_seen': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            
            if 'signal_strength' in status_data:
                update_data['signal_strength'] = status_data['signal_strength']
            if 'battery_level' in status_data:
                update_data['battery_level'] = status_data['battery_level']
            if 'data_usage' in status_data:
                update_data['data_usage'] = status_data['data_usage']
            
            return await self.device_repo.update('devices', device_id, update_data)
        except Exception as e:
            logger.error(f"Error updating device status: {e}")
            return False
    
    async def diagnose_connectivity(self, device_id: str) -> Dict[str, Any]:
        try:
            device = await self.device_repo.get_device(device_id)
            if not device:
                return {'error': 'Device not found'}
            
            diagnostics = {
                'device_id': device_id,
                'connectivity_status': 'unknown',
                'signal_quality': 'unknown',
                'network_registration': 'unknown',
                'data_connection': 'unknown',
                'recommendations': []
            }
            
            if device.signal_strength is not None:
                if device.signal_strength > 80:
                    diagnostics['signal_quality'] = 'excellent'
                elif device.signal_strength > 60:
                    diagnostics['signal_quality'] = 'good'
                elif device.signal_strength > 40:
                    diagnostics['signal_quality'] = 'fair'
                else:
                    diagnostics['signal_quality'] = 'poor'
                    diagnostics['recommendations'].append('Move to area with better signal coverage')
            
            if device.last_seen:
                time_since_last_seen = datetime.utcnow() - device.last_seen
                if time_since_last_seen.total_seconds() < 300:
                    diagnostics['connectivity_status'] = 'online'
                elif time_since_last_seen.total_seconds() < 3600:
                    diagnostics['connectivity_status'] = 'recently_online'
                else:
                    diagnostics['connectivity_status'] = 'offline'
                    diagnostics['recommendations'].append('Check device power and network settings')
            
            return diagnostics
        except Exception as e:
            logger.error(f"Error diagnosing connectivity: {e}")
            return {'error': str(e)}

class AuditLogger:
    def __init__(self):
        self.device_repo = DeviceRepository()
    
    async def log_activity(self, device_id: str, activity_type: str, details: Dict[str, Any]):
        try:
            log_entry = {
                'device_id': device_id,
                'activity_type': activity_type,
                'details': details,
                'timestamp': datetime.utcnow(),
                'log_id': str(uuid.uuid4())
            }
            
            await self.device_repo.create('device_logs', log_entry)
            logger.info(f"Activity logged: {activity_type} for device {device_id}")
        except Exception as e:
            logger.error(f"Error logging activity: {e}")
    
    async def get_device_logs(self, device_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            logs = await self.device_repo.query(
                'device_logs',
                filters=[('device_id', '==', device_id)],
                limit=limit
            )
            return sorted(logs, key=lambda x: x['timestamp'], reverse=True)
        except Exception as e:
            logger.error(f"Error getting device logs: {e}")
            return []
import asyncio
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import aiohttp
from cryptography.fernet import Fernet

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repositories import DeviceRepository
from encryption import DataEncryption

logger = logging.getLogger(__name__)

class M2MMessageRouter:
    def __init__(self):
        self.device_repo = DeviceRepository()
        self.encryption = DataEncryption()
        self.message_queue = asyncio.Queue()
        self.active_connections = {}
    
    async def route_message(self, source_device: str, target_device: str, message: Dict[str, Any]) -> bool:
        try:
            encrypted_message = self._encrypt_message(message)
            
            routing_info = {
                'message_id': str(uuid.uuid4()),
                'source_device': source_device,
                'target_device': target_device,
                'message': encrypted_message,
                'timestamp': datetime.utcnow(),
                'status': 'pending'
            }
            
            await self.message_queue.put(routing_info)
            await self._process_message_queue()
            
            return True
        except Exception as e:
            logger.error(f"Error routing M2M message: {e}")
            return False
    
    def _encrypt_message(self, message: Dict[str, Any]) -> str:
        message_json = json.dumps(message)
        return self.encryption.encrypt(message_json)
    
    def _decrypt_message(self, encrypted_message: str) -> Dict[str, Any]:
        decrypted_json = self.encryption.decrypt(encrypted_message)
        return json.loads(decrypted_json)
    
    async def _process_message_queue(self):
        try:
            while not self.message_queue.empty():
                message_info = await self.message_queue.get()
                await self._deliver_message(message_info)
        except Exception as e:
            logger.error(f"Error processing message queue: {e}")
    
    async def _deliver_message(self, message_info: Dict[str, Any]):
        try:
            target_device = message_info['target_device']
            device = await self.device_repo.get_device(target_device)
            
            if not device:
                logger.error(f"Target device not found: {target_device}")
                return
            
            if target_device in self.active_connections:
                await self._send_direct_message(target_device, message_info)
            else:
                await self._store_message_for_delivery(message_info)
            
            await self._log_message_delivery(message_info)
        except Exception as e:
            logger.error(f"Error delivering message: {e}")
    
    async def _send_direct_message(self, device_id: str, message_info: Dict[str, Any]):
        connection = self.active_connections.get(device_id)
        if connection:
            try:
                await connection.send(json.dumps(message_info))
                message_info['status'] = 'delivered'
            except Exception as e:
                logger.error(f"Error sending direct message: {e}")
                message_info['status'] = 'failed'
    
    async def _store_message_for_delivery(self, message_info: Dict[str, Any]):
        try:
            await self.device_repo.create('pending_messages', message_info)
            message_info['status'] = 'queued'
        except Exception as e:
            logger.error(f"Error storing message: {e}")
            message_info['status'] = 'failed'
    
    async def _log_message_delivery(self, message_info: Dict[str, Any]):
        log_entry = {
            'message_id': message_info['message_id'],
            'source_device': message_info['source_device'],
            'target_device': message_info['target_device'],
            'status': message_info['status'],
            'timestamp': datetime.utcnow()
        }
        await self.device_repo.create('message_logs', log_entry)

class M2MDeviceManager:
    def __init__(self):
        self.device_repo = DeviceRepository()
        self.message_router = M2MMessageRouter()
    
    async def register_m2m_device(self, device_data: Dict[str, Any]) -> str:
        try:
            device_id = str(uuid.uuid4())
            
            m2m_device = {
                'device_id': device_id,
                'device_type': 'm2m',
                'user_id': device_data['user_id'],
                'device_name': device_data.get('device_name', f'M2M-{device_id[:8]}'),
                'protocol': device_data.get('protocol', 'mqtt'),
                'endpoint': device_data.get('endpoint'),
                'status': 'registered',
                'capabilities': device_data.get('capabilities', []),
                'created_at': datetime.utcnow(),
                'last_seen': None,
                'metadata': device_data.get('metadata', {})
            }
            
            await self.device_repo.create('m2m_devices', m2m_device, device_id)
            return device_id
        except Exception as e:
            logger.error(f"Error registering M2M device: {e}")
            raise
    
    async def activate_m2m_device(self, device_id: str) -> bool:
        try:
            update_data = {
                'status': 'active',
                'activated_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            
            return await self.device_repo.update('m2m_devices', device_id, update_data)
        except Exception as e:
            logger.error(f"Error activating M2M device: {e}")
            return False
    
    async def get_m2m_devices(self, user_id: str) -> List[Dict[str, Any]]:
        try:
            devices = await self.device_repo.query(
                'm2m_devices',
                filters=[('user_id', '==', user_id)]
            )
            return devices
        except Exception as e:
            logger.error(f"Error getting M2M devices: {e}")
            return []
    
    async def send_command(self, device_id: str, command: Dict[str, Any]) -> bool:
        try:
            device = await self.device_repo.get('m2m_devices', device_id)
            if not device:
                return False
            
            command_message = {
                'type': 'command',
                'command': command,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return await self.message_router.route_message('system', device_id, command_message)
        except Exception as e:
            logger.error(f"Error sending command to M2M device: {e}")
            return False
    
    async def get_device_data(self, device_id: str, data_type: str = None) -> List[Dict[str, Any]]:
        try:
            filters = [('device_id', '==', device_id)]
            if data_type:
                filters.append(('data_type', '==', data_type))
            
            data = await self.device_repo.query('device_data', filters=filters, limit=100)
            return sorted(data, key=lambda x: x.get('timestamp', datetime.min), reverse=True)
        except Exception as e:
            logger.error(f"Error getting device data: {e}")
            return []

class M2MProtocolHandler:
    def __init__(self):
        self.device_manager = M2MDeviceManager()
        self.message_router = M2MMessageRouter()
    
    async def handle_mqtt_message(self, topic: str, payload: bytes, device_id: str):
        try:
            message = json.loads(payload.decode())
            
            if topic.endswith('/data'):
                await self._store_device_data(device_id, message)
            elif topic.endswith('/status'):
                await self._update_device_status(device_id, message)
            elif topic.endswith('/command_response'):
                await self._handle_command_response(device_id, message)
            
            await self._update_last_seen(device_id)
        except Exception as e:
            logger.error(f"Error handling MQTT message: {e}")
    
    async def handle_coap_request(self, path: str, payload: bytes, device_id: str):
        try:
            if payload:
                message = json.loads(payload.decode())
            else:
                message = {}
            
            if path == '/data':
                await self._store_device_data(device_id, message)
                return {'status': 'ok'}
            elif path == '/status':
                await self._update_device_status(device_id, message)
                return {'status': 'ok'}
            elif path == '/commands':
                commands = await self._get_pending_commands(device_id)
                return {'commands': commands}
            
            await self._update_last_seen(device_id)
            return {'status': 'ok'}
        except Exception as e:
            logger.error(f"Error handling CoAP request: {e}")
            return {'error': str(e)}
    
    async def _store_device_data(self, device_id: str, data: Dict[str, Any]):
        data_entry = {
            'device_id': device_id,
            'data': data,
            'timestamp': datetime.utcnow(),
            'data_type': data.get('type', 'sensor')
        }
        await self.device_manager.device_repo.create('device_data', data_entry)
    
    async def _update_device_status(self, device_id: str, status: Dict[str, Any]):
        update_data = {
            'status': status.get('status', 'active'),
            'last_status_update': datetime.utcnow(),
            'device_info': status
        }
        await self.device_manager.device_repo.update('m2m_devices', device_id, update_data)
    
    async def _handle_command_response(self, device_id: str, response: Dict[str, Any]):
        response_entry = {
            'device_id': device_id,
            'response': response,
            'timestamp': datetime.utcnow()
        }
        await self.device_manager.device_repo.create('command_responses', response_entry)
    
    async def _update_last_seen(self, device_id: str):
        await self.device_manager.device_repo.update('m2m_devices', device_id, {
            'last_seen': datetime.utcnow()
        })
    
    async def _get_pending_commands(self, device_id: str) -> List[Dict[str, Any]]:
        commands = await self.device_manager.device_repo.query(
            'pending_commands',
            filters=[('device_id', '==', device_id), ('status', '==', 'pending')]
        )
        return commands
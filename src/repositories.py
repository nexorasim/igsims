from typing import List, Optional, Dict, Any
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
import asyncio
from datetime import datetime
import logging

from ..models.device import Device
from ..models.esim_profile import eSIMProfile
from ..models.user import User
from ..models.ai_context import AIContext
from ..models.mcp_models import MCPRequest, MCPResponse

logger = logging.getLogger(__name__)

class FirestoreRepository:
    def __init__(self):
        self.db = firestore.Client()
    
    async def create(self, collection: str, data: Dict[str, Any], doc_id: Optional[str] = None) -> str:
        try:
            doc_ref = self.db.collection(collection).document(doc_id) if doc_id else self.db.collection(collection).document()
            doc_ref.set(data)
            return doc_ref.id
        except Exception as e:
            logger.error(f"Error creating document in {collection}: {e}")
            raise
    
    async def get(self, collection: str, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            doc = self.db.collection(collection).document(doc_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logger.error(f"Error getting document {doc_id} from {collection}: {e}")
            raise
    
    async def update(self, collection: str, doc_id: str, data: Dict[str, Any]) -> bool:
        try:
            self.db.collection(collection).document(doc_id).update(data)
            return True
        except Exception as e:
            logger.error(f"Error updating document {doc_id} in {collection}: {e}")
            return False
    
    async def delete(self, collection: str, doc_id: str) -> bool:
        try:
            self.db.collection(collection).document(doc_id).delete()
            return True
        except Exception as e:
            logger.error(f"Error deleting document {doc_id} from {collection}: {e}")
            return False
    
    async def query(self, collection: str, filters: List[tuple] = None, limit: int = None) -> List[Dict[str, Any]]:
        try:
            query = self.db.collection(collection)
            if filters:
                for field, op, value in filters:
                    query = query.where(filter=FieldFilter(field, op, value))
            if limit:
                query = query.limit(limit)
            return [doc.to_dict() for doc in query.stream()]
        except Exception as e:
            logger.error(f"Error querying collection {collection}: {e}")
            raise

class DeviceRepository(FirestoreRepository):
    COLLECTION = "devices"
    
    async def create_device(self, device: Device) -> str:
        return await self.create(self.COLLECTION, device.to_dict(), device.device_id)
    
    async def get_device(self, device_id: str) -> Optional[Device]:
        data = await self.get(self.COLLECTION, device_id)
        return Device.from_dict(data) if data else None
    
    async def get_devices_by_user(self, user_id: str) -> List[Device]:
        data = await self.query(self.COLLECTION, [("user_id", "==", user_id)])
        return [Device.from_dict(d) for d in data]

class eSIMRepository(FirestoreRepository):
    COLLECTION = "esim_profiles"
    
    async def create_profile(self, profile: eSIMProfile) -> str:
        return await self.create(self.COLLECTION, profile.to_dict(), profile.profile_id)
    
    async def get_profile(self, profile_id: str) -> Optional[eSIMProfile]:
        data = await self.get(self.COLLECTION, profile_id)
        return eSIMProfile.from_dict(data) if data else None

class UserRepository(FirestoreRepository):
    COLLECTION = "users"
    
    async def create_user(self, user: User) -> str:
        return await self.create(self.COLLECTION, user.to_dict(), user.user_id)
    
    async def get_user(self, user_id: str) -> Optional[User]:
        data = await self.get(self.COLLECTION, user_id)
        return User.from_dict(data) if data else None

class AIContextRepository(FirestoreRepository):
    COLLECTION = "ai_contexts"
    
    async def create_context(self, context: AIContext) -> str:
        return await self.create(self.COLLECTION, context.to_dict())
    
    async def get_context(self, context_id: str) -> Optional[AIContext]:
        data = await self.get(self.COLLECTION, context_id)
        return AIContext.from_dict(data) if data else None

class MCPRepository(FirestoreRepository):
    REQUEST_COLLECTION = "mcp_requests"
    RESPONSE_COLLECTION = "mcp_responses"
    
    async def create_request(self, request: MCPRequest) -> str:
        return await self.create(self.REQUEST_COLLECTION, request.to_dict())
    
    async def create_response(self, response: MCPResponse) -> str:
        return await self.create(self.RESPONSE_COLLECTION, response.to_dict())
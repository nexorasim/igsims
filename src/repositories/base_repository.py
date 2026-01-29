"""
Base repository class for Firestore operations
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, TypeVar, Generic, Type
from datetime import datetime
import logging

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    from google.cloud.firestore_v1.base_query import FieldFilter
    from google.cloud.exceptions import NotFound, Conflict
except ImportError:
    firebase_admin = None
    firestore = None
    FieldFilter = None
    NotFound = Exception
    Conflict = Exception

T = TypeVar('T')

class BaseRepository(Generic[T], ABC):
    """Base repository class with common Firestore operations"""
    
    def __init__(self, collection_name: str, model_class: Type[T]):
        self.collection_name = collection_name
        self.model_class = model_class
        self.db = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self._initialize_firestore()
    
    def _initialize_firestore(self):
        """Initialize Firestore client"""
        if not firebase_admin or not firestore:
            self.logger.warning("Firebase Admin SDK not available")
            return
        
        try:
            # Initialize Firebase app if not already done
            if not firebase_admin._apps:
                firebase_admin.initialize_app()
            
            self.db = firestore.client()
            self.logger.info(f"Firestore initialized for collection: {self.collection_name}")
        except Exception as e:
            self.logger.error(f"Failed to initialize Firestore: {e}")
    
    @abstractmethod
    def _to_dict(self, entity: T) -> Dict[str, Any]:
        """Convert entity to dictionary for storage"""
        pass
    
    @abstractmethod
    def _from_dict(self, data: Dict[str, Any]) -> T:
        """Convert dictionary to entity"""
        pass
    
    @abstractmethod
    def _get_id(self, entity: T) -> str:
        """Get entity ID"""
        pass
    
    async def create(self, entity: T) -> T:
        """Create a new entity"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            entity_id = self._get_id(entity)
            entity_dict = self._to_dict(entity)
            entity_dict['created_at'] = datetime.utcnow().isoformat()
            entity_dict['updated_at'] = datetime.utcnow().isoformat()
            
            doc_ref = self.db.collection(self.collection_name).document(entity_id)
            await asyncio.to_thread(doc_ref.set, entity_dict)
            
            self.logger.info(f"Created entity {entity_id} in {self.collection_name}")
            return entity
            
        except Exception as e:
            self.logger.error(f"Failed to create entity: {e}")
            raise
    
    async def get_by_id(self, entity_id: str) -> Optional[T]:
        """Get entity by ID"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            doc_ref = self.db.collection(self.collection_name).document(entity_id)
            doc = await asyncio.to_thread(doc_ref.get)
            
            if not doc.exists:
                return None
            
            return self._from_dict(doc.to_dict())
            
        except Exception as e:
            self.logger.error(f"Failed to get entity {entity_id}: {e}")
            raise
    
    async def update(self, entity: T) -> T:
        """Update an existing entity"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            entity_id = self._get_id(entity)
            entity_dict = self._to_dict(entity)
            entity_dict['updated_at'] = datetime.utcnow().isoformat()
            
            doc_ref = self.db.collection(self.collection_name).document(entity_id)
            await asyncio.to_thread(doc_ref.update, entity_dict)
            
            self.logger.info(f"Updated entity {entity_id} in {self.collection_name}")
            return entity
            
        except NotFound:
            self.logger.warning(f"Entity {entity_id} not found for update")
            raise
        except Exception as e:
            self.logger.error(f"Failed to update entity {entity_id}: {e}")
            raise
    
    async def delete(self, entity_id: str) -> bool:
        """Delete an entity by ID"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            doc_ref = self.db.collection(self.collection_name).document(entity_id)
            await asyncio.to_thread(doc_ref.delete)
            
            self.logger.info(f"Deleted entity {entity_id} from {self.collection_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete entity {entity_id}: {e}")
            return False
    
    async def list_all(self, limit: Optional[int] = None) -> List[T]:
        """List all entities with optional limit"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            query = self.db.collection(self.collection_name)
            
            if limit:
                query = query.limit(limit)
            
            docs = await asyncio.to_thread(query.stream)
            entities = []
            
            for doc in docs:
                entities.append(self._from_dict(doc.to_dict()))
            
            return entities
            
        except Exception as e:
            self.logger.error(f"Failed to list entities: {e}")
            raise
    
    async def query(self, field: str, operator: str, value: Any, limit: Optional[int] = None) -> List[T]:
        """Query entities by field"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            query = self.db.collection(self.collection_name)
            
            if FieldFilter:
                query = query.where(filter=FieldFilter(field, operator, value))
            else:
                # Fallback for older versions
                query = query.where(field, operator, value)
            
            if limit:
                query = query.limit(limit)
            
            docs = await asyncio.to_thread(query.stream)
            entities = []
            
            for doc in docs:
                entities.append(self._from_dict(doc.to_dict()))
            
            return entities
            
        except Exception as e:
            self.logger.error(f"Failed to query entities: {e}")
            raise
    
    async def exists(self, entity_id: str) -> bool:
        """Check if entity exists"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            doc_ref = self.db.collection(self.collection_name).document(entity_id)
            doc = await asyncio.to_thread(doc_ref.get)
            return doc.exists
            
        except Exception as e:
            self.logger.error(f"Failed to check existence of {entity_id}: {e}")
            return False
    
    async def count(self) -> int:
        """Count total entities in collection"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            docs = await asyncio.to_thread(self.db.collection(self.collection_name).stream)
            return sum(1 for _ in docs)
            
        except Exception as e:
            self.logger.error(f"Failed to count entities: {e}")
            return 0
    
    async def batch_create(self, entities: List[T]) -> List[T]:
        """Create multiple entities in a batch"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            batch = self.db.batch()
            
            for entity in entities:
                entity_id = self._get_id(entity)
                entity_dict = self._to_dict(entity)
                entity_dict['created_at'] = datetime.utcnow().isoformat()
                entity_dict['updated_at'] = datetime.utcnow().isoformat()
                
                doc_ref = self.db.collection(self.collection_name).document(entity_id)
                batch.set(doc_ref, entity_dict)
            
            await asyncio.to_thread(batch.commit)
            
            self.logger.info(f"Batch created {len(entities)} entities in {self.collection_name}")
            return entities
            
        except Exception as e:
            self.logger.error(f"Failed to batch create entities: {e}")
            raise
    
    async def batch_update(self, entities: List[T]) -> List[T]:
        """Update multiple entities in a batch"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            batch = self.db.batch()
            
            for entity in entities:
                entity_id = self._get_id(entity)
                entity_dict = self._to_dict(entity)
                entity_dict['updated_at'] = datetime.utcnow().isoformat()
                
                doc_ref = self.db.collection(self.collection_name).document(entity_id)
                batch.update(doc_ref, entity_dict)
            
            await asyncio.to_thread(batch.commit)
            
            self.logger.info(f"Batch updated {len(entities)} entities in {self.collection_name}")
            return entities
            
        except Exception as e:
            self.logger.error(f"Failed to batch update entities: {e}")
            raise
    
    async def transaction_update(self, entity_id: str, update_func) -> Optional[T]:
        """Update entity within a transaction"""
        if not self.db:
            raise RuntimeError("Firestore not initialized")
        
        try:
            @firestore.transactional
            def update_in_transaction(transaction):
                doc_ref = self.db.collection(self.collection_name).document(entity_id)
                doc = doc_ref.get(transaction=transaction)
                
                if not doc.exists:
                    return None
                
                current_entity = self._from_dict(doc.to_dict())
                updated_entity = update_func(current_entity)
                
                if updated_entity:
                    entity_dict = self._to_dict(updated_entity)
                    entity_dict['updated_at'] = datetime.utcnow().isoformat()
                    transaction.update(doc_ref, entity_dict)
                
                return updated_entity
            
            transaction = self.db.transaction()
            result = await asyncio.to_thread(update_in_transaction, transaction)
            
            if result:
                self.logger.info(f"Transaction updated entity {entity_id} in {self.collection_name}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to transaction update entity {entity_id}: {e}")
            raise
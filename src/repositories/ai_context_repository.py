"""
AI Context repository for Firestore operations
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.ai_context import AIContext, AIMessage, AIServiceType
from .base_repository import BaseRepository

class AIContextRepository(BaseRepository[AIContext]):
    """Repository for AI Context entities"""
    
    def __init__(self):
        super().__init__("ai_contexts", AIContext)
    
    def _to_dict(self, entity: AIContext) -> Dict[str, Any]:
        """Convert AI Context to dictionary"""
        return entity.to_dict()
    
    def _from_dict(self, data: Dict[str, Any]) -> AIContext:
        """Convert dictionary to AI Context"""
        return AIContext.from_dict(data)
    
    def _get_id(self, entity: AIContext) -> str:
        """Get AI Context ID"""
        return entity.context_id
    
    async def get_by_user_id(self, user_id: str, limit: Optional[int] = None) -> List[AIContext]:
        """Get AI contexts by user ID"""
        return await self.query("user_id", "==", user_id, limit)
    
    async def get_active_contexts(self, limit: Optional[int] = None) -> List[AIContext]:
        """Get all active AI contexts"""
        return await self.query("is_active", "==", True, limit)
    
    async def get_user_active_context(self, user_id: str) -> Optional[AIContext]:
        """Get the most recent active context for a user"""
        contexts = await self.query("user_id", "==", user_id, limit=1)
        active_contexts = [ctx for ctx in contexts if ctx.is_active]
        return active_contexts[0] if active_contexts else None
    
    async def create_user_context(self, user_id: str) -> AIContext:
        """Create a new AI context for a user"""
        context = AIContext.create_new(user_id)
        return await self.create(context)
    
    async def add_message_to_context(self, context_id: str, message: AIMessage) -> bool:
        """Add a message to an AI context"""
        try:
            def add_msg(context: AIContext) -> AIContext:
                context.add_message(message)
                return context
            
            result = await self.transaction_update(context_id, add_msg)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to add message to context {context_id}: {e}")
            return False
    
    async def clear_context_history(self, context_id: str) -> bool:
        """Clear conversation history for a context"""
        try:
            def clear_history(context: AIContext) -> AIContext:
                context.clear_history()
                return context
            
            result = await self.transaction_update(context_id, clear_history)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to clear history for context {context_id}: {e}")
            return False
    
    async def set_context_preference(self, context_id: str, key: str, value: Any) -> bool:
        """Set a preference for an AI context"""
        try:
            def set_pref(context: AIContext) -> AIContext:
                context.set_preference(key, value)
                return context
            
            result = await self.transaction_update(context_id, set_pref)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to set preference for context {context_id}: {e}")
            return False
    
    async def deactivate_context(self, context_id: str) -> bool:
        """Deactivate an AI context"""
        try:
            def deactivate(context: AIContext) -> AIContext:
                context.is_active = False
                return context
            
            result = await self.transaction_update(context_id, deactivate)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate context {context_id}: {e}")
            return False
    
    async def get_contexts_by_service_type(self, service_type: AIServiceType, limit: Optional[int] = None) -> List[AIContext]:
        """Get contexts that have used a specific AI service"""
        all_contexts = await self.list_all()
        
        matching_contexts = []
        for context in all_contexts:
            # Check if any message in the context used the specified service
            for message in context.conversation_history:
                if message.service_type == service_type:
                    matching_contexts.append(context)
                    break
            
            if limit and len(matching_contexts) >= limit:
                break
        
        return matching_contexts
    
    async def get_conversation_statistics(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get conversation statistics"""
        try:
            if user_id:
                contexts = await self.get_by_user_id(user_id)
            else:
                contexts = await self.list_all()
            
            stats = {
                "total_contexts": len(contexts),
                "active_contexts": 0,
                "total_messages": 0,
                "total_tokens": 0,
                "by_service_type": {},
                "average_messages_per_context": 0,
                "average_tokens_per_message": 0
            }
            
            # Initialize service type counters
            for service_type in AIServiceType:
                stats["by_service_type"][service_type.value] = {
                    "contexts": 0,
                    "messages": 0,
                    "tokens": 0
                }
            
            total_messages = 0
            total_tokens = 0
            service_usage = {}
            
            for context in contexts:
                if context.is_active:
                    stats["active_contexts"] += 1
                
                context_messages = len(context.conversation_history)
                total_messages += context_messages
                
                # Track service usage per context
                context_services = set()
                
                for message in context.conversation_history:
                    if message.tokens_used:
                        total_tokens += message.tokens_used
                    
                    service_type = message.service_type.value
                    context_services.add(service_type)
                    
                    stats["by_service_type"][service_type]["messages"] += 1
                    if message.tokens_used:
                        stats["by_service_type"][service_type]["tokens"] += message.tokens_used
                
                # Count contexts per service type
                for service in context_services:
                    stats["by_service_type"][service]["contexts"] += 1
            
            stats["total_messages"] = total_messages
            stats["total_tokens"] = total_tokens
            
            if len(contexts) > 0:
                stats["average_messages_per_context"] = total_messages / len(contexts)
            
            if total_messages > 0:
                stats["average_tokens_per_message"] = total_tokens / total_messages
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get conversation statistics: {e}")
            return {
                "total_contexts": 0,
                "active_contexts": 0,
                "total_messages": 0,
                "total_tokens": 0,
                "by_service_type": {},
                "average_messages_per_context": 0,
                "average_tokens_per_message": 0
            }
    
    async def cleanup_old_contexts(self, days_threshold: int = 30, keep_active: bool = True) -> int:
        """Remove old AI contexts"""
        try:
            threshold_time = datetime.utcnow() - timedelta(days=days_threshold)
            threshold_iso = threshold_time.isoformat()
            
            old_contexts = await self.query("updated_at", "<", threshold_iso)
            
            deleted_count = 0
            for context in old_contexts:
                # Skip active contexts if keep_active is True
                if keep_active and context.is_active:
                    continue
                
                if await self.delete(context.context_id):
                    deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} old AI contexts")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old contexts: {e}")
            return 0
    
    async def get_user_conversation_summary(self, user_id: str) -> Dict[str, Any]:
        """Get conversation summary for a specific user"""
        try:
            contexts = await self.get_by_user_id(user_id)
            
            if not contexts:
                return {
                    "user_id": user_id,
                    "total_contexts": 0,
                    "total_messages": 0,
                    "total_tokens": 0,
                    "favorite_service": None,
                    "most_recent_activity": None
                }
            
            total_messages = 0
            total_tokens = 0
            service_usage = {}
            most_recent_activity = None
            
            for context in contexts:
                summary = context.get_conversation_summary()
                total_messages += summary["total_messages"]
                total_tokens += summary["total_tokens"]
                
                # Track most recent activity
                if context.updated_at:
                    if not most_recent_activity or context.updated_at > most_recent_activity:
                        most_recent_activity = context.updated_at
                
                # Count service usage
                for message in context.conversation_history:
                    service = message.service_type.value
                    service_usage[service] = service_usage.get(service, 0) + 1
            
            # Find favorite service
            favorite_service = None
            if service_usage:
                favorite_service = max(service_usage, key=service_usage.get)
            
            return {
                "user_id": user_id,
                "total_contexts": len(contexts),
                "total_messages": total_messages,
                "total_tokens": total_tokens,
                "favorite_service": favorite_service,
                "service_usage": service_usage,
                "most_recent_activity": most_recent_activity.isoformat() if most_recent_activity else None
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get user conversation summary for {user_id}: {e}")
            return {
                "user_id": user_id,
                "total_contexts": 0,
                "total_messages": 0,
                "total_tokens": 0,
                "favorite_service": None,
                "most_recent_activity": None
            }
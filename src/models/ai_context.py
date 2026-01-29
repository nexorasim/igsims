"""
AI Context and Message data models for iGSIM AI Agent Platform
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

class AIServiceType(Enum):
    GEMINI = "gemini"
    XAI = "xai"
    GROQ = "groq"
    AUTO = "auto"

@dataclass
class AIMessage:
    """AI message model for conversation history"""
    
    message_id: str
    content: str
    role: str  # 'user', 'assistant', 'system'
    timestamp: datetime
    service_type: AIServiceType
    metadata: Dict[str, Any] = field(default_factory=dict)
    tokens_used: Optional[int] = None
    processing_time: Optional[float] = None
    
    def __post_init__(self):
        """Initialize message ID if not provided"""
        if not self.message_id:
            self.message_id = str(uuid.uuid4())
    
    def is_user_message(self) -> bool:
        """Check if message is from user"""
        return self.role == "user"
    
    def is_assistant_message(self) -> bool:
        """Check if message is from assistant"""
        return self.role == "assistant"
    
    def get_word_count(self) -> int:
        """Get word count of message content"""
        return len(self.content.split())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for storage"""
        return {
            'message_id': self.message_id,
            'content': self.content,
            'role': self.role,
            'timestamp': self.timestamp.isoformat(),
            'service_type': self.service_type.value,
            'metadata': self.metadata,
            'tokens_used': self.tokens_used,
            'processing_time': self.processing_time
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AIMessage':
        """Create message from dictionary"""
        return cls(
            message_id=data['message_id'],
            content=data['content'],
            role=data['role'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            service_type=AIServiceType(data['service_type']),
            metadata=data.get('metadata', {}),
            tokens_used=data.get('tokens_used'),
            processing_time=data.get('processing_time')
        )
    
    @classmethod
    def create_user_message(cls, content: str, service_type: AIServiceType = AIServiceType.AUTO) -> 'AIMessage':
        """Create a user message"""
        return cls(
            message_id=str(uuid.uuid4()),
            content=content,
            role="user",
            timestamp=datetime.utcnow(),
            service_type=service_type
        )
    
    @classmethod
    def create_assistant_message(cls, content: str, service_type: AIServiceType, 
                                tokens_used: Optional[int] = None, 
                                processing_time: Optional[float] = None) -> 'AIMessage':
        """Create an assistant message"""
        return cls(
            message_id=str(uuid.uuid4()),
            content=content,
            role="assistant",
            timestamp=datetime.utcnow(),
            service_type=service_type,
            tokens_used=tokens_used,
            processing_time=processing_time
        )

@dataclass
class AIContext:
    """AI context model for managing conversation state"""
    
    context_id: str
    user_id: str
    session_data: Dict[str, Any] = field(default_factory=dict)
    conversation_history: List[AIMessage] = field(default_factory=list)
    preferences: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True
    max_history_length: int = 100
    
    def __post_init__(self):
        """Initialize timestamps if not provided"""
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
    
    def add_message(self, message: AIMessage) -> None:
        """Add message to conversation history"""
        self.conversation_history.append(message)
        self.updated_at = datetime.utcnow()
        
        # Trim history if it exceeds max length
        if len(self.conversation_history) > self.max_history_length:
            self.conversation_history = self.conversation_history[-self.max_history_length:]
    
    def get_recent_messages(self, count: int = 10) -> List[AIMessage]:
        """Get recent messages from conversation history"""
        return self.conversation_history[-count:] if self.conversation_history else []
    
    def get_user_messages(self) -> List[AIMessage]:
        """Get all user messages"""
        return [msg for msg in self.conversation_history if msg.is_user_message()]
    
    def get_assistant_messages(self) -> List[AIMessage]:
        """Get all assistant messages"""
        return [msg for msg in self.conversation_history if msg.is_assistant_message()]
    
    def clear_history(self) -> None:
        """Clear conversation history"""
        self.conversation_history.clear()
        self.updated_at = datetime.utcnow()
    
    def set_preference(self, key: str, value: Any) -> None:
        """Set context preference"""
        self.preferences[key] = value
        self.updated_at = datetime.utcnow()
    
    def get_preference(self, key: str, default: Any = None) -> Any:
        """Get context preference"""
        return self.preferences.get(key, default)
    
    def get_conversation_summary(self) -> Dict[str, Any]:
        """Get conversation summary statistics"""
        total_messages = len(self.conversation_history)
        user_messages = len(self.get_user_messages())
        assistant_messages = len(self.get_assistant_messages())
        
        total_tokens = sum(msg.tokens_used for msg in self.conversation_history if msg.tokens_used)
        avg_processing_time = None
        
        processing_times = [msg.processing_time for msg in self.conversation_history 
                          if msg.processing_time is not None]
        if processing_times:
            avg_processing_time = sum(processing_times) / len(processing_times)
        
        return {
            'total_messages': total_messages,
            'user_messages': user_messages,
            'assistant_messages': assistant_messages,
            'total_tokens': total_tokens,
            'avg_processing_time': avg_processing_time,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for Firestore storage"""
        return {
            'context_id': self.context_id,
            'user_id': self.user_id,
            'session_data': self.session_data,
            'conversation_history': [msg.to_dict() for msg in self.conversation_history],
            'preferences': self.preferences,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_active': self.is_active,
            'max_history_length': self.max_history_length
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AIContext':
        """Create context from dictionary"""
        context = cls(
            context_id=data['context_id'],
            user_id=data['user_id'],
            session_data=data.get('session_data', {}),
            preferences=data.get('preferences', {}),
            is_active=data.get('is_active', True),
            max_history_length=data.get('max_history_length', 100),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None
        )
        
        # Load conversation history
        if data.get('conversation_history'):
            context.conversation_history = [
                AIMessage.from_dict(msg_data) 
                for msg_data in data['conversation_history']
            ]
        
        return context
    
    @classmethod
    def create_new(cls, user_id: str) -> 'AIContext':
        """Create a new AI context for user"""
        context_id = str(uuid.uuid4())
        return cls(
            context_id=context_id,
            user_id=user_id
        )
    
    def validate(self) -> bool:
        """Validate AI context data"""
        if not self.context_id or not isinstance(self.context_id, str):
            return False
        if not self.user_id or not isinstance(self.user_id, str):
            return False
        return True
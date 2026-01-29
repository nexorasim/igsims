"""
User data model for iGSIM AI Agent Platform
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
import hashlib

@dataclass
class User:
    """User model for authentication and authorization"""
    
    user_id: str
    email: str
    display_name: str
    role: str
    permissions: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    preferences: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    profile_image_url: Optional[str] = None
    
    def __post_init__(self):
        """Initialize timestamps if not provided"""
        if self.created_at is None:
            self.created_at = datetime.utcnow()
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission"""
        return permission in self.permissions or self.role == "admin"
    
    def add_permission(self, permission: str) -> None:
        """Add permission to user"""
        if permission not in self.permissions:
            self.permissions.append(permission)
    
    def remove_permission(self, permission: str) -> None:
        """Remove permission from user"""
        if permission in self.permissions:
            self.permissions.remove(permission)
    
    def update_last_login(self) -> None:
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
    
    def set_preference(self, key: str, value: Any) -> None:
        """Set user preference"""
        self.preferences[key] = value
    
    def get_preference(self, key: str, default: Any = None) -> Any:
        """Get user preference"""
        return self.preferences.get(key, default)
    
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return self.role == "admin"
    
    def is_operator(self) -> bool:
        """Check if user is operator"""
        return self.role in ["admin", "operator"]
    
    def get_avatar_url(self) -> str:
        """Get user avatar URL (Gravatar or custom)"""
        if self.profile_image_url:
            return self.profile_image_url
        
        # Generate Gravatar URL
        email_hash = hashlib.md5(self.email.lower().encode()).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}?d=identicon&s=200"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary for Firestore storage"""
        return {
            'user_id': self.user_id,
            'email': self.email,
            'display_name': self.display_name,
            'role': self.role,
            'permissions': self.permissions,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'preferences': self.preferences,
            'is_active': self.is_active,
            'profile_image_url': self.profile_image_url
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user from dictionary"""
        user = cls(
            user_id=data['user_id'],
            email=data['email'],
            display_name=data['display_name'],
            role=data['role'],
            permissions=data.get('permissions', []),
            preferences=data.get('preferences', {}),
            is_active=data.get('is_active', True),
            profile_image_url=data.get('profile_image_url'),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None
        )
        
        if data.get('last_login'):
            user.last_login = datetime.fromisoformat(data['last_login'])
        
        return user
    
    @classmethod
    def create_new(cls, email: str, display_name: str, role: str = "user") -> 'User':
        """Create a new user"""
        import uuid
        user_id = str(uuid.uuid4())
        
        # Set default permissions based on role
        permissions = []
        if role == "admin":
            permissions = ["read", "write", "delete", "manage_users", "manage_devices"]
        elif role == "operator":
            permissions = ["read", "write", "manage_devices"]
        else:
            permissions = ["read"]
        
        return cls(
            user_id=user_id,
            email=email,
            display_name=display_name,
            role=role,
            permissions=permissions
        )
    
    def validate(self) -> bool:
        """Validate user data"""
        if not self.user_id or not isinstance(self.user_id, str):
            return False
        if not self.email or not isinstance(self.email, str) or "@" not in self.email:
            return False
        if not self.display_name or not isinstance(self.display_name, str):
            return False
        if not self.role or not isinstance(self.role, str):
            return False
        if self.role not in ["admin", "operator", "user"]:
            return False
        return True
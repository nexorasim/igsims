import firebase_admin
from firebase_admin import credentials, auth
from typing import Optional, Dict, Any
import jwt
import logging
from datetime import datetime, timedelta
from functools import wraps

logger = logging.getLogger(__name__)

class FirebaseAuth:
    def __init__(self):
        if not firebase_admin._apps:
            cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
    
    async def create_user(self, email: str, password: str, display_name: str = None) -> str:
        try:
            user = auth.create_user(
                email=email,
                password=password,
                display_name=display_name
            )
            return user.uid
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise
    
    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            decoded_token = auth.verify_id_token(token)
            return decoded_token
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            return None
    
    async def get_user(self, uid: str) -> Optional[Dict[str, Any]]:
        try:
            user = auth.get_user(uid)
            return {
                'uid': user.uid,
                'email': user.email,
                'display_name': user.display_name,
                'email_verified': user.email_verified
            }
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None
    
    async def delete_user(self, uid: str) -> bool:
        try:
            auth.delete_user(uid)
            return True
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return False

class RoleManager:
    ROLES = {
        'admin': ['read', 'write', 'delete', 'manage_users'],
        'user': ['read', 'write'],
        'viewer': ['read']
    }
    
    def __init__(self):
        self.auth = FirebaseAuth()
    
    async def assign_role(self, uid: str, role: str) -> bool:
        try:
            auth.set_custom_user_claims(uid, {'role': role})
            return True
        except Exception as e:
            logger.error(f"Error assigning role: {e}")
            return False
    
    async def check_permission(self, uid: str, permission: str) -> bool:
        try:
            user = auth.get_user(uid)
            role = user.custom_claims.get('role', 'viewer') if user.custom_claims else 'viewer'
            return permission in self.ROLES.get(role, [])
        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False

def require_auth(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        token = kwargs.get('token')
        if not token:
            raise ValueError("Authentication token required")
        
        auth_service = FirebaseAuth()
        user = await auth_service.verify_token(token)
        if not user:
            raise ValueError("Invalid authentication token")
        
        kwargs['user'] = user
        return await f(*args, **kwargs)
    return decorated_function

def require_role(role: str):
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            user = kwargs.get('user')
            if not user:
                raise ValueError("User context required")
            
            role_manager = RoleManager()
            has_role = await role_manager.check_permission(user['uid'], 'manage_users' if role == 'admin' else 'read')
            if not has_role:
                raise ValueError(f"Insufficient permissions")
            
            return await f(*args, **kwargs)
        return decorated_function
    return decorator
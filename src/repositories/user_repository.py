"""
User repository for Firestore operations
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.user import User
from .base_repository import BaseRepository

class UserRepository(BaseRepository[User]):
    """Repository for User entities"""
    
    def __init__(self):
        super().__init__("users", User)
    
    def _to_dict(self, entity: User) -> Dict[str, Any]:
        """Convert User to dictionary"""
        return entity.to_dict()
    
    def _from_dict(self, data: Dict[str, Any]) -> User:
        """Convert dictionary to User"""
        return User.from_dict(data)
    
    def _get_id(self, entity: User) -> str:
        """Get User ID"""
        return entity.user_id
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address"""
        users = await self.query("email", "==", email, limit=1)
        return users[0] if users else None
    
    async def get_by_role(self, role: str, limit: Optional[int] = None) -> List[User]:
        """Get users by role"""
        return await self.query("role", "==", role, limit)
    
    async def get_active_users(self, limit: Optional[int] = None) -> List[User]:
        """Get all active users"""
        return await self.query("is_active", "==", True, limit)
    
    async def get_inactive_users(self, limit: Optional[int] = None) -> List[User]:
        """Get all inactive users"""
        return await self.query("is_active", "==", False, limit)
    
    async def get_admins(self, limit: Optional[int] = None) -> List[User]:
        """Get all admin users"""
        return await self.get_by_role("admin", limit)
    
    async def get_operators(self, limit: Optional[int] = None) -> List[User]:
        """Get all operator users"""
        return await self.get_by_role("operator", limit)
    
    async def update_last_login(self, user_id: str) -> bool:
        """Update user's last login timestamp"""
        try:
            def update_login(user: User) -> User:
                user.update_last_login()
                return user
            
            result = await self.transaction_update(user_id, update_login)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to update last login for user {user_id}: {e}")
            return False
    
    async def add_permission(self, user_id: str, permission: str) -> bool:
        """Add permission to user"""
        try:
            def add_perm(user: User) -> User:
                user.add_permission(permission)
                return user
            
            result = await self.transaction_update(user_id, add_perm)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to add permission {permission} to user {user_id}: {e}")
            return False
    
    async def remove_permission(self, user_id: str, permission: str) -> bool:
        """Remove permission from user"""
        try:
            def remove_perm(user: User) -> User:
                user.remove_permission(permission)
                return user
            
            result = await self.transaction_update(user_id, remove_perm)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to remove permission {permission} from user {user_id}: {e}")
            return False
    
    async def set_user_preference(self, user_id: str, key: str, value: Any) -> bool:
        """Set user preference"""
        try:
            def set_pref(user: User) -> User:
                user.set_preference(key, value)
                return user
            
            result = await self.transaction_update(user_id, set_pref)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to set preference {key} for user {user_id}: {e}")
            return False
    
    async def activate_user(self, user_id: str) -> bool:
        """Activate a user account"""
        try:
            def activate(user: User) -> User:
                user.is_active = True
                return user
            
            result = await self.transaction_update(user_id, activate)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to activate user {user_id}: {e}")
            return False
    
    async def deactivate_user(self, user_id: str) -> bool:
        """Deactivate a user account"""
        try:
            def deactivate(user: User) -> User:
                user.is_active = False
                return user
            
            result = await self.transaction_update(user_id, deactivate)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate user {user_id}: {e}")
            return False
    
    async def change_user_role(self, user_id: str, new_role: str) -> bool:
        """Change user role and update permissions accordingly"""
        try:
            def change_role(user: User) -> User:
                user.role = new_role
                
                # Update permissions based on new role
                if new_role == "admin":
                    user.permissions = ["read", "write", "delete", "manage_users", "manage_devices"]
                elif new_role == "operator":
                    user.permissions = ["read", "write", "manage_devices"]
                else:
                    user.permissions = ["read"]
                
                return user
            
            result = await self.transaction_update(user_id, change_role)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to change role for user {user_id}: {e}")
            return False
    
    async def search_users(self, search_term: str, limit: Optional[int] = None) -> List[User]:
        """Search users by email or display name containing search term"""
        # Note: Firestore doesn't support full-text search natively
        all_users = await self.list_all()
        
        matching_users = []
        search_lower = search_term.lower()
        
        for user in all_users:
            if (search_lower in user.email.lower() or 
                search_lower in user.display_name.lower()):
                matching_users.append(user)
                
                if limit and len(matching_users) >= limit:
                    break
        
        return matching_users
    
    async def get_user_statistics(self) -> Dict[str, Any]:
        """Get user statistics"""
        try:
            all_users = await self.list_all()
            
            stats = {
                "total_users": len(all_users),
                "active_users": 0,
                "inactive_users": 0,
                "by_role": {
                    "admin": 0,
                    "operator": 0,
                    "user": 0
                },
                "recent_logins": 0,  # Users who logged in within last 7 days
                "never_logged_in": 0
            }
            
            recent_threshold = datetime.utcnow().timestamp() - (7 * 24 * 60 * 60)  # 7 days ago
            
            for user in all_users:
                # Active/inactive count
                if user.is_active:
                    stats["active_users"] += 1
                else:
                    stats["inactive_users"] += 1
                
                # Role count
                if user.role in stats["by_role"]:
                    stats["by_role"][user.role] += 1
                
                # Login statistics
                if user.last_login:
                    if user.last_login.timestamp() > recent_threshold:
                        stats["recent_logins"] += 1
                else:
                    stats["never_logged_in"] += 1
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get user statistics: {e}")
            return {
                "total_users": 0,
                "active_users": 0,
                "inactive_users": 0,
                "by_role": {"admin": 0, "operator": 0, "user": 0},
                "recent_logins": 0,
                "never_logged_in": 0
            }
    
    async def get_users_with_permission(self, permission: str, limit: Optional[int] = None) -> List[User]:
        """Get users who have a specific permission"""
        all_users = await self.list_all()
        
        matching_users = []
        for user in all_users:
            if user.has_permission(permission):
                matching_users.append(user)
                
                if limit and len(matching_users) >= limit:
                    break
        
        return matching_users
    
    async def cleanup_inactive_users(self, days_inactive: int = 365) -> int:
        """Remove users who have been inactive for specified days and never logged in"""
        try:
            threshold_time = datetime.utcnow().timestamp() - (days_inactive * 24 * 60 * 60)
            
            all_users = await self.list_all()
            deleted_count = 0
            
            for user in all_users:
                # Only delete users who never logged in and were created long ago
                if (user.last_login is None and 
                    user.created_at and 
                    user.created_at.timestamp() < threshold_time and
                    not user.is_active):
                    
                    if await self.delete(user.user_id):
                        deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} inactive users")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup inactive users: {e}")
            return 0
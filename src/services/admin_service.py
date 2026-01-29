"""
Admin User Management Service for iGSIM AI Agent Platform

This service provides administrative functions for user management,
role assignment, and system administration tasks.

Requirements: 8.4 (Role-based access control)
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

from google.cloud import firestore

# Import our models and services
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.user import User
from models.rbac import Permission, Role, RoleDefinition, get_role_hierarchy
from repositories.user_repository import UserRepository
from services.role_service import get_role_service, RoleService
from services.auth_service import get_auth_service, AuthService
from config.settings import get_settings

logger = logging.getLogger(__name__)

@dataclass
class UserStats:
    """User statistics"""
    total_users: int
    active_users: int
    inactive_users: int
    users_by_role: Dict[str, int]
    recent_registrations: int  # Last 30 days
    recent_logins: int  # Last 7 days

@dataclass
class SystemStats:
    """System statistics"""
    user_stats: UserStats
    permission_grants: int
    resource_permissions: int
    custom_roles: int
    system_health: str

class AdminService:
    """Service for administrative user management functions"""
    
    def __init__(self):
        self.settings = get_settings()
        self.db = firestore.Client()
        self.user_repository = UserRepository()
        self.role_service = get_role_service()
        self.auth_service = get_auth_service()
        self.role_hierarchy = get_role_hierarchy()
        
        logger.info("AdminService initialized")
    
    # User Management
    
    async def get_all_users(self, admin_user_id: str, page: int = 1, 
                           page_size: int = 50, role_filter: Optional[str] = None,
                           active_filter: Optional[bool] = None) -> Dict[str, Any]:
        """
        Get all users with pagination and filtering
        
        Args:
            admin_user_id: ID of admin user making request
            page: Page number (1-based)
            page_size: Number of users per page
            role_filter: Optional role filter
            active_filter: Optional active status filter
            
        Returns:
            Dictionary with users and pagination info
            
        Raises:
            PermissionError: If user lacks admin permissions
        """
        try:
            # Verify admin permissions
            await self._verify_admin_permission(admin_user_id, Permission.READ_USERS)
            
            # Get users with filters
            users = await self.user_repository.get_all_users()
            
            # Apply filters
            if role_filter:
                users = [u for u in users if u.role == role_filter]
            
            if active_filter is not None:
                users = [u for u in users if u.is_active == active_filter]
            
            # Sort by creation date (newest first)
            users.sort(key=lambda u: u.created_at or datetime.min, reverse=True)
            
            # Pagination
            total_count = len(users)
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            paginated_users = users[start_idx:end_idx]
            
            # Convert to dict format
            user_dicts = []
            for user in paginated_users:
                user_dict = user.to_dict()
                # Add effective permissions
                permissions = await self.role_service.get_user_permissions(user.user_id)
                user_dict['effective_permissions'] = permissions.get('all_permissions', [])
                user_dicts.append(user_dict)
            
            return {
                'users': user_dicts,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_count': total_count,
                    'total_pages': (total_count + page_size - 1) // page_size,
                    'has_next': end_idx < total_count,
                    'has_prev': page > 1
                },
                'filters': {
                    'role': role_filter,
                    'active': active_filter
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get all users: {e}")
            raise
    
    async def get_user_details(self, admin_user_id: str, target_user_id: str) -> Dict[str, Any]:
        """
        Get detailed user information
        
        Args:
            admin_user_id: ID of admin user making request
            target_user_id: ID of user to get details for
            
        Returns:
            Detailed user information
            
        Raises:
            PermissionError: If user lacks admin permissions
            ValueError: If target user not found
        """
        try:
            # Verify admin permissions
            await self._verify_admin_permission(admin_user_id, Permission.READ_USERS)
            
            # Get target user
            user = await self.user_repository.get(target_user_id)
            if not user:
                raise ValueError(f"User '{target_user_id}' not found")
            
            # Get user permissions
            permissions = await self.role_service.get_user_permissions(target_user_id)
            
            # Get resource permissions
            resource_permissions = await self.role_service.get_user_resource_permissions(target_user_id)
            
            # Get role definition
            role_def = self.role_hierarchy.get_role(user.role)
            
            user_details = user.to_dict()
            user_details.update({
                'permissions': permissions,
                'resource_permissions': [rp.to_dict() for rp in resource_permissions],
                'role_definition': role_def.to_dict() if role_def else None,
                'login_history': await self._get_user_login_history(target_user_id)
            })
            
            return user_details
            
        except Exception as e:
            logger.error(f"Failed to get user details: {e}")
            raise
    
    async def create_user(self, admin_user_id: str, user_data: Dict[str, Any]) -> User:
        """
        Create a new user (admin function)
        
        Args:
            admin_user_id: ID of admin user creating the user
            user_data: User creation data
            
        Returns:
            Created user
            
        Raises:
            PermissionError: If user lacks admin permissions
            ValueError: If user data is invalid
        """
        try:
            # Verify admin permissions
            await self._verify_admin_permission(admin_user_id, Permission.CREATE_USERS)
            
            # Validate user data
            required_fields = ['email', 'display_name']
            for field in required_fields:
                if not user_data.get(field):
                    raise ValueError(f"Field '{field}' is required")
            
            # Check if user already exists
            existing_user = await self.user_repository.get_by_email(user_data['email'])
            if existing_user:
                raise ValueError(f"User with email '{user_data['email']}' already exists")
            
            # Create user
            user = User.create_new(
                email=user_data['email'],
                display_name=user_data['display_name'],
                role=user_data.get('role', 'user')
            )
            
            # Set additional properties
            if 'is_active' in user_data:
                user.is_active = user_data['is_active']
            
            if 'preferences' in user_data:
                user.preferences = user_data['preferences']
            
            # Save user
            await self.user_repository.create(user)
            
            logger.info(f"User created by admin: {user.email} by {admin_user_id}")
            return user
            
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise
    
    async def update_user(self, admin_user_id: str, target_user_id: str, 
                         updates: Dict[str, Any]) -> User:
        """
        Update user information (admin function)
        
        Args:
            admin_user_id: ID of admin user making update
            target_user_id: ID of user to update
            updates: Updates to apply
            
        Returns:
            Updated user
            
        Raises:
            PermissionError: If user lacks admin permissions
            ValueError: If target user not found
        """
        try:
            # Verify admin permissions
            await self._verify_admin_permission(admin_user_id, Permission.UPDATE_USERS)
            
            # Get target user
            user = await self.user_repository.get(target_user_id)
            if not user:
                raise ValueError(f"User '{target_user_id}' not found")
            
            # Apply updates
            if 'display_name' in updates:
                user.display_name = updates['display_name']
            
            if 'is_active' in updates:
                user.is_active = updates['is_active']
            
            if 'preferences' in updates:
                user.preferences.update(updates['preferences'])
            
            if 'profile_image_url' in updates:
                user.profile_image_url = updates['profile_image_url']
            
            # Role changes require special permission
            if 'role' in updates:
                await self._verify_admin_permission(admin_user_id, Permission.MANAGE_USER_ROLES)
                await self.role_service.assign_role_to_user(
                    target_user_id, 
                    updates['role'], 
                    admin_user_id
                )
            
            # Save user
            await self.user_repository.update(user)
            
            logger.info(f"User updated by admin: {user.email} by {admin_user_id}")
            return user
            
        except Exception as e:
            logger.error(f"Failed to update user: {e}")
            raise
    
    async def delete_user(self, admin_user_id: str, target_user_id: str) -> bool:
        """
        Delete user (admin function)
        
        Args:
            admin_user_id: ID of admin user making deletion
            target_user_id: ID of user to delete
            
        Returns:
            True if deleted successfully
            
        Raises:
            PermissionError: If user lacks admin permissions
            ValueError: If target user not found or cannot be deleted
        """
        try:
            # Verify admin permissions
            await self._verify_admin_permission(admin_user_id, Permission.DELETE_USERS)
            
            # Cannot delete self
            if admin_user_id == target_user_id:
                raise ValueError("Cannot delete your own account")
            
            # Get target user
            user = await self.user_repository.get(target_user_id)
            if not user:
                raise ValueError(f"User '{target_user_id}' not found")
            
            # Cannot delete other admins unless super admin
            admin_user = await self.user_repository.get(admin_user_id)
            if (user.role in ['admin', 'super_admin'] and 
                admin_user.role != 'super_admin'):
                raise ValueError("Only super admin can delete admin users")
            
            # Soft delete (deactivate) instead of hard delete
            user.is_active = False
            await self.user_repository.update(user)
            
            # Clean up user's permissions and grants
            await self._cleanup_user_permissions(target_user_id)
            
            logger.info(f"User deleted by admin: {user.email} by {admin_user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete user: {e}")
            raise
    
    async def activate_user(self, admin_user_id: str, target_user_id: str) -> bool:
        """
        Activate deactivated user
        
        Args:
            admin_user_id: ID of admin user
            target_user_id: ID of user to activate
            
        Returns:
            True if activated successfully
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.UPDATE_USERS)
            
            user = await self.user_repository.get(target_user_id)
            if not user:
                raise ValueError(f"User '{target_user_id}' not found")
            
            user.is_active = True
            await self.user_repository.update(user)
            
            logger.info(f"User activated by admin: {user.email} by {admin_user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to activate user: {e}")
            raise
    
    async def deactivate_user(self, admin_user_id: str, target_user_id: str) -> bool:
        """
        Deactivate user
        
        Args:
            admin_user_id: ID of admin user
            target_user_id: ID of user to deactivate
            
        Returns:
            True if deactivated successfully
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.UPDATE_USERS)
            
            # Cannot deactivate self
            if admin_user_id == target_user_id:
                raise ValueError("Cannot deactivate your own account")
            
            user = await self.user_repository.get(target_user_id)
            if not user:
                raise ValueError(f"User '{target_user_id}' not found")
            
            user.is_active = False
            await self.user_repository.update(user)
            
            logger.info(f"User deactivated by admin: {user.email} by {admin_user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deactivate user: {e}")
            raise
    
    # Role Management
    
    async def assign_role(self, admin_user_id: str, target_user_id: str, role: str) -> bool:
        """
        Assign role to user
        
        Args:
            admin_user_id: ID of admin user
            target_user_id: ID of user to assign role to
            role: Role to assign
            
        Returns:
            True if assigned successfully
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.MANAGE_USER_ROLES)
            
            return await self.role_service.assign_role_to_user(
                target_user_id, 
                role, 
                admin_user_id
            )
            
        except Exception as e:
            logger.error(f"Failed to assign role: {e}")
            raise
    
    async def remove_role(self, admin_user_id: str, target_user_id: str) -> bool:
        """
        Remove role from user (assign default user role)
        
        Args:
            admin_user_id: ID of admin user
            target_user_id: ID of user to remove role from
            
        Returns:
            True if removed successfully
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.MANAGE_USER_ROLES)
            
            return await self.role_service.remove_role_from_user(
                target_user_id, 
                admin_user_id
            )
            
        except Exception as e:
            logger.error(f"Failed to remove role: {e}")
            raise
    
    async def grant_permission(self, admin_user_id: str, target_user_id: str, 
                              permission: Permission, expires_at: Optional[datetime] = None,
                              reason: Optional[str] = None) -> bool:
        """
        Grant specific permission to user
        
        Args:
            admin_user_id: ID of admin user
            target_user_id: ID of user to grant permission to
            permission: Permission to grant
            expires_at: Optional expiration time
            reason: Optional reason for granting
            
        Returns:
            True if granted successfully
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.MANAGE_PERMISSIONS)
            
            await self.role_service.grant_permission_to_user(
                target_user_id,
                permission,
                admin_user_id,
                expires_at,
                reason
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to grant permission: {e}")
            raise
    
    async def revoke_permission(self, admin_user_id: str, target_user_id: str, 
                               permission: Permission) -> bool:
        """
        Revoke specific permission from user
        
        Args:
            admin_user_id: ID of admin user
            target_user_id: ID of user to revoke permission from
            permission: Permission to revoke
            
        Returns:
            True if revoked successfully
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.MANAGE_PERMISSIONS)
            
            return await self.role_service.revoke_permission_from_user(
                target_user_id,
                permission,
                admin_user_id
            )
            
        except Exception as e:
            logger.error(f"Failed to revoke permission: {e}")
            raise
    
    # System Statistics and Monitoring
    
    async def get_system_stats(self, admin_user_id: str) -> SystemStats:
        """
        Get system statistics
        
        Args:
            admin_user_id: ID of admin user
            
        Returns:
            System statistics
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.VIEW_SYSTEM_LOGS)
            
            # Get user statistics
            user_stats = await self._get_user_stats()
            
            # Get permission statistics
            permission_grants = await self._count_permission_grants()
            resource_permissions = await self._count_resource_permissions()
            
            # Get role statistics
            all_roles = self.role_hierarchy.get_all_roles()
            custom_roles = sum(1 for role in all_roles.values() if not role.is_system_role)
            
            # System health check
            system_health = await self._check_system_health()
            
            return SystemStats(
                user_stats=user_stats,
                permission_grants=permission_grants,
                resource_permissions=resource_permissions,
                custom_roles=custom_roles,
                system_health=system_health
            )
            
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            raise
    
    async def get_user_activity_log(self, admin_user_id: str, target_user_id: str,
                                   days: int = 30) -> List[Dict[str, Any]]:
        """
        Get user activity log
        
        Args:
            admin_user_id: ID of admin user
            target_user_id: ID of user to get activity for
            days: Number of days to look back
            
        Returns:
            List of activity records
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.VIEW_SYSTEM_LOGS)
            
            # This would typically query an audit log collection
            # For now, return basic login history
            return await self._get_user_login_history(target_user_id, days)
            
        except Exception as e:
            logger.error(f"Failed to get user activity log: {e}")
            raise
    
    async def cleanup_expired_permissions(self, admin_user_id: str) -> int:
        """
        Clean up expired permissions
        
        Args:
            admin_user_id: ID of admin user
            
        Returns:
            Number of permissions cleaned up
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.MANAGE_PERMISSIONS)
            
            count = await self.role_service.cleanup_expired_permissions()
            
            logger.info(f"Cleaned up {count} expired permissions by admin {admin_user_id}")
            return count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired permissions: {e}")
            raise
    
    # Bulk Operations
    
    async def bulk_assign_role(self, admin_user_id: str, user_ids: List[str], 
                              role: str) -> Dict[str, Any]:
        """
        Assign role to multiple users
        
        Args:
            admin_user_id: ID of admin user
            user_ids: List of user IDs
            role: Role to assign
            
        Returns:
            Results of bulk operation
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.MANAGE_USER_ROLES)
            
            results = {
                'successful': [],
                'failed': [],
                'total': len(user_ids)
            }
            
            for user_id in user_ids:
                try:
                    await self.role_service.assign_role_to_user(user_id, role, admin_user_id)
                    results['successful'].append(user_id)
                except Exception as e:
                    results['failed'].append({'user_id': user_id, 'error': str(e)})
            
            logger.info(f"Bulk role assignment: {len(results['successful'])}/{len(user_ids)} successful by {admin_user_id}")
            return results
            
        except Exception as e:
            logger.error(f"Failed bulk role assignment: {e}")
            raise
    
    async def bulk_deactivate_users(self, admin_user_id: str, user_ids: List[str]) -> Dict[str, Any]:
        """
        Deactivate multiple users
        
        Args:
            admin_user_id: ID of admin user
            user_ids: List of user IDs to deactivate
            
        Returns:
            Results of bulk operation
        """
        try:
            await self._verify_admin_permission(admin_user_id, Permission.UPDATE_USERS)
            
            results = {
                'successful': [],
                'failed': [],
                'total': len(user_ids)
            }
            
            for user_id in user_ids:
                try:
                    # Skip self
                    if user_id == admin_user_id:
                        results['failed'].append({'user_id': user_id, 'error': 'Cannot deactivate self'})
                        continue
                    
                    await self.deactivate_user(admin_user_id, user_id)
                    results['successful'].append(user_id)
                except Exception as e:
                    results['failed'].append({'user_id': user_id, 'error': str(e)})
            
            logger.info(f"Bulk user deactivation: {len(results['successful'])}/{len(user_ids)} successful by {admin_user_id}")
            return results
            
        except Exception as e:
            logger.error(f"Failed bulk user deactivation: {e}")
            raise
    
    # Private helper methods
    
    async def _verify_admin_permission(self, user_id: str, permission: Permission) -> None:
        """Verify user has admin permission"""
        user = await self.user_repository.get(user_id)
        if not user or not user.is_active:
            raise PermissionError("User not found or inactive")
        
        has_permission = await self.role_service.check_user_permission(user_id, permission)
        if not has_permission:
            raise PermissionError(f"Permission denied: {permission.value} required")
    
    async def _get_user_stats(self) -> UserStats:
        """Get user statistics"""
        users = await self.user_repository.get_all_users()
        
        total_users = len(users)
        active_users = sum(1 for u in users if u.is_active)
        inactive_users = total_users - active_users
        
        # Count users by role
        users_by_role = {}
        for user in users:
            role = user.role
            users_by_role[role] = users_by_role.get(role, 0) + 1
        
        # Recent registrations (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_registrations = sum(
            1 for u in users 
            if u.created_at and u.created_at > thirty_days_ago
        )
        
        # Recent logins (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_logins = sum(
            1 for u in users 
            if u.last_login and u.last_login > seven_days_ago
        )
        
        return UserStats(
            total_users=total_users,
            active_users=active_users,
            inactive_users=inactive_users,
            users_by_role=users_by_role,
            recent_registrations=recent_registrations,
            recent_logins=recent_logins
        )
    
    async def _count_permission_grants(self) -> int:
        """Count permission grants"""
        try:
            collection = self.db.collection("permission_grants")
            docs = collection.stream()
            return len(list(docs))
        except Exception:
            return 0
    
    async def _count_resource_permissions(self) -> int:
        """Count resource permissions"""
        try:
            collection = self.db.collection("resource_permissions")
            docs = collection.stream()
            return len(list(docs))
        except Exception:
            return 0
    
    async def _check_system_health(self) -> str:
        """Check system health"""
        try:
            # Basic health checks
            # Check database connectivity
            self.db.collection("users").limit(1).get()
            
            # Check role hierarchy
            errors = self.role_hierarchy.validate_role_hierarchy()
            if errors:
                return "Warning: Role hierarchy issues detected"
            
            return "Healthy"
            
        except Exception as e:
            logger.error(f"System health check failed: {e}")
            return "Unhealthy"
    
    async def _get_user_login_history(self, user_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get user login history"""
        # This is a placeholder - in a real implementation, you would
        # query an audit log or activity tracking system
        user = await self.user_repository.get(user_id)
        if not user or not user.last_login:
            return []
        
        return [{
            'event_type': 'login',
            'timestamp': user.last_login.isoformat(),
            'details': 'User login'
        }]
    
    async def _cleanup_user_permissions(self, user_id: str) -> None:
        """Clean up user's permissions and grants"""
        try:
            # Remove permission grants
            grants_collection = self.db.collection("permission_grants")
            grants_query = grants_collection.where('user_id', '==', user_id)
            grants_docs = grants_query.stream()
            
            for doc in grants_docs:
                doc.reference.delete()
            
            # Remove resource permissions
            resource_collection = self.db.collection("resource_permissions")
            resource_query = resource_collection.where('user_id', '==', user_id)
            resource_docs = resource_query.stream()
            
            for doc in resource_docs:
                doc.reference.delete()
            
            logger.info(f"Cleaned up permissions for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to cleanup user permissions: {e}")

# Global admin service instance
_admin_service: Optional[AdminService] = None

def get_admin_service() -> AdminService:
    """Get global admin service instance"""
    global _admin_service
    if _admin_service is None:
        _admin_service = AdminService()
    return _admin_service
"""
Role Management Service for iGSIM AI Agent Platform

This service handles role-based access control operations including
role management, permission assignment, and access control validation.

Requirements: 8.4 (Role-based access control)
"""

import logging
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta

from google.cloud import firestore

# Import our models and utilities
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.rbac import (
    Role, Permission, RoleDefinition, PermissionGrant, ResourcePermission,
    get_role_hierarchy, RoleHierarchy, check_permission
)
from models.user import User
from repositories.user_repository import UserRepository
from config.settings import get_settings

logger = logging.getLogger(__name__)

class RoleService:
    """Service for managing roles and permissions"""
    
    def __init__(self):
        self.settings = get_settings()
        self.db = firestore.Client()
        self.user_repository = UserRepository()
        self.role_hierarchy = get_role_hierarchy()
        
        # Collections
        self.roles_collection = "roles"
        self.permission_grants_collection = "permission_grants"
        self.resource_permissions_collection = "resource_permissions"
        
        logger.info("RoleService initialized")
    
    # Role Management
    
    async def create_role(self, role_data: Dict[str, Any], created_by: str) -> RoleDefinition:
        """
        Create a new custom role
        
        Args:
            role_data: Role definition data
            created_by: User ID who created the role
            
        Returns:
            Created role definition
            
        Raises:
            ValueError: If role data is invalid
            PermissionError: If user lacks permission
        """
        try:
            # Validate creator permissions
            creator = await self.user_repository.get(created_by)
            if not creator or not check_permission(creator.role, Permission.MANAGE_PERMISSIONS):
                raise PermissionError("Insufficient permissions to create roles")
            
            # Validate role data
            if not role_data.get('name') or not role_data.get('display_name'):
                raise ValueError("Role name and display name are required")
            
            # Check if role already exists
            existing_role = self.role_hierarchy.get_role(role_data['name'])
            if existing_role:
                raise ValueError(f"Role '{role_data['name']}' already exists")
            
            # Create role definition
            permissions = {Permission(p) for p in role_data.get('permissions', [])}
            
            role = RoleDefinition(
                name=role_data['name'],
                display_name=role_data['display_name'],
                description=role_data.get('description', ''),
                permissions=permissions,
                inherits_from=role_data.get('inherits_from'),
                is_system_role=False  # Custom roles are not system roles
            )
            
            # Validate hierarchy
            self.role_hierarchy.add_role(role)
            errors = self.role_hierarchy.validate_role_hierarchy()
            if errors:
                raise ValueError(f"Role hierarchy validation failed: {', '.join(errors)}")
            
            # Save to database
            await self._save_role_to_db(role)
            
            logger.info(f"Role created: {role.name} by {created_by}")
            return role
            
        except Exception as e:
            logger.error(f"Failed to create role: {e}")
            raise
    
    async def update_role(self, role_name: str, updates: Dict[str, Any], updated_by: str) -> RoleDefinition:
        """
        Update an existing role
        
        Args:
            role_name: Name of role to update
            updates: Updates to apply
            updated_by: User ID who updated the role
            
        Returns:
            Updated role definition
            
        Raises:
            ValueError: If role not found or updates invalid
            PermissionError: If user lacks permission
        """
        try:
            # Validate updater permissions
            updater = await self.user_repository.get(updated_by)
            if not updater or not check_permission(updater.role, Permission.MANAGE_PERMISSIONS):
                raise PermissionError("Insufficient permissions to update roles")
            
            # Get existing role
            role = self.role_hierarchy.get_role(role_name)
            if not role:
                raise ValueError(f"Role '{role_name}' not found")
            
            # Cannot update system roles
            if role.is_system_role:
                raise ValueError("Cannot update system roles")
            
            # Apply updates
            if 'display_name' in updates:
                role.display_name = updates['display_name']
            
            if 'description' in updates:
                role.description = updates['description']
            
            if 'permissions' in updates:
                role.permissions = {Permission(p) for p in updates['permissions']}
            
            if 'inherits_from' in updates:
                role.inherits_from = updates['inherits_from']
            
            role.updated_at = datetime.utcnow()
            
            # Validate hierarchy
            errors = self.role_hierarchy.validate_role_hierarchy()
            if errors:
                raise ValueError(f"Role hierarchy validation failed: {', '.join(errors)}")
            
            # Save to database
            await self._save_role_to_db(role)
            
            logger.info(f"Role updated: {role_name} by {updated_by}")
            return role
            
        except Exception as e:
            logger.error(f"Failed to update role: {e}")
            raise
    
    async def delete_role(self, role_name: str, deleted_by: str) -> bool:
        """
        Delete a custom role
        
        Args:
            role_name: Name of role to delete
            deleted_by: User ID who deleted the role
            
        Returns:
            True if deleted successfully
            
        Raises:
            ValueError: If role not found or cannot be deleted
            PermissionError: If user lacks permission
        """
        try:
            # Validate deleter permissions
            deleter = await self.user_repository.get(deleted_by)
            if not deleter or not check_permission(deleter.role, Permission.MANAGE_PERMISSIONS):
                raise PermissionError("Insufficient permissions to delete roles")
            
            # Get role
            role = self.role_hierarchy.get_role(role_name)
            if not role:
                raise ValueError(f"Role '{role_name}' not found")
            
            # Cannot delete system roles
            if role.is_system_role:
                raise ValueError("Cannot delete system roles")
            
            # Check if role is in use
            users_with_role = await self.user_repository.get_users_by_role(role_name)
            if users_with_role:
                raise ValueError(f"Cannot delete role '{role_name}': {len(users_with_role)} users have this role")
            
            # Remove from hierarchy
            success = self.role_hierarchy.remove_role(role_name)
            if not success:
                raise ValueError(f"Failed to remove role from hierarchy")
            
            # Delete from database
            await self._delete_role_from_db(role_name)
            
            logger.info(f"Role deleted: {role_name} by {deleted_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete role: {e}")
            raise
    
    async def get_role(self, role_name: str) -> Optional[RoleDefinition]:
        """Get role definition by name"""
        return self.role_hierarchy.get_role(role_name)
    
    async def get_all_roles(self) -> Dict[str, RoleDefinition]:
        """Get all role definitions"""
        return self.role_hierarchy.get_all_roles()
    
    async def get_role_permissions(self, role_name: str) -> Set[Permission]:
        """Get effective permissions for a role"""
        return self.role_hierarchy.get_effective_permissions(role_name)
    
    # User Role Management
    
    async def assign_role_to_user(self, user_id: str, role_name: str, assigned_by: str) -> bool:
        """
        Assign role to user
        
        Args:
            user_id: User ID
            role_name: Role name to assign
            assigned_by: User ID who assigned the role
            
        Returns:
            True if assigned successfully
            
        Raises:
            ValueError: If user or role not found
            PermissionError: If assigner lacks permission
        """
        try:
            # Validate assigner permissions
            assigner = await self.user_repository.get(assigned_by)
            if not assigner or not check_permission(assigner.role, Permission.MANAGE_USER_ROLES):
                raise PermissionError("Insufficient permissions to assign roles")
            
            # Get user and role
            user = await self.user_repository.get(user_id)
            if not user:
                raise ValueError(f"User '{user_id}' not found")
            
            role = self.role_hierarchy.get_role(role_name)
            if not role:
                raise ValueError(f"Role '{role_name}' not found")
            
            # Update user role
            old_role = user.role
            user.role = role_name
            
            # Update user permissions based on new role
            user.permissions = list(self.role_hierarchy.get_effective_permissions(role_name))
            
            # Save user
            await self.user_repository.update(user)
            
            logger.info(f"Role assigned: {role_name} to user {user_id} (was {old_role}) by {assigned_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to assign role: {e}")
            raise
    
    async def remove_role_from_user(self, user_id: str, removed_by: str, new_role: str = "user") -> bool:
        """
        Remove role from user (assign default role)
        
        Args:
            user_id: User ID
            removed_by: User ID who removed the role
            new_role: New role to assign (default: "user")
            
        Returns:
            True if removed successfully
            
        Raises:
            ValueError: If user not found
            PermissionError: If remover lacks permission
        """
        try:
            # Validate remover permissions
            remover = await self.user_repository.get(removed_by)
            if not remover or not check_permission(remover.role, Permission.MANAGE_USER_ROLES):
                raise PermissionError("Insufficient permissions to remove roles")
            
            # Get user
            user = await self.user_repository.get(user_id)
            if not user:
                raise ValueError(f"User '{user_id}' not found")
            
            # Cannot remove role from self if it would result in loss of permission
            if (removed_by == user_id and 
                not check_permission(new_role, Permission.MANAGE_USER_ROLES)):
                raise PermissionError("Cannot remove your own role management permissions")
            
            # Assign new role
            return await self.assign_role_to_user(user_id, new_role, removed_by)
            
        except Exception as e:
            logger.error(f"Failed to remove role: {e}")
            raise
    
    # Permission Management
    
    async def grant_permission_to_user(self, user_id: str, permission: Permission, 
                                     granted_by: str, expires_at: Optional[datetime] = None,
                                     reason: Optional[str] = None) -> PermissionGrant:
        """
        Grant specific permission to user
        
        Args:
            user_id: User ID
            permission: Permission to grant
            granted_by: User ID who granted the permission
            expires_at: Optional expiration time
            reason: Optional reason for granting
            
        Returns:
            Permission grant record
            
        Raises:
            ValueError: If user not found
            PermissionError: If granter lacks permission
        """
        try:
            # Validate granter permissions
            granter = await self.user_repository.get(granted_by)
            if not granter or not check_permission(granter.role, Permission.MANAGE_PERMISSIONS):
                raise PermissionError("Insufficient permissions to grant permissions")
            
            # Get user
            user = await self.user_repository.get(user_id)
            if not user:
                raise ValueError(f"User '{user_id}' not found")
            
            # Create permission grant
            grant = PermissionGrant(
                user_id=user_id,
                permission=permission,
                granted_by=granted_by,
                granted_at=datetime.utcnow(),
                expires_at=expires_at,
                reason=reason
            )
            
            # Save to database
            await self._save_permission_grant_to_db(grant)
            
            # Add to user's permissions if not already present
            if permission.value not in user.permissions:
                user.permissions.append(permission.value)
                await self.user_repository.update(user)
            
            logger.info(f"Permission granted: {permission.value} to user {user_id} by {granted_by}")
            return grant
            
        except Exception as e:
            logger.error(f"Failed to grant permission: {e}")
            raise
    
    async def revoke_permission_from_user(self, user_id: str, permission: Permission, 
                                        revoked_by: str) -> bool:
        """
        Revoke specific permission from user
        
        Args:
            user_id: User ID
            permission: Permission to revoke
            revoked_by: User ID who revoked the permission
            
        Returns:
            True if revoked successfully
            
        Raises:
            ValueError: If user not found
            PermissionError: If revoker lacks permission
        """
        try:
            # Validate revoker permissions
            revoker = await self.user_repository.get(revoked_by)
            if not revoker or not check_permission(revoker.role, Permission.MANAGE_PERMISSIONS):
                raise PermissionError("Insufficient permissions to revoke permissions")
            
            # Get user
            user = await self.user_repository.get(user_id)
            if not user:
                raise ValueError(f"User '{user_id}' not found")
            
            # Check if permission comes from role
            role_permissions = self.role_hierarchy.get_effective_permissions(user.role)
            if permission in role_permissions:
                raise ValueError(f"Cannot revoke role-based permission. Change user role instead.")
            
            # Remove from user's permissions
            if permission.value in user.permissions:
                user.permissions.remove(permission.value)
                await self.user_repository.update(user)
            
            # Remove permission grants from database
            await self._delete_permission_grants_from_db(user_id, permission)
            
            logger.info(f"Permission revoked: {permission.value} from user {user_id} by {revoked_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke permission: {e}")
            raise
    
    async def get_user_permissions(self, user_id: str) -> Dict[str, Any]:
        """
        Get all permissions for a user
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with role permissions and additional grants
        """
        try:
            user = await self.user_repository.get(user_id)
            if not user:
                return {}
            
            # Get role-based permissions
            role_permissions = self.role_hierarchy.get_effective_permissions(user.role)
            
            # Get additional permission grants
            grants = await self._get_permission_grants_from_db(user_id)
            additional_permissions = set()
            
            for grant in grants:
                if not grant.is_expired():
                    additional_permissions.add(grant.permission)
            
            return {
                'user_id': user_id,
                'role': user.role,
                'role_permissions': [p.value for p in role_permissions],
                'additional_permissions': [p.value for p in additional_permissions],
                'all_permissions': [p.value for p in (role_permissions | additional_permissions)]
            }
            
        except Exception as e:
            logger.error(f"Failed to get user permissions: {e}")
            return {}
    
    # Resource Permissions
    
    async def grant_resource_permission(self, user_id: str, resource_type: str, 
                                      resource_id: str, permissions: Set[Permission],
                                      granted_by: str, expires_at: Optional[datetime] = None) -> ResourcePermission:
        """
        Grant resource-specific permissions to user
        
        Args:
            user_id: User ID
            resource_type: Type of resource
            resource_id: Resource ID
            permissions: Set of permissions to grant
            granted_by: User ID who granted the permissions
            expires_at: Optional expiration time
            
        Returns:
            Resource permission record
            
        Raises:
            ValueError: If user not found
            PermissionError: If granter lacks permission
        """
        try:
            # Validate granter permissions
            granter = await self.user_repository.get(granted_by)
            if not granter or not check_permission(granter.role, Permission.MANAGE_PERMISSIONS):
                raise PermissionError("Insufficient permissions to grant resource permissions")
            
            # Get user
            user = await self.user_repository.get(user_id)
            if not user:
                raise ValueError(f"User '{user_id}' not found")
            
            # Create resource permission
            resource_perm = ResourcePermission(
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=user_id,
                permissions=permissions,
                granted_by=granted_by,
                granted_at=datetime.utcnow(),
                expires_at=expires_at
            )
            
            # Save to database
            await self._save_resource_permission_to_db(resource_perm)
            
            logger.info(f"Resource permissions granted: {resource_type}:{resource_id} to user {user_id} by {granted_by}")
            return resource_perm
            
        except Exception as e:
            logger.error(f"Failed to grant resource permission: {e}")
            raise
    
    async def revoke_resource_permission(self, user_id: str, resource_type: str, 
                                       resource_id: str, revoked_by: str) -> bool:
        """
        Revoke resource-specific permissions from user
        
        Args:
            user_id: User ID
            resource_type: Type of resource
            resource_id: Resource ID
            revoked_by: User ID who revoked the permissions
            
        Returns:
            True if revoked successfully
            
        Raises:
            PermissionError: If revoker lacks permission
        """
        try:
            # Validate revoker permissions
            revoker = await self.user_repository.get(revoked_by)
            if not revoker or not check_permission(revoker.role, Permission.MANAGE_PERMISSIONS):
                raise PermissionError("Insufficient permissions to revoke resource permissions")
            
            # Delete from database
            await self._delete_resource_permission_from_db(user_id, resource_type, resource_id)
            
            logger.info(f"Resource permissions revoked: {resource_type}:{resource_id} from user {user_id} by {revoked_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke resource permission: {e}")
            raise
    
    async def get_user_resource_permissions(self, user_id: str) -> List[ResourcePermission]:
        """Get all resource permissions for a user"""
        try:
            return await self._get_resource_permissions_from_db(user_id)
        except Exception as e:
            logger.error(f"Failed to get user resource permissions: {e}")
            return []
    
    # Permission Checking
    
    async def check_user_permission(self, user_id: str, permission: Permission) -> bool:
        """
        Check if user has specific permission
        
        Args:
            user_id: User ID
            permission: Permission to check
            
        Returns:
            True if user has permission
        """
        try:
            user = await self.user_repository.get(user_id)
            if not user or not user.is_active:
                return False
            
            # Check role-based permissions
            if check_permission(user.role, permission):
                return True
            
            # Check additional permission grants
            grants = await self._get_permission_grants_from_db(user_id)
            for grant in grants:
                if grant.permission == permission and not grant.is_expired():
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to check user permission: {e}")
            return False
    
    async def check_user_resource_permission(self, user_id: str, resource_type: str,
                                           resource_id: str, permission: Permission) -> bool:
        """
        Check if user has permission for specific resource
        
        Args:
            user_id: User ID
            resource_type: Type of resource
            resource_id: Resource ID
            permission: Permission to check
            
        Returns:
            True if user has permission for resource
        """
        try:
            user = await self.user_repository.get(user_id)
            if not user or not user.is_active:
                return False
            
            # Check role-based permissions first
            if check_permission(user.role, permission):
                return True
            
            # Check resource-specific permissions
            resource_perms = await self._get_resource_permissions_from_db(user_id)
            for res_perm in resource_perms:
                if (res_perm.resource_type == resource_type and
                    res_perm.resource_id == resource_id and
                    not res_perm.is_expired() and
                    res_perm.has_permission(permission)):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to check user resource permission: {e}")
            return False
    
    # Database operations
    
    async def _save_role_to_db(self, role: RoleDefinition) -> None:
        """Save role definition to database"""
        doc_ref = self.db.collection(self.roles_collection).document(role.name)
        await doc_ref.set(role.to_dict())
    
    async def _delete_role_from_db(self, role_name: str) -> None:
        """Delete role definition from database"""
        doc_ref = self.db.collection(self.roles_collection).document(role_name)
        await doc_ref.delete()
    
    async def _save_permission_grant_to_db(self, grant: PermissionGrant) -> None:
        """Save permission grant to database"""
        doc_id = f"{grant.user_id}_{grant.permission.value}_{int(grant.granted_at.timestamp())}"
        doc_ref = self.db.collection(self.permission_grants_collection).document(doc_id)
        await doc_ref.set(grant.to_dict())
    
    async def _get_permission_grants_from_db(self, user_id: str) -> List[PermissionGrant]:
        """Get permission grants for user from database"""
        query = self.db.collection(self.permission_grants_collection).where('user_id', '==', user_id)
        docs = query.stream()
        
        grants = []
        for doc in docs:
            try:
                grants.append(PermissionGrant.from_dict(doc.to_dict()))
            except Exception as e:
                logger.warning(f"Failed to parse permission grant {doc.id}: {e}")
        
        return grants
    
    async def _delete_permission_grants_from_db(self, user_id: str, permission: Permission) -> None:
        """Delete permission grants from database"""
        query = self.db.collection(self.permission_grants_collection).where('user_id', '==', user_id).where('permission', '==', permission.value)
        docs = query.stream()
        
        for doc in docs:
            doc.reference.delete()
    
    async def _save_resource_permission_to_db(self, resource_perm: ResourcePermission) -> None:
        """Save resource permission to database"""
        doc_id = f"{resource_perm.user_id}_{resource_perm.resource_type}_{resource_perm.resource_id}"
        doc_ref = self.db.collection(self.resource_permissions_collection).document(doc_id)
        await doc_ref.set(resource_perm.to_dict())
    
    async def _get_resource_permissions_from_db(self, user_id: str) -> List[ResourcePermission]:
        """Get resource permissions for user from database"""
        query = self.db.collection(self.resource_permissions_collection).where('user_id', '==', user_id)
        docs = query.stream()
        
        permissions = []
        for doc in docs:
            try:
                permissions.append(ResourcePermission.from_dict(doc.to_dict()))
            except Exception as e:
                logger.warning(f"Failed to parse resource permission {doc.id}: {e}")
        
        return permissions
    
    async def _delete_resource_permission_from_db(self, user_id: str, resource_type: str, resource_id: str) -> None:
        """Delete resource permission from database"""
        doc_id = f"{user_id}_{resource_type}_{resource_id}"
        doc_ref = self.db.collection(self.resource_permissions_collection).document(doc_id)
        await doc_ref.delete()
    
    # Cleanup operations
    
    async def cleanup_expired_permissions(self) -> int:
        """Clean up expired permission grants and resource permissions"""
        try:
            current_time = datetime.utcnow()
            cleaned_count = 0
            
            # Clean up expired permission grants
            grants_query = self.db.collection(self.permission_grants_collection)
            grants_docs = grants_query.stream()
            
            for doc in grants_docs:
                try:
                    grant = PermissionGrant.from_dict(doc.to_dict())
                    if grant.is_expired():
                        doc.reference.delete()
                        cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Failed to process permission grant {doc.id}: {e}")
            
            # Clean up expired resource permissions
            resource_query = self.db.collection(self.resource_permissions_collection)
            resource_docs = resource_query.stream()
            
            for doc in resource_docs:
                try:
                    resource_perm = ResourcePermission.from_dict(doc.to_dict())
                    if resource_perm.is_expired():
                        doc.reference.delete()
                        cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Failed to process resource permission {doc.id}: {e}")
            
            logger.info(f"Cleaned up {cleaned_count} expired permissions")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired permissions: {e}")
            return 0

# Global role service instance
_role_service: Optional[RoleService] = None

def get_role_service() -> RoleService:
    """Get global role service instance"""
    global _role_service
    if _role_service is None:
        _role_service = RoleService()
    return _role_service
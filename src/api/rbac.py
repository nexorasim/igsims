"""
Role-Based Access Control API endpoints for iGSIM AI Agent Platform

This module provides API endpoints for managing roles, permissions,
and user access control.

Requirements: 8.4 (Role-based access control)
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

from fastapi import APIRouter, HTTPException, status, Depends, Query
from pydantic import BaseModel, Field

# Import our services and utilities
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.rbac import Permission, Role, RoleDefinition
from models.user import User
from services.role_service import get_role_service, RoleService
from services.admin_service import get_admin_service, AdminService
from utils.rbac_decorators import (
    require_permission, require_admin, require_admin_or_self,
    require_any_permission, RBACError
)
from utils.auth_utils import get_current_active_user

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/rbac", tags=["rbac"])

# Pydantic models for request/response

class RoleCreateRequest(BaseModel):
    """Role creation request model"""
    name: str = Field(..., min_length=1, max_length=50, regex="^[a-zA-Z0-9_-]+$")
    display_name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    permissions: List[str] = Field(default_factory=list)
    inherits_from: Optional[str] = None

class RoleUpdateRequest(BaseModel):
    """Role update request model"""
    display_name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    permissions: Optional[List[str]] = None
    inherits_from: Optional[str] = None

class PermissionGrantRequest(BaseModel):
    """Permission grant request model"""
    user_id: str = Field(..., min_length=1)
    permission: str = Field(..., min_length=1)
    expires_at: Optional[datetime] = None
    reason: Optional[str] = Field(None, max_length=500)

class ResourcePermissionRequest(BaseModel):
    """Resource permission request model"""
    user_id: str = Field(..., min_length=1)
    resource_type: str = Field(..., min_length=1)
    resource_id: str = Field(..., min_length=1)
    permissions: List[str] = Field(..., min_items=1)
    expires_at: Optional[datetime] = None

class RoleAssignmentRequest(BaseModel):
    """Role assignment request model"""
    user_id: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)

class BulkRoleAssignmentRequest(BaseModel):
    """Bulk role assignment request model"""
    user_ids: List[str] = Field(..., min_items=1, max_items=100)
    role: str = Field(..., min_length=1)

class BulkUserActionRequest(BaseModel):
    """Bulk user action request model"""
    user_ids: List[str] = Field(..., min_items=1, max_items=100)

class RoleResponse(BaseModel):
    """Role response model"""
    name: str
    display_name: str
    description: str
    permissions: List[str]
    inherits_from: Optional[str]
    is_system_role: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

class PermissionResponse(BaseModel):
    """Permission response model"""
    user_id: str
    role: str
    role_permissions: List[str]
    additional_permissions: List[str]
    all_permissions: List[str]

class SystemStatsResponse(BaseModel):
    """System statistics response model"""
    user_stats: Dict[str, Any]
    permission_grants: int
    resource_permissions: int
    custom_roles: int
    system_health: str

# Helper functions

def validate_permission(permission_str: str) -> Permission:
    """Validate and convert permission string to Permission enum"""
    try:
        return Permission(permission_str)
    except ValueError:
        valid_permissions = [p.value for p in Permission]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission '{permission_str}'. Valid permissions: {valid_permissions}"
        )

def validate_permissions(permission_strs: List[str]) -> List[Permission]:
    """Validate and convert permission strings to Permission enums"""
    return [validate_permission(p) for p in permission_strs]

# Role Management Endpoints

@router.post("/roles", response_model=RoleResponse)
async def create_role(
    request: RoleCreateRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Create a new custom role
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        # Validate permissions
        permissions = validate_permissions(request.permissions)
        
        role_data = {
            'name': request.name,
            'display_name': request.display_name,
            'description': request.description,
            'permissions': [p.value for p in permissions],
            'inherits_from': request.inherits_from
        }
        
        role = await role_service.create_role(role_data, current_user.user_id)
        
        return RoleResponse(
            name=role.name,
            display_name=role.display_name,
            description=role.description,
            permissions=[p.value for p in role.permissions],
            inherits_from=role.inherits_from,
            is_system_role=role.is_system_role,
            created_at=role.created_at,
            updated_at=role.updated_at
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to create role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create role"
        )

@router.get("/roles", response_model=Dict[str, RoleResponse])
async def get_all_roles(
    current_user: User = Depends(require_permission(Permission.READ_USERS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Get all role definitions
    
    Requires: READ_USERS permission
    """
    try:
        roles = await role_service.get_all_roles()
        
        role_responses = {}
        for name, role in roles.items():
            role_responses[name] = RoleResponse(
                name=role.name,
                display_name=role.display_name,
                description=role.description,
                permissions=[p.value for p in role.permissions],
                inherits_from=role.inherits_from,
                is_system_role=role.is_system_role,
                created_at=role.created_at,
                updated_at=role.updated_at
            )
        
        return role_responses
        
    except Exception as e:
        logger.error(f"Failed to get roles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get roles"
        )

@router.get("/roles/{role_name}", response_model=RoleResponse)
async def get_role(
    role_name: str,
    current_user: User = Depends(require_permission(Permission.READ_USERS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Get specific role definition
    
    Requires: READ_USERS permission
    """
    try:
        role = await role_service.get_role(role_name)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found"
            )
        
        return RoleResponse(
            name=role.name,
            display_name=role.display_name,
            description=role.description,
            permissions=[p.value for p in role.permissions],
            inherits_from=role.inherits_from,
            is_system_role=role.is_system_role,
            created_at=role.created_at,
            updated_at=role.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get role"
        )

@router.put("/roles/{role_name}", response_model=RoleResponse)
async def update_role(
    role_name: str,
    request: RoleUpdateRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Update existing role
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        updates = {}
        
        if request.display_name is not None:
            updates['display_name'] = request.display_name
        
        if request.description is not None:
            updates['description'] = request.description
        
        if request.permissions is not None:
            permissions = validate_permissions(request.permissions)
            updates['permissions'] = [p.value for p in permissions]
        
        if request.inherits_from is not None:
            updates['inherits_from'] = request.inherits_from
        
        role = await role_service.update_role(role_name, updates, current_user.user_id)
        
        return RoleResponse(
            name=role.name,
            display_name=role.display_name,
            description=role.description,
            permissions=[p.value for p in role.permissions],
            inherits_from=role.inherits_from,
            is_system_role=role.is_system_role,
            created_at=role.created_at,
            updated_at=role.updated_at
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to update role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role"
        )

@router.delete("/roles/{role_name}")
async def delete_role(
    role_name: str,
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Delete custom role
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        success = await role_service.delete_role(role_name, current_user.user_id)
        
        if success:
            return {"success": True, "message": f"Role '{role_name}' deleted successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to delete role"
            )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to delete role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete role"
        )

@router.get("/roles/{role_name}/permissions", response_model=List[str])
async def get_role_permissions(
    role_name: str,
    current_user: User = Depends(require_permission(Permission.READ_USERS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Get effective permissions for a role
    
    Requires: READ_USERS permission
    """
    try:
        permissions = await role_service.get_role_permissions(role_name)
        return [p.value for p in permissions]
        
    except Exception as e:
        logger.error(f"Failed to get role permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get role permissions"
        )

# User Permission Management Endpoints

@router.post("/users/assign-role")
async def assign_role_to_user(
    request: RoleAssignmentRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_USER_ROLES)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Assign role to user
    
    Requires: MANAGE_USER_ROLES permission
    """
    try:
        success = await role_service.assign_role_to_user(
            request.user_id,
            request.role,
            current_user.user_id
        )
        
        if success:
            return {"success": True, "message": f"Role '{request.role}' assigned to user"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to assign role"
            )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to assign role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign role"
        )

@router.post("/users/remove-role")
async def remove_role_from_user(
    request: RoleAssignmentRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_USER_ROLES)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Remove role from user (assign default user role)
    
    Requires: MANAGE_USER_ROLES permission
    """
    try:
        success = await role_service.remove_role_from_user(
            request.user_id,
            current_user.user_id
        )
        
        if success:
            return {"success": True, "message": "Role removed from user"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to remove role"
            )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to remove role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove role"
        )

@router.post("/users/grant-permission")
async def grant_permission_to_user(
    request: PermissionGrantRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Grant specific permission to user
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        permission = validate_permission(request.permission)
        
        grant = await role_service.grant_permission_to_user(
            request.user_id,
            permission,
            current_user.user_id,
            request.expires_at,
            request.reason
        )
        
        return {
            "success": True,
            "message": f"Permission '{request.permission}' granted to user",
            "grant": grant.to_dict()
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to grant permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to grant permission"
        )

@router.post("/users/revoke-permission")
async def revoke_permission_from_user(
    request: PermissionGrantRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Revoke specific permission from user
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        permission = validate_permission(request.permission)
        
        success = await role_service.revoke_permission_from_user(
            request.user_id,
            permission,
            current_user.user_id
        )
        
        if success:
            return {"success": True, "message": f"Permission '{request.permission}' revoked from user"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to revoke permission"
            )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to revoke permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke permission"
        )

@router.get("/users/{user_id}/permissions", response_model=PermissionResponse)
async def get_user_permissions(
    user_id: str,
    current_user: User = Depends(require_admin_or_self("user_id")),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Get all permissions for a user
    
    Requires: Admin role or accessing own permissions
    """
    try:
        permissions = await role_service.get_user_permissions(user_id)
        
        if not permissions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return PermissionResponse(**permissions)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user permissions"
        )

@router.post("/users/grant-resource-permission")
async def grant_resource_permission(
    request: ResourcePermissionRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Grant resource-specific permissions to user
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        permissions = validate_permissions(request.permissions)
        
        resource_perm = await role_service.grant_resource_permission(
            request.user_id,
            request.resource_type,
            request.resource_id,
            set(permissions),
            current_user.user_id,
            request.expires_at
        )
        
        return {
            "success": True,
            "message": "Resource permissions granted",
            "resource_permission": resource_perm.to_dict()
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to grant resource permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to grant resource permission"
        )

@router.delete("/users/{user_id}/resource-permissions/{resource_type}/{resource_id}")
async def revoke_resource_permission(
    user_id: str,
    resource_type: str,
    resource_id: str,
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Revoke resource-specific permissions from user
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        success = await role_service.revoke_resource_permission(
            user_id,
            resource_type,
            resource_id,
            current_user.user_id
        )
        
        if success:
            return {"success": True, "message": "Resource permissions revoked"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to revoke resource permissions"
            )
        
    except Exception as e:
        logger.error(f"Failed to revoke resource permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke resource permission"
        )

# Permission Checking Endpoints

@router.get("/users/{user_id}/check-permission/{permission}")
async def check_user_permission(
    user_id: str,
    permission: str,
    current_user: User = Depends(require_admin_or_self("user_id")),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Check if user has specific permission
    
    Requires: Admin role or checking own permissions
    """
    try:
        perm = validate_permission(permission)
        has_permission = await role_service.check_user_permission(user_id, perm)
        
        return {
            "user_id": user_id,
            "permission": permission,
            "has_permission": has_permission
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to check user permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check user permission"
        )

@router.get("/users/{user_id}/check-resource-permission/{resource_type}/{resource_id}/{permission}")
async def check_user_resource_permission(
    user_id: str,
    resource_type: str,
    resource_id: str,
    permission: str,
    current_user: User = Depends(require_admin_or_self("user_id")),
    role_service: RoleService = Depends(get_role_service)
):
    """
    Check if user has permission for specific resource
    
    Requires: Admin role or checking own permissions
    """
    try:
        perm = validate_permission(permission)
        has_permission = await role_service.check_user_resource_permission(
            user_id, resource_type, resource_id, perm
        )
        
        return {
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "permission": permission,
            "has_permission": has_permission
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to check user resource permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check user resource permission"
        )

# Bulk Operations

@router.post("/users/bulk-assign-role")
async def bulk_assign_role(
    request: BulkRoleAssignmentRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_USER_ROLES)),
    admin_service: AdminService = Depends(get_admin_service)
):
    """
    Assign role to multiple users
    
    Requires: MANAGE_USER_ROLES permission
    """
    try:
        results = await admin_service.bulk_assign_role(
            current_user.user_id,
            request.user_ids,
            request.role
        )
        
        return {
            "success": True,
            "message": f"Bulk role assignment completed",
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Failed bulk role assignment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed bulk role assignment"
        )

# System Administration

@router.get("/system/stats", response_model=SystemStatsResponse)
async def get_system_stats(
    current_user: User = Depends(require_permission(Permission.VIEW_SYSTEM_LOGS)),
    admin_service: AdminService = Depends(get_admin_service)
):
    """
    Get system statistics
    
    Requires: VIEW_SYSTEM_LOGS permission
    """
    try:
        stats = await admin_service.get_system_stats(current_user.user_id)
        
        return SystemStatsResponse(
            user_stats=stats.user_stats.__dict__,
            permission_grants=stats.permission_grants,
            resource_permissions=stats.resource_permissions,
            custom_roles=stats.custom_roles,
            system_health=stats.system_health
        )
        
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system stats"
        )

@router.post("/system/cleanup-expired-permissions")
async def cleanup_expired_permissions(
    current_user: User = Depends(require_permission(Permission.MANAGE_PERMISSIONS)),
    admin_service: AdminService = Depends(get_admin_service)
):
    """
    Clean up expired permissions
    
    Requires: MANAGE_PERMISSIONS permission
    """
    try:
        count = await admin_service.cleanup_expired_permissions(current_user.user_id)
        
        return {
            "success": True,
            "message": f"Cleaned up {count} expired permissions"
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup expired permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cleanup expired permissions"
        )

# Available Permissions Endpoint

@router.get("/permissions")
async def get_available_permissions(
    current_user: User = Depends(require_permission(Permission.READ_USERS))
):
    """
    Get list of all available permissions
    
    Requires: READ_USERS permission
    """
    try:
        permissions = {}
        
        for perm in Permission:
            # Group permissions by category
            category = perm.value.split('_')[0]
            if category not in permissions:
                permissions[category] = []
            
            permissions[category].append({
                'name': perm.value,
                'description': perm.value.replace('_', ' ').title()
            })
        
        return {
            "permissions": permissions,
            "total_count": len(Permission)
        }
        
    except Exception as e:
        logger.error(f"Failed to get available permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get available permissions"
        )
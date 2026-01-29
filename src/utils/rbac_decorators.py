"""
RBAC Decorators and Middleware for iGSIM AI Agent Platform

This module provides decorators and middleware for enforcing role-based
access control throughout the application.

Requirements: 8.4 (Role-based access control)
"""

import logging
from typing import List, Optional, Callable, Any, Union
from functools import wraps
from datetime import datetime

from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Import our models and services
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.rbac import Permission, check_permission
from models.user import User
from services.auth_service import get_auth_service, AuthService
from services.role_service import get_role_service, RoleService
from utils.auth_utils import get_current_user, get_current_active_user

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

class RBACError(HTTPException):
    """RBAC-specific HTTP exception"""
    
    def __init__(self, detail: str, status_code: int = status.HTTP_403_FORBIDDEN):
        super().__init__(status_code=status_code, detail=detail)

# Permission checking decorators

def require_permission(permission: Permission):
    """
    Decorator to require specific permission
    
    Args:
        permission: Required permission
        
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(
        current_user: User = Depends(get_current_active_user),
        role_service: RoleService = Depends(get_role_service)
    ) -> User:
        """Check if user has required permission"""
        try:
            has_permission = await role_service.check_user_permission(
                current_user.user_id, 
                permission
            )
            
            if not has_permission:
                logger.warning(f"Permission denied: {current_user.email} lacks {permission.value}")
                raise RBACError(f"Permission denied: {permission.value} required")
            
            return current_user
            
        except RBACError:
            raise
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            raise RBACError("Permission check failed")
    
    return permission_dependency

def require_any_permission(permissions: List[Permission]):
    """
    Decorator to require any of the specified permissions
    
    Args:
        permissions: List of permissions (any one is sufficient)
        
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(
        current_user: User = Depends(get_current_active_user),
        role_service: RoleService = Depends(get_role_service)
    ) -> User:
        """Check if user has any of the required permissions"""
        try:
            for permission in permissions:
                has_permission = await role_service.check_user_permission(
                    current_user.user_id, 
                    permission
                )
                if has_permission:
                    return current_user
            
            permission_names = [p.value for p in permissions]
            logger.warning(f"Permission denied: {current_user.email} lacks any of {permission_names}")
            raise RBACError(f"Permission denied: One of {permission_names} required")
            
        except RBACError:
            raise
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            raise RBACError("Permission check failed")
    
    return permission_dependency

def require_all_permissions(permissions: List[Permission]):
    """
    Decorator to require all specified permissions
    
    Args:
        permissions: List of permissions (all must be present)
        
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(
        current_user: User = Depends(get_current_active_user),
        role_service: RoleService = Depends(get_role_service)
    ) -> User:
        """Check if user has all required permissions"""
        try:
            missing_permissions = []
            
            for permission in permissions:
                has_permission = await role_service.check_user_permission(
                    current_user.user_id, 
                    permission
                )
                if not has_permission:
                    missing_permissions.append(permission.value)
            
            if missing_permissions:
                logger.warning(f"Permission denied: {current_user.email} lacks {missing_permissions}")
                raise RBACError(f"Permission denied: Missing permissions: {missing_permissions}")
            
            return current_user
            
        except RBACError:
            raise
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            raise RBACError("Permission check failed")
    
    return permission_dependency

def require_role(role: str):
    """
    Decorator to require specific role
    
    Args:
        role: Required role name
        
    Returns:
        FastAPI dependency function
    """
    async def role_dependency(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """Check if user has required role"""
        if current_user.role != role and current_user.role != "admin":
            logger.warning(f"Role denied: {current_user.email} has role {current_user.role}, requires {role}")
            raise RBACError(f"Role '{role}' required")
        
        return current_user
    
    return role_dependency

def require_any_role(roles: List[str]):
    """
    Decorator to require any of the specified roles
    
    Args:
        roles: List of role names (any one is sufficient)
        
    Returns:
        FastAPI dependency function
    """
    async def role_dependency(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """Check if user has any of the required roles"""
        if current_user.role not in roles and current_user.role != "admin":
            logger.warning(f"Role denied: {current_user.email} has role {current_user.role}, requires one of {roles}")
            raise RBACError(f"One of roles {roles} required")
        
        return current_user
    
    return role_dependency

# Resource-based permission decorators

def require_resource_permission(resource_type: str, permission: Permission):
    """
    Decorator to require permission for specific resource
    
    Args:
        resource_type: Type of resource
        permission: Required permission
        
    Returns:
        FastAPI dependency function that takes resource_id as parameter
    """
    def decorator(resource_id_param: str = "resource_id"):
        async def permission_dependency(
            request: Request,
            current_user: User = Depends(get_current_active_user),
            role_service: RoleService = Depends(get_role_service)
        ) -> User:
            """Check if user has permission for specific resource"""
            try:
                # Get resource ID from path parameters
                resource_id = request.path_params.get(resource_id_param)
                if not resource_id:
                    raise RBACError(f"Resource ID parameter '{resource_id_param}' not found")
                
                has_permission = await role_service.check_user_resource_permission(
                    current_user.user_id,
                    resource_type,
                    resource_id,
                    permission
                )
                
                if not has_permission:
                    logger.warning(f"Resource permission denied: {current_user.email} lacks {permission.value} for {resource_type}:{resource_id}")
                    raise RBACError(f"Permission denied for {resource_type}")
                
                return current_user
                
            except RBACError:
                raise
            except Exception as e:
                logger.error(f"Resource permission check failed: {e}")
                raise RBACError("Resource permission check failed")
        
        return permission_dependency
    
    return decorator

# Admin-only decorators

def require_admin():
    """Decorator to require admin role"""
    return require_role("admin")

def require_admin_or_self(user_id_param: str = "user_id"):
    """
    Decorator to require admin role or accessing own resources
    
    Args:
        user_id_param: Name of the user ID parameter in the path
        
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(
        request: Request,
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """Check if user is admin or accessing own resources"""
        try:
            # Get user ID from path parameters
            target_user_id = request.path_params.get(user_id_param)
            if not target_user_id:
                raise RBACError(f"User ID parameter '{user_id_param}' not found")
            
            # Allow if admin or accessing own resources
            if current_user.role == "admin" or current_user.user_id == target_user_id:
                return current_user
            
            logger.warning(f"Access denied: {current_user.email} cannot access user {target_user_id}")
            raise RBACError("Access denied: Admin role required or can only access own resources")
            
        except RBACError:
            raise
        except Exception as e:
            logger.error(f"Admin or self check failed: {e}")
            raise RBACError("Access check failed")
    
    return permission_dependency

# Conditional permission decorators

def require_permission_if(condition_func: Callable[[Request, User], bool], permission: Permission):
    """
    Decorator to require permission only if condition is met
    
    Args:
        condition_func: Function that takes (request, user) and returns bool
        permission: Required permission if condition is True
        
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(
        request: Request,
        current_user: User = Depends(get_current_active_user),
        role_service: RoleService = Depends(get_role_service)
    ) -> User:
        """Check permission conditionally"""
        try:
            if condition_func(request, current_user):
                has_permission = await role_service.check_user_permission(
                    current_user.user_id, 
                    permission
                )
                
                if not has_permission:
                    logger.warning(f"Conditional permission denied: {current_user.email} lacks {permission.value}")
                    raise RBACError(f"Permission denied: {permission.value} required")
            
            return current_user
            
        except RBACError:
            raise
        except Exception as e:
            logger.error(f"Conditional permission check failed: {e}")
            raise RBACError("Permission check failed")
    
    return permission_dependency

# Middleware for RBAC

class RBACMiddleware:
    """Middleware for role-based access control"""
    
    def __init__(self):
        self.role_service = get_role_service()
        self.auth_service = get_auth_service()
    
    async def __call__(self, request: Request, call_next):
        """Process request with RBAC checks"""
        try:
            # Skip RBAC for public endpoints
            if self._is_public_endpoint(request.url.path):
                return await call_next(request)
            
            # Get user from token
            user = await self._get_user_from_request(request)
            if user:
                # Add user to request state for downstream use
                request.state.current_user = user
                
                # Log access attempt
                logger.debug(f"RBAC: User {user.email} accessing {request.method} {request.url.path}")
            
            response = await call_next(request)
            
            # Log successful access
            if user and response.status_code < 400:
                logger.debug(f"RBAC: Access granted to {user.email} for {request.method} {request.url.path}")
            
            return response
            
        except Exception as e:
            logger.error(f"RBAC middleware error: {e}")
            return await call_next(request)
    
    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public (no authentication required)"""
        public_paths = [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/auth/login",
            "/auth/register",
            "/auth/reset-password",
            "/auth/oauth/login"
        ]
        
        return any(path.startswith(public_path) for public_path in public_paths)
    
    async def _get_user_from_request(self, request: Request) -> Optional[User]:
        """Extract user from request authorization header"""
        try:
            authorization = request.headers.get("Authorization")
            if not authorization or not authorization.startswith("Bearer "):
                return None
            
            token = authorization.split(" ")[1]
            user = await self.auth_service.get_user_by_token(token)
            
            return user if user and user.is_active else None
            
        except Exception as e:
            logger.debug(f"Failed to get user from request: {e}")
            return None

# Utility functions for permission checking

async def check_user_has_permission(user: User, permission: Permission, 
                                   role_service: Optional[RoleService] = None) -> bool:
    """
    Utility function to check if user has permission
    
    Args:
        user: User object
        permission: Permission to check
        role_service: Optional role service instance
        
    Returns:
        True if user has permission
    """
    if not role_service:
        role_service = get_role_service()
    
    return await role_service.check_user_permission(user.user_id, permission)

async def check_user_has_any_permission(user: User, permissions: List[Permission],
                                       role_service: Optional[RoleService] = None) -> bool:
    """
    Utility function to check if user has any of the permissions
    
    Args:
        user: User object
        permissions: List of permissions to check
        role_service: Optional role service instance
        
    Returns:
        True if user has at least one permission
    """
    if not role_service:
        role_service = get_role_service()
    
    for permission in permissions:
        if await role_service.check_user_permission(user.user_id, permission):
            return True
    
    return False

async def check_user_has_all_permissions(user: User, permissions: List[Permission],
                                        role_service: Optional[RoleService] = None) -> bool:
    """
    Utility function to check if user has all permissions
    
    Args:
        user: User object
        permissions: List of permissions to check
        role_service: Optional role service instance
        
    Returns:
        True if user has all permissions
    """
    if not role_service:
        role_service = get_role_service()
    
    for permission in permissions:
        if not await role_service.check_user_permission(user.user_id, permission):
            return False
    
    return True

async def get_user_missing_permissions(user: User, permissions: List[Permission],
                                      role_service: Optional[RoleService] = None) -> List[Permission]:
    """
    Utility function to get missing permissions for user
    
    Args:
        user: User object
        permissions: List of permissions to check
        role_service: Optional role service instance
        
    Returns:
        List of missing permissions
    """
    if not role_service:
        role_service = get_role_service()
    
    missing = []
    for permission in permissions:
        if not await role_service.check_user_permission(user.user_id, permission):
            missing.append(permission)
    
    return missing

# Context managers for temporary permission elevation

class TemporaryPermissionElevation:
    """Context manager for temporary permission elevation"""
    
    def __init__(self, user: User, permissions: List[Permission], 
                 role_service: Optional[RoleService] = None):
        self.user = user
        self.permissions = permissions
        self.role_service = role_service or get_role_service()
        self.original_permissions = user.permissions.copy()
    
    async def __aenter__(self):
        """Grant temporary permissions"""
        for permission in self.permissions:
            if permission.value not in self.user.permissions:
                self.user.permissions.append(permission.value)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Restore original permissions"""
        self.user.permissions = self.original_permissions

# Audit logging for RBAC events

class RBACLogger:
    """Logger for RBAC events"""
    
    def __init__(self):
        self.logger = logging.getLogger("rbac_audit")
    
    def log_permission_check(self, user_id: str, permission: str, 
                           resource_type: Optional[str] = None,
                           resource_id: Optional[str] = None,
                           granted: bool = False):
        """Log permission check event"""
        event_data = {
            "event_type": "permission_check",
            "user_id": user_id,
            "permission": permission,
            "granted": granted,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if resource_type:
            event_data["resource_type"] = resource_type
        if resource_id:
            event_data["resource_id"] = resource_id
        
        self.logger.info(f"RBAC Event: {event_data}")
    
    def log_role_assignment(self, user_id: str, role: str, assigned_by: str):
        """Log role assignment event"""
        event_data = {
            "event_type": "role_assignment",
            "user_id": user_id,
            "role": role,
            "assigned_by": assigned_by,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"RBAC Event: {event_data}")
    
    def log_permission_grant(self, user_id: str, permission: str, granted_by: str):
        """Log permission grant event"""
        event_data = {
            "event_type": "permission_grant",
            "user_id": user_id,
            "permission": permission,
            "granted_by": granted_by,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"RBAC Event: {event_data}")

# Global RBAC logger instance
rbac_logger = RBACLogger()
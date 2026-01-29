"""
Role-Based Access Control (RBAC) models for iGSIM AI Agent Platform

This module defines roles, permissions, and RBAC-related data structures
for implementing comprehensive access control throughout the platform.

Requirements: 8.4 (Role-based access control)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from enum import Enum
from datetime import datetime
import json

class Permission(Enum):
    """System permissions"""
    
    # User management permissions
    READ_USERS = "read_users"
    CREATE_USERS = "create_users"
    UPDATE_USERS = "update_users"
    DELETE_USERS = "delete_users"
    MANAGE_USER_ROLES = "manage_user_roles"
    
    # Device management permissions
    READ_DEVICES = "read_devices"
    CREATE_DEVICES = "create_devices"
    UPDATE_DEVICES = "update_devices"
    DELETE_DEVICES = "delete_devices"
    PROVISION_ESIM = "provision_esim"
    MANAGE_DEVICE_PROFILES = "manage_device_profiles"
    
    # eSIM profile permissions
    READ_ESIM_PROFILES = "read_esim_profiles"
    CREATE_ESIM_PROFILES = "create_esim_profiles"
    UPDATE_ESIM_PROFILES = "update_esim_profiles"
    DELETE_ESIM_PROFILES = "delete_esim_profiles"
    ACTIVATE_ESIM = "activate_esim"
    DEACTIVATE_ESIM = "deactivate_esim"
    
    # AI services permissions
    USE_AI_SERVICES = "use_ai_services"
    MANAGE_AI_CONTEXTS = "manage_ai_contexts"
    ACCESS_AI_ANALYTICS = "access_ai_analytics"
    
    # System administration permissions
    VIEW_SYSTEM_LOGS = "view_system_logs"
    MANAGE_SYSTEM_CONFIG = "manage_system_config"
    ACCESS_ADMIN_PANEL = "access_admin_panel"
    MANAGE_PERMISSIONS = "manage_permissions"
    
    # Monitoring and analytics permissions
    VIEW_ANALYTICS = "view_analytics"
    EXPORT_DATA = "export_data"
    MANAGE_REPORTS = "manage_reports"
    
    # API access permissions
    API_READ = "api_read"
    API_WRITE = "api_write"
    API_DELETE = "api_delete"
    API_ADMIN = "api_admin"

class Role(Enum):
    """System roles with hierarchical structure"""
    
    # Basic user role
    USER = "user"
    
    # Device operator role
    OPERATOR = "operator"
    
    # System administrator role
    ADMIN = "admin"
    
    # Super administrator role (for system maintenance)
    SUPER_ADMIN = "super_admin"

@dataclass
class RoleDefinition:
    """Role definition with permissions and metadata"""
    
    name: str
    display_name: str
    description: str
    permissions: Set[Permission]
    inherits_from: Optional[str] = None
    is_system_role: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize timestamps"""
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if role has specific permission"""
        return permission in self.permissions
    
    def add_permission(self, permission: Permission) -> None:
        """Add permission to role"""
        self.permissions.add(permission)
        self.updated_at = datetime.utcnow()
    
    def remove_permission(self, permission: Permission) -> None:
        """Remove permission from role"""
        self.permissions.discard(permission)
        self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'permissions': [p.value for p in self.permissions],
            'inherits_from': self.inherits_from,
            'is_system_role': self.is_system_role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RoleDefinition':
        """Create from dictionary"""
        permissions = {Permission(p) for p in data.get('permissions', [])}
        
        role_def = cls(
            name=data['name'],
            display_name=data['display_name'],
            description=data['description'],
            permissions=permissions,
            inherits_from=data.get('inherits_from'),
            is_system_role=data.get('is_system_role', True)
        )
        
        if data.get('created_at'):
            role_def.created_at = datetime.fromisoformat(data['created_at'])
        if data.get('updated_at'):
            role_def.updated_at = datetime.fromisoformat(data['updated_at'])
        
        return role_def

@dataclass
class PermissionGrant:
    """Individual permission grant to a user"""
    
    user_id: str
    permission: Permission
    granted_by: str
    granted_at: datetime
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if permission grant is expired"""
        return self.expires_at is not None and self.expires_at < datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'user_id': self.user_id,
            'permission': self.permission.value,
            'granted_by': self.granted_by,
            'granted_at': self.granted_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'reason': self.reason
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PermissionGrant':
        """Create from dictionary"""
        grant = cls(
            user_id=data['user_id'],
            permission=Permission(data['permission']),
            granted_by=data['granted_by'],
            granted_at=datetime.fromisoformat(data['granted_at']),
            reason=data.get('reason')
        )
        
        if data.get('expires_at'):
            grant.expires_at = datetime.fromisoformat(data['expires_at'])
        
        return grant

class RoleHierarchy:
    """Manages role hierarchy and permission inheritance"""
    
    def __init__(self):
        self._roles: Dict[str, RoleDefinition] = {}
        self._initialize_default_roles()
    
    def _initialize_default_roles(self) -> None:
        """Initialize default system roles"""
        
        # User role - basic permissions
        user_permissions = {
            Permission.READ_DEVICES,
            Permission.READ_ESIM_PROFILES,
            Permission.USE_AI_SERVICES,
            Permission.API_READ
        }
        
        self._roles[Role.USER.value] = RoleDefinition(
            name=Role.USER.value,
            display_name="User",
            description="Basic user with read access to own resources",
            permissions=user_permissions
        )
        
        # Operator role - device management permissions
        operator_permissions = user_permissions | {
            Permission.CREATE_DEVICES,
            Permission.UPDATE_DEVICES,
            Permission.PROVISION_ESIM,
            Permission.MANAGE_DEVICE_PROFILES,
            Permission.CREATE_ESIM_PROFILES,
            Permission.UPDATE_ESIM_PROFILES,
            Permission.ACTIVATE_ESIM,
            Permission.DEACTIVATE_ESIM,
            Permission.MANAGE_AI_CONTEXTS,
            Permission.VIEW_ANALYTICS,
            Permission.API_WRITE
        }
        
        self._roles[Role.OPERATOR.value] = RoleDefinition(
            name=Role.OPERATOR.value,
            display_name="Operator",
            description="Device operator with management permissions",
            permissions=operator_permissions,
            inherits_from=Role.USER.value
        )
        
        # Admin role - full system permissions
        admin_permissions = operator_permissions | {
            Permission.READ_USERS,
            Permission.CREATE_USERS,
            Permission.UPDATE_USERS,
            Permission.DELETE_USERS,
            Permission.MANAGE_USER_ROLES,
            Permission.DELETE_DEVICES,
            Permission.DELETE_ESIM_PROFILES,
            Permission.ACCESS_AI_ANALYTICS,
            Permission.VIEW_SYSTEM_LOGS,
            Permission.MANAGE_SYSTEM_CONFIG,
            Permission.ACCESS_ADMIN_PANEL,
            Permission.EXPORT_DATA,
            Permission.MANAGE_REPORTS,
            Permission.API_DELETE,
            Permission.API_ADMIN
        }
        
        self._roles[Role.ADMIN.value] = RoleDefinition(
            name=Role.ADMIN.value,
            display_name="Administrator",
            description="System administrator with full permissions",
            permissions=admin_permissions,
            inherits_from=Role.OPERATOR.value
        )
        
        # Super Admin role - all permissions including permission management
        super_admin_permissions = admin_permissions | {
            Permission.MANAGE_PERMISSIONS
        }
        
        self._roles[Role.SUPER_ADMIN.value] = RoleDefinition(
            name=Role.SUPER_ADMIN.value,
            display_name="Super Administrator",
            description="Super administrator with all system permissions",
            permissions=super_admin_permissions,
            inherits_from=Role.ADMIN.value
        )
    
    def get_role(self, role_name: str) -> Optional[RoleDefinition]:
        """Get role definition by name"""
        return self._roles.get(role_name)
    
    def get_all_roles(self) -> Dict[str, RoleDefinition]:
        """Get all role definitions"""
        return self._roles.copy()
    
    def add_role(self, role: RoleDefinition) -> None:
        """Add custom role definition"""
        self._roles[role.name] = role
    
    def remove_role(self, role_name: str) -> bool:
        """Remove custom role (cannot remove system roles)"""
        if role_name in self._roles:
            role = self._roles[role_name]
            if not role.is_system_role:
                del self._roles[role_name]
                return True
        return False
    
    def get_effective_permissions(self, role_name: str) -> Set[Permission]:
        """Get all effective permissions for a role (including inherited)"""
        role = self.get_role(role_name)
        if not role:
            return set()
        
        permissions = role.permissions.copy()
        
        # Add inherited permissions
        if role.inherits_from:
            inherited_permissions = self.get_effective_permissions(role.inherits_from)
            permissions.update(inherited_permissions)
        
        return permissions
    
    def role_has_permission(self, role_name: str, permission: Permission) -> bool:
        """Check if role has specific permission (including inherited)"""
        effective_permissions = self.get_effective_permissions(role_name)
        return permission in effective_permissions
    
    def get_role_hierarchy(self) -> Dict[str, List[str]]:
        """Get role hierarchy mapping"""
        hierarchy = {}
        for role_name, role in self._roles.items():
            if role.inherits_from:
                if role.inherits_from not in hierarchy:
                    hierarchy[role.inherits_from] = []
                hierarchy[role.inherits_from].append(role_name)
        return hierarchy
    
    def validate_role_hierarchy(self) -> List[str]:
        """Validate role hierarchy for circular dependencies"""
        errors = []
        
        def check_circular(role_name: str, visited: Set[str]) -> bool:
            if role_name in visited:
                return True
            
            role = self.get_role(role_name)
            if not role or not role.inherits_from:
                return False
            
            visited.add(role_name)
            return check_circular(role.inherits_from, visited)
        
        for role_name in self._roles:
            if check_circular(role_name, set()):
                errors.append(f"Circular dependency detected in role hierarchy for: {role_name}")
        
        return errors

# Global role hierarchy instance
_role_hierarchy: Optional[RoleHierarchy] = None

def get_role_hierarchy() -> RoleHierarchy:
    """Get global role hierarchy instance"""
    global _role_hierarchy
    if _role_hierarchy is None:
        _role_hierarchy = RoleHierarchy()
    return _role_hierarchy

# Permission checking utilities

def check_permission(user_role: str, required_permission: Permission, 
                    additional_permissions: Optional[List[Permission]] = None) -> bool:
    """
    Check if user role has required permission
    
    Args:
        user_role: User's role name
        required_permission: Required permission
        additional_permissions: Additional user-specific permissions
        
    Returns:
        True if user has permission
    """
    hierarchy = get_role_hierarchy()
    
    # Check role-based permissions
    if hierarchy.role_has_permission(user_role, required_permission):
        return True
    
    # Check additional user-specific permissions
    if additional_permissions and required_permission in additional_permissions:
        return True
    
    return False

def check_any_permission(user_role: str, required_permissions: List[Permission],
                        additional_permissions: Optional[List[Permission]] = None) -> bool:
    """
    Check if user role has any of the required permissions
    
    Args:
        user_role: User's role name
        required_permissions: List of required permissions (any one is sufficient)
        additional_permissions: Additional user-specific permissions
        
    Returns:
        True if user has at least one permission
    """
    for permission in required_permissions:
        if check_permission(user_role, permission, additional_permissions):
            return True
    return False

def check_all_permissions(user_role: str, required_permissions: List[Permission],
                         additional_permissions: Optional[List[Permission]] = None) -> bool:
    """
    Check if user role has all required permissions
    
    Args:
        user_role: User's role name
        required_permissions: List of required permissions (all must be present)
        additional_permissions: Additional user-specific permissions
        
    Returns:
        True if user has all permissions
    """
    for permission in required_permissions:
        if not check_permission(user_role, permission, additional_permissions):
            return False
    return True

def get_missing_permissions(user_role: str, required_permissions: List[Permission],
                           additional_permissions: Optional[List[Permission]] = None) -> List[Permission]:
    """
    Get list of missing permissions for user
    
    Args:
        user_role: User's role name
        required_permissions: List of required permissions
        additional_permissions: Additional user-specific permissions
        
    Returns:
        List of missing permissions
    """
    missing = []
    for permission in required_permissions:
        if not check_permission(user_role, permission, additional_permissions):
            missing.append(permission)
    return missing

# Resource-based access control

@dataclass
class ResourcePermission:
    """Resource-specific permission"""
    
    resource_type: str  # e.g., "device", "esim_profile", "user"
    resource_id: str
    user_id: str
    permissions: Set[Permission]
    granted_by: str
    granted_at: datetime
    expires_at: Optional[datetime] = None
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if resource permission includes specific permission"""
        return permission in self.permissions
    
    def is_expired(self) -> bool:
        """Check if resource permission is expired"""
        return self.expires_at is not None and self.expires_at < datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'user_id': self.user_id,
            'permissions': [p.value for p in self.permissions],
            'granted_by': self.granted_by,
            'granted_at': self.granted_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourcePermission':
        """Create from dictionary"""
        permissions = {Permission(p) for p in data.get('permissions', [])}
        
        resource_perm = cls(
            resource_type=data['resource_type'],
            resource_id=data['resource_id'],
            user_id=data['user_id'],
            permissions=permissions,
            granted_by=data['granted_by'],
            granted_at=datetime.fromisoformat(data['granted_at'])
        )
        
        if data.get('expires_at'):
            resource_perm.expires_at = datetime.fromisoformat(data['expires_at'])
        
        return resource_perm

def check_resource_permission(user_id: str, user_role: str, resource_type: str, 
                             resource_id: str, required_permission: Permission,
                             resource_permissions: Optional[List[ResourcePermission]] = None) -> bool:
    """
    Check if user has permission for specific resource
    
    Args:
        user_id: User ID
        user_role: User's role
        resource_type: Type of resource
        resource_id: Resource ID
        required_permission: Required permission
        resource_permissions: User's resource-specific permissions
        
    Returns:
        True if user has permission for resource
    """
    # Check role-based permissions first
    hierarchy = get_role_hierarchy()
    if hierarchy.role_has_permission(user_role, required_permission):
        return True
    
    # Check resource-specific permissions
    if resource_permissions:
        for res_perm in resource_permissions:
            if (res_perm.resource_type == resource_type and 
                res_perm.resource_id == resource_id and
                res_perm.user_id == user_id and
                not res_perm.is_expired() and
                res_perm.has_permission(required_permission)):
                return True
    
    return False
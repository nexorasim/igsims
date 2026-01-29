"""
Unit tests for RBAC models in iGSIM AI Agent Platform

Tests the role-based access control models including roles, permissions,
and hierarchy management.

Requirements: 8.4 (Role-based access control)
"""

import pytest
from datetime import datetime, timedelta
from typing import Set

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.rbac import (
    Permission, Role, RoleDefinition, PermissionGrant, ResourcePermission,
    RoleHierarchy, get_role_hierarchy, check_permission, check_any_permission,
    check_all_permissions, get_missing_permissions, check_resource_permission
)

class TestPermissionEnum:
    """Test Permission enum"""
    
    def test_permission_values(self):
        """Test that all permissions have correct string values"""
        assert Permission.READ_USERS.value == "read_users"
        assert Permission.CREATE_USERS.value == "create_users"
        assert Permission.MANAGE_PERMISSIONS.value == "manage_permissions"
        assert Permission.API_ADMIN.value == "api_admin"
    
    def test_permission_count(self):
        """Test that we have expected number of permissions"""
        # Should have at least 25 permissions defined
        assert len(Permission) >= 25

class TestRoleEnum:
    """Test Role enum"""
    
    def test_role_values(self):
        """Test that all roles have correct string values"""
        assert Role.USER.value == "user"
        assert Role.OPERATOR.value == "operator"
        assert Role.ADMIN.value == "admin"
        assert Role.SUPER_ADMIN.value == "super_admin"

class TestRoleDefinition:
    """Test RoleDefinition class"""
    
    def test_role_definition_creation(self):
        """Test creating a role definition"""
        permissions = {Permission.READ_USERS, Permission.CREATE_USERS}
        
        role = RoleDefinition(
            name="test_role",
            display_name="Test Role",
            description="A test role",
            permissions=permissions
        )
        
        assert role.name == "test_role"
        assert role.display_name == "Test Role"
        assert role.description == "A test role"
        assert role.permissions == permissions
        assert role.inherits_from is None
        assert role.is_system_role is True
        assert isinstance(role.created_at, datetime)
        assert isinstance(role.updated_at, datetime)
    
    def test_role_definition_with_inheritance(self):
        """Test creating a role definition with inheritance"""
        permissions = {Permission.READ_USERS}
        
        role = RoleDefinition(
            name="child_role",
            display_name="Child Role",
            description="A child role",
            permissions=permissions,
            inherits_from="parent_role"
        )
        
        assert role.inherits_from == "parent_role"
    
    def test_has_permission(self):
        """Test permission checking"""
        permissions = {Permission.READ_USERS, Permission.CREATE_USERS}
        
        role = RoleDefinition(
            name="test_role",
            display_name="Test Role",
            description="A test role",
            permissions=permissions
        )
        
        assert role.has_permission(Permission.READ_USERS)
        assert role.has_permission(Permission.CREATE_USERS)
        assert not role.has_permission(Permission.DELETE_USERS)
    
    def test_add_remove_permission(self):
        """Test adding and removing permissions"""
        permissions = {Permission.READ_USERS}
        
        role = RoleDefinition(
            name="test_role",
            display_name="Test Role",
            description="A test role",
            permissions=permissions
        )
        
        # Add permission
        role.add_permission(Permission.CREATE_USERS)
        assert Permission.CREATE_USERS in role.permissions
        
        # Remove permission
        role.remove_permission(Permission.READ_USERS)
        assert Permission.READ_USERS not in role.permissions
    
    def test_to_dict(self):
        """Test converting role to dictionary"""
        permissions = {Permission.READ_USERS, Permission.CREATE_USERS}
        
        role = RoleDefinition(
            name="test_role",
            display_name="Test Role",
            description="A test role",
            permissions=permissions,
            inherits_from="parent_role",
            is_system_role=False
        )
        
        role_dict = role.to_dict()
        
        assert role_dict['name'] == "test_role"
        assert role_dict['display_name'] == "Test Role"
        assert role_dict['description'] == "A test role"
        assert set(role_dict['permissions']) == {"read_users", "create_users"}
        assert role_dict['inherits_from'] == "parent_role"
        assert role_dict['is_system_role'] is False
        assert 'created_at' in role_dict
        assert 'updated_at' in role_dict
    
    def test_from_dict(self):
        """Test creating role from dictionary"""
        role_data = {
            'name': 'test_role',
            'display_name': 'Test Role',
            'description': 'A test role',
            'permissions': ['read_users', 'create_users'],
            'inherits_from': 'parent_role',
            'is_system_role': False,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        
        role = RoleDefinition.from_dict(role_data)
        
        assert role.name == "test_role"
        assert role.display_name == "Test Role"
        assert role.description == "A test role"
        assert Permission.READ_USERS in role.permissions
        assert Permission.CREATE_USERS in role.permissions
        assert role.inherits_from == "parent_role"
        assert role.is_system_role is False

class TestPermissionGrant:
    """Test PermissionGrant class"""
    
    def test_permission_grant_creation(self):
        """Test creating a permission grant"""
        grant = PermissionGrant(
            user_id="user123",
            permission=Permission.READ_USERS,
            granted_by="admin123",
            granted_at=datetime.utcnow()
        )
        
        assert grant.user_id == "user123"
        assert grant.permission == Permission.READ_USERS
        assert grant.granted_by == "admin123"
        assert isinstance(grant.granted_at, datetime)
        assert grant.expires_at is None
        assert grant.reason is None
    
    def test_permission_grant_with_expiration(self):
        """Test creating a permission grant with expiration"""
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        grant = PermissionGrant(
            user_id="user123",
            permission=Permission.READ_USERS,
            granted_by="admin123",
            granted_at=datetime.utcnow(),
            expires_at=expires_at,
            reason="Temporary access"
        )
        
        assert grant.expires_at == expires_at
        assert grant.reason == "Temporary access"
    
    def test_is_expired(self):
        """Test expiration checking"""
        # Non-expiring grant
        grant1 = PermissionGrant(
            user_id="user123",
            permission=Permission.READ_USERS,
            granted_by="admin123",
            granted_at=datetime.utcnow()
        )
        assert not grant1.is_expired()
        
        # Expired grant
        grant2 = PermissionGrant(
            user_id="user123",
            permission=Permission.READ_USERS,
            granted_by="admin123",
            granted_at=datetime.utcnow(),
            expires_at=datetime.utcnow() - timedelta(days=1)
        )
        assert grant2.is_expired()
        
        # Future expiration
        grant3 = PermissionGrant(
            user_id="user123",
            permission=Permission.READ_USERS,
            granted_by="admin123",
            granted_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=1)
        )
        assert not grant3.is_expired()
    
    def test_to_from_dict(self):
        """Test converting permission grant to/from dictionary"""
        grant = PermissionGrant(
            user_id="user123",
            permission=Permission.READ_USERS,
            granted_by="admin123",
            granted_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            reason="Test reason"
        )
        
        grant_dict = grant.to_dict()
        restored_grant = PermissionGrant.from_dict(grant_dict)
        
        assert restored_grant.user_id == grant.user_id
        assert restored_grant.permission == grant.permission
        assert restored_grant.granted_by == grant.granted_by
        assert restored_grant.reason == grant.reason

class TestResourcePermission:
    """Test ResourcePermission class"""
    
    def test_resource_permission_creation(self):
        """Test creating a resource permission"""
        permissions = {Permission.READ_DEVICES, Permission.UPDATE_DEVICES}
        
        resource_perm = ResourcePermission(
            resource_type="device",
            resource_id="device123",
            user_id="user123",
            permissions=permissions,
            granted_by="admin123",
            granted_at=datetime.utcnow()
        )
        
        assert resource_perm.resource_type == "device"
        assert resource_perm.resource_id == "device123"
        assert resource_perm.user_id == "user123"
        assert resource_perm.permissions == permissions
        assert resource_perm.granted_by == "admin123"
        assert isinstance(resource_perm.granted_at, datetime)
    
    def test_has_permission(self):
        """Test permission checking for resource"""
        permissions = {Permission.READ_DEVICES, Permission.UPDATE_DEVICES}
        
        resource_perm = ResourcePermission(
            resource_type="device",
            resource_id="device123",
            user_id="user123",
            permissions=permissions,
            granted_by="admin123",
            granted_at=datetime.utcnow()
        )
        
        assert resource_perm.has_permission(Permission.READ_DEVICES)
        assert resource_perm.has_permission(Permission.UPDATE_DEVICES)
        assert not resource_perm.has_permission(Permission.DELETE_DEVICES)
    
    def test_is_expired(self):
        """Test expiration checking for resource permission"""
        permissions = {Permission.READ_DEVICES}
        
        # Non-expiring permission
        resource_perm1 = ResourcePermission(
            resource_type="device",
            resource_id="device123",
            user_id="user123",
            permissions=permissions,
            granted_by="admin123",
            granted_at=datetime.utcnow()
        )
        assert not resource_perm1.is_expired()
        
        # Expired permission
        resource_perm2 = ResourcePermission(
            resource_type="device",
            resource_id="device123",
            user_id="user123",
            permissions=permissions,
            granted_by="admin123",
            granted_at=datetime.utcnow(),
            expires_at=datetime.utcnow() - timedelta(days=1)
        )
        assert resource_perm2.is_expired()

class TestRoleHierarchy:
    """Test RoleHierarchy class"""
    
    def test_default_roles_initialization(self):
        """Test that default roles are initialized correctly"""
        hierarchy = RoleHierarchy()
        
        # Check that all default roles exist
        assert hierarchy.get_role("user") is not None
        assert hierarchy.get_role("operator") is not None
        assert hierarchy.get_role("admin") is not None
        assert hierarchy.get_role("super_admin") is not None
        
        # Check role inheritance
        operator_role = hierarchy.get_role("operator")
        assert operator_role.inherits_from == "user"
        
        admin_role = hierarchy.get_role("admin")
        assert admin_role.inherits_from == "operator"
        
        super_admin_role = hierarchy.get_role("super_admin")
        assert super_admin_role.inherits_from == "admin"
    
    def test_get_effective_permissions(self):
        """Test getting effective permissions with inheritance"""
        hierarchy = RoleHierarchy()
        
        # User permissions
        user_perms = hierarchy.get_effective_permissions("user")
        assert Permission.READ_DEVICES in user_perms
        assert Permission.API_READ in user_perms
        
        # Operator permissions (should include user permissions)
        operator_perms = hierarchy.get_effective_permissions("operator")
        assert Permission.READ_DEVICES in operator_perms  # From user
        assert Permission.CREATE_DEVICES in operator_perms  # Operator-specific
        assert Permission.API_WRITE in operator_perms
        
        # Admin permissions (should include operator and user permissions)
        admin_perms = hierarchy.get_effective_permissions("admin")
        assert Permission.READ_DEVICES in admin_perms  # From user
        assert Permission.CREATE_DEVICES in admin_perms  # From operator
        assert Permission.DELETE_USERS in admin_perms  # Admin-specific
        assert Permission.API_ADMIN in admin_perms
    
    def test_role_has_permission(self):
        """Test checking if role has permission"""
        hierarchy = RoleHierarchy()
        
        # User role
        assert hierarchy.role_has_permission("user", Permission.READ_DEVICES)
        assert not hierarchy.role_has_permission("user", Permission.CREATE_DEVICES)
        
        # Operator role (inherits from user)
        assert hierarchy.role_has_permission("operator", Permission.READ_DEVICES)  # Inherited
        assert hierarchy.role_has_permission("operator", Permission.CREATE_DEVICES)  # Own
        
        # Admin role (inherits from operator and user)
        assert hierarchy.role_has_permission("admin", Permission.READ_DEVICES)  # From user
        assert hierarchy.role_has_permission("admin", Permission.CREATE_DEVICES)  # From operator
        assert hierarchy.role_has_permission("admin", Permission.DELETE_USERS)  # Own
    
    def test_add_custom_role(self):
        """Test adding custom role"""
        hierarchy = RoleHierarchy()
        
        custom_permissions = {Permission.READ_DEVICES, Permission.VIEW_ANALYTICS}
        custom_role = RoleDefinition(
            name="custom_role",
            display_name="Custom Role",
            description="A custom role",
            permissions=custom_permissions,
            is_system_role=False
        )
        
        hierarchy.add_role(custom_role)
        
        retrieved_role = hierarchy.get_role("custom_role")
        assert retrieved_role is not None
        assert retrieved_role.name == "custom_role"
        assert not retrieved_role.is_system_role
    
    def test_remove_custom_role(self):
        """Test removing custom role"""
        hierarchy = RoleHierarchy()
        
        # Add custom role
        custom_permissions = {Permission.READ_DEVICES}
        custom_role = RoleDefinition(
            name="custom_role",
            display_name="Custom Role",
            description="A custom role",
            permissions=custom_permissions,
            is_system_role=False
        )
        hierarchy.add_role(custom_role)
        
        # Remove custom role
        success = hierarchy.remove_role("custom_role")
        assert success
        assert hierarchy.get_role("custom_role") is None
        
        # Cannot remove system role
        success = hierarchy.remove_role("admin")
        assert not success
        assert hierarchy.get_role("admin") is not None
    
    def test_get_role_hierarchy(self):
        """Test getting role hierarchy mapping"""
        hierarchy = RoleHierarchy()
        hierarchy_map = hierarchy.get_role_hierarchy()
        
        assert "user" in hierarchy_map
        assert "operator" in hierarchy_map["user"]
        assert "admin" in hierarchy_map["operator"]
        assert "super_admin" in hierarchy_map["admin"]
    
    def test_validate_role_hierarchy_no_cycles(self):
        """Test role hierarchy validation with no cycles"""
        hierarchy = RoleHierarchy()
        errors = hierarchy.validate_role_hierarchy()
        assert len(errors) == 0
    
    def test_validate_role_hierarchy_with_cycle(self):
        """Test role hierarchy validation with circular dependency"""
        hierarchy = RoleHierarchy()
        
        # Create circular dependency
        role_a = RoleDefinition(
            name="role_a",
            display_name="Role A",
            description="Role A",
            permissions={Permission.READ_DEVICES},
            inherits_from="role_b",
            is_system_role=False
        )
        
        role_b = RoleDefinition(
            name="role_b",
            display_name="Role B",
            description="Role B",
            permissions={Permission.READ_DEVICES},
            inherits_from="role_a",
            is_system_role=False
        )
        
        hierarchy.add_role(role_a)
        hierarchy.add_role(role_b)
        
        errors = hierarchy.validate_role_hierarchy()
        assert len(errors) > 0
        assert any("Circular dependency" in error for error in errors)

class TestPermissionCheckingUtilities:
    """Test permission checking utility functions"""
    
    def test_check_permission(self):
        """Test basic permission checking"""
        # Admin should have all permissions
        assert check_permission("admin", Permission.READ_USERS)
        assert check_permission("admin", Permission.DELETE_USERS)
        
        # User should have limited permissions
        assert check_permission("user", Permission.READ_DEVICES)
        assert not check_permission("user", Permission.DELETE_USERS)
        
        # With additional permissions
        additional_perms = [Permission.DELETE_USERS]
        assert check_permission("user", Permission.DELETE_USERS, additional_perms)
    
    def test_check_any_permission(self):
        """Test checking any of multiple permissions"""
        required_perms = [Permission.READ_USERS, Permission.CREATE_USERS]
        
        # Admin should have both
        assert check_any_permission("admin", required_perms)
        
        # User should have neither
        assert not check_any_permission("user", required_perms)
        
        # With additional permissions
        additional_perms = [Permission.READ_USERS]
        assert check_any_permission("user", required_perms, additional_perms)
    
    def test_check_all_permissions(self):
        """Test checking all required permissions"""
        required_perms = [Permission.READ_DEVICES, Permission.API_READ]
        
        # User should have both
        assert check_all_permissions("user", required_perms)
        
        # Test with permissions user doesn't have
        required_perms = [Permission.READ_DEVICES, Permission.DELETE_USERS]
        assert not check_all_permissions("user", required_perms)
        
        # Admin should have all
        assert check_all_permissions("admin", required_perms)
    
    def test_get_missing_permissions(self):
        """Test getting missing permissions"""
        required_perms = [Permission.READ_DEVICES, Permission.DELETE_USERS, Permission.API_READ]
        
        # User should be missing DELETE_USERS
        missing = get_missing_permissions("user", required_perms)
        assert Permission.DELETE_USERS in missing
        assert Permission.READ_DEVICES not in missing
        assert Permission.API_READ not in missing
        
        # Admin should have all
        missing = get_missing_permissions("admin", required_perms)
        assert len(missing) == 0
    
    def test_check_resource_permission(self):
        """Test resource-based permission checking"""
        # Admin should have access to any resource
        assert check_resource_permission(
            "user123", "admin", "device", "device123", Permission.READ_DEVICES
        )
        
        # User without resource permissions should not have access to admin-only permissions
        assert not check_resource_permission(
            "user123", "user", "device", "device123", Permission.DELETE_DEVICES
        )
        
        # Test with resource permissions
        resource_perms = [
            ResourcePermission(
                resource_type="device",
                resource_id="device123",
                user_id="user123",
                permissions={Permission.DELETE_DEVICES},
                granted_by="admin123",
                granted_at=datetime.utcnow()
            )
        ]
        
        assert check_resource_permission(
            "user123", "user", "device", "device123", Permission.DELETE_DEVICES, resource_perms
        )

class TestGlobalRoleHierarchy:
    """Test global role hierarchy instance"""
    
    def test_get_role_hierarchy_singleton(self):
        """Test that get_role_hierarchy returns singleton instance"""
        hierarchy1 = get_role_hierarchy()
        hierarchy2 = get_role_hierarchy()
        
        assert hierarchy1 is hierarchy2
    
    def test_global_hierarchy_has_default_roles(self):
        """Test that global hierarchy has default roles"""
        hierarchy = get_role_hierarchy()
        
        assert hierarchy.get_role("user") is not None
        assert hierarchy.get_role("operator") is not None
        assert hierarchy.get_role("admin") is not None
        assert hierarchy.get_role("super_admin") is not None

if __name__ == "__main__":
    pytest.main([__file__])
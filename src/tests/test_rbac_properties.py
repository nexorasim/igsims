"""
Property-based tests for RBAC system in iGSIM AI Agent Platform

These tests verify universal properties that should hold across all
valid inputs for the role-based access control system.

Requirements: 8.4 (Role-based access control)
"""

import pytest
from hypothesis import given, strategies as st, assume, settings
from datetime import datetime, timedelta
from typing import Set, List

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.rbac import (
    Permission, Role, RoleDefinition, PermissionGrant, ResourcePermission,
    RoleHierarchy, check_permission, check_any_permission, check_all_permissions,
    get_missing_permissions, check_resource_permission
)

# Hypothesis strategies for generating test data

@st.composite
def permission_strategy(draw):
    """Generate valid Permission enum values"""
    return draw(st.sampled_from(list(Permission)))

@st.composite
def permission_set_strategy(draw):
    """Generate sets of permissions"""
    permissions = draw(st.lists(permission_strategy(), min_size=0, max_size=10, unique=True))
    return set(permissions)

@st.composite
def role_name_strategy(draw):
    """Generate valid role names"""
    return draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='_-'),
        min_size=1,
        max_size=50
    ).filter(lambda x: x and not x.startswith('_') and not x.endswith('_')))

@st.composite
def role_definition_strategy(draw):
    """Generate RoleDefinition instances"""
    name = draw(role_name_strategy())
    display_name = draw(st.text(min_size=1, max_size=100))
    description = draw(st.text(max_size=500))
    permissions = draw(permission_set_strategy())
    inherits_from = draw(st.one_of(st.none(), role_name_strategy()))
    is_system_role = draw(st.booleans())
    
    return RoleDefinition(
        name=name,
        display_name=display_name,
        description=description,
        permissions=permissions,
        inherits_from=inherits_from,
        is_system_role=is_system_role
    )

@st.composite
def user_id_strategy(draw):
    """Generate user IDs"""
    return draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-'),
        min_size=1,
        max_size=50
    ))

@st.composite
def permission_grant_strategy(draw):
    """Generate PermissionGrant instances"""
    user_id = draw(user_id_strategy())
    permission = draw(permission_strategy())
    granted_by = draw(user_id_strategy())
    granted_at = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 12, 31)
    ))
    expires_at = draw(st.one_of(
        st.none(),
        st.datetimes(
            min_value=granted_at,
            max_value=datetime(2030, 12, 31)
        )
    ))
    reason = draw(st.one_of(st.none(), st.text(max_size=500)))
    
    return PermissionGrant(
        user_id=user_id,
        permission=permission,
        granted_by=granted_by,
        granted_at=granted_at,
        expires_at=expires_at,
        reason=reason
    )

@st.composite
def resource_permission_strategy(draw):
    """Generate ResourcePermission instances"""
    resource_type = draw(st.text(min_size=1, max_size=50))
    resource_id = draw(st.text(min_size=1, max_size=100))
    user_id = draw(user_id_strategy())
    permissions = draw(permission_set_strategy())
    assume(len(permissions) > 0)  # Must have at least one permission
    granted_by = draw(user_id_strategy())
    granted_at = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 12, 31)
    ))
    expires_at = draw(st.one_of(
        st.none(),
        st.datetimes(
            min_value=granted_at,
            max_value=datetime(2030, 12, 31)
        )
    ))
    
    return ResourcePermission(
        resource_type=resource_type,
        resource_id=resource_id,
        user_id=user_id,
        permissions=permissions,
        granted_by=granted_by,
        granted_at=granted_at,
        expires_at=expires_at
    )

class TestRoleDefinitionProperties:
    """Property-based tests for RoleDefinition"""
    
    @given(role_definition_strategy())
    def test_role_definition_serialization_roundtrip(self, role_def):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role definition, serializing to dict and back should preserve all data
        **Validates: Requirements 8.4**
        """
        # Convert to dict and back
        role_dict = role_def.to_dict()
        restored_role = RoleDefinition.from_dict(role_dict)
        
        # All fields should be preserved
        assert restored_role.name == role_def.name
        assert restored_role.display_name == role_def.display_name
        assert restored_role.description == role_def.description
        assert restored_role.permissions == role_def.permissions
        assert restored_role.inherits_from == role_def.inherits_from
        assert restored_role.is_system_role == role_def.is_system_role
    
    @given(role_definition_strategy(), permission_strategy())
    def test_permission_management_consistency(self, role_def, permission):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role and permission, adding and removing permissions should be consistent
        **Validates: Requirements 8.4**
        """
        original_permissions = role_def.permissions.copy()
        
        # Add permission
        role_def.add_permission(permission)
        assert role_def.has_permission(permission)
        
        # Remove permission
        role_def.remove_permission(permission)
        
        # If permission wasn't originally present, it should be gone
        if permission not in original_permissions:
            assert not role_def.has_permission(permission)
        else:
            # If it was originally present, it should still be gone after removal
            assert not role_def.has_permission(permission)
    
    @given(role_definition_strategy())
    def test_role_definition_timestamps(self, role_def):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role definition, timestamps should be valid and consistent
        **Validates: Requirements 8.4**
        """
        assert isinstance(role_def.created_at, datetime)
        assert isinstance(role_def.updated_at, datetime)
        assert role_def.created_at <= role_def.updated_at

class TestPermissionGrantProperties:
    """Property-based tests for PermissionGrant"""
    
    @given(permission_grant_strategy())
    def test_permission_grant_serialization_roundtrip(self, grant):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any permission grant, serializing to dict and back should preserve all data
        **Validates: Requirements 8.4**
        """
        grant_dict = grant.to_dict()
        restored_grant = PermissionGrant.from_dict(grant_dict)
        
        assert restored_grant.user_id == grant.user_id
        assert restored_grant.permission == grant.permission
        assert restored_grant.granted_by == grant.granted_by
        assert restored_grant.reason == grant.reason
        
        # Timestamps should be close (within 1 second due to serialization precision)
        assert abs((restored_grant.granted_at - grant.granted_at).total_seconds()) < 1
        
        if grant.expires_at:
            assert abs((restored_grant.expires_at - grant.expires_at).total_seconds()) < 1
        else:
            assert restored_grant.expires_at is None
    
    @given(permission_grant_strategy())
    def test_permission_grant_expiration_logic(self, grant):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any permission grant, expiration logic should be consistent with current time
        **Validates: Requirements 8.4**
        """
        current_time = datetime.utcnow()
        
        if grant.expires_at is None:
            # Non-expiring grants should never be expired
            assert not grant.is_expired()
        elif grant.expires_at > current_time:
            # Future expiration should not be expired
            assert not grant.is_expired()
        else:
            # Past expiration should be expired
            assert grant.is_expired()
    
    @given(user_id_strategy(), permission_strategy(), user_id_strategy())
    def test_permission_grant_creation_invariants(self, user_id, permission, granted_by):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any valid permission grant parameters, creation should succeed with valid timestamps
        **Validates: Requirements 8.4**
        """
        granted_at = datetime.utcnow()
        
        grant = PermissionGrant(
            user_id=user_id,
            permission=permission,
            granted_by=granted_by,
            granted_at=granted_at
        )
        
        assert grant.user_id == user_id
        assert grant.permission == permission
        assert grant.granted_by == granted_by
        assert grant.granted_at == granted_at
        assert grant.expires_at is None
        assert grant.reason is None

class TestResourcePermissionProperties:
    """Property-based tests for ResourcePermission"""
    
    @given(resource_permission_strategy())
    def test_resource_permission_serialization_roundtrip(self, resource_perm):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any resource permission, serializing to dict and back should preserve all data
        **Validates: Requirements 8.4**
        """
        perm_dict = resource_perm.to_dict()
        restored_perm = ResourcePermission.from_dict(perm_dict)
        
        assert restored_perm.resource_type == resource_perm.resource_type
        assert restored_perm.resource_id == resource_perm.resource_id
        assert restored_perm.user_id == resource_perm.user_id
        assert restored_perm.permissions == resource_perm.permissions
        assert restored_perm.granted_by == resource_perm.granted_by
    
    @given(resource_permission_strategy(), permission_strategy())
    def test_resource_permission_checking_consistency(self, resource_perm, permission):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any resource permission and permission, has_permission should be consistent with the permission set
        **Validates: Requirements 8.4**
        """
        has_permission = resource_perm.has_permission(permission)
        in_permission_set = permission in resource_perm.permissions
        
        assert has_permission == in_permission_set
    
    @given(resource_permission_strategy())
    def test_resource_permission_expiration_logic(self, resource_perm):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any resource permission, expiration logic should be consistent with current time
        **Validates: Requirements 8.4**
        """
        current_time = datetime.utcnow()
        
        if resource_perm.expires_at is None:
            assert not resource_perm.is_expired()
        elif resource_perm.expires_at > current_time:
            assert not resource_perm.is_expired()
        else:
            assert resource_perm.is_expired()

class TestRoleHierarchyProperties:
    """Property-based tests for RoleHierarchy"""
    
    @given(st.lists(role_definition_strategy(), min_size=1, max_size=10, unique_by=lambda x: x.name))
    def test_role_hierarchy_consistency(self, roles):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any set of roles, the hierarchy should maintain consistency after adding all roles
        **Validates: Requirements 8.4**
        """
        hierarchy = RoleHierarchy()
        
        # Add all roles
        for role in roles:
            hierarchy.add_role(role)
        
        # All roles should be retrievable
        for role in roles:
            retrieved_role = hierarchy.get_role(role.name)
            assert retrieved_role is not None
            assert retrieved_role.name == role.name
    
    @given(role_name_strategy(), permission_set_strategy())
    def test_effective_permissions_include_direct_permissions(self, role_name, permissions):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role, effective permissions should always include the role's direct permissions
        **Validates: Requirements 8.4**
        """
        hierarchy = RoleHierarchy()
        
        role = RoleDefinition(
            name=role_name,
            display_name=f"Test {role_name}",
            description="Test role",
            permissions=permissions,
            is_system_role=False
        )
        
        hierarchy.add_role(role)
        effective_permissions = hierarchy.get_effective_permissions(role_name)
        
        # All direct permissions should be in effective permissions
        assert permissions.issubset(effective_permissions)
    
    @settings(max_examples=50)  # Reduce examples for complex test
    @given(st.lists(role_definition_strategy(), min_size=2, max_size=5, unique_by=lambda x: x.name))
    def test_permission_inheritance_transitivity(self, roles):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role hierarchy, permission inheritance should be transitive
        **Validates: Requirements 8.4**
        """
        assume(len(roles) >= 2)
        
        hierarchy = RoleHierarchy()
        
        # Create a simple inheritance chain
        parent_role = roles[0]
        child_role = roles[1]
        child_role.inherits_from = parent_role.name
        
        hierarchy.add_role(parent_role)
        hierarchy.add_role(child_role)
        
        # Validate no circular dependencies
        errors = hierarchy.validate_role_hierarchy()
        assume(len(errors) == 0)
        
        parent_permissions = hierarchy.get_effective_permissions(parent_role.name)
        child_permissions = hierarchy.get_effective_permissions(child_role.name)
        
        # Child should have all parent permissions
        assert parent_permissions.issubset(child_permissions)

class TestPermissionCheckingProperties:
    """Property-based tests for permission checking utilities"""
    
    @given(st.sampled_from(["user", "operator", "admin", "super_admin"]), permission_strategy())
    def test_admin_has_all_permissions(self, role, permission):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any permission, admin role should always have access
        **Validates: Requirements 8.4**
        """
        admin_has_permission = check_permission("admin", permission)
        assert admin_has_permission
    
    @given(st.sampled_from(["user", "operator", "admin"]), st.lists(permission_strategy(), min_size=1, max_size=5))
    def test_check_any_permission_logic(self, role, permissions):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role and list of permissions, check_any_permission should return true if any individual permission check returns true
        **Validates: Requirements 8.4**
        """
        individual_checks = [check_permission(role, perm) for perm in permissions]
        any_check_result = check_any_permission(role, permissions)
        
        assert any_check_result == any(individual_checks)
    
    @given(st.sampled_from(["user", "operator", "admin"]), st.lists(permission_strategy(), min_size=1, max_size=5))
    def test_check_all_permissions_logic(self, role, permissions):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role and list of permissions, check_all_permissions should return true only if all individual permission checks return true
        **Validates: Requirements 8.4**
        """
        individual_checks = [check_permission(role, perm) for perm in permissions]
        all_check_result = check_all_permissions(role, permissions)
        
        assert all_check_result == all(individual_checks)
    
    @given(st.sampled_from(["user", "operator", "admin"]), st.lists(permission_strategy(), min_size=1, max_size=5))
    def test_missing_permissions_consistency(self, role, permissions):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any role and list of permissions, missing permissions should be exactly those that fail individual checks
        **Validates: Requirements 8.4**
        """
        missing_permissions = get_missing_permissions(role, permissions)
        
        for perm in permissions:
            has_permission = check_permission(role, perm)
            is_missing = perm in missing_permissions
            
            # Permission should be missing if and only if the check fails
            assert is_missing == (not has_permission)
    
    @given(
        user_id_strategy(),
        st.sampled_from(["user", "operator", "admin"]),
        st.text(min_size=1, max_size=50),
        st.text(min_size=1, max_size=100),
        permission_strategy(),
        st.lists(resource_permission_strategy(), max_size=3)
    )
    def test_resource_permission_fallback_to_role(self, user_id, role, resource_type, resource_id, permission, resource_permissions):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any resource permission check, if role-based permission succeeds, result should be true regardless of resource permissions
        **Validates: Requirements 8.4**
        """
        role_has_permission = check_permission(role, permission)
        
        result = check_resource_permission(
            user_id, role, resource_type, resource_id, permission, resource_permissions
        )
        
        # If role has permission, result should always be true
        if role_has_permission:
            assert result

class TestRBACSystemProperties:
    """System-level property tests for RBAC"""
    
    @given(
        st.lists(permission_strategy(), min_size=1, max_size=10, unique=True),
        st.lists(permission_strategy(), min_size=1, max_size=10, unique=True)
    )
    def test_permission_set_operations(self, permissions1, permissions2):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any two sets of permissions, set operations should behave consistently
        **Validates: Requirements 8.4**
        """
        set1 = set(permissions1)
        set2 = set(permissions2)
        
        # Union should contain all permissions from both sets
        union = set1 | set2
        assert set1.issubset(union)
        assert set2.issubset(union)
        
        # Intersection should be subset of both sets
        intersection = set1 & set2
        assert intersection.issubset(set1)
        assert intersection.issubset(set2)
        
        # Difference should not contain any permissions from the other set
        difference = set1 - set2
        assert difference.isdisjoint(set2)
    
    @given(permission_grant_strategy())
    def test_permission_grant_temporal_consistency(self, grant):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any permission grant, granted_at should be before or equal to expires_at
        **Validates: Requirements 8.4**
        """
        if grant.expires_at is not None:
            assert grant.granted_at <= grant.expires_at
    
    @given(resource_permission_strategy())
    def test_resource_permission_temporal_consistency(self, resource_perm):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any resource permission, granted_at should be before or equal to expires_at
        **Validates: Requirements 8.4**
        """
        if resource_perm.expires_at is not None:
            assert resource_perm.granted_at <= resource_perm.expires_at
    
    @settings(max_examples=20)  # Reduce examples for expensive test
    @given(st.lists(role_definition_strategy(), min_size=1, max_size=5, unique_by=lambda x: x.name))
    def test_role_hierarchy_acyclic_property(self, roles):
        """
        Feature: igsim-ai-agent-platform, Property 29: Role-Based Access Control
        For any set of roles, adding them to hierarchy should not create cycles if inheritance is properly managed
        **Validates: Requirements 8.4**
        """
        hierarchy = RoleHierarchy()
        
        # Add roles without inheritance first
        for role in roles:
            role_copy = RoleDefinition(
                name=role.name,
                display_name=role.display_name,
                description=role.description,
                permissions=role.permissions,
                inherits_from=None,  # No inheritance initially
                is_system_role=role.is_system_role
            )
            hierarchy.add_role(role_copy)
        
        # Hierarchy should be valid without inheritance
        errors = hierarchy.validate_role_hierarchy()
        assert len(errors) == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
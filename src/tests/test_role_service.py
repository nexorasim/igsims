"""
Unit tests for Role Service in iGSIM AI Agent Platform

Tests the role management service including role CRUD operations,
permission management, and access control validation.

Requirements: 8.4 (Role-based access control)
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.rbac import Permission, RoleDefinition, PermissionGrant, ResourcePermission
from models.user import User
from services.role_service import RoleService, get_role_service

class TestRoleService:
    """Test RoleService class"""
    
    @pytest.fixture
    def mock_dependencies(self):
        """Mock external dependencies"""
        with patch('services.role_service.firestore.Client') as mock_firestore, \
             patch('services.role_service.UserRepository') as mock_user_repo, \
             patch('services.role_service.get_role_hierarchy') as mock_hierarchy:
            
            # Mock Firestore
            mock_db = Mock()
            mock_firestore.return_value = mock_db
            
            # Mock UserRepository
            mock_repo = Mock()
            mock_user_repo.return_value = mock_repo
            
            # Mock RoleHierarchy
            mock_role_hierarchy = Mock()
            mock_hierarchy.return_value = mock_role_hierarchy
            
            yield {
                'db': mock_db,
                'user_repository': mock_repo,
                'role_hierarchy': mock_role_hierarchy
            }
    
    @pytest.fixture
    def role_service(self, mock_dependencies):
        """Create RoleService instance with mocked dependencies"""
        return RoleService()
    
    @pytest.fixture
    def admin_user(self):
        """Create admin user for testing"""
        return User(
            user_id="admin123",
            email="admin@test.com",
            display_name="Admin User",
            role="admin",
            permissions=["manage_permissions", "manage_user_roles"]
        )
    
    @pytest.fixture
    def regular_user(self):
        """Create regular user for testing"""
        return User(
            user_id="user123",
            email="user@test.com",
            display_name="Regular User",
            role="user",
            permissions=["read_devices"]
        )
    
    @pytest.fixture
    def test_role_data(self):
        """Test role data"""
        return {
            'name': 'test_role',
            'display_name': 'Test Role',
            'description': 'A test role',
            'permissions': ['read_devices', 'create_devices']
        }

class TestRoleManagement(TestRoleService):
    """Test role management operations"""
    
    @pytest.mark.asyncio
    async def test_create_role_success(self, role_service, mock_dependencies, admin_user, test_role_data):
        """Test successful role creation"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        mock_dependencies['role_hierarchy'].get_role.return_value = None  # Role doesn't exist
        mock_dependencies['role_hierarchy'].validate_role_hierarchy.return_value = []  # No errors
        
        with patch.object(role_service, '_save_role_to_db', new_callable=AsyncMock) as mock_save:
            # Test role creation
            role = await role_service.create_role(test_role_data, admin_user.user_id)
            
            assert role.name == 'test_role'
            assert role.display_name == 'Test Role'
            assert role.description == 'A test role'
            assert Permission.READ_DEVICES in role.permissions
            assert Permission.CREATE_DEVICES in role.permissions
            assert not role.is_system_role
            
            # Verify role was added to hierarchy and saved
            mock_dependencies['role_hierarchy'].add_role.assert_called_once()
            mock_save.assert_called_once_with(role)
    
    @pytest.mark.asyncio
    async def test_create_role_permission_denied(self, role_service, mock_dependencies, regular_user, test_role_data):
        """Test role creation with insufficient permissions"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=regular_user)
        
        # Test permission denial
        with pytest.raises(PermissionError, match="Insufficient permissions"):
            await role_service.create_role(test_role_data, regular_user.user_id)
    
    @pytest.mark.asyncio
    async def test_create_role_already_exists(self, role_service, mock_dependencies, admin_user, test_role_data):
        """Test role creation when role already exists"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        existing_role = Mock()
        mock_dependencies['role_hierarchy'].get_role.return_value = existing_role
        
        # Test role already exists
        with pytest.raises(ValueError, match="already exists"):
            await role_service.create_role(test_role_data, admin_user.user_id)
    
    @pytest.mark.asyncio
    async def test_create_role_hierarchy_validation_error(self, role_service, mock_dependencies, admin_user, test_role_data):
        """Test role creation with hierarchy validation error"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        mock_dependencies['role_hierarchy'].get_role.return_value = None
        mock_dependencies['role_hierarchy'].validate_role_hierarchy.return_value = ["Circular dependency"]
        
        # Test hierarchy validation error
        with pytest.raises(ValueError, match="Role hierarchy validation failed"):
            await role_service.create_role(test_role_data, admin_user.user_id)
    
    @pytest.mark.asyncio
    async def test_update_role_success(self, role_service, mock_dependencies, admin_user):
        """Test successful role update"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        
        existing_role = RoleDefinition(
            name="test_role",
            display_name="Old Display Name",
            description="Old description",
            permissions={Permission.READ_DEVICES},
            is_system_role=False
        )
        mock_dependencies['role_hierarchy'].get_role.return_value = existing_role
        mock_dependencies['role_hierarchy'].validate_role_hierarchy.return_value = []
        
        updates = {
            'display_name': 'New Display Name',
            'description': 'New description',
            'permissions': ['read_devices', 'create_devices']
        }
        
        with patch.object(role_service, '_save_role_to_db', new_callable=AsyncMock) as mock_save:
            # Test role update
            role = await role_service.update_role("test_role", updates, admin_user.user_id)
            
            assert role.display_name == 'New Display Name'
            assert role.description == 'New description'
            assert Permission.CREATE_DEVICES in role.permissions
            
            mock_save.assert_called_once_with(role)
    
    @pytest.mark.asyncio
    async def test_update_system_role_denied(self, role_service, mock_dependencies, admin_user):
        """Test updating system role is denied"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        
        system_role = RoleDefinition(
            name="admin",
            display_name="Administrator",
            description="System admin role",
            permissions={Permission.MANAGE_PERMISSIONS},
            is_system_role=True
        )
        mock_dependencies['role_hierarchy'].get_role.return_value = system_role
        
        # Test system role update denial
        with pytest.raises(ValueError, match="Cannot update system roles"):
            await role_service.update_role("admin", {'display_name': 'New Name'}, admin_user.user_id)
    
    @pytest.mark.asyncio
    async def test_delete_role_success(self, role_service, mock_dependencies, admin_user):
        """Test successful role deletion"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        mock_dependencies['user_repository'].get_users_by_role = AsyncMock(return_value=[])
        
        custom_role = RoleDefinition(
            name="custom_role",
            display_name="Custom Role",
            description="A custom role",
            permissions={Permission.READ_DEVICES},
            is_system_role=False
        )
        mock_dependencies['role_hierarchy'].get_role.return_value = custom_role
        mock_dependencies['role_hierarchy'].remove_role.return_value = True
        
        with patch.object(role_service, '_delete_role_from_db', new_callable=AsyncMock) as mock_delete:
            # Test role deletion
            success = await role_service.delete_role("custom_role", admin_user.user_id)
            
            assert success
            mock_dependencies['role_hierarchy'].remove_role.assert_called_once_with("custom_role")
            mock_delete.assert_called_once_with("custom_role")
    
    @pytest.mark.asyncio
    async def test_delete_role_in_use(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test deleting role that is in use"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        mock_dependencies['user_repository'].get_users_by_role = AsyncMock(return_value=[regular_user])
        
        custom_role = RoleDefinition(
            name="custom_role",
            display_name="Custom Role",
            description="A custom role",
            permissions={Permission.READ_DEVICES},
            is_system_role=False
        )
        mock_dependencies['role_hierarchy'].get_role.return_value = custom_role
        
        # Test role deletion failure when in use
        with pytest.raises(ValueError, match="Cannot delete role.*users have this role"):
            await role_service.delete_role("custom_role", admin_user.user_id)

class TestUserRoleManagement(TestRoleService):
    """Test user role management operations"""
    
    @pytest.mark.asyncio
    async def test_assign_role_to_user_success(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test successful role assignment"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, regular_user])
        mock_dependencies['user_repository'].update = AsyncMock()
        
        operator_role = Mock()
        mock_dependencies['role_hierarchy'].get_role.return_value = operator_role
        mock_dependencies['role_hierarchy'].get_effective_permissions.return_value = {Permission.READ_DEVICES, Permission.CREATE_DEVICES}
        
        # Test role assignment
        success = await role_service.assign_role_to_user(
            regular_user.user_id, 
            "operator", 
            admin_user.user_id
        )
        
        assert success
        mock_dependencies['user_repository'].update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_assign_role_permission_denied(self, role_service, mock_dependencies, regular_user):
        """Test role assignment with insufficient permissions"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=regular_user)
        
        # Test permission denial
        with pytest.raises(PermissionError, match="Insufficient permissions"):
            await role_service.assign_role_to_user("user456", "operator", regular_user.user_id)
    
    @pytest.mark.asyncio
    async def test_assign_role_user_not_found(self, role_service, mock_dependencies, admin_user):
        """Test role assignment when user not found"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, None])
        
        # Test user not found
        with pytest.raises(ValueError, match="User.*not found"):
            await role_service.assign_role_to_user("nonexistent", "operator", admin_user.user_id)
    
    @pytest.mark.asyncio
    async def test_assign_role_role_not_found(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test role assignment when role not found"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, regular_user])
        mock_dependencies['role_hierarchy'].get_role.return_value = None
        
        # Test role not found
        with pytest.raises(ValueError, match="Role.*not found"):
            await role_service.assign_role_to_user(regular_user.user_id, "nonexistent", admin_user.user_id)

class TestPermissionManagement(TestRoleService):
    """Test permission management operations"""
    
    @pytest.mark.asyncio
    async def test_grant_permission_success(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test successful permission grant"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, regular_user])
        mock_dependencies['user_repository'].update = AsyncMock()
        
        with patch.object(role_service, '_save_permission_grant_to_db', new_callable=AsyncMock) as mock_save:
            # Test permission grant
            grant = await role_service.grant_permission_to_user(
                regular_user.user_id,
                Permission.CREATE_DEVICES,
                admin_user.user_id,
                reason="Testing purposes"
            )
            
            assert grant.user_id == regular_user.user_id
            assert grant.permission == Permission.CREATE_DEVICES
            assert grant.granted_by == admin_user.user_id
            assert grant.reason == "Testing purposes"
            
            mock_save.assert_called_once_with(grant)
            mock_dependencies['user_repository'].update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_grant_permission_with_expiration(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test permission grant with expiration"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, regular_user])
        mock_dependencies['user_repository'].update = AsyncMock()
        
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        with patch.object(role_service, '_save_permission_grant_to_db', new_callable=AsyncMock):
            # Test permission grant with expiration
            grant = await role_service.grant_permission_to_user(
                regular_user.user_id,
                Permission.CREATE_DEVICES,
                admin_user.user_id,
                expires_at=expires_at
            )
            
            assert grant.expires_at == expires_at
    
    @pytest.mark.asyncio
    async def test_revoke_permission_success(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test successful permission revocation"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, regular_user])
        mock_dependencies['user_repository'].update = AsyncMock()
        mock_dependencies['role_hierarchy'].get_effective_permissions.return_value = {Permission.READ_DEVICES}
        
        # Add permission to user
        regular_user.permissions.append("create_devices")
        
        with patch.object(role_service, '_delete_permission_grants_from_db', new_callable=AsyncMock) as mock_delete:
            # Test permission revocation
            success = await role_service.revoke_permission_from_user(
                regular_user.user_id,
                Permission.CREATE_DEVICES,
                admin_user.user_id
            )
            
            assert success
            assert "create_devices" not in regular_user.permissions
            mock_delete.assert_called_once_with(regular_user.user_id, Permission.CREATE_DEVICES)
    
    @pytest.mark.asyncio
    async def test_revoke_role_based_permission_denied(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test revoking role-based permission is denied"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, regular_user])
        mock_dependencies['role_hierarchy'].get_effective_permissions.return_value = {Permission.READ_DEVICES}
        
        # Test revoking role-based permission
        with pytest.raises(ValueError, match="Cannot revoke role-based permission"):
            await role_service.revoke_permission_from_user(
                regular_user.user_id,
                Permission.READ_DEVICES,  # This is a role-based permission for user
                admin_user.user_id
            )
    
    @pytest.mark.asyncio
    async def test_get_user_permissions(self, role_service, mock_dependencies, regular_user):
        """Test getting user permissions"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=regular_user)
        mock_dependencies['role_hierarchy'].get_effective_permissions.return_value = {Permission.READ_DEVICES, Permission.API_READ}
        
        mock_grants = [
            PermissionGrant(
                user_id=regular_user.user_id,
                permission=Permission.CREATE_DEVICES,
                granted_by="admin123",
                granted_at=datetime.utcnow()
            )
        ]
        
        with patch.object(role_service, '_get_permission_grants_from_db', new_callable=AsyncMock, return_value=mock_grants):
            # Test getting user permissions
            permissions = await role_service.get_user_permissions(regular_user.user_id)
            
            assert permissions['user_id'] == regular_user.user_id
            assert permissions['role'] == regular_user.role
            assert 'read_devices' in permissions['role_permissions']
            assert 'api_read' in permissions['role_permissions']
            assert 'create_devices' in permissions['additional_permissions']
            assert 'create_devices' in permissions['all_permissions']

class TestResourcePermissions(TestRoleService):
    """Test resource permission management"""
    
    @pytest.mark.asyncio
    async def test_grant_resource_permission_success(self, role_service, mock_dependencies, admin_user, regular_user):
        """Test successful resource permission grant"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(side_effect=[admin_user, regular_user])
        
        permissions = {Permission.READ_DEVICES, Permission.UPDATE_DEVICES}
        
        with patch.object(role_service, '_save_resource_permission_to_db', new_callable=AsyncMock) as mock_save:
            # Test resource permission grant
            resource_perm = await role_service.grant_resource_permission(
                regular_user.user_id,
                "device",
                "device123",
                permissions,
                admin_user.user_id
            )
            
            assert resource_perm.user_id == regular_user.user_id
            assert resource_perm.resource_type == "device"
            assert resource_perm.resource_id == "device123"
            assert resource_perm.permissions == permissions
            assert resource_perm.granted_by == admin_user.user_id
            
            mock_save.assert_called_once_with(resource_perm)
    
    @pytest.mark.asyncio
    async def test_revoke_resource_permission_success(self, role_service, mock_dependencies, admin_user):
        """Test successful resource permission revocation"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=admin_user)
        
        with patch.object(role_service, '_delete_resource_permission_from_db', new_callable=AsyncMock) as mock_delete:
            # Test resource permission revocation
            success = await role_service.revoke_resource_permission(
                "user123",
                "device",
                "device123",
                admin_user.user_id
            )
            
            assert success
            mock_delete.assert_called_once_with("user123", "device", "device123")

class TestPermissionChecking(TestRoleService):
    """Test permission checking operations"""
    
    @pytest.mark.asyncio
    async def test_check_user_permission_role_based(self, role_service, mock_dependencies, regular_user):
        """Test checking user permission (role-based)"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=regular_user)
        
        with patch('services.role_service.check_permission', return_value=True) as mock_check:
            # Test permission check
            has_permission = await role_service.check_user_permission(
                regular_user.user_id,
                Permission.READ_DEVICES
            )
            
            assert has_permission
            mock_check.assert_called_once_with(regular_user.role, Permission.READ_DEVICES)
    
    @pytest.mark.asyncio
    async def test_check_user_permission_additional_grants(self, role_service, mock_dependencies, regular_user):
        """Test checking user permission (additional grants)"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=regular_user)
        
        mock_grants = [
            PermissionGrant(
                user_id=regular_user.user_id,
                permission=Permission.CREATE_DEVICES,
                granted_by="admin123",
                granted_at=datetime.utcnow()
            )
        ]
        
        with patch('services.role_service.check_permission', return_value=False), \
             patch.object(role_service, '_get_permission_grants_from_db', new_callable=AsyncMock, return_value=mock_grants):
            
            # Test permission check with additional grants
            has_permission = await role_service.check_user_permission(
                regular_user.user_id,
                Permission.CREATE_DEVICES
            )
            
            assert has_permission
    
    @pytest.mark.asyncio
    async def test_check_user_permission_expired_grant(self, role_service, mock_dependencies, regular_user):
        """Test checking user permission with expired grant"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=regular_user)
        
        expired_grant = PermissionGrant(
            user_id=regular_user.user_id,
            permission=Permission.CREATE_DEVICES,
            granted_by="admin123",
            granted_at=datetime.utcnow(),
            expires_at=datetime.utcnow() - timedelta(days=1)  # Expired
        )
        
        with patch('services.role_service.check_permission', return_value=False), \
             patch.object(role_service, '_get_permission_grants_from_db', new_callable=AsyncMock, return_value=[expired_grant]):
            
            # Test permission check with expired grant
            has_permission = await role_service.check_user_permission(
                regular_user.user_id,
                Permission.CREATE_DEVICES
            )
            
            assert not has_permission
    
    @pytest.mark.asyncio
    async def test_check_user_resource_permission(self, role_service, mock_dependencies, regular_user):
        """Test checking user resource permission"""
        # Setup mocks
        mock_dependencies['user_repository'].get = AsyncMock(return_value=regular_user)
        
        resource_perm = ResourcePermission(
            resource_type="device",
            resource_id="device123",
            user_id=regular_user.user_id,
            permissions={Permission.UPDATE_DEVICES},
            granted_by="admin123",
            granted_at=datetime.utcnow()
        )
        
        with patch('services.role_service.check_permission', return_value=False), \
             patch.object(role_service, '_get_resource_permissions_from_db', new_callable=AsyncMock, return_value=[resource_perm]):
            
            # Test resource permission check
            has_permission = await role_service.check_user_resource_permission(
                regular_user.user_id,
                "device",
                "device123",
                Permission.UPDATE_DEVICES
            )
            
            assert has_permission

class TestCleanupOperations(TestRoleService):
    """Test cleanup operations"""
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_permissions(self, role_service, mock_dependencies):
        """Test cleaning up expired permissions"""
        # Mock Firestore collections and documents
        mock_grants_collection = Mock()
        mock_resource_collection = Mock()
        mock_dependencies['db'].collection.side_effect = [mock_grants_collection, mock_resource_collection]
        
        # Mock expired grant
        expired_grant_doc = Mock()
        expired_grant_doc.to_dict.return_value = {
            'user_id': 'user123',
            'permission': 'create_devices',
            'granted_by': 'admin123',
            'granted_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() - timedelta(days=1)).isoformat()
        }
        expired_grant_doc.reference.delete = Mock()
        
        # Mock valid grant
        valid_grant_doc = Mock()
        valid_grant_doc.to_dict.return_value = {
            'user_id': 'user123',
            'permission': 'read_devices',
            'granted_by': 'admin123',
            'granted_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(days=1)).isoformat()
        }
        
        mock_grants_collection.stream.return_value = [expired_grant_doc, valid_grant_doc]
        mock_resource_collection.stream.return_value = []
        
        # Test cleanup
        count = await role_service.cleanup_expired_permissions()
        
        assert count == 1
        expired_grant_doc.reference.delete.assert_called_once()

class TestGlobalRoleService:
    """Test global role service instance"""
    
    def test_get_role_service_singleton(self):
        """Test that get_role_service returns singleton instance"""
        service1 = get_role_service()
        service2 = get_role_service()
        
        assert service1 is service2
    
    def test_get_role_service_returns_role_service(self):
        """Test that get_role_service returns RoleService instance"""
        service = get_role_service()
        assert isinstance(service, RoleService)

if __name__ == "__main__":
    pytest.main([__file__])
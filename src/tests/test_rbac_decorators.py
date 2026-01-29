"""
Unit tests for RBAC decorators and middleware in iGSIM AI Agent Platform

Tests the permission checking decorators, middleware, and utility functions
for role-based access control.

Requirements: 8.4 (Role-based access control)
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.rbac import Permission
from models.user import User
from utils.rbac_decorators import (
    RBACError, require_permission, require_any_permission, require_all_permissions,
    require_role, require_any_role, require_admin, require_admin_or_self,
    RBACMiddleware, check_user_has_permission, check_user_has_any_permission,
    check_user_has_all_permissions, get_user_missing_permissions, rbac_logger
)

class TestRBACError:
    """Test RBACError exception"""
    
    def test_rbac_error_default_status(self):
        """Test RBACError with default status code"""
        error = RBACError("Permission denied")
        assert error.status_code == 403
        assert error.detail == "Permission denied"
    
    def test_rbac_error_custom_status(self):
        """Test RBACError with custom status code"""
        error = RBACError("Unauthorized", status_code=401)
        assert error.status_code == 401
        assert error.detail == "Unauthorized"

class TestPermissionDecorators:
    """Test permission checking decorators"""
    
    @pytest.fixture
    def admin_user(self):
        """Create admin user for testing"""
        return User(
            user_id="admin123",
            email="admin@test.com",
            display_name="Admin User",
            role="admin",
            permissions=["manage_permissions", "read_users"]
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
    def mock_role_service(self):
        """Mock role service"""
        return Mock()
    
    @pytest.mark.asyncio
    async def test_require_permission_success(self, admin_user, mock_role_service):
        """Test require_permission decorator with sufficient permissions"""
        mock_role_service.check_user_permission = AsyncMock(return_value=True)
        
        # Create dependency function
        permission_dep = require_permission(Permission.READ_USERS)
        
        # Test with admin user
        result = await permission_dep(admin_user, mock_role_service)
        assert result == admin_user
        
        mock_role_service.check_user_permission.assert_called_once_with(
            admin_user.user_id, Permission.READ_USERS
        )
    
    @pytest.mark.asyncio
    async def test_require_permission_denied(self, regular_user, mock_role_service):
        """Test require_permission decorator with insufficient permissions"""
        mock_role_service.check_user_permission = AsyncMock(return_value=False)
        
        # Create dependency function
        permission_dep = require_permission(Permission.MANAGE_PERMISSIONS)
        
        # Test with regular user
        with pytest.raises(RBACError, match="Permission denied: manage_permissions required"):
            await permission_dep(regular_user, mock_role_service)
    
    @pytest.mark.asyncio
    async def test_require_any_permission_success(self, admin_user, mock_role_service):
        """Test require_any_permission decorator with one sufficient permission"""
        mock_role_service.check_user_permission = AsyncMock(side_effect=[False, True])
        
        permissions = [Permission.CREATE_USERS, Permission.READ_USERS]
        permission_dep = require_any_permission(permissions)
        
        result = await permission_dep(admin_user, mock_role_service)
        assert result == admin_user
    
    @pytest.mark.asyncio
    async def test_require_any_permission_denied(self, regular_user, mock_role_service):
        """Test require_any_permission decorator with no sufficient permissions"""
        mock_role_service.check_user_permission = AsyncMock(return_value=False)
        
        permissions = [Permission.CREATE_USERS, Permission.DELETE_USERS]
        permission_dep = require_any_permission(permissions)
        
        with pytest.raises(RBACError, match="Permission denied: One of"):
            await permission_dep(regular_user, mock_role_service)
    
    @pytest.mark.asyncio
    async def test_require_all_permissions_success(self, admin_user, mock_role_service):
        """Test require_all_permissions decorator with all permissions"""
        mock_role_service.check_user_permission = AsyncMock(return_value=True)
        
        permissions = [Permission.READ_USERS, Permission.CREATE_USERS]
        permission_dep = require_all_permissions(permissions)
        
        result = await permission_dep(admin_user, mock_role_service)
        assert result == admin_user
        
        # Should check all permissions
        assert mock_role_service.check_user_permission.call_count == 2
    
    @pytest.mark.asyncio
    async def test_require_all_permissions_denied(self, regular_user, mock_role_service):
        """Test require_all_permissions decorator with missing permissions"""
        mock_role_service.check_user_permission = AsyncMock(side_effect=[True, False])
        
        permissions = [Permission.READ_DEVICES, Permission.CREATE_DEVICES]
        permission_dep = require_all_permissions(permissions)
        
        with pytest.raises(RBACError, match="Permission denied: Missing permissions"):
            await permission_dep(regular_user, mock_role_service)

class TestRoleDecorators:
    """Test role checking decorators"""
    
    @pytest.fixture
    def admin_user(self):
        return User(
            user_id="admin123",
            email="admin@test.com",
            display_name="Admin User",
            role="admin"
        )
    
    @pytest.fixture
    def operator_user(self):
        return User(
            user_id="operator123",
            email="operator@test.com",
            display_name="Operator User",
            role="operator"
        )
    
    @pytest.fixture
    def regular_user(self):
        return User(
            user_id="user123",
            email="user@test.com",
            display_name="Regular User",
            role="user"
        )
    
    @pytest.mark.asyncio
    async def test_require_role_success(self, operator_user):
        """Test require_role decorator with correct role"""
        role_dep = require_role("operator")
        result = await role_dep(operator_user)
        assert result == operator_user
    
    @pytest.mark.asyncio
    async def test_require_role_admin_bypass(self, admin_user):
        """Test require_role decorator with admin bypass"""
        role_dep = require_role("operator")
        result = await role_dep(admin_user)
        assert result == admin_user
    
    @pytest.mark.asyncio
    async def test_require_role_denied(self, regular_user):
        """Test require_role decorator with insufficient role"""
        role_dep = require_role("operator")
        
        with pytest.raises(RBACError, match="Role 'operator' required"):
            await role_dep(regular_user)
    
    @pytest.mark.asyncio
    async def test_require_any_role_success(self, operator_user):
        """Test require_any_role decorator with one matching role"""
        roles = ["operator", "admin"]
        role_dep = require_any_role(roles)
        result = await role_dep(operator_user)
        assert result == operator_user
    
    @pytest.mark.asyncio
    async def test_require_any_role_denied(self, regular_user):
        """Test require_any_role decorator with no matching roles"""
        roles = ["operator", "manager"]
        role_dep = require_any_role(roles)
        
        with pytest.raises(RBACError, match="One of roles"):
            await role_dep(regular_user)
    
    @pytest.mark.asyncio
    async def test_require_admin_success(self, admin_user):
        """Test require_admin decorator with admin user"""
        admin_dep = require_admin()
        result = await admin_dep(admin_user)
        assert result == admin_user
    
    @pytest.mark.asyncio
    async def test_require_admin_denied(self, regular_user):
        """Test require_admin decorator with non-admin user"""
        admin_dep = require_admin()
        
        with pytest.raises(RBACError, match="Role 'admin' required"):
            await admin_dep(regular_user)

class TestAdminOrSelfDecorator:
    """Test admin or self access decorator"""
    
    @pytest.fixture
    def admin_user(self):
        return User(
            user_id="admin123",
            email="admin@test.com",
            display_name="Admin User",
            role="admin"
        )
    
    @pytest.fixture
    def regular_user(self):
        return User(
            user_id="user123",
            email="user@test.com",
            display_name="Regular User",
            role="user"
        )
    
    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI request"""
        request = Mock(spec=Request)
        request.path_params = {}
        return request
    
    @pytest.mark.asyncio
    async def test_require_admin_or_self_admin_access(self, mock_request, admin_user):
        """Test admin can access any user"""
        mock_request.path_params = {"user_id": "other_user"}
        
        admin_or_self_dep = require_admin_or_self("user_id")
        result = await admin_or_self_dep(mock_request, admin_user)
        assert result == admin_user
    
    @pytest.mark.asyncio
    async def test_require_admin_or_self_self_access(self, mock_request, regular_user):
        """Test user can access own resources"""
        mock_request.path_params = {"user_id": regular_user.user_id}
        
        admin_or_self_dep = require_admin_or_self("user_id")
        result = await admin_or_self_dep(mock_request, regular_user)
        assert result == regular_user
    
    @pytest.mark.asyncio
    async def test_require_admin_or_self_denied(self, mock_request, regular_user):
        """Test user cannot access other users"""
        mock_request.path_params = {"user_id": "other_user"}
        
        admin_or_self_dep = require_admin_or_self("user_id")
        
        with pytest.raises(RBACError, match="Access denied"):
            await admin_or_self_dep(mock_request, regular_user)
    
    @pytest.mark.asyncio
    async def test_require_admin_or_self_missing_param(self, mock_request, regular_user):
        """Test error when user ID parameter is missing"""
        mock_request.path_params = {}
        
        admin_or_self_dep = require_admin_or_self("user_id")
        
        with pytest.raises(RBACError, match="User ID parameter 'user_id' not found"):
            await admin_or_self_dep(mock_request, regular_user)

class TestRBACMiddleware:
    """Test RBAC middleware"""
    
    @pytest.fixture
    def middleware(self):
        """Create RBAC middleware instance"""
        with patch('utils.rbac_decorators.get_role_service'), \
             patch('utils.rbac_decorators.get_auth_service'):
            return RBACMiddleware()
    
    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI request"""
        request = Mock(spec=Request)
        request.url.path = "/api/test"
        request.method = "GET"
        request.headers = {}
        request.state = Mock()
        return request
    
    @pytest.fixture
    def mock_call_next(self):
        """Mock call_next function"""
        async def call_next(request):
            response = Mock()
            response.status_code = 200
            return response
        return call_next
    
    @pytest.mark.asyncio
    async def test_middleware_public_endpoint(self, middleware, mock_call_next):
        """Test middleware skips public endpoints"""
        request = Mock(spec=Request)
        request.url.path = "/docs"
        
        response = await middleware(request, mock_call_next)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_middleware_with_user(self, middleware, mock_request, mock_call_next):
        """Test middleware with authenticated user"""
        user = User(
            user_id="user123",
            email="user@test.com",
            display_name="Test User",
            role="user"
        )
        
        middleware.auth_service.get_user_by_token = AsyncMock(return_value=user)
        mock_request.headers = {"Authorization": "Bearer valid_token"}
        
        response = await middleware(request, mock_call_next)
        assert response.status_code == 200
        assert mock_request.state.current_user == user
    
    @pytest.mark.asyncio
    async def test_middleware_without_auth(self, middleware, mock_request, mock_call_next):
        """Test middleware without authentication"""
        middleware.auth_service.get_user_by_token = AsyncMock(return_value=None)
        
        response = await middleware(mock_request, mock_call_next)
        assert response.status_code == 200
    
    def test_is_public_endpoint(self, middleware):
        """Test public endpoint detection"""
        assert middleware._is_public_endpoint("/docs")
        assert middleware._is_public_endpoint("/redoc")
        assert middleware._is_public_endpoint("/auth/login")
        assert middleware._is_public_endpoint("/health")
        assert not middleware._is_public_endpoint("/api/users")
        assert not middleware._is_public_endpoint("/rbac/roles")

class TestUtilityFunctions:
    """Test RBAC utility functions"""
    
    @pytest.fixture
    def user(self):
        return User(
            user_id="user123",
            email="user@test.com",
            display_name="Test User",
            role="user"
        )
    
    @pytest.fixture
    def mock_role_service(self):
        return Mock()
    
    @pytest.mark.asyncio
    async def test_check_user_has_permission(self, user, mock_role_service):
        """Test check_user_has_permission utility"""
        mock_role_service.check_user_permission = AsyncMock(return_value=True)
        
        result = await check_user_has_permission(user, Permission.READ_DEVICES, mock_role_service)
        assert result is True
        
        mock_role_service.check_user_permission.assert_called_once_with(
            user.user_id, Permission.READ_DEVICES
        )
    
    @pytest.mark.asyncio
    async def test_check_user_has_any_permission(self, user, mock_role_service):
        """Test check_user_has_any_permission utility"""
        mock_role_service.check_user_permission = AsyncMock(side_effect=[False, True])
        
        permissions = [Permission.CREATE_DEVICES, Permission.READ_DEVICES]
        result = await check_user_has_any_permission(user, permissions, mock_role_service)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_check_user_has_all_permissions(self, user, mock_role_service):
        """Test check_user_has_all_permissions utility"""
        mock_role_service.check_user_permission = AsyncMock(return_value=True)
        
        permissions = [Permission.READ_DEVICES, Permission.USE_AI_SERVICES]
        result = await check_user_has_all_permissions(user, permissions, mock_role_service)
        assert result is True
        
        assert mock_role_service.check_user_permission.call_count == 2
    
    @pytest.mark.asyncio
    async def test_get_user_missing_permissions(self, user, mock_role_service):
        """Test get_user_missing_permissions utility"""
        mock_role_service.check_user_permission = AsyncMock(side_effect=[True, False, True])
        
        permissions = [Permission.READ_DEVICES, Permission.CREATE_DEVICES, Permission.USE_AI_SERVICES]
        missing = await get_user_missing_permissions(user, permissions, mock_role_service)
        
        assert missing == [Permission.CREATE_DEVICES]

class TestRBACLogger:
    """Test RBAC audit logger"""
    
    def test_log_permission_check(self):
        """Test logging permission check events"""
        with patch.object(rbac_logger.logger, 'info') as mock_info:
            rbac_logger.log_permission_check(
                user_id="user123",
                permission="read_devices",
                granted=True
            )
            
            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "permission_check" in call_args
            assert "user123" in call_args
            assert "read_devices" in call_args
    
    def test_log_permission_check_with_resource(self):
        """Test logging permission check with resource info"""
        with patch.object(rbac_logger.logger, 'info') as mock_info:
            rbac_logger.log_permission_check(
                user_id="user123",
                permission="read_devices",
                resource_type="device",
                resource_id="device123",
                granted=False
            )
            
            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "device" in call_args
            assert "device123" in call_args
    
    def test_log_role_assignment(self):
        """Test logging role assignment events"""
        with patch.object(rbac_logger.logger, 'info') as mock_info:
            rbac_logger.log_role_assignment(
                user_id="user123",
                role="operator",
                assigned_by="admin123"
            )
            
            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "role_assignment" in call_args
            assert "operator" in call_args
            assert "admin123" in call_args
    
    def test_log_permission_grant(self):
        """Test logging permission grant events"""
        with patch.object(rbac_logger.logger, 'info') as mock_info:
            rbac_logger.log_permission_grant(
                user_id="user123",
                permission="create_devices",
                granted_by="admin123"
            )
            
            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "permission_grant" in call_args
            assert "create_devices" in call_args
            assert "admin123" in call_args

if __name__ == "__main__":
    pytest.main([__file__])
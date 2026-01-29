"""
Property-based test for Authentication Security - Property 27

This test specifically validates Requirements 8.1 and 8.2 for comprehensive authentication security.
Property 27: For any user access attempt or API call, the platform should implement secure 
authentication and validate authentication tokens correctly.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import jwt
import secrets
import string

from hypothesis import given, strategies as st, assume, settings, HealthCheck

# Import our modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.auth_service import AuthService, AuthResult, TokenValidationResult, RegistrationData, AuthProvider
from models.user import User
from utils.auth_utils import AuthUtils
from config.settings import Settings

class TestProperty27AuthenticationSecurity:
    """Property-based test for Property 27: Comprehensive Authentication Security"""
    
    def create_mock_auth_service(self):
        """Create a mock auth service for testing"""
        with patch('services.auth_service.get_settings'), \
             patch('services.auth_service.UserRepository') as mock_repo, \
             patch('services.auth_service.firestore.Client'), \
             patch('services.auth_service.firebase_admin.initialize_app'), \
             patch('services.auth_service.firebase_admin.get_app'):
            
            service = AuthService()
            service._jwt_secret = "test-secret-key-for-property-27-testing"
            service._access_token_expire_minutes = 30  # 30 minutes
            
            # Setup mock repository
            mock_repo_instance = Mock()
            mock_repo_instance.get_by_email = AsyncMock(return_value=None)
            mock_repo_instance.get = AsyncMock()
            mock_repo_instance.create = AsyncMock(return_value=True)
            mock_repo_instance.update_last_login = AsyncMock(return_value=True)
            service.user_repository = mock_repo_instance
            
            return service
    
    @pytest.mark.asyncio
    @given(
        st.text(min_size=1, max_size=100).filter(lambda x: len(x.strip()) > 0),  # email
        st.text(min_size=1, max_size=100).filter(lambda x: len(x.strip()) > 0),  # password
        st.booleans()  # should_be_valid_credentials
    )
    @settings(max_examples=100, deadline=None)
    async def test_property_27_comprehensive_authentication_security(self, email, password, should_be_valid_credentials):
        """
        **Validates: Requirements 8.1, 8.2**
        Property 27: Comprehensive Authentication Security
        For any user access attempt or API call, the platform should implement secure 
        authentication and validate authentication tokens correctly
        """
        mock_auth_service = self.create_mock_auth_service()
        
        # Determine if credentials should be considered valid based on our validation rules
        email_valid = mock_auth_service._validate_email(email)
        password_valid = mock_auth_service._validate_password(password)
        credentials_actually_valid = email_valid and password_valid and should_be_valid_credentials
        
        with patch('firebase_admin.auth.create_user') as mock_create, \
             patch.object(mock_auth_service, '_authenticate_with_firebase') as mock_firebase_auth:
            
            if credentials_actually_valid:
                # Setup successful authentication mocks
                mock_firebase_user = Mock()
                mock_firebase_user.uid = f"firebase-uid-{secrets.token_hex(8)}"
                mock_firebase_user.email = email
                mock_firebase_user.display_name = "Test User"
                mock_create.return_value = mock_firebase_user
                
                mock_firebase_auth.return_value = {
                    "success": True,
                    "user_id": mock_firebase_user.uid,
                    "id_token": "valid-firebase-token",
                    "refresh_token": "valid-firebase-refresh"
                }
                
                # Create valid user for authentication
                valid_user = User.create_new(email, "Test User")
                valid_user.user_id = mock_firebase_user.uid
                mock_auth_service.user_repository.get.return_value = valid_user
                
            else:
                # Setup failed authentication mocks
                mock_firebase_auth.return_value = {
                    "success": False,
                    "error_code": "AUTH_FAILED",
                    "error_message": "Authentication failed"
                }
                mock_auth_service.user_repository.get.return_value = None
            
            # Test authentication attempt
            auth_result = await mock_auth_service.login_with_email_password(email, password)
            
            if credentials_actually_valid:
                # Valid credentials should succeed
                assert auth_result.success, f"Valid authentication should succeed for valid credentials"
                assert auth_result.user is not None, "Successful auth should return user"
                assert auth_result.access_token is not None, "Successful auth should return access token"
                assert auth_result.refresh_token is not None, "Successful auth should return refresh token"
                assert auth_result.error_code is None, "Successful auth should not have error code"
                
                # Test that the returned token is properly formatted
                assert isinstance(auth_result.access_token, str), "Access token should be a string"
                assert len(auth_result.access_token) > 0, "Access token should not be empty"
                
                # Test that the token contains expected structure (JWT format)
                token_parts = auth_result.access_token.split('.')
                assert len(token_parts) == 3, "JWT token should have 3 parts separated by dots"
                
            else:
                # Invalid credentials should fail
                assert not auth_result.success, f"Invalid authentication should fail for invalid credentials"
                assert auth_result.user is None, "Failed auth should not return user"
                assert auth_result.access_token is None, "Failed auth should not return access token"
                assert auth_result.error_code is not None, "Failed auth should return error code"
                assert auth_result.error_message is not None, "Failed auth should return error message"
    
    @pytest.mark.asyncio
    @given(st.text(min_size=1, max_size=200))
    @settings(max_examples=100, deadline=None)
    async def test_property_27_api_token_validation_security(self, token_input):
        """
        **Validates: Requirements 8.1, 8.2**
        Property 27: Comprehensive Authentication Security - API Token Validation
        For any API call with a token, the platform should validate authentication tokens correctly
        """
        mock_auth_service = self.create_mock_auth_service()
        
        # Create a valid user for comparison
        valid_user = User.create_new("test@example.com", "Test User")
        valid_user.user_id = f"user-{secrets.token_hex(8)}"
        mock_auth_service.user_repository.get.return_value = valid_user
        
        # Generate a known valid token for comparison
        valid_token = mock_auth_service._generate_access_token(valid_user)
        
        # Test token validation
        validation_result = await mock_auth_service.validate_token(token_input)
        
        if token_input == valid_token:
            # The exact valid token should pass validation
            assert validation_result.valid, "Valid token should pass validation"
            assert validation_result.user_id == valid_user.user_id, "Valid token should return correct user ID"
            assert validation_result.claims is not None, "Valid token should return claims"
            assert validation_result.error_message is None, "Valid token should not have error message"
        else:
            # Any other token should fail validation
            assert not validation_result.valid, f"Invalid token should fail validation"
            assert validation_result.user_id is None, "Invalid token should not return user ID"
            assert validation_result.claims is None, "Invalid token should not return claims"
            assert validation_result.error_message is not None, "Invalid token should return error message"
    
    @pytest.mark.asyncio
    @given(st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=5, unique=True))
    @settings(max_examples=50, deadline=None)
    async def test_property_27_permission_based_access_security(self, required_permissions):
        """
        **Validates: Requirements 8.1**
        Property 27: Comprehensive Authentication Security - Permission-based Access
        For any set of required permissions, the platform should correctly validate user access
        """
        # Create users with different permission sets
        admin_user = User.create_new("admin@example.com", "Admin User", "admin")
        regular_user = User.create_new("user@example.com", "Regular User", "user")
        
        # Add some permissions to regular user (but not all)
        permissions_to_add = required_permissions[:len(required_permissions)//2] if len(required_permissions) > 1 else []
        for permission in permissions_to_add:
            regular_user.add_permission(permission)
        
        # Test admin user access (should have all permissions due to admin role)
        for permission in required_permissions:
            assert admin_user.has_permission(permission), f"Admin should have permission: {permission}"
        
        # Test regular user access (should only have explicitly granted permissions)
        for permission in required_permissions:
            if permission in permissions_to_add:
                assert regular_user.has_permission(permission), f"Regular user should have granted permission: {permission}"
            else:
                assert not regular_user.has_permission(permission), f"Regular user should not have non-granted permission: {permission}"
    
    @pytest.mark.asyncio
    @given(st.integers(min_value=1, max_value=10))
    @settings(max_examples=20, deadline=None)
    async def test_property_27_concurrent_authentication_security(self, concurrent_attempts):
        """
        **Validates: Requirements 8.1, 8.2**
        Property 27: Comprehensive Authentication Security - Concurrent Access
        For any number of concurrent authentication attempts, the platform should maintain security
        """
        mock_auth_service = self.create_mock_auth_service()
        
        valid_user = User.create_new("test@example.com", "Test User")
        valid_user.user_id = f"user-{secrets.token_hex(8)}"
        mock_auth_service.user_repository.get.return_value = valid_user
        
        with patch.object(mock_auth_service, '_authenticate_with_firebase') as mock_firebase_auth:
            mock_firebase_auth.return_value = {
                "success": True,
                "user_id": valid_user.user_id,
                "id_token": "valid-firebase-token",
                "refresh_token": "valid-firebase-refresh"
            }
            
            # Simulate concurrent authentication attempts
            tasks = []
            for i in range(concurrent_attempts):
                task = mock_auth_service.login_with_email_password("test@example.com", "validpassword123")
                tasks.append(task)
            
            # Execute all authentication attempts concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All attempts should succeed (same valid credentials)
            successful_auths = 0
            unique_tokens = set()
            
            for result in results:
                if isinstance(result, AuthResult) and result.success:
                    successful_auths += 1
                    if result.access_token:
                        unique_tokens.add(result.access_token)
            
            assert successful_auths == concurrent_attempts, f"All {concurrent_attempts} concurrent auth attempts should succeed"
            assert len(unique_tokens) == concurrent_attempts, "All concurrent authentications should generate unique tokens"
    
    @pytest.mark.asyncio
    @given(st.text(min_size=1, max_size=50))
    @settings(max_examples=50, deadline=None)
    async def test_property_27_user_session_security(self, display_name):
        """
        **Validates: Requirements 8.2**
        Property 27: Comprehensive Authentication Security - User Session Management
        For any user session, the platform should maintain secure session state
        """
        assume(len(display_name.strip()) > 0)
        
        mock_auth_service = self.create_mock_auth_service()
        
        # Create a user
        user = User.create_new("test@example.com", display_name.strip())
        user.user_id = f"user-{secrets.token_hex(8)}"
        
        # Generate tokens
        access_token = mock_auth_service._generate_access_token(user)
        refresh_token = mock_auth_service._generate_refresh_token(user)
        
        # Verify token properties
        assert isinstance(access_token, str), "Access token should be a string"
        assert isinstance(refresh_token, str), "Refresh token should be a string"
        assert len(access_token) > 0, "Access token should not be empty"
        assert len(refresh_token) > 0, "Refresh token should not be empty"
        assert access_token != refresh_token, "Access and refresh tokens should be different"
        
        # Verify refresh token is stored securely
        assert refresh_token in mock_auth_service._refresh_tokens, "Refresh token should be stored"
        token_data = mock_auth_service._refresh_tokens[refresh_token]
        assert token_data['user_id'] == user.user_id, "Stored token should be associated with correct user"
        assert token_data['expires_at'] > datetime.utcnow().timestamp(), "Refresh token should have future expiration"
        
        # Test logout functionality
        logout_success = await mock_auth_service.logout(refresh_token)
        assert logout_success, "Logout should succeed"
        assert refresh_token not in mock_auth_service._refresh_tokens, "Refresh token should be removed after logout"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
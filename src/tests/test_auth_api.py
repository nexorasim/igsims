"""
Integration tests for Authentication API endpoints

Tests Requirements 8.1 (User authentication and authorization) and 8.2 (Secure session management)
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import json

from fastapi.testclient import TestClient
from fastapi import FastAPI

# Import our modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.auth import router as auth_router
from services.auth_service import AuthService, AuthResult, RegistrationData
from models.user import User
from utils.auth_utils import rate_limiter

# Create test app
app = FastAPI()
app.include_router(auth_router)

class TestAuthAPI:
    """Test cases for Authentication API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Test client for API testing"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_auth_service(self):
        """Mock authentication service"""
        service = Mock(spec=AuthService)
        return service
    
    @pytest.fixture
    def sample_user(self):
        """Sample user for testing"""
        user = User.create_new(
            email="test@example.com",
            display_name="Test User",
            role="user"
        )
        user.user_id = "test-user-id"
        return user
    
    @pytest.fixture(autouse=True)
    def setup_rate_limiter(self):
        """Clear rate limiter before each test"""
        rate_limiter._attempts.clear()
        rate_limiter._lockouts.clear()
        yield
        rate_limiter._attempts.clear()
        rate_limiter._lockouts.clear()
    
    def test_register_success(self, client, mock_auth_service, sample_user):
        """Test successful user registration"""
        # Setup mock
        mock_result = AuthResult(
            success=True,
            user=sample_user,
            access_token="test-access-token",
            refresh_token="test-refresh-token",
            expires_in=1800
        )
        mock_auth_service.register_user = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            # Execute
            response = client.post("/auth/register", json={
                "email": "test@example.com",
                "password": "SecurePass123!",
                "display_name": "Test User",
                "role": "user"
            })
            
            # Verify
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "User registered successfully"
            assert data["user"]["email"] == "test@example.com"
            assert data["access_token"] == "test-access-token"
            assert data["refresh_token"] == "test-refresh-token"
    
    def test_register_invalid_email(self, client):
        """Test registration with invalid email"""
        response = client.post("/auth/register", json={
            "email": "invalid-email",
            "password": "SecurePass123!",
            "display_name": "Test User"
        })
        
        assert response.status_code == 400
        data = response.json()
        assert "Invalid email format" in data["detail"]
    
    def test_register_weak_password(self, client):
        """Test registration with weak password"""
        response = client.post("/auth/register", json={
            "email": "test@example.com",
            "password": "weak",
            "display_name": "Test User"
        })
        
        assert response.status_code == 400
        data = response.json()
        assert "Password validation failed" in data["detail"]
    
    def test_register_user_exists(self, client, mock_auth_service):
        """Test registration with existing user"""
        # Setup mock
        mock_result = AuthResult(
            success=False,
            error_code="USER_EXISTS",
            error_message="User with this email already exists"
        )
        mock_auth_service.register_user = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/register", json={
                "email": "existing@example.com",
                "password": "SecurePass123!",
                "display_name": "Existing User"
            })
            
            assert response.status_code == 400
            data = response.json()
            assert "already exists" in data["detail"]
    
    def test_login_success(self, client, mock_auth_service, sample_user):
        """Test successful login"""
        # Setup mock
        mock_result = AuthResult(
            success=True,
            user=sample_user,
            access_token="test-access-token",
            refresh_token="test-refresh-token",
            expires_in=1800
        )
        mock_auth_service.login_with_email_password = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/login", json={
                "email": "test@example.com",
                "password": "SecurePass123!"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Login successful"
            assert data["user"]["email"] == "test@example.com"
            assert data["access_token"] == "test-access-token"
    
    def test_login_invalid_credentials(self, client, mock_auth_service):
        """Test login with invalid credentials"""
        # Setup mock
        mock_result = AuthResult(
            success=False,
            error_code="AUTH_FAILED",
            error_message="Invalid credentials"
        )
        mock_auth_service.login_with_email_password = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/login", json={
                "email": "test@example.com",
                "password": "wrongpassword"
            })
            
            assert response.status_code == 401
            data = response.json()
            assert "Invalid email or password" in data["detail"]
    
    def test_oauth_login_success(self, client, mock_auth_service, sample_user):
        """Test successful OAuth login"""
        # Setup mock
        mock_result = AuthResult(
            success=True,
            user=sample_user,
            access_token="test-access-token",
            refresh_token="test-refresh-token",
            expires_in=1800
        )
        mock_auth_service.login_with_oauth = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/oauth/login", json={
                "provider": "google.com",
                "oauth_token": "valid-oauth-token"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "OAuth login successful"
            assert data["access_token"] == "test-access-token"
    
    def test_oauth_login_invalid_provider(self, client):
        """Test OAuth login with invalid provider"""
        response = client.post("/auth/oauth/login", json={
            "provider": "invalid-provider",
            "oauth_token": "some-token"
        })
        
        assert response.status_code == 422  # Validation error
    
    def test_refresh_token_success(self, client, mock_auth_service, sample_user):
        """Test successful token refresh"""
        # Setup mock
        mock_result = AuthResult(
            success=True,
            user=sample_user,
            access_token="new-access-token",
            refresh_token="same-refresh-token",
            expires_in=1800
        )
        mock_auth_service.refresh_access_token = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/refresh", json={
                "refresh_token": "valid-refresh-token"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Token refreshed successfully"
            assert data["access_token"] == "new-access-token"
    
    def test_refresh_token_invalid(self, client, mock_auth_service):
        """Test token refresh with invalid token"""
        # Setup mock
        mock_result = AuthResult(
            success=False,
            error_code="INVALID_REFRESH_TOKEN",
            error_message="Invalid refresh token"
        )
        mock_auth_service.refresh_access_token = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/refresh", json={
                "refresh_token": "invalid-refresh-token"
            })
            
            assert response.status_code == 401
            data = response.json()
            assert "Token refresh failed" in data["detail"]
    
    def test_logout_success(self, client, mock_auth_service, sample_user):
        """Test successful logout"""
        # Setup mocks
        mock_auth_service.logout = AsyncMock(return_value=True)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service), \
             patch('api.auth.get_current_active_user', return_value=sample_user):
            
            response = client.post("/auth/logout", 
                json={"refresh_token": "valid-refresh-token"},
                headers={"Authorization": "Bearer valid-access-token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Logout successful"
    
    def test_logout_unauthorized(self, client):
        """Test logout without authentication"""
        response = client.post("/auth/logout", json={
            "refresh_token": "some-token"
        })
        
        assert response.status_code == 403  # No authorization header
    
    def test_reset_password_success(self, client, mock_auth_service):
        """Test successful password reset request"""
        mock_auth_service.send_password_reset_email = AsyncMock(return_value=True)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/reset-password", json={
                "email": "test@example.com"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "password reset link" in data["message"]
    
    def test_reset_password_nonexistent_user(self, client, mock_auth_service):
        """Test password reset for non-existent user"""
        mock_auth_service.send_password_reset_email = AsyncMock(return_value=True)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/reset-password", json={
                "email": "nonexistent@example.com"
            })
            
            # Should still return success to prevent email enumeration
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
    
    def test_change_password_success(self, client, mock_auth_service, sample_user):
        """Test successful password change"""
        # Setup mocks
        login_result = AuthResult(success=True, user=sample_user)
        mock_auth_service.login_with_email_password = AsyncMock(return_value=login_result)
        mock_auth_service.change_password = AsyncMock(return_value=True)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service), \
             patch('api.auth.get_current_active_user', return_value=sample_user):
            
            response = client.post("/auth/change-password",
                json={
                    "current_password": "OldPass123!",
                    "new_password": "NewPass123!"
                },
                headers={"Authorization": "Bearer valid-access-token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Password changed successfully"
    
    def test_change_password_wrong_current(self, client, mock_auth_service, sample_user):
        """Test password change with wrong current password"""
        # Setup mocks
        login_result = AuthResult(success=False, error_message="Invalid credentials")
        mock_auth_service.login_with_email_password = AsyncMock(return_value=login_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service), \
             patch('api.auth.get_current_active_user', return_value=sample_user):
            
            response = client.post("/auth/change-password",
                json={
                    "current_password": "WrongPass123!",
                    "new_password": "NewPass123!"
                },
                headers={"Authorization": "Bearer valid-access-token"}
            )
            
            assert response.status_code == 400
            data = response.json()
            assert "Current password is incorrect" in data["detail"]
    
    def test_change_password_weak_new(self, client, sample_user):
        """Test password change with weak new password"""
        with patch('api.auth.get_current_active_user', return_value=sample_user):
            response = client.post("/auth/change-password",
                json={
                    "current_password": "OldPass123!",
                    "new_password": "weak"
                },
                headers={"Authorization": "Bearer valid-access-token"}
            )
            
            assert response.status_code == 400
            data = response.json()
            assert "Password validation failed" in data["detail"]
    
    def test_get_current_user_success(self, client, sample_user):
        """Test getting current user information"""
        with patch('api.auth.get_current_active_user', return_value=sample_user):
            response = client.get("/auth/me",
                headers={"Authorization": "Bearer valid-access-token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["user_id"] == sample_user.user_id
            assert data["email"] == sample_user.email
            assert data["display_name"] == sample_user.display_name
            assert data["role"] == sample_user.role
            assert data["is_active"] == sample_user.is_active
    
    def test_get_current_user_unauthorized(self, client):
        """Test getting current user without authentication"""
        response = client.get("/auth/me")
        
        assert response.status_code == 403  # No authorization header
    
    def test_verify_email_success(self, client, mock_auth_service):
        """Test successful email verification"""
        mock_auth_service.verify_email = AsyncMock(return_value=True)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/verify-email/test-user-id")
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Email verified successfully"
    
    def test_verify_email_failure(self, client, mock_auth_service):
        """Test email verification failure"""
        mock_auth_service.verify_email = AsyncMock(return_value=False)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/verify-email/invalid-user-id")
            
            assert response.status_code == 400
            data = response.json()
            assert "Email verification failed" in data["detail"]
    
    def test_validate_token_success(self, client, sample_user):
        """Test token validation"""
        with patch('api.auth.get_current_user', return_value=sample_user):
            response = client.get("/auth/validate-token",
                headers={"Authorization": "Bearer valid-access-token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["valid"] is True
            assert data["user"]["email"] == sample_user.email
            assert data["message"] == "Token is valid"
    
    def test_validate_token_invalid(self, client):
        """Test validation of invalid token"""
        response = client.get("/auth/validate-token",
            headers={"Authorization": "Bearer invalid-token"}
        )
        
        assert response.status_code == 401
    
    def test_rate_limiting_registration(self, client):
        """Test rate limiting on registration endpoint"""
        # Make multiple failed registration attempts
        for i in range(6):  # Exceed rate limit
            response = client.post("/auth/register", json={
                "email": "invalid-email",  # This will fail validation
                "password": "SecurePass123!",
                "display_name": "Test User"
            })
            
            if i < 5:
                assert response.status_code == 400  # Validation error
            else:
                assert response.status_code == 429  # Rate limited
                data = response.json()
                assert "Too many" in data["detail"]
    
    def test_rate_limiting_login(self, client, mock_auth_service):
        """Test rate limiting on login endpoint"""
        # Setup mock to always fail
        mock_result = AuthResult(
            success=False,
            error_code="AUTH_FAILED",
            error_message="Invalid credentials"
        )
        mock_auth_service.login_with_email_password = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            # Make multiple failed login attempts
            for i in range(6):  # Exceed rate limit
                response = client.post("/auth/login", json={
                    "email": "test@example.com",
                    "password": "wrongpassword"
                })
                
                if i < 5:
                    assert response.status_code == 401  # Auth failed
                else:
                    assert response.status_code == 429  # Rate limited
                    data = response.json()
                    assert "Too many" in data["detail"]
    
    def test_input_validation_missing_fields(self, client):
        """Test input validation with missing required fields"""
        # Missing password
        response = client.post("/auth/register", json={
            "email": "test@example.com",
            "display_name": "Test User"
        })
        assert response.status_code == 422  # Validation error
        
        # Missing email
        response = client.post("/auth/login", json={
            "password": "SecurePass123!"
        })
        assert response.status_code == 422  # Validation error
    
    def test_input_validation_invalid_role(self, client):
        """Test input validation with invalid role"""
        response = client.post("/auth/register", json={
            "email": "test@example.com",
            "password": "SecurePass123!",
            "display_name": "Test User",
            "role": "invalid_role"
        })
        assert response.status_code == 422  # Validation error
    
    def test_cors_headers(self, client):
        """Test CORS headers are present (if configured)"""
        response = client.options("/auth/login")
        # This test would verify CORS headers if configured
        # For now, just check that OPTIONS is handled
        assert response.status_code in [200, 405]  # Either allowed or method not allowed
    
    def test_security_headers(self, client, sample_user):
        """Test security headers in responses"""
        with patch('api.auth.get_current_active_user', return_value=sample_user):
            response = client.get("/auth/me",
                headers={"Authorization": "Bearer valid-access-token"}
            )
            
            # Check that sensitive information is not leaked in headers
            assert "password" not in str(response.headers).lower()
            assert "secret" not in str(response.headers).lower()
    
    def test_json_response_format(self, client, mock_auth_service, sample_user):
        """Test that all responses follow consistent JSON format"""
        mock_result = AuthResult(
            success=True,
            user=sample_user,
            access_token="test-token",
            refresh_token="test-refresh",
            expires_in=1800
        )
        mock_auth_service.register_user = AsyncMock(return_value=mock_result)
        
        with patch('api.auth.get_auth_service', return_value=mock_auth_service):
            response = client.post("/auth/register", json={
                "email": "test@example.com",
                "password": "SecurePass123!",
                "display_name": "Test User"
            })
            
            assert response.status_code == 200
            assert response.headers["content-type"] == "application/json"
            
            data = response.json()
            # Check consistent response structure
            assert "success" in data
            assert "message" in data
            assert isinstance(data["success"], bool)
            assert isinstance(data["message"], str)
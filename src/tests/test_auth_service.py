"""
Unit tests for Firebase Authentication Service

Tests Requirements 8.1 (User authentication and authorization) and 8.2 (Secure session management)
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import jwt
import secrets

# Import our modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.auth_service import AuthService, AuthResult, TokenValidationResult, RegistrationData, AuthProvider
from models.user import User
from repositories.user_repository import UserRepository
from config.settings import Settings

class TestAuthService:
    """Test cases for AuthService"""
    
    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing"""
        settings = Mock(spec=Settings)
        settings.firebase_project_id = "test-project"
        settings.firebase_api_key = "test-api-key"
        settings.firebase_credentials_path = None
        settings.jwt_secret_key = "test-secret-key"
        settings.jwt_algorithm = "HS256"
        settings.jwt_access_token_expire_minutes = 30
        settings.jwt_refresh_token_expire_days = 30
        return settings
    
    @pytest.fixture
    def mock_user_repository(self):
        """Mock user repository for testing"""
        repo = Mock(spec=UserRepository)
        repo.get_by_email = AsyncMock()
        repo.get = AsyncMock()
        repo.create = AsyncMock()
        repo.update_last_login = AsyncMock()
        return repo
    
    @pytest.fixture
    def sample_user(self):
        """Sample user for testing"""
        return User.create_new(
            email="test@example.com",
            display_name="Test User",
            role="user"
        )
    
    @pytest.fixture
    def auth_service(self, mock_settings, mock_user_repository):
        """AuthService instance with mocked dependencies"""
        with patch('services.auth_service.get_settings', return_value=mock_settings), \
             patch('services.auth_service.UserRepository', return_value=mock_user_repository), \
             patch('services.auth_service.firestore.Client'), \
             patch('services.auth_service.firebase_admin.initialize_app'), \
             patch('services.auth_service.firebase_admin.get_app'):
            
            service = AuthService()
            service.user_repository = mock_user_repository
            return service
    
    @pytest.mark.asyncio
    async def test_register_user_success(self, auth_service, mock_user_repository):
        """Test successful user registration"""
        # Setup
        registration_data = RegistrationData(
            email="newuser@example.com",
            password="SecurePass123!",
            display_name="New User"
        )
        
        mock_user_repository.get_by_email.return_value = None  # User doesn't exist
        mock_user_repository.create.return_value = True
        
        with patch('firebase_admin.auth.create_user') as mock_create_user, \
             patch.object(auth_service, '_send_email_verification', return_value=True):
            
            mock_firebase_user = Mock()
            mock_firebase_user.uid = "firebase-uid-123"
            mock_create_user.return_value = mock_firebase_user
            
            # Execute
            result = await auth_service.register_user(registration_data)
            
            # Verify
            assert result.success is True
            assert result.user is not None
            assert result.access_token is not None
            assert result.refresh_token is not None
            assert result.user.email == registration_data.email
            assert result.user.display_name == registration_data.display_name
            
            mock_user_repository.create.assert_called_once()
            mock_create_user.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_register_user_email_exists(self, auth_service, mock_user_repository, sample_user):
        """Test registration with existing email"""
        # Setup
        registration_data = RegistrationData(
            email="existing@example.com",
            password="SecurePass123!",
            display_name="Existing User"
        )
        
        mock_user_repository.get_by_email.return_value = sample_user
        
        # Execute
        result = await auth_service.register_user(registration_data)
        
        # Verify
        assert result.success is False
        assert result.error_code == "USER_EXISTS"
        assert "already exists" in result.error_message
    
    @pytest.mark.asyncio
    async def test_register_user_invalid_email(self, auth_service):
        """Test registration with invalid email"""
        # Setup
        registration_data = RegistrationData(
            email="invalid-email",
            password="SecurePass123!",
            display_name="Test User"
        )
        
        # Execute
        result = await auth_service.register_user(registration_data)
        
        # Verify
        assert result.success is False
        assert result.error_code == "INVALID_EMAIL"
    
    @pytest.mark.asyncio
    async def test_register_user_weak_password(self, auth_service):
        """Test registration with weak password"""
        # Setup
        registration_data = RegistrationData(
            email="test@example.com",
            password="weak",
            display_name="Test User"
        )
        
        # Execute
        result = await auth_service.register_user(registration_data)
        
        # Verify
        assert result.success is False
        assert result.error_code == "WEAK_PASSWORD"
    
    @pytest.mark.asyncio
    async def test_login_success(self, auth_service, mock_user_repository, sample_user):
        """Test successful login"""
        # Setup
        email = "test@example.com"
        password = "SecurePass123!"
        
        mock_user_repository.get.return_value = sample_user
        mock_user_repository.update_last_login.return_value = True
        
        with patch.object(auth_service, '_authenticate_with_firebase') as mock_auth:
            mock_auth.return_value = {
                "success": True,
                "user_id": sample_user.user_id,
                "id_token": "firebase-token",
                "refresh_token": "firebase-refresh"
            }
            
            # Execute
            result = await auth_service.login_with_email_password(email, password)
            
            # Verify
            assert result.success is True
            assert result.user == sample_user
            assert result.access_token is not None
            assert result.refresh_token is not None
            
            mock_user_repository.update_last_login.assert_called_once_with(sample_user.user_id)
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, auth_service):
        """Test login with invalid credentials"""
        # Setup
        email = "test@example.com"
        password = "wrongpassword"
        
        with patch.object(auth_service, '_authenticate_with_firebase') as mock_auth:
            mock_auth.return_value = {
                "success": False,
                "error_code": "AUTH_FAILED",
                "error_message": "Invalid credentials"
            }
            
            # Execute
            result = await auth_service.login_with_email_password(email, password)
            
            # Verify
            assert result.success is False
            assert result.error_code == "AUTH_FAILED"
    
    @pytest.mark.asyncio
    async def test_login_inactive_user(self, auth_service, mock_user_repository, sample_user):
        """Test login with inactive user"""
        # Setup
        email = "test@example.com"
        password = "SecurePass123!"
        sample_user.is_active = False
        
        mock_user_repository.get.return_value = sample_user
        
        with patch.object(auth_service, '_authenticate_with_firebase') as mock_auth:
            mock_auth.return_value = {
                "success": True,
                "user_id": sample_user.user_id,
                "id_token": "firebase-token",
                "refresh_token": "firebase-refresh"
            }
            
            # Execute
            result = await auth_service.login_with_email_password(email, password)
            
            # Verify
            assert result.success is False
            assert result.error_code == "USER_DISABLED"
    
    @pytest.mark.asyncio
    async def test_oauth_login_success(self, auth_service, mock_user_repository, sample_user):
        """Test successful OAuth login"""
        # Setup
        provider = AuthProvider.GOOGLE
        oauth_token = "valid-oauth-token"
        
        mock_user_repository.get.return_value = sample_user
        mock_user_repository.update_last_login.return_value = True
        
        with patch('firebase_admin.auth.verify_id_token') as mock_verify, \
             patch('firebase_admin.auth.get_user') as mock_get_user:
            
            mock_verify.return_value = {'uid': sample_user.user_id}
            
            mock_firebase_user = Mock()
            mock_firebase_user.email = sample_user.email
            mock_firebase_user.display_name = sample_user.display_name
            mock_firebase_user.provider_data = [Mock(provider_id="google.com")]
            mock_get_user.return_value = mock_firebase_user
            
            # Execute
            result = await auth_service.login_with_oauth(provider, oauth_token)
            
            # Verify
            assert result.success is True
            assert result.user == sample_user
            assert result.access_token is not None
            assert result.refresh_token is not None
    
    @pytest.mark.asyncio
    async def test_oauth_login_invalid_token(self, auth_service):
        """Test OAuth login with invalid token"""
        # Setup
        provider = AuthProvider.GOOGLE
        oauth_token = "invalid-token"
        
        with patch('firebase_admin.auth.verify_id_token') as mock_verify:
            from firebase_admin.auth import InvalidIdTokenError
            mock_verify.side_effect = InvalidIdTokenError("Invalid token")
            
            # Execute
            result = await auth_service.login_with_oauth(provider, oauth_token)
            
            # Verify
            assert result.success is False
            assert result.error_code == "INVALID_TOKEN"
    
    @pytest.mark.asyncio
    async def test_validate_token_success(self, auth_service, mock_user_repository, sample_user):
        """Test successful token validation"""
        # Setup
        token = auth_service._generate_access_token(sample_user)
        mock_user_repository.get.return_value = sample_user
        
        # Execute
        result = await auth_service.validate_token(token)
        
        # Verify
        assert result.valid is True
        assert result.user_id == sample_user.user_id
        assert result.claims is not None
    
    @pytest.mark.asyncio
    async def test_validate_token_expired(self, auth_service):
        """Test validation of expired token"""
        # Setup - create expired token
        now = datetime.utcnow()
        payload = {
            'sub': 'user-123',
            'email': 'test@example.com',
            'iat': (now - timedelta(hours=2)).timestamp(),
            'exp': (now - timedelta(hours=1)).timestamp(),  # Expired 1 hour ago
            'type': 'access'
        }
        
        expired_token = jwt.encode(payload, auth_service._jwt_secret, algorithm=auth_service._jwt_algorithm)
        
        # Execute
        result = await auth_service.validate_token(expired_token)
        
        # Verify
        assert result.valid is False
        assert "expired" in result.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_validate_token_invalid_format(self, auth_service):
        """Test validation of invalid token format"""
        # Setup
        invalid_token = "invalid.token.format"
        
        # Execute
        result = await auth_service.validate_token(invalid_token)
        
        # Verify
        assert result.valid is False
        assert "invalid" in result.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, auth_service, mock_user_repository, sample_user):
        """Test successful token refresh"""
        # Setup
        refresh_token = auth_service._generate_refresh_token(sample_user)
        mock_user_repository.get.return_value = sample_user
        
        # Execute
        result = await auth_service.refresh_access_token(refresh_token)
        
        # Verify
        assert result.success is True
        assert result.user == sample_user
        assert result.access_token is not None
        assert result.refresh_token == refresh_token  # Same refresh token
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, auth_service):
        """Test refresh with invalid token"""
        # Setup
        invalid_refresh_token = "invalid-refresh-token"
        
        # Execute
        result = await auth_service.refresh_access_token(invalid_refresh_token)
        
        # Verify
        assert result.success is False
        assert result.error_code == "INVALID_REFRESH_TOKEN"
    
    @pytest.mark.asyncio
    async def test_refresh_token_expired(self, auth_service, sample_user):
        """Test refresh with expired token"""
        # Setup - create expired refresh token
        refresh_token = secrets.token_urlsafe(32)
        expired_time = datetime.utcnow() - timedelta(days=1)
        
        auth_service._refresh_tokens[refresh_token] = {
            'user_id': sample_user.user_id,
            'expires_at': expired_time.timestamp(),
            'created_at': (expired_time - timedelta(days=30)).timestamp()
        }
        
        # Execute
        result = await auth_service.refresh_access_token(refresh_token)
        
        # Verify
        assert result.success is False
        assert result.error_code == "REFRESH_TOKEN_EXPIRED"
        assert refresh_token not in auth_service._refresh_tokens  # Should be cleaned up
    
    @pytest.mark.asyncio
    async def test_logout_success(self, auth_service, sample_user):
        """Test successful logout"""
        # Setup
        refresh_token = auth_service._generate_refresh_token(sample_user)
        
        # Execute
        result = await auth_service.logout(refresh_token)
        
        # Verify
        assert result is True
        assert refresh_token not in auth_service._refresh_tokens
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email(self, auth_service):
        """Test sending password reset email"""
        # Setup
        email = "test@example.com"
        
        with patch('firebase_admin.auth.generate_password_reset_link') as mock_generate:
            mock_generate.return_value = "https://example.com/reset?token=abc123"
            
            # Execute
            result = await auth_service.send_password_reset_email(email)
            
            # Verify
            assert result is True
            mock_generate.assert_called_once_with(email)
    
    @pytest.mark.asyncio
    async def test_send_password_reset_nonexistent_user(self, auth_service):
        """Test password reset for non-existent user"""
        # Setup
        email = "nonexistent@example.com"
        
        with patch('firebase_admin.auth.generate_password_reset_link') as mock_generate:
            from firebase_admin.auth import UserNotFoundError
            mock_generate.side_effect = UserNotFoundError("User not found")
            
            # Execute
            result = await auth_service.send_password_reset_email(email)
            
            # Verify - should still return True to prevent email enumeration
            assert result is True
    
    @pytest.mark.asyncio
    async def test_verify_email_success(self, auth_service):
        """Test successful email verification"""
        # Setup
        user_id = "user-123"
        
        with patch('firebase_admin.auth.update_user') as mock_update:
            # Execute
            result = await auth_service.verify_email(user_id)
            
            # Verify
            assert result is True
            mock_update.assert_called_once_with(user_id, email_verified=True)
    
    @pytest.mark.asyncio
    async def test_change_password_success(self, auth_service):
        """Test successful password change"""
        # Setup
        user_id = "user-123"
        new_password = "NewSecurePass123!"
        
        with patch('firebase_admin.auth.update_user') as mock_update:
            # Execute
            result = await auth_service.change_password(user_id, new_password)
            
            # Verify
            assert result is True
            mock_update.assert_called_once_with(user_id, password=new_password)
    
    @pytest.mark.asyncio
    async def test_change_password_weak(self, auth_service):
        """Test password change with weak password"""
        # Setup
        user_id = "user-123"
        weak_password = "weak"
        
        # Execute
        result = await auth_service.change_password(user_id, weak_password)
        
        # Verify
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_user_by_token_success(self, auth_service, mock_user_repository, sample_user):
        """Test getting user by valid token"""
        # Setup
        token = auth_service._generate_access_token(sample_user)
        mock_user_repository.get.return_value = sample_user
        
        # Execute
        result = await auth_service.get_user_by_token(token)
        
        # Verify
        assert result == sample_user
    
    @pytest.mark.asyncio
    async def test_get_user_by_token_invalid(self, auth_service):
        """Test getting user by invalid token"""
        # Setup
        invalid_token = "invalid.token.here"
        
        # Execute
        result = await auth_service.get_user_by_token(invalid_token)
        
        # Verify
        assert result is None
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens(self, auth_service, sample_user):
        """Test cleanup of expired refresh tokens"""
        # Setup - create mix of valid and expired tokens
        valid_token = auth_service._generate_refresh_token(sample_user)
        
        expired_token = secrets.token_urlsafe(32)
        expired_time = datetime.utcnow() - timedelta(days=1)
        auth_service._refresh_tokens[expired_token] = {
            'user_id': sample_user.user_id,
            'expires_at': expired_time.timestamp(),
            'created_at': (expired_time - timedelta(days=30)).timestamp()
        }
        
        # Execute
        cleaned_count = await auth_service.cleanup_expired_tokens()
        
        # Verify
        assert cleaned_count == 1
        assert valid_token in auth_service._refresh_tokens
        assert expired_token not in auth_service._refresh_tokens
    
    def test_generate_access_token(self, auth_service, sample_user):
        """Test access token generation"""
        # Execute
        token = auth_service._generate_access_token(sample_user)
        
        # Verify
        assert token is not None
        assert isinstance(token, str)
        
        # Decode and verify payload
        payload = jwt.decode(token, auth_service._jwt_secret, algorithms=[auth_service._jwt_algorithm])
        assert payload['sub'] == sample_user.user_id
        assert payload['email'] == sample_user.email
        assert payload['role'] == sample_user.role
        assert payload['permissions'] == sample_user.permissions
        assert payload['type'] == 'access'
    
    def test_generate_refresh_token(self, auth_service, sample_user):
        """Test refresh token generation"""
        # Execute
        token = auth_service._generate_refresh_token(sample_user)
        
        # Verify
        assert token is not None
        assert isinstance(token, str)
        assert token in auth_service._refresh_tokens
        
        token_data = auth_service._refresh_tokens[token]
        assert token_data['user_id'] == sample_user.user_id
        assert token_data['expires_at'] > datetime.utcnow().timestamp()
    
    def test_validate_email(self, auth_service):
        """Test email validation"""
        # Valid emails
        assert auth_service._validate_email("test@example.com") is True
        assert auth_service._validate_email("user.name+tag@domain.co.uk") is True
        
        # Invalid emails
        assert auth_service._validate_email("invalid-email") is False
        assert auth_service._validate_email("@domain.com") is False
        assert auth_service._validate_email("user@") is False
        assert auth_service._validate_email("") is False
    
    def test_validate_password(self, auth_service):
        """Test password validation"""
        # Valid passwords
        assert auth_service._validate_password("SecurePass123!") is True
        assert auth_service._validate_password("12345678") is True  # Basic implementation
        
        # Invalid passwords
        assert auth_service._validate_password("short") is False
        assert auth_service._validate_password("") is False
        assert auth_service._validate_password("1234567") is False  # Too short

# Property-based tests using Hypothesis

from hypothesis import given, strategies as st

class TestAuthServiceProperties:
    """Property-based tests for AuthService"""
    
    @pytest.fixture
    def auth_service(self):
        """Simple auth service for property testing"""
        with patch('services.auth_service.get_settings'), \
             patch('services.auth_service.UserRepository'), \
             patch('services.auth_service.firestore.Client'), \
             patch('services.auth_service.firebase_admin.initialize_app'), \
             patch('services.auth_service.firebase_admin.get_app'):
            return AuthService()
    
    @given(st.emails())
    def test_email_validation_property(self, auth_service, email):
        """
        **Validates: Requirements 8.1**
        Property: For any valid email format, validation should succeed
        """
        result = auth_service._validate_email(email)
        # Hypothesis generates valid emails, so they should all pass
        assert result is True
    
    @given(st.text(min_size=8, max_size=100))
    def test_password_validation_property(self, auth_service, password):
        """
        **Validates: Requirements 8.1**
        Property: For any password with minimum length, basic validation should succeed
        """
        result = auth_service._validate_password(password)
        # Our basic implementation only checks length
        assert result is True
    
    @given(st.text(max_size=7))
    def test_short_password_rejection_property(self, auth_service, password):
        """
        **Validates: Requirements 8.1**
        Property: For any password shorter than 8 characters, validation should fail
        """
        result = auth_service._validate_password(password)
        assert result is False
    
    def test_token_generation_uniqueness_property(self, auth_service):
        """
        **Validates: Requirements 8.2**
        Property: Generated tokens should be unique across multiple generations
        """
        sample_user = User.create_new("test@example.com", "Test User")
        
        # Generate multiple tokens
        tokens = set()
        for _ in range(100):
            token = auth_service._generate_access_token(sample_user)
            tokens.add(token)
        
        # All tokens should be unique
        assert len(tokens) == 100
    
    def test_refresh_token_uniqueness_property(self, auth_service):
        """
        **Validates: Requirements 8.2**
        Property: Generated refresh tokens should be unique
        """
        sample_user = User.create_new("test@example.com", "Test User")
        
        # Generate multiple refresh tokens
        tokens = set()
        for _ in range(100):
            token = auth_service._generate_refresh_token(sample_user)
            tokens.add(token)
        
        # All tokens should be unique
        assert len(tokens) == 100
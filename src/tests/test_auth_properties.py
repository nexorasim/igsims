"""
Property-based tests for Authentication System

Tests Requirements 8.1 (User authentication and authorization) and 8.2 (Secure session management)
using property-based testing to verify universal properties across all inputs.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
import jwt
import secrets
import string

from hypothesis import given, strategies as st, assume, settings, HealthCheck
from hypothesis.strategies import composite

# Import our modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.auth_service import AuthService, AuthResult, TokenValidationResult, RegistrationData, AuthProvider
from models.user import User
from utils.auth_utils import AuthUtils
from config.settings import Settings

# Custom strategies for testing

@composite
def valid_emails(draw):
    """Generate valid email addresses"""
    local_part = draw(st.text(
        alphabet=string.ascii_letters + string.digits + "._-",
        min_size=2,
        max_size=20
    ).filter(lambda x: x[0] not in ".-" and x[-1] not in ".-" and ".." not in x))
    
    domain = draw(st.text(
        alphabet=string.ascii_letters + string.digits + "-",
        min_size=2,
        max_size=15
    ).filter(lambda x: x[0] != "-" and x[-1] != "-"))
    
    tld = draw(st.text(
        alphabet=string.ascii_letters,
        min_size=2,
        max_size=4
    ))
    
    email = f"{local_part}@{domain}.{tld}"
    # Additional validation to ensure it's a reasonable email
    assume(len(email) >= 6)  # Minimum reasonable email length
    assume("@" in email and email.count("@") == 1)
    assume("." in email.split("@")[1])  # Domain must have a dot
    
    return email

@composite
def invalid_emails(draw):
    """Generate invalid email addresses"""
    # Various invalid email patterns
    patterns = [
        st.text(max_size=50).filter(lambda x: "@" not in x),  # No @ symbol
        st.just("@domain.com"),  # Missing local part
        st.just("user@"),  # Missing domain
        st.just("user@domain"),  # Missing TLD
        st.just(""),  # Empty string
        st.just("user@@domain.com"),  # Double @
        st.just("user@domain..com"),  # Double dots
    ]
    
    return draw(st.one_of(patterns))

@composite
def strong_passwords(draw):
    """Generate strong passwords"""
    length = draw(st.integers(min_value=8, max_value=50))
    
    # Ensure at least one of each required character type
    uppercase = draw(st.text(alphabet=string.ascii_uppercase, min_size=1, max_size=5))
    lowercase = draw(st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10))
    digits = draw(st.text(alphabet=string.digits, min_size=1, max_size=5))
    special = draw(st.text(alphabet="!@#$%^&*(),.?\":{}|<>", min_size=1, max_size=5))
    
    # Fill remaining length with random characters
    remaining_length = max(0, length - len(uppercase) - len(lowercase) - len(digits) - len(special))
    filler = draw(st.text(
        alphabet=string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>",
        min_size=0,
        max_size=remaining_length
    ))
    
    # Combine and shuffle
    password_chars = list(uppercase + lowercase + digits + special + filler)
    draw(st.randoms()).shuffle(password_chars)
    
    return ''.join(password_chars)

@composite
def weak_passwords(draw):
    """Generate weak passwords"""
    patterns = [
        st.text(max_size=7),  # Too short
        st.text(alphabet=string.ascii_lowercase, min_size=8, max_size=20),  # Only lowercase
        st.text(alphabet=string.digits, min_size=8, max_size=20),  # Only digits
        st.just(""),  # Empty
        st.just("password"),  # Common weak password
        st.just("12345678"),  # Sequential digits
    ]
    
    return draw(st.one_of(patterns))

class TestAuthenticationProperties:
    """Property-based tests for authentication system"""
    
    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service for property testing"""
        with patch('services.auth_service.get_settings'), \
             patch('services.auth_service.UserRepository'), \
             patch('services.auth_service.firestore.Client'), \
             patch('services.auth_service.firebase_admin.initialize_app'), \
             patch('services.auth_service.firebase_admin.get_app'):
            
            service = AuthService()
            service._jwt_secret = "test-secret-key-for-property-testing"
            return service
    
    @given(valid_emails())
    def test_valid_email_validation_property(self, mock_auth_service, email):
        """
        **Validates: Requirements 8.1**
        Property: For any valid email format, email validation should succeed
        """
        result = mock_auth_service._validate_email(email)
        assert result is True, f"Valid email {email} should pass validation"
    
    @given(invalid_emails())
    def test_invalid_email_validation_property(self, mock_auth_service, email):
        """
        **Validates: Requirements 8.1**
        Property: For any invalid email format, email validation should fail
        """
        result = mock_auth_service._validate_email(email)
        assert result is False, f"Invalid email {email} should fail validation"
    
    @given(st.text(min_size=8, max_size=100))
    def test_minimum_password_length_property(self, mock_auth_service, password):
        """
        **Validates: Requirements 8.1**
        Property: For any password with minimum length (8+ chars), basic validation should succeed
        """
        result = mock_auth_service._validate_password(password)
        assert result is True, f"Password with {len(password)} characters should pass basic validation"
    
    @given(st.text(max_size=7))
    def test_short_password_rejection_property(self, mock_auth_service, password):
        """
        **Validates: Requirements 8.1**
        Property: For any password shorter than 8 characters, validation should fail
        """
        result = mock_auth_service._validate_password(password)
        assert result is False, f"Password with {len(password)} characters should fail validation"
    
    @given(st.text(min_size=1, max_size=50), st.text(min_size=1, max_size=50))
    def test_user_creation_property(self, display_name, role):
        """
        **Validates: Requirements 8.1**
        Property: For any valid display name and role, user creation should produce valid user objects
        """
        assume(role in ["user", "operator", "admin"])  # Valid roles only
        assume(len(display_name.strip()) > 0)  # Non-empty display name
        
        email = "test@example.com"  # Use fixed valid email
        user = User.create_new(email, display_name.strip(), role)
        
        assert user.email == email
        assert user.display_name == display_name.strip()
        assert user.role == role
        assert user.user_id is not None
        assert len(user.user_id) > 0
        assert user.is_active is True
        assert user.validate() is True
    
    @given(st.lists(st.text(min_size=1, max_size=20), min_size=0, max_size=10))
    def test_permission_management_property(self, permissions):
        """
        **Validates: Requirements 8.1**
        Property: For any list of permissions, user permission management should work correctly
        """
        user = User.create_new("test@example.com", "Test User")
        
        # Add all permissions
        for permission in permissions:
            user.add_permission(permission)
        
        # Verify all permissions are present
        for permission in permissions:
            assert user.has_permission(permission), f"User should have permission: {permission}"
        
        # Remove all permissions
        for permission in permissions:
            user.remove_permission(permission)
        
        # Verify all permissions are removed (except for admin role)
        if user.role != "admin":
            for permission in permissions:
                assert not user.has_permission(permission), f"User should not have permission: {permission}"
    
    def test_token_generation_uniqueness_property(self, mock_auth_service):
        """
        **Validates: Requirements 8.2**
        Property: Generated access tokens should be unique across multiple generations
        """
        user = User.create_new("test@example.com", "Test User")
        
        # Generate multiple tokens
        tokens = set()
        for _ in range(100):
            token = mock_auth_service._generate_access_token(user)
            tokens.add(token)
        
        # All tokens should be unique
        assert len(tokens) == 100, "All generated access tokens should be unique"
    
    def test_refresh_token_uniqueness_property(self, mock_auth_service):
        """
        **Validates: Requirements 8.2**
        Property: Generated refresh tokens should be unique across multiple generations
        """
        user = User.create_new("test@example.com", "Test User")
        
        # Generate multiple refresh tokens
        tokens = set()
        for _ in range(100):
            token = mock_auth_service._generate_refresh_token(user)
            tokens.add(token)
        
        # All tokens should be unique
        assert len(tokens) == 100, "All generated refresh tokens should be unique"
    
    @given(st.integers(min_value=1, max_value=1000))
    def test_token_expiration_property(self, mock_auth_service, minutes_in_future):
        """
        **Validates: Requirements 8.2**
        Property: For any future expiration time, tokens should be valid until expiration
        """
        user = User.create_new("test@example.com", "Test User")
        
        # Override expiration time for testing
        original_expire_minutes = mock_auth_service._access_token_expire_minutes
        mock_auth_service._access_token_expire_minutes = minutes_in_future
        
        try:
            token = mock_auth_service._generate_access_token(user)
            
            # Decode token to check expiration
            payload = jwt.decode(
                token, 
                mock_auth_service._jwt_secret, 
                algorithms=[mock_auth_service._jwt_algorithm]
            )
            
            expected_exp = datetime.utcnow() + timedelta(minutes=minutes_in_future)
            actual_exp = datetime.fromtimestamp(payload['exp'])
            
            # Allow 1 minute tolerance for test execution time
            time_diff = abs((actual_exp - expected_exp).total_seconds())
            assert time_diff < 60, f"Token expiration should be approximately {minutes_in_future} minutes from now"
            
        finally:
            # Restore original expiration time
            mock_auth_service._access_token_expire_minutes = original_expire_minutes
    
    @given(st.text(min_size=1, max_size=100))
    def test_token_payload_integrity_property(self, mock_auth_service, display_name):
        """
        **Validates: Requirements 8.2**
        Property: For any user data, generated tokens should contain correct payload information
        """
        assume(len(display_name.strip()) > 0)
        
        user = User.create_new("test@example.com", display_name.strip())
        token = mock_auth_service._generate_access_token(user)
        
        # Decode and verify payload
        payload = jwt.decode(
            token, 
            mock_auth_service._jwt_secret, 
            algorithms=[mock_auth_service._jwt_algorithm]
        )
        
        assert payload['sub'] == user.user_id
        assert payload['email'] == user.email
        assert payload['role'] == user.role
        assert payload['permissions'] == user.permissions
        assert payload['type'] == 'access'
        assert 'iat' in payload
        assert 'exp' in payload
    
    @given(st.integers(min_value=1, max_value=100))
    def test_refresh_token_storage_property(self, mock_auth_service, num_tokens):
        """
        **Validates: Requirements 8.2**
        Property: For any number of refresh tokens, storage should maintain correct associations
        """
        user = User.create_new("test@example.com", "Test User")
        
        # Generate multiple refresh tokens
        tokens = []
        for _ in range(num_tokens):
            token = mock_auth_service._generate_refresh_token(user)
            tokens.append(token)
        
        # Verify all tokens are stored correctly
        assert len(mock_auth_service._refresh_tokens) >= num_tokens
        
        for token in tokens:
            assert token in mock_auth_service._refresh_tokens
            token_data = mock_auth_service._refresh_tokens[token]
            assert token_data['user_id'] == user.user_id
            assert token_data['expires_at'] > datetime.utcnow().timestamp()
    
    @given(st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=5, unique=True))
    def test_role_permission_inheritance_property(self, permissions):
        """
        **Validates: Requirements 8.1**
        Property: For any set of permissions, admin users should have all permissions
        """
        # Create users with different roles
        admin_user = User.create_new("admin@example.com", "Admin User", "admin")
        regular_user = User.create_new("user@example.com", "Regular User", "user")
        
        # Add permissions to regular user
        for permission in permissions:
            regular_user.add_permission(permission)
        
        # Admin should have all permissions without explicitly adding them
        for permission in permissions:
            assert admin_user.has_permission(permission), f"Admin should have permission: {permission}"
            assert regular_user.has_permission(permission), f"Regular user should have explicitly added permission: {permission}"
    
    @given(st.text(min_size=1, max_size=50))
    def test_user_preference_property(self, preference_key):
        """
        **Validates: Requirements 8.1**
        Property: For any preference key, user preference management should work correctly
        """
        assume(len(preference_key.strip()) > 0)
        
        user = User.create_new("test@example.com", "Test User")
        test_value = "test_value"
        
        # Set preference
        user.set_preference(preference_key, test_value)
        
        # Get preference
        retrieved_value = user.get_preference(preference_key)
        assert retrieved_value == test_value, f"Retrieved preference should match set value"
        
        # Get non-existent preference with default
        default_value = "default"
        non_existent_value = user.get_preference("non_existent_key", default_value)
        assert non_existent_value == default_value, f"Non-existent preference should return default value"

class TestAuthUtilsProperties:
    """Property-based tests for authentication utilities"""
    
    @given(st.integers(min_value=1, max_value=100))
    def test_secure_token_generation_property(self, length):
        """
        **Validates: Requirements 8.2**
        Property: For any valid length, secure token generation should produce unique tokens
        """
        tokens = set()
        for _ in range(50):  # Generate 50 tokens
            token = AuthUtils.generate_secure_token(length)
            tokens.add(token)
            assert len(token) > 0, "Generated token should not be empty"
        
        # All tokens should be unique
        assert len(tokens) == 50, "All generated secure tokens should be unique"
    
    @given(st.integers(min_value=1, max_value=20))
    def test_verification_code_generation_property(self, length):
        """
        **Validates: Requirements 8.2**
        Property: For any valid length, verification codes should be numeric and unique
        """
        codes = set()
        for _ in range(50):
            code = AuthUtils.generate_verification_code(length)
            codes.add(code)
            assert len(code) == length, f"Verification code should be exactly {length} characters"
            assert code.isdigit(), "Verification code should contain only digits"
        
        # Most codes should be unique (allowing for some collision in small lengths)
        uniqueness_ratio = len(codes) / 50
        if length >= 4:
            assert uniqueness_ratio > 0.8, "Most verification codes should be unique"
    
    @given(st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=10))
    def test_safe_redirect_url_property(self, allowed_hosts):
        """
        **Validates: Requirements 8.1**
        Property: For any list of allowed hosts, URL safety validation should work correctly
        """
        assume(all(len(host.strip()) > 0 for host in allowed_hosts))
        allowed_hosts = [host.strip() for host in allowed_hosts]
        
        # Test relative URLs (should be safe)
        relative_urls = ["/dashboard", "/profile", "/settings"]
        for url in relative_urls:
            assert AuthUtils.is_safe_redirect_url(url, allowed_hosts), f"Relative URL {url} should be safe"
        
        # Test absolute URLs with allowed hosts
        for host in allowed_hosts[:3]:  # Test first 3 hosts to avoid too many tests
            safe_url = f"https://{host}/path"
            assert AuthUtils.is_safe_redirect_url(safe_url, allowed_hosts), f"URL with allowed host {safe_url} should be safe"
        
        # Test unsafe URLs
        unsafe_urls = ["//evil.com/path", "javascript:alert('xss')", ""]
        for url in unsafe_urls:
            assert not AuthUtils.is_safe_redirect_url(url, allowed_hosts), f"Unsafe URL {url} should be rejected"

# Integration property tests

class TestAuthenticationSecurityProperties:
    """Property-based tests for comprehensive authentication security - Property 27"""
    
    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service for security property testing"""
        with patch('services.auth_service.get_settings'), \
             patch('services.auth_service.UserRepository') as mock_repo, \
             patch('services.auth_service.firestore.Client'), \
             patch('services.auth_service.firebase_admin.initialize_app'), \
             patch('services.auth_service.firebase_admin.get_app'):
            
            service = AuthService()
            service._jwt_secret = "test-secret-key-for-security-testing"
            
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
        st.one_of(
            # Valid authentication attempts
            st.tuples(valid_emails(), strong_passwords(), st.just(True)),
            # Invalid authentication attempts  
            st.tuples(invalid_emails(), st.text(), st.just(False)),
            st.tuples(valid_emails(), weak_passwords(), st.just(False)),
            st.tuples(st.text().filter(lambda x: "@" not in x or len(x) < 5), st.text(), st.just(False))
        )
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    async def test_comprehensive_authentication_security_property(self, mock_auth_service, auth_data):
        """
        **Validates: Requirements 8.1, 8.2**
        Property 27: Comprehensive Authentication Security
        For any user access attempt or API call, the platform should implement secure 
        authentication and validate authentication tokens correctly
        """
        email, password, should_succeed = auth_data
        
        # Skip empty credentials as they're handled by input validation
        assume(email is not None and password is not None)
        assume(len(str(email)) > 0 and len(str(password)) > 0)
        
        with patch('firebase_admin.auth.create_user') as mock_create, \
             patch.object(mock_auth_service, '_authenticate_with_firebase') as mock_firebase_auth:
            
            # Check if credentials are actually valid according to our validation rules
            email_valid = mock_auth_service._validate_email(email)
            password_valid = mock_auth_service._validate_password(password)
            credentials_valid = email_valid and password_valid
            
            if should_succeed and credentials_valid:
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
                
                # Test authentication attempt
                auth_result = await mock_auth_service.login_with_email_password(email, password)
                
                # Valid credentials should succeed
                assert auth_result.success, f"Valid authentication should succeed for {email}"
                assert auth_result.user is not None, "Successful auth should return user"
                assert auth_result.access_token is not None, "Successful auth should return access token"
                assert auth_result.refresh_token is not None, "Successful auth should return refresh token"
                
                # Test token validation with a small delay to avoid timing issues
                import time
                time.sleep(0.1)  # Small delay to ensure token is not expired immediately
                token_validation = await mock_auth_service.validate_token(auth_result.access_token)
                assert token_validation.valid, "Generated access token should be valid"
                assert token_validation.user_id == auth_result.user.user_id, "Token should contain correct user ID"
                
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
                
                # Invalid credentials should fail
                assert not auth_result.success, f"Invalid authentication should fail for {email}"
                assert auth_result.user is None, "Failed auth should not return user"
                assert auth_result.access_token is None, "Failed auth should not return access token"
                assert auth_result.error_code is not None, "Failed auth should return error code"
    
    @pytest.mark.asyncio
    @given(st.text(min_size=1, max_size=200))
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    async def test_api_token_validation_security_property(self, mock_auth_service, token_input):
        """
        **Validates: Requirements 8.1, 8.2**
        Property 27: Comprehensive Authentication Security - API Token Validation
        For any API call with a token, the platform should validate authentication tokens correctly
        """
        # Test various token formats and validity
        
        if len(token_input.strip()) == 0:
            # Empty tokens should be invalid
            validation_result = await mock_auth_service.validate_token(token_input)
            assert not validation_result.valid, "Empty token should be invalid"
            return
        
        # Create a valid user and token for comparison
        valid_user = User.create_new("test@example.com", "Test User")
        valid_user.user_id = f"user-{secrets.token_hex(8)}"
        mock_auth_service.user_repository.get.return_value = valid_user
        
        valid_token = mock_auth_service._generate_access_token(valid_user)
        
        if token_input == valid_token:
            # Valid token should pass validation
            validation_result = await mock_auth_service.validate_token(token_input)
            assert validation_result.valid, "Valid token should pass validation"
            assert validation_result.user_id == valid_user.user_id, "Valid token should return correct user ID"
        else:
            # Invalid/malformed tokens should fail validation
            validation_result = await mock_auth_service.validate_token(token_input)
            assert not validation_result.valid, f"Invalid token should fail validation: {token_input[:50]}..."
            assert validation_result.user_id is None, "Invalid token should not return user ID"
            assert validation_result.error_message is not None, "Invalid token should return error message"
    
    @pytest.mark.asyncio
    @given(st.integers(min_value=-3600, max_value=3600))  # -1 hour to +1 hour
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    async def test_token_expiration_security_property(self, mock_auth_service, time_offset_seconds):
        """
        **Validates: Requirements 8.2**
        Property 27: Comprehensive Authentication Security - Token Expiration
        For any token with expiration time, the platform should correctly validate based on current time
        """
        valid_user = User.create_new("test@example.com", "Test User")
        valid_user.user_id = f"user-{secrets.token_hex(8)}"
        mock_auth_service.user_repository.get.return_value = valid_user
        
        # Create token with custom expiration - add buffer to avoid timing issues
        now = datetime.utcnow()
        # Always add at least 10 seconds buffer for non-negative offsets to avoid timing issues
        buffer_seconds = 10 if time_offset_seconds >= 0 else 0
        exp_time = now + timedelta(seconds=time_offset_seconds + buffer_seconds)
        
        payload = {
            'sub': valid_user.user_id,
            'email': valid_user.email,
            'role': valid_user.role,
            'permissions': valid_user.permissions,
            'iat': now.timestamp(),
            'exp': exp_time.timestamp(),
            'type': 'access'
        }
        
        token = jwt.encode(payload, mock_auth_service._jwt_secret, algorithm=mock_auth_service._jwt_algorithm)
        
        # Validate token
        validation_result = await mock_auth_service.validate_token(token)
        
        if time_offset_seconds >= -10:  # Allow 10 second tolerance for past tokens
            # Future expiration should be valid
            assert validation_result.valid, f"Token with future expiration (+{time_offset_seconds}s) should be valid"
            assert validation_result.user_id == valid_user.user_id, "Valid token should return correct user ID"
        else:
            # Past expiration should be invalid
            assert not validation_result.valid, f"Token with past expiration ({time_offset_seconds}s) should be invalid"
            assert "expired" in validation_result.error_message.lower(), "Expired token should return expiration error"
    
    @pytest.mark.asyncio
    @given(st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=5, unique=True))
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    async def test_permission_based_access_security_property(self, mock_auth_service, required_permissions):
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
        
        # Test admin user access (should have all permissions)
        for permission in required_permissions:
            assert admin_user.has_permission(permission), f"Admin should have permission: {permission}"
        
        # Test regular user access (should only have explicitly granted permissions)
        for permission in required_permissions:
            if permission in permissions_to_add:
                assert regular_user.has_permission(permission), f"Regular user should have granted permission: {permission}"
            else:
                assert not regular_user.has_permission(permission), f"Regular user should not have non-granted permission: {permission}"
    
    @pytest.mark.asyncio
    @given(st.integers(min_value=1, max_value=20))
    @settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    async def test_concurrent_authentication_security_property(self, mock_auth_service, concurrent_attempts):
        """
        **Validates: Requirements 8.1, 8.2**
        Property 27: Comprehensive Authentication Security - Concurrent Access
        For any number of concurrent authentication attempts, the platform should maintain security
        """
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
                    unique_tokens.add(result.access_token)
            
            assert successful_auths == concurrent_attempts, f"All {concurrent_attempts} concurrent auth attempts should succeed"
            assert len(unique_tokens) == concurrent_attempts, "All concurrent authentications should generate unique tokens"

class TestAuthenticationIntegrationProperties:
    """Property-based integration tests for authentication system"""
    
    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service for integration testing"""
        with patch('services.auth_service.get_settings'), \
             patch('services.auth_service.UserRepository') as mock_repo, \
             patch('services.auth_service.firestore.Client'), \
             patch('services.auth_service.firebase_admin.initialize_app'), \
             patch('services.auth_service.firebase_admin.get_app'):
            
            service = AuthService()
            service._jwt_secret = "test-secret-key-for-integration-testing"
            
            # Setup mock repository
            mock_repo_instance = Mock()
            mock_repo_instance.get_by_email = AsyncMock(return_value=None)
            mock_repo_instance.get = AsyncMock()
            mock_repo_instance.create = AsyncMock(return_value=True)
            mock_repo_instance.update_last_login = AsyncMock(return_value=True)
            service.user_repository = mock_repo_instance
            
            return service
    
    @pytest.mark.asyncio
    @given(valid_emails(), st.text(min_size=8, max_size=50), st.text(min_size=1, max_size=50))
    async def test_registration_login_flow_property(self, mock_auth_service, email, password, display_name):
        """
        **Validates: Requirements 8.1, 8.2**
        Property: For any valid registration data, the complete registration-login flow should work
        """
        assume(len(display_name.strip()) > 0)
        
        with patch('firebase_admin.auth.create_user') as mock_create, \
             patch.object(mock_auth_service, '_send_email_verification', return_value=True), \
             patch.object(mock_auth_service, '_authenticate_with_firebase') as mock_auth:
            
            # Setup mocks
            mock_firebase_user = Mock()
            mock_firebase_user.uid = "firebase-uid-123"
            mock_create.return_value = mock_firebase_user
            
            mock_auth.return_value = {
                "success": True,
                "user_id": "firebase-uid-123",
                "id_token": "firebase-token",
                "refresh_token": "firebase-refresh"
            }
            
            # Setup user repository mock to return created user
            created_user = User.create_new(email, display_name.strip())
            created_user.user_id = "firebase-uid-123"
            mock_auth_service.user_repository.get.return_value = created_user
            
            # Test registration
            registration_data = RegistrationData(
                email=email,
                password=password,
                display_name=display_name.strip()
            )
            
            reg_result = await mock_auth_service.register_user(registration_data)
            assert reg_result.success, f"Registration should succeed for valid data"
            assert reg_result.user is not None
            assert reg_result.access_token is not None
            assert reg_result.refresh_token is not None
            
            # Test login with same credentials
            login_result = await mock_auth_service.login_with_email_password(email, password)
            assert login_result.success, f"Login should succeed after registration"
            assert login_result.user.email == email
            assert login_result.access_token is not None
            assert login_result.refresh_token is not None
    
    @pytest.mark.asyncio
    @given(st.integers(min_value=1, max_value=10))
    async def test_token_refresh_chain_property(self, mock_auth_service, refresh_count):
        """
        **Validates: Requirements 8.2**
        Property: For any number of token refreshes, the chain should maintain security
        """
        user = User.create_new("test@example.com", "Test User")
        mock_auth_service.user_repository.get.return_value = user
        
        # Start with initial tokens
        current_access_token = mock_auth_service._generate_access_token(user)
        current_refresh_token = mock_auth_service._generate_refresh_token(user)
        
        access_tokens = [current_access_token]
        
        # Perform chain of refreshes
        for i in range(refresh_count):
            result = await mock_auth_service.refresh_access_token(current_refresh_token)
            
            assert result.success, f"Refresh {i+1} should succeed"
            assert result.access_token is not None
            assert result.access_token != current_access_token, f"New access token should be different"
            
            # Verify new token is valid
            validation = await mock_auth_service.validate_token(result.access_token)
            assert validation.valid, f"Refreshed token {i+1} should be valid"
            
            access_tokens.append(result.access_token)
            current_access_token = result.access_token
        
        # All access tokens should be unique
        assert len(set(access_tokens)) == len(access_tokens), "All access tokens in refresh chain should be unique"
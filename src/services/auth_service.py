"""
Firebase Authentication Service for iGSIM AI Agent Platform

This service handles user authentication, registration, and JWT token management
using Firebase Auth with email/password and OAuth providers.

Requirements: 8.1 (User authentication and authorization), 8.2 (Secure session management)
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
import jwt
import secrets
import hashlib
from dataclasses import dataclass
from enum import Enum

import firebase_admin
from firebase_admin import auth as firebase_auth, credentials
from google.cloud import firestore
import httpx

# Import our models and repositories
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.user import User
from repositories.user_repository import UserRepository
from config.settings import get_settings

# Configure logging
logger = logging.getLogger(__name__)

class AuthProvider(Enum):
    """Supported authentication providers"""
    EMAIL_PASSWORD = "email_password"
    GOOGLE = "google.com"
    GITHUB = "github.com"
    MICROSOFT = "microsoft.com"

@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    user: Optional[User] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None

@dataclass
class TokenValidationResult:
    """Token validation result"""
    valid: bool
    user_id: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

@dataclass
class RegistrationData:
    """User registration data"""
    email: str
    password: str
    display_name: str
    role: str = "user"
    send_verification: bool = True

class AuthService:
    """Firebase Authentication Service"""
    
    def __init__(self):
        self.settings = get_settings()
        self.user_repository = UserRepository()
        self.db = firestore.Client()
        self._jwt_secret = self.settings.jwt_secret_key
        self._jwt_algorithm = "HS256"
        self._access_token_expire_minutes = 30
        self._refresh_token_expire_days = 30
        
        # Initialize Firebase Admin SDK if not already initialized
        self._initialize_firebase()
        
        # Cache for refresh tokens
        self._refresh_tokens: Dict[str, Dict[str, Any]] = {}
        
        logger.info("AuthService initialized")
    
    def _initialize_firebase(self) -> None:
        """Initialize Firebase Admin SDK"""
        try:
            # Check if Firebase is already initialized
            firebase_admin.get_app()
            logger.info("Firebase Admin SDK already initialized")
        except ValueError:
            # Initialize Firebase Admin SDK
            if self.settings.firebase_credentials_path:
                cred = credentials.Certificate(self.settings.firebase_credentials_path)
            else:
                # Use default credentials (for Cloud Run, etc.)
                cred = credentials.ApplicationDefault()
            
            firebase_admin.initialize_app(cred, {
                'projectId': self.settings.firebase_project_id,
            })
            logger.info("Firebase Admin SDK initialized")
    
    async def register_user(self, registration_data: RegistrationData) -> AuthResult:
        """
        Register a new user with email/password authentication
        
        Args:
            registration_data: User registration information
            
        Returns:
            AuthResult with success status and user data
        """
        try:
            # Validate registration data
            if not self._validate_email(registration_data.email):
                return AuthResult(
                    success=False,
                    error_code="INVALID_EMAIL",
                    error_message="Invalid email format"
                )
            
            if not self._validate_password(registration_data.password):
                return AuthResult(
                    success=False,
                    error_code="WEAK_PASSWORD",
                    error_message="Password must be at least 8 characters long"
                )
            
            # Check if user already exists
            existing_user = await self.user_repository.get_by_email(registration_data.email)
            if existing_user:
                return AuthResult(
                    success=False,
                    error_code="USER_EXISTS",
                    error_message="User with this email already exists"
                )
            
            # Create Firebase user
            firebase_user = firebase_auth.create_user(
                email=registration_data.email,
                password=registration_data.password,
                display_name=registration_data.display_name,
                email_verified=False
            )
            
            # Create user in our database
            user = User.create_new(
                email=registration_data.email,
                display_name=registration_data.display_name,
                role=registration_data.role
            )
            user.user_id = firebase_user.uid  # Use Firebase UID as our user ID
            
            # Save user to database
            await self.user_repository.create(user)
            
            # Send email verification if requested
            if registration_data.send_verification:
                await self._send_email_verification(firebase_user.uid)
            
            # Generate tokens
            access_token = self._generate_access_token(user)
            refresh_token = self._generate_refresh_token(user)
            
            logger.info(f"User registered successfully: {user.email}")
            
            return AuthResult(
                success=True,
                user=user,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=self._access_token_expire_minutes * 60
            )
            
        except firebase_auth.EmailAlreadyExistsError:
            return AuthResult(
                success=False,
                error_code="EMAIL_EXISTS",
                error_message="Email already exists"
            )
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return AuthResult(
                success=False,
                error_code="REGISTRATION_FAILED",
                error_message=str(e)
            )
    
    async def login_with_email_password(self, email: str, password: str) -> AuthResult:
        """
        Authenticate user with email and password
        
        Args:
            email: User email
            password: User password
            
        Returns:
            AuthResult with authentication status and tokens
        """
        try:
            # Validate input
            if not email or not password:
                return AuthResult(
                    success=False,
                    error_code="MISSING_CREDENTIALS",
                    error_message="Email and password are required"
                )
            
            # Authenticate with Firebase Auth REST API
            auth_result = await self._authenticate_with_firebase(email, password)
            if not auth_result["success"]:
                return AuthResult(
                    success=False,
                    error_code=auth_result.get("error_code", "AUTH_FAILED"),
                    error_message=auth_result.get("error_message", "Authentication failed")
                )
            
            firebase_uid = auth_result["user_id"]
            
            # Get user from our database
            user = await self.user_repository.get(firebase_uid)
            if not user:
                # User exists in Firebase but not in our database - create it
                firebase_user = firebase_auth.get_user(firebase_uid)
                user = User.create_new(
                    email=firebase_user.email,
                    display_name=firebase_user.display_name or firebase_user.email.split('@')[0]
                )
                user.user_id = firebase_uid
                await self.user_repository.create(user)
            
            # Check if user is active
            if not user.is_active:
                return AuthResult(
                    success=False,
                    error_code="USER_DISABLED",
                    error_message="User account is disabled"
                )
            
            # Update last login
            await self.user_repository.update_last_login(user.user_id)
            
            # Generate tokens
            access_token = self._generate_access_token(user)
            refresh_token = self._generate_refresh_token(user)
            
            logger.info(f"User logged in successfully: {user.email}")
            
            return AuthResult(
                success=True,
                user=user,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=self._access_token_expire_minutes * 60
            )
            
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return AuthResult(
                success=False,
                error_code="LOGIN_FAILED",
                error_message=str(e)
            )
    
    async def login_with_oauth(self, provider: AuthProvider, oauth_token: str) -> AuthResult:
        """
        Authenticate user with OAuth provider
        
        Args:
            provider: OAuth provider (Google, GitHub, etc.)
            oauth_token: OAuth access token
            
        Returns:
            AuthResult with authentication status and tokens
        """
        try:
            # Verify OAuth token with Firebase
            decoded_token = firebase_auth.verify_id_token(oauth_token)
            firebase_uid = decoded_token['uid']
            
            # Check if this is the expected provider
            firebase_user = firebase_auth.get_user(firebase_uid)
            provider_found = False
            
            for provider_data in firebase_user.provider_data:
                if provider_data.provider_id == provider.value:
                    provider_found = True
                    break
            
            if not provider_found:
                return AuthResult(
                    success=False,
                    error_code="INVALID_PROVIDER",
                    error_message=f"User is not authenticated with {provider.value}"
                )
            
            # Get or create user in our database
            user = await self.user_repository.get(firebase_uid)
            if not user:
                user = User.create_new(
                    email=firebase_user.email,
                    display_name=firebase_user.display_name or firebase_user.email.split('@')[0]
                )
                user.user_id = firebase_uid
                await self.user_repository.create(user)
            
            # Check if user is active
            if not user.is_active:
                return AuthResult(
                    success=False,
                    error_code="USER_DISABLED",
                    error_message="User account is disabled"
                )
            
            # Update last login
            await self.user_repository.update_last_login(user.user_id)
            
            # Generate tokens
            access_token = self._generate_access_token(user)
            refresh_token = self._generate_refresh_token(user)
            
            logger.info(f"OAuth login successful: {user.email} via {provider.value}")
            
            return AuthResult(
                success=True,
                user=user,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=self._access_token_expire_minutes * 60
            )
            
        except firebase_auth.InvalidIdTokenError:
            return AuthResult(
                success=False,
                error_code="INVALID_TOKEN",
                error_message="Invalid OAuth token"
            )
        except Exception as e:
            logger.error(f"OAuth login failed: {e}")
            return AuthResult(
                success=False,
                error_code="OAUTH_LOGIN_FAILED",
                error_message=str(e)
            )
    
    async def validate_token(self, token: str) -> TokenValidationResult:
        """
        Validate JWT access token
        
        Args:
            token: JWT access token
            
        Returns:
            TokenValidationResult with validation status and claims
        """
        try:
            # Decode JWT token
            payload = jwt.decode(
                token,
                self._jwt_secret,
                algorithms=[self._jwt_algorithm]
            )
            
            # Check expiration
            if payload.get('exp', 0) < datetime.utcnow().timestamp():
                return TokenValidationResult(
                    valid=False,
                    error_message="Token expired"
                )
            
            # Verify user exists and is active
            user_id = payload.get('sub')
            if not user_id:
                return TokenValidationResult(
                    valid=False,
                    error_message="Invalid token format"
                )
            
            user = await self.user_repository.get(user_id)
            if not user or not user.is_active:
                return TokenValidationResult(
                    valid=False,
                    error_message="User not found or inactive"
                )
            
            return TokenValidationResult(
                valid=True,
                user_id=user_id,
                claims=payload
            )
            
        except jwt.ExpiredSignatureError:
            return TokenValidationResult(
                valid=False,
                error_message="Token expired"
            )
        except jwt.InvalidTokenError:
            return TokenValidationResult(
                valid=False,
                error_message="Invalid token"
            )
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return TokenValidationResult(
                valid=False,
                error_message=str(e)
            )
    
    async def refresh_access_token(self, refresh_token: str) -> AuthResult:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            AuthResult with new access token
        """
        try:
            # Validate refresh token
            if refresh_token not in self._refresh_tokens:
                return AuthResult(
                    success=False,
                    error_code="INVALID_REFRESH_TOKEN",
                    error_message="Invalid refresh token"
                )
            
            token_data = self._refresh_tokens[refresh_token]
            
            # Check expiration
            if token_data['expires_at'] < datetime.utcnow().timestamp():
                # Remove expired token
                del self._refresh_tokens[refresh_token]
                return AuthResult(
                    success=False,
                    error_code="REFRESH_TOKEN_EXPIRED",
                    error_message="Refresh token expired"
                )
            
            # Get user
            user = await self.user_repository.get(token_data['user_id'])
            if not user or not user.is_active:
                # Remove token for inactive user
                del self._refresh_tokens[refresh_token]
                return AuthResult(
                    success=False,
                    error_code="USER_INACTIVE",
                    error_message="User not found or inactive"
                )
            
            # Generate new access token
            access_token = self._generate_access_token(user)
            
            return AuthResult(
                success=True,
                user=user,
                access_token=access_token,
                refresh_token=refresh_token,  # Keep the same refresh token
                expires_in=self._access_token_expire_minutes * 60
            )
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return AuthResult(
                success=False,
                error_code="REFRESH_FAILED",
                error_message=str(e)
            )
    
    async def logout(self, refresh_token: str) -> bool:
        """
        Logout user by invalidating refresh token
        
        Args:
            refresh_token: Refresh token to invalidate
            
        Returns:
            True if successful
        """
        try:
            if refresh_token in self._refresh_tokens:
                del self._refresh_tokens[refresh_token]
            return True
        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return False
    
    async def send_password_reset_email(self, email: str) -> bool:
        """
        Send password reset email
        
        Args:
            email: User email address
            
        Returns:
            True if email sent successfully
        """
        try:
            # Generate password reset link
            link = firebase_auth.generate_password_reset_link(email)
            
            # In a real implementation, you would send this via email service
            # For now, we'll just log it
            logger.info(f"Password reset link for {email}: {link}")
            
            return True
            
        except firebase_auth.UserNotFoundError:
            logger.warning(f"Password reset requested for non-existent user: {email}")
            # Return True to prevent email enumeration attacks
            return True
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            return False
    
    async def verify_email(self, user_id: str) -> bool:
        """
        Mark user email as verified
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful
        """
        try:
            firebase_auth.update_user(user_id, email_verified=True)
            logger.info(f"Email verified for user: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Email verification failed: {e}")
            return False
    
    async def change_password(self, user_id: str, new_password: str) -> bool:
        """
        Change user password
        
        Args:
            user_id: User ID
            new_password: New password
            
        Returns:
            True if successful
        """
        try:
            if not self._validate_password(new_password):
                return False
            
            firebase_auth.update_user(user_id, password=new_password)
            logger.info(f"Password changed for user: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return False
    
    async def get_user_by_token(self, token: str) -> Optional[User]:
        """
        Get user by access token
        
        Args:
            token: JWT access token
            
        Returns:
            User object if token is valid
        """
        validation_result = await self.validate_token(token)
        if validation_result.valid and validation_result.user_id:
            return await self.user_repository.get(validation_result.user_id)
        return None
    
    # Private helper methods
    
    def _generate_access_token(self, user: User) -> str:
        """Generate JWT access token"""
        now = datetime.utcnow()
        payload = {
            'sub': user.user_id,
            'email': user.email,
            'role': user.role,
            'permissions': user.permissions,
            'iat': now.timestamp(),
            'exp': (now + timedelta(minutes=self._access_token_expire_minutes)).timestamp(),
            'type': 'access'
        }
        
        return jwt.encode(payload, self._jwt_secret, algorithm=self._jwt_algorithm)
    
    def _generate_refresh_token(self, user: User) -> str:
        """Generate refresh token"""
        refresh_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=self._refresh_token_expire_days)
        
        self._refresh_tokens[refresh_token] = {
            'user_id': user.user_id,
            'expires_at': expires_at.timestamp(),
            'created_at': datetime.utcnow().timestamp()
        }
        
        return refresh_token
    
    async def _authenticate_with_firebase(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate with Firebase Auth REST API"""
        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.settings.firebase_api_key}"
            
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "user_id": data["localId"],
                        "id_token": data["idToken"],
                        "refresh_token": data["refreshToken"]
                    }
                else:
                    error_data = response.json()
                    error_message = error_data.get("error", {}).get("message", "Authentication failed")
                    
                    return {
                        "success": False,
                        "error_code": "AUTH_FAILED",
                        "error_message": error_message
                    }
                    
        except Exception as e:
            return {
                "success": False,
                "error_code": "AUTH_ERROR",
                "error_message": str(e)
            }
    
    async def _send_email_verification(self, user_id: str) -> bool:
        """Send email verification"""
        try:
            link = firebase_auth.generate_email_verification_link(
                firebase_auth.get_user(user_id).email
            )
            
            # In a real implementation, send this via email service
            logger.info(f"Email verification link for user {user_id}: {link}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email verification: {e}")
            return False
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _validate_password(self, password: str) -> bool:
        """Validate password strength"""
        return len(password) >= 8
    
    async def cleanup_expired_tokens(self) -> int:
        """Clean up expired refresh tokens"""
        try:
            current_time = datetime.utcnow().timestamp()
            expired_tokens = []
            
            for token, data in self._refresh_tokens.items():
                if data['expires_at'] < current_time:
                    expired_tokens.append(token)
            
            for token in expired_tokens:
                del self._refresh_tokens[token]
            
            logger.info(f"Cleaned up {len(expired_tokens)} expired refresh tokens")
            return len(expired_tokens)
            
        except Exception as e:
            logger.error(f"Token cleanup failed: {e}")
            return 0

# Global auth service instance
_auth_service: Optional[AuthService] = None

def get_auth_service() -> AuthService:
    """Get global auth service instance"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
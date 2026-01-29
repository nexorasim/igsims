"""
Authentication API endpoints for iGSIM AI Agent Platform
"""

from typing import Dict, Any, Optional
from datetime import datetime
import logging

from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, EmailStr, Field

# Import our services and utilities
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.auth_service import get_auth_service, AuthService, AuthProvider, RegistrationData
from utils.auth_utils import (
    get_current_user, 
    get_current_active_user, 
    AuthUtils, 
    rate_limiter
)
from models.user import User

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/auth", tags=["authentication"])

# Pydantic models for request/response

class LoginRequest(BaseModel):
    """Login request model"""
    email: EmailStr
    password: str = Field(..., min_length=1)

class RegisterRequest(BaseModel):
    """Registration request model"""
    email: EmailStr
    password: str = Field(..., min_length=8)
    display_name: str = Field(..., min_length=1, max_length=100)
    role: str = Field(default="user", regex="^(user|operator|admin)$")

class OAuthLoginRequest(BaseModel):
    """OAuth login request model"""
    provider: str = Field(..., regex="^(google.com|github.com|microsoft.com)$")
    oauth_token: str = Field(..., min_length=1)

class RefreshTokenRequest(BaseModel):
    """Refresh token request model"""
    refresh_token: str = Field(..., min_length=1)

class PasswordResetRequest(BaseModel):
    """Password reset request model"""
    email: EmailStr

class ChangePasswordRequest(BaseModel):
    """Change password request model"""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)

class AuthResponse(BaseModel):
    """Authentication response model"""
    success: bool
    message: str
    user: Optional[Dict[str, Any]] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None

class UserResponse(BaseModel):
    """User response model"""
    user_id: str
    email: str
    display_name: str
    role: str
    permissions: list
    is_active: bool
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

# Helper functions

def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    return request.client.host if request.client else "unknown"

def user_to_dict(user: User) -> Dict[str, Any]:
    """Convert User model to dictionary for response"""
    return {
        "user_id": user.user_id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "permissions": user.permissions,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "avatar_url": user.get_avatar_url()
    }

# Authentication endpoints

@router.post("/register", response_model=AuthResponse)
async def register(
    request: RegisterRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user account
    
    Args:
        request: Registration request data
        http_request: HTTP request object
        auth_service: Authentication service
        
    Returns:
        Authentication response with user data and tokens
    """
    try:
        # Check rate limiting
        client_ip = get_client_ip(http_request)
        if rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many registration attempts. Please try again later."
            )
        
        # Validate input
        if not AuthUtils.validate_email(request.email):
            rate_limiter.record_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        password_validation = AuthUtils.validate_password(request.password)
        if not password_validation["valid"]:
            rate_limiter.record_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
            )
        
        # Create registration data
        registration_data = RegistrationData(
            email=request.email,
            password=request.password,
            display_name=request.display_name,
            role=request.role
        )
        
        # Register user
        result = await auth_service.register_user(registration_data)
        
        if not result.success:
            rate_limiter.record_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message or "Registration failed"
            )
        
        # Clear rate limiting on success
        rate_limiter.clear_attempts(client_ip)
        
        logger.info(f"User registered successfully: {request.email}")
        
        return AuthResponse(
            success=True,
            message="User registered successfully",
            user=user_to_dict(result.user),
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            expires_in=result.expires_in
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/login", response_model=AuthResponse)
async def login(
    request: LoginRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user with email and password
    
    Args:
        request: Login request data
        http_request: HTTP request object
        auth_service: Authentication service
        
    Returns:
        Authentication response with user data and tokens
    """
    try:
        # Check rate limiting
        client_ip = get_client_ip(http_request)
        if rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please try again later."
            )
        
        # Authenticate user
        result = await auth_service.login_with_email_password(
            request.email, 
            request.password
        )
        
        if not result.success:
            rate_limiter.record_attempt(client_ip)
            
            # Return generic error message to prevent user enumeration
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Clear rate limiting on success
        rate_limiter.clear_attempts(client_ip)
        
        logger.info(f"User logged in successfully: {request.email}")
        
        return AuthResponse(
            success=True,
            message="Login successful",
            user=user_to_dict(result.user),
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            expires_in=result.expires_in
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/oauth/login", response_model=AuthResponse)
async def oauth_login(
    request: OAuthLoginRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user with OAuth provider
    
    Args:
        request: OAuth login request data
        http_request: HTTP request object
        auth_service: Authentication service
        
    Returns:
        Authentication response with user data and tokens
    """
    try:
        # Check rate limiting
        client_ip = get_client_ip(http_request)
        if rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please try again later."
            )
        
        # Map provider string to enum
        provider_map = {
            "google.com": AuthProvider.GOOGLE,
            "github.com": AuthProvider.GITHUB,
            "microsoft.com": AuthProvider.MICROSOFT
        }
        
        provider = provider_map.get(request.provider)
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported OAuth provider"
            )
        
        # Authenticate with OAuth
        result = await auth_service.login_with_oauth(provider, request.oauth_token)
        
        if not result.success:
            rate_limiter.record_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error_message or "OAuth authentication failed"
            )
        
        # Clear rate limiting on success
        rate_limiter.clear_attempts(client_ip)
        
        logger.info(f"OAuth login successful: {result.user.email} via {request.provider}")
        
        return AuthResponse(
            success=True,
            message="OAuth login successful",
            user=user_to_dict(result.user),
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            expires_in=result.expires_in
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Refresh access token using refresh token
    
    Args:
        request: Refresh token request data
        auth_service: Authentication service
        
    Returns:
        Authentication response with new access token
    """
    try:
        result = await auth_service.refresh_access_token(request.refresh_token)
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error_message or "Token refresh failed"
            )
        
        return AuthResponse(
            success=True,
            message="Token refreshed successfully",
            user=user_to_dict(result.user),
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            expires_in=result.expires_in
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/logout")
async def logout(
    request: RefreshTokenRequest,
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Logout user by invalidating refresh token
    
    Args:
        request: Refresh token request data
        current_user: Current authenticated user
        auth_service: Authentication service
        
    Returns:
        Success message
    """
    try:
        success = await auth_service.logout(request.refresh_token)
        
        if success:
            logger.info(f"User logged out: {current_user.email}")
            return {"success": True, "message": "Logout successful"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Logout failed"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/reset-password")
async def reset_password(
    request: PasswordResetRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Send password reset email
    
    Args:
        request: Password reset request data
        http_request: HTTP request object
        auth_service: Authentication service
        
    Returns:
        Success message
    """
    try:
        # Check rate limiting
        client_ip = get_client_ip(http_request)
        if rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many password reset attempts. Please try again later."
            )
        
        success = await auth_service.send_password_reset_email(request.email)
        
        # Always return success to prevent email enumeration
        return {
            "success": True, 
            "message": "If the email exists, a password reset link has been sent"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        # Still return success to prevent information disclosure
        return {
            "success": True, 
            "message": "If the email exists, a password reset link has been sent"
        }

@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Change user password
    
    Args:
        request: Change password request data
        current_user: Current authenticated user
        auth_service: Authentication service
        
    Returns:
        Success message
    """
    try:
        # Validate new password
        password_validation = AuthUtils.validate_password(request.new_password)
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
            )
        
        # Verify current password by attempting login
        login_result = await auth_service.login_with_email_password(
            current_user.email, 
            request.current_password
        )
        
        if not login_result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Change password
        success = await auth_service.change_password(
            current_user.user_id, 
            request.new_password
        )
        
        if success:
            logger.info(f"Password changed for user: {current_user.email}")
            return {"success": True, "message": "Password changed successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password change failed"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user information
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Current user information
    """
    return UserResponse(
        user_id=current_user.user_id,
        email=current_user.email,
        display_name=current_user.display_name,
        role=current_user.role,
        permissions=current_user.permissions,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login=current_user.last_login
    )

@router.post("/verify-email/{user_id}")
async def verify_email(
    user_id: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Verify user email address
    
    Args:
        user_id: User ID to verify
        auth_service: Authentication service
        
    Returns:
        Success message
    """
    try:
        success = await auth_service.verify_email(user_id)
        
        if success:
            return {"success": True, "message": "Email verified successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email verification failed"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/validate-token")
async def validate_token(
    current_user: User = Depends(get_current_user)
):
    """
    Validate current access token
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Token validation result
    """
    return {
        "valid": True,
        "user": user_to_dict(current_user),
        "message": "Token is valid"
    }
"""
Authentication utilities for iGSIM AI Agent Platform
"""

import re
import hashlib
import secrets
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from functools import wraps
import logging

from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Import our services
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.auth_service import get_auth_service, AuthService
from models.user import User

logger = logging.getLogger(__name__)

# Security scheme for FastAPI
security = HTTPBearer()

class AuthUtils:
    """Authentication utility functions"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        """
        Validate password strength
        
        Returns:
            Dict with validation result and requirements
        """
        result = {
            "valid": True,
            "errors": [],
            "requirements": {
                "min_length": 8,
                "has_uppercase": False,
                "has_lowercase": False,
                "has_digit": False,
                "has_special": False
            }
        }
        
        if len(password) < 8:
            result["valid"] = False
            result["errors"].append("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', password):
            result["errors"].append("Password must contain at least one uppercase letter")
        else:
            result["requirements"]["has_uppercase"] = True
        
        if not re.search(r'[a-z]', password):
            result["errors"].append("Password must contain at least one lowercase letter")
        else:
            result["requirements"]["has_lowercase"] = True
        
        if not re.search(r'\d', password):
            result["errors"].append("Password must contain at least one digit")
        else:
            result["requirements"]["has_digit"] = True
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            result["errors"].append("Password must contain at least one special character")
        else:
            result["requirements"]["has_special"] = True
        
        # For basic implementation, only require minimum length
        if len(password) >= 8:
            result["valid"] = True
            result["errors"] = []
        
        return result
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt (placeholder implementation)"""
        # In a real implementation, use bcrypt
        salt = secrets.token_hex(16)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() + ':' + salt
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash (placeholder implementation)"""
        try:
            hash_part, salt = hashed.split(':')
            return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == hash_part
        except:
            return False
    
    @staticmethod
    def generate_verification_code(length: int = 6) -> str:
        """Generate numeric verification code"""
        return ''.join(secrets.choice('0123456789') for _ in range(length))
    
    @staticmethod
    def is_safe_redirect_url(url: str, allowed_hosts: List[str]) -> bool:
        """Check if redirect URL is safe"""
        if not url:
            return False
        
        # Check for absolute URLs
        if url.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc in allowed_hosts
        
        # Relative URLs are generally safe
        return url.startswith('/') and not url.startswith('//')

# FastAPI Dependencies

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(get_auth_service)
) -> User:
    """
    FastAPI dependency to get current authenticated user
    
    Args:
        credentials: HTTP Bearer token
        auth_service: Authentication service
        
    Returns:
        Current user
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        token = credentials.credentials
        user = await auth_service.get_user_by_token(token)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    FastAPI dependency to get current active user
    
    Args:
        current_user: Current user from get_current_user
        
    Returns:
        Current active user
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

def require_permissions(required_permissions: List[str]):
    """
    Decorator to require specific permissions
    
    Args:
        required_permissions: List of required permissions
        
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        for permission in required_permissions:
            if not current_user.has_permission(permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission} required"
                )
        return current_user
    
    return permission_dependency

def require_role(required_role: str):
    """
    Decorator to require specific role
    
    Args:
        required_role: Required user role
        
    Returns:
        FastAPI dependency function
    """
    async def role_dependency(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        if current_user.role != required_role and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required"
            )
        return current_user
    
    return role_dependency

async def get_optional_user(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
) -> Optional[User]:
    """
    FastAPI dependency to get current user if authenticated (optional)
    
    Args:
        request: FastAPI request object
        auth_service: Authentication service
        
    Returns:
        Current user if authenticated, None otherwise
    """
    try:
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            return None
        
        token = authorization.split(" ")[1]
        user = await auth_service.get_user_by_token(token)
        
        return user if user and user.is_active else None
        
    except Exception as e:
        logger.debug(f"Optional authentication failed: {e}")
        return None

# Rate limiting utilities

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self._attempts: Dict[str, List[datetime]] = {}
        self._lockouts: Dict[str, datetime] = {}
    
    def is_rate_limited(self, identifier: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """
        Check if identifier is rate limited
        
        Args:
            identifier: Unique identifier (e.g., IP address, user ID)
            max_attempts: Maximum attempts allowed
            window_minutes: Time window in minutes
            
        Returns:
            True if rate limited
        """
        now = datetime.utcnow()
        
        # Check if currently locked out
        if identifier in self._lockouts:
            if now < self._lockouts[identifier]:
                return True
            else:
                # Lockout expired
                del self._lockouts[identifier]
        
        # Clean old attempts
        if identifier in self._attempts:
            cutoff = now - timedelta(minutes=window_minutes)
            self._attempts[identifier] = [
                attempt for attempt in self._attempts[identifier]
                if attempt > cutoff
            ]
        
        # Check current attempts
        attempts = self._attempts.get(identifier, [])
        return len(attempts) >= max_attempts
    
    def record_attempt(self, identifier: str, max_attempts: int = 5, lockout_minutes: int = 15):
        """
        Record a failed attempt
        
        Args:
            identifier: Unique identifier
            max_attempts: Maximum attempts before lockout
            lockout_minutes: Lockout duration in minutes
        """
        now = datetime.utcnow()
        
        if identifier not in self._attempts:
            self._attempts[identifier] = []
        
        self._attempts[identifier].append(now)
        
        # Check if should be locked out
        if len(self._attempts[identifier]) >= max_attempts:
            self._lockouts[identifier] = now + timedelta(minutes=lockout_minutes)
    
    def clear_attempts(self, identifier: str):
        """Clear attempts for identifier"""
        if identifier in self._attempts:
            del self._attempts[identifier]
        if identifier in self._lockouts:
            del self._lockouts[identifier]

# Global rate limiter instance
rate_limiter = RateLimiter()

# Middleware for rate limiting
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Check rate limit for authentication endpoints
    if request.url.path in ["/auth/login", "/auth/register", "/auth/reset-password"]:
        if rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later."
            )
    
    response = await call_next(request)
    
    # Record failed authentication attempts
    if (request.url.path in ["/auth/login", "/auth/register"] and 
        response.status_code in [401, 403]):
        rate_limiter.record_attempt(client_ip)
    elif response.status_code == 200 and request.url.path == "/auth/login":
        # Clear attempts on successful login
        rate_limiter.clear_attempts(client_ip)
    
    return response
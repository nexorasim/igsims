"""
Configuration settings for iGSIM AI Agent Platform
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
import secrets

@dataclass
class TLSConfig:
    """TLS/SSL configuration settings"""
    enabled: bool = True
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    verify_mode: str = "required"  # none, optional, required
    min_version: str = "TLSv1.2"
    max_version: str = "TLSv1.3"
    ciphers: Optional[str] = None
    
    def __post_init__(self):
        """Initialize TLS settings from environment"""
        self.enabled = os.getenv("TLS_ENABLED", "true").lower() == "true"
        self.cert_file = os.getenv("TLS_CERT_FILE")
        self.key_file = os.getenv("TLS_KEY_FILE")
        self.ca_file = os.getenv("TLS_CA_FILE")
        self.verify_mode = os.getenv("TLS_VERIFY_MODE", "required")
        self.min_version = os.getenv("TLS_MIN_VERSION", "TLSv1.2")
        self.max_version = os.getenv("TLS_MAX_VERSION", "TLSv1.3")
        self.ciphers = os.getenv("TLS_CIPHERS")

@dataclass
class EncryptionSettings:
    """Encryption configuration settings"""
    data_encryption_enabled: bool = True
    field_level_encryption: bool = True
    asymmetric_encryption: bool = False
    key_rotation_days: int = 90
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation_iterations: int = 100000
    
    def __post_init__(self):
        """Initialize encryption settings from environment"""
        self.data_encryption_enabled = os.getenv("DATA_ENCRYPTION_ENABLED", "true").lower() == "true"
        self.field_level_encryption = os.getenv("FIELD_LEVEL_ENCRYPTION", "true").lower() == "true"
        self.asymmetric_encryption = os.getenv("ASYMMETRIC_ENCRYPTION", "false").lower() == "true"
        self.key_rotation_days = int(os.getenv("KEY_ROTATION_DAYS", "90"))
        self.encryption_algorithm = os.getenv("ENCRYPTION_ALGORITHM", "AES-256-GCM")
        self.key_derivation_iterations = int(os.getenv("KEY_DERIVATION_ITERATIONS", "100000"))

@dataclass
class SecuritySettings:
    """Security configuration settings"""
    enforce_https: bool = True
    secure_cookies: bool = True
    csrf_protection: bool = True
    rate_limiting: bool = True
    api_key_rotation: bool = True
    audit_logging: bool = True
    security_headers: bool = True
    
    def __post_init__(self):
        """Initialize security settings from environment"""
        self.enforce_https = os.getenv("ENFORCE_HTTPS", "true").lower() == "true"
        self.secure_cookies = os.getenv("SECURE_COOKIES", "true").lower() == "true"
        self.csrf_protection = os.getenv("CSRF_PROTECTION", "true").lower() == "true"
        self.rate_limiting = os.getenv("RATE_LIMITING", "true").lower() == "true"
        self.api_key_rotation = os.getenv("API_KEY_ROTATION", "true").lower() == "true"
        self.audit_logging = os.getenv("AUDIT_LOGGING", "true").lower() == "true"
        self.security_headers = os.getenv("SECURITY_HEADERS", "true").lower() == "true"

@dataclass
class Settings:
    """Application settings"""
    # Firebase Configuration
    firebase_project_id: str = "bamboo-reason-483913-i4"
    firebase_api_key: Optional[str] = None
    firebase_credentials_path: Optional[str] = None
    
    # JWT Configuration
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 30
    
    # Security Configuration
    password_min_length: int = 8
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    # Email Configuration
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    from_email: Optional[str] = None
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    
    # Development Configuration
    debug: bool = False
    log_level: str = "INFO"
    
    # TLS Configuration
    tls: TLSConfig = None
    
    # Encryption Configuration
    encryption: EncryptionSettings = None
    
    # Security Configuration
    security: SecuritySettings = None
    
    def __post_init__(self):
        """Initialize settings from environment variables"""
        # Initialize sub-configurations
        self.tls = TLSConfig()
        self.encryption = EncryptionSettings()
        self.security = SecuritySettings()
        
        # Firebase settings
        self.firebase_api_key = os.getenv("FIREBASE_API_KEY")
        self.firebase_credentials_path = os.getenv("FIREBASE_CREDENTIALS_PATH")
        
        # JWT settings
        jwt_secret = os.getenv("JWT_SECRET_KEY")
        if not jwt_secret:
            # Generate a random secret for development
            jwt_secret = secrets.token_urlsafe(32)
            if self.debug:
                print(f"Generated JWT secret: {jwt_secret}")
        self.jwt_secret_key = jwt_secret
        
        # Development settings
        self.debug = os.getenv("DEBUG", "False").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        
        # Email settings
        self.smtp_server = os.getenv("SMTP_SERVER")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_email = os.getenv("FROM_EMAIL")
        self.smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
        self.smtp_use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        if not self.security.security_headers:
            return {}
        
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        return headers
    
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return not self.debug and os.getenv("ENVIRONMENT", "development").lower() == "production"

# Global settings instance
_settings: Optional[Settings] = None

def get_settings() -> Settings:
    """Get global settings instance"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings

# Platform Configuration
PLATFORM_CONFIG = {
    "name": "iGSIM AI Agent powered by eSIM Myanmar",
    "version": "1.0.0",
    "description": "Comprehensive AI Agent platform with eSIM AI Agent M2M and Smart Website services",
    "brand": "iGSIM AI Agent powered by eSIM Myanmar"
}

# Google Cloud Configuration
GOOGLE_CLOUD_CONFIG = {
    "project_id": "bamboo-reason-483913-i4",
    "region": "us-central1",
    "firebase_project": "bamboo-reason-483913-i4"
}

# Firebase Configuration
FIREBASE_CONFIG = {
    "project_id": "bamboo-reason-483913-i4",
    "hosting_url": "bamboo-reason-483913-i4.web.app",
    "database_url": f"https://bamboo-reason-483913-i4-default-rtdb.firebaseio.com/"
}

# AI Services Configuration with secure storage
AI_CONFIG = {
    "gemini_api_key": os.getenv("GEMINI_API_KEY"),
    "xai_api_key": os.getenv("XAI_API_KEY"),
    "groq_api_key": os.getenv("GROQ_API_KEY"),
    "model_name": "gemini-pro",
    "encrypt_api_keys": True,
    "api_key_rotation_enabled": True
}

# UI/UX Configuration
UI_CONFIG = {
    "theme": "modern",
    "design_inspiration": "accio.com",
    "layout": "simple",
    "responsive": True,
    "accessibility": True
}

# Development Configuration
DEV_CONFIG = {
    "debug": os.getenv("DEBUG", "False").lower() == "true",
    "log_level": os.getenv("LOG_LEVEL", "INFO"),
    "auto_reload": True
}

# Repository Configuration
REPO_CONFIG = {
    "github_url": "github.com/nexorasim/igsims",
    "branch": "main",
    "auto_deploy": True
}

# Authentication Configuration
AUTH_CONFIG = {
    "providers": ["email_password", "google.com", "github.com"],
    "require_email_verification": True,
    "password_reset_enabled": True,
    "session_timeout_minutes": 30,
    "max_sessions_per_user": 5,
    "enforce_2fa": False,
    "password_complexity": True
}

# API Security Configuration
API_SECURITY_CONFIG = {
    "rate_limit_per_minute": 100,
    "rate_limit_per_hour": 1000,
    "require_api_key": True,
    "api_key_header": "X-API-Key",
    "cors_origins": ["https://bamboo-reason-483913-i4.web.app"],
    "max_request_size": "10MB",
    "timeout_seconds": 30
}
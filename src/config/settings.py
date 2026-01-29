"""
Configuration settings for iGSIM AI Agent Platform
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
import secrets

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
    
    # Development Configuration
    debug: bool = False
    log_level: str = "INFO"
    
    def __post_init__(self):
        """Initialize settings from environment variables"""
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

# AI Services Configuration
AI_CONFIG = {
    "gemini_api_key": os.getenv("GEMINI_API_KEY"),
    "xai_api_key": os.getenv("XAI_API_KEY"),
    "groq_api_key": os.getenv("GROQ_API_KEY"),
    "model_name": "gemini-pro"
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
    "max_sessions_per_user": 5
}
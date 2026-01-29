"""
Secure API Key Manager for iGSIM AI Agent Platform
Handles secure storage, retrieval, and rotation of API keys and secrets
"""

import os
import sys
import json
import logging
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from contextlib import contextmanager

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from encryption import SecureStorage, DataEncryption
from config.settings import get_settings

logger = logging.getLogger(__name__)

@dataclass
class APIKeyMetadata:
    """Metadata for API keys"""
    service_name: str
    created_at: datetime
    last_rotated: datetime
    expires_at: Optional[datetime] = None
    rotation_interval_days: int = 90
    is_encrypted: bool = True
    key_version: int = 1
    
    def is_expired(self) -> bool:
        """Check if API key is expired"""
        if self.expires_at:
            return datetime.now() > self.expires_at
        return False
    
    def needs_rotation(self) -> bool:
        """Check if API key needs rotation"""
        rotation_due = self.last_rotated + timedelta(days=self.rotation_interval_days)
        return datetime.now() > rotation_due
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'APIKeyMetadata':
        """Create from dictionary"""
        # Convert ISO strings back to datetime objects
        for key in ['created_at', 'last_rotated', 'expires_at']:
            if key in data and data[key]:
                data[key] = datetime.fromisoformat(data[key])
        return cls(**data)

class SecureAPIKeyManager:
    """Secure manager for API keys and secrets"""
    
    def __init__(self, storage_path: str = ".secure_keys", encryption: Optional[DataEncryption] = None):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True, mode=0o700)  # Restrictive permissions
        
        self.secure_storage = SecureStorage(encryption)
        self.metadata_file = self.storage_path / "metadata.json"
        self.keys_file = self.storage_path / "keys.enc"
        
        self._metadata: Dict[str, APIKeyMetadata] = {}
        self._keys: Dict[str, str] = {}
        
        self._load_data()
    
    def _load_data(self):
        """Load metadata and encrypted keys from storage"""
        try:
            # Load metadata
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    metadata_data = json.load(f)
                    self._metadata = {
                        name: APIKeyMetadata.from_dict(data)
                        for name, data in metadata_data.items()
                    }
            
            # Load encrypted keys
            if self.keys_file.exists():
                with open(self.keys_file, 'r') as f:
                    encrypted_data = json.load(f)
                    self._keys = self.secure_storage.retrieve_sensitive_data(encrypted_data)
                    
        except Exception as e:
            logger.error(f"Failed to load secure data: {e}")
            self._metadata = {}
            self._keys = {}
    
    def _save_data(self):
        """Save metadata and encrypted keys to storage"""
        try:
            # Save metadata
            metadata_data = {
                name: metadata.to_dict()
                for name, metadata in self._metadata.items()
            }
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata_data, f, indent=2)
            os.chmod(self.metadata_file, 0o600)
            
            # Save encrypted keys
            encrypted_data = self.secure_storage.store_sensitive_data(self._keys)
            with open(self.keys_file, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
            os.chmod(self.keys_file, 0o600)
            
        except Exception as e:
            logger.error(f"Failed to save secure data: {e}")
            raise
    
    def store_api_key(self, service_name: str, api_key: str, 
                     expires_at: Optional[datetime] = None,
                     rotation_interval_days: int = 90) -> bool:
        """Store API key securely"""
        try:
            now = datetime.now()
            
            # Create metadata
            metadata = APIKeyMetadata(
                service_name=service_name,
                created_at=now,
                last_rotated=now,
                expires_at=expires_at,
                rotation_interval_days=rotation_interval_days,
                is_encrypted=True,
                key_version=1
            )
            
            # Update existing key version if it exists
            if service_name in self._metadata:
                metadata.key_version = self._metadata[service_name].key_version + 1
            
            # Store key and metadata
            self._keys[service_name] = api_key
            self._metadata[service_name] = metadata
            
            self._save_data()
            logger.info(f"Stored API key for service: {service_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store API key for {service_name}: {e}")
            return False
    
    def retrieve_api_key(self, service_name: str) -> Optional[str]:
        """Retrieve API key securely"""
        try:
            if service_name not in self._keys:
                logger.warning(f"API key not found for service: {service_name}")
                return None
            
            metadata = self._metadata.get(service_name)
            if metadata and metadata.is_expired():
                logger.warning(f"API key expired for service: {service_name}")
                return None
            
            return self._keys[service_name]
            
        except Exception as e:
            logger.error(f"Failed to retrieve API key for {service_name}: {e}")
            return None
    
    def rotate_api_key(self, service_name: str, new_api_key: str) -> bool:
        """Rotate API key"""
        try:
            if service_name not in self._metadata:
                logger.error(f"Cannot rotate non-existent key for service: {service_name}")
                return False
            
            metadata = self._metadata[service_name]
            metadata.last_rotated = datetime.now()
            metadata.key_version += 1
            
            self._keys[service_name] = new_api_key
            
            self._save_data()
            logger.info(f"Rotated API key for service: {service_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate API key for {service_name}: {e}")
            return False
    
    def delete_api_key(self, service_name: str) -> bool:
        """Delete API key securely"""
        try:
            if service_name in self._keys:
                del self._keys[service_name]
            if service_name in self._metadata:
                del self._metadata[service_name]
            
            self._save_data()
            logger.info(f"Deleted API key for service: {service_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete API key for {service_name}: {e}")
            return False
    
    def list_services(self) -> Dict[str, APIKeyMetadata]:
        """List all stored services and their metadata"""
        return self._metadata.copy()
    
    def get_keys_needing_rotation(self) -> Dict[str, APIKeyMetadata]:
        """Get services with keys that need rotation"""
        return {
            name: metadata
            for name, metadata in self._metadata.items()
            if metadata.needs_rotation()
        }
    
    def get_expired_keys(self) -> Dict[str, APIKeyMetadata]:
        """Get services with expired keys"""
        return {
            name: metadata
            for name, metadata in self._metadata.items()
            if metadata.is_expired()
        }
    
    @contextmanager
    def secure_context(self, service_name: str):
        """Context manager for secure API key usage"""
        api_key = self.retrieve_api_key(service_name)
        if not api_key:
            raise ValueError(f"API key not available for service: {service_name}")
        
        try:
            yield api_key
        finally:
            # Clear the key from memory
            api_key = None

class EnvironmentSecretManager:
    """Manager for environment-based secrets with fallback to secure storage"""
    
    def __init__(self, api_manager: Optional[SecureAPIKeyManager] = None):
        self.api_manager = api_manager or SecureAPIKeyManager()
        self.settings = get_settings()
    
    def get_secret(self, key: str, service_name: Optional[str] = None) -> Optional[str]:
        """Get secret from environment or secure storage"""
        # First try environment variable
        env_value = os.getenv(key)
        if env_value:
            return env_value
        
        # Fallback to secure storage
        if service_name:
            return self.api_manager.retrieve_api_key(service_name)
        
        # Try using the key as service name
        return self.api_manager.retrieve_api_key(key.lower())
    
    def store_secret(self, key: str, value: str, service_name: Optional[str] = None) -> bool:
        """Store secret in secure storage"""
        service = service_name or key.lower()
        return self.api_manager.store_api_key(service, value)
    
    def get_ai_service_keys(self) -> Dict[str, Optional[str]]:
        """Get all AI service API keys"""
        return {
            'gemini': self.get_secret('GEMINI_API_KEY', 'gemini'),
            'xai': self.get_secret('XAI_API_KEY', 'xai'),
            'groq': self.get_secret('GROQ_API_KEY', 'groq'),
            'openai': self.get_secret('OPENAI_API_KEY', 'openai'),
            'anthropic': self.get_secret('ANTHROPIC_API_KEY', 'anthropic')
        }
    
    def get_firebase_credentials(self) -> Dict[str, Optional[str]]:
        """Get Firebase credentials"""
        return {
            'api_key': self.get_secret('FIREBASE_API_KEY', 'firebase'),
            'credentials_path': self.get_secret('FIREBASE_CREDENTIALS_PATH'),
            'project_id': self.get_secret('FIREBASE_PROJECT_ID') or self.settings.firebase_project_id
        }

# Global instances
_api_key_manager: Optional[SecureAPIKeyManager] = None
_secret_manager: Optional[EnvironmentSecretManager] = None

def get_api_key_manager() -> SecureAPIKeyManager:
    """Get global API key manager instance"""
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = SecureAPIKeyManager()
    return _api_key_manager

def get_secret_manager() -> EnvironmentSecretManager:
    """Get global secret manager instance"""
    global _secret_manager
    if _secret_manager is None:
        _secret_manager = EnvironmentSecretManager()
    return _secret_manager
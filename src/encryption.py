"""
Data encryption utilities for iGSIM AI Agent Platform
Provides comprehensive encryption for sensitive information including API keys, secrets, and user data
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import secrets
import logging
import json
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class EncryptionConfig:
    """Configuration for encryption settings"""
    key_derivation_iterations: int = 100000
    salt_length: int = 32
    key_length: int = 32
    rsa_key_size: int = 2048
    encryption_key_file: str = '.encryption_key'
    private_key_file: str = '.private_key.pem'
    public_key_file: str = '.public_key.pem'

class DataEncryption:
    """Enhanced data encryption class with multiple encryption methods"""
    
    def __init__(self, password: Optional[str] = None, config: Optional[EncryptionConfig] = None):
        self.config = config or EncryptionConfig()
        
        if password:
            self.key = self._derive_key(password)
        else:
            self.key = self._load_or_generate_key()
        
        self.cipher = Fernet(self.key)
        self._ensure_rsa_keys()
    
    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = b'igsim_salt_2024_secure'  # Fixed salt for consistency
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.key_length,
            salt=salt,
            iterations=self.config.key_derivation_iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _load_or_generate_key(self) -> bytes:
        """Load existing encryption key or generate new one"""
        key_file = Path(self.config.encryption_key_file)
        
        if key_file.exists():
            try:
                with open(key_file, 'rb') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to load encryption key: {e}")
        
        # Generate new key
        key = Fernet.generate_key()
        try:
            # Ensure directory exists
            key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
            logger.info("Generated new encryption key")
        except Exception as e:
            logger.error(f"Failed to save encryption key: {e}")
        
        return key
    
    def _ensure_rsa_keys(self):
        """Ensure RSA key pair exists for asymmetric encryption"""
        private_key_path = Path(self.config.private_key_file)
        public_key_path = Path(self.config.public_key_file)
        
        if not private_key_path.exists() or not public_key_path.exists():
            self._generate_rsa_keys()
        
        try:
            self._load_rsa_keys()
        except Exception as e:
            logger.warning(f"Failed to load RSA keys, regenerating: {e}")
            self._generate_rsa_keys()
            self._load_rsa_keys()
    
    def _generate_rsa_keys(self):
        """Generate RSA key pair for asymmetric encryption"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.config.rsa_key_size,
            )
            
            # Save private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            private_key_path = Path(self.config.private_key_file)
            private_key_path.parent.mkdir(parents=True, exist_ok=True)
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_key_path, 0o600)
            
            # Save public key
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            public_key_path = Path(self.config.public_key_file)
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            os.chmod(public_key_path, 0o644)
            
            logger.info("Generated new RSA key pair")
            
        except Exception as e:
            logger.error(f"Failed to generate RSA keys: {e}")
            raise
    
    def _load_rsa_keys(self):
        """Load RSA key pair"""
        try:
            # Load private key
            with open(self.config.private_key_file, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )
            
            # Load public key
            with open(self.config.public_key_file, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(f.read())
                
        except Exception as e:
            logger.error(f"Failed to load RSA keys: {e}")
            raise
    
    def encrypt(self, data: str) -> str:
        """Encrypt data using Fernet symmetric encryption"""
        try:
            if not isinstance(data, str):
                data = str(data)
            encrypted = self.cipher.encrypt(data.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using Fernet symmetric encryption"""
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise
    
    def encrypt_asymmetric(self, data: str) -> str:
        """Encrypt data using RSA public key"""
        try:
            if not hasattr(self, 'public_key'):
                raise ValueError("RSA keys not available")
            
            data_bytes = data.encode('utf-8')
            encrypted = self.public_key.encrypt(
                data_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Asymmetric encryption error: {e}")
            raise
    
    def decrypt_asymmetric(self, encrypted_data: str) -> str:
        """Decrypt data using RSA private key"""
        try:
            if not hasattr(self, 'private_key'):
                raise ValueError("RSA keys not available")
            
            decoded = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.private_key.decrypt(
                decoded,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Asymmetric decryption error: {e}")
            raise
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    def hash_data(self, data: str, salt: Optional[str] = None) -> tuple[str, str]:
        """Hash data with salt, returns (hash, salt)"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        combined = f"{data}{salt}".encode('utf-8')
        digest = hashes.Hash(hashes.SHA256())
        digest.update(combined)
        hash_value = digest.finalize()
        
        return base64.urlsafe_b64encode(hash_value).decode('utf-8'), salt

class SecureStorage:
    """Enhanced secure storage for API keys and sensitive data"""
    
    def __init__(self, encryption: Optional[DataEncryption] = None):
        self.encryption = encryption or DataEncryption()
        self.sensitive_fields = {
            'api_key', 'secret', 'password', 'token', 'private_key',
            'access_token', 'refresh_token', 'client_secret', 'webhook_secret'
        }
    
    def is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field contains sensitive data"""
        field_lower = field_name.lower()
        return any(sensitive in field_lower for sensitive in self.sensitive_fields)
    
    def store_api_key(self, service: str, api_key: str, use_asymmetric: bool = False) -> str:
        """Store API key with encryption"""
        try:
            if use_asymmetric:
                encrypted_key = self.encryption.encrypt_asymmetric(api_key)
            else:
                encrypted_key = self.encryption.encrypt(api_key)
            
            logger.info(f"Stored API key for service: {service}")
            return encrypted_key
        except Exception as e:
            logger.error(f"Failed to store API key for {service}: {e}")
            raise
    
    def retrieve_api_key(self, encrypted_key: str, use_asymmetric: bool = False) -> str:
        """Retrieve and decrypt API key"""
        try:
            if use_asymmetric:
                return self.encryption.decrypt_asymmetric(encrypted_key)
            else:
                return self.encryption.decrypt(encrypted_key)
        except Exception as e:
            logger.error(f"Failed to retrieve API key: {e}")
            raise
    
    def store_sensitive_data(self, data: Dict[str, Any], use_asymmetric: bool = False) -> Dict[str, Any]:
        """Store dictionary with automatic encryption of sensitive fields"""
        encrypted_data = {}
        
        for key, value in data.items():
            if isinstance(value, str) and self.is_sensitive_field(key):
                try:
                    if use_asymmetric:
                        encrypted_data[key] = self.encryption.encrypt_asymmetric(value)
                    else:
                        encrypted_data[key] = self.encryption.encrypt(value)
                    encrypted_data[f"{key}_encrypted"] = True
                except Exception as e:
                    logger.error(f"Failed to encrypt field {key}: {e}")
                    encrypted_data[key] = value
            elif isinstance(value, dict):
                # Recursively handle nested dictionaries
                encrypted_data[key] = self.store_sensitive_data(value, use_asymmetric)
            else:
                encrypted_data[key] = value
        
        return encrypted_data
    
    def retrieve_sensitive_data(self, encrypted_data: Dict[str, Any], use_asymmetric: bool = False) -> Dict[str, Any]:
        """Retrieve dictionary with automatic decryption of sensitive fields"""
        decrypted_data = {}
        
        for key, value in encrypted_data.items():
            if key.endswith('_encrypted'):
                continue  # Skip encryption flags
            
            if isinstance(value, str) and encrypted_data.get(f"{key}_encrypted", False):
                try:
                    if use_asymmetric:
                        decrypted_data[key] = self.encryption.decrypt_asymmetric(value)
                    else:
                        decrypted_data[key] = self.encryption.decrypt(value)
                except Exception as e:
                    logger.error(f"Failed to decrypt field {key}: {e}")
                    decrypted_data[key] = value
            elif isinstance(value, dict):
                # Recursively handle nested dictionaries
                decrypted_data[key] = self.retrieve_sensitive_data(value, use_asymmetric)
            else:
                decrypted_data[key] = value
        
        return decrypted_data
    
    def store_credentials(self, credentials: Dict[str, str]) -> Dict[str, str]:
        """Store user credentials with encryption"""
        return self.store_sensitive_data(credentials)
    
    def retrieve_credentials(self, encrypted_credentials: Dict[str, str]) -> Dict[str, str]:
        """Retrieve and decrypt user credentials"""
        return self.retrieve_sensitive_data(encrypted_credentials)

class FieldLevelEncryption:
    """Field-level encryption for database records"""
    
    def __init__(self, encryption: Optional[DataEncryption] = None):
        self.encryption = encryption or DataEncryption()
        self.secure_storage = SecureStorage(self.encryption)
    
    def encrypt_record(self, record: Dict[str, Any], encrypted_fields: Optional[list] = None) -> Dict[str, Any]:
        """Encrypt specific fields in a database record"""
        if encrypted_fields is None:
            # Auto-detect sensitive fields
            return self.secure_storage.store_sensitive_data(record)
        
        encrypted_record = record.copy()
        for field in encrypted_fields:
            if field in encrypted_record and isinstance(encrypted_record[field], str):
                encrypted_record[field] = self.encryption.encrypt(encrypted_record[field])
                encrypted_record[f"{field}_encrypted"] = True
        
        return encrypted_record
    
    def decrypt_record(self, encrypted_record: Dict[str, Any], encrypted_fields: Optional[list] = None) -> Dict[str, Any]:
        """Decrypt specific fields in a database record"""
        if encrypted_fields is None:
            # Auto-detect encrypted fields
            return self.secure_storage.retrieve_sensitive_data(encrypted_record)
        
        decrypted_record = encrypted_record.copy()
        for field in encrypted_fields:
            if f"{field}_encrypted" in decrypted_record and decrypted_record[f"{field}_encrypted"]:
                try:
                    decrypted_record[field] = self.encryption.decrypt(decrypted_record[field])
                    del decrypted_record[f"{field}_encrypted"]
                except Exception as e:
                    logger.error(f"Failed to decrypt field {field}: {e}")
        
        return decrypted_record

# Global instances for easy access
_default_encryption = None
_default_secure_storage = None

def get_encryption() -> DataEncryption:
    """Get default encryption instance"""
    global _default_encryption
    if _default_encryption is None:
        _default_encryption = DataEncryption()
    return _default_encryption

def get_secure_storage() -> SecureStorage:
    """Get default secure storage instance"""
    global _default_secure_storage
    if _default_secure_storage is None:
        _default_secure_storage = SecureStorage()
    return _default_secure_storage
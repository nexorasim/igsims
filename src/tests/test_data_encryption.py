"""
Unit tests for data encryption functionality
Tests the DataEncryption, SecureStorage, and SecureAPIKeyManager classes
"""

import pytest
import os
import sys
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from encryption import (
    DataEncryption, SecureStorage, FieldLevelEncryption,
    EncryptionConfig, get_encryption, get_secure_storage
)
from utils.secure_api_manager import (
    SecureAPIKeyManager, EnvironmentSecretManager, APIKeyMetadata
)

class TestDataEncryption:
    """Test cases for DataEncryption class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = EncryptionConfig(
            encryption_key_file=os.path.join(self.temp_dir, 'test_key'),
            private_key_file=os.path.join(self.temp_dir, 'test_private.pem'),
            public_key_file=os.path.join(self.temp_dir, 'test_public.pem')
        )
        self.encryption = DataEncryption(config=self.config)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_symmetric_encryption_decryption(self):
        """Test basic symmetric encryption and decryption"""
        test_data = "This is sensitive test data"
        
        # Encrypt data
        encrypted = self.encryption.encrypt(test_data)
        assert encrypted != test_data
        assert isinstance(encrypted, str)
        
        # Decrypt data
        decrypted = self.encryption.decrypt(encrypted)
        assert decrypted == test_data
    
    def test_password_based_encryption(self):
        """Test password-based key derivation"""
        password = "test_password_123"
        encryption_with_password = DataEncryption(password=password, config=self.config)
        
        test_data = "Password protected data"
        encrypted = encryption_with_password.encrypt(test_data)
        decrypted = encryption_with_password.decrypt(encrypted)
        
        assert decrypted == test_data
    
    def test_asymmetric_encryption_decryption(self):
        """Test RSA asymmetric encryption and decryption"""
        test_data = "Asymmetric encryption test"
        
        # Encrypt with public key
        encrypted = self.encryption.encrypt_asymmetric(test_data)
        assert encrypted != test_data
        assert isinstance(encrypted, str)
        
        # Decrypt with private key
        decrypted = self.encryption.decrypt_asymmetric(encrypted)
        assert decrypted == test_data
    
    def test_secure_token_generation(self):
        """Test secure token generation"""
        token1 = self.encryption.generate_secure_token()
        token2 = self.encryption.generate_secure_token()
        
        assert len(token1) > 0
        assert len(token2) > 0
        assert token1 != token2
        
        # Test custom length
        long_token = self.encryption.generate_secure_token(64)
        assert len(long_token) > len(token1)
    
    def test_data_hashing(self):
        """Test data hashing with salt"""
        test_data = "data to hash"
        
        hash1, salt1 = self.encryption.hash_data(test_data)
        hash2, salt2 = self.encryption.hash_data(test_data)
        
        # Different salts should produce different hashes
        assert hash1 != hash2
        assert salt1 != salt2
        
        # Same salt should produce same hash
        hash3, _ = self.encryption.hash_data(test_data, salt1)
        assert hash1 == hash3
    
    def test_encryption_error_handling(self):
        """Test error handling in encryption operations"""
        with pytest.raises(Exception):
            self.encryption.decrypt("invalid_encrypted_data")
    
    def test_key_persistence(self):
        """Test that encryption keys are persisted correctly"""
        # Create encryption instance
        encryption1 = DataEncryption(config=self.config)
        test_data = "persistence test"
        encrypted = encryption1.encrypt(test_data)
        
        # Create new instance with same config
        encryption2 = DataEncryption(config=self.config)
        decrypted = encryption2.decrypt(encrypted)
        
        assert decrypted == test_data

class TestSecureStorage:
    """Test cases for SecureStorage class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        config = EncryptionConfig(
            encryption_key_file=os.path.join(self.temp_dir, 'test_key'),
            private_key_file=os.path.join(self.temp_dir, 'test_private.pem'),
            public_key_file=os.path.join(self.temp_dir, 'test_public.pem')
        )
        encryption = DataEncryption(config=config)
        self.storage = SecureStorage(encryption)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_api_key_storage_retrieval(self):
        """Test API key storage and retrieval"""
        service = "test_service"
        api_key = "sk-test-api-key-12345"
        
        # Store API key
        encrypted_key = self.storage.store_api_key(service, api_key)
        assert encrypted_key != api_key
        
        # Retrieve API key
        retrieved_key = self.storage.retrieve_api_key(encrypted_key)
        assert retrieved_key == api_key
    
    def test_sensitive_data_detection(self):
        """Test automatic detection of sensitive fields"""
        assert self.storage.is_sensitive_field("api_key")
        assert self.storage.is_sensitive_field("password")
        assert self.storage.is_sensitive_field("secret_token")
        assert self.storage.is_sensitive_field("private_key")
        assert not self.storage.is_sensitive_field("username")
        assert not self.storage.is_sensitive_field("email")
    
    def test_sensitive_data_storage(self):
        """Test automatic encryption of sensitive data"""
        test_data = {
            "username": "testuser",
            "password": "secret123",
            "api_key": "sk-12345",
            "email": "test@example.com",
            "access_token": "token123"
        }
        
        # Store data with automatic encryption
        encrypted_data = self.storage.store_sensitive_data(test_data)
        
        # Check that sensitive fields are encrypted
        assert encrypted_data["username"] == "testuser"  # Not sensitive
        assert encrypted_data["email"] == "test@example.com"  # Not sensitive
        assert encrypted_data["password"] != "secret123"  # Encrypted
        assert encrypted_data["api_key"] != "sk-12345"  # Encrypted
        assert encrypted_data["access_token"] != "token123"  # Encrypted
        
        # Retrieve and verify decryption
        decrypted_data = self.storage.retrieve_sensitive_data(encrypted_data)
        assert decrypted_data == test_data
    
    def test_nested_data_encryption(self):
        """Test encryption of nested dictionary structures"""
        nested_data = {
            "user_info": {
                "username": "testuser",
                "password": "secret123"
            },
            "api_config": {
                "api_key": "sk-12345",
                "endpoint": "https://api.example.com"
            }
        }
        
        encrypted_data = self.storage.store_sensitive_data(nested_data)
        decrypted_data = self.storage.retrieve_sensitive_data(encrypted_data)
        
        assert decrypted_data == nested_data
    
    def test_credentials_storage(self):
        """Test credential storage and retrieval"""
        credentials = {
            "username": "testuser",
            "password": "secret123",
            "api_key": "sk-12345"
        }
        
        encrypted_creds = self.storage.store_credentials(credentials)
        retrieved_creds = self.storage.retrieve_credentials(encrypted_creds)
        
        assert retrieved_creds == credentials

class TestFieldLevelEncryption:
    """Test cases for FieldLevelEncryption class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        config = EncryptionConfig(
            encryption_key_file=os.path.join(self.temp_dir, 'test_key'),
            private_key_file=os.path.join(self.temp_dir, 'test_private.pem'),
            public_key_file=os.path.join(self.temp_dir, 'test_public.pem')
        )
        encryption = DataEncryption(config=config)
        self.field_encryption = FieldLevelEncryption(encryption)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_record_encryption_auto_detect(self):
        """Test automatic field detection in record encryption"""
        record = {
            "id": "user123",
            "name": "John Doe",
            "password": "secret123",
            "api_key": "sk-12345",
            "email": "john@example.com"
        }
        
        encrypted_record = self.field_encryption.encrypt_record(record)
        decrypted_record = self.field_encryption.decrypt_record(encrypted_record)
        
        assert decrypted_record == record
    
    def test_record_encryption_specific_fields(self):
        """Test encryption of specific fields"""
        record = {
            "id": "user123",
            "name": "John Doe",
            "sensitive_data": "secret information",
            "public_data": "public information"
        }
        
        encrypted_fields = ["sensitive_data"]
        encrypted_record = self.field_encryption.encrypt_record(record, encrypted_fields)
        
        # Check that only specified field is encrypted
        assert encrypted_record["id"] == "user123"
        assert encrypted_record["name"] == "John Doe"
        assert encrypted_record["public_data"] == "public information"
        assert encrypted_record["sensitive_data"] != "secret information"
        assert encrypted_record["sensitive_data_encrypted"] is True
        
        # Decrypt and verify
        decrypted_record = self.field_encryption.decrypt_record(encrypted_record, encrypted_fields)
        assert decrypted_record["sensitive_data"] == "secret information"
        assert "sensitive_data_encrypted" not in decrypted_record

class TestSecureAPIKeyManager:
    """Test cases for SecureAPIKeyManager class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = SecureAPIKeyManager(storage_path=os.path.join(self.temp_dir, "keys"))
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_api_key_storage_retrieval(self):
        """Test API key storage and retrieval"""
        service = "test_service"
        api_key = "sk-test-12345"
        
        # Store API key
        success = self.manager.store_api_key(service, api_key)
        assert success
        
        # Retrieve API key
        retrieved_key = self.manager.retrieve_api_key(service)
        assert retrieved_key == api_key
    
    def test_api_key_rotation(self):
        """Test API key rotation"""
        service = "test_service"
        old_key = "sk-old-12345"
        new_key = "sk-new-67890"
        
        # Store initial key
        self.manager.store_api_key(service, old_key)
        
        # Rotate key
        success = self.manager.rotate_api_key(service, new_key)
        assert success
        
        # Verify new key is retrieved
        retrieved_key = self.manager.retrieve_api_key(service)
        assert retrieved_key == new_key
        
        # Check metadata was updated
        metadata = self.manager.list_services()[service]
        assert metadata.key_version == 2
    
    def test_api_key_expiration(self):
        """Test API key expiration handling"""
        service = "test_service"
        api_key = "sk-test-12345"
        expires_at = datetime.now() - timedelta(days=1)  # Expired
        
        # Store expired key
        self.manager.store_api_key(service, api_key, expires_at=expires_at)
        
        # Should return None for expired key
        retrieved_key = self.manager.retrieve_api_key(service)
        assert retrieved_key is None
    
    def test_keys_needing_rotation(self):
        """Test identification of keys needing rotation"""
        service = "test_service"
        api_key = "sk-test-12345"
        
        # Store key with short rotation interval
        self.manager.store_api_key(service, api_key, rotation_interval_days=0)
        
        # Should need rotation immediately
        keys_needing_rotation = self.manager.get_keys_needing_rotation()
        assert service in keys_needing_rotation
    
    def test_secure_context_manager(self):
        """Test secure context manager for API key usage"""
        service = "test_service"
        api_key = "sk-test-12345"
        
        self.manager.store_api_key(service, api_key)
        
        # Use context manager
        with self.manager.secure_context(service) as key:
            assert key == api_key
        
        # Test with non-existent service
        with pytest.raises(ValueError):
            with self.manager.secure_context("non_existent"):
                pass
    
    def test_api_key_deletion(self):
        """Test API key deletion"""
        service = "test_service"
        api_key = "sk-test-12345"
        
        # Store and then delete
        self.manager.store_api_key(service, api_key)
        success = self.manager.delete_api_key(service)
        assert success
        
        # Should return None after deletion
        retrieved_key = self.manager.retrieve_api_key(service)
        assert retrieved_key is None
    
    def test_persistence(self):
        """Test that API keys persist across manager instances"""
        service = "test_service"
        api_key = "sk-test-12345"
        
        # Store key with first manager
        self.manager.store_api_key(service, api_key)
        
        # Create new manager with same storage path
        new_manager = SecureAPIKeyManager(storage_path=os.path.join(self.temp_dir, "keys"))
        
        # Should retrieve the same key
        retrieved_key = new_manager.retrieve_api_key(service)
        assert retrieved_key == api_key

class TestEnvironmentSecretManager:
    """Test cases for EnvironmentSecretManager class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        api_manager = SecureAPIKeyManager(storage_path=os.path.join(self.temp_dir, "keys"))
        self.secret_manager = EnvironmentSecretManager(api_manager)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        # Clean up environment variables
        for key in ["TEST_API_KEY", "GEMINI_API_KEY"]:
            if key in os.environ:
                del os.environ[key]
    
    def test_environment_variable_priority(self):
        """Test that environment variables take priority"""
        key = "TEST_API_KEY"
        env_value = "env-key-12345"
        stored_value = "stored-key-67890"
        
        # Store value in secure storage
        self.secret_manager.store_secret(key, stored_value)
        
        # Set environment variable
        os.environ[key] = env_value
        
        # Should return environment variable value
        retrieved = self.secret_manager.get_secret(key)
        assert retrieved == env_value
    
    def test_fallback_to_secure_storage(self):
        """Test fallback to secure storage when env var not set"""
        key = "TEST_API_KEY"
        stored_value = "stored-key-12345"
        
        # Ensure env var is not set
        if key in os.environ:
            del os.environ[key]
        
        # Store in secure storage
        self.secret_manager.store_secret(key, stored_value)
        
        # Should return stored value
        retrieved = self.secret_manager.get_secret(key)
        assert retrieved == stored_value
    
    def test_ai_service_keys_retrieval(self):
        """Test retrieval of AI service keys"""
        # Set some environment variables
        os.environ["GEMINI_API_KEY"] = "gemini-key-12345"
        
        # Store some in secure storage
        self.secret_manager.store_secret("XAI_API_KEY", "xai-key-67890", "xai")
        
        keys = self.secret_manager.get_ai_service_keys()
        
        assert keys["gemini"] == "gemini-key-12345"
        assert keys["xai"] == "xai-key-67890"
        assert keys["groq"] is None  # Not set
    
    def test_firebase_credentials_retrieval(self):
        """Test Firebase credentials retrieval"""
        os.environ["FIREBASE_API_KEY"] = "firebase-key-12345"
        
        credentials = self.secret_manager.get_firebase_credentials()
        
        assert credentials["api_key"] == "firebase-key-12345"
        assert credentials["project_id"] == "bamboo-reason-483913-i4"  # From settings

class TestGlobalInstances:
    """Test global encryption instances"""
    
    def test_global_encryption_instance(self):
        """Test global encryption instance"""
        encryption1 = get_encryption()
        encryption2 = get_encryption()
        
        # Should return same instance
        assert encryption1 is encryption2
    
    def test_global_secure_storage_instance(self):
        """Test global secure storage instance"""
        storage1 = get_secure_storage()
        storage2 = get_secure_storage()
        
        # Should return same instance
        assert storage1 is storage2
    
    def test_encryption_functionality(self):
        """Test that global instances work correctly"""
        encryption = get_encryption()
        storage = get_secure_storage()
        
        test_data = "global instance test"
        encrypted = encryption.encrypt(test_data)
        decrypted = encryption.decrypt(encrypted)
        
        assert decrypted == test_data
        
        # Test storage
        api_key = storage.store_api_key("test", "sk-12345")
        retrieved = storage.retrieve_api_key(api_key)
        assert retrieved == "sk-12345"

if __name__ == "__main__":
    pytest.main([__file__])
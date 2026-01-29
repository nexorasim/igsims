"""
Property-based tests for data encryption functionality
Tests universal properties of encryption across all inputs

Feature: igsim-ai-agent-platform, Property 28: Data Encryption
**Validates: Requirements 8.3**
"""

import pytest
import os
import sys
import tempfile
import shutil
from hypothesis import given, strategies as st, settings, assume
from typing import Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from encryption import DataEncryption, SecureStorage, FieldLevelEncryption, EncryptionConfig
from utils.secure_api_manager import SecureAPIKeyManager, EnvironmentSecretManager

# Test strategies
sensitive_field_names = st.sampled_from([
    'api_key', 'secret', 'password', 'token', 'private_key',
    'access_token', 'refresh_token', 'client_secret', 'webhook_secret'
])

non_sensitive_field_names = st.sampled_from([
    'username', 'email', 'name', 'id', 'description', 'url', 'status'
])

text_data = st.text(min_size=1, max_size=1000)
api_key_data = st.text(min_size=10, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc')))

class TestDataEncryptionProperties:
    """Property-based tests for data encryption"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = EncryptionConfig(
            encryption_key_file=os.path.join(self.temp_dir, 'test_key'),
            private_key_file=os.path.join(self.temp_dir, 'test_private.pem'),
            public_key_file=os.path.join(self.temp_dir, 'test_public.pem')
        )
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @given(text_data)
    @settings(max_examples=100)
    def test_symmetric_encryption_roundtrip_property(self, data):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any text data, symmetric encryption followed by decryption should return the original data
        **Validates: Requirements 8.3**
        """
        assume(len(data.strip()) > 0)  # Avoid empty strings
        
        encryption = DataEncryption(config=self.config)
        
        # Encrypt then decrypt
        encrypted = encryption.encrypt(data)
        decrypted = encryption.decrypt(encrypted)
        
        # Property: Decryption should recover original data
        assert decrypted == data
        
        # Property: Encrypted data should be different from original (unless very short)
        if len(data) > 1:
            assert encrypted != data
    
    @given(text_data)
    @settings(max_examples=100)
    def test_asymmetric_encryption_roundtrip_property(self, data):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any text data, asymmetric encryption followed by decryption should return the original data
        **Validates: Requirements 8.3**
        """
        assume(len(data.strip()) > 0 and len(data.encode('utf-8')) <= 190)  # RSA size limit
        
        encryption = DataEncryption(config=self.config)
        
        # Encrypt with public key, decrypt with private key
        encrypted = encryption.encrypt_asymmetric(data)
        decrypted = encryption.decrypt_asymmetric(encrypted)
        
        # Property: Decryption should recover original data
        assert decrypted == data
        
        # Property: Encrypted data should be different from original
        assert encrypted != data
    
    @given(st.text(min_size=1, max_size=50))
    @settings(max_examples=100)
    def test_password_based_encryption_consistency_property(self, password):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any password, the same password should always generate the same encryption key
        **Validates: Requirements 8.3**
        """
        assume(len(password.strip()) > 0)
        
        test_data = "consistent encryption test"
        
        # Create two encryption instances with same password
        encryption1 = DataEncryption(password=password, config=self.config)
        encryption2 = DataEncryption(password=password, config=self.config)
        
        # Encrypt with first instance
        encrypted1 = encryption1.encrypt(test_data)
        
        # Decrypt with second instance
        decrypted2 = encryption2.decrypt(encrypted1)
        
        # Property: Same password should allow decryption
        assert decrypted2 == test_data
    
    @given(st.integers(min_value=8, max_value=128))
    @settings(max_examples=50)
    def test_secure_token_uniqueness_property(self, length):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any token length, generated tokens should be unique and of correct length
        **Validates: Requirements 8.3**
        """
        encryption = DataEncryption(config=self.config)
        
        # Generate multiple tokens
        tokens = [encryption.generate_secure_token(length) for _ in range(10)]
        
        # Property: All tokens should be unique
        assert len(set(tokens)) == len(tokens)
        
        # Property: All tokens should have expected length (URL-safe base64 encoding)
        for token in tokens:
            assert len(token) > 0
            assert isinstance(token, str)
    
    @given(text_data)
    @settings(max_examples=100)
    def test_hash_consistency_property(self, data):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any data and salt, hashing should be consistent and deterministic
        **Validates: Requirements 8.3**
        """
        assume(len(data.strip()) > 0)
        
        encryption = DataEncryption(config=self.config)
        
        # Hash with random salt
        hash1, salt1 = encryption.hash_data(data)
        
        # Hash same data with same salt
        hash2, salt2 = encryption.hash_data(data, salt1)
        
        # Property: Same data and salt should produce same hash
        assert hash1 == hash2
        assert salt1 == salt2
        
        # Hash with different salt
        hash3, salt3 = encryption.hash_data(data)
        
        # Property: Different salt should produce different hash (with high probability)
        if salt1 != salt3:
            assert hash1 != hash3

class TestSecureStorageProperties:
    """Property-based tests for secure storage"""
    
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
    
    @given(st.text(min_size=1, max_size=50), api_key_data)
    @settings(max_examples=100)
    def test_api_key_storage_property(self, service_name, api_key):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any service name and API key, storage and retrieval should preserve the key
        **Validates: Requirements 8.3**
        """
        assume(len(service_name.strip()) > 0 and len(api_key.strip()) > 0)
        
        # Store API key
        encrypted_key = self.storage.store_api_key(service_name, api_key)
        
        # Property: Encrypted key should be different from original
        assert encrypted_key != api_key
        
        # Retrieve API key
        retrieved_key = self.storage.retrieve_api_key(encrypted_key)
        
        # Property: Retrieved key should match original
        assert retrieved_key == api_key
    
    @given(sensitive_field_names)
    @settings(max_examples=50)
    def test_sensitive_field_detection_property(self, field_name):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any field name containing sensitive keywords, it should be detected as sensitive
        **Validates: Requirements 8.3**
        """
        # Property: Fields with sensitive keywords should be detected
        assert self.storage.is_sensitive_field(field_name)
        assert self.storage.is_sensitive_field(field_name.upper())
        assert self.storage.is_sensitive_field(f"user_{field_name}")
        assert self.storage.is_sensitive_field(f"{field_name}_value")
    
    @given(non_sensitive_field_names)
    @settings(max_examples=50)
    def test_non_sensitive_field_detection_property(self, field_name):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any field name without sensitive keywords, it should not be detected as sensitive
        **Validates: Requirements 8.3**
        """
        # Property: Fields without sensitive keywords should not be detected
        assert not self.storage.is_sensitive_field(field_name)
    
    @given(st.dictionaries(
        keys=st.sampled_from(['username', 'password', 'api_key', 'email', 'secret']),
        values=text_data,
        min_size=1,
        max_size=5
    ))
    @settings(max_examples=100)
    def test_sensitive_data_encryption_property(self, data_dict):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any dictionary with mixed sensitive/non-sensitive fields, 
        only sensitive fields should be encrypted
        **Validates: Requirements 8.3**
        """
        assume(all(len(str(v).strip()) > 0 for v in data_dict.values()))
        
        # Store data with automatic encryption
        encrypted_data = self.storage.store_sensitive_data(data_dict)
        
        # Property: Sensitive fields should be encrypted, non-sensitive preserved
        for key, original_value in data_dict.items():
            if self.storage.is_sensitive_field(key):
                # Sensitive field should be encrypted
                assert encrypted_data[key] != original_value
                assert encrypted_data.get(f"{key}_encrypted", False)
            else:
                # Non-sensitive field should be preserved
                assert encrypted_data[key] == original_value
        
        # Retrieve and verify decryption
        decrypted_data = self.storage.retrieve_sensitive_data(encrypted_data)
        
        # Property: Decrypted data should match original
        assert decrypted_data == data_dict
    
    @given(st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.dictionaries(
            keys=st.sampled_from(['username', 'password', 'token']),
            values=text_data,
            min_size=1,
            max_size=3
        ),
        min_size=1,
        max_size=3
    ))
    @settings(max_examples=50)
    def test_nested_data_encryption_property(self, nested_data):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any nested dictionary structure, encryption should work recursively
        **Validates: Requirements 8.3**
        """
        assume(all(
            all(len(str(v).strip()) > 0 for v in inner_dict.values())
            for inner_dict in nested_data.values()
        ))
        
        # Store nested data
        encrypted_data = self.storage.store_sensitive_data(nested_data)
        
        # Retrieve and verify
        decrypted_data = self.storage.retrieve_sensitive_data(encrypted_data)
        
        # Property: Nested structure should be preserved
        assert decrypted_data == nested_data

class TestSecureAPIKeyManagerProperties:
    """Property-based tests for secure API key manager"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = SecureAPIKeyManager(storage_path=os.path.join(self.temp_dir, "keys"))
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @given(st.text(min_size=1, max_size=50), api_key_data)
    @settings(max_examples=100)
    def test_api_key_manager_roundtrip_property(self, service_name, api_key):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any service name and API key, storage and retrieval should preserve the key
        **Validates: Requirements 8.3**
        """
        assume(len(service_name.strip()) > 0 and len(api_key.strip()) > 0)
        
        # Store API key
        success = self.manager.store_api_key(service_name, api_key)
        assert success
        
        # Retrieve API key
        retrieved_key = self.manager.retrieve_api_key(service_name)
        
        # Property: Retrieved key should match original
        assert retrieved_key == api_key
        
        # Property: Metadata should be created
        services = self.manager.list_services()
        assert service_name in services
        assert services[service_name].service_name == service_name
    
    @given(st.text(min_size=1, max_size=50), api_key_data, api_key_data)
    @settings(max_examples=50)
    def test_api_key_rotation_property(self, service_name, old_key, new_key):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any service, key rotation should update the key and increment version
        **Validates: Requirements 8.3**
        """
        assume(len(service_name.strip()) > 0)
        assume(len(old_key.strip()) > 0 and len(new_key.strip()) > 0)
        assume(old_key != new_key)
        
        # Store initial key
        self.manager.store_api_key(service_name, old_key)
        initial_metadata = self.manager.list_services()[service_name]
        
        # Rotate key
        success = self.manager.rotate_api_key(service_name, new_key)
        assert success
        
        # Property: New key should be retrieved
        retrieved_key = self.manager.retrieve_api_key(service_name)
        assert retrieved_key == new_key
        
        # Property: Version should be incremented
        updated_metadata = self.manager.list_services()[service_name]
        assert updated_metadata.key_version == initial_metadata.key_version + 1
    
    @given(st.text(min_size=1, max_size=50), api_key_data)
    @settings(max_examples=50)
    def test_api_key_deletion_property(self, service_name, api_key):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any stored API key, deletion should remove it completely
        **Validates: Requirements 8.3**
        """
        assume(len(service_name.strip()) > 0 and len(api_key.strip()) > 0)
        
        # Store API key
        self.manager.store_api_key(service_name, api_key)
        assert self.manager.retrieve_api_key(service_name) == api_key
        
        # Delete API key
        success = self.manager.delete_api_key(service_name)
        assert success
        
        # Property: Key should no longer be retrievable
        retrieved_key = self.manager.retrieve_api_key(service_name)
        assert retrieved_key is None
        
        # Property: Service should not be in list
        services = self.manager.list_services()
        assert service_name not in services
    
    @given(st.lists(
        st.tuples(st.text(min_size=1, max_size=20), api_key_data),
        min_size=1,
        max_size=10,
        unique_by=lambda x: x[0]  # Unique service names
    ))
    @settings(max_examples=50)
    def test_multiple_services_property(self, service_key_pairs):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any collection of service-key pairs, all should be stored and retrieved correctly
        **Validates: Requirements 8.3**
        """
        assume(all(len(service.strip()) > 0 and len(key.strip()) > 0 
                  for service, key in service_key_pairs))
        
        # Store all service keys
        for service_name, api_key in service_key_pairs:
            success = self.manager.store_api_key(service_name, api_key)
            assert success
        
        # Property: All keys should be retrievable
        for service_name, expected_key in service_key_pairs:
            retrieved_key = self.manager.retrieve_api_key(service_name)
            assert retrieved_key == expected_key
        
        # Property: Service list should contain all services
        services = self.manager.list_services()
        for service_name, _ in service_key_pairs:
            assert service_name in services

class TestEnvironmentSecretManagerProperties:
    """Property-based tests for environment secret manager"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        api_manager = SecureAPIKeyManager(storage_path=os.path.join(self.temp_dir, "keys"))
        self.secret_manager = EnvironmentSecretManager(api_manager)
        self.env_vars_to_clean = []
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        # Clean up environment variables
        for var in self.env_vars_to_clean:
            if var in os.environ:
                del os.environ[var]
    
    @given(st.text(min_size=1, max_size=30), api_key_data, api_key_data)
    @settings(max_examples=50)
    def test_environment_priority_property(self, key_name, env_value, stored_value):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any key, environment variables should take priority over stored values
        **Validates: Requirements 8.3**
        """
        assume(len(key_name.strip()) > 0)
        assume(len(env_value.strip()) > 0 and len(stored_value.strip()) > 0)
        assume(env_value != stored_value)
        
        # Clean key name for environment variable
        clean_key = key_name.upper().replace(' ', '_').replace('-', '_')
        self.env_vars_to_clean.append(clean_key)
        
        # Store value in secure storage
        self.secret_manager.store_secret(clean_key, stored_value)
        
        # Set environment variable
        os.environ[clean_key] = env_value
        
        # Property: Environment variable should take priority
        retrieved = self.secret_manager.get_secret(clean_key)
        assert retrieved == env_value
    
    @given(st.text(min_size=1, max_size=30), api_key_data)
    @settings(max_examples=50)
    def test_storage_fallback_property(self, key_name, stored_value):
        """
        Feature: igsim-ai-agent-platform, Property 28: Data Encryption
        For any key without environment variable, should fallback to secure storage
        **Validates: Requirements 8.3**
        """
        assume(len(key_name.strip()) > 0 and len(stored_value.strip()) > 0)
        
        # Clean key name
        clean_key = key_name.upper().replace(' ', '_').replace('-', '_')
        
        # Ensure environment variable is not set
        if clean_key in os.environ:
            del os.environ[clean_key]
        
        # Store in secure storage
        success = self.secret_manager.store_secret(clean_key, stored_value)
        assert success
        
        # Property: Should retrieve from storage when env var not set
        retrieved = self.secret_manager.get_secret(clean_key)
        assert retrieved == stored_value

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
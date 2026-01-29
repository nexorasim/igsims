# Data Encryption Documentation

## Overview

The iGSIM AI Agent Platform implements comprehensive data encryption for sensitive information, including API keys, user credentials, and other confidential data. The encryption system provides both symmetric and asymmetric encryption capabilities with secure key management.

## Features

### Core Encryption Capabilities

- **Symmetric Encryption**: AES-256 encryption using Fernet for fast, secure data encryption
- **Asymmetric Encryption**: RSA-2048 encryption for secure key exchange and highly sensitive data
- **Password-Based Key Derivation**: PBKDF2 with SHA-256 for secure key generation from passwords
- **Secure Token Generation**: Cryptographically secure random token generation
- **Data Hashing**: SHA-256 hashing with salt for password storage and data integrity

### Security Features

- **Field-Level Encryption**: Automatic detection and encryption of sensitive fields
- **API Key Management**: Secure storage, retrieval, and rotation of API keys
- **TLS/SSL Support**: Comprehensive TLS configuration for secure communications
- **Security Headers**: Automatic security headers for web responses
- **Environment Variable Priority**: Secure fallback from environment to encrypted storage

## Architecture

### Core Components

1. **DataEncryption**: Core encryption/decryption functionality
2. **SecureStorage**: High-level interface for storing sensitive data
3. **FieldLevelEncryption**: Database record encryption with field detection
4. **SecureAPIKeyManager**: API key lifecycle management
5. **EnvironmentSecretManager**: Environment variable and secure storage integration

### Encryption Flow

```
Sensitive Data → Field Detection → Encryption → Secure Storage
                                      ↓
Retrieval Request → Decryption → Field Restoration → Clean Data
```

## Usage Examples

### Basic Encryption

```python
from encryption import DataEncryption

# Initialize encryption
encryption = DataEncryption()

# Encrypt sensitive data
sensitive_data = "user_password_123"
encrypted = encryption.encrypt(sensitive_data)

# Decrypt when needed
decrypted = encryption.decrypt(encrypted)
```

### Secure Storage

```python
from encryption import SecureStorage

# Initialize secure storage
storage = SecureStorage()

# Store API key
encrypted_key = storage.store_api_key("gemini", "your-api-key-here")

# Retrieve API key
api_key = storage.retrieve_api_key(encrypted_key)

# Store mixed sensitive/non-sensitive data
user_data = {
    "username": "john_doe",
    "password": "secret123",
    "email": "john@example.com",
    "api_key": "sk-12345"
}

encrypted_data = storage.store_sensitive_data(user_data)
decrypted_data = storage.retrieve_sensitive_data(encrypted_data)
```

### API Key Management

```python
from utils.secure_api_manager import SecureAPIKeyManager

# Initialize manager
manager = SecureAPIKeyManager()

# Store API key with metadata
manager.store_api_key("gemini", "your-api-key", rotation_interval_days=90)

# Retrieve API key
api_key = manager.retrieve_api_key("gemini")

# Use secure context manager
with manager.secure_context("gemini") as key:
    # Use the API key securely
    response = make_api_call(key)
# Key is automatically cleared from memory

# Rotate API key
manager.rotate_api_key("gemini", "new-api-key")
```

### Environment Secret Management

```python
from utils.secure_api_manager import EnvironmentSecretManager

# Initialize manager
secret_manager = EnvironmentSecretManager()

# Get secret (tries environment first, then secure storage)
api_key = secret_manager.get_secret("GEMINI_API_KEY", "gemini")

# Get all AI service keys
ai_keys = secret_manager.get_ai_service_keys()
```

## Configuration

### Environment Variables

Configure encryption behavior through environment variables:

```bash
# Encryption Settings
DATA_ENCRYPTION_ENABLED=true
FIELD_LEVEL_ENCRYPTION=true
ASYMMETRIC_ENCRYPTION=false
KEY_ROTATION_DAYS=90
ENCRYPTION_ALGORITHM=AES-256-GCM
KEY_DERIVATION_ITERATIONS=100000

# TLS Settings
TLS_ENABLED=true
TLS_MIN_VERSION=TLSv1.2
TLS_MAX_VERSION=TLSv1.3
TLS_CERT_FILE=path/to/cert.pem
TLS_KEY_FILE=path/to/key.pem

# Security Settings
ENFORCE_HTTPS=true
SECURE_COOKIES=true
CSRF_PROTECTION=true
SECURITY_HEADERS=true
```

### Programmatic Configuration

```python
from encryption import EncryptionConfig, DataEncryption

# Custom encryption configuration
config = EncryptionConfig(
    key_derivation_iterations=200000,
    salt_length=64,
    key_length=32,
    rsa_key_size=4096
)

encryption = DataEncryption(config=config)
```

## Security Best Practices

### Key Management

1. **Key Rotation**: Regularly rotate API keys and encryption keys
2. **Secure Storage**: Store encryption keys with restrictive file permissions (600)
3. **Environment Separation**: Use different keys for development, staging, and production
4. **Key Backup**: Securely backup encryption keys with proper access controls

### Data Handling

1. **Field Detection**: Rely on automatic sensitive field detection when possible
2. **Memory Management**: Clear sensitive data from memory after use
3. **Logging**: Never log decrypted sensitive data
4. **Error Handling**: Handle encryption errors gracefully without exposing data

### Network Security

1. **TLS Configuration**: Use TLS 1.2 or higher for all communications
2. **Certificate Validation**: Always validate TLS certificates
3. **Security Headers**: Enable all security headers for web responses
4. **HTTPS Enforcement**: Redirect HTTP to HTTPS in production

## File Structure

```
src/
├── encryption.py                    # Core encryption functionality
├── utils/
│   └── secure_api_manager.py       # API key management
├── config/
│   └── settings.py                 # Security configuration
├── tests/
│   ├── test_data_encryption.py     # Unit tests
│   └── test_data_encryption_property.py  # Property tests
└── docs/
    └── ENCRYPTION.md               # This documentation
```

## Testing

### Unit Tests

Run comprehensive unit tests:

```bash
python -m pytest src/tests/test_data_encryption.py -v
```

### Property-Based Tests

Run property-based tests to verify encryption properties:

```bash
python -m pytest src/tests/test_data_encryption_property.py -v
```

### Test Coverage

The encryption system includes tests for:

- Symmetric and asymmetric encryption roundtrips
- Password-based key derivation consistency
- Secure token generation uniqueness
- API key storage and retrieval
- Field-level encryption detection
- Environment variable priority
- Key rotation and lifecycle management

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed from requirements.txt
2. **Key File Permissions**: Check that key files have correct permissions (600)
3. **Environment Variables**: Verify environment variables are properly set
4. **TLS Configuration**: Ensure certificate files exist and are valid

### Debug Mode

Enable debug logging for encryption operations:

```python
import logging
logging.getLogger('encryption').setLevel(logging.DEBUG)
```

### Performance Considerations

1. **Caching**: Encryption instances are cached globally for performance
2. **Batch Operations**: Use batch operations for multiple encryptions
3. **Asymmetric Encryption**: Use sparingly due to performance overhead
4. **Key Derivation**: PBKDF2 iterations balance security and performance

## Compliance

The encryption implementation follows industry standards:

- **FIPS 140-2**: Uses FIPS-approved algorithms (AES, SHA-256, RSA)
- **NIST Guidelines**: Follows NIST recommendations for key lengths and algorithms
- **OWASP**: Implements OWASP security best practices
- **GDPR**: Supports data protection requirements through encryption

## API Reference

### DataEncryption Class

- `encrypt(data: str) -> str`: Encrypt data using symmetric encryption
- `decrypt(encrypted_data: str) -> str`: Decrypt data using symmetric encryption
- `encrypt_asymmetric(data: str) -> str`: Encrypt using RSA public key
- `decrypt_asymmetric(encrypted_data: str) -> str`: Decrypt using RSA private key
- `generate_secure_token(length: int = 32) -> str`: Generate secure random token
- `hash_data(data: str, salt: str = None) -> tuple`: Hash data with salt

### SecureStorage Class

- `store_api_key(service: str, api_key: str) -> str`: Store encrypted API key
- `retrieve_api_key(encrypted_key: str) -> str`: Retrieve decrypted API key
- `store_sensitive_data(data: dict) -> dict`: Store data with field-level encryption
- `retrieve_sensitive_data(encrypted_data: dict) -> dict`: Retrieve decrypted data
- `is_sensitive_field(field_name: str) -> bool`: Check if field is sensitive

### SecureAPIKeyManager Class

- `store_api_key(service: str, api_key: str, **kwargs) -> bool`: Store API key with metadata
- `retrieve_api_key(service: str) -> str`: Retrieve API key
- `rotate_api_key(service: str, new_key: str) -> bool`: Rotate API key
- `delete_api_key(service: str) -> bool`: Delete API key
- `list_services() -> dict`: List all stored services
- `secure_context(service: str)`: Context manager for secure key usage

## Support

For questions or issues with the encryption system:

1. Check this documentation first
2. Review the test files for usage examples
3. Check the GitHub issues for known problems
4. Contact the development team for additional support
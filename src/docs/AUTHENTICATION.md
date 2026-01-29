# Firebase Authentication System

This document describes the Firebase Authentication system implemented for the iGSIM AI Agent Platform, fulfilling **Requirements 8.1 (User authentication and authorization)** and **Requirements 8.2 (Secure session management)**.

## Overview

The authentication system provides comprehensive user management with Firebase Auth integration, supporting:

- **Email/Password Authentication**: Traditional email and password login
- **OAuth Providers**: Google, GitHub, and Microsoft authentication
- **JWT Token Management**: Secure access and refresh token handling
- **Role-Based Access Control**: User, operator, and admin roles
- **Security Features**: Rate limiting, password validation, and secure token generation

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │    │   Auth API      │    │  Auth Service   │
│                 │    │                 │    │                 │
│ - Web Frontend  │◄──►│ - Registration  │◄──►│ - Firebase Auth │
│ - Mobile App    │    │ - Login         │    │ - JWT Tokens    │
│ - Desktop GUI   │    │ - OAuth         │    │ - User Mgmt     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   Auth Utils    │    │  User Repository│
                       │                 │    │                 │
                       │ - Validation    │    │ - Firestore DB  │
                       │ - Rate Limiting │    │ - User CRUD     │
                       │ - Security      │    │ - Permissions   │
                       └─────────────────┘    └─────────────────┘
```

## Components

### 1. AuthService (`src/services/auth_service.py`)

The core authentication service that handles:

- User registration and login
- Firebase Auth integration
- JWT token generation and validation
- OAuth provider authentication
- Password reset and email verification

**Key Methods:**
```python
async def register_user(registration_data: RegistrationData) -> AuthResult
async def login_with_email_password(email: str, password: str) -> AuthResult
async def login_with_oauth(provider: AuthProvider, oauth_token: str) -> AuthResult
async def validate_token(token: str) -> TokenValidationResult
async def refresh_access_token(refresh_token: str) -> AuthResult
```

### 2. Authentication API (`src/api/auth.py`)

FastAPI endpoints for authentication operations:

- `POST /auth/register` - User registration
- `POST /auth/login` - Email/password login
- `POST /auth/oauth/login` - OAuth authentication
- `POST /auth/refresh` - Token refresh
- `POST /auth/logout` - User logout
- `GET /auth/me` - Get current user info
- `POST /auth/reset-password` - Password reset
- `POST /auth/change-password` - Change password

### 3. Authentication Utilities (`src/utils/auth_utils.py`)

Helper functions and FastAPI dependencies:

- Email and password validation
- Token generation and verification
- Rate limiting
- FastAPI dependencies for authentication
- Security utilities

### 4. User Model (`src/models/user.py`)

User data model with:

- User information (email, display name, role)
- Permission management
- User preferences
- Serialization/deserialization

## Usage Examples

### 1. User Registration

```python
from services.auth_service import AuthService, RegistrationData

auth_service = AuthService()

registration_data = RegistrationData(
    email="user@example.com",
    password="SecurePassword123!",
    display_name="John Doe",
    role="user"
)

result = await auth_service.register_user(registration_data)

if result.success:
    print(f"User registered: {result.user.email}")
    print(f"Access token: {result.access_token}")
else:
    print(f"Registration failed: {result.error_message}")
```

### 2. User Login

```python
result = await auth_service.login_with_email_password(
    "user@example.com", 
    "SecurePassword123!"
)

if result.success:
    print(f"Login successful: {result.user.email}")
    print(f"Access token: {result.access_token}")
    print(f"Refresh token: {result.refresh_token}")
else:
    print(f"Login failed: {result.error_message}")
```

### 3. OAuth Authentication

```python
from services.auth_service import AuthProvider

result = await auth_service.login_with_oauth(
    AuthProvider.GOOGLE,
    "google-oauth-token"
)

if result.success:
    print(f"OAuth login successful: {result.user.email}")
else:
    print(f"OAuth login failed: {result.error_message}")
```

### 4. Token Validation

```python
validation_result = await auth_service.validate_token("jwt-access-token")

if validation_result.valid:
    print(f"Token valid for user: {validation_result.user_id}")
    print(f"Claims: {validation_result.claims}")
else:
    print(f"Token invalid: {validation_result.error_message}")
```

### 5. FastAPI Integration

```python
from fastapi import FastAPI, Depends
from utils.auth_utils import get_current_user, require_permissions
from models.user import User

app = FastAPI()

@app.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.display_name}"}

@app.get("/admin-only")
async def admin_endpoint(
    current_user: User = Depends(require_permissions(["manage_users"]))
):
    return {"message": "Admin access granted"}
```

## Security Features

### 1. Password Security

- Minimum 8 characters required
- Password strength validation
- Secure password hashing (via Firebase)
- Password reset functionality

### 2. Token Security

- JWT tokens with expiration
- Secure refresh token mechanism
- Token validation and verification
- Automatic token cleanup

### 3. Rate Limiting

- Failed login attempt limiting
- IP-based rate limiting
- Configurable limits and timeouts
- Automatic lockout mechanism

### 4. Input Validation

- Email format validation
- Password strength requirements
- Request data validation
- SQL injection prevention

### 5. OAuth Security

- Provider token verification
- Secure OAuth flow handling
- Provider validation
- Token exchange security

## Configuration

### Environment Variables

```bash
# Firebase Configuration
FIREBASE_PROJECT_ID=bamboo-reason-483913-i4
FIREBASE_API_KEY=your-firebase-api-key
FIREBASE_CREDENTIALS_PATH=/path/to/service-account.json

# JWT Configuration
JWT_SECRET_KEY=your-secret-key
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Security Configuration
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15

# Email Configuration (optional)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=noreply@yourdomain.com
```

### Firebase Setup

1. Create a Firebase project at https://console.firebase.google.com
2. Enable Authentication and configure providers
3. Generate service account credentials
4. Configure authentication settings

## API Reference

### Authentication Endpoints

#### POST /auth/register

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "display_name": "John Doe",
  "role": "user"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "user_id": "user-123",
    "email": "user@example.com",
    "display_name": "John Doe",
    "role": "user",
    "permissions": ["read"],
    "is_active": true
  },
  "access_token": "jwt-access-token",
  "refresh_token": "refresh-token",
  "expires_in": 1800
}
```

#### POST /auth/login

Authenticate with email and password.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": { /* user object */ },
  "access_token": "jwt-access-token",
  "refresh_token": "refresh-token",
  "expires_in": 1800
}
```

#### POST /auth/oauth/login

Authenticate with OAuth provider.

**Request Body:**
```json
{
  "provider": "google.com",
  "oauth_token": "google-oauth-token"
}
```

#### POST /auth/refresh

Refresh access token.

**Request Body:**
```json
{
  "refresh_token": "refresh-token"
}
```

#### POST /auth/logout

Logout and invalidate refresh token.

**Request Body:**
```json
{
  "refresh_token": "refresh-token"
}
```

**Headers:**
```
Authorization: Bearer jwt-access-token
```

#### GET /auth/me

Get current user information.

**Headers:**
```
Authorization: Bearer jwt-access-token
```

**Response:**
```json
{
  "user_id": "user-123",
  "email": "user@example.com",
  "display_name": "John Doe",
  "role": "user",
  "permissions": ["read"],
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z",
  "last_login": "2024-01-01T12:00:00Z"
}
```

## Error Handling

### Common Error Codes

- `INVALID_EMAIL` - Email format is invalid
- `WEAK_PASSWORD` - Password doesn't meet requirements
- `USER_EXISTS` - User with email already exists
- `AUTH_FAILED` - Authentication failed
- `USER_DISABLED` - User account is disabled
- `INVALID_TOKEN` - JWT token is invalid or expired
- `INVALID_REFRESH_TOKEN` - Refresh token is invalid
- `REFRESH_TOKEN_EXPIRED` - Refresh token has expired

### Error Response Format

```json
{
  "detail": "Error message",
  "error_code": "ERROR_CODE"
}
```

## Testing

### Unit Tests

Run unit tests for the authentication service:

```bash
pytest src/tests/test_auth_service.py -v
```

### Property-Based Tests

Run property-based tests to verify universal properties:

```bash
pytest src/tests/test_auth_properties.py -v
```

### API Integration Tests

Run API integration tests:

```bash
pytest src/tests/test_auth_api.py -v
```

### Validation Script

Run the validation script to check implementation:

```bash
python src/tests/validate_auth.py
```

### Example Usage

Run the comprehensive example:

```bash
python src/examples/auth_example.py
```

## Deployment

### Firebase Deployment

1. Install Firebase CLI: `npm install -g firebase-tools`
2. Login to Firebase: `firebase login`
3. Initialize project: `firebase init`
4. Deploy: `firebase deploy`

### Environment Setup

1. Create `.env` file with required variables
2. Configure Firebase service account
3. Set up OAuth providers in Firebase Console
4. Configure CORS settings for your domain

## Security Considerations

### Production Checklist

- [ ] Use strong JWT secret key
- [ ] Configure HTTPS only
- [ ] Set up proper CORS policies
- [ ] Enable Firebase security rules
- [ ] Configure rate limiting
- [ ] Set up monitoring and alerting
- [ ] Regular security audits
- [ ] Keep dependencies updated

### Best Practices

1. **Never store passwords in plain text**
2. **Use HTTPS for all authentication endpoints**
3. **Implement proper session management**
4. **Validate all input data**
5. **Use secure random token generation**
6. **Implement proper error handling**
7. **Log security events**
8. **Regular security updates**

## Troubleshooting

### Common Issues

1. **Firebase connection errors**
   - Check service account credentials
   - Verify project ID configuration
   - Ensure Firebase APIs are enabled

2. **Token validation failures**
   - Check JWT secret key
   - Verify token expiration settings
   - Ensure clock synchronization

3. **OAuth authentication issues**
   - Verify OAuth provider configuration
   - Check redirect URLs
   - Validate OAuth tokens

4. **Rate limiting problems**
   - Check rate limit configuration
   - Clear rate limit cache if needed
   - Verify IP address detection

### Debug Mode

Enable debug logging by setting:

```bash
DEBUG=true
LOG_LEVEL=DEBUG
```

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review the example code
3. Run the validation script
4. Check Firebase console for errors
5. Review application logs

## License

This authentication system is part of the iGSIM AI Agent Platform and is licensed under the Apache License 2.0.
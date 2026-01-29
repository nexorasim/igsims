"""
Example usage of the Firebase Authentication System

This example demonstrates how to use the authentication service
for user registration, login, and token management.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.auth_service import AuthService, RegistrationData, AuthProvider
from models.user import User
from utils.auth_utils import AuthUtils

async def example_registration_and_login():
    """Example of user registration and login flow"""
    print("=== User Registration and Login Example ===")
    
    # Note: This is a mock example since we don't have Firebase credentials
    # In a real implementation, you would have Firebase configured
    
    try:
        # Initialize auth service (would connect to Firebase in real implementation)
        auth_service = AuthService()
        print("✓ Auth service initialized")
        
        # Example registration data
        registration_data = RegistrationData(
            email="user@example.com",
            password="SecurePassword123!",
            display_name="Example User",
            role="user"
        )
        
        print(f"📝 Registering user: {registration_data.email}")
        
        # In a real implementation, this would create the user in Firebase
        # result = await auth_service.register_user(registration_data)
        
        # For demonstration, create a user manually
        user = User.create_new(
            email=registration_data.email,
            display_name=registration_data.display_name,
            role=registration_data.role
        )
        
        print(f"✓ User created: {user.email}")
        print(f"  - User ID: {user.user_id}")
        print(f"  - Role: {user.role}")
        print(f"  - Permissions: {user.permissions}")
        
        # Generate tokens (demonstration)
        access_token = auth_service._generate_access_token(user)
        refresh_token = auth_service._generate_refresh_token(user)
        
        print(f"✓ Tokens generated")
        print(f"  - Access token length: {len(access_token)}")
        print(f"  - Refresh token length: {len(refresh_token)}")
        
        # Validate token
        validation_result = await auth_service.validate_token(access_token)
        print(f"✓ Token validation: {validation_result.valid}")
        
        if validation_result.valid:
            print(f"  - User ID from token: {validation_result.user_id}")
            print(f"  - Token claims: {list(validation_result.claims.keys())}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in registration/login example: {e}")
        return False

def example_user_management():
    """Example of user management operations"""
    print("\n=== User Management Example ===")
    
    try:
        # Create different types of users
        admin_user = User.create_new("admin@example.com", "Admin User", "admin")
        operator_user = User.create_new("operator@example.com", "Operator User", "operator")
        regular_user = User.create_new("user@example.com", "Regular User", "user")
        
        print("✓ Created users with different roles:")
        print(f"  - Admin: {admin_user.email} (permissions: {admin_user.permissions})")
        print(f"  - Operator: {operator_user.email} (permissions: {operator_user.permissions})")
        print(f"  - User: {regular_user.email} (permissions: {regular_user.permissions})")
        
        # Test permission management
        print("\n📋 Testing permission management:")
        
        # Add custom permission to regular user
        regular_user.add_permission("custom_feature")
        print(f"  - Added 'custom_feature' to regular user")
        print(f"  - Regular user has 'custom_feature': {regular_user.has_permission('custom_feature')}")
        print(f"  - Admin has 'custom_feature': {admin_user.has_permission('custom_feature')}")  # Should be True (admin has all)
        
        # Test preferences
        print("\n⚙️ Testing user preferences:")
        regular_user.set_preference("theme", "dark")
        regular_user.set_preference("language", "en")
        regular_user.set_preference("notifications", True)
        
        print(f"  - Theme: {regular_user.get_preference('theme')}")
        print(f"  - Language: {regular_user.get_preference('language')}")
        print(f"  - Notifications: {regular_user.get_preference('notifications')}")
        print(f"  - Non-existent pref: {regular_user.get_preference('non_existent', 'default_value')}")
        
        # Test user validation
        print("\n✅ Testing user validation:")
        print(f"  - Admin user valid: {admin_user.validate()}")
        print(f"  - Operator user valid: {operator_user.validate()}")
        print(f"  - Regular user valid: {regular_user.validate()}")
        
        # Test serialization
        print("\n💾 Testing user serialization:")
        user_dict = regular_user.to_dict()
        restored_user = User.from_dict(user_dict)
        print(f"  - Original email: {regular_user.email}")
        print(f"  - Restored email: {restored_user.email}")
        print(f"  - Preferences preserved: {restored_user.preferences == regular_user.preferences}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in user management example: {e}")
        return False

def example_auth_utilities():
    """Example of authentication utility functions"""
    print("\n=== Authentication Utilities Example ===")
    
    try:
        # Email validation examples
        print("📧 Email validation examples:")
        test_emails = [
            "valid@example.com",
            "user.name+tag@domain.co.uk",
            "invalid-email",
            "@domain.com",
            "user@",
            ""
        ]
        
        for email in test_emails:
            is_valid = AuthUtils.validate_email(email)
            status = "✓" if is_valid else "✗"
            print(f"  {status} {email or '(empty)'}: {is_valid}")
        
        # Password validation examples
        print("\n🔒 Password validation examples:")
        test_passwords = [
            "SecurePassword123!",
            "AnotherGood1!",
            "weak",
            "",
            "12345678",  # Only digits but meets minimum length
            "verylongpasswordwithoutspecialchars"
        ]
        
        for password in test_passwords:
            result = AuthUtils.validate_password(password)
            status = "✓" if result["valid"] else "✗"
            display_password = password or "(empty)"
            if len(display_password) > 20:
                display_password = display_password[:17] + "..."
            print(f"  {status} {display_password}: {result['valid']}")
            if not result["valid"] and result["errors"]:
                print(f"    Errors: {', '.join(result['errors'])}")
        
        # Token generation examples
        print("\n🎫 Token generation examples:")
        for length in [16, 32, 64]:
            token = AuthUtils.generate_secure_token(length)
            print(f"  - {length}-char token: {token[:20]}... (length: {len(token)})")
        
        # Verification code examples
        print("\n🔢 Verification code examples:")
        for length in [4, 6, 8]:
            code = AuthUtils.generate_verification_code(length)
            print(f"  - {length}-digit code: {code}")
        
        # URL safety examples
        print("\n🔗 URL safety examples:")
        allowed_hosts = ["example.com", "app.example.com", "secure.example.com"]
        test_urls = [
            "/dashboard",  # Relative URL (safe)
            "/profile/settings",  # Relative URL (safe)
            "https://example.com/callback",  # Allowed host (safe)
            "https://app.example.com/auth",  # Allowed host (safe)
            "https://evil.com/phishing",  # Not allowed host (unsafe)
            "//evil.com/path",  # Protocol-relative (unsafe)
            "javascript:alert('xss')",  # JavaScript (unsafe)
            ""  # Empty (unsafe)
        ]
        
        print(f"  Allowed hosts: {allowed_hosts}")
        for url in test_urls:
            is_safe = AuthUtils.is_safe_redirect_url(url, allowed_hosts)
            status = "✓" if is_safe else "✗"
            display_url = url or "(empty)"
            print(f"  {status} {display_url}: {is_safe}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in auth utilities example: {e}")
        return False

async def example_oauth_flow():
    """Example of OAuth authentication flow"""
    print("\n=== OAuth Authentication Example ===")
    
    try:
        auth_service = AuthService()
        
        # Simulate OAuth providers
        providers = [
            (AuthProvider.GOOGLE, "Google"),
            (AuthProvider.GITHUB, "GitHub"),
            (AuthProvider.MICROSOFT, "Microsoft")
        ]
        
        print("🔐 Supported OAuth providers:")
        for provider, name in providers:
            print(f"  - {name}: {provider.value}")
        
        # In a real implementation, you would:
        # 1. Redirect user to OAuth provider
        # 2. Receive OAuth token from provider
        # 3. Verify token with Firebase
        # 4. Create or update user in your database
        
        print("\n📝 OAuth flow steps:")
        print("  1. User clicks 'Login with Google'")
        print("  2. Redirect to Google OAuth")
        print("  3. User authorizes application")
        print("  4. Google redirects back with token")
        print("  5. Verify token with Firebase")
        print("  6. Create/update user in database")
        print("  7. Generate application tokens")
        print("  8. Return tokens to client")
        
        # Example of what the OAuth result would look like
        print("\n✅ Example OAuth result:")
        example_user = User.create_new("oauth.user@gmail.com", "OAuth User", "user")
        access_token = auth_service._generate_access_token(example_user)
        
        print(f"  - User: {example_user.email}")
        print(f"  - Provider: Google")
        print(f"  - Access token generated: {len(access_token)} characters")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in OAuth example: {e}")
        return False

def example_security_features():
    """Example of security features"""
    print("\n=== Security Features Example ===")
    
    try:
        from utils.auth_utils import RateLimiter
        
        # Rate limiting example
        print("🚦 Rate limiting example:")
        rate_limiter = RateLimiter()
        
        client_ip = "192.168.1.100"
        max_attempts = 3
        
        print(f"  Testing rate limiting for IP: {client_ip}")
        print(f"  Max attempts allowed: {max_attempts}")
        
        for attempt in range(5):
            is_limited = rate_limiter.is_rate_limited(client_ip, max_attempts, 15)
            print(f"  - Attempt {attempt + 1}: Rate limited = {is_limited}")
            
            if not is_limited:
                # Simulate failed attempt
                rate_limiter.record_attempt(client_ip, max_attempts, 15)
                print(f"    Recorded failed attempt")
            else:
                print(f"    Client is rate limited")
                break
        
        # Password hashing example (placeholder implementation)
        print("\n🔐 Password security example:")
        password = "MySecurePassword123!"
        hashed = AuthUtils.hash_password(password)
        is_valid = AuthUtils.verify_password(password, hashed)
        
        print(f"  - Original password: {password}")
        print(f"  - Hashed password: {hashed[:50]}...")
        print(f"  - Verification result: {is_valid}")
        print(f"  - Wrong password verification: {AuthUtils.verify_password('wrong', hashed)}")
        
        # Token expiration example
        print("\n⏰ Token expiration example:")
        user = User.create_new("test@example.com", "Test User")
        auth_service = AuthService()
        
        # Generate token
        token = auth_service._generate_access_token(user)
        print(f"  - Generated token: {token[:30]}...")
        
        # Validate immediately (should be valid)
        validation = await auth_service.validate_token(token)
        print(f"  - Immediate validation: {validation.valid}")
        
        if validation.valid and validation.claims:
            import datetime
            exp_timestamp = validation.claims.get('exp', 0)
            exp_datetime = datetime.datetime.fromtimestamp(exp_timestamp)
            print(f"  - Token expires at: {exp_datetime}")
            print(f"  - Time until expiration: {exp_datetime - datetime.datetime.now()}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in security features example: {e}")
        return False

async def main():
    """Run all examples"""
    print("🔐 Firebase Authentication System Examples")
    print("=" * 60)
    
    examples = [
        ("Registration and Login", example_registration_and_login),
        ("User Management", example_user_management),
        ("Authentication Utilities", example_auth_utilities),
        ("OAuth Flow", example_oauth_flow),
        ("Security Features", example_security_features),
    ]
    
    passed = 0
    total = len(examples)
    
    for name, example_func in examples:
        print(f"\n{'=' * 20} {name} {'=' * 20}")
        try:
            if asyncio.iscoroutinefunction(example_func):
                result = await example_func()
            else:
                result = example_func()
            
            if result:
                passed += 1
                print(f"✅ {name} completed successfully")
            else:
                print(f"❌ {name} failed")
        except Exception as e:
            print(f"❌ {name} failed with error: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Examples Results: {passed}/{total} completed successfully")
    
    if passed == total:
        print("🎉 All examples completed successfully!")
        print("\n📚 Next steps:")
        print("  1. Configure Firebase credentials")
        print("  2. Set up environment variables")
        print("  3. Deploy to Firebase hosting")
        print("  4. Test with real Firebase authentication")
    else:
        print("⚠️ Some examples had issues. Check the output above.")
    
    return passed == total

if __name__ == "__main__":
    asyncio.run(main())
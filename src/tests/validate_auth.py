"""
Simple validation script for authentication implementation
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def validate_imports():
    """Validate that all authentication modules can be imported"""
    try:
        from services.auth_service import AuthService, AuthResult, RegistrationData, AuthProvider
        print("✓ AuthService imports successfully")
        
        from utils.auth_utils import AuthUtils, get_current_user, require_permissions
        print("✓ AuthUtils imports successfully")
        
        from api.auth import router
        print("✓ Auth API router imports successfully")
        
        from models.user import User
        print("✓ User model imports successfully")
        
        from config.settings import get_settings
        print("✓ Settings imports successfully")
        
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def validate_user_model():
    """Validate User model functionality"""
    try:
        from models.user import User
        
        # Test user creation
        user = User.create_new("test@example.com", "Test User", "user")
        assert user.email == "test@example.com"
        assert user.display_name == "Test User"
        assert user.role == "user"
        assert user.is_active is True
        assert user.validate() is True
        print("✓ User model creation works")
        
        # Test permissions
        user.add_permission("read")
        assert user.has_permission("read")
        user.remove_permission("read")
        assert not user.has_permission("read")
        print("✓ User permission management works")
        
        # Test preferences
        user.set_preference("theme", "dark")
        assert user.get_preference("theme") == "dark"
        print("✓ User preferences work")
        
        # Test serialization
        user_dict = user.to_dict()
        user_from_dict = User.from_dict(user_dict)
        assert user_from_dict.email == user.email
        print("✓ User serialization works")
        
        return True
    except Exception as e:
        print(f"✗ User model validation error: {e}")
        return False

def validate_auth_utils():
    """Validate authentication utilities"""
    try:
        from utils.auth_utils import AuthUtils
        
        # Test email validation
        assert AuthUtils.validate_email("test@example.com") is True
        assert AuthUtils.validate_email("invalid-email") is False
        print("✓ Email validation works")
        
        # Test password validation
        result = AuthUtils.validate_password("SecurePass123!")
        assert result["valid"] is True
        
        result = AuthUtils.validate_password("weak")
        assert result["valid"] is False
        print("✓ Password validation works")
        
        # Test token generation
        token = AuthUtils.generate_secure_token(32)
        assert len(token) > 0
        print("✓ Token generation works")
        
        return True
    except Exception as e:
        print(f"✗ Auth utils validation error: {e}")
        return False

def validate_settings():
    """Validate settings configuration"""
    try:
        from config.settings import get_settings, Settings
        
        settings = get_settings()
        assert isinstance(settings, Settings)
        assert settings.firebase_project_id == "bamboo-reason-483913-i4"
        print("✓ Settings configuration works")
        
        return True
    except Exception as e:
        print(f"✗ Settings validation error: {e}")
        return False

def main():
    """Run all validations"""
    print("Validating Authentication Implementation...")
    print("=" * 50)
    
    validations = [
        ("Import validation", validate_imports),
        ("User model validation", validate_user_model),
        ("Auth utils validation", validate_auth_utils),
        ("Settings validation", validate_settings),
    ]
    
    passed = 0
    total = len(validations)
    
    for name, validation_func in validations:
        print(f"\n{name}:")
        if validation_func():
            passed += 1
        else:
            print(f"✗ {name} failed")
    
    print("\n" + "=" * 50)
    print(f"Validation Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All validations passed! Authentication implementation is ready.")
        return True
    else:
        print("❌ Some validations failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
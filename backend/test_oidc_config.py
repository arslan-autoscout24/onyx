#!/usr/bin/env python3
"""
Test script to verify OIDC configuration is working correctly.
"""

import os
import sys
sys.path.insert(0, '.')

def test_oidc_imports():
    """Test that all OIDC modules can be imported."""
    try:
        from onyx.auth.oidc_simple import map_oidc_groups_to_role, handle_oidc_callback
        from onyx.auth.schemas import UserRole
        print("✅ OIDC modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_oidc_group_mapping():
    """Test OIDC group mapping functionality."""
    try:
        from onyx.auth.oidc_simple import map_oidc_groups_to_role
        from onyx.auth.schemas import UserRole
        
        # Test admin group
        admin_role = map_oidc_groups_to_role(["Onyx-Admins"])
        assert admin_role == UserRole.ADMIN, f"Expected ADMIN, got {admin_role}"
        
        # Test non-admin group
        user_role = map_oidc_groups_to_role(["Some-Other-Group"])
        assert user_role == UserRole.BASIC, f"Expected BASIC, got {user_role}"
        
        # Test empty groups
        empty_role = map_oidc_groups_to_role([])
        assert empty_role == UserRole.BASIC, f"Expected BASIC, got {empty_role}"
        
        print("✅ OIDC group mapping working correctly")
        return True
    except Exception as e:
        print(f"❌ Group mapping error: {e}")
        return False

def test_oauth_settings():
    """Test OAuth settings can be loaded."""
    try:
        from onyx.configs.oauth_settings import OAuthSettings
        print("✅ OAuth settings structure is valid")
        return True
    except Exception as e:
        print(f"❌ OAuth settings error: {e}")
        return False

def main():
    """Run all tests."""
    print("Testing OIDC Configuration...")
    print("=" * 40)
    
    tests = [
        test_oidc_imports,
        test_oidc_group_mapping,
        test_oauth_settings
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All OIDC configuration tests passed!")
        return True
    else:
        print("💥 Some tests failed!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

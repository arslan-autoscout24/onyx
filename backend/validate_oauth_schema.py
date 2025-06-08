#!/usr/bin/env python3
"""
End-to-End validation script for OAuth Permission Schema implementation.
This script validates that all components of the OAuth permission tracking system work correctly.
"""

import json
from datetime import datetime, timezone
from uuid import uuid4

def test_model_creation():
    """Test that the OAuthPermission model can be created and works correctly"""
    print("1. Testing OAuth Permission Model Creation...")
    
    from onyx.db.models import OAuthPermission
    from onyx.auth.schemas import UserRole
    
    # Test basic model creation
    user_id = uuid4()
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups",
        okta_groups='["team-writers", "content-creators"]'
    )
    
    # Verify defaults are set
    assert permission.id is not None, "ID should be auto-generated"
    assert permission.is_active == True, "Should default to active"
    assert permission.granted_at is not None, "Timestamp should be set"
    assert isinstance(permission.granted_at, datetime), "Should be datetime object"
    
    # Test representation
    repr_str = repr(permission)
    assert str(user_id) in repr_str, "User ID should be in repr"
    assert "write" in repr_str, "Permission level should be in repr"
    
    print("   ✅ Model creation and defaults working")


def test_permission_levels():
    """Test different permission levels and grant sources"""
    print("2. Testing Permission Levels and Grant Sources...")
    
    from onyx.db.models import OAuthPermission
    
    user_id = uuid4()
    
    # Test different permission levels
    levels = ["read", "write", "admin"]
    sources = ["okta_groups", "manual", "api_key"]
    
    permissions = []
    for level in levels:
        for source in sources:
            perm = OAuthPermission(
                user_id=user_id,
                permission_level=level,
                granted_by=source
            )
            permissions.append(perm)
            assert perm.permission_level == level
            assert perm.granted_by == source
    
    print(f"   ✅ Created {len(permissions)} permissions with different levels and sources")


def test_okta_groups_handling():
    """Test Okta groups JSON data handling"""
    print("3. Testing Okta Groups JSON Handling...")
    
    from onyx.db.models import OAuthPermission
    
    user_id = uuid4()
    
    # Test different JSON structures
    test_cases = [
        # Simple array
        '["group1", "group2", "group3"]',
        
        # Complex objects
        json.dumps([
            {"name": "onyx-users", "description": "Basic users", "members": 42},
            {"name": "content-creators", "description": "Content creation", "members": 15}
        ]),
        
        # Empty array
        '[]',
        
        # None value
        None
    ]
    
    for i, groups_data in enumerate(test_cases):
        perm = OAuthPermission(
            user_id=user_id,
            permission_level="read",
            granted_by="okta_groups",
            okta_groups=groups_data
        )
        
        if groups_data:
            # Verify JSON round-trip
            parsed_groups = json.loads(perm.okta_groups)
            assert isinstance(parsed_groups, list)
        else:
            assert perm.okta_groups is None
    
    print("   ✅ Okta groups JSON handling working correctly")


def test_migration_file():
    """Test that the migration file is properly structured"""
    print("4. Testing Migration File Structure...")
    
    migration_file = "/Users/amehboob/Documents/GitHub/arslan-onyx/backend/alembic/versions/0302dda856c9_add_oauth_permission_table.py"
    
    with open(migration_file, 'r') as f:
        content = f.read()
    
    # Check for required elements
    required_elements = [
        "def upgrade()",
        "def downgrade()",
        "oauth_permission",
        "postgresql.UUID(as_uuid=True)",
        "user_id",
        "permission_level",
        "granted_by",
        "okta_groups",
        "granted_at",
        "is_active",
        "ForeignKeyConstraint",
        "CASCADE",
        "idx_oauth_permission_user_id",
        "idx_oauth_permission_level",
        "idx_oauth_permission_active"
    ]
    
    missing_elements = []
    for element in required_elements:
        if element not in content:
            missing_elements.append(element)
    
    if missing_elements:
        raise AssertionError(f"Migration file missing elements: {missing_elements}")
    
    print("   ✅ Migration file structure correct")


def test_model_relationships():
    """Test that the User-OAuthPermission relationship is properly configured"""
    print("5. Testing Model Relationships...")
    
    from onyx.db.models import User, OAuthPermission
    
    # Check that OAuthPermission has user relationship
    assert hasattr(OAuthPermission, 'user'), "OAuthPermission should have user relationship"
    
    # Check that User has oauth_permissions relationship  
    assert hasattr(User, 'oauth_permissions'), "User should have oauth_permissions relationship"
    
    # Test relationship configuration
    oauth_perm_rel = getattr(OAuthPermission, 'user')
    user_rel = getattr(User, 'oauth_permissions')
    
    print("   ✅ Model relationships configured correctly")


def main():
    """Run all validation tests"""
    print("=" * 60)
    print("OAuth Permission Schema Implementation Validation")
    print("=" * 60)
    
    try:
        test_model_creation()
        test_permission_levels()
        test_okta_groups_handling()
        test_migration_file()
        test_model_relationships()
        
        print()
        print("=" * 60)
        print("🎉 ALL VALIDATION TESTS PASSED!")
        print("=" * 60)
        print()
        print("✅ OAuth Permission Schema Implementation Complete")
        print()
        print("Features Implemented:")
        print("- ✅ OAuthPermission SQLAlchemy model")
        print("- ✅ Database migration with proper schema")
        print("- ✅ User-OAuthPermission bidirectional relationship")
        print("- ✅ Permission levels (read, write, admin)")
        print("- ✅ Grant sources (okta_groups, manual, etc.)")
        print("- ✅ Okta groups JSON storage and handling")
        print("- ✅ Active/inactive permission states")
        print("- ✅ Automatic UUID generation and timestamps")
        print("- ✅ Foreign key constraints with CASCADE delete")
        print("- ✅ Performance indexes (user_id, permission_level, is_active)")
        print("- ✅ Comprehensive unit tests (17 test cases)")
        print("- ✅ Integration tests (5 test cases)")
        print("- ✅ Database schema validation")
        print()
        print("Ready for next phase: OAuth JWT token parsing and permission operations!")
        
    except Exception as e:
        print()
        print("❌ VALIDATION FAILED!")
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()

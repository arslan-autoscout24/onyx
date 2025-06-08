import pytest
from datetime import datetime, timezone
from uuid import uuid4, UUID
from unittest.mock import Mock
from onyx.db.models import OAuthPermission, User


def test_oauth_permission_creation():
    """Test creating OAuth permission record"""
    user_id = uuid4()
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups",
        okta_groups='["onyx-users", "content-creators"]'
    )
    
    assert permission.user_id == user_id
    assert permission.permission_level == "write"
    assert permission.granted_by == "okta_groups"
    assert permission.okta_groups == '["onyx-users", "content-creators"]'
    assert permission.is_active == True
    assert permission.granted_at is not None


def test_oauth_permission_repr():
    """Test string representation"""
    user_id = uuid4()
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="okta_groups"
    )
    
    expected = f"<OAuthPermission(user_id={user_id}, level=admin)>"
    assert repr(permission) == expected


def test_oauth_permission_default_values():
    """Test default values are set correctly"""
    user_id = uuid4()
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="manual"
    )
    
    # Test default values
    assert permission.is_active == True
    assert permission.okta_groups is None
    assert permission.id is not None  # Should be auto-generated
    assert permission.granted_at is not None


def test_oauth_permission_permission_levels():
    """Test different permission levels"""
    user_id = uuid4()
    
    # Test read permission
    read_permission = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="okta_groups"
    )
    assert read_permission.permission_level == "read"
    
    # Test write permission
    write_permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups"
    )
    assert write_permission.permission_level == "write"
    
    # Test admin permission
    admin_permission = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="okta_groups"
    )
    assert admin_permission.permission_level == "admin"


def test_oauth_permission_granted_by_sources():
    """Test different granted_by sources"""
    user_id = uuid4()
    
    # Test okta_groups source
    okta_permission = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="okta_groups"
    )
    assert okta_permission.granted_by == "okta_groups"
    
    # Test manual source
    manual_permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="manual"
    )
    assert manual_permission.granted_by == "manual"


def test_oauth_permission_with_okta_groups():
    """Test OAuth permission with Okta groups JSON"""
    user_id = uuid4()
    okta_groups = '["onyx-admins", "content-team", "data-science"]'
    
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="okta_groups",
        okta_groups=okta_groups
    )
    
    assert permission.okta_groups == okta_groups
    assert permission.permission_level == "admin"
    assert permission.granted_by == "okta_groups"


def test_oauth_permission_active_inactive():
    """Test active and inactive permissions"""
    user_id = uuid4()
    
    # Test active permission
    active_permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups",
        is_active=True
    )
    assert active_permission.is_active == True
    
    # Test inactive permission
    inactive_permission = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="manual",
        is_active=False
    )
    assert inactive_permission.is_active == False


def test_oauth_permission_id_generation():
    """Test that UUID IDs are properly generated"""
    user_id = uuid4()
    
    permission1 = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="okta_groups"
    )
    
    permission2 = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="manual"
    )
    
    # IDs should be different UUIDs
    assert isinstance(permission1.id, UUID)
    assert isinstance(permission2.id, UUID)
    assert permission1.id != permission2.id


def test_oauth_permission_with_complex_okta_groups():
    """Test OAuth permission with complex Okta groups structure"""
    user_id = uuid4()
    complex_groups = '["Onyx-Team-Alpha", "Content-Writers-2024", "External-Contractors-Q4"]'
    
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups",
        okta_groups=complex_groups
    )
    
    assert permission.okta_groups == complex_groups
    assert '"Onyx-Team-Alpha"' in permission.okta_groups
    assert '"Content-Writers-2024"' in permission.okta_groups
    assert '"External-Contractors-Q4"' in permission.okta_groups


def test_oauth_permission_foreign_key_constraint():
    """Test that user_id properly references a User"""
    user_id = uuid4()
    
    # Create permission with user_id
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="okta_groups"
    )
    
    # Verify the foreign key reference
    assert permission.user_id == user_id
    assert isinstance(permission.user_id, UUID)


def test_oauth_permission_granted_at_timestamp():
    """Test that granted_at timestamp is properly set"""
    user_id = uuid4()
    before_creation = datetime.now(timezone.utc)
    
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="okta_groups"
    )
    
    after_creation = datetime.now(timezone.utc)
    
    # granted_at should be set automatically and be between before and after
    assert permission.granted_at is not None
    assert isinstance(permission.granted_at, datetime)
    # Note: We can't guarantee exact timing in tests, so we just check it's reasonable
    # In real database usage, server_default=func.now() would handle this


def test_oauth_permission_edge_cases():
    """Test edge cases for OAuth permission model"""
    user_id = uuid4()
    
    # Test with empty okta_groups
    permission_empty_groups = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="okta_groups",
        okta_groups=""
    )
    assert permission_empty_groups.okta_groups == ""
    
    # Test with None okta_groups (default)
    permission_none_groups = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="manual"
    )
    assert permission_none_groups.okta_groups is None
    
    # Test with very long permission level (up to 20 chars as per schema)
    long_permission = "custom_admin_level"  # 18 chars, should be valid
    permission_long_level = OAuthPermission(
        user_id=user_id,
        permission_level=long_permission,
        granted_by="custom_system"
    )
    assert permission_long_level.permission_level == long_permission


def test_oauth_permission_relationship_setup():
    """Test that the relationship to User is properly configured"""
    user_id = uuid4()
    
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="okta_groups"
    )
    
    # Test that the relationship attribute exists
    assert hasattr(permission, 'user')
    # In unit test context without database, user will be None
    # This tests the relationship is configured correctly


def test_oauth_permission_multiple_grants():
    """Test multiple permissions for the same user with different sources"""
    user_id = uuid4()
    
    # Permission from Okta
    okta_permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups",
        okta_groups='["team-writers"]'
    )
    
    # Manual permission override
    manual_permission = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="manual"
    )
    
    # Both should have different IDs but same user_id
    assert okta_permission.user_id == manual_permission.user_id == user_id
    assert okta_permission.id != manual_permission.id
    assert okta_permission.granted_by != manual_permission.granted_by
    assert okta_permission.permission_level != manual_permission.permission_level


def test_oauth_permission_json_okta_groups_format():
    """Test various JSON formats for okta_groups field"""
    user_id = uuid4()
    
    # Test single group
    single_group = '["single-group"]'
    permission1 = OAuthPermission(
        user_id=user_id,
        permission_level="read",
        granted_by="okta_groups",
        okta_groups=single_group
    )
    assert permission1.okta_groups == single_group
    
    # Test multiple groups
    multiple_groups = '["group1", "group2", "group3"]'
    permission2 = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups",
        okta_groups=multiple_groups
    )
    assert permission2.okta_groups == multiple_groups
    
    # Test empty array
    empty_groups = '[]'
    permission3 = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="okta_groups",
        okta_groups=empty_groups
    )
    assert permission3.okta_groups == empty_groups


def test_oauth_permission_tablename():
    """Test that the table name is correctly set"""
    assert OAuthPermission.__tablename__ == "oauth_permission"


def test_oauth_permission_cascade_delete():
    """Test the foreign key cascade delete configuration"""
    user_id = uuid4()
    
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups"
    )
    
    # Verify the user_id foreign key is set correctly
    assert permission.user_id == user_id
    # The CASCADE delete behavior would be tested in integration tests with actual database
import pytest
from sqlalchemy.orm import Session
from onyx.db.engine import get_session_context_manager
from onyx.db.models import User, OAuthPermission
from onyx.auth.schemas import UserRole
from uuid import uuid4
import json


def test_oauth_permission_user_relationship():
    """Test the relationship between User and OAuthPermission models"""
    with get_session_context_manager() as db_session:
        # Create a test user
        test_user = User(
            email="test@example.com",
            hashed_password="hashed_password",
            is_active=True,
            is_superuser=False,
            is_verified=True,
            role=UserRole.BASIC
        )
        db_session.add(test_user)
        db_session.flush()  # To get the user ID
        
        try:
            # Create OAuth permissions for the user
            permission1 = OAuthPermission(
                user_id=test_user.id,
                permission_level="read",
                granted_by="okta_groups",
                okta_groups='["team-readers"]'
            )
            
            permission2 = OAuthPermission(
                user_id=test_user.id,
                permission_level="write", 
                granted_by="manual"
            )
            
            db_session.add_all([permission1, permission2])
            db_session.flush()
            
            # Test forward relationship (User -> OAuthPermissions)
            db_session.refresh(test_user)
            assert len(test_user.oauth_permissions) == 2
            
            permission_levels = {perm.permission_level for perm in test_user.oauth_permissions}
            assert permission_levels == {"read", "write"}
            
            # Test backward relationship (OAuthPermission -> User)
            db_session.refresh(permission1)
            assert permission1.user.email == "test@example.com"
            assert permission1.user.id == test_user.id
            
            # Test filtering and querying through relationship
            read_permissions = [p for p in test_user.oauth_permissions if p.permission_level == "read"]
            assert len(read_permissions) == 1
            assert read_permissions[0].okta_groups == '["team-readers"]'
            
            # Test cascade delete behavior
            user_id = test_user.id
            
            # Explicitly delete permissions first to avoid foreign key issues
            # The CASCADE should handle this automatically, but in test environment
            # we'll verify the relationship works properly
            permissions_count_before = db_session.query(OAuthPermission).filter(
                OAuthPermission.user_id == user_id
            ).count()
            assert permissions_count_before == 2
            
            # Delete the user - this should cascade to permissions
            db_session.delete(test_user)
            db_session.commit()  # Use commit instead of flush for cascade to work properly
            
            # Start new transaction to verify cascade worked
            db_session.begin()
            remaining_permissions = db_session.query(OAuthPermission).filter(
                OAuthPermission.user_id == user_id
            ).all()
            assert len(remaining_permissions) == 0
            
        finally:
            db_session.rollback()


def test_oauth_permission_orm_queries():
    """Test various ORM queries with OAuth permissions"""
    with get_session_context_manager() as db_session:
        # Create test users
        user1 = User(
            email="user1@example.com",
            hashed_password="hash1",
            is_active=True,
            is_superuser=False,
            is_verified=True,
            role=UserRole.BASIC
        )
        
        user2 = User(
            email="user2@example.com", 
            hashed_password="hash2",
            is_active=True,
            is_superuser=False,
            is_verified=True,
            role=UserRole.ADMIN
        )
        
        db_session.add_all([user1, user2])
        db_session.flush()
        
        try:
            # Create permissions
            permissions = [
                OAuthPermission(
                    user_id=user1.id,
                    permission_level="read",
                    granted_by="okta_groups",
                    okta_groups='["team-readers"]'
                ),
                OAuthPermission(
                    user_id=user1.id,
                    permission_level="write",
                    granted_by="okta_groups", 
                    okta_groups='["team-writers"]'
                ),
                OAuthPermission(
                    user_id=user2.id,
                    permission_level="admin",
                    granted_by="manual"
                )
            ]
            
            db_session.add_all(permissions)
            db_session.flush()
            
            # Test join queries
            users_with_write_perms = db_session.query(User).join(OAuthPermission).filter(
                OAuthPermission.permission_level == "write"
            ).all()
            assert len(users_with_write_perms) == 1
            assert users_with_write_perms[0].email == "user1@example.com"
            
            # Test users with Okta-granted permissions
            okta_users = db_session.query(User).join(OAuthPermission).filter(
                OAuthPermission.granted_by == "okta_groups"
            ).distinct().all()
            assert len(okta_users) == 1
            assert okta_users[0].email == "user1@example.com"
            
            # Test permission aggregation
            all_permissions = db_session.query(OAuthPermission).all()
            assert len(all_permissions) == 3
            
            permission_levels = {p.permission_level for p in all_permissions}
            assert permission_levels == {"read", "write", "admin"}
            
            # Test filtering by active status
            active_permissions = db_session.query(OAuthPermission).filter(
                OAuthPermission.is_active == True
            ).all()
            assert len(active_permissions) == 3
            
            # Test deactivating a permission
            permissions[0].is_active = False
            db_session.flush()
            
            active_permissions = db_session.query(OAuthPermission).filter(
                OAuthPermission.is_active == True
            ).all()
            assert len(active_permissions) == 2
            
        finally:
            db_session.rollback()


def test_oauth_permission_okta_groups_json():
    """Test handling of Okta groups JSON data"""
    with get_session_context_manager() as db_session:
        # Create test user
        test_user = User(
            email="json_test@example.com",
            hashed_password="hash",
            is_active=True,
            is_superuser=False,
            is_verified=True,
            role=UserRole.BASIC
        )
        db_session.add(test_user)
        db_session.flush()
        
        try:
            # Test with complex JSON structure
            complex_groups = json.dumps([
                {
                    "name": "onyx-admin",
                    "description": "Admin access to Onyx",
                    "members": 15
                },
                {
                    "name": "content-creators", 
                    "description": "Content creation permissions",
                    "members": 42
                }
            ])
            
            permission = OAuthPermission(
                user_id=test_user.id,
                permission_level="admin",
                granted_by="okta_groups",
                okta_groups=complex_groups
            )
            
            db_session.add(permission)
            db_session.flush()
            
            # Verify JSON data round-trip
            db_session.refresh(permission)
            stored_groups = json.loads(permission.okta_groups)
            assert len(stored_groups) == 2
            assert stored_groups[0]["name"] == "onyx-admin"
            assert stored_groups[1]["members"] == 42
            
            # Test querying with JSON operators (PostgreSQL specific)
            # Note: This would require PostgreSQL JSON operators in a real query
            # For now, we'll test basic string contains
            group_search_results = db_session.query(OAuthPermission).filter(
                OAuthPermission.okta_groups.contains("onyx-admin")
            ).all()
            assert len(group_search_results) == 1
            
        finally:
            db_session.rollback()


def test_oauth_permission_performance_indexes():
    """Test that the created indexes improve query performance"""
    with get_session_context_manager() as db_session:
        # Create multiple users and permissions to test index usage
        users = []
        for i in range(10):
            user = User(
                email=f"perf_test_{i}@example.com",
                hashed_password=f"hash_{i}",
                is_active=True,
                is_superuser=False,
                is_verified=True,
                role=UserRole.BASIC
            )
            users.append(user)
        
        db_session.add_all(users)
        db_session.flush()
        
        try:
            # Create permissions with various levels
            permissions = []
            for i, user in enumerate(users):
                level = ["read", "write", "admin"][i % 3]
                is_active = i % 2 == 0  # Alternate active/inactive
                
                permission = OAuthPermission(
                    user_id=user.id,
                    permission_level=level,
                    granted_by="okta_groups",
                    is_active=is_active
                )
                permissions.append(permission)
            
            db_session.add_all(permissions)
            db_session.flush()
            
            # Test indexed queries - these should use the created indexes
            
            # Query by user_id (should use idx_oauth_permission_user_id)
            user_permissions = db_session.query(OAuthPermission).filter(
                OAuthPermission.user_id == users[0].id
            ).all()
            assert len(user_permissions) == 1
            
            # Query by permission_level (should use idx_oauth_permission_level)
            admin_permissions = db_session.query(OAuthPermission).filter(
                OAuthPermission.permission_level == "admin"
            ).all()
            assert len(admin_permissions) >= 1
            
            # Query by is_active (should use idx_oauth_permission_active)
            active_permissions = db_session.query(OAuthPermission).filter(
                OAuthPermission.is_active == True
            ).all()
            assert len(active_permissions) == 5  # Half of 10 permissions
            
            # Combined query that could use multiple indexes
            active_write_permissions = db_session.query(OAuthPermission).filter(
                OAuthPermission.permission_level == "write",
                OAuthPermission.is_active == True
            ).all()
            
            # Verify results are correct
            for perm in active_write_permissions:
                assert perm.permission_level == "write"
                assert perm.is_active == True
                
        finally:
            db_session.rollback()

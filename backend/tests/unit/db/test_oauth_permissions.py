"""
Unit tests for OAuth permission database operations.

This module provides comprehensive testing for all OAuth permission
database operations including CRUD operations, bulk operations,
and utility functions.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime, timedelta
from typing import List, Dict, Any

from onyx.db.oauth_permissions import (
    get_user_oauth_permission,
    get_user_permission_level,
    update_user_oauth_permission,
    deactivate_user_oauth_permissions,
    get_users_by_permission_level,
    get_permission_summary,
    bulk_update_permissions,
    cleanup_inactive_permissions,
    user_has_permission,
    get_user_okta_groups,
    InvalidPermissionLevelError,
    PermissionNotFoundError,
    OAuthPermissionError,
    VALID_PERMISSION_LEVELS
)
from onyx.db.oauth_utils import (
    check_multiple_users_permissions,
    get_permission_stats
)


class TestOAuthPermissionBasics:
    """Test basic OAuth permission operations."""
    
    def test_valid_permission_levels(self):
        """Test that valid permission levels are correctly defined."""
        expected_levels = {"read", "write", "admin"}
        assert VALID_PERMISSION_LEVELS == expected_levels
    
    def test_exception_hierarchy(self):
        """Test that exception classes have proper hierarchy."""
        assert issubclass(PermissionNotFoundError, OAuthPermissionError)
        assert issubclass(InvalidPermissionLevelError, OAuthPermissionError)
        assert issubclass(OAuthPermissionError, Exception)


class TestGetUserOAuthPermission:
    """Test get_user_oauth_permission function."""
    
    @pytest.fixture
    def mock_permission(self):
        """Create a mock permission object."""
        permission = MagicMock()
        permission.user_id = uuid4()
        permission.permission_level = "admin"
        permission.okta_groups = "group1,group2"
        permission.granted_at = datetime.utcnow()
        permission.is_active = True
        return permission
    
    @pytest.mark.asyncio
    async def test_get_user_oauth_permission_found(self, mock_permission):
        """Test getting user permission when permission exists."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock the database query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = mock_permission
            mock_db_session.execute.return_value = mock_result
            
            result = await get_user_oauth_permission(user_id)
            
            assert result == mock_permission
            mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_oauth_permission_not_found(self):
        """Test getting user permission when no permission exists."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock no result found
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_db_session.execute.return_value = mock_result
            
            result = await get_user_oauth_permission(user_id)
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_oauth_permission_with_session(self, mock_permission):
        """Test getting user permission with provided session."""
        user_id = uuid4()
        mock_session = AsyncMock()
        
        # Mock the database query result
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_permission
        mock_session.execute.return_value = mock_result
        
        result = await get_user_oauth_permission(user_id, session=mock_session)
        
        assert result == mock_permission
        mock_session.execute.assert_called_once()


class TestGetUserPermissionLevel:
    """Test get_user_permission_level function."""
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_valid(self):
        """Test getting valid permission level."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_permission = MagicMock()
            mock_permission.permission_level = "write"
            mock_get.return_value = mock_permission
            
            result = await get_user_permission_level(user_id)
            
            assert result == "write"
            mock_get.assert_called_once_with(user_id, None)
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_invalid_defaults_to_read(self):
        """Test that invalid permission level defaults to read."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_permission = MagicMock()
            mock_permission.permission_level = "invalid_level"
            mock_get.return_value = mock_permission
            
            result = await get_user_permission_level(user_id)
            
            assert result == "read"
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_no_permission_defaults_to_read(self):
        """Test that no permission defaults to read."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_get.return_value = None
            
            result = await get_user_permission_level(user_id)
            
            assert result == "read"


class TestUpdateUserOAuthPermission:
    """Test update_user_oauth_permission function."""
    
    @pytest.mark.asyncio
    async def test_update_user_oauth_permission_valid(self):
        """Test updating user permission with valid data."""
        user_id = uuid4()
        permission_level = "admin"
        okta_groups = ["group1", "group2"]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session, \
             patch('onyx.db.oauth_permissions.deactivate_user_oauth_permissions') as mock_deactivate:
            
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            mock_new_permission = MagicMock()
            mock_new_permission.user_id = user_id
            mock_new_permission.permission_level = permission_level
            
            result = await update_user_oauth_permission(
                user_id, permission_level, okta_groups
            )
            
            mock_deactivate.assert_called_once_with(user_id, mock_db_session)
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_user_oauth_permission_invalid_level(self):
        """Test updating user permission with invalid permission level."""
        user_id = uuid4()
        invalid_level = "invalid"
        okta_groups = ["group1"]
        
        with pytest.raises(InvalidPermissionLevelError):
            await update_user_oauth_permission(user_id, invalid_level, okta_groups)
    
    @pytest.mark.asyncio
    async def test_update_user_oauth_permission_empty_okta_groups(self):
        """Test updating user permission with empty okta groups."""
        user_id = uuid4()
        permission_level = "read"
        okta_groups = []
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session, \
             patch('onyx.db.oauth_permissions.deactivate_user_oauth_permissions'):
            
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            await update_user_oauth_permission(user_id, permission_level, okta_groups)
            
            # Verify that the session operations were called
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()


class TestDeactivateUserOAuthPermissions:
    """Test deactivate_user_oauth_permissions function."""
    
    @pytest.mark.asyncio
    async def test_deactivate_user_oauth_permissions(self):
        """Test deactivating user permissions."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            mock_result = MagicMock()
            mock_result.rowcount = 2
            mock_db_session.execute.return_value = mock_result
            
            await deactivate_user_oauth_permissions(user_id)
            
            mock_db_session.execute.assert_called_once()
            mock_db_session.commit.assert_called_once()


class TestGetUsersByPermissionLevel:
    """Test get_users_by_permission_level function."""
    
    @pytest.mark.asyncio
    async def test_get_users_by_permission_level_valid(self):
        """Test getting users by valid permission level."""
        permission_level = "admin"
        expected_user_ids = [uuid4(), uuid4()]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            mock_result = MagicMock()
            mock_result.fetchall.return_value = [(uid,) for uid in expected_user_ids]
            mock_db_session.execute.return_value = mock_result
            
            result = await get_users_by_permission_level(permission_level)
            
            assert result == expected_user_ids
    
    @pytest.mark.asyncio
    async def test_get_users_by_permission_level_invalid(self):
        """Test getting users by invalid permission level."""
        invalid_level = "invalid"
        
        with pytest.raises(InvalidPermissionLevelError):
            await get_users_by_permission_level(invalid_level)


class TestUserHasPermission:
    """Test user_has_permission function."""
    
    @pytest.mark.asyncio
    async def test_user_has_permission_sufficient(self):
        """Test user has sufficient permission."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
            mock_get.return_value = "admin"
            
            # Admin should have write permission
            result = await user_has_permission(user_id, "write")
            assert result is True
            
            # Admin should have read permission
            result = await user_has_permission(user_id, "read")
            assert result is True
            
            # Admin should have admin permission
            result = await user_has_permission(user_id, "admin")
            assert result is True
    
    @pytest.mark.asyncio
    async def test_user_has_permission_insufficient(self):
        """Test user has insufficient permission."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
            mock_get.return_value = "read"
            
            # Read user should not have write permission
            result = await user_has_permission(user_id, "write")
            assert result is False
            
            # Read user should not have admin permission
            result = await user_has_permission(user_id, "admin")
            assert result is False
    
    @pytest.mark.asyncio
    async def test_user_has_permission_invalid_required_level(self):
        """Test user permission check with invalid required level."""
        user_id = uuid4()
        
        result = await user_has_permission(user_id, "invalid")
        assert result is False


class TestGetUserOktaGroups:
    """Test get_user_okta_groups function."""
    
    @pytest.mark.asyncio
    async def test_get_user_okta_groups_with_groups(self):
        """Test getting user okta groups when groups exist."""
        user_id = uuid4()
        expected_groups = ["group1", "group2", "group3"]
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_permission = MagicMock()
            mock_permission.okta_groups = ",".join(expected_groups)
            mock_get.return_value = mock_permission
            
            result = await get_user_okta_groups(user_id)
            
            assert result == expected_groups
    
    @pytest.mark.asyncio
    async def test_get_user_okta_groups_no_permission(self):
        """Test getting user okta groups when no permission exists."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_get.return_value = None
            
            result = await get_user_okta_groups(user_id)
            
            assert result == []
    
    @pytest.mark.asyncio
    async def test_get_user_okta_groups_no_groups(self):
        """Test getting user okta groups when permission has no groups."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_permission = MagicMock()
            mock_permission.okta_groups = None
            mock_get.return_value = mock_permission
            
            result = await get_user_okta_groups(user_id)
            
            assert result == []


class TestBulkOperations:
    """Test bulk operation functions."""
    
    @pytest.mark.asyncio
    async def test_bulk_update_permissions_valid(self):
        """Test bulk updating permissions with valid data."""
        updates = [
            {
                "user_id": uuid4(),
                "permission_level": "admin",
                "okta_groups": ["group1"],
                "granted_by": "okta_groups"
            },
            {
                "user_id": uuid4(),
                "permission_level": "write",
                "okta_groups": ["group2"]
            }
        ]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session, \
             patch('onyx.db.oauth_permissions.update_user_oauth_permission') as mock_update:
            
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            mock_permission = MagicMock()
            mock_update.return_value = mock_permission
            
            result = await bulk_update_permissions(updates)
            
            assert len(result) == 2
            assert mock_update.call_count == 2
    
    @pytest.mark.asyncio
    async def test_bulk_update_permissions_mixed_validity(self):
        """Test bulk updating permissions with mix of valid and invalid data."""
        updates = [
            {
                "user_id": uuid4(),
                "permission_level": "admin",
                "okta_groups": ["group1"]
            },
            {
                "user_id": uuid4(),
                "permission_level": "invalid",  # Invalid level
                "okta_groups": ["group2"]
            }
        ]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session, \
             patch('onyx.db.oauth_permissions.update_user_oauth_permission') as mock_update:
            
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            mock_permission = MagicMock()
            mock_update.return_value = mock_permission
            
            result = await bulk_update_permissions(updates)
            
            # Only valid update should be processed
            assert len(result) == 1
            assert mock_update.call_count == 1


class TestCleanupOperations:
    """Test cleanup operation functions."""
    
    @pytest.mark.asyncio
    async def test_cleanup_inactive_permissions(self):
        """Test cleaning up inactive permissions."""
        days_old = 30
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            mock_result = MagicMock()
            mock_result.rowcount = 5
            mock_db_session.execute.return_value = mock_result
            
            result = await cleanup_inactive_permissions(days_old)
            
            assert result == 5
            mock_db_session.execute.assert_called_once()
            mock_db_session.commit.assert_called_once()


class TestUtilityFunctions:
    """Test utility functions from oauth_utils module."""
    
    @pytest.mark.asyncio
    async def test_check_multiple_users_permissions(self):
        """Test checking permissions for multiple users."""
        user_ids = [uuid4(), uuid4(), uuid4()]
        required_level = "write"
        
        with patch('onyx.db.oauth_utils.user_has_permission') as mock_check:
            mock_check.side_effect = [True, False, True]
            
            result = await check_multiple_users_permissions(user_ids, required_level)
            
            assert len(result) == 3
            assert result[user_ids[0]] is True
            assert result[user_ids[1]] is False
            assert result[user_ids[2]] is True
    
    @pytest.mark.asyncio
    async def test_check_multiple_users_permissions_invalid_level(self):
        """Test checking permissions with invalid required level."""
        user_ids = [uuid4(), uuid4()]
        invalid_level = "invalid"
        
        result = await check_multiple_users_permissions(user_ids, invalid_level)
        
        assert len(result) == 2
        assert all(not has_permission for has_permission in result.values())
    
    @pytest.mark.asyncio
    async def test_get_permission_stats(self):
        """Test getting permission statistics."""
        mock_summary = {
            "read": 10,
            "write": 5,
            "admin": 2,
            "no_oauth_permission": 3
        }
        
        with patch('onyx.db.oauth_utils.get_permission_summary') as mock_summary_func:
            mock_summary_func.return_value = mock_summary
            
            result = await get_permission_stats()
            
            assert result["total_users"] == 20
            assert result["oauth_enabled_users"] == 17
            assert result["oauth_percentage"] == 85.0
            assert result["permission_distribution"] == mock_summary
    
    @pytest.mark.asyncio
    async def test_get_users_by_multiple_permission_levels(self):
        """Test getting users for multiple permission levels."""
        permission_levels = ["read", "write"]
        
        with patch('onyx.db.oauth_utils.get_users_by_permission_level') as mock_get:
            mock_get.side_effect = [
                [uuid4(), uuid4()],  # read users
                [uuid4()]            # write users
            ]
            
            result = await get_users_by_multiple_permission_levels(permission_levels)
            
            assert len(result) == 2
            assert len(result["read"]) == 2
            assert len(result["write"]) == 1
    
    @pytest.mark.asyncio
    async def test_validate_permission_hierarchy(self):
        """Test validating permission hierarchy."""
        user_permissions = {
            uuid4(): "read",
            uuid4(): "write", 
            uuid4(): "admin",
            uuid4(): "invalid"
        }
        
        result = await validate_permission_hierarchy(user_permissions)
        
        assert result["total_users_checked"] == 4
        assert result["valid_permissions"] == 3
        assert result["invalid_count"] == 1
        assert "hierarchy_analysis" in result
    
    @pytest.mark.asyncio
    async def test_find_permission_conflicts(self):
        """Test finding permission conflicts."""
        user_permissions = {uuid4(): "read" for _ in range(5)}
        expected_permissions = {list(user_permissions.keys())[0]: "write"}
        
        result = await find_permission_conflicts(user_permissions, expected_permissions)
        
        assert len(result) == 1
        assert result[0]["conflict_type"] == "permission_mismatch"
    
    @pytest.mark.asyncio
    async def test_find_permission_conflicts_too_many_admins(self):
        """Test finding conflicts with too many admin users."""
        # Create 11 admin users (exceeds limit of 10)
        user_permissions = {uuid4(): "admin" for _ in range(11)}
        
        result = await find_permission_conflicts(user_permissions)
        
        conflicts = [c for c in result if c.get("conflict_type") == "too_many_admins"]
        assert len(conflicts) == 1
        assert conflicts[0]["admin_count"] == 11
    
    @pytest.mark.asyncio
    async def test_generate_permission_audit_report(self):
        """Test generating comprehensive audit report."""
        with patch('onyx.db.oauth_utils.get_permission_stats') as mock_stats, \
             patch('onyx.db.oauth_utils.get_users_by_multiple_permission_levels') as mock_users, \
             patch('onyx.db.oauth_utils.validate_permission_hierarchy') as mock_validate, \
             patch('onyx.db.oauth_utils.find_permission_conflicts') as mock_conflicts:
            
            mock_stats.return_value = {"oauth_percentage": 75}
            mock_users.return_value = {"read": [uuid4()], "write": [uuid4()], "admin": [uuid4()]}
            mock_validate.return_value = {"invalid_count": 0}
            mock_conflicts.return_value = []
            
            result = await generate_permission_audit_report()
            
            assert "report_metadata" in result
            assert "permission_statistics" in result
            assert "users_by_level" in result
            assert "validation_results" in result
            assert "conflicts" in result
            assert "recommendations" in result


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple operations."""
    
    @pytest.mark.asyncio
    async def test_user_permission_lifecycle(self):
        """Test complete user permission lifecycle."""
        user_id = uuid4()
        
        # Mock the database operations
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session, \
             patch('onyx.db.oauth_permissions.deactivate_user_oauth_permissions') as mock_deactivate:
            
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # 1. Create initial permission
            await update_user_oauth_permission(user_id, "read", ["group1"])
            
            # 2. Update to higher permission
            await update_user_oauth_permission(user_id, "write", ["group1", "group2"])
            
            # 3. Update to admin permission  
            await update_user_oauth_permission(user_id, "admin", ["group1", "group2", "admin_group"])
            
            # 4. Deactivate permissions
            await deactivate_user_oauth_permissions(user_id)
            
            # Verify that operations were called correctly
            assert mock_db_session.add.call_count == 3
            assert mock_db_session.commit.call_count == 3
            assert mock_deactivate.call_count == 4  # Called once per update_user_oauth_permission + final call
    
    @pytest.mark.asyncio
    async def test_bulk_operation_with_validation(self):
        """Test bulk operations with validation."""
        updates = [
            {"user_id": uuid4(), "permission_level": "read", "okta_groups": ["group1"]},
            {"user_id": uuid4(), "permission_level": "write", "okta_groups": ["group2"]},
            {"user_id": uuid4(), "permission_level": "admin", "okta_groups": ["admin_group"]},
            {"user_id": uuid4(), "permission_level": "invalid", "okta_groups": ["group3"]},  # Invalid
        ]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session, \
             patch('onyx.db.oauth_permissions.update_user_oauth_permission') as mock_update:
            
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            mock_update.return_value = MagicMock()
            
            # Perform bulk update
            result = await bulk_update_permissions(updates)
            
            # Should only process 3 valid updates
            assert len(result) == 3
            assert mock_update.call_count == 3


@pytest.fixture
def sample_user_ids():
    """Fixture providing sample user IDs for testing."""
    return [uuid4() for _ in range(5)]


@pytest.fixture
def sample_permission_levels():
    """Fixture providing sample permission levels."""
    return ["read", "write", "admin"]


@pytest.fixture
def sample_okta_groups():
    """Fixture providing sample Okta groups."""
    return ["engineering", "product", "admin", "sales", "marketing"]


# Performance test helpers
class TestPerformanceHelpers:
    """Helper methods for performance testing."""
    
    @staticmethod
    async def measure_operation_time(operation_func, *args, **kwargs):
        """Measure the execution time of an async operation."""
        start_time = datetime.utcnow()
        result = await operation_func(*args, **kwargs)
        end_time = datetime.utcnow()
        
        execution_time = (end_time - start_time).total_seconds() * 1000  # Convert to milliseconds
        return result, execution_time
    
    @pytest.mark.asyncio
    async def test_permission_lookup_performance_mock(self):
        """Test that permission lookup operations are fast (mocked)."""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_permission = MagicMock()
            mock_permission.permission_level = "admin"
            mock_get.return_value = mock_permission
            
            result, execution_time = await self.measure_operation_time(
                get_user_permission_level, user_id
            )
            
            # Mock should be very fast
            assert execution_time < 1.0  # Less than 1ms for mocked operation
            assert result == "admin"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])

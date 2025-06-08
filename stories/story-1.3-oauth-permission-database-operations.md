# Story 1.3: OAuth Permission Database Operations

## 📊 Story Overview

**Story ID**: 1.3  
**Priority**: P0 - Critical Foundation  
**Estimate**: 1 day  
**Sprint**: 1 (Week 1)  
**Dependencies**: Story 1.1 (Database Schema)  
**Assignee**: TBD  

## 🎯 Description

Create database operations to manage OAuth permissions. This story implements the data access layer for the OAuth permission system, providing efficient CRUD operations and optimized queries for permission checking.

## ✅ Acceptance Criteria

### Core Database Operations
- [ ] CRUD operations for `OAuthPermission` model
- [ ] Method to get user's current permission level
- [ ] Method to update/create user's OAuth permissions
- [ ] Method to deactivate expired permissions
- [ ] Unit tests for all database operations
- [ ] Performance optimized queries with proper indexing

### Query Performance
- [ ] Permission lookup queries execute in under 10ms
- [ ] Bulk operations support for multiple users
- [ ] Database connection pooling compatibility
- [ ] Proper use of indexes created in Story 1.1

### Data Integrity
- [ ] Foreign key constraints respected
- [ ] Atomic operations for permission updates
- [ ] Proper handling of concurrent updates
- [ ] Data validation for permission levels

## 🔧 Technical Implementation

### Files to Create

#### 1. Main Database Operations
**Path**: `backend/onyx/db/oauth_permissions.py`

```python
"""
Database operations for OAuth permissions management.

This module provides the data access layer for OAuth permissions,
including CRUD operations and optimized queries for permission checking.
"""
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from onyx.db.models import OAuthPermission, User
from onyx.db.engine import get_async_session

logger = logging.getLogger(__name__)


class OAuthPermissionError(Exception):
    """Base exception for OAuth permission operations"""
    pass


class PermissionNotFoundError(OAuthPermissionError):
    """Raised when a permission record is not found"""
    pass


class InvalidPermissionLevelError(OAuthPermissionError):
    """Raised when an invalid permission level is provided"""
    pass


# Valid permission levels
VALID_PERMISSION_LEVELS = {"read", "write", "admin"}


async def get_user_oauth_permission(
    user_id: UUID, 
    session: Optional[AsyncSession] = None
) -> Optional[OAuthPermission]:
    """
    Get the active OAuth permission for a user.
    
    Args:
        user_id: UUID of the user
        session: Database session (optional, will create if not provided)
        
    Returns:
        OAuthPermission object if found, None otherwise
    """
    async def _get_permission(db_session: AsyncSession) -> Optional[OAuthPermission]:
        stmt = select(OAuthPermission).where(
            and_(
                OAuthPermission.user_id == user_id,
                OAuthPermission.is_active == True
            )
        ).order_by(OAuthPermission.granted_at.desc())
        
        result = await db_session.execute(stmt)
        return result.scalar_one_or_none()
    
    if session:
        return await _get_permission(session)
    else:
        async with get_async_session() as db_session:
            return await _get_permission(db_session)


async def get_user_permission_level(
    user_id: UUID, 
    session: Optional[AsyncSession] = None
) -> str:
    """
    Get the permission level for a user, with fallback to 'read'.
    
    Args:
        user_id: UUID of the user
        session: Database session (optional)
        
    Returns:
        Permission level string ('read', 'write', or 'admin')
    """
    permission = await get_user_oauth_permission(user_id, session)
    
    if permission and permission.permission_level in VALID_PERMISSION_LEVELS:
        logger.debug(f"Found permission level '{permission.permission_level}' for user {user_id}")
        return permission.permission_level
    
    logger.debug(f"No valid permission found for user {user_id}, defaulting to 'read'")
    return "read"


async def update_user_oauth_permission(
    user_id: UUID,
    permission_level: str,
    okta_groups: List[str],
    granted_by: str = "okta_groups",
    session: Optional[AsyncSession] = None
) -> OAuthPermission:
    """
    Update or create a user's OAuth permission.
    
    Args:
        user_id: UUID of the user
        permission_level: Permission level ('read', 'write', 'admin')
        okta_groups: List of Okta groups that granted this permission
        granted_by: Source of the permission grant (default: 'okta_groups')
        session: Database session (optional)
        
    Returns:
        Created or updated OAuthPermission object
        
    Raises:
        InvalidPermissionLevelError: If permission_level is invalid
    """
    if permission_level not in VALID_PERMISSION_LEVELS:
        raise InvalidPermissionLevelError(f"Invalid permission level: {permission_level}")
    
    async def _update_permission(db_session: AsyncSession) -> OAuthPermission:
        # First, deactivate any existing permissions
        await deactivate_user_oauth_permissions(user_id, db_session)
        
        # Create new permission record
        new_permission = OAuthPermission(
            user_id=user_id,
            permission_level=permission_level,
            granted_by=granted_by,
            okta_groups=",".join(okta_groups) if okta_groups else None,
            granted_at=datetime.utcnow(),
            is_active=True
        )
        
        db_session.add(new_permission)
        await db_session.commit()
        await db_session.refresh(new_permission)
        
        logger.info(f"Updated permission for user {user_id} to '{permission_level}' with groups: {okta_groups}")
        return new_permission
    
    if session:
        return await _update_permission(session)
    else:
        async with get_async_session() as db_session:
            return await _update_permission(db_session)


async def deactivate_user_oauth_permissions(
    user_id: UUID, 
    session: Optional[AsyncSession] = None
) -> None:
    """
    Deactivate all OAuth permissions for a user.
    
    Args:
        user_id: UUID of the user
        session: Database session (optional)
    """
    async def _deactivate_permissions(db_session: AsyncSession) -> None:
        stmt = update(OAuthPermission).where(
            and_(
                OAuthPermission.user_id == user_id,
                OAuthPermission.is_active == True
            )
        ).values(is_active=False)
        
        result = await db_session.execute(stmt)
        await db_session.commit()
        
        logger.debug(f"Deactivated {result.rowcount} permissions for user {user_id}")
    
    if session:
        await _deactivate_permissions(session)
    else:
        async with get_async_session() as db_session:
            await _deactivate_permissions(db_session)


async def get_users_by_permission_level(
    permission_level: str, 
    session: Optional[AsyncSession] = None
) -> List[UUID]:
    """
    Get all users with a specific permission level.
    
    Args:
        permission_level: Permission level to search for
        session: Database session (optional)
        
    Returns:
        List of user UUIDs with the specified permission level
        
    Raises:
        InvalidPermissionLevelError: If permission_level is invalid
    """
    if permission_level not in VALID_PERMISSION_LEVELS:
        raise InvalidPermissionLevelError(f"Invalid permission level: {permission_level}")
    
    async def _get_users(db_session: AsyncSession) -> List[UUID]:
        stmt = select(OAuthPermission.user_id).where(
            and_(
                OAuthPermission.permission_level == permission_level,
                OAuthPermission.is_active == True
            )
        ).distinct()
        
        result = await db_session.execute(stmt)
        user_ids = [row[0] for row in result.fetchall()]
        
        logger.debug(f"Found {len(user_ids)} users with permission level '{permission_level}'")
        return user_ids
    
    if session:
        return await _get_users(session)
    else:
        async with get_async_session() as db_session:
            return await _get_users(db_session)


async def get_permission_summary() -> Dict[str, int]:
    """
    Get a summary of permission distribution across all users.
    
    Returns:
        Dictionary with permission levels as keys and user counts as values
    """
    async with get_async_session() as session:
        summary = {}
        
        for level in VALID_PERMISSION_LEVELS:
            users = await get_users_by_permission_level(level, session)
            summary[level] = len(users)
        
        # Also count users with no OAuth permissions
        stmt = select(User.id).where(
            ~User.id.in_(
                select(OAuthPermission.user_id).where(
                    OAuthPermission.is_active == True
                )
            )
        )
        result = await session.execute(stmt)
        summary["no_oauth_permission"] = len(result.fetchall())
        
        logger.info(f"Permission summary: {summary}")
        return summary


async def bulk_update_permissions(
    permission_updates: List[Dict[str, Any]], 
    session: Optional[AsyncSession] = None
) -> List[OAuthPermission]:
    """
    Bulk update permissions for multiple users.
    
    Args:
        permission_updates: List of dicts with keys: user_id, permission_level, okta_groups
        session: Database session (optional)
        
    Returns:
        List of created/updated OAuthPermission objects
    """
    async def _bulk_update(db_session: AsyncSession) -> List[OAuthPermission]:
        updated_permissions = []
        
        for update in permission_updates:
            user_id = update["user_id"]
            permission_level = update["permission_level"]
            okta_groups = update.get("okta_groups", [])
            granted_by = update.get("granted_by", "okta_groups")
            
            # Validate permission level
            if permission_level not in VALID_PERMISSION_LEVELS:
                logger.warning(f"Skipping invalid permission level '{permission_level}' for user {user_id}")
                continue
            
            try:
                permission = await update_user_oauth_permission(
                    user_id=user_id,
                    permission_level=permission_level,
                    okta_groups=okta_groups,
                    granted_by=granted_by,
                    session=db_session
                )
                updated_permissions.append(permission)
            except Exception as e:
                logger.error(f"Failed to update permission for user {user_id}: {str(e)}")
                continue
        
        logger.info(f"Bulk updated {len(updated_permissions)} permissions")
        return updated_permissions
    
    if session:
        return await _bulk_update(session)
    else:
        async with get_async_session() as db_session:
            return await _bulk_update(db_session)


async def cleanup_inactive_permissions(days_old: int = 30) -> int:
    """
    Clean up old inactive permission records.
    
    Args:
        days_old: Delete inactive permissions older than this many days
        
    Returns:
        Number of deleted records
    """
    from datetime import timedelta
    
    cutoff_date = datetime.utcnow() - timedelta(days=days_old)
    
    async with get_async_session() as session:
        stmt = delete(OAuthPermission).where(
            and_(
                OAuthPermission.is_active == False,
                OAuthPermission.granted_at < cutoff_date
            )
        )
        
        result = await session.execute(stmt)
        await session.commit()
        
        deleted_count = result.rowcount
        logger.info(f"Cleaned up {deleted_count} inactive permission records older than {days_old} days")
        return deleted_count


# Convenience functions for common operations
async def user_has_permission(user_id: UUID, required_level: str) -> bool:
    """
    Check if user has at least the required permission level.
    
    Args:
        user_id: UUID of the user
        required_level: Required permission level
        
    Returns:
        True if user has sufficient permission, False otherwise
    """
    if required_level not in VALID_PERMISSION_LEVELS:
        return False
    
    user_level = await get_user_permission_level(user_id)
    
    # Permission hierarchy: read < write < admin
    hierarchy = {"read": 0, "write": 1, "admin": 2}
    
    return hierarchy.get(user_level, 0) >= hierarchy.get(required_level, 0)


async def get_user_okta_groups(user_id: UUID) -> List[str]:
    """
    Get the Okta groups for a user's current permission.
    
    Args:
        user_id: UUID of the user
        
    Returns:
        List of Okta group names
    """
    permission = await get_user_oauth_permission(user_id)
    
    if permission and permission.okta_groups:
        return permission.okta_groups.split(",")
    
    return []
```

#### 2. Database Utilities
**Path**: `backend/onyx/db/oauth_utils.py`

```python
"""
Utility functions for OAuth permission database operations.
"""
from typing import List, Dict, Any
from uuid import UUID

from onyx.db.oauth_permissions import (
    get_user_permission_level,
    user_has_permission,
    get_permission_summary
)


async def check_multiple_users_permissions(
    user_ids: List[UUID], 
    required_level: str
) -> Dict[UUID, bool]:
    """
    Check permissions for multiple users efficiently.
    
    Args:
        user_ids: List of user UUIDs to check
        required_level: Required permission level
        
    Returns:
        Dictionary mapping user_id to permission check result
    """
    results = {}
    
    for user_id in user_ids:
        results[user_id] = await user_has_permission(user_id, required_level)
    
    return results


async def get_permission_stats() -> Dict[str, Any]:
    """
    Get comprehensive permission statistics.
    
    Returns:
        Dictionary with permission statistics
    """
    summary = await get_permission_summary()
    
    total_users = sum(summary.values())
    oauth_users = total_users - summary.get("no_oauth_permission", 0)
    
    stats = {
        "total_users": total_users,
        "oauth_enabled_users": oauth_users,
        "oauth_percentage": (oauth_users / total_users * 100) if total_users > 0 else 0,
        "permission_distribution": summary
    }
    
    return stats
```

## 🧪 Testing Requirements

### Unit Tests
**Path**: `backend/tests/unit/db/test_oauth_permissions.py`

```python
"""
Unit tests for OAuth permission database operations.
"""
import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4, UUID
from datetime import datetime

from onyx.db.oauth_permissions import (
    get_user_oauth_permission,
    get_user_permission_level,
    update_user_oauth_permission,
    deactivate_user_oauth_permissions,
    get_users_by_permission_level,
    user_has_permission,
    InvalidPermissionLevelError
)
from onyx.db.models import OAuthPermission


class TestOAuthPermissionOperations:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_id = uuid4()
        self.mock_session = AsyncMock()
    
    @pytest.mark.asyncio
    async def test_get_user_oauth_permission_found(self):
        """Test getting existing OAuth permission"""
        # Mock database response
        mock_permission = OAuthPermission(
            id=uuid4(),
            user_id=self.user_id,
            permission_level="write",
            granted_by="okta_groups",
            okta_groups="Onyx-Writers",
            granted_at=datetime.utcnow(),
            is_active=True
        )
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_get_session:
            mock_session = AsyncMock()
            mock_get_session.return_value.__aenter__.return_value = mock_session
            mock_session.execute.return_value.scalar_one_or_none.return_value = mock_permission
            
            result = await get_user_oauth_permission(self.user_id)
            
            assert result == mock_permission
            assert result.permission_level == "write"
    
    @pytest.mark.asyncio
    async def test_get_user_oauth_permission_not_found(self):
        """Test getting non-existent OAuth permission"""
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_get_session:
            mock_session = AsyncMock()
            mock_get_session.return_value.__aenter__.return_value = mock_session
            mock_session.execute.return_value.scalar_one_or_none.return_value = None
            
            result = await get_user_oauth_permission(self.user_id)
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_with_permission(self):
        """Test getting permission level for user with OAuth permission"""
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_permission = OAuthPermission(
                user_id=self.user_id,
                permission_level="admin",
                granted_by="okta_groups",
                is_active=True
            )
            mock_get.return_value = mock_permission
            
            level = await get_user_permission_level(self.user_id)
            
            assert level == "admin"
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_fallback(self):
        """Test fallback to 'read' when no permission found"""
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_get.return_value = None
            
            level = await get_user_permission_level(self.user_id)
            
            assert level == "read"
    
    @pytest.mark.asyncio
    async def test_update_user_oauth_permission_create(self):
        """Test creating new OAuth permission"""
        okta_groups = ["Onyx-Admins", "Other-Group"]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_get_session:
            mock_session = AsyncMock()
            mock_get_session.return_value.__aenter__.return_value = mock_session
            
            with patch('onyx.db.oauth_permissions.deactivate_user_oauth_permissions') as mock_deactivate:
                result = await update_user_oauth_permission(
                    self.user_id, 
                    "admin", 
                    okta_groups
                )
                
                mock_deactivate.assert_called_once()
                mock_session.add.assert_called_once()
                mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_user_oauth_permission_invalid_level(self):
        """Test error handling for invalid permission level"""
        with pytest.raises(InvalidPermissionLevelError):
            await update_user_oauth_permission(
                self.user_id, 
                "invalid_level", 
                []
            )
    
    @pytest.mark.asyncio
    async def test_deactivate_user_oauth_permissions(self):
        """Test deactivating user permissions"""
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_get_session:
            mock_session = AsyncMock()
            mock_get_session.return_value.__aenter__.return_value = mock_session
            mock_session.execute.return_value.rowcount = 2
            
            await deactivate_user_oauth_permissions(self.user_id)
            
            mock_session.execute.assert_called_once()
            mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_users_by_permission_level(self):
        """Test getting users by permission level"""
        expected_users = [uuid4(), uuid4()]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_get_session:
            mock_session = AsyncMock()
            mock_get_session.return_value.__aenter__.return_value = mock_session
            mock_session.execute.return_value.fetchall.return_value = [(uid,) for uid in expected_users]
            
            result = await get_users_by_permission_level("admin")
            
            assert result == expected_users
    
    @pytest.mark.asyncio
    async def test_get_users_by_permission_level_invalid(self):
        """Test error handling for invalid permission level"""
        with pytest.raises(InvalidPermissionLevelError):
            await get_users_by_permission_level("invalid_level")
    
    @pytest.mark.asyncio
    async def test_user_has_permission_sufficient(self):
        """Test permission check with sufficient permission"""
        with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
            mock_get.return_value = "admin"
            
            result = await user_has_permission(self.user_id, "write")
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_user_has_permission_insufficient(self):
        """Test permission check with insufficient permission"""
        with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
            mock_get.return_value = "read"
            
            result = await user_has_permission(self.user_id, "admin")
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_user_has_permission_invalid_required(self):
        """Test permission check with invalid required level"""
        result = await user_has_permission(self.user_id, "invalid_level")
        
        assert result is False
```

### Performance Tests
**Path**: `backend/tests/performance/test_oauth_permission_performance.py`

```python
"""
Performance tests for OAuth permission operations.
"""
import pytest
import asyncio
import time
from uuid import uuid4
from unittest.mock import patch, AsyncMock

from onyx.db.oauth_permissions import get_user_permission_level


class TestOAuthPermissionPerformance:
    
    @pytest.mark.asyncio
    async def test_permission_lookup_performance(self):
        """Test that permission lookup is fast enough"""
        user_id = uuid4()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_get.return_value = None  # Fast path
            
            start_time = time.time()
            
            # Run multiple permission checks
            tasks = [get_user_permission_level(user_id) for _ in range(100)]
            results = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_time = end_time - start_time
            avg_time_ms = (total_time / 100) * 1000
            
            # Should be under 10ms per lookup
            assert avg_time_ms < 10
            assert all(result == "read" for result in results)
```

## 🚀 Deployment Checklist

### Pre-deployment
- [ ] Code review completed
- [ ] All unit tests passing
- [ ] Performance tests meet requirements (<10ms query time)
- [ ] Database indexes from Story 1.1 are in place
- [ ] Integration tests with database schema working

### Deployment Steps
1. [ ] Deploy database operations module
2. [ ] Verify database connectivity
3. [ ] Test basic CRUD operations
4. [ ] Monitor query performance
5. [ ] Verify proper index usage

### Post-deployment Verification
- [ ] All database operations work correctly
- [ ] Query performance meets requirements
- [ ] No database connection issues
- [ ] Proper error handling working
- [ ] Memory usage within acceptable limits

### Rollback Plan
If issues occur:
1. Remove new database operations module
2. Revert any imports/dependencies
3. Verify existing database operations work
4. Check database connection stability

## 📋 Definition of Done

- [ ] All acceptance criteria met
- [ ] Complete CRUD operations implemented
- [ ] Performance requirements met (<10ms queries)
- [ ] Comprehensive unit tests with >95% coverage
- [ ] Performance tests passing
- [ ] Error handling for all edge cases
- [ ] Database integrity maintained
- [ ] Code reviewed and approved
- [ ] Documentation added
- [ ] Deployed successfully

## 🔗 Related Stories

**Dependencies**: Story 1.1 (Database Schema for OAuth Permissions)  
**Next Stories**:
- Story 2.1: Enhanced OAuth Callback Handler (will use these operations)
- Story 2.2: Permission Retrieval Service (will build on these operations)

## 📝 Notes

- All operations are designed to be async for performance
- Proper session management with optional session parameter
- Built-in permission level validation
- Optimized queries using indexes from Story 1.1
- Comprehensive error handling with custom exceptions
- Support for bulk operations for efficiency

## 🐛 Known Risks

1. **Database Performance**: Frequent permission checks could impact database
2. **Concurrent Updates**: Race conditions in permission updates
3. **Data Integrity**: Orphaned permission records if user deletion fails
4. **Memory Usage**: Large result sets for bulk operations

## 💡 Success Metrics

- All database operations complete in under 10ms
- 100% test coverage for database operations
- Zero data integrity issues
- Memory usage stays under 100MB for typical operations
- No database connection leaks

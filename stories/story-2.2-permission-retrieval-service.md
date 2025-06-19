# Story 2.2: Permission Retrieval Service

## 📊 Story Overview

**Story ID**: 2.2  
**Priority**: P1 - High  
**Estimate**: 1 day  
**Sprint**: 2 (Week 2)  
**Dependencies**: Story 2.1 (Enhanced OAuth Callback Handler)  
**Assignee**: TBD  

## 🎯 Description

Create service to retrieve user's current OAuth permissions with caching. This service acts as the primary interface for checking user permissions throughout the application, with intelligent caching to optimize performance.

## ✅ Acceptance Criteria

### Core Service Functionality
- [ ] Service to get user's current permission level
- [ ] In-memory caching for 5 minutes to improve performance
- [ ] Fallback to 'read' permission if no OAuth permission found
- [ ] Method to invalidate cache when permissions change
- [ ] Unit tests for caching behavior

### Performance Requirements
- [ ] Permission lookup completes in under 5ms (cached)
- [ ] First lookup completes in under 50ms (database)
- [ ] Cache hit rate >90% in typical usage
- [ ] Memory usage <10MB for 1000+ cached users

### Reliability Features
- [ ] Graceful handling of database connection failures
- [ ] Circuit breaker pattern for database issues
- [ ] Metrics collection for monitoring
- [ ] Thread-safe cache operations

## 🔧 Technical Implementation

### Files to Create

#### 1. Permission Retrieval Service
**Path**: `backend/onyx/auth/permission_service.py`

```python
"""
Permission Retrieval Service with caching and fallback handling.

This service provides the primary interface for checking user permissions
throughout the application, with intelligent caching and reliability features.
"""
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Set
from uuid import UUID
from dataclasses import dataclass
from threading import Lock
import time

from onyx.db.oauth_permissions import get_user_permission_level
from onyx.configs.app_configs import OAUTH_PERMISSIONS_ENABLED

logger = logging.getLogger(__name__)

@dataclass
class CachedPermission:
    """Cached permission data with timestamp"""
    permission_level: str
    cached_at: datetime
    user_id: UUID

class PermissionService:
    """
    Service for retrieving and caching user OAuth permissions.
    
    This service provides:
    - Fast permission lookups with caching
    - Fallback behavior when permissions aren't found
    - Cache invalidation when permissions change
    - Metrics collection for monitoring
    """
    
    def __init__(self, cache_ttl_minutes: int = 5):
        """
        Initialize the permission service.
        
        Args:
            cache_ttl_minutes: How long to cache permissions (default: 5 minutes)
        """
        self.cache_ttl = timedelta(minutes=cache_ttl_minutes)
        self._cache: Dict[UUID, CachedPermission] = {}
        self._cache_lock = Lock()
        
        # Metrics
        self._cache_hits = 0
        self._cache_misses = 0
        self._db_errors = 0
        self._total_requests = 0
        
        logger.info(f"PermissionService initialized with {cache_ttl_minutes}m cache TTL")
    
    async def get_user_permission_level(self, user_id: UUID) -> str:
        """
        Get user's permission level with caching.
        
        Args:
            user_id: UUID of the user
            
        Returns:
            Permission level string ('read', 'write', or 'admin')
        """
        self._total_requests += 1
        
        # Check cache first
        cached_permission = self._get_from_cache(user_id)
        if cached_permission:
            self._cache_hits += 1
            logger.debug(f"Cache hit for user {user_id}: {cached_permission.permission_level}")
            return cached_permission.permission_level
        
        # Cache miss - fetch from database
        self._cache_misses += 1
        logger.debug(f"Cache miss for user {user_id}, fetching from database")
        
        try:
            # Get permission from database
            permission_level = await self._fetch_from_database(user_id)
            
            # Cache the result
            self._store_in_cache(user_id, permission_level)
            
            return permission_level
            
        except Exception as e:
            self._db_errors += 1
            logger.error(f"Failed to fetch permission for user {user_id}: {str(e)}")
            
            # Return safe fallback
            return "read"
    
    async def get_multiple_user_permissions(self, user_ids: Set[UUID]) -> Dict[UUID, str]:
        """
        Get permissions for multiple users efficiently.
        
        Args:
            user_ids: Set of user UUIDs
            
        Returns:
            Dictionary mapping user_id to permission level
        """
        results = {}
        
        # Use asyncio.gather for concurrent fetching
        tasks = [self.get_user_permission_level(user_id) for user_id in user_ids]
        permissions = await asyncio.gather(*tasks, return_exceptions=True)
        
        for user_id, permission in zip(user_ids, permissions):
            if isinstance(permission, Exception):
                logger.error(f"Error fetching permission for user {user_id}: {permission}")
                results[user_id] = "read"  # Fallback
            else:
                results[user_id] = permission
        
        return results
    
    def invalidate_user_cache(self, user_id: UUID) -> None:
        """
        Invalidate cache for a specific user.
        
        Args:
            user_id: UUID of the user to invalidate
        """
        with self._cache_lock:
            if user_id in self._cache:
                del self._cache[user_id]
                logger.debug(f"Invalidated cache for user {user_id}")
    
    def invalidate_all_cache(self) -> None:
        """Invalidate all cached permissions."""
        with self._cache_lock:
            cache_size = len(self._cache)
            self._cache.clear()
            logger.info(f"Invalidated all cache ({cache_size} entries)")
    
    def cleanup_expired_cache(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        now = datetime.utcnow()
        expired_users = []
        
        with self._cache_lock:
            for user_id, cached_perm in self._cache.items():
                if not self._is_cache_valid(cached_perm.cached_at, now):
                    expired_users.append(user_id)
            
            for user_id in expired_users:
                del self._cache[user_id]
        
        if expired_users:
            logger.debug(f"Cleaned up {len(expired_users)} expired cache entries")
        
        return len(expired_users)
    
    def get_cache_stats(self) -> Dict[str, any]:
        """
        Get cache statistics for monitoring.
        
        Returns:
            Dictionary with cache statistics
        """
        with self._cache_lock:
            cache_size = len(self._cache)
        
        hit_rate = (self._cache_hits / self._total_requests * 100) if self._total_requests > 0 else 0
        
        return {
            "cache_size": cache_size,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "hit_rate_percent": round(hit_rate, 2),
            "db_errors": self._db_errors,
            "total_requests": self._total_requests
        }
    
    def _get_from_cache(self, user_id: UUID) -> Optional[CachedPermission]:
        """Get permission from cache if valid."""
        with self._cache_lock:
            cached_perm = self._cache.get(user_id)
            
            if cached_perm and self._is_cache_valid(cached_perm.cached_at):
                return cached_perm
            elif cached_perm:
                # Remove expired entry
                del self._cache[user_id]
        
        return None
    
    def _store_in_cache(self, user_id: UUID, permission_level: str) -> None:
        """Store permission in cache."""
        cached_permission = CachedPermission(
            permission_level=permission_level,
            cached_at=datetime.utcnow(),
            user_id=user_id
        )
        
        with self._cache_lock:
            self._cache[user_id] = cached_permission
    
    def _is_cache_valid(self, cached_time: datetime, now: datetime = None) -> bool:
        """Check if cached entry is still valid."""
        if now is None:
            now = datetime.utcnow()
        return (now - cached_time) < self.cache_ttl
    
    async def _fetch_from_database(self, user_id: UUID) -> str:
        """Fetch permission from database with error handling."""
        if not OAUTH_PERMISSIONS_ENABLED:
            logger.debug("OAuth permissions disabled, returning default 'read' permission")
            return "read"
        
        try:
            permission_level = await get_user_permission_level(user_id)
            logger.debug(f"Fetched permission '{permission_level}' for user {user_id} from database")
            return permission_level
        except Exception as e:
            logger.error(f"Database error fetching permission for user {user_id}: {str(e)}")
            raise


# Global service instance
_permission_service: Optional[PermissionService] = None

def get_permission_service() -> PermissionService:
    """
    Get the global permission service instance.
    
    Returns:
        PermissionService instance
    """
    global _permission_service
    if _permission_service is None:
        _permission_service = PermissionService()
    return _permission_service

# Convenience functions for easy usage
async def get_user_permission(user_id: UUID) -> str:
    """
    Convenience function to get user permission.
    
    Args:
        user_id: UUID of the user
        
    Returns:
        Permission level string
    """
    service = get_permission_service()
    return await service.get_user_permission_level(user_id)

async def user_has_permission(user_id: UUID, required_level: str) -> bool:
    """
    Check if user has at least the required permission level.
    
    Args:
        user_id: UUID of the user
        required_level: Required permission level
        
    Returns:
        True if user has sufficient permission
    """
    if required_level not in {"read", "write", "admin"}:
        return False
    
    user_level = await get_user_permission(user_id)
    
    # Permission hierarchy
    hierarchy = {"read": 0, "write": 1, "admin": 2}
    
    return hierarchy.get(user_level, 0) >= hierarchy.get(required_level, 0)

def invalidate_user_permission_cache(user_id: UUID) -> None:
    """
    Invalidate cache for a user (convenience function).
    
    Args:
        user_id: UUID of the user
    """
    service = get_permission_service()
    service.invalidate_user_cache(user_id)
```

#### 2. Background Cache Cleanup Task
**Path**: `backend/onyx/background/permission_cache_cleanup.py`

```python
"""
Background task for permission cache cleanup.
"""
import asyncio
import logging
from datetime import datetime

from onyx.auth.permission_service import get_permission_service

logger = logging.getLogger(__name__)

async def cleanup_permission_cache():
    """Background task to clean up expired cache entries."""
    service = get_permission_service()
    
    try:
        expired_count = service.cleanup_expired_cache()
        stats = service.get_cache_stats()
        
        logger.info(
            f"Permission cache cleanup completed: "
            f"removed {expired_count} expired entries, "
            f"cache size: {stats['cache_size']}, "
            f"hit rate: {stats['hit_rate_percent']}%"
        )
        
    except Exception as e:
        logger.error(f"Error during permission cache cleanup: {str(e)}")

# Function to be called by background job scheduler
async def schedule_permission_cache_cleanup():
    """Schedule periodic cache cleanup (every 30 minutes)."""
    while True:
        await cleanup_permission_cache()
        await asyncio.sleep(30 * 60)  # 30 minutes
```

#### 3. Configuration Support
**Path**: `backend/onyx/configs/app_configs.py` (enhancement)

Add these configuration options:

```python
# Permission Service Configuration
PERMISSION_CACHE_TTL_MINUTES = env.int("PERMISSION_CACHE_TTL_MINUTES", default=5)
PERMISSION_CACHE_CLEANUP_INTERVAL_MINUTES = env.int("PERMISSION_CACHE_CLEANUP_INTERVAL_MINUTES", default=30)
PERMISSION_SERVICE_METRICS_ENABLED = env.bool("PERMISSION_SERVICE_METRICS_ENABLED", default=True)
```

## 🧪 Testing Requirements

### Unit Tests
**Path**: `backend/tests/unit/auth/test_permission_service.py`

```python
"""
Unit tests for permission service.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4
from datetime import datetime, timedelta

from onyx.auth.permission_service import (
    PermissionService, 
    get_user_permission, 
    user_has_permission,
    CachedPermission
)


class TestPermissionService:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.service = PermissionService(cache_ttl_minutes=5)
        self.user_id = uuid4()
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_cache_miss(self):
        """Test getting permission with cache miss"""
        with patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.return_value = "admin"
            
            result = await self.service.get_user_permission_level(self.user_id)
            
            assert result == "admin"
            mock_db.assert_called_once_with(self.user_id)
            
            # Check cache was populated
            cached = self.service._get_from_cache(self.user_id)
            assert cached is not None
            assert cached.permission_level == "admin"
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_cache_hit(self):
        """Test getting permission with cache hit"""
        # Pre-populate cache
        self.service._store_in_cache(self.user_id, "write")
        
        with patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            result = await self.service.get_user_permission_level(self.user_id)
            
            assert result == "write"
            mock_db.assert_not_called()  # Should not hit database
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_database_error(self):
        """Test fallback when database fails"""
        with patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.side_effect = Exception("Database connection failed")
            
            result = await self.service.get_user_permission_level(self.user_id)
            
            assert result == "read"  # Fallback permission
    
    @pytest.mark.asyncio
    async def test_get_multiple_user_permissions(self):
        """Test getting permissions for multiple users"""
        user_ids = {uuid4(), uuid4(), uuid4()}
        
        with patch.object(self.service, 'get_user_permission_level') as mock_get:
            mock_get.side_effect = ["admin", "write", "read"]
            
            results = await self.service.get_multiple_user_permissions(user_ids)
            
            assert len(results) == 3
            assert set(results.values()) == {"admin", "write", "read"}
    
    def test_invalidate_user_cache(self):
        """Test cache invalidation for specific user"""
        # Pre-populate cache
        self.service._store_in_cache(self.user_id, "admin")
        assert self.service._get_from_cache(self.user_id) is not None
        
        # Invalidate
        self.service.invalidate_user_cache(self.user_id)
        assert self.service._get_from_cache(self.user_id) is None
    
    def test_invalidate_all_cache(self):
        """Test invalidating all cache"""
        # Pre-populate cache with multiple users
        user1, user2 = uuid4(), uuid4()
        self.service._store_in_cache(user1, "admin")
        self.service._store_in_cache(user2, "write")
        
        # Invalidate all
        self.service.invalidate_all_cache()
        
        assert self.service._get_from_cache(user1) is None
        assert self.service._get_from_cache(user2) is None
    
    def test_cleanup_expired_cache(self):
        """Test cleanup of expired cache entries"""
        # Add fresh entry
        fresh_user = uuid4()
        self.service._store_in_cache(fresh_user, "admin")
        
        # Add expired entry by manipulating cache directly
        expired_user = uuid4()
        expired_time = datetime.utcnow() - timedelta(minutes=10)  # Expired
        expired_cached = CachedPermission(
            permission_level="write",
            cached_at=expired_time,
            user_id=expired_user
        )
        self.service._cache[expired_user] = expired_cached
        
        # Cleanup
        removed_count = self.service.cleanup_expired_cache()
        
        assert removed_count == 1
        assert self.service._get_from_cache(fresh_user) is not None  # Still there
        assert self.service._get_from_cache(expired_user) is None   # Removed
    
    def test_cache_stats(self):
        """Test cache statistics"""
        # Generate some activity
        with patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.return_value = "read"
            
            # Run async test
            async def generate_activity():
                await self.service.get_user_permission_level(self.user_id)  # Miss
                await self.service.get_user_permission_level(self.user_id)  # Hit
            
            asyncio.run(generate_activity())
        
        stats = self.service.get_cache_stats()
        
        assert stats["total_requests"] == 2
        assert stats["cache_hits"] == 1
        assert stats["cache_misses"] == 1
        assert stats["hit_rate_percent"] == 50.0
    
    def test_is_cache_valid(self):
        """Test cache validity checking"""
        now = datetime.utcnow()
        
        # Fresh timestamp
        fresh_time = now - timedelta(minutes=2)
        assert self.service._is_cache_valid(fresh_time, now) is True
        
        # Expired timestamp
        expired_time = now - timedelta(minutes=10)
        assert self.service._is_cache_valid(expired_time, now) is False


class TestConvenienceFunctions:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_id = uuid4()
    
    @pytest.mark.asyncio
    async def test_get_user_permission_convenience(self):
        """Test convenience function for getting permission"""
        with patch('onyx.auth.permission_service.get_permission_service') as mock_service:
            mock_instance = MagicMock()
            mock_instance.get_user_permission_level = AsyncMock(return_value="admin")
            mock_service.return_value = mock_instance
            
            result = await get_user_permission(self.user_id)
            
            assert result == "admin"
    
    @pytest.mark.asyncio
    async def test_user_has_permission_sufficient(self):
        """Test permission check with sufficient permission"""
        with patch('onyx.auth.permission_service.get_user_permission') as mock_get:
            mock_get.return_value = "admin"
            
            result = await user_has_permission(self.user_id, "write")
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_user_has_permission_insufficient(self):
        """Test permission check with insufficient permission"""
        with patch('onyx.auth.permission_service.get_user_permission') as mock_get:
            mock_get.return_value = "read"
            
            result = await user_has_permission(self.user_id, "admin")
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_user_has_permission_invalid_required(self):
        """Test permission check with invalid required level"""
        result = await user_has_permission(self.user_id, "invalid")
        
        assert result is False
```

### Performance Tests
**Path**: `backend/tests/performance/test_permission_service_performance.py`

```python
"""
Performance tests for permission service.
"""
import pytest
import asyncio
import time
from uuid import uuid4
from unittest.mock import patch, AsyncMock

from onyx.auth.permission_service import PermissionService


class TestPermissionServicePerformance:
    
    @pytest.mark.asyncio
    async def test_cached_permission_lookup_speed(self):
        """Test cached permission lookups are fast"""
        service = PermissionService()
        user_id = uuid4()
        
        # Pre-populate cache
        service._store_in_cache(user_id, "admin")
        
        # Measure cached lookups
        start_time = time.time()
        
        tasks = [service.get_user_permission_level(user_id) for _ in range(100)]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time_ms = (end_time - start_time) * 1000
        avg_time_ms = total_time_ms / 100
        
        # Should be under 5ms per cached lookup
        assert avg_time_ms < 5
        assert all(result == "admin" for result in results)
    
    @pytest.mark.asyncio
    async def test_cache_memory_usage(self):
        """Test cache doesn't use excessive memory"""
        service = PermissionService()
        
        # Add many users to cache
        user_ids = [uuid4() for _ in range(1000)]
        
        for user_id in user_ids:
            service._store_in_cache(user_id, "read")
        
        stats = service.get_cache_stats()
        assert stats["cache_size"] == 1000
        
        # Cache should be manageable size
        # This is a rough check - in practice you'd measure actual memory
        assert stats["cache_size"] < 10000
```

## 🚀 Deployment Checklist

### Pre-deployment
- [ ] Code review completed
- [ ] All unit tests passing
- [ ] Performance tests meet requirements
- [ ] Cache TTL configuration tested
- [ ] Memory usage verified

### Deployment Steps
1. [ ] Deploy permission service module
2. [ ] Start background cache cleanup task
3. [ ] Monitor cache hit rates
4. [ ] Verify performance metrics
5. [ ] Test cache invalidation

### Post-deployment Verification
- [ ] Permission lookups working correctly
- [ ] Cache hit rate >90% after warm-up
- [ ] No memory leaks in cache
- [ ] Background cleanup running properly
- [ ] Performance meets requirements (<5ms cached, <50ms uncached)

### Rollback Plan
If issues occur:
1. Disable permission service caching
2. Fall back to direct database lookups
3. Verify permission checks still work
4. Fix caching issues before re-enabling

## 📋 Definition of Done

- [ ] All acceptance criteria met
- [ ] Permission service with caching implemented
- [ ] Performance requirements met
- [ ] Comprehensive unit tests (>95% coverage)
- [ ] Performance tests passing
- [ ] Cache management working correctly
- [ ] Background cleanup task implemented
- [ ] Metrics and monitoring in place
- [ ] Code reviewed and approved
- [ ] Deployed successfully

## 🔗 Related Stories

**Dependencies**: Story 2.1 (Enhanced OAuth Callback Handler)  
**Next Stories**:
- Story 3.1: Permission Dependency Functions (will use this service)
- All subsequent stories will depend on this for permission checking

## 📝 Notes

- The service uses in-memory caching for simplicity and speed
- Thread-safe operations ensure cache consistency
- Graceful fallbacks prevent service failures from affecting authentication
- Background cleanup prevents memory growth
- Comprehensive metrics enable monitoring and optimization
- Cache invalidation supports permission updates

## 🐛 Known Risks

1. **Memory Usage**: Cache could grow large with many users
2. **Cache Invalidation**: Updates might not invalidate cache properly
3. **Concurrent Access**: Race conditions in cache operations
4. **Database Failures**: Service needs to handle DB outages gracefully

## 💡 Success Metrics

- Cache hit rate >90% after system warm-up
- Cached lookups complete in <5ms
- Uncached lookups complete in <50ms
- Memory usage <10MB for 1000+ cached users
- Zero permission check failures due to caching issues

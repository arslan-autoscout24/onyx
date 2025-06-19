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
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
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
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.side_effect = Exception("Database error")
            
            result = await self.service.get_user_permission_level(self.user_id)
            
            # Should fallback to 'read'
            assert result == "read"
            assert self.service._db_errors == 1
    
    @pytest.mark.asyncio
    async def test_get_multiple_user_permissions(self):
        """Test multiple user permission retrieval"""
        user1, user2, user3 = uuid4(), uuid4(), uuid4()
        
        # Pre-populate cache for user1
        self.service._store_in_cache(user1, "admin")
        
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.side_effect = ["write", "read"]  # For user2 and user3
            
            result = await self.service.get_multiple_user_permissions({user1, user2, user3})
            
            assert result[user1] == "admin"  # From cache
            assert result[user2] == "write"  # From database
            assert result[user3] == "read"   # From database
            assert mock_db.call_count == 2   # Only called for user2 and user3
    
    def test_invalidate_user_cache(self):
        """Test invalidating specific user cache"""
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
    async def test_get_user_permission(self):
        """Test convenience function for getting user permission"""
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.return_value = "write"
            
            result = await get_user_permission(self.user_id)
            
            assert result == "write"
    
    @pytest.mark.asyncio
    async def test_user_has_permission_sufficient(self):
        """Test user has sufficient permission"""
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.return_value = "admin"
            
            # Admin should have write permission
            result = await user_has_permission(self.user_id, "write")
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_user_has_permission_insufficient(self):
        """Test user has insufficient permission"""
        with patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.return_value = "read"
            
            # Read should not have admin permission
            result = await user_has_permission(self.user_id, "admin")
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_user_has_permission_equal(self):
        """Test user has exact permission level"""
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.return_value = "write"
            
            # Write should have write permission
            result = await user_has_permission(self.user_id, "write")
            
            assert result is True


class TestOAuthPermissionsDisabled:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.service = PermissionService(cache_ttl_minutes=5)
        self.user_id = uuid4()
    
    @pytest.mark.asyncio
    async def test_permission_service_when_oauth_disabled(self):
        """Test permission service when OAuth permissions are disabled"""
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', False):
            result = await self.service.get_user_permission_level(self.user_id)
            
            # Should return 'read' when OAuth permissions are disabled
            assert result == "read"


class TestThreadSafety:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.service = PermissionService(cache_ttl_minutes=5)
    
    def test_concurrent_cache_operations(self):
        """Test thread safety of cache operations"""
        import threading
        import time
        
        users = [uuid4() for _ in range(10)]
        results = []
        
        def store_permission(user_id):
            """Store permission in cache"""
            self.service._store_in_cache(user_id, "test_permission")
            results.append(user_id)
        
        # Create and start multiple threads
        threads = []
        for user_id in users:
            thread = threading.Thread(target=store_permission, args=(user_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all operations completed
        assert len(results) == 10
        assert len(self.service._cache) == 10
    
    def test_concurrent_cache_invalidation(self):
        """Test thread safety of cache invalidation"""
        import threading
        
        # Pre-populate cache
        users = [uuid4() for _ in range(5)]
        for user_id in users:
            self.service._store_in_cache(user_id, "test_permission")
        
        # Invalidate from multiple threads
        threads = []
        for user_id in users:
            thread = threading.Thread(target=self.service.invalidate_user_cache, args=(user_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Cache should be empty
        assert len(self.service._cache) == 0


class TestPermissionServiceCircuitBreaker:
    """Test circuit breaker functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.service = PermissionService(cache_ttl_minutes=5)
        self.user_id = uuid4()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_after_failures(self):
        """Test circuit breaker opens after threshold failures"""
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.side_effect = Exception("Database connection failed")
            
            # Trigger failures up to threshold
            for i in range(5):
                result = await self.service.get_user_permission_level(self.user_id)
                assert result == "read"  # Fallback
            
            # Circuit breaker should now be open
            assert self.service._circuit_breaker.is_open is True
            assert self.service._circuit_breaker_trips == 1
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks_requests_when_open(self):
        """Test circuit breaker blocks requests when open"""
        # Manually open circuit breaker
        self.service._circuit_breaker.is_open = True
        self.service._circuit_breaker.last_failure_time = datetime.utcnow()
        
        with patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            result = await self.service.get_user_permission_level(self.user_id)
            
            assert result == "read"  # Fallback
            mock_db.assert_not_called()  # Should not hit database
    
    @pytest.mark.asyncio 
    async def test_circuit_breaker_resets_after_success(self):
        """Test circuit breaker resets after successful operation"""
        # Set some failures
        self.service._circuit_breaker.failure_count = 3
        
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            mock_db.return_value = "admin"
            
            result = await self.service.get_user_permission_level(self.user_id)
            
            assert result == "admin"
            assert self.service._circuit_breaker.failure_count == 0
            assert self.service._circuit_breaker.is_open is False

    def test_circuit_breaker_stats_in_cache_stats(self):
        """Test circuit breaker metrics are included in stats"""
        self.service._circuit_breaker_trips = 2
        self.service._circuit_breaker.is_open = True
        self.service._circuit_breaker.failure_count = 3
        
        stats = self.service.get_cache_stats()
        
        assert stats["circuit_breaker_trips"] == 2
        assert stats["circuit_breaker_open"] is True
        assert stats["circuit_breaker_failures"] == 3

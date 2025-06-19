"""
Integration tests for permission service functionality.
"""
import pytest
import asyncio
from uuid import uuid4
from unittest.mock import patch

from onyx.auth.permission_service import (
    get_permission_service, 
    get_user_permission,
    user_has_permission,
    invalidate_user_permission_cache
)


class TestPermissionServiceIntegration:
    """Test permission service integration with actual components"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_id = uuid4()
        
    def teardown_method(self):
        """Clean up after tests"""
        # Clear the global service instance for clean tests
        import onyx.auth.permission_service as perm_module
        perm_module._permission_service = None

    @pytest.mark.asyncio
    async def test_permission_service_end_to_end(self):
        """Test full permission service workflow"""
        # Mock the database call
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            
            mock_db.return_value = "admin"
            
            # Test getting permission (should hit database)
            permission = await get_user_permission(self.user_id)
            assert permission == "admin"
            assert mock_db.call_count == 1
            
            # Test getting same permission again (should hit cache)
            permission2 = await get_user_permission(self.user_id)
            assert permission2 == "admin"
            assert mock_db.call_count == 1  # Should not have called DB again
            
            # Test permission checking
            has_read = await user_has_permission(self.user_id, "read")
            has_write = await user_has_permission(self.user_id, "write")
            has_admin = await user_has_permission(self.user_id, "admin")
            
            assert has_read is True
            assert has_write is True
            assert has_admin is True
            
            # Invalidate cache and verify it hits DB again
            invalidate_user_permission_cache(self.user_id)
            
            mock_db.return_value = "read"
            permission3 = await get_user_permission(self.user_id)
            assert permission3 == "read"
            assert mock_db.call_count == 2  # Should have called DB again

    @pytest.mark.asyncio
    async def test_permission_hierarchy(self):
        """Test permission hierarchy logic"""
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            
            # Test read permission
            mock_db.return_value = "read"
            
            assert await user_has_permission(self.user_id, "read") is True
            assert await user_has_permission(self.user_id, "write") is False
            assert await user_has_permission(self.user_id, "admin") is False
            
            # Clear cache for next test
            invalidate_user_permission_cache(self.user_id)
            
            # Test write permission
            mock_db.return_value = "write"
            
            assert await user_has_permission(self.user_id, "read") is True
            assert await user_has_permission(self.user_id, "write") is True
            assert await user_has_permission(self.user_id, "admin") is False

    @pytest.mark.asyncio
    async def test_fallback_behavior(self):
        """Test fallback behavior when database fails"""
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            
            mock_db.side_effect = Exception("Database connection failed")
            
            # Should fallback to read permission
            permission = await get_user_permission(self.user_id)
            assert permission == "read"
            
            # Should still work for permission checking
            has_read = await user_has_permission(self.user_id, "read")
            assert has_read is True

    @pytest.mark.asyncio
    async def test_circuit_breaker_behavior(self):
        """Test circuit breaker opens after repeated failures"""
        service = get_permission_service()
        
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            
            mock_db.side_effect = Exception("Database connection failed")
            
            # Trigger enough failures to open circuit breaker
            for i in range(6):
                permission = await service.get_user_permission_level(self.user_id)
                assert permission == "read"  # Fallback
            
            # Circuit breaker should now be open
            assert service._circuit_breaker.is_open is True
            
            # Even with DB working, should return fallback while circuit is open
            mock_db.side_effect = None
            mock_db.return_value = "admin"
            
            permission = await service.get_user_permission_level(self.user_id)
            assert permission == "read"  # Still fallback due to open circuit
            
            # Should not have called database while circuit is open
            mock_db.assert_not_called()

    def test_cache_statistics(self):
        """Test cache statistics collection"""
        service = get_permission_service()
        
        # Generate some mock activity
        service._total_requests = 100
        service._cache_hits = 85
        service._cache_misses = 15
        service._db_errors = 2
        
        stats = service.get_cache_stats()
        
        assert stats["total_requests"] == 100
        assert stats["cache_hits"] == 85
        assert stats["cache_misses"] == 15
        assert stats["hit_rate_percent"] == 85.0
        assert stats["db_errors"] == 2
        assert "circuit_breaker_trips" in stats
        assert "circuit_breaker_open" in stats

    @pytest.mark.asyncio
    async def test_multiple_users_performance(self):
        """Test handling multiple users efficiently"""
        user_ids = {uuid4() for _ in range(10)}
        
        with patch('onyx.auth.permission_service.OAUTH_PERMISSIONS_ENABLED', True), \
             patch('onyx.auth.permission_service.get_user_permission_level') as mock_db:
            
            mock_db.return_value = "write"
            
            service = get_permission_service()
            permissions = await service.get_multiple_user_permissions(user_ids)
            
            assert len(permissions) == 10
            assert all(perm == "write" for perm in permissions.values())
            assert mock_db.call_count == 10  # Called once per user
            
            # Second call should use cache
            permissions2 = await service.get_multiple_user_permissions(user_ids)
            assert len(permissions2) == 10
            assert mock_db.call_count == 10  # Should not have increased

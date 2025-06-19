"""
Unit tests for OAuth permission dependencies.

Tests the core functionality of permission checking, hierarchy enforcement,
and dependency behavior.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException, status
from uuid import uuid4

from onyx.server.auth_check import (
    require_permission, 
    get_oauth_permission,
    has_permission,
    optional_permission,
    PERMISSION_HIERARCHY
)
from onyx.db.models import User


class TestOAuthDependencies:
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing"""
        user = User()
        user.id = uuid4()
        user.email = "test@example.com"
        return user
    
    @pytest.mark.asyncio
    async def test_get_oauth_permission_success(self, mock_user):
        """Test successful permission retrieval"""
        with patch('onyx.server.auth_check.get_user_permission_level') as mock_get, \
             patch('onyx.server.auth_check.get_redis_client') as mock_redis:
            
            # Mock Redis cache miss
            mock_redis_client = AsyncMock()
            mock_redis_client.get.return_value = None
            mock_redis_client.setex.return_value = None
            mock_redis.return_value = mock_redis_client
            
            # Mock database response
            mock_get.return_value = "write"
            
            permission = await get_oauth_permission(mock_user)
            assert permission == "write"
            mock_get.assert_called_once_with(mock_user.id)
    
    @pytest.mark.asyncio
    async def test_get_oauth_permission_cache_hit(self, mock_user):
        """Test cached permission retrieval"""
        with patch('onyx.server.auth_check.get_redis_client') as mock_redis:
            # Mock Redis cache hit
            mock_redis_client = AsyncMock()
            mock_redis_client.get.return_value = '{"level": "admin", "cached_at": "2023-01-01T00:00:00"}'
            mock_redis.return_value = mock_redis_client
            
            permission = await get_oauth_permission(mock_user)
            assert permission == "admin"
            mock_redis_client.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_oauth_permission_failure(self, mock_user):
        """Test permission retrieval failure"""
        with patch('onyx.server.auth_check.get_user_permission_level') as mock_get, \
             patch('onyx.server.auth_check.get_redis_client') as mock_redis:
            
            mock_redis_client = AsyncMock()
            mock_redis_client.get.return_value = None
            mock_redis.return_value = mock_redis_client
            
            mock_get.side_effect = Exception("Database error")
            
            with pytest.raises(HTTPException) as exc_info:
                await get_oauth_permission(mock_user)
            
            assert exc_info.value.status_code == 500
    
    @pytest.mark.asyncio 
    async def test_require_permission_sufficient(self, mock_user):
        """Test permission dependency with sufficient permission"""
        require_write = require_permission("write")
        
        with patch('onyx.server.auth_check.get_oauth_permission') as mock_get:
            mock_get.return_value = "admin"  # admin > write
            
            result = await require_write(mock_user, "admin")
            assert result == mock_user
    
    @pytest.mark.asyncio 
    async def test_require_permission_insufficient(self, mock_user):
        """Test permission dependency with insufficient permission"""
        require_admin = require_permission("admin")
        
        with patch('onyx.server.auth_check.get_oauth_permission') as mock_get:
            mock_get.return_value = "read"  # read < admin
            
            with pytest.raises(HTTPException) as exc_info:
                await require_admin(mock_user, "read")
            
            assert exc_info.value.status_code == 403
            assert "Insufficient permissions" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_require_permission_exact_match(self, mock_user):
        """Test permission dependency with exact permission match"""
        require_write = require_permission("write")
        
        with patch('onyx.server.auth_check.get_oauth_permission') as mock_get:
            mock_get.return_value = "write"  # write == write
            
            result = await require_write(mock_user, "write")
            assert result == mock_user
    
    def test_has_permission_hierarchy(self):
        """Test permission hierarchy logic"""
        # Admin can access everything
        assert has_permission("admin", "read") == True
        assert has_permission("admin", "write") == True
        assert has_permission("admin", "admin") == True
        
        # Write can access read and write
        assert has_permission("write", "read") == True
        assert has_permission("write", "write") == True
        assert has_permission("write", "admin") == False
        
        # Read can only access read
        assert has_permission("read", "read") == True
        assert has_permission("read", "write") == False
        assert has_permission("read", "admin") == False
        
        # None/invalid permissions
        assert has_permission("none", "read") == False
        assert has_permission("invalid", "read") == False
        assert has_permission("read", "invalid") == False
    
    def test_permission_hierarchy_values(self):
        """Test that permission hierarchy has correct values"""
        assert PERMISSION_HIERARCHY["read"] == 1
        assert PERMISSION_HIERARCHY["write"] == 2
        assert PERMISSION_HIERARCHY["admin"] == 3
    
    def test_require_permission_invalid_level(self):
        """Test that invalid permission levels raise ValueError"""
        with pytest.raises(ValueError) as exc_info:
            require_permission("invalid_level")
        
        assert "Invalid permission level" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_optional_permission_success(self, mock_user):
        """Test optional permission dependency success"""
        with patch('onyx.server.auth_check.get_oauth_permission') as mock_get:
            mock_get.return_value = "write"
            
            permission = await optional_permission(mock_user)
            assert permission == "write"
    
    @pytest.mark.asyncio
    async def test_optional_permission_failure(self, mock_user):
        """Test optional permission dependency handles failure gracefully"""
        with patch('onyx.server.auth_check.get_oauth_permission') as mock_get:
            mock_get.side_effect = HTTPException(status_code=403, detail="No permission")
            
            permission = await optional_permission(mock_user)
            assert permission is None
    
    @pytest.mark.asyncio
    async def test_permission_error_details(self, mock_user):
        """Test that permission errors contain helpful details"""
        require_admin = require_permission("admin")
        
        with patch('onyx.server.auth_check.get_oauth_permission') as mock_get:
            mock_get.return_value = "read"
            
            with pytest.raises(HTTPException) as exc_info:
                await require_admin(mock_user, "read")
            
            assert exc_info.value.status_code == 403
            assert "Required: admin" in exc_info.value.detail
            assert "Current: read" in exc_info.value.detail


class TestPermissionCaching:
    """Test caching behavior of permission dependencies"""
    
    @pytest.fixture
    def mock_user(self):
        user = User()
        user.id = uuid4()
        user.email = "cache_test@example.com"
        return user
    
    @pytest.mark.asyncio
    async def test_cache_invalidation(self, mock_user):
        """Test cache invalidation functionality"""
        from onyx.server.auth_check import invalidate_user_permission_cache
        
        with patch('onyx.server.auth_check.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis_client.delete.return_value = None
            mock_redis.return_value = mock_redis_client
            
            await invalidate_user_permission_cache(str(mock_user.id))
            
            mock_redis_client.delete.assert_called_once_with(f"user_oauth_permission:{mock_user.id}")


class TestPermissionFactories:
    """Test the pre-configured permission dependencies"""
    
    def test_require_read_factory(self):
        """Test that require_read is properly configured"""
        from onyx.server.auth_check import require_read
        assert callable(require_read)
    
    def test_require_write_factory(self):
        """Test that require_write is properly configured"""
        from onyx.server.auth_check import require_write
        assert callable(require_write)
    
    def test_require_admin_factory(self):
        """Test that require_admin is properly configured"""
        from onyx.server.auth_check import require_admin
        assert callable(require_admin)

"""
Integration tests for OAuth permission dependencies.

Tests the permission dependencies in the context of actual FastAPI routes
and database operations.
"""
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from uuid import uuid4

from onyx.server.auth_check import require_read, require_write, require_admin
from onyx.db.models import User


class TestPermissionDependenciesIntegration:
    
    @pytest.fixture
    def test_app(self):
        """Create a test FastAPI app with permission-protected endpoints"""
        app = FastAPI()
        
        @app.get("/read-endpoint")
        async def read_endpoint(user: User = Depends(require_read)):
            return {"message": "Read access granted", "user_id": str(user.id)}
        
        @app.post("/write-endpoint")
        async def write_endpoint(user: User = Depends(require_write)):
            return {"message": "Write access granted", "user_id": str(user.id)}
        
        @app.delete("/admin-endpoint")
        async def admin_endpoint(user: User = Depends(require_admin)):
            return {"message": "Admin access granted", "user_id": str(user.id)}
        
        return app
    
    @pytest.fixture
    def client(self, test_app):
        """Create test client"""
        return TestClient(test_app)
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user"""
        user = User()
        user.id = uuid4()
        user.email = "integration_test@example.com"
        return user
    
    def test_read_endpoint_with_read_permission(self, client, mock_user):
        """Test read endpoint with read permission"""
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "read"
            
            response = client.get("/read-endpoint")
            assert response.status_code == 200
            assert "Read access granted" in response.json()["message"]
    
    def test_read_endpoint_with_admin_permission(self, client, mock_user):
        """Test read endpoint with admin permission (should work due to hierarchy)"""
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "admin"
            
            response = client.get("/read-endpoint")
            assert response.status_code == 200
    
    def test_write_endpoint_with_read_permission(self, client, mock_user):
        """Test write endpoint with insufficient read permission"""
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "read"
            
            response = client.post("/write-endpoint")
            assert response.status_code == 403
            assert "Insufficient permissions" in response.json()["detail"]
    
    def test_write_endpoint_with_write_permission(self, client, mock_user):
        """Test write endpoint with sufficient write permission"""
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "write"
            
            response = client.post("/write-endpoint")
            assert response.status_code == 200
            assert "Write access granted" in response.json()["message"]
    
    def test_admin_endpoint_with_read_permission(self, client, mock_user):
        """Test admin endpoint with insufficient read permission"""
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "read"
            
            response = client.delete("/admin-endpoint")
            assert response.status_code == 403
    
    def test_admin_endpoint_with_admin_permission(self, client, mock_user):
        """Test admin endpoint with sufficient admin permission"""
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "admin"
            
            response = client.delete("/admin-endpoint")
            assert response.status_code == 200
            assert "Admin access granted" in response.json()["message"]
    
    def test_error_response_format(self, client, mock_user):
        """Test that 403 errors have consistent format"""
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "read"
            
            response = client.delete("/admin-endpoint")
            assert response.status_code == 403
            
            error_data = response.json()
            assert "detail" in error_data
            assert "Required: admin" in error_data["detail"]
            assert "Current: read" in error_data["detail"]


class TestPermissionHierarchyIntegration:
    """Test permission hierarchy enforcement in integration scenarios"""
    
    @pytest.fixture
    def hierarchy_app(self):
        """Create app to test permission hierarchy"""
        app = FastAPI()
        
        @app.get("/multi-permission")
        async def multi_permission_endpoint(
            read_user: User = Depends(require_read),
            write_user: User = Depends(require_write)
        ):
            # This endpoint requires both read and write (effectively write)
            return {"message": "Multi-permission access granted"}
        
        return app
    
    def test_hierarchy_enforcement(self, hierarchy_app, mock_user):
        """Test that permission hierarchy is properly enforced"""
        client = TestClient(hierarchy_app)
        
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "admin"  # Should satisfy both dependencies
            
            response = client.get("/multi-permission")
            assert response.status_code == 200


class TestCachingIntegration:
    """Test caching behavior in integration scenarios"""
    
    @pytest.fixture
    def cached_app(self):
        """Create app to test caching"""
        app = FastAPI()
        
        @app.get("/cached-endpoint")
        async def cached_endpoint(user: User = Depends(require_read)):
            return {"message": "Cached access", "user_id": str(user.id)}
        
        return app
    
    def test_permission_caching(self, cached_app, mock_user):
        """Test that permissions are properly cached"""
        client = TestClient(cached_app)
        
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_redis_client') as mock_redis, \
             patch('onyx.server.auth_check.get_user_permission_level') as mock_get_level:
            
            mock_current_user.return_value = mock_user
            
            # Mock Redis operations
            mock_redis_client = AsyncMock()
            mock_redis_client.get.return_value = None  # Cache miss first time
            mock_redis_client.setex.return_value = None
            mock_redis.return_value = mock_redis_client
            
            mock_get_level.return_value = "read"
            
            # First request should hit database
            response1 = client.get("/cached-endpoint")
            assert response1.status_code == 200
            mock_get_level.assert_called_once()
            
            # Mock cache hit for second request
            mock_redis_client.get.return_value = '{"level": "read", "cached_at": "2023-01-01T00:00:00"}'
            mock_get_level.reset_mock()
            
            # Second request should hit cache
            response2 = client.get("/cached-endpoint")
            assert response2.status_code == 200
            mock_get_level.assert_not_called()  # Should not hit database

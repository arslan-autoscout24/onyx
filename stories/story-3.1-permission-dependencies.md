# Story 3.1: OAuth Permission Dependencies

## Overview
**Sprint**: 3 - Authorization Middleware  
**Story ID**: 3.1  
**Title**: OAuth Permission Dependencies  
**Priority**: P0 - Critical  
**Estimate**: 2 days  
**Dependencies**: Story 2.2 (Permission Retrieval Service)

## Description
Create FastAPI dependencies for OAuth permission checking that integrate seamlessly with the existing authentication system. This provides a reusable, declarative way to protect API endpoints based on OAuth permission levels.

## Acceptance Criteria
- [ ] Permission dependency factory `require_permission(level)` implemented
- [ ] Specific dependencies created: `require_read`, `require_write`, `require_admin`
- [ ] Integration with existing `current_user` dependency maintained
- [ ] Proper HTTP 403 responses for insufficient permissions
- [ ] Permission hierarchy enforcement implemented (admin > write > read)
- [ ] Unit tests for all permission levels with 100% coverage
- [ ] Performance tests showing <10ms permission check latency
- [ ] Documentation for developers on using permission dependencies

## Technical Implementation

### Core Files to Modify/Create

#### 1. Enhanced Authentication Checker
**File**: `backend/onyx/server/auth_check.py`

```python
from functools import wraps
from typing import Callable, Optional
from fastapi import Depends, HTTPException, status
from onyx.auth.users import current_user
from onyx.db.models import User
from onyx.server.auth.permissions import get_user_oauth_permission
import logging

logger = logging.getLogger(__name__)

# Permission hierarchy mapping
PERMISSION_HIERARCHY = {
    "read": 1,
    "write": 2,
    "admin": 3
}

async def get_oauth_permission(user: User = Depends(current_user)) -> str:
    """
    Dependency to get the current user's OAuth permission level.
    
    Returns:
        str: Permission level ('read', 'write', 'admin', or 'none')
        
    Raises:
        HTTPException: If user has no OAuth permissions
    """
    try:
        permission_level = await get_user_oauth_permission(user.id)
        logger.debug(f"User {user.email} has permission level: {permission_level}")
        return permission_level
    except Exception as e:
        logger.error(f"Failed to get OAuth permission for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user permissions"
        )

def require_permission(required_level: str) -> Callable:
    """
    Factory function to create permission dependency functions.
    
    Args:
        required_level: Minimum permission level required ('read', 'write', 'admin')
        
    Returns:
        Dependency function that validates user has required permission
    """
    if required_level not in PERMISSION_HIERARCHY:
        raise ValueError(f"Invalid permission level: {required_level}")
    
    async def permission_dependency(
        user: User = Depends(current_user),
        user_permission: str = Depends(get_oauth_permission)
    ) -> User:
        """
        Check if user has the required permission level.
        
        Returns:
            User: The authenticated user if permission check passes
            
        Raises:
            HTTPException: 403 if user lacks required permission
        """
        required_level_value = PERMISSION_HIERARCHY[required_level]
        user_level_value = PERMISSION_HIERARCHY.get(user_permission, 0)
        
        if user_level_value < required_level_value:
            logger.warning(
                f"User {user.email} with permission '{user_permission}' "
                f"attempted to access endpoint requiring '{required_level}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {required_level}, "
                       f"Current: {user_permission}"
            )
        
        logger.debug(f"Permission check passed for user {user.email}")
        return user
    
    return permission_dependency

# Pre-configured permission dependencies
require_read = require_permission("read")
require_write = require_permission("write")
require_admin = require_permission("admin")

# Optional dependency that doesn't raise on failure
async def optional_permission(user: User = Depends(current_user)) -> Optional[str]:
    """
    Get user permission without failing if permission is missing.
    Useful for conditional logic in endpoints.
    """
    try:
        return await get_oauth_permission(user)
    except HTTPException:
        return None

# Utility function for manual permission checks
def has_permission(user_permission: str, required_permission: str) -> bool:
    """
    Check if a permission level meets the requirement.
    
    Args:
        user_permission: User's current permission level
        required_permission: Required permission level
        
    Returns:
        bool: True if user has sufficient permission
    """
    user_level = PERMISSION_HIERARCHY.get(user_permission, 0)
    required_level = PERMISSION_HIERARCHY.get(required_permission, 999)
    return user_level >= required_level
```

#### 2. Permission Service Integration
**File**: `backend/onyx/server/auth/permissions.py` (enhancement)

```python
from fastapi import HTTPException, status
from onyx.redis.redis_pool import get_redis_client
from onyx.db.models import User
from onyx.db.engine import get_session
import json
import logging

logger = logging.getLogger(__name__)

async def get_user_oauth_permission(user_id: int) -> str:
    """
    Get cached OAuth permission for a user with fallback to database.
    
    Args:
        user_id: User's database ID
        
    Returns:
        str: Permission level ('read', 'write', 'admin', or 'none')
        
    Raises:
        HTTPException: If permission cannot be determined
    """
    redis_client = get_redis_client()
    cache_key = f"user_oauth_permission:{user_id}"
    
    try:
        # Try cache first
        cached_permission = await redis_client.get(cache_key)
        if cached_permission:
            permission_data = json.loads(cached_permission)
            logger.debug(f"Cache hit for user {user_id}: {permission_data['level']}")
            return permission_data['level']
        
        # Fallback to database
        with get_session() as db_session:
            oauth_permission = db_session.query(OAuthPermission).filter(
                OAuthPermission.user_id == user_id
            ).first()
            
            if not oauth_permission:
                logger.warning(f"No OAuth permission found for user {user_id}")
                return "none"
            
            permission_level = oauth_permission.permission_level
            
            # Cache the result
            permission_data = {
                "level": permission_level,
                "okta_groups": oauth_permission.okta_groups or [],
                "cached_at": datetime.utcnow().isoformat()
            }
            await redis_client.setex(
                cache_key, 
                PERMISSION_CACHE_TTL, 
                json.dumps(permission_data)
            )
            
            logger.debug(f"Database hit for user {user_id}: {permission_level}")
            return permission_level
            
    except Exception as e:
        logger.error(f"Error getting permission for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user permissions"
        )
```

#### 3. Custom Exception Handler
**File**: `backend/onyx/server/middleware/auth_middleware.py` (new)

```python
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

async def oauth_permission_exception_handler(request: Request, exc: HTTPException):
    """
    Custom exception handler for OAuth permission errors.
    Provides consistent error responses across the application.
    """
    if exc.status_code == status.HTTP_403_FORBIDDEN:
        logger.warning(
            f"Permission denied for {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )
        
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "detail": exc.detail,
                "error_code": "INSUFFICIENT_OAUTH_PERMISSIONS",
                "required_action": "Contact administrator to update your permissions",
                "support_email": "support@yourcompany.com"
            }
        )
    
    # Let other exceptions be handled normally
    raise exc
```

## Testing Requirements

### Unit Tests
**File**: `backend/tests/unit/test_oauth_dependencies.py`

```python
import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException, status
from onyx.server.auth_check import (
    require_permission, 
    get_oauth_permission,
    has_permission,
    optional_permission
)
from onyx.db.models import User

class TestOAuthDependencies:
    
    @pytest.fixture
    def mock_user(self):
        user = User()
        user.id = 1
        user.email = "test@example.com"
        return user
    
    @pytest.mark.asyncio
    async def test_get_oauth_permission_success(self, mock_user):
        """Test successful permission retrieval"""
        with patch('onyx.server.auth_check.get_user_oauth_permission') as mock_get:
            mock_get.return_value = "write"
            
            permission = await get_oauth_permission(mock_user)
            assert permission == "write"
            mock_get.assert_called_once_with(1)
    
    @pytest.mark.asyncio
    async def test_get_oauth_permission_failure(self, mock_user):
        """Test permission retrieval failure"""
        with patch('onyx.server.auth_check.get_user_oauth_permission') as mock_get:
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
    
    def test_has_permission_hierarchy(self):
        """Test permission hierarchy logic"""
        assert has_permission("admin", "read") == True
        assert has_permission("admin", "write") == True
        assert has_permission("admin", "admin") == True
        
        assert has_permission("write", "read") == True
        assert has_permission("write", "write") == True
        assert has_permission("write", "admin") == False
        
        assert has_permission("read", "read") == True
        assert has_permission("read", "write") == False
        assert has_permission("read", "admin") == False
        
        assert has_permission("none", "read") == False
    
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
```

### Integration Tests
**File**: `backend/tests/integration/test_permission_dependencies.py`

```python
import pytest
from fastapi.testclient import TestClient
from onyx.main import app
from onyx.db.models import User, OAuthPermission
from tests.integration.test_utils import TestUser

class TestPermissionDependenciesIntegration:
    
    @pytest.fixture
    def client(self):
        return TestClient(app)
    
    @pytest.fixture
    def read_user(self, db_session):
        user = TestUser.create_test_user(email="read@test.com")
        permission = OAuthPermission(
            user_id=user.id,
            permission_level="read",
            okta_groups=["Onyx-Readers"]
        )
        db_session.add(permission)
        db_session.commit()
        return user
    
    @pytest.fixture
    def admin_user(self, db_session):
        user = TestUser.create_test_user(email="admin@test.com")
        permission = OAuthPermission(
            user_id=user.id,
            permission_level="admin",
            okta_groups=["Onyx-Admins"]
        )
        db_session.add(permission)
        db_session.commit()
        return user
    
    def test_permission_enforcement_read_endpoint(self, client, read_user, admin_user):
        """Test that read endpoints work with read+ permissions"""
        # Test with read user
        with TestUser.logged_in_user(read_user):
            response = client.get("/api/documents")
            assert response.status_code == 200
        
        # Test with admin user  
        with TestUser.logged_in_user(admin_user):
            response = client.get("/api/documents")
            assert response.status_code == 200
    
    def test_permission_enforcement_write_endpoint(self, client, read_user, admin_user):
        """Test that write endpoints require write+ permissions"""
        # Test with read user (should fail)
        with TestUser.logged_in_user(read_user):
            response = client.post("/api/documents", json={"title": "Test"})
            assert response.status_code == 403
            assert "Insufficient permissions" in response.json()["detail"]
        
        # Test with admin user (should succeed)
        with TestUser.logged_in_user(admin_user):
            response = client.post("/api/documents", json={"title": "Test"})
            assert response.status_code in [200, 201]
    
    def test_error_response_format(self, client, read_user):
        """Test that 403 errors have consistent format"""
        with TestUser.logged_in_user(read_user):
            response = client.post("/api/admin/users")
            assert response.status_code == 403
            
            error_data = response.json()
            assert "detail" in error_data
            assert "error_code" in error_data
            assert error_data["error_code"] == "INSUFFICIENT_OAUTH_PERMISSIONS"
```

## Performance Requirements

- **Permission Check Latency**: < 10ms per request (95th percentile)
- **Cache Hit Rate**: > 95% for permission lookups
- **Memory Usage**: < 50MB additional memory for permission caching
- **Concurrent Requests**: Support 1000+ concurrent permission checks

### Performance Tests
**File**: `backend/tests/performance/test_permission_performance.py`

```python
import pytest
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from onyx.server.auth_check import get_oauth_permission, require_permission

class TestPermissionPerformance:
    
    @pytest.mark.asyncio
    async def test_permission_check_latency(self, test_user_with_permissions):
        """Test that permission checks complete within latency requirements"""
        start_time = time.perf_counter()
        
        # Run 100 permission checks
        tasks = []
        for _ in range(100):
            tasks.append(get_oauth_permission(test_user_with_permissions))
        
        await asyncio.gather(*tasks)
        
        end_time = time.perf_counter()
        avg_latency = (end_time - start_time) / 100
        
        # Should average < 5ms per check
        assert avg_latency < 0.005, f"Average latency {avg_latency:.4f}s exceeds 5ms"
    
    @pytest.mark.asyncio
    async def test_concurrent_permission_checks(self, test_user_with_permissions):
        """Test concurrent permission checking performance"""
        require_write = require_permission("write")
        
        async def check_permission():
            return await require_write(test_user_with_permissions, "write")
        
        # Run 1000 concurrent permission checks
        start_time = time.perf_counter()
        tasks = [check_permission() for _ in range(1000)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.perf_counter()
        
        # All should succeed
        successful = sum(1 for r in results if not isinstance(r, Exception))
        assert successful == 1000
        
        # Should complete within 1 second
        total_time = end_time - start_time
        assert total_time < 1.0, f"1000 concurrent checks took {total_time:.2f}s"
```

## Security Considerations

1. **Permission Escalation Prevention**: Strict hierarchy enforcement prevents users from accessing higher-level resources
2. **Cache Poisoning Protection**: Redis cache keys are user-specific and expire automatically
3. **Audit Logging**: All permission denials are logged for security monitoring
4. **Error Information Leakage**: 403 responses don't reveal system internals
5. **Session Security**: Permission checks always verify current user session

## Deployment Checklist

### Pre-deployment
- [ ] All unit tests pass (target: 100% coverage)
- [ ] Integration tests pass in staging environment
- [ ] Performance tests meet latency requirements
- [ ] Security review completed
- [ ] Database migrations tested
- [ ] Redis cache configuration verified

### Deployment Steps
1. **Deploy Code**: Deploy new auth_check.py with permission dependencies
2. **Verify Dependencies**: Test that `require_read`, `require_write`, `require_admin` work
3. **Monitor Logs**: Watch for permission-related errors or unusual patterns
4. **Performance Check**: Verify permission check latency stays < 10ms
5. **Rollback Plan**: Feature flag `ENABLE_OAUTH_DEPENDENCIES` for quick disable

### Post-deployment
- [ ] Monitor permission check latency metrics
- [ ] Verify cache hit rates are > 95%
- [ ] Check error rates for 403 responses
- [ ] Validate audit logs are capturing permission denials
- [ ] Test with different user permission levels

## Rollback Plan

### Immediate Rollback (< 5 minutes)
1. Set feature flag `ENABLE_OAUTH_DEPENDENCIES=false`
2. Restart application servers
3. Verify existing authentication still works

### Full Rollback (< 15 minutes)
1. Deploy previous version of `auth_check.py`
2. Clear Redis permission cache
3. Restart all services
4. Run smoke tests to verify functionality

## Definition of Done

- [ ] ✅ Permission dependency factory implemented and tested
- [ ] ✅ All three permission levels (read/write/admin) working
- [ ] ✅ Integration with existing `current_user` dependency
- [ ] ✅ Proper HTTP 403 responses with consistent format
- [ ] ✅ Permission hierarchy correctly enforced
- [ ] ✅ Unit tests achieving 100% code coverage
- [ ] ✅ Integration tests covering all permission scenarios
- [ ] ✅ Performance tests showing < 10ms latency
- [ ] ✅ Security review completed and approved
- [ ] ✅ Documentation updated for developers
- [ ] ✅ Deployment checklist verified
- [ ] ✅ Monitoring and alerting configured
- [ ] ✅ Rollback plan tested and documented

## Risk Assessment

**High Risk**: Changes to authentication flow could break existing API access  
**Mitigation**: Feature flags, comprehensive testing, gradual rollout

**Medium Risk**: Performance impact from additional permission checks  
**Mitigation**: Redis caching, performance monitoring, load testing

**Low Risk**: Cache-related issues  
**Mitigation**: Fallback to database, cache invalidation strategies

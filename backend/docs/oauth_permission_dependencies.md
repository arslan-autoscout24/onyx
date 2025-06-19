# OAuth Permission Dependencies - Developer Guide

## Overview

This guide explains how to use the OAuth permission dependencies introduced in Story 3.1. These dependencies provide a declarative way to protect API endpoints based on OAuth permission levels, with automatic integration into the existing authentication system.

## Quick Start

### Basic Usage

The simplest way to protect an endpoint is to use one of the pre-configured dependencies:

```python
from fastapi import APIRouter, Depends
from onyx.server.auth_check import require_read, require_write, require_admin
from onyx.db.models import User

router = APIRouter()

@router.get("/public-data")
async def get_public_data(user: User = Depends(require_read)):
    """Requires read permission or higher"""
    return {"data": "public information"}

@router.post("/create-data")
async def create_data(user: User = Depends(require_write)):
    """Requires write permission or higher"""
    return {"message": "data created"}

@router.delete("/admin-action")
async def admin_action(user: User = Depends(require_admin)):
    """Requires admin permission"""
    return {"message": "admin action completed"}
```

### Permission Hierarchy

The permission system enforces a hierarchy:
- **admin** (level 3): Can access admin, write, and read endpoints
- **write** (level 2): Can access write and read endpoints  
- **read** (level 1): Can only access read endpoints

## Available Dependencies

### Pre-configured Dependencies

| Dependency | Required Permission | Use Case |
|------------|-------------------|----------|
| `require_read` | read or higher | Viewing data, search, analytics |
| `require_write` | write or higher | Creating, updating resources |
| `require_admin` | admin only | User management, system config |

### Advanced Dependencies

#### Optional Permission Checking

Use `optional_permission` when you need conditional logic based on permission level:

```python
from onyx.server.auth_check import optional_permission
from typing import Optional

@router.get("/dashboard")
async def get_dashboard(
    user: User = Depends(current_user),
    permission: Optional[str] = Depends(optional_permission)
):
    if permission == "admin":
        return {"view": "admin_dashboard", "data": get_admin_data()}
    elif permission == "write":
        return {"view": "editor_dashboard", "data": get_editor_data()}
    else:
        return {"view": "reader_dashboard", "data": get_public_data()}
```

#### Custom Permission Factory

Create custom permission dependencies for specific levels:

```python
from onyx.server.auth_check import require_permission

# Custom dependency for a specific permission level
require_moderator = require_permission("moderator")  # If you add new levels

@router.post("/moderate-content")
async def moderate_content(user: User = Depends(require_moderator)):
    return {"message": "content moderated"}
```

#### Manual Permission Checking

Use `has_permission()` for complex authorization logic:

```python
from onyx.server.auth_check import has_permission, optional_permission

@router.put("/resource/{resource_id}")
async def update_resource(
    resource_id: str,
    user: User = Depends(current_user),
    user_permission: Optional[str] = Depends(optional_permission)
):
    # Get resource ownership
    resource = get_resource(resource_id)
    is_owner = resource.owner_id == user.id
    
    # Complex permission logic
    if is_owner and has_permission(user_permission, "write"):
        # Owner with write permission can update
        return update_resource_data(resource_id)
    elif has_permission(user_permission, "admin"):
        # Admin can update any resource
        return update_resource_data(resource_id)
    else:
        raise HTTPException(403, "Insufficient permissions")
```

## Error Handling

### Standard Error Response

When a user lacks sufficient permissions, they receive a standardized 403 response:

```json
{
    "detail": "Insufficient permissions. Required: write, Current: read",
    "error_code": "INSUFFICIENT_OAUTH_PERMISSIONS",
    "required_action": "Contact administrator to update your permissions",
    "support_email": "support@yourcompany.com"
}
```

### Custom Error Handling

You can catch and handle permission errors in your endpoints:

```python
from fastapi import HTTPException

@router.post("/sensitive-action")
async def sensitive_action(user: User = Depends(require_admin)):
    try:
        # Your endpoint logic here
        return {"message": "action completed"}
    except HTTPException as e:
        if e.status_code == 403:
            # Log the permission denial
            logger.warning(f"User {user.email} denied access to sensitive action")
        raise
```

## Performance Considerations

### Caching

Permission lookups are automatically cached in Redis with a 5-minute TTL:
- First request: Database lookup + cache store
- Subsequent requests: Cache hit (< 1ms response time)
- Cache hit rate: > 95% in typical usage

### Cache Invalidation

When user permissions change, invalidate their cache:

```python
from onyx.server.auth_check import invalidate_user_permission_cache

async def update_user_permissions(user_id: str, new_permission: str):
    # Update permissions in database
    await update_oauth_permission(user_id, new_permission)
    
    # Invalidate cache
    await invalidate_user_permission_cache(user_id)
```

## Security Best Practices

### 1. Always Use Dependencies

Don't manually check permissions in endpoint bodies. Use dependencies:

```python
# ❌ Bad - manual checking
@router.get("/data")
async def get_data(user: User = Depends(current_user)):
    if not has_admin_permission(user):
        raise HTTPException(403, "Access denied")
    return get_sensitive_data()

# ✅ Good - use dependency
@router.get("/data")
async def get_data(user: User = Depends(require_admin)):
    return get_sensitive_data()
```

### 2. Principle of Least Privilege

Use the minimum required permission level:

```python
# ❌ Bad - unnecessarily high permission
@router.get("/public-stats")
async def get_stats(user: User = Depends(require_admin)):
    return get_public_statistics()

# ✅ Good - minimum required permission
@router.get("/public-stats")  
async def get_stats(user: User = Depends(require_read)):
    return get_public_statistics()
```

### 3. Combine with Existing Auth

OAuth permissions work alongside existing authentication:

```python
@router.get("/user-specific-data")
async def get_user_data(
    user: User = Depends(require_read),  # OAuth permission check
    db_session: Session = Depends(get_session)
):
    # Additional access control based on user identity
    if not user_can_access_data(user, requested_data):
        raise HTTPException(403, "Access denied to this specific data")
    
    return get_data_for_user(user.id)
```

## Testing

### Unit Tests

Test your permission-protected endpoints:

```python
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

def test_endpoint_with_sufficient_permission(client):
    with patch('onyx.server.auth_check.get_oauth_permission') as mock_perm:
        mock_perm.return_value = "write"
        
        response = client.post("/create-resource")
        assert response.status_code == 200

def test_endpoint_with_insufficient_permission(client):
    with patch('onyx.server.auth_check.get_oauth_permission') as mock_perm:
        mock_perm.return_value = "read"
        
        response = client.post("/create-resource")  # Requires write
        assert response.status_code == 403
```

### Integration Tests

Test permission dependencies with real database:

```python
@pytest.mark.integration
def test_permission_integration(client, test_user_with_write_permission):
    # Test with real user who has write permission in database
    with authenticated_user(test_user_with_write_permission):
        response = client.post("/create-resource", json={"name": "test"})
        assert response.status_code == 200
```

## Migration Guide

### Updating Existing Endpoints

To add OAuth permissions to existing endpoints:

```python
# Before
@router.get("/documents")
async def get_documents(user: User = Depends(current_user)):
    return get_user_documents(user)

# After  
@router.get("/documents")
async def get_documents(user: User = Depends(require_read)):
    return get_user_documents(user)
```

### Gradual Rollout

Use feature flags to gradually roll out permission checking:

```python
from onyx.configs.app_configs import OAUTH_PERMISSIONS_ENABLED

@router.get("/documents")
async def get_documents(
    user: User = Depends(require_read if OAUTH_PERMISSIONS_ENABLED else current_user)
):
    return get_user_documents(user)
```

## Troubleshooting

### Common Issues

#### 1. Permission Check Too Slow
```
Solution: Check Redis configuration and cache hit rates
Debug: Enable debug logging to see cache miss patterns
```

#### 2. User Getting 403 Unexpectedly
```
Solution: Check user's OAuth permission in database
Debug: Look for cache invalidation issues
```

#### 3. Endpoints Not Recognizing New Dependencies
```
Solution: Ensure auth_check.py imports new dependencies properly
Debug: Check router registration includes permission dependencies
```

### Debug Logging

Enable debug logging to troubleshoot permission issues:

```python
import logging
logging.getLogger('onyx.server.auth_check').setLevel(logging.DEBUG)
```

## API Reference

### Functions

#### `require_permission(level: str) -> Callable`
Factory function to create permission dependencies.

**Parameters:**
- `level`: Required permission level ('read', 'write', 'admin')

**Returns:** Dependency function that validates user permission

**Example:**
```python
require_custom = require_permission("custom_level")
```

#### `has_permission(user_permission: str, required_permission: str) -> bool`
Check if user permission meets requirement.

**Parameters:**
- `user_permission`: User's current permission level
- `required_permission`: Required permission level

**Returns:** True if user has sufficient permission

#### `invalidate_user_permission_cache(user_id: str) -> None`
Invalidate cached permission for a user.

**Parameters:**
- `user_id`: UUID of user whose cache should be invalidated

### Pre-configured Dependencies

- `require_read`: Requires read permission or higher
- `require_write`: Requires write permission or higher  
- `require_admin`: Requires admin permission
- `optional_permission`: Returns permission level without failing

## Examples

See `onyx/server/examples/oauth_permission_examples.py` for complete working examples of all permission dependency patterns.

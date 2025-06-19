# Story 4.1: Admin API Permission Protection

**Priority**: P0 - Critical  
**Estimate**: 1.5 days  
**Dependencies**: Story 3.1 (Permission Dependencies)  
**Sprint**: 4 - Admin Protection & Testing

## Description

Apply admin-level OAuth permissions to administrative endpoints, ensuring only users with admin privileges can access sensitive system management functions.

## Acceptance Criteria

- [ ] Connector management endpoints require `admin` permission
- [ ] User management endpoints require `admin` permission  
- [ ] System configuration endpoints require `admin` permission
- [ ] All admin endpoints return 403 for non-admin users
- [ ] Integration tests for admin endpoint protection
- [ ] Audit logging for all admin operations
- [ ] Performance impact < 50ms per admin request
- [ ] Backward compatibility maintained for existing admin flows

## Technical Implementation

### Core Changes

#### 1. Connector Management Protection
```python
# File: backend/onyx/server/manage/connector.py
from onyx.auth.oauth_dependencies import require_admin

@router.post("/admin/connector")
async def create_connector(
    connector_data: ConnectorBase,
    user: User = Depends(require_admin)
):
    """Create a new connector - requires admin permission."""
    logger.info(f"Admin {user.id} creating connector: {connector_data.name}")
    # ...existing implementation...

@router.put("/admin/connector/{connector_id}")
async def update_connector(
    connector_id: int,
    connector_data: ConnectorBase,
    user: User = Depends(require_admin)
):
    """Update connector configuration - requires admin permission."""
    logger.info(f"Admin {user.id} updating connector: {connector_id}")
    # ...existing implementation...

@router.delete("/admin/connector/{connector_id}")
async def delete_connector(
    connector_id: int,
    user: User = Depends(require_admin)
):
    """Delete a connector - requires admin permission."""
    logger.info(f"Admin {user.id} deleting connector: {connector_id}")
    # ...existing implementation...

@router.get("/admin/connector")
async def list_connectors(user: User = Depends(require_admin)):
    """List all connectors - requires admin permission."""
    # ...existing implementation...
```

#### 2. User Management Protection  
```python
# File: backend/onyx/server/manage/users.py
from onyx.auth.oauth_dependencies import require_admin

@router.get("/admin/users")
async def get_users(user: User = Depends(require_admin)):
    """Get all users - requires admin permission."""
    logger.info(f"Admin {user.id} retrieving user list")
    # ...existing implementation...

@router.get("/admin/users/{user_id}")
async def get_user(
    user_id: UUID,
    admin: User = Depends(require_admin)
):
    """Get specific user details - requires admin permission."""
    logger.info(f"Admin {admin.id} retrieving user: {user_id}")
    # ...existing implementation...

@router.put("/admin/users/{user_id}/role")
async def update_user_role(
    user_id: UUID,
    role_data: UserRoleUpdate,
    admin: User = Depends(require_admin)
):
    """Update user role - requires admin permission."""
    logger.info(f"Admin {admin.id} updating role for user: {user_id}")
    # ...existing implementation...

@router.delete("/admin/users/{user_id}")
async def deactivate_user(
    user_id: UUID,
    admin: User = Depends(require_admin)
):
    """Deactivate a user - requires admin permission."""
    logger.info(f"Admin {admin.id} deactivating user: {user_id}")
    # ...existing implementation...
```

#### 3. System Configuration Protection
```python
# File: backend/onyx/server/manage/settings.py
from onyx.auth.oauth_dependencies import require_admin

@router.get("/admin/settings")
async def get_system_settings(user: User = Depends(require_admin)):
    """Get system configuration - requires admin permission."""
    logger.info(f"Admin {user.id} retrieving system settings")
    # ...existing implementation...

@router.put("/admin/settings")
async def update_system_settings(
    settings: SystemSettings,
    user: User = Depends(require_admin)
):
    """Update system configuration - requires admin permission."""
    logger.info(f"Admin {user.id} updating system settings")
    # ...existing implementation...

@router.get("/admin/analytics")
async def get_system_analytics(user: User = Depends(require_admin)):
    """Get system analytics - requires admin permission."""
    logger.info(f"Admin {user.id} retrieving analytics")
    # ...existing implementation...
```

#### 4. Enhanced Error Handling
```python
# File: backend/onyx/auth/oauth_dependencies.py (enhancement)
from fastapi import HTTPException, status
from onyx.utils.logger import setup_logger

logger = setup_logger()

async def require_admin(current_user: User = Depends(current_user)) -> User:
    """Dependency that ensures user has admin permissions."""
    try:
        user_permissions = await get_user_oauth_permissions(current_user.id)
        
        if user_permissions.permission_level != PermissionLevel.ADMIN:
            logger.warning(
                f"Access denied: User {current_user.id} attempted admin operation "
                f"with permission level: {user_permissions.permission_level}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "admin_permission_required",
                    "message": "This operation requires admin privileges",
                    "required_permission": "admin",
                    "user_permission": user_permissions.permission_level.value
                }
            )
        
        # Log successful admin access
        logger.info(f"Admin access granted to user {current_user.id}")
        return current_user
        
    except Exception as e:
        logger.error(f"Error checking admin permissions for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error verifying admin permissions"
        )
```

### Database Changes

#### Admin Audit Logging
```python
# File: backend/onyx/db/models.py (enhancement)
class AdminAuditLog(Base):
    __tablename__ = "admin_audit_log"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    admin_user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    action: Mapped[str] = mapped_column(String(100))
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[Optional[str]] = mapped_column(String(100))
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(500))
    
    admin_user: Mapped["User"] = relationship("User")
```

#### Migration Script
```python
# File: backend/alembic/versions/xxx_add_admin_audit_log.py
"""Add admin audit log table

Revision ID: xxx
Revises: previous_revision
Create Date: 2025-06-08 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'xxx'
down_revision = 'previous_revision'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('admin_audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('admin_user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.String(length=100), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(['admin_user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_admin_audit_log_admin_user_id', 'admin_audit_log', ['admin_user_id'])
    op.create_index('ix_admin_audit_log_timestamp', 'admin_audit_log', ['timestamp'])

def downgrade():
    op.drop_index('ix_admin_audit_log_timestamp', table_name='admin_audit_log')
    op.drop_index('ix_admin_audit_log_admin_user_id', table_name='admin_audit_log')
    op.drop_table('admin_audit_log')
```

## Testing Requirements

### Unit Tests
```python
# File: backend/tests/unit/auth/test_admin_dependencies.py
import pytest
from unittest.mock import Mock, patch
from fastapi import HTTPException
from onyx.auth.oauth_dependencies import require_admin
from onyx.db.models import User, OAuthPermission, PermissionLevel

@pytest.mark.asyncio
async def test_require_admin_with_admin_user():
    """Test admin dependency with valid admin user."""
    admin_user = Mock(spec=User)
    admin_user.id = "admin-123"
    
    with patch('onyx.auth.oauth_dependencies.get_user_oauth_permissions') as mock_get_perms:
        mock_permission = Mock()
        mock_permission.permission_level = PermissionLevel.ADMIN
        mock_get_perms.return_value = mock_permission
        
        result = await require_admin(admin_user)
        assert result == admin_user

@pytest.mark.asyncio
async def test_require_admin_with_non_admin_user():
    """Test admin dependency rejects non-admin users."""
    regular_user = Mock(spec=User)
    regular_user.id = "user-123"
    
    with patch('onyx.auth.oauth_dependencies.get_user_oauth_permissions') as mock_get_perms:
        mock_permission = Mock()
        mock_permission.permission_level = PermissionLevel.WRITE
        mock_get_perms.return_value = mock_permission
        
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(regular_user)
        
        assert exc_info.value.status_code == 403
        assert "admin_permission_required" in str(exc_info.value.detail)

@pytest.mark.asyncio
async def test_require_admin_handles_permission_error():
    """Test admin dependency handles permission lookup errors."""
    user = Mock(spec=User)
    user.id = "user-123"
    
    with patch('onyx.auth.oauth_dependencies.get_user_oauth_permissions') as mock_get_perms:
        mock_get_perms.side_effect = Exception("Database error")
        
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(user)
        
        assert exc_info.value.status_code == 500
```

### Integration Tests
```python
# File: backend/tests/integration/test_admin_api_protection.py
import pytest
from fastapi.testclient import TestClient
from onyx.main import app
from tests.helpers.auth import create_test_admin, create_test_user

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin_user():
    return create_test_admin("admin@example.com")

@pytest.fixture
def regular_user():
    return create_test_user("user@example.com", permission_level="write")

def test_admin_connector_creation_requires_admin(client, admin_user, regular_user):
    """Test that connector creation requires admin permission."""
    connector_data = {
        "name": "Test Connector",
        "source": "file",
        "connector_specific_config": {}
    }
    
    # Admin can create connector
    admin_response = client.post(
        "/admin/connector",
        json=connector_data,
        headers={"Authorization": f"Bearer {admin_user.token}"}
    )
    assert admin_response.status_code == 200
    
    # Regular user cannot create connector
    user_response = client.post(
        "/admin/connector", 
        json=connector_data,
        headers={"Authorization": f"Bearer {regular_user.token}"}
    )
    assert user_response.status_code == 403
    assert "admin_permission_required" in user_response.json()["detail"]["error"]

def test_admin_user_management_requires_admin(client, admin_user, regular_user):
    """Test that user management requires admin permission."""
    # Admin can list users
    admin_response = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_user.token}"}
    )
    assert admin_response.status_code == 200
    
    # Regular user cannot list users
    user_response = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {regular_user.token}"}
    )
    assert user_response.status_code == 403

def test_admin_settings_requires_admin(client, admin_user, regular_user):
    """Test that system settings require admin permission."""
    # Admin can access settings
    admin_response = client.get(
        "/admin/settings",
        headers={"Authorization": f"Bearer {admin_user.token}"}
    )
    assert admin_response.status_code == 200
    
    # Regular user cannot access settings
    user_response = client.get(
        "/admin/settings",
        headers={"Authorization": f"Bearer {regular_user.token}"}
    )
    assert user_response.status_code == 403

@pytest.mark.asyncio
async def test_admin_audit_logging(client, admin_user):
    """Test that admin operations are properly logged."""
    connector_data = {
        "name": "Audit Test Connector",
        "source": "file",
        "connector_specific_config": {}
    }
    
    response = client.post(
        "/admin/connector",
        json=connector_data,
        headers={"Authorization": f"Bearer {admin_user.token}"}
    )
    assert response.status_code == 200
    
    # Verify audit log entry was created
    # (This would require database query in actual implementation)
```

### Performance Tests
```python
# File: backend/tests/performance/test_admin_permission_performance.py
import pytest
import time
from fastapi.testclient import TestClient
from onyx.main import app

def test_admin_permission_check_performance():
    """Test that admin permission checks are fast."""
    client = TestClient(app)
    admin_token = "admin_test_token"
    
    start_time = time.time()
    
    # Make 100 admin requests
    for _ in range(100):
        response = client.get(
            "/admin/settings",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
    
    end_time = time.time()
    avg_time_ms = ((end_time - start_time) / 100) * 1000
    
    # Assert average response time is under 50ms
    assert avg_time_ms < 50, f"Admin permission check took {avg_time_ms}ms on average"
```

## Security Considerations

### Access Control
- **Principle of Least Privilege**: Only grant admin access to necessary users
- **Multi-Factor Authentication**: Recommend MFA for admin users
- **Session Management**: Admin sessions should have shorter timeouts
- **IP Restriction**: Consider restricting admin access to specific IP ranges

### Audit Requirements
- **Complete Logging**: All admin operations must be logged
- **Immutable Logs**: Audit logs should be tamper-proof
- **Retention Policy**: Admin logs retained for compliance requirements
- **Alert System**: Real-time alerts for suspicious admin activity

### Error Handling
- **Information Disclosure**: Error messages should not reveal system internals
- **Rate Limiting**: Implement rate limiting for admin endpoints
- **Fail Secure**: Default to denying access on permission errors

## Performance Requirements

### Response Time Targets
- **Admin Permission Check**: < 50ms
- **Admin Endpoint Response**: < 500ms (excluding business logic)
- **Audit Log Write**: < 10ms (asynchronous)

### Scalability
- **Concurrent Admin Users**: Support 10+ simultaneous admin users
- **Permission Cache**: 95%+ cache hit rate for permission checks
- **Database Impact**: < 10% increase in database load

## Deployment Procedures

### Pre-Deployment Checklist
- [ ] Run all unit tests
- [ ] Run integration tests
- [ ] Test admin permission enforcement in staging
- [ ] Verify audit logging works correctly
- [ ] Test error handling scenarios
- [ ] Validate performance requirements
- [ ] Review security configurations

### Deployment Steps
1. **Database Migration**: Apply admin audit log table migration
2. **Code Deployment**: Deploy updated admin endpoint code
3. **Feature Flag**: Enable admin permission enforcement
4. **Monitoring**: Monitor for errors and performance issues
5. **Validation**: Test admin operations in production

### Rollback Plan
1. **Immediate**: Disable admin permission enforcement via feature flag
2. **Code Rollback**: Revert to previous code version if needed
3. **Database Rollback**: Rollback audit log table migration if necessary
4. **Verification**: Ensure admin functionality restored

### Monitoring & Alerts
- **Permission Denied Errors**: Alert on 403 errors for admin endpoints
- **Performance Degradation**: Alert if response times exceed thresholds
- **Failed Permission Checks**: Alert on permission lookup failures
- **Suspicious Activity**: Alert on unusual admin access patterns

## Definition of Done

### Functional Requirements ✅
- [ ] All admin endpoints protected with `require_admin` dependency
- [ ] Non-admin users receive 403 errors for admin endpoints
- [ ] Admin users can access all protected endpoints
- [ ] Audit logging captures all admin operations
- [ ] Error handling provides appropriate responses

### Quality Requirements ✅
- [ ] Unit test coverage > 95% for admin permission code
- [ ] Integration tests cover all admin endpoints
- [ ] Performance tests validate response time requirements
- [ ] Security review completed and approved
- [ ] Code review completed by senior developer

### Documentation Requirements ✅
- [ ] API documentation updated with admin permission requirements
- [ ] Security documentation updated with admin access controls
- [ ] Deployment guide includes admin protection steps
- [ ] Troubleshooting guide covers admin permission issues

### Deployment Requirements ✅
- [ ] Staging environment validates all requirements
- [ ] Production deployment plan reviewed and approved
- [ ] Rollback procedures tested and documented
- [ ] Monitoring and alerting configured
- [ ] Security team approval obtained

---

**Story Dependencies**: This story builds on Story 3.1 (Permission Dependencies) and enables comprehensive admin protection across the system. It's critical for the security model and must be completed before Story 4.3 (End-to-End Integration Testing).

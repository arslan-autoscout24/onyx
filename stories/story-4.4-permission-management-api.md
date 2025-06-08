# Story 4.4: Permission Management API

**Priority**: P2 - Medium  
**Estimate**: 1.5 days  
**Dependencies**: Story 4.1 (Admin API Protection)  
**Sprint**: 4 - Admin Protection & Testing

## Description

Create API endpoints for viewing and managing user permissions, providing administrators with tools to understand and manage the OAuth authorization system.

## Acceptance Criteria

- [ ] GET `/auth/permissions` - view current user's permissions
- [ ] GET `/admin/users/{id}/permissions` - admin view of user permissions
- [ ] API responses include permission level and Okta groups
- [ ] Admin can view all users and their permission levels
- [ ] Integration tests for permission management endpoints
- [ ] Permission history tracking
- [ ] Bulk permission operations for admins
- [ ] Export/import permission configurations

## Technical Implementation

### Core API Endpoints

#### 1. User Permission Viewing
```python
# File: backend/onyx/server/auth/permissions.py (new file)
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from onyx.auth.oauth_dependencies import current_user, require_admin
from onyx.auth.oauth_permissions import get_user_oauth_permissions
from onyx.db.models import User, OAuthPermission, PermissionLevel
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/auth", tags=["permissions"])

class UserPermissionResponse(BaseModel):
    """Response model for user permission information."""
    user_id: UUID
    email: str
    permission_level: PermissionLevel
    okta_groups: List[str]
    granted_at: datetime
    last_updated: datetime
    source: str  # 'okta', 'manual', etc.
    is_active: bool

class PermissionHistoryEntry(BaseModel):
    """Model for permission history tracking."""
    id: int
    user_id: UUID
    previous_level: Optional[PermissionLevel]
    new_level: PermissionLevel
    changed_by: UUID
    changed_at: datetime
    reason: str
    okta_groups_before: List[str]
    okta_groups_after: List[str]

@router.get("/permissions", response_model=UserPermissionResponse)
async def get_current_user_permissions(
    current_user: User = Depends(current_user)
) -> UserPermissionResponse:
    """Get current user's OAuth permissions and group memberships."""
    try:
        user_permissions = await get_user_oauth_permissions(current_user.id)
        
        if not user_permissions:
            logger.warning(f"No OAuth permissions found for user {current_user.id}")
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "permissions_not_found",
                    "message": "No OAuth permissions found for user",
                    "user_id": str(current_user.id)
                }
            )
        
        logger.info(f"Retrieved permissions for user {current_user.id}: {user_permissions.permission_level}")
        
        return UserPermissionResponse(
            user_id=current_user.id,
            email=current_user.email,
            permission_level=user_permissions.permission_level,
            okta_groups=user_permissions.okta_groups or [],
            granted_at=user_permissions.created_at,
            last_updated=user_permissions.updated_at,
            source=user_permissions.source or "okta",
            is_active=user_permissions.is_active
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving permissions for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving user permissions"
        )

@router.get("/permissions/history", response_model=List[PermissionHistoryEntry])
async def get_current_user_permission_history(
    current_user: User = Depends(current_user),
    limit: int = Query(50, ge=1, le=100)
) -> List[PermissionHistoryEntry]:
    """Get current user's permission change history."""
    try:
        # Implementation would query permission history table
        history = await get_permission_history(current_user.id, limit)
        logger.info(f"Retrieved {len(history)} permission history entries for user {current_user.id}")
        return history
        
    except Exception as e:
        logger.error(f"Error retrieving permission history for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving permission history"
        )
```

#### 2. Admin Permission Management
```python
# File: backend/onyx/server/auth/permissions.py (continued)
class BulkPermissionUpdate(BaseModel):
    """Model for bulk permission updates."""
    user_ids: List[UUID]
    permission_level: PermissionLevel
    reason: str

class PermissionSummary(BaseModel):
    """Summary of all user permissions."""
    total_users: int
    admin_users: int
    write_users: int
    read_users: int
    inactive_users: int
    recent_changes: int  # Changes in last 24 hours

@router.get("/admin/users/{user_id}/permissions", response_model=UserPermissionResponse)
async def get_user_permissions(
    user_id: UUID,
    admin: User = Depends(require_admin)
) -> UserPermissionResponse:
    """Get specific user's permissions - requires admin permission."""
    try:
        # Verify user exists
        target_user = await get_user_by_id(user_id)
        if not target_user:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "user_not_found",
                    "message": f"User with ID {user_id} not found"
                }
            )
        
        user_permissions = await get_user_oauth_permissions(user_id)
        
        if not user_permissions:
            logger.warning(f"No OAuth permissions found for user {user_id}")
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "permissions_not_found",
                    "message": "No OAuth permissions found for user"
                }
            )
        
        logger.info(f"Admin {admin.id} retrieved permissions for user {user_id}")
        
        return UserPermissionResponse(
            user_id=target_user.id,
            email=target_user.email,
            permission_level=user_permissions.permission_level,
            okta_groups=user_permissions.okta_groups or [],
            granted_at=user_permissions.created_at,
            last_updated=user_permissions.updated_at,
            source=user_permissions.source or "okta",
            is_active=user_permissions.is_active
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving permissions for user {user_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving user permissions"
        )

@router.get("/admin/permissions/summary", response_model=PermissionSummary)
async def get_permissions_summary(
    admin: User = Depends(require_admin)
) -> PermissionSummary:
    """Get summary of all user permissions - requires admin permission."""
    try:
        summary = await calculate_permission_summary()
        logger.info(f"Admin {admin.id} retrieved permission summary")
        return summary
        
    except Exception as e:
        logger.error(f"Error calculating permission summary: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving permission summary"
        )

@router.get("/admin/users/permissions", response_model=List[UserPermissionResponse])
async def list_all_user_permissions(
    admin: User = Depends(require_admin),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    permission_level: Optional[PermissionLevel] = Query(None),
    search: Optional[str] = Query(None)
) -> List[UserPermissionResponse]:
    """List all users and their permissions - requires admin permission."""
    try:
        filters = {}
        if permission_level:
            filters['permission_level'] = permission_level
        if search:
            filters['email_search'] = search
        
        users_with_permissions = await get_all_users_with_permissions(
            limit=limit,
            offset=offset,
            filters=filters
        )
        
        logger.info(
            f"Admin {admin.id} retrieved {len(users_with_permissions)} user permissions "
            f"(limit: {limit}, offset: {offset})"
        )
        
        return users_with_permissions
        
    except Exception as e:
        logger.error(f"Error listing user permissions: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving user permissions list"
        )

@router.put("/admin/users/{user_id}/permissions")
async def update_user_permissions(
    user_id: UUID,
    permission_update: PermissionUpdate,
    admin: User = Depends(require_admin)
) -> UserPermissionResponse:
    """Update user's permissions - requires admin permission."""
    try:
        # Verify target user exists
        target_user = await get_user_by_id(user_id)
        if not target_user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        # Get current permissions for history
        current_permissions = await get_user_oauth_permissions(user_id)
        
        # Update permissions
        updated_permissions = await update_user_oauth_permissions(
            user_id=user_id,
            new_level=permission_update.permission_level,
            updated_by=admin.id,
            reason=permission_update.reason
        )
        
        # Log permission change
        await log_permission_change(
            user_id=user_id,
            previous_level=current_permissions.permission_level if current_permissions else None,
            new_level=permission_update.permission_level,
            changed_by=admin.id,
            reason=permission_update.reason
        )
        
        logger.info(
            f"Admin {admin.id} updated permissions for user {user_id}: "
            f"{current_permissions.permission_level if current_permissions else 'None'} → "
            f"{permission_update.permission_level}"
        )
        
        return UserPermissionResponse(
            user_id=target_user.id,
            email=target_user.email,
            permission_level=updated_permissions.permission_level,
            okta_groups=updated_permissions.okta_groups or [],
            granted_at=updated_permissions.created_at,
            last_updated=updated_permissions.updated_at,
            source="manual",
            is_active=updated_permissions.is_active
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating permissions for user {user_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error updating user permissions"
        )

@router.post("/admin/permissions/bulk-update")
async def bulk_update_permissions(
    bulk_update: BulkPermissionUpdate,
    admin: User = Depends(require_admin)
) -> Dict[str, Any]:
    """Bulk update permissions for multiple users - requires admin permission."""
    try:
        if len(bulk_update.user_ids) > 100:
            raise HTTPException(
                status_code=400,
                detail="Cannot update more than 100 users at once"
            )
        
        results = {
            "successful_updates": [],
            "failed_updates": [],
            "total_requested": len(bulk_update.user_ids)
        }
        
        for user_id in bulk_update.user_ids:
            try:
                # Update individual user permissions
                await update_user_oauth_permissions(
                    user_id=user_id,
                    new_level=bulk_update.permission_level,
                    updated_by=admin.id,
                    reason=bulk_update.reason
                )
                
                # Log the change
                await log_permission_change(
                    user_id=user_id,
                    previous_level=None,  # Would need to fetch current level
                    new_level=bulk_update.permission_level,
                    changed_by=admin.id,
                    reason=f"Bulk update: {bulk_update.reason}"
                )
                
                results["successful_updates"].append(str(user_id))
                
            except Exception as user_error:
                logger.error(f"Failed to update permissions for user {user_id}: {user_error}")
                results["failed_updates"].append({
                    "user_id": str(user_id),
                    "error": str(user_error)
                })
        
        logger.info(
            f"Admin {admin.id} performed bulk permission update: "
            f"{len(results['successful_updates'])} successful, "
            f"{len(results['failed_updates'])} failed"
        )
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in bulk permission update: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error performing bulk permission update"
        )
```

#### 3. Permission Export/Import
```python
# File: backend/onyx/server/auth/permissions.py (continued)
from fastapi import UploadFile, File
from fastapi.responses import StreamingResponse
import csv
import io

class PermissionExportEntry(BaseModel):
    """Model for permission export entries."""
    email: str
    permission_level: str
    okta_groups: str  # Comma-separated
    granted_at: str
    last_updated: str
    is_active: bool

@router.get("/admin/permissions/export")
async def export_permissions(
    admin: User = Depends(require_admin),
    format: str = Query("csv", regex="^(csv|json)$")
) -> StreamingResponse:
    """Export all user permissions - requires admin permission."""
    try:
        users_with_permissions = await get_all_users_with_permissions()
        
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                "email", "permission_level", "okta_groups", 
                "granted_at", "last_updated", "is_active"
            ])
            
            # Write data
            for user_perm in users_with_permissions:
                writer.writerow([
                    user_perm.email,
                    user_perm.permission_level.value,
                    ",".join(user_perm.okta_groups),
                    user_perm.granted_at.isoformat(),
                    user_perm.last_updated.isoformat(),
                    user_perm.is_active
                ])
            
            output.seek(0)
            
            def generate():
                yield output.getvalue()
            
            logger.info(f"Admin {admin.id} exported {len(users_with_permissions)} permission records as CSV")
            
            return StreamingResponse(
                generate(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=user_permissions.csv"}
            )
            
        elif format == "json":
            export_data = {
                "exported_at": datetime.utcnow().isoformat(),
                "exported_by": admin.email,
                "total_records": len(users_with_permissions),
                "permissions": [
                    {
                        "email": up.email,
                        "permission_level": up.permission_level.value,
                        "okta_groups": up.okta_groups,
                        "granted_at": up.granted_at.isoformat(),
                        "last_updated": up.last_updated.isoformat(),
                        "is_active": up.is_active
                    }
                    for up in users_with_permissions
                ]
            }
            
            def generate():
                yield json.dumps(export_data, indent=2)
            
            logger.info(f"Admin {admin.id} exported {len(users_with_permissions)} permission records as JSON")
            
            return StreamingResponse(
                generate(),
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=user_permissions.json"}
            )
            
    except Exception as e:
        logger.error(f"Error exporting permissions: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error exporting permissions"
        )

@router.post("/admin/permissions/import")
async def import_permissions(
    admin: User = Depends(require_admin),
    file: UploadFile = File(...),
    dry_run: bool = Query(False)
) -> Dict[str, Any]:
    """Import user permissions from CSV/JSON - requires admin permission."""
    try:
        if file.content_type not in ["text/csv", "application/json"]:
            raise HTTPException(
                status_code=400,
                detail="Only CSV and JSON files are supported"
            )
        
        content = await file.read()
        results = {
            "total_processed": 0,
            "successful_imports": [],
            "failed_imports": [],
            "dry_run": dry_run
        }
        
        if file.content_type == "text/csv":
            # Process CSV import
            csv_data = io.StringIO(content.decode('utf-8'))
            reader = csv.DictReader(csv_data)
            
            for row in reader:
                try:
                    results["total_processed"] += 1
                    
                    if not dry_run:
                        # Actually perform the import
                        user = await get_user_by_email(row["email"])
                        if user:
                            await update_user_oauth_permissions(
                                user_id=user.id,
                                new_level=PermissionLevel(row["permission_level"]),
                                updated_by=admin.id,
                                reason="Imported from CSV"
                            )
                    
                    results["successful_imports"].append(row["email"])
                    
                except Exception as row_error:
                    results["failed_imports"].append({
                        "email": row.get("email", "unknown"),
                        "error": str(row_error)
                    })
        
        logger.info(
            f"Admin {admin.id} {'simulated' if dry_run else 'performed'} permission import: "
            f"{len(results['successful_imports'])} successful, "
            f"{len(results['failed_imports'])} failed"
        )
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error importing permissions: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error importing permissions"
        )
```

### Database Enhancements

#### Permission History Tracking
```python
# File: backend/onyx/db/models.py (enhancement)
class PermissionHistory(Base):
    """Track permission changes for audit purposes."""
    __tablename__ = "permission_history"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    previous_level: Mapped[Optional[PermissionLevel]] = mapped_column()
    new_level: Mapped[PermissionLevel] = mapped_column()
    changed_by: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    reason: Mapped[str] = mapped_column(String(500))
    okta_groups_before: Mapped[Optional[List[str]]] = mapped_column(JSON)
    okta_groups_after: Mapped[Optional[List[str]]] = mapped_column(JSON)
    source: Mapped[str] = mapped_column(String(50), default="manual")  # 'okta', 'manual', 'import'
    
    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    changed_by_user: Mapped["User"] = relationship("User", foreign_keys=[changed_by])

# Migration for permission history
# File: backend/alembic/versions/xxx_add_permission_history.py
def upgrade():
    op.create_table('permission_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('previous_level', sa.Enum(PermissionLevel), nullable=True),
        sa.Column('new_level', sa.Enum(PermissionLevel), nullable=False),
        sa.Column('changed_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('changed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reason', sa.String(length=500), nullable=False),
        sa.Column('okta_groups_before', sa.JSON(), nullable=True),
        sa.Column('okta_groups_after', sa.JSON(), nullable=True),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.ForeignKeyConstraint(['changed_by'], ['user.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_permission_history_user_id', 'permission_history', ['user_id'])
    op.create_index('ix_permission_history_changed_at', 'permission_history', ['changed_at'])
```

## Testing Requirements

### Unit Tests
```python
# File: backend/tests/unit/auth/test_permission_management_api.py
import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from onyx.main import app
from onyx.db.models import User, OAuthPermission, PermissionLevel

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin_user():
    user = Mock(spec=User)
    user.id = "admin-123"
    user.email = "admin@test.com"
    return user

@pytest.fixture  
def regular_user():
    user = Mock(spec=User)
    user.id = "user-123"
    user.email = "user@test.com"
    return user

def test_get_current_user_permissions(client, regular_user):
    """Test getting current user's permissions."""
    with patch('onyx.auth.oauth_dependencies.current_user', return_value=regular_user), \
         patch('onyx.auth.oauth_permissions.get_user_oauth_permissions') as mock_get_perms:
        
        mock_permission = Mock()
        mock_permission.permission_level = PermissionLevel.READ
        mock_permission.okta_groups = ["Onyx-Readers"]
        mock_permission.created_at = datetime.utcnow()
        mock_permission.updated_at = datetime.utcnow()
        mock_permission.source = "okta"
        mock_permission.is_active = True
        mock_get_perms.return_value = mock_permission
        
        response = client.get("/auth/permissions")
        assert response.status_code == 200
        
        data = response.json()
        assert data["permission_level"] == "read"
        assert data["okta_groups"] == ["Onyx-Readers"]
        assert data["email"] == regular_user.email

def test_admin_get_user_permissions(client, admin_user):
    """Test admin getting another user's permissions."""
    target_user_id = "target-user-123"
    
    with patch('onyx.auth.oauth_dependencies.require_admin', return_value=admin_user), \
         patch('onyx.auth.oauth_permissions.get_user_by_id') as mock_get_user, \
         patch('onyx.auth.oauth_permissions.get_user_oauth_permissions') as mock_get_perms:
        
        target_user = Mock(spec=User)
        target_user.id = target_user_id
        target_user.email = "target@test.com"
        mock_get_user.return_value = target_user
        
        mock_permission = Mock()
        mock_permission.permission_level = PermissionLevel.WRITE
        mock_permission.okta_groups = ["Onyx-Writers"]
        mock_permission.created_at = datetime.utcnow()
        mock_permission.updated_at = datetime.utcnow()
        mock_permission.source = "okta"
        mock_permission.is_active = True
        mock_get_perms.return_value = mock_permission
        
        response = client.get(f"/auth/admin/users/{target_user_id}/permissions")
        assert response.status_code == 200
        
        data = response.json()
        assert data["permission_level"] == "write"
        assert data["email"] == "target@test.com"

def test_non_admin_cannot_access_admin_endpoints(client, regular_user):
    """Test that non-admin users cannot access admin permission endpoints."""
    with patch('onyx.auth.oauth_dependencies.require_admin', side_effect=HTTPException(status_code=403)):
        response = client.get("/auth/admin/users/123/permissions")
        assert response.status_code == 403

def test_permission_export(client, admin_user):
    """Test permission export functionality."""
    with patch('onyx.auth.oauth_dependencies.require_admin', return_value=admin_user), \
         patch('onyx.auth.oauth_permissions.get_all_users_with_permissions') as mock_get_all:
        
        mock_permissions = [
            Mock(
                email="user1@test.com",
                permission_level=PermissionLevel.READ,
                okta_groups=["Onyx-Readers"],
                granted_at=datetime.utcnow(),
                last_updated=datetime.utcnow(),
                is_active=True
            )
        ]
        mock_get_all.return_value = mock_permissions
        
        response = client.get("/auth/admin/permissions/export?format=csv")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"

def test_bulk_permission_update(client, admin_user):
    """Test bulk permission update functionality."""
    with patch('onyx.auth.oauth_dependencies.require_admin', return_value=admin_user), \
         patch('onyx.auth.oauth_permissions.update_user_oauth_permissions') as mock_update, \
         patch('onyx.auth.oauth_permissions.log_permission_change') as mock_log:
        
        bulk_data = {
            "user_ids": ["user1", "user2"],
            "permission_level": "write",
            "reason": "Promotion to write access"
        }
        
        response = client.post("/auth/admin/permissions/bulk-update", json=bulk_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["total_requested"] == 2
        assert len(data["successful_updates"]) == 2
```

### Integration Tests
```python
# File: backend/tests/integration/test_permission_management_integration.py
import pytest
from fastapi.testclient import TestClient
from onyx.main import app
from tests.helpers.auth import create_test_admin, create_test_user

def test_complete_permission_management_flow():
    """Test complete permission management workflow."""
    client = TestClient(app)
    
    # Create test users
    admin = create_test_admin("admin@test.com")
    user = create_test_user("user@test.com", permission_level="read")
    
    # Admin views user's permissions
    response = client.get(
        f"/auth/admin/users/{user.id}/permissions",
        headers={"Authorization": f"Bearer {admin.token}"}
    )
    assert response.status_code == 200
    assert response.json()["permission_level"] == "read"
    
    # Admin updates user's permissions
    update_data = {
        "permission_level": "write",
        "reason": "User needs write access for new role"
    }
    response = client.put(
        f"/auth/admin/users/{user.id}/permissions",
        json=update_data,
        headers={"Authorization": f"Bearer {admin.token}"}
    )
    assert response.status_code == 200
    assert response.json()["permission_level"] == "write"
    
    # Verify permission history was recorded
    response = client.get(
        f"/auth/admin/users/{user.id}/permissions/history",
        headers={"Authorization": f"Bearer {admin.token}"}
    )
    assert response.status_code == 200
    history = response.json()
    assert len(history) > 0
    assert history[0]["new_level"] == "write"
```

## Performance Requirements

### API Response Times
- **Single User Permissions**: < 100ms
- **Admin User List**: < 500ms (up to 100 users)
- **Permission Export**: < 2 seconds (up to 1000 users)
- **Bulk Updates**: < 5 seconds (up to 100 users)

### Database Performance
- **Permission Queries**: Use proper indexing for fast lookups
- **History Tracking**: Efficient insertion without blocking operations
- **Bulk Operations**: Batch database operations for performance

## Security Considerations

### Access Control
- **Admin Only**: All admin endpoints require admin permission
- **User Isolation**: Users can only view their own permissions
- **Audit Trail**: All permission changes are logged
- **Data Validation**: All inputs are validated and sanitized

### Sensitive Data
- **Permission History**: Include reason for all changes
- **Export Control**: Admin-only access to bulk data exports
- **Import Validation**: Validate all imported data before processing

## Deployment Procedures

### Pre-Deployment Checklist
- [ ] Database migration for permission history completed
- [ ] Unit tests pass for all permission management features
- [ ] Integration tests validate admin workflows
- [ ] Performance tests meet response time requirements
- [ ] Security review completed for new admin endpoints

### Deployment Steps
1. **Database Migration**: Apply permission history table
2. **API Deployment**: Deploy new permission management endpoints
3. **Feature Testing**: Validate admin permission management works
4. **Performance Validation**: Confirm response times meet requirements
5. **Security Verification**: Test admin access controls

### Monitoring & Alerts
- **Admin Operations**: Monitor permission changes and exports
- **Performance**: Track API response times
- **Security**: Alert on unusual admin activity patterns
- **Data Integrity**: Monitor permission consistency

## Definition of Done

### Functional Requirements ✅
- [ ] Users can view their own permissions via API
- [ ] Admins can view and manage all user permissions
- [ ] Permission history is tracked for all changes
- [ ] Bulk operations work correctly for admins
- [ ] Export/import functionality works as specified

### Quality Requirements ✅
- [ ] Unit test coverage > 95% for permission management code
- [ ] Integration tests cover all permission management workflows
- [ ] Performance requirements met for all endpoints
- [ ] Security review passed for admin functionality
- [ ] Error handling provides appropriate responses

### Documentation Requirements ✅
- [ ] API documentation updated with new endpoints
- [ ] Admin guide includes permission management procedures
- [ ] Security documentation covers permission controls
- [ ] Troubleshooting guide updated

---

**Story Dependencies**: This story builds on Story 4.1 (Admin API Protection) and provides administrative tools for managing the OAuth permission system. It enhances the system with visibility and management capabilities.

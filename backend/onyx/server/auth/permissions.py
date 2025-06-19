"""
Permission Management API endpoints.

This module provides API endpoints for viewing and managing OAuth permissions,
including user permission queries, admin management tools, and permission history.
"""
import json
import csv
import io
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from onyx.auth.users import current_user
from onyx.server.auth_check import require_admin
from onyx.db.oauth_permissions import (
    get_user_oauth_permission,
    update_user_oauth_permission,
    get_users_by_permission_level,
    get_permission_summary,
    get_all_users_with_permissions,
    get_permission_history,
    log_permission_change,
    calculate_permission_summary,
    get_user_by_id,
    get_user_by_email
)
from onyx.db.models import User, OAuthPermission, PermissionLevel, PermissionHistory
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

    class Config:
        from_attributes = True


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
    source: str

    class Config:
        from_attributes = True


class PermissionUpdate(BaseModel):
    """Model for permission updates."""
    permission_level: PermissionLevel
    reason: str


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


@router.get("/permissions", response_model=UserPermissionResponse)
async def get_current_user_permissions(
    current_user: User = Depends(current_user)
) -> UserPermissionResponse:
    """Get current user's OAuth permissions and group memberships."""
    try:
        user_permissions = await get_user_oauth_permission(current_user.id)
        
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
            granted_at=user_permissions.granted_at,
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
        history = await get_permission_history(current_user.id, limit)
        logger.info(f"Retrieved {len(history)} permission history entries for user {current_user.id}")
        return [PermissionHistoryEntry(**entry) for entry in history]
        
    except Exception as e:
        logger.error(f"Error retrieving permission history for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving permission history"
        )


# Admin endpoints
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
        
        user_permissions = await get_user_oauth_permission(user_id)
        
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
            granted_at=user_permissions.granted_at,
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
        # Use existing get_permission_summary function
        summary_data = await get_permission_summary()
        logger.info(f"Admin {admin.id} retrieved permission summary")
        
        return PermissionSummary(
            total_users=sum(summary_data.values()),
            admin_users=summary_data.get("admin", 0),
            write_users=summary_data.get("write", 0),
            read_users=summary_data.get("read", 0),
            inactive_users=summary_data.get("no_oauth_permission", 0),
            recent_changes=0  # TODO: Implement recent changes tracking
        )
        
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
            filters['permission_level'] = permission_level.value
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
        
        # Convert to response model
        result = []
        for user_data in users_with_permissions:
            result.append(UserPermissionResponse(
                user_id=user_data["user_id"],
                email=user_data["email"],
                permission_level=PermissionLevel(user_data["permission_level"]),
                okta_groups=user_data["okta_groups"],
                granted_at=user_data["granted_at"],
                last_updated=user_data["last_updated"],
                source=user_data["source"],
                is_active=user_data["is_active"]
            ))
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing user permissions: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving user permissions list"
        )


@router.put("/admin/users/{user_id}/permissions", response_model=UserPermissionResponse)
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
        current_permissions = await get_user_oauth_permission(user_id)
        
        # Update permissions using existing function
        updated_permissions = await update_user_oauth_permission(
            user_id=user_id,
            permission_level=permission_update.permission_level.value,
            okta_groups=[],  # Preserve existing groups or set to empty
            granted_by="manual"
        )
        
        # Log permission change
        await log_permission_change(
            user_id=user_id,
            previous_level=current_permissions.permission_level if current_permissions else None,
            new_level=permission_update.permission_level.value,
            changed_by=admin.id,
            reason=permission_update.reason,
            source="manual"
        )
        
        logger.info(
            f"Admin {admin.id} updated permissions for user {user_id}: "
            f"{current_permissions.permission_level if current_permissions else 'None'} → "
            f"{permission_update.permission_level.value}"
        )
        
        return UserPermissionResponse(
            user_id=target_user.id,
            email=target_user.email,
            permission_level=updated_permissions.permission_level,
            okta_groups=updated_permissions.okta_groups or [],
            granted_at=updated_permissions.granted_at,
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
                # Verify user exists
                target_user = await get_user_by_id(user_id)
                if not target_user:
                    results["failed_updates"].append({
                        "user_id": str(user_id),
                        "error": "User not found"
                    })
                    continue
                
                # Get current permissions for logging
                current_permissions = await get_user_oauth_permission(user_id)
                
                # Update individual user permissions
                await update_user_oauth_permission(
                    user_id=user_id,
                    permission_level=bulk_update.permission_level.value,
                    okta_groups=[],  # Preserve existing or set to empty
                    granted_by="manual"
                )
                
                # Log the change
                await log_permission_change(
                    user_id=user_id,
                    previous_level=current_permissions.permission_level if current_permissions else None,
                    new_level=bulk_update.permission_level.value,
                    changed_by=admin.id,
                    reason=f"Bulk update: {bulk_update.reason}",
                    source="manual"
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


# Export/Import functionality
@router.get("/admin/permissions/export")
async def export_permissions(
    admin: User = Depends(require_admin),
    format: str = Query("csv", regex="^(csv|json)$")
) -> StreamingResponse:
    """Export all user permissions - requires admin permission."""
    try:
        users_with_permissions_data = await get_all_users_with_permissions(limit=1000)
        
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                "email", "permission_level", "okta_groups", 
                "granted_at", "last_updated", "is_active"
            ])
            
            # Write data
            for user_perm in users_with_permissions_data:
                writer.writerow([
                    user_perm["email"],
                    user_perm["permission_level"],
                    ",".join(user_perm["okta_groups"]),
                    user_perm["granted_at"].isoformat(),
                    user_perm["last_updated"].isoformat(),
                    user_perm["is_active"]
                ])
            
            output.seek(0)
            
            def generate():
                yield output.getvalue()
            
            logger.info(f"Admin {admin.id} exported {len(users_with_permissions_data)} permission records as CSV")
            
            return StreamingResponse(
                generate(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=user_permissions.csv"}
            )
            
        elif format == "json":
            export_data = {
                "exported_at": datetime.utcnow().isoformat(),
                "exported_by": admin.email,
                "total_records": len(users_with_permissions_data),
                "permissions": [
                    {
                        "email": up["email"],
                        "permission_level": up["permission_level"],
                        "okta_groups": up["okta_groups"],
                        "granted_at": up["granted_at"].isoformat(),
                        "last_updated": up["last_updated"].isoformat(),
                        "is_active": up["is_active"]
                    }
                    for up in users_with_permissions_data
                ]
            }
            
            def generate():
                yield json.dumps(export_data, indent=2)
            
            logger.info(f"Admin {admin.id} exported {len(users_with_permissions_data)} permission records as JSON")
            
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
                            await update_user_oauth_permission(
                                user_id=user.id,
                                permission_level=row["permission_level"],
                                okta_groups=row.get("okta_groups", "").split(",") if row.get("okta_groups") else [],
                                granted_by="import"
                            )
                            
                            # Log the import
                            await log_permission_change(
                                user_id=user.id,
                                previous_level=None,  # Don't track previous for imports
                                new_level=row["permission_level"],
                                changed_by=admin.id,
                                reason="Imported from CSV",
                                source="import"
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

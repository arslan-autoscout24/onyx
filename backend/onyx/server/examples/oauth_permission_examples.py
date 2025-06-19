"""
Example usage of OAuth permission dependencies.

This file demonstrates how to use the new OAuth permission dependencies
in FastAPI endpoints to enforce permission-based access control.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from onyx.auth.users import current_user
from onyx.server.auth_check import require_read, require_write, require_admin, optional_permission
from onyx.db.engine import get_session
from onyx.db.models import User
from pydantic import BaseModel
from typing import Optional


router = APIRouter(prefix="/example-permissions")


class ExampleResponse(BaseModel):
    message: str
    user_email: str
    permission_level: str


class CreateResourceRequest(BaseModel):
    name: str
    description: Optional[str] = None


class UpdateResourceRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


# Example 1: Read-only endpoint
@router.get("/read-only-resource")
async def get_resource(
    user: User = Depends(require_read),
    db_session: Session = Depends(get_session)
) -> ExampleResponse:
    """
    Example endpoint that requires read permission.
    
    Any user with 'read', 'write', or 'admin' permission can access this.
    """
    return ExampleResponse(
        message="Successfully accessed read-only resource",
        user_email=user.email,
        permission_level="read (or higher)"
    )


# Example 2: Write endpoint
@router.post("/create-resource")
async def create_resource(
    request: CreateResourceRequest,
    user: User = Depends(require_write),
    db_session: Session = Depends(get_session)
) -> ExampleResponse:
    """
    Example endpoint that requires write permission.
    
    Only users with 'write' or 'admin' permission can access this.
    Users with only 'read' permission will get 403 Forbidden.
    """
    # In a real implementation, you would create the resource in the database
    return ExampleResponse(
        message=f"Successfully created resource: {request.name}",
        user_email=user.email,
        permission_level="write (or higher)"
    )


# Example 3: Admin-only endpoint
@router.delete("/admin-resource/{resource_id}")
async def delete_resource(
    resource_id: str,
    user: User = Depends(require_admin),
    db_session: Session = Depends(get_session)
) -> ExampleResponse:
    """
    Example endpoint that requires admin permission.
    
    Only users with 'admin' permission can access this.
    Users with 'read' or 'write' permission will get 403 Forbidden.
    """
    # In a real implementation, you would delete the resource from the database
    return ExampleResponse(
        message=f"Successfully deleted resource: {resource_id}",
        user_email=user.email,
        permission_level="admin"
    )


# Example 4: Optional permission for conditional logic
@router.get("/conditional-resource")
async def get_conditional_resource(
    user: User = Depends(current_user),
    user_permission: Optional[str] = Depends(optional_permission),
    db_session: Session = Depends(get_session)
) -> ExampleResponse:
    """
    Example endpoint that uses optional permission for conditional logic.
    
    All authenticated users can access this, but they get different responses
    based on their permission level.
    """
    if user_permission == "admin":
        message = "Admin view: Full access to all resources"
    elif user_permission == "write":
        message = "Writer view: Can read and modify your own resources"
    elif user_permission == "read":
        message = "Reader view: Can only view public resources"
    else:
        message = "Limited view: Basic access only"
    
    return ExampleResponse(
        message=message,
        user_email=user.email,
        permission_level=user_permission or "none"
    )


# Example 5: Manual permission checking
@router.put("/update-resource/{resource_id}")
async def update_resource(
    resource_id: str,
    request: UpdateResourceRequest,
    user: User = Depends(current_user),
    user_permission: str = Depends(optional_permission),
    db_session: Session = Depends(get_session)
) -> ExampleResponse:
    """
    Example endpoint that manually checks permissions for complex logic.
    
    Demonstrates how to use the has_permission utility function for
    custom permission logic.
    """
    from onyx.server.auth_check import has_permission
    
    # Example: Allow write access for own resources, admin access for all resources
    is_own_resource = True  # In reality, you'd check if user owns the resource
    
    if is_own_resource and has_permission(user_permission, "write"):
        # User can update their own resource with write permission
        action = "Updated your resource"
    elif has_permission(user_permission, "admin"):
        # Admin can update any resource
        action = "Updated resource (admin access)"
    else:
        # Insufficient permissions
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Need write access for your own resources or admin access for all resources."
        )
    
    return ExampleResponse(
        message=f"{action}: {resource_id}",
        user_email=user.email,
        permission_level=user_permission or "none"
    )


# Example 6: Multiple permission checks
@router.get("/admin-analytics")
async def get_admin_analytics(
    admin_user: User = Depends(require_admin),
    db_session: Session = Depends(get_session)
) -> dict:
    """
    Example admin-only analytics endpoint.
    
    Demonstrates a real-world use case where admin permission is required
    to access sensitive analytics data.
    """
    # In a real implementation, you would query analytics from the database
    analytics_data = {
        "total_users": 150,
        "active_users_today": 45,
        "permission_distribution": {
            "read": 100,
            "write": 35,
            "admin": 15
        },
        "accessed_by": admin_user.email
    }
    
    return analytics_data


# Error handling example
@router.get("/test-permission-error")
async def test_permission_error(
    user: User = Depends(require_admin)
) -> dict:
    """
    Example endpoint to test permission error responses.
    
    This endpoint requires admin permission and will return a 403 error
    with a consistent format if the user doesn't have sufficient permissions.
    """
    return {"message": "You have admin access!"}

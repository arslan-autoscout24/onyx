"""
Ultra-simplified OIDC authentication handler.

No complex permission tables - just maps OIDC groups to user.role.
"""

import os
from typing import List
from onyx.auth.schemas import UserRole
from onyx.db.models import User


def map_oidc_groups_to_role(oidc_groups: List[str]) -> UserRole:
    """
    Map OIDC groups to simple admin/user roles.
    
    Args:
        oidc_groups: List of groups from OIDC provider
        
    Returns:
        UserRole.ADMIN if user is in admin groups, otherwise UserRole.BASIC
    """
    admin_groups = os.getenv("OIDC_ADMIN_GROUPS", "Onyx-Admins").split(",")
    admin_groups = [group.strip() for group in admin_groups]
    
    # Check if user has any admin groups
    for user_group in oidc_groups:
        if user_group in admin_groups:
            return UserRole.ADMIN
    
    # Default to basic user
    return UserRole.BASIC


async def handle_oidc_callback(user: User, oidc_groups: List[str]) -> User:
    """
    Handle OIDC authentication callback.
    
    Simply updates user.role based on OIDC groups.
    No complex permission tracking needed.
    """
    # Map groups to role
    new_role = map_oidc_groups_to_role(oidc_groups)
    
    # Update user role if it changed
    if user.role != new_role:
        user.role = new_role
        # Save user (handled by calling code)
    
    return user


# Simple permission decorators
from functools import wraps
from fastapi import HTTPException, Depends
from onyx.auth.users import current_user


def require_admin(user: User = Depends(current_user)):
    """Require admin role."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def require_user(user: User = Depends(current_user)):
    """Require any authenticated user."""
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account inactive")
    return user

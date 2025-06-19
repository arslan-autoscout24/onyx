from functools import wraps
from typing import Callable, Optional, cast
import logging

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.dependencies.models import Dependant
from starlette.routing import BaseRoute

from onyx.auth.users import (
    current_admin_user,
    current_chat_accessible_user,
    current_curator_or_admin_user,
    current_limited_user,
    current_user,
    current_user_with_expired_token,
)
from onyx.db.models import User
from onyx.db.oauth_permissions import get_user_permission_level
from onyx.redis.redis_pool import get_redis_client
from onyx.configs.app_configs import APP_API_PREFIX
from onyx.server.onyx_api.ingestion import api_key_dep
from onyx.utils.variable_functionality import fetch_ee_implementation_or_noop

import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Permission hierarchy mapping
PERMISSION_HIERARCHY = {
    "read": 1,
    "write": 2,
    "admin": 3
}

# Permission cache TTL in seconds (5 minutes)
PERMISSION_CACHE_TTL = 300

async def get_oauth_permission(user: User = Depends(current_user)) -> str:
    """
    Dependency to get the current user's OAuth permission level with caching.
    
    Returns:
        str: Permission level ('read', 'write', 'admin', or 'none')
        
    Raises:
        HTTPException: If user has no OAuth permissions
    """
    redis_client = get_redis_client()
    cache_key = f"user_oauth_permission:{user.id}"
    
    try:
        # Try cache first
        cached_permission = await redis_client.get(cache_key)
        if cached_permission:
            permission_data = json.loads(cached_permission)
            logger.debug(f"Cache hit for user {user.id}: {permission_data['level']}")
            return permission_data['level']
        
        # Cache miss - fetch from database
        permission_level = await get_user_permission_level(user.id)
        
        # Cache the result
        permission_data = {
            "level": permission_level,
            "cached_at": datetime.utcnow().isoformat()
        }
        await redis_client.setex(
            cache_key, 
            PERMISSION_CACHE_TTL, 
            json.dumps(permission_data)
        )
        
        logger.debug(f"Database hit for user {user.id}: {permission_level}")
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

async def invalidate_user_permission_cache(user_id: str) -> None:
    """
    Invalidate cached permission for a specific user.
    
    Args:
        user_id: UUID of the user whose cache should be invalidated
    """
    redis_client = get_redis_client()
    cache_key = f"user_oauth_permission:{user_id}"
    try:
        await redis_client.delete(cache_key)
        logger.debug(f"Invalidated permission cache for user {user_id}")
    except Exception as e:
        logger.error(f"Failed to invalidate cache for user {user_id}: {e}")


PUBLIC_ENDPOINT_SPECS = [
    # built-in documentation functions
    ("/openapi.json", {"GET", "HEAD"}),
    ("/docs", {"GET", "HEAD"}),
    ("/docs/oauth2-redirect", {"GET", "HEAD"}),
    ("/redoc", {"GET", "HEAD"}),
    # should always be callable, will just return 401 if not authenticated
    ("/me", {"GET"}),
    # just returns 200 to validate that the server is up
    ("/health", {"GET"}),
    # just returns auth type, needs to be accessible before the user is logged
    # in to determine what flow to give the user
    ("/auth/type", {"GET"}),
    # just gets the version of Onyx (e.g. 0.3.11)
    ("/version", {"GET"}),
    # stuff related to basic auth
    ("/auth/refresh", {"POST"}),
    ("/auth/register", {"POST"}),
    ("/auth/login", {"POST"}),
    ("/auth/logout", {"POST"}),
    ("/auth/forgot-password", {"POST"}),
    ("/auth/reset-password", {"POST"}),
    ("/auth/request-verify-token", {"POST"}),
    ("/auth/verify", {"POST"}),
    ("/users/me", {"GET"}),
    ("/users/me", {"PATCH"}),
    ("/users/{id}", {"GET"}),
    ("/users/{id}", {"PATCH"}),
    ("/users/{id}", {"DELETE"}),
    # oauth
    ("/auth/oauth/authorize", {"GET"}),
    ("/auth/oauth/callback", {"GET"}),
    # anonymous user on cloud
    ("/tenants/anonymous-user", {"POST"}),
    ("/metrics", {"GET"}),  # added by prometheus_fastapi_instrumentator
]


def is_route_in_spec_list(
    route: BaseRoute, public_endpoint_specs: list[tuple[str, set[str]]]
) -> bool:
    if not hasattr(route, "path") or not hasattr(route, "methods"):
        return False

    # try adding the prefix AND not adding the prefix, since some endpoints
    # are not prefixed (e.g. /openapi.json)
    if (route.path, route.methods) in public_endpoint_specs:
        return True

    processed_global_prefix = f"/{APP_API_PREFIX.strip('/')}" if APP_API_PREFIX else ""
    if not processed_global_prefix:
        return False

    for endpoint_spec in public_endpoint_specs:
        base_path, methods = endpoint_spec
        prefixed_path = f"{processed_global_prefix}/{base_path.strip('/')}"

        if prefixed_path == route.path and route.methods == methods:
            return True

    return False


def check_router_auth(
    application: FastAPI,
    public_endpoint_specs: list[tuple[str, set[str]]] = PUBLIC_ENDPOINT_SPECS,
) -> None:
    """Ensures that all endpoints on the passed in application either
    (1) have auth enabled OR
    (2) are explicitly marked as a public endpoint
    """

    control_plane_dep = fetch_ee_implementation_or_noop(
        "onyx.server.tenants.access", "control_plane_dep"
    )
    current_cloud_superuser = fetch_ee_implementation_or_noop(
        "onyx.auth.users", "current_cloud_superuser"
    )

    for route in application.routes:
        # explicitly marked as public
        if is_route_in_spec_list(route, public_endpoint_specs):
            continue

        # check for auth
        found_auth = False
        route_dependant_obj = cast(
            Dependant | None, route.dependant if hasattr(route, "dependant") else None
        )
        if route_dependant_obj:
            for dependency in route_dependant_obj.dependencies:
                depends_fn = dependency.cache_key[0]
                if (
                    depends_fn == current_limited_user
                    or depends_fn == current_user
                    or depends_fn == current_admin_user
                    or depends_fn == current_curator_or_admin_user
                    or depends_fn == api_key_dep
                    or depends_fn == current_user_with_expired_token
                    or depends_fn == current_chat_accessible_user
                    or depends_fn == control_plane_dep
                    or depends_fn == current_cloud_superuser
                    or depends_fn == require_read
                    or depends_fn == require_write
                    or depends_fn == require_admin
                ):
                    found_auth = True
                    break

        if not found_auth:
            # uncomment to print out all route(s) that are missing auth
            # print(f"(\"{route.path}\", {set(route.methods)}),")

            raise RuntimeError(
                f"Did not find user dependency in private route - {route}"
            )

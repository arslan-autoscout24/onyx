"""
Database operations for OAuth permissions management.

This module provides the data access layer for OAuth permissions,
including CRUD operations and optimized queries for permission checking.
"""
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from onyx.db.models import OAuthPermission, User
from onyx.db.engine import get_async_session

logger = logging.getLogger(__name__)


class OAuthPermissionError(Exception):
    """Base exception for OAuth permission operations"""
    pass


class PermissionNotFoundError(OAuthPermissionError):
    """Raised when a permission record is not found"""
    pass


class InvalidPermissionLevelError(OAuthPermissionError):
    """Raised when an invalid permission level is provided"""
    pass


# Valid permission levels
VALID_PERMISSION_LEVELS = {"read", "write", "admin"}


async def get_user_oauth_permission(
    user_id: UUID, 
    session: Optional[AsyncSession] = None
) -> Optional[OAuthPermission]:
    """
    Get the active OAuth permission for a user.
    
    Args:
        user_id: UUID of the user
        session: Database session (optional, will create if not provided)
        
    Returns:
        OAuthPermission object if found, None otherwise
    """
    async def _get_permission(db_session: AsyncSession) -> Optional[OAuthPermission]:
        stmt = select(OAuthPermission).where(
            and_(
                OAuthPermission.user_id == user_id,
                OAuthPermission.is_active == True
            )
        ).order_by(OAuthPermission.granted_at.desc())
        
        result = await db_session.execute(stmt)
        return result.scalar_one_or_none()
    
    if session:
        return await _get_permission(session)
    else:
        async with get_async_session() as db_session:
            return await _get_permission(db_session)


async def get_user_permission_level(
    user_id: UUID, 
    session: Optional[AsyncSession] = None
) -> str:
    """
    Get the permission level for a user, with fallback to 'read'.
    
    Args:
        user_id: UUID of the user
        session: Database session (optional)
        
    Returns:
        Permission level string ('read', 'write', or 'admin')
    """
    permission = await get_user_oauth_permission(user_id, session)
    
    if permission and permission.permission_level in VALID_PERMISSION_LEVELS:
        logger.debug(f"Found permission level '{permission.permission_level}' for user {user_id}")
        return permission.permission_level
    
    logger.debug(f"No valid permission found for user {user_id}, defaulting to 'read'")
    return "read"


async def update_user_oauth_permission(
    user_id: UUID,
    permission_level: str,
    okta_groups: List[str],
    granted_by: str = "okta_groups",
    session: Optional[AsyncSession] = None
) -> OAuthPermission:
    """
    Update or create a user's OAuth permission.
    
    Args:
        user_id: UUID of the user
        permission_level: Permission level ('read', 'write', 'admin')
        okta_groups: List of Okta groups that granted this permission
        granted_by: Source of the permission grant (default: 'okta_groups')
        session: Database session (optional)
        
    Returns:
        Created or updated OAuthPermission object
        
    Raises:
        InvalidPermissionLevelError: If permission_level is invalid
    """
    if permission_level not in VALID_PERMISSION_LEVELS:
        raise InvalidPermissionLevelError(f"Invalid permission level: {permission_level}")
    
    async def _update_permission(db_session: AsyncSession) -> OAuthPermission:
        # First, deactivate any existing permissions
        await deactivate_user_oauth_permissions(user_id, db_session)
        
        # Create new permission record
        new_permission = OAuthPermission(
            user_id=user_id,
            permission_level=permission_level,
            granted_by=granted_by,
            okta_groups=",".join(okta_groups) if okta_groups else None,
            granted_at=datetime.utcnow(),
            is_active=True
        )
        
        db_session.add(new_permission)
        await db_session.commit()
        await db_session.refresh(new_permission)
        
        logger.info(f"Updated permission for user {user_id} to '{permission_level}' with groups: {okta_groups}")
        return new_permission
    
    if session:
        return await _update_permission(session)
    else:
        async with get_async_session() as db_session:
            return await _update_permission(db_session)


async def deactivate_user_oauth_permissions(
    user_id: UUID, 
    session: Optional[AsyncSession] = None
) -> None:
    """
    Deactivate all OAuth permissions for a user.
    
    Args:
        user_id: UUID of the user
        session: Database session (optional)
    """
    async def _deactivate_permissions(db_session: AsyncSession) -> None:
        stmt = update(OAuthPermission).where(
            and_(
                OAuthPermission.user_id == user_id,
                OAuthPermission.is_active == True
            )
        ).values(is_active=False)
        
        result = await db_session.execute(stmt)
        await db_session.commit()
        
        logger.debug(f"Deactivated {result.rowcount} permissions for user {user_id}")
    
    if session:
        await _deactivate_permissions(session)
    else:
        async with get_async_session() as db_session:
            await _deactivate_permissions(db_session)


async def get_users_by_permission_level(
    permission_level: str, 
    session: Optional[AsyncSession] = None
) -> List[UUID]:
    """
    Get all users with a specific permission level.
    
    Args:
        permission_level: Permission level to search for
        session: Database session (optional)
        
    Returns:
        List of user UUIDs with the specified permission level
        
    Raises:
        InvalidPermissionLevelError: If permission_level is invalid
    """
    if permission_level not in VALID_PERMISSION_LEVELS:
        raise InvalidPermissionLevelError(f"Invalid permission level: {permission_level}")
    
    async def _get_users(db_session: AsyncSession) -> List[UUID]:
        stmt = select(OAuthPermission.user_id).where(
            and_(
                OAuthPermission.permission_level == permission_level,
                OAuthPermission.is_active == True
            )
        ).distinct()
        
        result = await db_session.execute(stmt)
        user_ids = [row[0] for row in result.fetchall()]
        
        logger.debug(f"Found {len(user_ids)} users with permission level '{permission_level}'")
        return user_ids
    
    if session:
        return await _get_users(session)
    else:
        async with get_async_session() as db_session:
            return await _get_users(db_session)


async def get_permission_summary() -> Dict[str, int]:
    """
    Get a summary of permission distribution across all users.
    
    Returns:
        Dictionary with permission levels as keys and user counts as values
    """
    async with get_async_session() as session:
        summary = {}
        
        for level in VALID_PERMISSION_LEVELS:
            users = await get_users_by_permission_level(level, session)
            summary[level] = len(users)
        
        # Also count users with no OAuth permissions
        stmt = select(User.id).where(
            ~User.id.in_(
                select(OAuthPermission.user_id).where(
                    OAuthPermission.is_active == True
                )
            )
        )
        result = await session.execute(stmt)
        summary["no_oauth_permission"] = len(result.fetchall())
        
        logger.info(f"Permission summary: {summary}")
        return summary


async def bulk_update_permissions(
    permission_updates: List[Dict[str, Any]], 
    session: Optional[AsyncSession] = None
) -> List[OAuthPermission]:
    """
    Bulk update permissions for multiple users.
    
    Args:
        permission_updates: List of dicts with keys: user_id, permission_level, okta_groups
        session: Database session (optional)
        
    Returns:
        List of created/updated OAuthPermission objects
    """
    async def _bulk_update(db_session: AsyncSession) -> List[OAuthPermission]:
        updated_permissions = []
        
        for update in permission_updates:
            user_id = update["user_id"]
            permission_level = update["permission_level"]
            okta_groups = update.get("okta_groups", [])
            granted_by = update.get("granted_by", "okta_groups")
            
            # Validate permission level
            if permission_level not in VALID_PERMISSION_LEVELS:
                logger.warning(f"Skipping invalid permission level '{permission_level}' for user {user_id}")
                continue
            
            try:
                permission = await update_user_oauth_permission(
                    user_id=user_id,
                    permission_level=permission_level,
                    okta_groups=okta_groups,
                    granted_by=granted_by,
                    session=db_session
                )
                updated_permissions.append(permission)
            except Exception as e:
                logger.error(f"Failed to update permission for user {user_id}: {str(e)}")
                continue
        
        logger.info(f"Bulk updated {len(updated_permissions)} permissions")
        return updated_permissions
    
    if session:
        return await _bulk_update(session)
    else:
        async with get_async_session() as db_session:
            return await _bulk_update(db_session)


async def cleanup_inactive_permissions(days_old: int = 30) -> int:
    """
    Clean up old inactive permission records.
    
    Args:
        days_old: Delete inactive permissions older than this many days
        
    Returns:
        Number of deleted records
    """
    from datetime import timedelta
    
    cutoff_date = datetime.utcnow() - timedelta(days=days_old)
    
    async with get_async_session() as session:
        stmt = delete(OAuthPermission).where(
            and_(
                OAuthPermission.is_active == False,
                OAuthPermission.granted_at < cutoff_date
            )
        )
        
        result = await session.execute(stmt)
        await session.commit()
        
        deleted_count = result.rowcount
        logger.info(f"Cleaned up {deleted_count} inactive permission records older than {days_old} days")
        return deleted_count


# Convenience functions for common operations
async def user_has_permission(user_id: UUID, required_level: str) -> bool:
    """
    Check if user has at least the required permission level.
    
    Args:
        user_id: UUID of the user
        required_level: Required permission level
        
    Returns:
        True if user has sufficient permission, False otherwise
    """
    if required_level not in VALID_PERMISSION_LEVELS:
        return False
    
    user_level = await get_user_permission_level(user_id)
    
    # Permission hierarchy: read < write < admin
    hierarchy = {"read": 0, "write": 1, "admin": 2}
    
    return hierarchy.get(user_level, 0) >= hierarchy.get(required_level, 0)


async def get_user_okta_groups(user_id: UUID) -> List[str]:
    """
    Get the Okta groups for a user's current permission.
    
    Args:
        user_id: UUID of the user
        
    Returns:
        List of Okta group names
    """
    permission = await get_user_oauth_permission(user_id)
    
    if permission and permission.okta_groups:
        return permission.okta_groups.split(",")
    
    return []


async def get_all_users_with_permissions(
    limit: int = 100,
    offset: int = 0,
    filters: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Get all users with their permission information.
    
    Args:
        limit: Maximum number of users to return
        offset: Number of users to skip
        filters: Optional filters (permission_level, email_search)
        
    Returns:
        List of user permission dictionaries
    """
    async with get_async_session() as session:
        # Base query with joins
        stmt = select(
            User.id,
            User.email,
            OAuthPermission.permission_level,
            OAuthPermission.okta_groups,
            OAuthPermission.granted_at,
            OAuthPermission.updated_at,
            OAuthPermission.source,
            OAuthPermission.is_active
        ).select_from(
            User
        ).outerjoin(
            OAuthPermission, 
            and_(
                User.id == OAuthPermission.user_id,
                OAuthPermission.is_active == True
            )
        )
        
        # Apply filters
        if filters:
            if "permission_level" in filters:
                stmt = stmt.where(OAuthPermission.permission_level == filters["permission_level"])
            if "email_search" in filters:
                stmt = stmt.where(User.email.ilike(f"%{filters['email_search']}%"))
        
        # Add limit and offset
        stmt = stmt.limit(limit).offset(offset)
        
        result = await session.execute(stmt)
        rows = result.fetchall()
        
        users_with_permissions = []
        for row in rows:
            users_with_permissions.append({
                "user_id": row.id,
                "email": row.email,
                "permission_level": row.permission_level or "read",  # Default to read
                "okta_groups": row.okta_groups or [],
                "granted_at": row.granted_at or datetime.utcnow(),
                "last_updated": row.updated_at or datetime.utcnow(),
                "source": row.source or "none",
                "is_active": row.is_active if row.is_active is not None else False
            })
        
        logger.info(f"Retrieved {len(users_with_permissions)} users with permissions")
        return users_with_permissions


async def get_permission_history(
    user_id: UUID,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Get permission history for a user.
    
    Args:
        user_id: UUID of the user
        limit: Maximum number of history entries to return
        
    Returns:
        List of permission history entries
    """
    async with get_async_session() as session:
        from onyx.db.models import PermissionHistory
        
        stmt = select(PermissionHistory).where(
            PermissionHistory.user_id == user_id
        ).order_by(
            PermissionHistory.changed_at.desc()
        ).limit(limit)
        
        result = await session.execute(stmt)
        history_entries = result.scalars().all()
        
        history_list = []
        for entry in history_entries:
            history_list.append({
                "id": entry.id,
                "user_id": entry.user_id,
                "previous_level": entry.previous_level,
                "new_level": entry.new_level,
                "changed_by": entry.changed_by,
                "changed_at": entry.changed_at,
                "reason": entry.reason,
                "okta_groups_before": entry.okta_groups_before or [],
                "okta_groups_after": entry.okta_groups_after or [],
                "source": entry.source
            })
        
        logger.info(f"Retrieved {len(history_list)} permission history entries for user {user_id}")
        return history_list


async def log_permission_change(
    user_id: UUID,
    previous_level: Optional[str],
    new_level: str,
    changed_by: UUID,
    reason: str,
    okta_groups_before: Optional[List[str]] = None,
    okta_groups_after: Optional[List[str]] = None,
    source: str = "manual"
) -> None:
    """
    Log a permission change for audit purposes.
    
    Args:
        user_id: UUID of the user whose permissions changed
        previous_level: Previous permission level
        new_level: New permission level
        changed_by: UUID of the user who made the change
        reason: Reason for the change
        okta_groups_before: Previous Okta groups
        okta_groups_after: New Okta groups
        source: Source of the change ('manual', 'okta', 'import')
    """
    async with get_async_session() as session:
        from onyx.db.models import PermissionHistory, PermissionLevel
        
        # Convert string levels to enum values
        prev_level_enum = None
        if previous_level:
            prev_level_enum = PermissionLevel(previous_level)
        new_level_enum = PermissionLevel(new_level)
        
        history_entry = PermissionHistory(
            user_id=user_id,
            previous_level=prev_level_enum,
            new_level=new_level_enum,
            changed_by=changed_by,
            reason=reason,
            okta_groups_before=okta_groups_before,
            okta_groups_after=okta_groups_after,
            source=source
        )
        
        session.add(history_entry)
        await session.commit()
        
        logger.info(
            f"Permission change logged for user {user_id}: "
            f"{previous_level} → {new_level} by {changed_by} "
            f"(reason: {reason})"
        )


async def get_user_by_id(user_id: UUID) -> Optional[User]:
    """
    Get a user by their ID.
    
    Args:
        user_id: UUID of the user
        
    Returns:
        User object if found, None otherwise
    """
    async with get_async_session() as session:
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()


async def get_user_by_email(email: str) -> Optional[User]:
    """
    Get a user by their email address.
    
    Args:
        email: Email address of the user
        
    Returns:
        User object if found, None otherwise
    """
    async with get_async_session() as session:
        stmt = select(User).where(User.email == email)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()


async def calculate_permission_summary() -> Dict[str, int]:
    """
    Calculate a comprehensive permission summary.
    
    Returns:
        Dictionary with permission statistics
    """
    return await get_permission_summary()

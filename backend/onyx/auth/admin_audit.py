"""Admin audit logging utilities."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import Request
from sqlalchemy.orm import Session

from onyx.db.models import AdminAuditLog, User
from onyx.utils.logger import setup_logger

logger = setup_logger()


def log_admin_action(
    db_session: Session,
    admin_user: User,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    """
    Log an admin action to the audit log.
    
    Args:
        db_session: Database session
        admin_user: The admin user performing the action
        action: Description of the action performed
        resource_type: Type of resource being acted upon
        resource_id: ID of the specific resource (optional)
        details: Additional details about the action (optional)
        request: FastAPI request object for IP/user agent (optional)
    """
    try:
        # Extract IP address and user agent from request if available
        ip_address = None
        user_agent = None
        
        if request:
            # Get client IP (handling potential proxy headers)
            ip_address = (
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or request.headers.get("X-Real-IP")
                or getattr(request.client, "host", None)
            )
            user_agent = request.headers.get("User-Agent")
        
        # Create audit log entry
        audit_log = AdminAuditLog(
            admin_user_id=admin_user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        db_session.add(audit_log)
        db_session.commit()
        
        logger.info(
            f"Admin audit log: User {admin_user.id} performed '{action}' on "
            f"{resource_type}" + (f" (ID: {resource_id})" if resource_id else "")
        )
        
    except Exception as e:
        logger.error(f"Failed to log admin action: {e}")
        # Don't re-raise to avoid disrupting the main operation
        db_session.rollback()


# Common action constants for consistency
class AdminActions:
    # Connector actions
    CREATE_CONNECTOR = "create_connector"
    UPDATE_CONNECTOR = "update_connector"
    DELETE_CONNECTOR = "delete_connector"
    LIST_CONNECTORS = "list_connectors"
    
    # User management actions
    INVITE_USERS = "invite_users"
    DEACTIVATE_USER = "deactivate_user"
    DELETE_USER = "delete_user"
    ACTIVATE_USER = "activate_user"
    UPDATE_USER_ROLE = "update_user_role"
    
    # System configuration actions
    UPDATE_SETTINGS = "update_settings"
    VIEW_ANALYTICS = "view_analytics"
    VIEW_SETTINGS = "view_settings"
    
    # Document management actions
    BOOST_DOCUMENT = "boost_document"
    HIDE_DOCUMENT = "hide_document"


# Common resource types for consistency
class ResourceTypes:
    CONNECTOR = "connector"
    USER = "user"
    SYSTEM = "system"
    DOCUMENT = "document"
    SETTINGS = "settings"

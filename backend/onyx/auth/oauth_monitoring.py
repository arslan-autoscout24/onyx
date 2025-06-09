"""
Monitoring and metrics for OAuth permission processing.
"""
import logging
from typing import Dict, Any
from datetime import datetime
from uuid import UUID

logger = logging.getLogger(__name__)

class OAuthPermissionMonitor:
    """Monitor OAuth permission processing events"""
    
    @staticmethod
    def log_permission_grant(
        user_id: UUID, 
        permission_level: str, 
        okta_groups: list, 
        processing_time_ms: float
    ) -> None:
        """Log successful permission grant"""
        logger.info(
            f"OAuth permission granted - User: {user_id}, Level: {permission_level}, "
            f"Groups: {okta_groups}, Processing time: {processing_time_ms:.2f}ms"
        )
    
    @staticmethod
    def log_permission_error(
        user_id: UUID, 
        error: str, 
        access_token_preview: str = None
    ) -> None:
        """Log permission processing error"""
        token_info = f", Token preview: {access_token_preview[:20]}..." if access_token_preview else ""
        logger.error(f"OAuth permission error - User: {user_id}, Error: {error}{token_info}")
    
    @staticmethod
    def log_oauth_callback_start(oauth_name: str, account_email: str) -> None:
        """Log start of OAuth callback processing"""
        logger.debug(f"OAuth callback started - Provider: {oauth_name}, Email: {account_email}")
    
    @staticmethod
    def log_oauth_callback_complete(oauth_name: str, user_id: UUID, had_groups: bool) -> None:
        """Log completion of OAuth callback"""
        groups_processed = "with groups" if had_groups else "without groups"
        logger.info(f"OAuth callback completed - Provider: {oauth_name}, User: {user_id}, {groups_processed}")

    @staticmethod
    def log_security_event(event_type: str, user_id: UUID, details: Dict[str, Any]) -> None:
        """Log security-related OAuth events"""
        logger.warning(
            f"OAuth security event - Type: {event_type}, User: {user_id}, "
            f"Details: {details}, Timestamp: {datetime.utcnow().isoformat()}"
        )
    
    @staticmethod
    def log_token_parsing_failure(user_id: UUID, oauth_name: str, error_details: str) -> None:
        """Log token parsing failures for debugging"""
        logger.warning(
            f"Token parsing failed - User: {user_id}, Provider: {oauth_name}, "
            f"Error: {error_details}"
        )

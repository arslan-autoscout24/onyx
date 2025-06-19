"""
Custom exception handler for OAuth permission errors.

This middleware provides consistent error responses across the application
for OAuth permission-related errors.
"""
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

async def oauth_permission_exception_handler(request: Request, exc: HTTPException):
    """
    Custom exception handler for OAuth permission errors.
    Provides consistent error responses across the application.
    """
    if exc.status_code == status.HTTP_403_FORBIDDEN:
        logger.warning(
            f"Permission denied for {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )
        
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "detail": exc.detail,
                "error_code": "INSUFFICIENT_OAUTH_PERMISSIONS",
                "required_action": "Contact administrator to update your permissions",
                "support_email": "support@yourcompany.com"
            }
        )
    
    # Let other exceptions be handled normally
    raise exc

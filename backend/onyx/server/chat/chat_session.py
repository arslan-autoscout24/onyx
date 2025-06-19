"""
Chat session API endpoints with OAuth permission protection.

This module provides RESTful endpoints for managing chat sessions with proper
permission-based access control using OAuth permissions.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional
from sqlalchemy.orm import Session
from uuid import UUID
from datetime import datetime

from onyx.auth.users import current_user
from onyx.server.auth_check import require_read, require_write, require_admin, get_oauth_permission
from onyx.db.engine import get_session
from onyx.db.models import User, ChatSession, ChatMessage
from onyx.db.chat import (
    get_chat_session_by_id,
    get_chat_sessions_by_user,
    create_chat_session,
    delete_chat_session as db_delete_chat_session
)
from onyx.server.chat.models import (
    ChatSessionResponse,
    ChatSessionCreate,
    ChatSessionUpdate,
    ChatMessageResponse
)
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/chat-api", tags=["chat-api"])


async def get_user_oauth_permission(user_id: UUID) -> str:
    """Get user's OAuth permission level."""
    from onyx.db.oauth_permissions import get_user_permission_level
    return await get_user_permission_level(user_id)


def check_session_access(session: ChatSession, user: User, user_permission: str) -> bool:
    """
    Check if user has access to a chat session based on ownership, sharing, and permission level.
    
    Args:
        session: Chat session to check access for
        user: User requesting access
        user_permission: User's permission level
        
    Returns:
        bool: True if user has access
    """
    # Owner always has access
    if session.user_id == user.id:
        return True
    
    # Check if session is shared
    if hasattr(session, 'shared_status') and session.shared_status.value == "public":
        return True
    
    # Check for legacy is_shared attribute if it exists
    if hasattr(session, 'is_shared') and session.is_shared:
        return True
    
    # Admin users have access to all sessions
    if user_permission == "admin":
        return True
    
    # TODO: Add collaborator support when the database model supports it
    # if user_permission in ["write", "admin"] and user.id in [c.id for c in session.collaborators]:
    #     return True
    
    return False


def check_session_write_access(session: ChatSession, user: User, user_permission: str) -> bool:
    """
    Check if user has write access to a chat session.
    
    Args:
        session: Chat session to check write access for
        user: User requesting write access
        user_permission: User's permission level
        
    Returns:
        bool: True if user has write access
    """
    # Owner can always write
    if session.user_id == user.id:
        return True
    
    # Admin can write to any session
    if user_permission == "admin":
        return True
    
    # Write users can write to shared sessions
    if user_permission == "write":
        if hasattr(session, 'shared_status') and session.shared_status.value == "public":
            return True
        if hasattr(session, 'is_shared') and session.is_shared:
            return True
    
    # TODO: Add collaborator support
    # if user_permission in ["write", "admin"] and user.id in [c.id for c in session.collaborators]:
    #     return True
    
    return False


@router.get("/sessions", response_model=List[ChatSessionResponse])
async def get_chat_sessions(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    include_messages: bool = Query(False),
    user: User = Depends(require_read),  # OAuth permission required
    db_session: Session = Depends(get_session)
) -> List[ChatSessionResponse]:
    """
    Retrieve chat sessions with OAuth read permission.
    
    Args:
        limit: Maximum number of sessions to return
        offset: Number of sessions to skip
        include_messages: Whether to include recent messages
        user: Authenticated user with read permission
        db_session: Database session
        
    Returns:
        List of chat sessions the user has access to
    """
    logger.info(f"User {user.email} requesting chat sessions (limit={limit}, offset={offset})")
    
    try:
        # Get user's permission level for filtering
        user_permission = await get_user_oauth_permission(user.id)
        
        # Get user's chat sessions
        sessions = get_chat_sessions_by_user(
            user_id=user.id,
            deleted=False,
            db_session=db_session,
            limit=limit,
            offset=offset
        )
        
        # TODO: For admin users, we might want to get all sessions, not just user's sessions
        # This would require modifying the get_chat_sessions_by_user function or creating a new one
        
        logger.info(f"Found {len(sessions)} chat sessions for user {user.email}")
        
        session_responses = []
        for session in sessions:
            # Double-check access (should always pass for user's own sessions)
            if check_session_access(session, user, user_permission):
                session_response = ChatSessionResponse.from_chat_session(session)
                
                if include_messages:
                    # Get recent messages for each session
                    from onyx.db.chat import get_chat_messages_by_session
                    recent_messages = get_chat_messages_by_session(
                        chat_session_id=session.id,
                        user_id=user.id,
                        db_session=db_session,
                        limit=5
                    )
                    
                    session_response.recent_messages = [
                        ChatMessageResponse.from_chat_message(msg) for msg in recent_messages
                    ]
                
                session_responses.append(session_response)
        
        return session_responses
        
    except Exception as e:
        logger.error(f"Error retrieving chat sessions for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve chat sessions"
        )


@router.get("/sessions/{session_id}", response_model=ChatSessionResponse)
async def get_chat_session(
    session_id: UUID = Path(..., description="Chat session ID"),
    include_messages: bool = Query(True),
    user: User = Depends(require_read),  # OAuth permission required
    db_session: Session = Depends(get_session)
) -> ChatSessionResponse:
    """
    Get a specific chat session by ID with OAuth read permission.
    
    Args:
        session_id: ID of the chat session to retrieve
        include_messages: Whether to include chat messages
        user: Authenticated user with read permission
        db_session: Database session
        
    Returns:
        Chat session data with messages
        
    Raises:
        HTTPException: 404 if session not found or access denied
    """
    logger.info(f"User {user.email} requesting chat session {session_id}")
    
    try:
        session = get_chat_session_by_id(
            chat_session_id=session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        logger.warning(f"Chat session {session_id} not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check if user has access to this session
    user_permission = await get_user_oauth_permission(user.id)
    if not check_session_access(session, user, user_permission):
        logger.warning(f"User {user.email} denied access to chat session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to chat session"
        )
    
    session_response = ChatSessionResponse.from_chat_session(session)
    
    if include_messages:
        from onyx.db.chat import get_chat_messages_by_session
        messages = get_chat_messages_by_session(
            chat_session_id=session_id,
            user_id=user.id,
            db_session=db_session
        )
        
        session_response.messages = [
            ChatMessageResponse.from_chat_message(msg) for msg in messages
        ]
    
    return session_response


@router.post("/sessions", response_model=ChatSessionResponse, status_code=status.HTTP_201_CREATED)
async def create_chat_session_endpoint(
    session_data: ChatSessionCreate,
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> ChatSessionResponse:
    """
    Create a new chat session with OAuth write permission.
    
    Args:
        session_data: Chat session creation data
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        Created chat session data
        
    Raises:
        HTTPException: 400 if validation fails, 500 if creation fails
    """
    logger.info(f"User {user.email} creating chat session: {session_data.title}")
    
    try:
        # Validate session data
        if not session_data.title or len(session_data.title.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chat session title is required"
            )
        
        # Create chat session using existing database function
        new_session = create_chat_session(
            db_session=db_session,
            description=session_data.title,  # The existing function uses description field for title
            user_id=user.id,
            persona_id=0  # Default persona
        )
        
        logger.info(f"Chat session {new_session.id} created by user {user.email}")
        return ChatSessionResponse.from_chat_session(new_session)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating chat session for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create chat session"
        )


@router.put("/sessions/{session_id}", response_model=ChatSessionResponse)
async def update_chat_session(
    session_id: UUID = Path(..., description="Chat session ID"),
    session_data: ChatSessionUpdate = ...,
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> ChatSessionResponse:
    """
    Update an existing chat session with OAuth write permission.
    
    Args:
        session_id: ID of the chat session to update
        session_data: Chat session update data
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        Updated chat session data
        
    Raises:
        HTTPException: 404 if session not found, 403 if access denied
    """
    logger.info(f"User {user.email} updating chat session {session_id}")
    
    try:
        session = get_chat_session_by_id(
            chat_session_id=session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        logger.warning(f"Chat session {session_id} not found for update: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check if user can update this session
    user_permission = await get_user_oauth_permission(user.id)
    if not check_session_write_access(session, user, user_permission):
        logger.warning(f"User {user.email} denied update access to chat session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only update your own chat sessions or sessions you collaborate on"
        )
    
    try:
        # Update session fields
        updated = False
        if session_data.title is not None:
            session.description = session_data.title  # Using description field for title
            updated = True
        if session_data.is_shared is not None:
            # Update shared status if the model supports it
            if hasattr(session, 'shared_status'):
                from onyx.db.enums import ChatSessionSharedStatus
                session.shared_status = ChatSessionSharedStatus.PUBLIC if session_data.is_shared else ChatSessionSharedStatus.PRIVATE
                updated = True
        
        if updated:
            session.time_updated = datetime.utcnow()
            db_session.commit()
            db_session.refresh(session)
        
        logger.info(f"Chat session {session_id} updated by user {user.email}")
        return ChatSessionResponse.from_chat_session(session)
        
    except Exception as e:
        logger.error(f"Error updating chat session {session_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update chat session"
        )


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_chat_session_endpoint(
    session_id: UUID = Path(..., description="Chat session ID"),
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> None:
    """
    Delete a chat session with OAuth write permission.
    
    Args:
        session_id: ID of the chat session to delete
        user: Authenticated user with write permission
        db_session: Database session
        
    Raises:
        HTTPException: 404 if session not found, 403 if access denied
    """
    logger.info(f"User {user.email} deleting chat session {session_id}")
    
    try:
        session = get_chat_session_by_id(
            chat_session_id=session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        logger.warning(f"Chat session {session_id} not found for deletion: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check if user can delete this session
    user_permission = await get_user_oauth_permission(user.id)
    if user_permission != "admin" and session.user_id != user.id:
        logger.warning(f"User {user.email} denied delete access to chat session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only delete your own chat sessions"
        )
    
    try:
        # Use existing delete function
        db_delete_chat_session(
            user_id=user.id,
            chat_session_id=session_id,
            db_session=db_session
        )
        
        logger.info(f"Chat session {session_id} deleted by user {user.email}")
        
    except Exception as e:
        logger.error(f"Error deleting chat session {session_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete chat session"
        )

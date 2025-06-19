"""
Chat message API endpoints with OAuth permission protection.

This module provides RESTful endpoints for managing chat messages with proper
permission-based access control using OAuth permissions.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Path, Query
from typing import List, Optional
from sqlalchemy.orm import Session
from uuid import UUID
from datetime import datetime

from onyx.auth.users import current_user
from onyx.server.auth_check import require_read, require_write
from onyx.db.engine import get_session
from onyx.db.models import User, ChatSession, ChatMessage
from onyx.db.chat import (
    get_chat_session_by_id,
    get_chat_messages_by_session,
    get_chat_message,
    create_new_chat_message
)
from onyx.server.chat.models import (
    ChatMessageResponse,
    ChatMessageCreate,
    ChatMessageUpdate
)
from onyx.server.chat.chat_session import (
    get_user_oauth_permission,
    check_session_access,
    check_session_write_access
)
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/chat-api", tags=["chat-api"])


@router.get("/sessions/{session_id}/messages", response_model=List[ChatMessageResponse])
async def get_chat_messages(
    session_id: UUID = Path(..., description="Chat session ID"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: User = Depends(require_read),  # OAuth permission required
    db_session: Session = Depends(get_session)
) -> List[ChatMessageResponse]:
    """
    Get messages for a chat session with OAuth read permission.
    
    Args:
        session_id: ID of the chat session
        limit: Maximum number of messages to return
        offset: Number of messages to skip
        user: Authenticated user with read permission
        db_session: Database session
        
    Returns:
        List of chat messages
        
    Raises:
        HTTPException: 404 if session not found, 403 if access denied
    """
    logger.info(f"User {user.email} requesting messages for session {session_id}")
    
    # First verify user has access to the session
    try:
        session = get_chat_session_by_id(
            chat_session_id=session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check session access (same logic as get_chat_session)
    user_permission = await get_user_oauth_permission(user.id)
    if not check_session_access(session, user, user_permission):
        logger.warning(f"User {user.email} denied access to messages for session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to chat session messages"
        )
    
    try:
        messages = get_chat_messages_by_session(
            chat_session_id=session_id,
            user_id=user.id,
            db_session=db_session,
            limit=limit,
            offset=offset
        )
        
        logger.info(f"Returning {len(messages)} messages to user {user.email}")
        return [ChatMessageResponse.from_chat_message(msg) for msg in messages]
        
    except Exception as e:
        logger.error(f"Error retrieving messages for session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve chat messages"
        )


@router.post("/sessions/{session_id}/messages", response_model=ChatMessageResponse, status_code=status.HTTP_201_CREATED)
async def send_chat_message(
    session_id: UUID = Path(..., description="Chat session ID"),
    message_data: ChatMessageCreate = ...,
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> ChatMessageResponse:
    """
    Send a new message to a chat session with OAuth write permission.
    
    Args:
        session_id: ID of the chat session
        message_data: Message content and metadata
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        Created message data
        
    Raises:
        HTTPException: 404 if session not found, 403 if access denied
    """
    logger.info(f"User {user.email} sending message to session {session_id}")
    
    # Verify session exists and user has write access
    try:
        session = get_chat_session_by_id(
            chat_session_id=session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check if user can send messages to this session
    user_permission = await get_user_oauth_permission(user.id)
    if not check_session_write_access(session, user, user_permission):
        logger.warning(f"User {user.email} denied message send access to session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot send messages to this chat session"
        )
    
    try:
        # Validate message content
        if not message_data.content or len(message_data.content.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message content is required"
            )
        
        # Create new message using existing database function
        # Note: The existing create_new_chat_message function has a complex signature
        # We'll create a simplified version for this API
        new_message = ChatMessage(
            chat_session_id=session_id,
            message=message_data.content,
            token_count=0,  # Will be calculated if needed
            message_type=getattr(__import__('onyx.configs.constants', fromlist=['MessageType']), 'MessageType').USER,
            time_sent=datetime.utcnow()
        )
        
        db_session.add(new_message)
        
        # Update session timestamp
        session.time_updated = datetime.utcnow()
        
        db_session.commit()
        db_session.refresh(new_message)
        
        logger.info(f"Message {new_message.id} sent to session {session_id} by user {user.email}")
        return ChatMessageResponse.from_chat_message(new_message)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending message to session {session_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send chat message"
        )


@router.get("/messages/{message_id}", response_model=ChatMessageResponse)
async def get_chat_message_by_id(
    message_id: int = Path(..., description="Chat message ID"),
    user: User = Depends(require_read),  # OAuth permission required
    db_session: Session = Depends(get_session)
) -> ChatMessageResponse:
    """
    Get a specific chat message by ID with OAuth read permission.
    
    Args:
        message_id: ID of the message to retrieve
        user: Authenticated user with read permission
        db_session: Database session
        
    Returns:
        Chat message data
        
    Raises:
        HTTPException: 404 if message not found, 403 if access denied
    """
    logger.info(f"User {user.email} requesting message {message_id}")
    
    try:
        message = get_chat_message(
            chat_message_id=message_id,
            user_id=user.id,
            db_session=db_session
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat message not found"
        )
    
    # Check if user has access to the session this message belongs to
    try:
        session = get_chat_session_by_id(
            chat_session_id=message.chat_session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    user_permission = await get_user_oauth_permission(user.id)
    if not check_session_access(session, user, user_permission):
        logger.warning(f"User {user.email} denied access to message {message_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to chat message"
        )
    
    return ChatMessageResponse.from_chat_message(message)


@router.put("/messages/{message_id}", response_model=ChatMessageResponse)
async def update_chat_message(
    message_id: int = Path(..., description="Chat message ID"),
    message_data: ChatMessageUpdate = ...,
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> ChatMessageResponse:
    """
    Update a chat message with OAuth write permission.
    
    Args:
        message_id: ID of the message to update
        message_data: Updated message data
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        Updated message data
        
    Raises:
        HTTPException: 404 if message not found, 403 if access denied
    """
    logger.info(f"User {user.email} updating message {message_id}")
    
    try:
        message = get_chat_message(
            chat_message_id=message_id,
            user_id=user.id,
            db_session=db_session
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat message not found"
        )
    
    # Check if user can update this message
    user_permission = await get_user_oauth_permission(user.id)
    
    # For now, only allow users to edit their own messages or admin to edit any
    # TODO: When we have user_id on messages, use that. For now, we'll use session ownership
    try:
        session = get_chat_session_by_id(
            chat_session_id=message.chat_session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    if user_permission != "admin" and session.user_id != user.id:
        logger.warning(f"User {user.email} denied update access to message {message_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only update your own messages"
        )
    
    try:
        # Update message fields
        updated = False
        if message_data.content is not None:
            message.message = message_data.content
            updated = True
        if message_data.metadata is not None and hasattr(message, 'metadata'):
            message.metadata = message_data.metadata
            updated = True
        
        if updated:
            # Mark as edited if the model supports it
            if hasattr(message, 'is_edited'):
                message.is_edited = True
            if hasattr(message, 'updated_at'):
                message.updated_at = datetime.utcnow()
            
            db_session.commit()
            db_session.refresh(message)
        
        logger.info(f"Message {message_id} updated by user {user.email}")
        return ChatMessageResponse.from_chat_message(message)
        
    except Exception as e:
        logger.error(f"Error updating message {message_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update chat message"
        )


@router.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_chat_message(
    message_id: int = Path(..., description="Chat message ID"),
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> None:
    """
    Delete a chat message with OAuth write permission.
    
    Args:
        message_id: ID of the message to delete
        user: Authenticated user with write permission
        db_session: Database session
        
    Raises:
        HTTPException: 404 if message not found, 403 if access denied
    """
    logger.info(f"User {user.email} deleting message {message_id}")
    
    try:
        message = get_chat_message(
            chat_message_id=message_id,
            user_id=user.id,
            db_session=db_session
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat message not found"
        )
    
    # Check if user can delete this message
    user_permission = await get_user_oauth_permission(user.id)
    
    # For now, only allow users to delete their own messages or admin to delete any
    try:
        session = get_chat_session_by_id(
            chat_session_id=message.chat_session_id,
            user_id=user.id,
            db_session=db_session,
            include_deleted=False
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    if user_permission != "admin" and session.user_id != user.id:
        logger.warning(f"User {user.email} denied delete access to message {message_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only delete your own messages"
        )
    
    try:
        db_session.delete(message)
        db_session.commit()
        
        logger.info(f"Message {message_id} deleted by user {user.email}")
        
    except Exception as e:
        logger.error(f"Error deleting message {message_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete chat message"
        )

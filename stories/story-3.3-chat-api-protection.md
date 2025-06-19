# Story 3.3: Chat API Permission Protection

## Overview
**Sprint**: 3 - Authorization Middleware  
**Story ID**: 3.3  
**Title**: Chat API Permission Protection  
**Priority**: P1 - High  
**Estimate**: 1 day  
**Dependencies**: Story 3.1 (OAuth Permission Dependencies)

## Description
Apply OAuth permission-based access control to all chat-related API endpoints using the permission dependencies. This ensures users can only access chat operations appropriate to their permission level while maintaining the conversational flow and real-time features.

## Acceptance Criteria
- [ ] GET `/chat-sessions` requires `read` permission
- [ ] POST `/chat-sessions` requires `write` permission
- [ ] Chat message endpoints require appropriate permissions
- [ ] WebSocket chat connections respect permission levels
- [ ] Integration tests for chat permission enforcement
- [ ] Real-time chat features maintained with permission checks
- [ ] Chat history access filtered by user permissions
- [ ] Chat session ownership and sharing rules enforced

## Technical Implementation

### Core Files to Modify

#### 1. Chat Session Router Protection
**File**: `backend/onyx/server/chat/chat_session.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional
from sqlalchemy.orm import Session
from uuid import UUID

from onyx.auth.users import current_user
from onyx.server.auth_check import require_read, require_write, require_admin
from onyx.db.engine import get_session
from onyx.db.models import User, ChatSession, ChatMessage
from onyx.server.chat.models import (
    ChatSessionResponse,
    ChatSessionCreate,
    ChatSessionUpdate,
    ChatMessageResponse
)
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/chat", tags=["chat"])

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
        query = db_session.query(ChatSession)
        
        # Apply user-specific filtering based on permission level
        user_permission = await get_user_oauth_permission(user.id)
        if user_permission == "read":
            # Read users see only their own sessions and public shared sessions
            query = query.filter(
                (ChatSession.user_id == user.id) | 
                (ChatSession.is_shared == True)
            )
        elif user_permission == "write":
            # Write users see their own sessions and sessions they can collaborate on
            query = query.filter(
                (ChatSession.user_id == user.id) |
                (ChatSession.is_shared == True) |
                (ChatSession.collaborators.any(User.id == user.id))
            )
        # Admin users see all sessions (no additional filter)
        
        sessions = query.order_by(ChatSession.updated_at.desc()).offset(offset).limit(limit).all()
        
        logger.info(f"Returning {len(sessions)} chat sessions to user {user.email}")
        
        session_responses = []
        for session in sessions:
            session_response = ChatSessionResponse.from_chat_session(session)
            
            if include_messages:
                # Get recent messages for each session
                recent_messages = db_session.query(ChatMessage).filter(
                    ChatMessage.chat_session_id == session.id
                ).order_by(ChatMessage.created_at.desc()).limit(5).all()
                
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
    
    session = db_session.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        logger.warning(f"Chat session {session_id} not found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check if user has access to this session
    user_permission = await get_user_oauth_permission(user.id)
    has_access = False
    
    if session.user_id == user.id:
        # Owner always has access
        has_access = True
    elif session.is_shared:
        # Shared sessions are accessible to read+ users
        has_access = True
    elif user_permission in ["write", "admin"] and user.id in [c.id for c in session.collaborators]:
        # Collaborator access for write+ users
        has_access = True
    elif user_permission == "admin":
        # Admin access to any session
        has_access = True
    
    if not has_access:
        logger.warning(f"User {user.email} denied access to chat session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to chat session"
        )
    
    session_response = ChatSessionResponse.from_chat_session(session)
    
    if include_messages:
        messages = db_session.query(ChatMessage).filter(
            ChatMessage.chat_session_id == session_id
        ).order_by(ChatMessage.created_at.asc()).all()
        
        session_response.messages = [
            ChatMessageResponse.from_chat_message(msg) for msg in messages
        ]
    
    return session_response

@router.post("/sessions", response_model=ChatSessionResponse, status_code=status.HTTP_201_CREATED)
async def create_chat_session(
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
        
        # Create chat session
        new_session = ChatSession(
            title=session_data.title,
            description=session_data.description or "",
            user_id=user.id,
            is_shared=session_data.is_shared if session_data.is_shared is not None else False,
            chat_settings=session_data.chat_settings or {}
        )
        
        db_session.add(new_session)
        db_session.commit()
        db_session.refresh(new_session)
        
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
    
    session = db_session.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        logger.warning(f"Chat session {session_id} not found for update")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check if user can update this session
    user_permission = await get_user_oauth_permission(user.id)
    can_update = False
    
    if session.user_id == user.id:
        # Owner can always update
        can_update = True
    elif user_permission in ["write", "admin"] and user.id in [c.id for c in session.collaborators]:
        # Collaborators with write+ permission can update
        can_update = True
    elif user_permission == "admin":
        # Admin can update any session
        can_update = True
    
    if not can_update:
        logger.warning(f"User {user.email} denied update access to chat session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only update your own chat sessions or sessions you collaborate on"
        )
    
    try:
        # Update session fields
        if session_data.title is not None:
            session.title = session_data.title
        if session_data.description is not None:
            session.description = session_data.description
        if session_data.is_shared is not None:
            session.is_shared = session_data.is_shared
        if session_data.chat_settings is not None:
            session.chat_settings = session_data.chat_settings
        
        session.updated_at = datetime.utcnow()
        
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
async def delete_chat_session(
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
    
    session = db_session.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        logger.warning(f"Chat session {session_id} not found for deletion")
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
        # Delete associated messages first (cascade delete)
        db_session.query(ChatMessage).filter(ChatMessage.chat_session_id == session_id).delete()
        
        # Delete the session
        db_session.delete(session)
        db_session.commit()
        
        logger.info(f"Chat session {session_id} deleted by user {user.email}")
        
    except Exception as e:
        logger.error(f"Error deleting chat session {session_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete chat session"
        )
```

#### 2. Chat Message Operations Protection
**File**: `backend/onyx/server/chat/chat_message.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status, Path, Query
from typing import List, Optional
from sqlalchemy.orm import Session
from uuid import UUID

from onyx.auth.users import current_user
from onyx.server.auth_check import require_read, require_write
from onyx.db.engine import get_session
from onyx.db.models import User, ChatSession, ChatMessage
from onyx.server.chat.models import (
    ChatMessageResponse,
    ChatMessageCreate,
    ChatMessageUpdate
)
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/chat", tags=["chat"])

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
    session = db_session.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check session access (same logic as get_chat_session)
    user_permission = await get_user_oauth_permission(user.id)
    has_access = (
        session.user_id == user.id or
        session.is_shared or
        (user_permission in ["write", "admin"] and user.id in [c.id for c in session.collaborators]) or
        user_permission == "admin"
    )
    
    if not has_access:
        logger.warning(f"User {user.email} denied access to messages for session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to chat session messages"
        )
    
    try:
        messages = db_session.query(ChatMessage).filter(
            ChatMessage.chat_session_id == session_id
        ).order_by(ChatMessage.created_at.asc()).offset(offset).limit(limit).all()
        
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
    session = db_session.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found"
        )
    
    # Check if user can send messages to this session
    user_permission = await get_user_oauth_permission(user.id)
    can_send = (
        session.user_id == user.id or
        (session.is_shared and user_permission in ["write", "admin"]) or
        (user_permission in ["write", "admin"] and user.id in [c.id for c in session.collaborators]) or
        user_permission == "admin"
    )
    
    if not can_send:
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
        
        # Create new message
        new_message = ChatMessage(
            chat_session_id=session_id,
            user_id=user.id,
            content=message_data.content,
            message_type=message_data.message_type or "user",
            metadata=message_data.metadata or {}
        )
        
        db_session.add(new_message)
        
        # Update session timestamp
        session.updated_at = datetime.utcnow()
        
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

@router.put("/messages/{message_id}", response_model=ChatMessageResponse)
async def update_chat_message(
    message_id: UUID = Path(..., description="Chat message ID"),
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
    
    message = db_session.query(ChatMessage).filter(ChatMessage.id == message_id).first()
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat message not found"
        )
    
    # Check if user can update this message
    user_permission = await get_user_oauth_permission(user.id)
    if user_permission != "admin" and message.user_id != user.id:
        logger.warning(f"User {user.email} denied update access to message {message_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only update your own messages"
        )
    
    try:
        # Update message fields
        if message_data.content is not None:
            message.content = message_data.content
        if message_data.metadata is not None:
            message.metadata = message_data.metadata
        
        message.updated_at = datetime.utcnow()
        message.is_edited = True
        
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
    message_id: UUID = Path(..., description="Chat message ID"),
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
    
    message = db_session.query(ChatMessage).filter(ChatMessage.id == message_id).first()
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat message not found"
        )
    
    # Check if user can delete this message
    user_permission = await get_user_oauth_permission(user.id)
    if user_permission != "admin" and message.user_id != user.id:
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
```

#### 3. WebSocket Chat Protection
**File**: `backend/onyx/server/chat/websocket.py`

```python
from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from typing import Dict, Set
from uuid import UUID
import json
import asyncio
from sqlalchemy.orm import Session

from onyx.auth.users import current_user
from onyx.server.auth_check import get_oauth_permission, has_permission
from onyx.db.engine import get_session
from onyx.db.models import User, ChatSession, ChatMessage
from onyx.utils.logger import setup_logger

logger = setup_logger()

class ChatWebSocketManager:
    """
    Manages WebSocket connections for real-time chat with permission enforcement.
    """
    
    def __init__(self):
        # session_id -> set of websockets
        self.session_connections: Dict[UUID, Set[WebSocket]] = {}
        # websocket -> user info
        self.connection_users: Dict[WebSocket, dict] = {}
    
    async def connect(
        self, 
        websocket: WebSocket, 
        session_id: UUID, 
        user: User,
        db_session: Session
    ):
        """
        Connect user to chat session websocket with permission verification.
        
        Args:
            websocket: WebSocket connection
            session_id: Chat session ID
            user: Authenticated user
            db_session: Database session
            
        Raises:
            HTTPException: If user lacks permission to access session
        """
        # Verify session exists
        session = db_session.query(ChatSession).filter(ChatSession.id == session_id).first()
        if not session:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session not found")
            return
        
        # Check user permission to access this session
        user_permission = await get_oauth_permission(user)
        has_access = (
            session.user_id == user.id or
            session.is_shared or
            (user_permission in ["write", "admin"] and user.id in [c.id for c in session.collaborators]) or
            user_permission == "admin"
        )
        
        if not has_access:
            logger.warning(f"User {user.email} denied WebSocket access to session {session_id}")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Access denied")
            return
        
        # Accept connection
        await websocket.accept()
        
        # Add to connections
        if session_id not in self.session_connections:
            self.session_connections[session_id] = set()
        self.session_connections[session_id].add(websocket)
        
        # Store user info for this connection
        self.connection_users[websocket] = {
            "user_id": user.id,
            "user_email": user.email,
            "permission": user_permission,
            "session_id": session_id
        }
        
        logger.info(f"User {user.email} connected to chat session {session_id} via WebSocket")
        
        # Notify other users in the session
        await self.broadcast_to_session(session_id, {
            "type": "user_joined",
            "user_email": user.email,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_websocket=websocket)
    
    async def disconnect(self, websocket: WebSocket):
        """
        Disconnect user from chat session websocket.
        
        Args:
            websocket: WebSocket connection to disconnect
        """
        if websocket not in self.connection_users:
            return
        
        user_info = self.connection_users[websocket]
        session_id = user_info["session_id"]
        
        # Remove from connections
        if session_id in self.session_connections:
            self.session_connections[session_id].discard(websocket)
            if not self.session_connections[session_id]:
                del self.session_connections[session_id]
        
        del self.connection_users[websocket]
        
        logger.info(f"User {user_info['user_email']} disconnected from session {session_id}")
        
        # Notify other users
        await self.broadcast_to_session(session_id, {
            "type": "user_left",
            "user_email": user_info["user_email"],
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def send_message(
        self, 
        websocket: WebSocket, 
        message_data: dict,
        db_session: Session
    ):
        """
        Process and broadcast a chat message with permission verification.
        
        Args:
            websocket: Sender's WebSocket connection
            message_data: Message content and metadata
            db_session: Database session
        """
        if websocket not in self.connection_users:
            logger.error("Message from unregistered WebSocket connection")
            return
        
        user_info = self.connection_users[websocket]
        session_id = user_info["session_id"]
        user_permission = user_info["permission"]
        
        # Verify user can send messages (write permission required)
        if not has_permission(user_permission, "write"):
            logger.warning(f"User {user_info['user_email']} denied message send (permission: {user_permission})")
            await websocket.send_json({
                "type": "error",
                "message": "Insufficient permissions to send messages",
                "code": "PERMISSION_DENIED"
            })
            return
        
        try:
            # Validate message content
            if not message_data.get("content") or len(message_data["content"].strip()) == 0:
                await websocket.send_json({
                    "type": "error",
                    "message": "Message content is required",
                    "code": "INVALID_CONTENT"
                })
                return
            
            # Create and save message to database
            new_message = ChatMessage(
                chat_session_id=session_id,
                user_id=user_info["user_id"],
                content=message_data["content"],
                message_type=message_data.get("message_type", "user"),
                metadata=message_data.get("metadata", {})
            )
            
            db_session.add(new_message)
            db_session.commit()
            db_session.refresh(new_message)
            
            # Broadcast message to all connected users in the session
            broadcast_data = {
                "type": "message",
                "message_id": str(new_message.id),
                "content": new_message.content,
                "user_id": user_info["user_id"],
                "user_email": user_info["user_email"],
                "message_type": new_message.message_type,
                "timestamp": new_message.created_at.isoformat(),
                "metadata": new_message.metadata
            }
            
            await self.broadcast_to_session(session_id, broadcast_data)
            
            logger.info(f"Message broadcast to session {session_id} from user {user_info['user_email']}")
            
        except Exception as e:
            logger.error(f"Error processing message from user {user_info['user_id']}: {e}")
            await websocket.send_json({
                "type": "error",
                "message": "Failed to send message",
                "code": "SEND_FAILED"
            })
    
    async def broadcast_to_session(
        self, 
        session_id: UUID, 
        data: dict, 
        exclude_websocket: WebSocket = None
    ):
        """
        Broadcast data to all connected users in a session.
        
        Args:
            session_id: Chat session ID
            data: Data to broadcast
            exclude_websocket: WebSocket to exclude from broadcast
        """
        if session_id not in self.session_connections:
            return
        
        # Get list of websockets (copy to avoid modification during iteration)
        websockets = list(self.session_connections[session_id])
        
        # Send to all connected users
        for websocket in websockets:
            if websocket == exclude_websocket:
                continue
            
            try:
                await websocket.send_json(data)
            except Exception as e:
                logger.error(f"Error sending data to WebSocket: {e}")
                # Remove failed connection
                await self.disconnect(websocket)

# Global WebSocket manager instance
chat_manager = ChatWebSocketManager()

@router.websocket("/sessions/{session_id}/ws")
async def chat_websocket_endpoint(
    websocket: WebSocket,
    session_id: UUID,
    user: User = Depends(current_user),  # Authentication required
    db_session: Session = Depends(get_session)
):
    """
    WebSocket endpoint for real-time chat with OAuth permission enforcement.
    
    Args:
        websocket: WebSocket connection
        session_id: Chat session ID
        user: Authenticated user
        db_session: Database session
    """
    try:
        # Connect user to session with permission check
        await chat_manager.connect(websocket, session_id, user, db_session)
        
        # Handle incoming messages
        while True:
            try:
                # Receive message from client
                data = await websocket.receive_json()
                
                # Process different message types
                if data.get("type") == "message":
                    await chat_manager.send_message(websocket, data, db_session)
                elif data.get("type") == "typing":
                    # Broadcast typing indicator
                    typing_data = {
                        "type": "typing",
                        "user_email": user.email,
                        "is_typing": data.get("is_typing", False),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    await chat_manager.broadcast_to_session(session_id, typing_data, exclude_websocket=websocket)
                else:
                    logger.warning(f"Unknown message type: {data.get('type')}")
                    
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON format",
                    "code": "INVALID_JSON"
                })
            except Exception as e:
                logger.error(f"Error in WebSocket message handling: {e}")
                await websocket.send_json({
                    "type": "error",
                    "message": "Message processing failed",
                    "code": "PROCESSING_FAILED"
                })
    
    except Exception as e:
        logger.error(f"Error in WebSocket connection for user {user.id}: {e}")
    
    finally:
        # Clean up connection
        await chat_manager.disconnect(websocket)
```

## Testing Requirements

### Unit Tests
**File**: `backend/tests/unit/test_chat_permissions.py`

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException, status
from uuid import uuid4
from onyx.server.chat.chat_session import (
    get_chat_sessions,
    get_chat_session,
    create_chat_session,
    update_chat_session,
    delete_chat_session
)
from onyx.db.models import User, ChatSession

class TestChatPermissions:
    
    @pytest.fixture
    def mock_user(self):
        user = User()
        user.id = 1
        user.email = "test@example.com"
        return user
    
    @pytest.fixture
    def mock_session(self):
        session = ChatSession()
        session.id = uuid4()
        session.title = "Test Chat"
        session.user_id = 1
        session.is_shared = False
        session.collaborators = []
        return session
    
    @pytest.mark.asyncio
    async def test_get_chat_sessions_read_permission(self, mock_user, mock_session, mock_db_session):
        """Test chat session retrieval with read permission"""
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_session]
        
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "read"
            
            sessions = await get_chat_sessions(
                limit=50,
                offset=0,
                include_messages=False,
                user=mock_user,
                db_session=mock_db_session
            )
            
            assert len(sessions) == 1
            assert sessions[0].title == "Test Chat"
    
    @pytest.mark.asyncio
    async def test_create_chat_session_write_permission(self, mock_user, mock_db_session):
        """Test chat session creation with write permission"""
        from onyx.server.chat.models import ChatSessionCreate
        
        session_data = ChatSessionCreate(
            title="New Chat Session",
            description="Test description",
            is_shared=False
        )
        
        mock_db_session.add = MagicMock()
        mock_db_session.commit = MagicMock()
        mock_db_session.refresh = MagicMock()
        
        created_session = await create_chat_session(
            session_data=session_data,
            user=mock_user,
            db_session=mock_db_session
        )
        
        assert created_session.title == "New Chat Session"
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_access_private_session_denied(self, mock_user, mock_session, mock_db_session):
        """Test access denied to private session of another user"""
        mock_session.user_id = 999  # Different user
        mock_session.is_shared = False
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_session
        
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "read"
            
            with pytest.raises(HTTPException) as exc_info:
                await get_chat_session(
                    session_id=mock_session.id,
                    include_messages=True,
                    user=mock_user,
                    db_session=mock_db_session
                )
            
            assert exc_info.value.status_code == 403
            assert "Access denied to chat session" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_access_shared_session_allowed(self, mock_user, mock_session, mock_db_session):
        """Test access allowed to shared session"""
        mock_session.user_id = 999  # Different user
        mock_session.is_shared = True  # But shared
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_session
        
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "read"
            
            # Should not raise exception
            session = await get_chat_session(
                session_id=mock_session.id,
                include_messages=False,
                user=mock_user,
                db_session=mock_db_session
            )
            
            assert session.title == "Test Chat"
    
    @pytest.mark.asyncio
    async def test_admin_access_any_session(self, mock_user, mock_session, mock_db_session):
        """Test admin can access any session"""
        mock_session.user_id = 999  # Different user
        mock_session.is_shared = False  # Not shared
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_session
        
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "admin"
            
            # Should not raise exception
            session = await get_chat_session(
                session_id=mock_session.id,
                include_messages=False,
                user=mock_user,
                db_session=mock_db_session
            )
            
            assert session.title == "Test Chat"
```

### Integration Tests
**File**: `backend/tests/integration/test_chat_api_permissions.py`

```python
import pytest
from fastapi.testclient import TestClient
from onyx.main import app
from onyx.db.models import User, OAuthPermission, ChatSession, ChatMessage
from tests.integration.test_utils import TestUser
from uuid import uuid4

class TestChatAPIPermissions:
    
    @pytest.fixture
    def client(self):
        return TestClient(app)
    
    @pytest.fixture
    def read_user(self, db_session):
        user = TestUser.create_test_user(email="read@test.com")
        permission = OAuthPermission(
            user_id=user.id,
            permission_level="read",
            okta_groups=["Onyx-Readers"]
        )
        db_session.add(permission)
        db_session.commit()
        return user
    
    @pytest.fixture
    def write_user(self, db_session):
        user = TestUser.create_test_user(email="write@test.com")
        permission = OAuthPermission(
            user_id=user.id,
            permission_level="write",
            okta_groups=["Onyx-Writers"]
        )
        db_session.add(permission)
        db_session.commit()
        return user
    
    @pytest.fixture
    def test_chat_session(self, db_session, write_user):
        session = ChatSession(
            id=uuid4(),
            title="Test Chat Session",
            description="Test description",
            user_id=write_user.id,
            is_shared=True
        )
        db_session.add(session)
        db_session.commit()
        return session
    
    def test_get_chat_sessions_read_permission(self, client, read_user):
        """Test GET /chat/sessions with read permission"""
        with TestUser.logged_in_user(read_user):
            response = client.get("/api/chat/sessions")
            assert response.status_code == 200
            assert isinstance(response.json(), list)
    
    def test_create_chat_session_write_permission(self, client, write_user):
        """Test POST /chat/sessions with write permission"""
        session_data = {
            "title": "New Chat Session",
            "description": "Test description",
            "is_shared": False
        }
        
        with TestUser.logged_in_user(write_user):
            response = client.post("/api/chat/sessions", json=session_data)
            assert response.status_code == 201
            
            response_data = response.json()
            assert response_data["title"] == "New Chat Session"
    
    def test_create_chat_session_read_only_denied(self, client, read_user):
        """Test POST /chat/sessions denied with read-only permission"""
        session_data = {
            "title": "New Chat Session",
            "description": "Test description"
        }
        
        with TestUser.logged_in_user(read_user):
            response = client.post("/api/chat/sessions", json=session_data)
            assert response.status_code == 403
    
    def test_send_message_write_permission(self, client, write_user, test_chat_session):
        """Test sending message with write permission"""
        message_data = {
            "content": "Hello, this is a test message!",
            "message_type": "user"
        }
        
        with TestUser.logged_in_user(write_user):
            response = client.post(
                f"/api/chat/sessions/{test_chat_session.id}/messages",
                json=message_data
            )
            assert response.status_code == 201
            
            response_data = response.json()
            assert response_data["content"] == "Hello, this is a test message!"
    
    def test_send_message_read_only_denied(self, client, read_user, test_chat_session):
        """Test sending message denied with read-only permission"""
        message_data = {
            "content": "This should be denied",
            "message_type": "user"
        }
        
        with TestUser.logged_in_user(read_user):
            response = client.post(
                f"/api/chat/sessions/{test_chat_session.id}/messages",
                json=message_data
            )
            assert response.status_code == 403
    
    def test_get_messages_read_permission(self, client, read_user, test_chat_session):
        """Test getting messages with read permission"""
        with TestUser.logged_in_user(read_user):
            response = client.get(f"/api/chat/sessions/{test_chat_session.id}/messages")
            assert response.status_code == 200
            assert isinstance(response.json(), list)
    
    def test_websocket_connection_permission(self, client, write_user, test_chat_session):
        """Test WebSocket connection with proper permission"""
        with TestUser.logged_in_user(write_user):
            with client.websocket_connect(f"/api/chat/sessions/{test_chat_session.id}/ws") as websocket:
                # Connection should succeed
                data = websocket.receive_json()
                # Should receive connection confirmation or be able to send/receive
                assert websocket is not None
```

## Performance Requirements

- **Session List Response**: < 300ms for 50 sessions (95th percentile)
- **Message Send Latency**: < 100ms for real-time messaging
- **WebSocket Connection**: < 50ms connection establishment
- **Concurrent Chat Users**: Support 200+ concurrent users per session

## Security Considerations

1. **Session Access Control**: Proper enforcement of session ownership and sharing rules
2. **Message Privacy**: Users cannot access messages from private sessions
3. **Real-time Security**: WebSocket connections enforce same permission checks as REST API
4. **Data Isolation**: Read users cannot access collaborative features
5. **Audit Trail**: All permission-denied chat access attempts are logged

## Deployment Checklist

### Pre-deployment
- [ ] All unit tests pass (target: 95% coverage)
- [ ] Integration tests pass including WebSocket tests
- [ ] Performance tests meet latency requirements
- [ ] WebSocket connection and disconnection handling verified
- [ ] Real-time messaging features tested with permissions

### Deployment Steps
1. **Deploy Code**: Deploy updated chat routers with permission dependencies
2. **Verify WebSocket**: Test WebSocket connections with different permission levels
3. **Test Real-time**: Verify real-time messaging works with permission checks
4. **Monitor Performance**: Check response times and WebSocket connection rates
5. **Validate Permissions**: Confirm proper access control for all chat features

### Post-deployment
- [ ] Monitor chat API response times
- [ ] Verify WebSocket connections are stable
- [ ] Check real-time messaging performance
- [ ] Validate session access control is working
- [ ] Monitor for any permission-related errors

## Rollback Plan

### Immediate Rollback (< 5 minutes)
1. Set feature flag `ENABLE_CHAT_PERMISSIONS=false`
2. Restart application servers
3. Verify chat functionality works without permission checks

### Full Rollback (< 15 minutes)
1. Deploy previous version of chat routers
2. Restart services including WebSocket handlers
3. Run smoke tests on chat endpoints and WebSocket connections

## Definition of Done

- [ ] ✅ All chat endpoints protected with appropriate permission levels
- [ ] ✅ Session access control properly enforced
- [ ] ✅ Message operations require correct permissions
- [ ] ✅ WebSocket connections respect permission levels
- [ ] ✅ Real-time features maintained with permission checks
- [ ] ✅ Chat history filtering by user permissions
- [ ] ✅ Session sharing and collaboration rules enforced
- [ ] ✅ Integration tests covering all chat permission scenarios
- [ ] ✅ WebSocket permission enforcement tested
- [ ] ✅ Performance requirements met for real-time features
- [ ] ✅ Security review completed for chat access control
- [ ] ✅ Audit logging for chat permission denials
- [ ] ✅ Documentation updated for chat permission requirements

## Risk Assessment

**Medium Risk**: WebSocket connections may be complex to secure properly  
**Mitigation**: Thorough testing of WebSocket permission checks, gradual rollout

**Medium Risk**: Real-time features could be impacted by permission check latency  
**Mitigation**: Performance testing, optimized permission caching

**Low Risk**: Chat session access logic complexity  
**Mitigation**: Comprehensive unit tests, clear access rules documentation

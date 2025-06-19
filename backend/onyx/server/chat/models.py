"""
Pydantic models for chat API endpoints with OAuth permission protection.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, validator

from onyx.configs.constants import MessageType


class ChatSessionCreate(BaseModel):
    """Model for creating a new chat session."""
    title: str = Field(..., min_length=1, max_length=255, description="Chat session title")
    description: Optional[str] = Field(None, max_length=1000, description="Optional description")
    is_shared: Optional[bool] = Field(False, description="Whether session is publicly shared")
    chat_settings: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Chat configuration settings")


class ChatSessionUpdate(BaseModel):
    """Model for updating an existing chat session."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    is_shared: Optional[bool] = None
    chat_settings: Optional[Dict[str, Any]] = None


class ChatMessageCreate(BaseModel):
    """Model for creating a new chat message."""
    content: str = Field(..., min_length=1, description="Message content")
    message_type: Optional[str] = Field("user", description="Type of message")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class ChatMessageUpdate(BaseModel):
    """Model for updating an existing chat message."""
    content: Optional[str] = Field(None, min_length=1)
    metadata: Optional[Dict[str, Any]] = None


class ChatMessageResponse(BaseModel):
    """Response model for chat messages."""
    id: UUID
    chat_session_id: UUID
    user_id: UUID
    content: str
    message_type: str
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: Optional[datetime] = None
    is_edited: bool = False

    class Config:
        from_attributes = True

    @classmethod
    def from_chat_message(cls, message) -> "ChatMessageResponse":
        """Convert database ChatMessage to response model."""
        return cls(
            id=message.id,
            chat_session_id=message.chat_session_id,
            user_id=message.user_id if hasattr(message, 'user_id') else None,
            content=message.message if hasattr(message, 'message') else message.content,
            message_type=message.message_type.value if hasattr(message.message_type, 'value') else str(message.message_type),
            metadata=message.metadata if hasattr(message, 'metadata') else {},
            created_at=message.time_sent if hasattr(message, 'time_sent') else message.created_at,
            updated_at=getattr(message, 'updated_at', None),
            is_edited=getattr(message, 'is_edited', False)
        )


class ChatSessionResponse(BaseModel):
    """Response model for chat sessions."""
    id: UUID
    user_id: Optional[UUID]
    title: str
    description: Optional[str]
    is_shared: bool
    chat_settings: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    messages: Optional[List[ChatMessageResponse]] = None
    recent_messages: Optional[List[ChatMessageResponse]] = None

    class Config:
        from_attributes = True

    @classmethod
    def from_chat_session(cls, session) -> "ChatSessionResponse":
        """Convert database ChatSession to response model."""
        return cls(
            id=session.id,
            user_id=session.user_id,
            title=getattr(session, 'title', session.description or f"Chat {session.id}"),
            description=session.description,
            is_shared=session.shared_status.value == "public" if hasattr(session, 'shared_status') else False,
            chat_settings=getattr(session, 'chat_settings', {}),
            created_at=getattr(session, 'time_created', getattr(session, 'created_at', datetime.utcnow())),
            updated_at=getattr(session, 'time_updated', getattr(session, 'updated_at', datetime.utcnow()))
        )


class WebSocketMessage(BaseModel):
    """Model for WebSocket chat messages."""
    type: str = Field(..., description="Message type: 'message', 'typing', 'user_joined', 'user_left'")
    content: Optional[str] = Field(None, description="Message content for type 'message'")
    message_type: Optional[str] = Field("user", description="Type of chat message")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    is_typing: Optional[bool] = Field(None, description="Typing status for type 'typing'")
    user_email: Optional[str] = Field(None, description="User identifier for status messages")
    timestamp: Optional[str] = Field(None, description="ISO timestamp")


class WebSocketResponse(BaseModel):
    """Model for WebSocket responses."""
    type: str
    message_id: Optional[str] = None
    content: Optional[str] = None
    user_id: Optional[UUID] = None
    user_email: Optional[str] = None
    message_type: Optional[str] = None
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None
    code: Optional[str] = None  # For error responses
    message: Optional[str] = None  # For error responses

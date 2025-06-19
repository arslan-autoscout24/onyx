"""
Integration tests for chat API OAuth permission protection.

This module tests the OAuth permission-based access control for chat sessions,
messages, and WebSocket connections.
"""
import pytest
import asyncio
import json
from uuid import uuid4, UUID
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from unittest.mock import AsyncMock, patch, MagicMock

from onyx.db.models import User, ChatSession
from onyx.server.chat.models import (
    ChatSessionCreate, 
    ChatSessionUpdate, 
    ChatMessageCreate,
    ChatMessageUpdate
)


class TestChatSessionPermissions:
    """Test OAuth permission enforcement for chat session endpoints."""
    
    @pytest.fixture
    def mock_user_read(self):
        """Mock user with read permission."""
        user = MagicMock(spec=User)
        user.id = uuid4()
        user.email = "read@example.com"
        return user
    
    @pytest.fixture
    def mock_user_write(self):
        """Mock user with write permission."""
        user = MagicMock(spec=User)
        user.id = uuid4()
        user.email = "write@example.com"
        return user
    
    @pytest.fixture
    def mock_user_admin(self):
        """Mock user with admin permission."""
        user = MagicMock(spec=User)
        user.id = uuid4()
        user.email = "admin@example.com"
        return user
    
    @pytest.fixture
    def mock_chat_session(self, mock_user_write):
        """Mock chat session owned by write user."""
        session = MagicMock(spec=ChatSession)
        session.id = uuid4()
        session.user_id = mock_user_write.id
        session.description = "Test Session"
        session.deleted = False
        session.shared_status = MagicMock()
        session.shared_status.value = "private"
        session.time_updated = datetime.utcnow()
        return session
    
    @pytest.fixture
    def mock_shared_session(self, mock_user_write):
        """Mock shared chat session."""
        session = MagicMock(spec=ChatSession)
        session.id = uuid4()
        session.user_id = mock_user_write.id
        session.description = "Shared Session"
        session.deleted = False
        session.shared_status = MagicMock()
        session.shared_status.value = "public"
        session.time_updated = datetime.utcnow()
        return session
    
    @pytest.mark.asyncio
    async def test_get_sessions_read_permission(self, mock_user_read):
        """Test that users with read permission can list their sessions."""
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_sessions_by_user') as mock_get_sessions:
            
            mock_get_perm.return_value = "read"
            mock_get_sessions.return_value = []
            
            from onyx.server.chat.chat_session import get_chat_sessions
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            
            result = await get_chat_sessions(
                limit=50,
                offset=0,
                include_messages=False,
                user=mock_user_read,
                db_session=mock_db
            )
            
            assert isinstance(result, list)
            mock_get_perm.assert_called_once_with(mock_user_read.id)
            mock_get_sessions.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_session_access_control(self, mock_user_read, mock_chat_session):
        """Test session access control based on ownership and sharing."""
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session:
            
            mock_get_perm.return_value = "read"
            mock_get_session.return_value = mock_chat_session
            
            from onyx.server.chat.chat_session import get_chat_session
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            
            # Should raise 403 since read user doesn't own the private session
            with pytest.raises(HTTPException) as exc_info:
                await get_chat_session(
                    session_id=mock_chat_session.id,
                    include_messages=True,
                    user=mock_user_read,
                    db_session=mock_db
                )
            
            assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_get_shared_session_access(self, mock_user_read, mock_shared_session):
        """Test that read users can access shared sessions."""
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session, \
             patch('onyx.db.chat.get_chat_messages_by_session') as mock_get_messages:
            
            mock_get_perm.return_value = "read"
            mock_get_session.return_value = mock_shared_session
            mock_get_messages.return_value = []
            
            from onyx.server.chat.chat_session import get_chat_session
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            
            result = await get_chat_session(
                session_id=mock_shared_session.id,
                include_messages=True,
                user=mock_user_read,
                db_session=mock_db
            )
            
            assert result.id == mock_shared_session.id
    
    @pytest.mark.asyncio
    async def test_create_session_write_permission(self, mock_user_write):
        """Test that write permission is required to create sessions."""
        with patch('onyx.db.chat.create_chat_session') as mock_create:
            
            mock_session = MagicMock()
            mock_session.id = uuid4()
            mock_create.return_value = mock_session
            
            from onyx.server.chat.chat_session import create_chat_session_endpoint
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            session_data = ChatSessionCreate(title="Test Session")
            
            result = await create_chat_session_endpoint(
                session_data=session_data,
                user=mock_user_write,
                db_session=mock_db
            )
            
            mock_create.assert_called_once()
            assert result.id == mock_session.id
    
    @pytest.mark.asyncio
    async def test_update_session_owner_access(self, mock_user_write, mock_chat_session):
        """Test that session owner can update their sessions."""
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session:
            
            mock_get_perm.return_value = "write"
            mock_get_session.return_value = mock_chat_session
            
            from onyx.server.chat.chat_session import update_chat_session
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            mock_db.commit = MagicMock()
            mock_db.refresh = MagicMock()
            
            session_data = ChatSessionUpdate(title="Updated Title")
            
            result = await update_chat_session(
                session_id=mock_chat_session.id,
                session_data=session_data,
                user=mock_user_write,
                db_session=mock_db
            )
            
            assert mock_chat_session.description == "Updated Title"
            mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_session_owner_only(self, mock_user_read, mock_chat_session):
        """Test that only owners (or admins) can delete sessions."""
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session:
            
            mock_get_perm.return_value = "read"
            mock_get_session.return_value = mock_chat_session
            
            from onyx.server.chat.chat_session import delete_chat_session_endpoint
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            
            # Should raise 403 since read user is not owner and not admin
            with pytest.raises(HTTPException) as exc_info:
                await delete_chat_session_endpoint(
                    session_id=mock_chat_session.id,
                    user=mock_user_read,
                    db_session=mock_db
                )
            
            assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_admin_access_all_sessions(self, mock_user_admin, mock_chat_session):
        """Test that admin users can access any session."""
        with patch('onyx.server.chat.chat_session.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session, \
             patch('onyx.db.chat.get_chat_messages_by_session') as mock_get_messages:
            
            mock_get_perm.return_value = "admin"
            mock_get_session.return_value = mock_chat_session
            mock_get_messages.return_value = []
            
            from onyx.server.chat.chat_session import get_chat_session
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            
            result = await get_chat_session(
                session_id=mock_chat_session.id,
                include_messages=True,
                user=mock_user_admin,
                db_session=mock_db
            )
            
            assert result.id == mock_chat_session.id


class TestChatMessagePermissions:
    """Test OAuth permission enforcement for chat message endpoints."""
    
    @pytest.fixture
    def mock_user_write(self):
        """Mock user with write permission."""
        user = MagicMock(spec=User)
        user.id = uuid4()
        user.email = "write@example.com"
        return user
    
    @pytest.fixture
    def mock_chat_message(self, mock_user_write):
        """Mock chat message."""
        from onyx.configs.constants import MessageType
        message = MagicMock()
        message.id = 1
        message.chat_session_id = uuid4()
        message.message = "Test message"
        message.message_type = MessageType.USER
        message.time_sent = datetime.utcnow()
        return message
    
    @pytest.fixture
    def mock_chat_session(self, mock_user_write):
        """Mock chat session."""
        session = MagicMock(spec=ChatSession)
        session.id = uuid4()
        session.user_id = mock_user_write.id
        session.shared_status = MagicMock()
        session.shared_status.value = "private"
        return session
    
    @pytest.mark.asyncio
    async def test_send_message_write_permission(self, mock_user_write, mock_chat_session):
        """Test that write permission is required to send messages."""
        with patch('onyx.server.chat.chat_message.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session:
            
            mock_get_perm.return_value = "write"
            mock_get_session.return_value = mock_chat_session
            
            from onyx.server.chat.chat_message import send_chat_message
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            mock_db.add = MagicMock()
            mock_db.commit = MagicMock()
            mock_db.refresh = MagicMock()
            
            message_data = ChatMessageCreate(content="Test message")
            
            result = await send_chat_message(
                session_id=mock_chat_session.id,
                message_data=message_data,
                user=mock_user_write,
                db_session=mock_db
            )
            
            mock_db.add.assert_called_once()
            mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_read_messages_session_access(self, mock_user_write, mock_chat_session):
        """Test that message access follows session access rules."""
        with patch('onyx.server.chat.chat_message.get_user_oauth_permission') as mock_get_perm, \
             patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session, \
             patch('onyx.db.chat.get_chat_messages_by_session') as mock_get_messages:
            
            mock_get_perm.return_value = "read"
            mock_get_session.return_value = mock_chat_session
            mock_get_messages.return_value = []
            
            from onyx.server.chat.chat_message import get_chat_messages
            
            # Mock dependencies
            mock_db = MagicMock(spec=Session)
            
            result = await get_chat_messages(
                session_id=mock_chat_session.id,
                limit=100,
                offset=0,
                user=mock_user_write,
                db_session=mock_db
            )
            
            assert isinstance(result, list)
            mock_get_messages.assert_called_once()


class TestWebSocketPermissions:
    """Test OAuth permission enforcement for WebSocket connections."""
    
    @pytest.fixture
    def mock_user_read(self):
        """Mock user with read permission."""
        user = MagicMock(spec=User)
        user.id = uuid4()
        user.email = "read@example.com"
        return user
    
    @pytest.fixture
    def mock_user_write(self):
        """Mock user with write permission."""
        user = MagicMock(spec=User)
        user.id = uuid4()
        user.email = "write@example.com"
        return user
    
    @pytest.fixture
    def mock_websocket(self):
        """Mock WebSocket connection."""
        websocket = AsyncMock()
        websocket.accept = AsyncMock()
        websocket.close = AsyncMock()
        websocket.send_json = AsyncMock()
        return websocket
    
    @pytest.fixture
    def mock_chat_session(self, mock_user_write):
        """Mock chat session."""
        session = MagicMock(spec=ChatSession)
        session.id = uuid4()
        session.user_id = mock_user_write.id
        session.shared_status = MagicMock()
        session.shared_status.value = "private"
        return session
    
    @pytest.mark.asyncio
    async def test_websocket_connect_permission_check(
        self, 
        mock_websocket, 
        mock_user_read, 
        mock_chat_session
    ):
        """Test WebSocket connection permission verification."""
        with patch('onyx.db.chat.get_chat_session_by_id') as mock_get_session, \
             patch('onyx.server.chat.websocket.get_user_oauth_permission') as mock_get_perm:
            
            mock_get_session.return_value = mock_chat_session
            mock_get_perm.return_value = "read"
            
            from onyx.server.chat.websocket import ChatWebSocketManager
            
            manager = ChatWebSocketManager()
            mock_db = MagicMock(spec=Session)
            
            # Should fail because read user doesn't own private session
            result = await manager.connect(
                websocket=mock_websocket,
                session_id=mock_chat_session.id,
                user=mock_user_read,
                db_session=mock_db
            )
            
            assert result is False
            mock_websocket.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_websocket_send_message_write_permission(
        self,
        mock_websocket,
        mock_user_read,
        mock_chat_session
    ):
        """Test that sending messages via WebSocket requires write permission."""
        from onyx.server.chat.websocket import ChatWebSocketManager
        
        manager = ChatWebSocketManager()
        
        # Manually add connection (simulating successful connect)
        manager.connection_users[mock_websocket] = {
            "user_id": mock_user_read.id,
            "user_email": mock_user_read.email,
            "permission": "read",  # Read permission
            "session_id": mock_chat_session.id
        }
        
        mock_db = MagicMock(spec=Session)
        message_data = {"content": "Test message"}
        
        await manager.send_message(
            websocket=mock_websocket,
            message_data=message_data,
            db_session=mock_db
        )
        
        # Should send error due to insufficient permissions
        mock_websocket.send_json.assert_called_once()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["type"] == "error"
        assert call_args["code"] == "PERMISSION_DENIED"


# Helper function to create test fixtures if needed
def create_test_user(permission_level: str) -> User:
    """Create a test user with specified permission level."""
    user = User()
    user.id = uuid4()
    user.email = f"{permission_level}@example.com"
    return user


def create_test_session(owner_id: UUID, is_shared: bool = False) -> ChatSession:
    """Create a test chat session."""
    session = ChatSession()
    session.id = uuid4()
    session.user_id = owner_id
    session.description = "Test Session"
    session.deleted = False
    if hasattr(session, 'shared_status'):
        from onyx.db.enums import ChatSessionSharedStatus
        session.shared_status = ChatSessionSharedStatus.PUBLIC if is_shared else ChatSessionSharedStatus.PRIVATE
    return session


# Integration test configuration
@pytest.fixture(scope="session")
def test_app():
    """Create test FastAPI app for integration testing."""
    from fastapi import FastAPI
    from onyx.server.chat.router import router
    
    app = FastAPI()
    app.include_router(router)
    return app


# Add HTTP status code import for tests
from fastapi import HTTPException

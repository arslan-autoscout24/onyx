"""
Unit tests for chat API permission logic.

This module contains unit tests for the permission checking logic used
in the chat API endpoints.
"""
import pytest
from uuid import uuid4
from unittest.mock import MagicMock

from onyx.db.models import User, ChatSession


class TestPermissionLogic:
    """Test the permission checking functions."""
    
    def test_check_session_access_owner(self):
        """Test session access for owner."""
        from onyx.server.chat.chat_session import check_session_access
        
        user = MagicMock(spec=User)
        user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = user.id
        
        # Owner should have access
        assert check_session_access(session, user, "read") is True
        assert check_session_access(session, user, "write") is True
        assert check_session_access(session, user, "admin") is True
    
    def test_check_session_access_shared(self):
        """Test session access for shared sessions."""
        from onyx.server.chat.chat_session import check_session_access
        
        owner = MagicMock(spec=User)
        owner.id = uuid4()
        
        other_user = MagicMock(spec=User) 
        other_user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = owner.id
        session.shared_status = MagicMock()
        session.shared_status.value = "public"
        
        # Any user should have access to public shared session
        assert check_session_access(session, other_user, "read") is True
        assert check_session_access(session, other_user, "write") is True
        assert check_session_access(session, other_user, "admin") is True
    
    def test_check_session_access_private_denied(self):
        """Test session access denied for private sessions."""
        from onyx.server.chat.chat_session import check_session_access
        
        owner = MagicMock(spec=User)
        owner.id = uuid4()
        
        other_user = MagicMock(spec=User)
        other_user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = owner.id
        session.shared_status = MagicMock()
        session.shared_status.value = "private"
        
        # Non-owner should not have access to private session
        assert check_session_access(session, other_user, "read") is False
        assert check_session_access(session, other_user, "write") is False
    
    def test_check_session_access_admin_override(self):
        """Test admin permission overrides access control."""
        from onyx.server.chat.chat_session import check_session_access
        
        owner = MagicMock(spec=User)
        owner.id = uuid4()
        
        admin_user = MagicMock(spec=User)
        admin_user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = owner.id
        session.shared_status = MagicMock()
        session.shared_status.value = "private"
        
        # Admin should have access to any session
        assert check_session_access(session, admin_user, "admin") is True
    
    def test_check_session_write_access_owner(self):
        """Test write access for session owner."""
        from onyx.server.chat.chat_session import check_session_write_access
        
        user = MagicMock(spec=User)
        user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = user.id
        
        # Owner should have write access
        assert check_session_write_access(session, user, "read") is True
        assert check_session_write_access(session, user, "write") is True
        assert check_session_write_access(session, user, "admin") is True
    
    def test_check_session_write_access_shared_write_user(self):
        """Test write access for write users on shared sessions."""
        from onyx.server.chat.chat_session import check_session_write_access
        
        owner = MagicMock(spec=User)
        owner.id = uuid4()
        
        write_user = MagicMock(spec=User)
        write_user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = owner.id
        session.shared_status = MagicMock()
        session.shared_status.value = "public"
        
        # Write user should have write access to shared session
        assert check_session_write_access(session, write_user, "write") is True
        assert check_session_write_access(session, write_user, "admin") is True
    
    def test_check_session_write_access_shared_read_user_denied(self):
        """Test write access denied for read users on shared sessions."""
        from onyx.server.chat.chat_session import check_session_write_access
        
        owner = MagicMock(spec=User)
        owner.id = uuid4()
        
        read_user = MagicMock(spec=User)
        read_user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = owner.id
        session.shared_status = MagicMock()
        session.shared_status.value = "public"
        
        # Read user should not have write access even to shared session
        assert check_session_write_access(session, read_user, "read") is False
    
    def test_check_session_write_access_admin_override(self):
        """Test admin write access override."""
        from onyx.server.chat.chat_session import check_session_write_access
        
        owner = MagicMock(spec=User)
        owner.id = uuid4()
        
        admin_user = MagicMock(spec=User)
        admin_user.id = uuid4()
        
        session = MagicMock(spec=ChatSession)
        session.user_id = owner.id
        session.shared_status = MagicMock()
        session.shared_status.value = "private"
        
        # Admin should have write access to any session
        assert check_session_write_access(session, admin_user, "admin") is True


class TestPermissionHierarchy:
    """Test permission hierarchy logic."""
    
    def test_has_permission_hierarchy(self):
        """Test permission hierarchy checking."""
        from onyx.server.auth_check import has_permission
        
        # Admin has all permissions
        assert has_permission("admin", "read") is True
        assert has_permission("admin", "write") is True
        assert has_permission("admin", "admin") is True
        
        # Write has read and write
        assert has_permission("write", "read") is True
        assert has_permission("write", "write") is True
        assert has_permission("write", "admin") is False
        
        # Read only has read
        assert has_permission("read", "read") is True
        assert has_permission("read", "write") is False
        assert has_permission("read", "admin") is False
        
        # Invalid permission levels
        assert has_permission("invalid", "read") is False
        assert has_permission("read", "invalid") is False


class TestChatModels:
    """Test chat API models."""
    
    def test_chat_session_create_validation(self):
        """Test chat session creation model validation."""
        from onyx.server.chat.models import ChatSessionCreate
        
        # Valid creation
        valid_data = ChatSessionCreate(
            title="Test Session",
            description="A test session",
            is_shared=False
        )
        assert valid_data.title == "Test Session"
        assert valid_data.is_shared is False
        
        # Invalid - empty title
        with pytest.raises(ValueError):
            ChatSessionCreate(title="")
    
    def test_chat_message_create_validation(self):
        """Test chat message creation model validation."""
        from onyx.server.chat.models import ChatMessageCreate
        
        # Valid creation
        valid_data = ChatMessageCreate(
            content="Hello world",
            message_type="user"
        )
        assert valid_data.content == "Hello world"
        assert valid_data.message_type == "user"
        
        # Invalid - empty content
        with pytest.raises(ValueError):
            ChatMessageCreate(content="")
    
    def test_websocket_message_validation(self):
        """Test WebSocket message model validation."""
        from onyx.server.chat.models import WebSocketMessage
        
        # Valid message
        valid_msg = WebSocketMessage(
            type="message",
            content="Hello",
            message_type="user"
        )
        assert valid_msg.type == "message"
        assert valid_msg.content == "Hello"
        
        # Valid typing indicator
        valid_typing = WebSocketMessage(
            type="typing",
            is_typing=True
        )
        assert valid_typing.type == "typing"
        assert valid_typing.is_typing is True
        
        # Invalid - missing required type
        with pytest.raises(ValueError):
            WebSocketMessage(content="Hello")

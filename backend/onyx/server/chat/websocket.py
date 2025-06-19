"""
WebSocket implementation for real-time chat with OAuth permission protection.

This module provides WebSocket endpoints for real-time chat messaging with proper
permission-based access control using OAuth permissions.
"""
from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from typing import Dict, Set, Optional, Any, List
from uuid import UUID
import json
import asyncio
from datetime import datetime
from sqlalchemy.orm import Session

from onyx.auth.users import current_user
from onyx.server.auth_check import get_oauth_permission, has_permission
from onyx.db.engine import get_session
from onyx.db.models import User, ChatSession, ChatMessage
from onyx.db.chat import get_chat_session_by_id
from onyx.server.chat.models import WebSocketMessage, WebSocketResponse
from onyx.server.chat.chat_session import (
    get_user_oauth_permission,
    check_session_access,
    check_session_write_access
)
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
    ) -> bool:
        """
        Connect user to chat session websocket with permission verification.
        
        Args:
            websocket: WebSocket connection
            session_id: Chat session ID
            user: Authenticated user
            db_session: Database session
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Verify session exists
            session = get_chat_session_by_id(
                chat_session_id=session_id,
                user_id=user.id,
                db_session=db_session,
                include_deleted=False
            )
        except ValueError:
            logger.warning(f"Session {session_id} not found for WebSocket connection")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session not found")
            return False
        
        # Check user permission to access this session
        user_permission = await get_user_oauth_permission(user.id)
        if not check_session_access(session, user, user_permission):
            logger.warning(f"User {user.email} denied WebSocket access to session {session_id}")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Access denied")
            return False
        
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
        
        # Send connection confirmation
        await websocket.send_json({
            "type": "connection_confirmed",
            "session_id": str(session_id),
            "user_email": user.email,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Notify other users in the session
        await self.broadcast_to_session(session_id, {
            "type": "user_joined",
            "user_email": user.email,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_websocket=websocket)
        
        return True
    
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
            from onyx.configs.constants import MessageType
            new_message = ChatMessage(
                chat_session_id=session_id,
                message=message_data["content"],
                token_count=0,
                message_type=MessageType.USER,
                time_sent=datetime.utcnow()
            )
            
            db_session.add(new_message)
            db_session.commit()
            db_session.refresh(new_message)
            
            # Broadcast message to all connected users in the session
            broadcast_data = {
                "type": "message",
                "message_id": str(new_message.id),
                "content": new_message.message,
                "user_id": str(user_info["user_id"]),
                "user_email": user_info["user_email"],
                "message_type": new_message.message_type.value if hasattr(new_message.message_type, 'value') else str(new_message.message_type),
                "timestamp": new_message.time_sent.isoformat(),
                "metadata": message_data.get("metadata", {})
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
    
    async def handle_typing(
        self,
        websocket: WebSocket,
        typing_data: dict
    ):
        """
        Handle typing indicator messages.
        
        Args:
            websocket: Sender's WebSocket connection
            typing_data: Typing status data
        """
        if websocket not in self.connection_users:
            return
        
        user_info = self.connection_users[websocket]
        session_id = user_info["session_id"]
        
        # Broadcast typing indicator
        typing_broadcast = {
            "type": "typing",
            "user_email": user_info["user_email"],
            "is_typing": typing_data.get("is_typing", False),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.broadcast_to_session(session_id, typing_broadcast, exclude_websocket=websocket)
    
    async def broadcast_to_session(
        self, 
        session_id: UUID, 
        data: dict, 
        exclude_websocket: Optional[WebSocket] = None
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
        disconnected_websockets = []
        for websocket in websockets:
            if websocket == exclude_websocket:
                continue
            
            try:
                await websocket.send_json(data)
            except Exception as e:
                logger.error(f"Error sending data to WebSocket: {e}")
                # Mark for disconnection
                disconnected_websockets.append(websocket)
        
        # Clean up failed connections
        for websocket in disconnected_websockets:
            await self.disconnect(websocket)
    
    def get_session_user_count(self, session_id: UUID) -> int:
        """Get the number of connected users for a session."""
        return len(self.session_connections.get(session_id, set()))
    
    def get_connected_users(self, session_id: UUID) -> List[str]:
        """Get list of connected user emails for a session."""
        if session_id not in self.session_connections:
            return []
        
        users = []
        for websocket in self.session_connections[session_id]:
            if websocket in self.connection_users:
                users.append(self.connection_users[websocket]["user_email"])
        
        return users


# Global WebSocket manager instance
chat_manager = ChatWebSocketManager()


# WebSocket endpoint function - will be added to router in main application
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
    connected = False
    try:
        # Connect user to session with permission check
        connected = await chat_manager.connect(websocket, session_id, user, db_session)
        
        if not connected:
            return
        
        # Handle incoming messages
        while True:
            try:
                # Receive message from client
                data = await websocket.receive_json()
                
                # Validate message structure
                try:
                    message = WebSocketMessage(**data)
                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Invalid message format: {e}",
                        "code": "INVALID_FORMAT"
                    })
                    continue
                
                # Process different message types
                if message.type == "message":
                    await chat_manager.send_message(websocket, data, db_session)
                elif message.type == "typing":
                    await chat_manager.handle_typing(websocket, data)
                elif message.type == "ping":
                    # Respond to ping with pong
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                else:
                    logger.warning(f"Unknown message type: {message.type}")
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Unknown message type: {message.type}",
                        "code": "UNKNOWN_MESSAGE_TYPE"
                    })
                    
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
        if connected:
            await chat_manager.disconnect(websocket)

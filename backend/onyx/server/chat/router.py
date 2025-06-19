"""
Main chat router that combines all chat API endpoints with OAuth permission protection.

This module aggregates chat session, message, and WebSocket endpoints into a single
router with proper permission-based access control.
"""
from fastapi import APIRouter
from onyx.server.chat.chat_session import router as session_router
from onyx.server.chat.chat_message import router as message_router
from onyx.server.chat.websocket import chat_websocket_endpoint

# Create main chat router
router = APIRouter(prefix="/chat-api", tags=["chat-api"])

# Include session endpoints
router.include_router(session_router, prefix="")

# Include message endpoints  
router.include_router(message_router, prefix="")

# Add WebSocket endpoint
router.websocket("/sessions/{session_id}/ws")(chat_websocket_endpoint)

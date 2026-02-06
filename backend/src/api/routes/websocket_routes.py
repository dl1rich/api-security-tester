"""WebSocket API routes for real-time notifications."""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import List, Optional
import uuid

from websocket.manager import websocket_manager, NotificationType, WebSocketMessage

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    session_id: Optional[str] = Query(None),
    subscriptions: Optional[str] = Query("all")  # Comma-separated list
):
    """Main WebSocket endpoint for real-time notifications."""
    
    # Generate unique connection ID
    connection_id = str(uuid.uuid4())
    
    # Parse subscriptions
    subscription_list = [s.strip() for s in subscriptions.split(",")] if subscriptions else ["all"]
    
    try:
        # Connect to WebSocket manager
        connection = await websocket_manager.connect(
            websocket, 
            connection_id, 
            subscription_list
        )
        
        # Subscribe to specific session if provided
        if session_id:
            websocket_manager.subscribe_to_session(connection_id, session_id)
            logger.info(f"WebSocket {connection_id} subscribed to session {session_id}")
        
        # Send initial connection info
        await connection.send_message(WebSocketMessage(
            NotificationType.SESSION_UPDATE,
            {
                'status': 'ready',
                'connection_id': connection_id,
                'session_id': session_id,
                'subscriptions': subscription_list,
                'message': 'WebSocket connection established successfully'
            }
        ))
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages from client
                message = await websocket.receive_text()
                await handle_client_message(connection_id, message, session_id)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error handling message from {connection_id}: {e}")
                await websocket_manager.notify_error(
                    session_id or "system",
                    f"WebSocket error: {str(e)}"
                )
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket {connection_id} disconnected")
    except Exception as e:
        logger.error(f"WebSocket connection error for {connection_id}: {e}")
    finally:
        # Clean up connection
        await websocket_manager.disconnect(connection_id)


async def handle_client_message(connection_id: str, message: str, session_id: Optional[str]):
    """Handle messages sent from client to server."""
    
    try:
        import json
        data = json.loads(message)
        message_type = data.get('type')
        payload = data.get('data', {})
        
        if message_type == 'ping':
            # Respond to ping with pong
            pong_message = WebSocketMessage(
                NotificationType.HEARTBEAT,
                {'type': 'pong', 'timestamp': data.get('timestamp')}
            )
            await websocket_manager.send_to_connection(connection_id, pong_message)
        
        elif message_type == 'subscribe':
            # Handle subscription requests
            channels = payload.get('channels', [])
            if channels:
                connection = websocket_manager.connections.get(connection_id)
                if connection:
                    for channel in channels:
                        connection.add_subscription(channel)
                    
                    response = WebSocketMessage(
                        NotificationType.SESSION_UPDATE,
                        {
                            'type': 'subscription_updated',
                            'subscriptions': list(connection.subscriptions)
                        }
                    )
                    await websocket_manager.send_to_connection(connection_id, response)
        
        elif message_type == 'unsubscribe':
            # Handle unsubscription requests
            channels = payload.get('channels', [])
            if channels:
                connection = websocket_manager.connections.get(connection_id)
                if connection:
                    for channel in channels:
                        connection.remove_subscription(channel)
                    
                    response = WebSocketMessage(
                        NotificationType.SESSION_UPDATE,
                        {
                            'type': 'subscription_updated',
                            'subscriptions': list(connection.subscriptions)
                        }
                    )
                    await websocket_manager.send_to_connection(connection_id, response)
        
        elif message_type == 'get_status':
            # Send current connection status
            stats = websocket_manager.get_connection_stats()
            response = WebSocketMessage(
                NotificationType.SESSION_UPDATE,
                {
                    'type': 'status',
                    'connection_stats': stats
                }
            )
            await websocket_manager.send_to_connection(connection_id, response)
        
        else:
            logger.warning(f"Unknown message type from {connection_id}: {message_type}")
    
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON from {connection_id}: {message}")
    except Exception as e:
        logger.error(f"Error handling client message from {connection_id}: {e}")


@router.get("/ws/stats")
async def get_websocket_stats():
    """Get WebSocket connection statistics."""
    return websocket_manager.get_connection_stats()


@router.post("/ws/broadcast")
async def broadcast_message(message_type: str, data: dict, session_id: Optional[str] = None):
    """Broadcast a message to WebSocket clients (for testing/admin use)."""
    
    try:
        # Convert string to enum
        notification_type = NotificationType(message_type)
        
        message = WebSocketMessage(
            notification_type,
            data,
            session_id
        )
        
        if session_id:
            await websocket_manager.broadcast_to_session(session_id, message)
        else:
            await websocket_manager.broadcast_to_all(message)
        
        return {
            'success': True,
            'message': f'Broadcast sent to {"session " + session_id if session_id else "all connections"}'
        }
    
    except ValueError:
        return {
            'success': False,
            'error': f'Invalid message type: {message_type}'
        }
    except Exception as e:
        logger.error(f"Error broadcasting message: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@router.post("/ws/notify")
async def send_notification(
    notification_type: str,
    session_id: str,
    title: str,
    message: str,
    data: Optional[dict] = None
):
    """Send a structured notification to a session."""
    
    try:
        # Convert string to enum
        msg_type = NotificationType(notification_type)
        
        notification_data = {
            'title': title,
            'message': message,
            'timestamp': data.get('timestamp') if data else None,
        }
        
        if data:
            notification_data.update(data)
        
        notification = WebSocketMessage(
            msg_type,
            notification_data,
            session_id
        )
        
        await websocket_manager.broadcast_to_session(session_id, notification)
        
        return {
            'success': True,
            'notification_sent': True,
            'session_id': session_id
        }
    
    except ValueError:
        return {
            'success': False,
            'error': f'Invalid notification type: {notification_type}'
        }
    except Exception as e:
        logger.error(f"Error sending notification: {e}")
        return {
            'success': False,
            'error': str(e)
        }
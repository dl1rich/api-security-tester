"""WebSocket connection manager for real-time notifications."""

import asyncio
import json
import logging
from typing import Dict, List, Set, Any, Optional
from datetime import datetime, timedelta
from fastapi import WebSocket, WebSocketDisconnect
from enum import Enum

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    """Types of notifications."""
    TEST_STARTED = "test_started"
    TEST_PROGRESS = "test_progress"
    TEST_COMPLETED = "test_completed"
    TEST_FAILED = "test_failed"
    VULNERABILITY_FOUND = "vulnerability_found"
    ENDPOINT_TESTED = "endpoint_tested"
    DETECTOR_STARTED = "detector_started"
    DETECTOR_COMPLETED = "detector_completed"
    SESSION_UPDATE = "session_update"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class WebSocketMessage:
    """Structured WebSocket message."""
    
    def __init__(self, message_type: NotificationType, data: Dict[str, Any],
                 session_id: str = None, timestamp: datetime = None):
        self.type = message_type
        self.data = data
        self.session_id = session_id
        self.timestamp = timestamp or datetime.utcnow()
        self.message_id = f"{self.timestamp.timestamp()}_{message_type.value}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for JSON serialization."""
        return {
            'id': self.message_id,
            'type': self.type.value,
            'data': self.data,
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat(),
        }
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        try:
            return json.dumps(self.to_dict(), default=str)
        except Exception as e:
            logger.error(f"Error serializing message to JSON: {e}")
            # Fallback to basic message
            return json.dumps({
                'type': self.type.value,
                'error': 'Serialization failed',
                'timestamp': self.timestamp.isoformat()
            })


class WebSocketConnection:
    """Represents a WebSocket connection with improved error handling."""
    
    def __init__(self, websocket: WebSocket, connection_id: str, 
                 subscriptions: Set[str] = None):
        self.websocket = websocket
        self.connection_id = connection_id
        self.subscriptions = subscriptions or set()
        self.connected_at = datetime.utcnow()
        self.last_heartbeat = datetime.utcnow()
        self.is_active = True
        self.send_failures = 0
        self.max_failures = 3  # Max consecutive failures before marking inactive
        self.message_queue = asyncio.Queue(maxsize=100)  # Buffer for messages
    
    async def send_message(self, message: WebSocketMessage, retry: bool = True):
        """Send a message to this connection with retry logic."""
        if not self.is_active:
            return False
        
        try:
            await self.websocket.send_text(message.to_json())
            self.send_failures = 0  # Reset failure count on success
            logger.debug(f"Sent message {message.type.value} to connection {self.connection_id}")
            return True
        except WebSocketDisconnect:
            logger.info(f"Connection {self.connection_id} disconnected during send")
            self.is_active = False
            return False
        except Exception as e:
            self.send_failures += 1
            logger.error(f"Failed to send message to {self.connection_id} (attempt {self.send_failures}): {e}")
            
            if self.send_failures >= self.max_failures:
                logger.warning(f"Connection {self.connection_id} marked inactive after {self.send_failures} failures")
                self.is_active = False
                return False
            
            # Retry once if enabled
            if retry and self.send_failures < 2:
                await asyncio.sleep(0.1)
                return await self.send_message(message, retry=False)
            
            return False
    
    async def send_heartbeat(self):
        """Send heartbeat to connection."""
        heartbeat = WebSocketMessage(
            NotificationType.HEARTBEAT,
            {'timestamp': datetime.utcnow().isoformat()}
        )
        success = await self.send_message(heartbeat, retry=False)
        if success:
            self.last_heartbeat = datetime.utcnow()
        return success
    
    def is_stale(self, timeout_seconds: int = 120) -> bool:
        """Check if connection hasn't received heartbeat response in timeout period."""
        return (datetime.utcnow() - self.last_heartbeat).total_seconds() > timeout_seconds
    
    def is_subscribed_to(self, channel: str) -> bool:
        """Check if connection is subscribed to a channel."""
        return channel in self.subscriptions or 'all' in self.subscriptions
    
    def add_subscription(self, channel: str):
        """Add subscription to a channel."""
        self.subscriptions.add(channel)
    
    def remove_subscription(self, channel: str):
        """Remove subscription from a channel."""
        self.subscriptions.discard(channel)


class WebSocketManager:
    """Manages WebSocket connections and broadcasting with improved reliability."""
    
    def __init__(self):
        self.connections: Dict[str, WebSocketConnection] = {}
        self.session_connections: Dict[str, Set[str]] = {}  # session_id -> connection_ids
        self.heartbeat_interval = 30  # seconds
        self.cleanup_interval = 60  # seconds
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()  # For thread-safe operations
    
    async def start(self):
        """Start background tasks."""
        if self._running:
            return
        
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("WebSocket manager started")
    
    async def stop(self):
        """Stop background tasks."""
        self._running = False
        
        # Cancel background tasks
        tasks_to_cancel = []
        if self._heartbeat_task and not self._heartbeat_task.done():
            tasks_to_cancel.append(self._heartbeat_task)
        if self._cleanup_task and not self._cleanup_task.done():
            tasks_to_cancel.append(self._cleanup_task)
        
        for task in tasks_to_cancel:
            task.cancel()
        
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
        
        # Close all connections
        async with self._lock:
            connection_ids = list(self.connections.keys())
        
        for conn_id in connection_ids:
            await self.disconnect(conn_id)
        
        logger.info("WebSocket manager stopped")
    
    async def connect(self, websocket: WebSocket, connection_id: str,
                     subscriptions: List[str] = None) -> WebSocketConnection:
        """Add a new WebSocket connection."""
        try:
            await websocket.accept()
        except Exception as e:
            logger.error(f"Failed to accept WebSocket connection {connection_id}: {e}")
            raise
        
        connection = WebSocketConnection(
            websocket, 
            connection_id, 
            set(subscriptions or ['all'])
        )
        
        async with self._lock:
            self.connections[connection_id] = connection
        
        # Send connection confirmation
        welcome_message = WebSocketMessage(
            NotificationType.SESSION_UPDATE,
            {
                'status': 'connected',
                'connection_id': connection_id,
                'subscriptions': list(connection.subscriptions),
                'server_time': datetime.utcnow().isoformat()
            }
        )
        await connection.send_message(welcome_message)
        
        logger.info(f"WebSocket connection {connection_id} established with subscriptions: {connection.subscriptions}")
        return connection
    
    async def disconnect(self, connection_id: str):
        """Remove a WebSocket connection."""
        async with self._lock:
            if connection_id not in self.connections:
                return
            
            connection = self.connections[connection_id]
            
            try:
                if connection.is_active:
                    await connection.websocket.close()
            except Exception as e:
                logger.debug(f"Error closing WebSocket {connection_id}: {e}")
            
            del self.connections[connection_id]
            
            # Remove from session mappings
            for session_id, conn_ids in list(self.session_connections.items()):
                conn_ids.discard(connection_id)
                # Clean up empty session mappings
                if not conn_ids:
                    del self.session_connections[session_id]
        
        logger.info(f"WebSocket connection {connection_id} disconnected")
    
    def subscribe_to_session(self, connection_id: str, session_id: str):
        """Subscribe a connection to session updates."""
        if connection_id in self.connections:
            if session_id not in self.session_connections:
                self.session_connections[session_id] = set()
            self.session_connections[session_id].add(connection_id)
            
            # Add session-specific subscription
            self.connections[connection_id].add_subscription(f"session:{session_id}")
            
            logger.debug(f"Connection {connection_id} subscribed to session {session_id}")
    
    def unsubscribe_from_session(self, connection_id: str, session_id: str):
        """Unsubscribe a connection from session updates."""
        if session_id in self.session_connections:
            self.session_connections[session_id].discard(connection_id)
            
            # Clean up empty session mappings
            if not self.session_connections[session_id]:
                del self.session_connections[session_id]
            
            if connection_id in self.connections:
                self.connections[connection_id].remove_subscription(f"session:{session_id}")
            
            logger.debug(f"Connection {connection_id} unsubscribed from session {session_id}")
    
    async def broadcast_to_all(self, message: WebSocketMessage):
        """Broadcast message to all connections."""
        async with self._lock:
            connections = list(self.connections.values())
        
        if not connections:
            return
        
        tasks = []
        for connection in connections:
            if connection.is_active:
                tasks.append(self._safe_send(connection, message))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Log any exceptions
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Error broadcasting to connection: {result}")
    
    async def broadcast_to_session(self, session_id: str, message: WebSocketMessage):
        """Broadcast message to connections subscribed to a session."""
        if session_id not in self.session_connections:
            logger.debug(f"No connections subscribed to session {session_id}")
            return
        
        async with self._lock:
            connection_ids = self.session_connections[session_id].copy()
        
        tasks = []
        for conn_id in connection_ids:
            if conn_id in self.connections:
                connection = self.connections[conn_id]
                if connection.is_active and connection.is_subscribed_to(f"session:{session_id}"):
                    tasks.append(self._safe_send(connection, message))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Log failures
            failures = sum(1 for r in results if isinstance(r, Exception) or r is False)
            if failures > 0:
                logger.warning(f"Failed to send to {failures}/{len(tasks)} connections for session {session_id}")
    
    async def _safe_send(self, connection: WebSocketConnection, message: WebSocketMessage):
        """Safely send a message with error handling."""
        try:
            return await connection.send_message(message)
        except Exception as e:
            logger.error(f"Error sending to connection {connection.connection_id}: {e}")
            return False
    
    async def send_to_connection(self, connection_id: str, message: WebSocketMessage):
        """Send message to a specific connection."""
        if connection_id in self.connections:
            connection = self.connections[connection_id]
            if connection.is_active:
                await connection.send_message(message)
    
    async def _heartbeat_loop(self):
        """Background task to send periodic heartbeats."""
        logger.info("Heartbeat loop started")
        
        while self._running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                async with self._lock:
                    connections = list(self.connections.values())
                
                tasks = []
                for connection in connections:
                    if connection.is_active:
                        tasks.append(connection.send_heartbeat())
                
                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    failures = sum(1 for r in results if not r or isinstance(r, Exception))
                    if failures > 0:
                        logger.debug(f"Heartbeat failed for {failures}/{len(tasks)} connections")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
        
        logger.info("Heartbeat loop stopped")
    
    async def _cleanup_loop(self):
        """Background task to clean up stale connections."""
        logger.info("Cleanup loop started")
        
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                async with self._lock:
                    stale_connections = [
                        conn_id for conn_id, conn in self.connections.items()
                        if not conn.is_active or conn.is_stale()
                    ]
                
                for conn_id in stale_connections:
                    logger.info(f"Cleaning up stale connection: {conn_id}")
                    await self.disconnect(conn_id)
                
                if stale_connections:
                    logger.info(f"Cleaned up {len(stale_connections)} stale connections")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
        
        logger.info("Cleanup loop stopped")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get statistics about active connections."""
        return {
            'total_connections': len(self.connections),
            'active_connections': sum(1 for c in self.connections.values() if c.is_active),
            'sessions_with_connections': len(self.session_connections),
            'total_session_subscriptions': sum(len(conns) for conns in self.session_connections.values())
        }
    
    async def notify_test_started(self, session_id: str, test_config: Dict[str, Any]):
        """Notify that a test session has started."""
        message = WebSocketMessage(
            NotificationType.TEST_STARTED,
            {
                'session_id': session_id,
                'config': test_config,
                'message': 'Security testing started'
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def notify_test_progress(self, session_id: str, progress: Dict[str, Any]):
        """Notify of test progress updates."""
        message = WebSocketMessage(
            NotificationType.TEST_PROGRESS,
            {
                'session_id': session_id,
                'progress': progress,
                'message': f"Testing progress: {progress.get('percentage', 0)}%"
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def notify_vulnerability_found(self, session_id: str, vulnerability: Dict[str, Any]):
        """Notify when a vulnerability is discovered."""
        message = WebSocketMessage(
            NotificationType.VULNERABILITY_FOUND,
            {
                'session_id': session_id,
                'vulnerability': vulnerability,
                'message': f"Vulnerability found: {vulnerability.get('title', 'Unknown')}"
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def notify_detector_started(self, session_id: str, detector_name: str, 
                                    endpoint: str):
        """Notify when a detector starts testing an endpoint."""
        message = WebSocketMessage(
            NotificationType.DETECTOR_STARTED,
            {
                'session_id': session_id,
                'detector': detector_name,
                'endpoint': endpoint,
                'message': f"Started {detector_name} on {endpoint}"
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def notify_detector_completed(self, session_id: str, detector_name: str,
                                      endpoint: str, results: Dict[str, Any]):
        """Notify when a detector completes testing an endpoint."""
        message = WebSocketMessage(
            NotificationType.DETECTOR_COMPLETED,
            {
                'session_id': session_id,
                'detector': detector_name,
                'endpoint': endpoint,
                'results': results,
                'message': f"Completed {detector_name} on {endpoint}"
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def notify_test_completed(self, session_id: str, summary: Dict[str, Any]):
        """Notify that testing has completed."""
        message = WebSocketMessage(
            NotificationType.TEST_COMPLETED,
            {
                'session_id': session_id,
                'summary': summary,
                'message': 'Security testing completed'
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def notify_test_failed(self, session_id: str, error: str):
        """Notify that testing has failed."""
        message = WebSocketMessage(
            NotificationType.TEST_FAILED,
            {
                'session_id': session_id,
                'error': error,
                'message': f'Security testing failed: {error}'
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def notify_error(self, session_id: str, error: str, details: Dict = None):
        """Notify of an error."""
        message = WebSocketMessage(
            NotificationType.ERROR,
            {
                'session_id': session_id,
                'error': error,
                'details': details or {},
                'message': f'Error: {error}'
            },
            session_id
        )
        await self.broadcast_to_session(session_id, message)
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeat messages."""
        while self._running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                if not self.connections:
                    continue
                
                # Send heartbeat to all connections
                tasks = []
                for connection in list(self.connections.values()):
                    if connection.is_active:
                        tasks.append(connection.send_heartbeat())
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
    
    async def _cleanup_loop(self):
        """Clean up inactive connections."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                current_time = datetime.utcnow()
                inactive_connections = []
                
                for conn_id, connection in self.connections.items():
                    # Check if connection is stale (no heartbeat response for 2 intervals)
                    if not connection.is_active or \
                       (current_time - connection.last_heartbeat).total_seconds() > (self.heartbeat_interval * 2):
                        inactive_connections.append(conn_id)
                
                # Remove inactive connections
                for conn_id in inactive_connections:
                    await self.disconnect(conn_id)
                    logger.info(f"Cleaned up inactive connection: {conn_id}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get statistics about current connections."""
        active_connections = sum(1 for conn in self.connections.values() if conn.is_active)
        
        return {
            'total_connections': len(self.connections),
            'active_connections': active_connections,
            'sessions_with_connections': len(self.session_connections),
            'average_connection_age': self._calculate_average_connection_age(),
            'heartbeat_interval': self.heartbeat_interval,
            'last_cleanup': datetime.utcnow().isoformat()
        }
    
    def _calculate_average_connection_age(self) -> float:
        """Calculate average connection age in seconds."""
        if not self.connections:
            return 0
        
        current_time = datetime.utcnow()
        total_age = sum(
            (current_time - conn.connected_at).total_seconds()
            for conn in self.connections.values()
            if conn.is_active
        )
        
        active_count = sum(1 for conn in self.connections.values() if conn.is_active)
        return total_age / active_count if active_count > 0 else 0


# Global WebSocket manager instance
websocket_manager = WebSocketManager()
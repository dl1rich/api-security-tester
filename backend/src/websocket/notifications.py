"""WebSocket integration for real-time test notifications."""

import logging
from typing import Dict, Any, Optional
import asyncio

from .manager import websocket_manager, NotificationType

logger = logging.getLogger(__name__)


class TestNotifier:
    """Handles real-time notifications for security testing with improved error handling."""
    
    def __init__(self):
        self.websocket_manager = websocket_manager
        self._notification_queue = asyncio.Queue()
        self._failed_notifications = []
    
    async def _safe_notify(self, notify_func, *args, **kwargs):
        """Safely execute a notification with error handling."""
        try:
            await notify_func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            # Store failed notification for retry
            self._failed_notifications.append({
                'func': notify_func,
                'args': args,
                'kwargs': kwargs,
                'error': str(e)
            })
    
    async def notify_session_started(self, session_id: str, config: Dict[str, Any]):
        """Notify that a test session has started."""
        try:
            test_config = {
                'test_modules': config.get('test_modules', []),
                'target_url': config.get('target_base_url', ''),
                'intensity': config.get('test_intensity', 'medium'),
                'auth_handling': config.get('auth_handling', 'preserve_roles'),
                'estimated_duration': config.get('estimated_duration', 0)
            }
            
            await self._safe_notify(
                self.websocket_manager.notify_test_started,
                session_id,
                test_config
            )
            logger.info(f"Notified test start for session {session_id}")
        except Exception as e:
            logger.error(f"Error in notify_session_started: {e}")
    
    async def notify_progress_update(self, session_id: str, progress_data: Dict[str, Any]):
        """Notify of test progress updates."""
        try:
            progress = {
                'percentage': progress_data.get('progress_percentage', 0),
                'current_test': progress_data.get('current_test', ''),
                'completed_tests': progress_data.get('completed_tests', 0),
                'total_tests': progress_data.get('total_tests', 0),
                'vulnerabilities_found': progress_data.get('vulnerability_count', 0),
                'time_elapsed': progress_data.get('time_elapsed', 0),
                'estimated_remaining': progress_data.get('estimated_remaining', 0)
            }
            
            await self._safe_notify(
                self.websocket_manager.notify_test_progress,
                session_id,
                progress
            )
        except Exception as e:
            logger.error(f"Error in notify_progress_update: {e}")
    
    async def notify_detector_activity(self, session_id: str, detector_name: str, 
                                     endpoint_path: str, status: str, 
                                     results: Optional[Dict[str, Any]] = None):
        """Notify of detector activity on specific endpoints."""
        try:
            if status == "started":
                await self._safe_notify(
                    self.websocket_manager.notify_detector_started,
                    session_id,
                    detector_name,
                    endpoint_path
                )
            elif status == "completed":
                await self._safe_notify(
                    self.websocket_manager.notify_detector_completed,
                    session_id,
                    detector_name,
                    endpoint_path,
                    results or {}
                )
        except Exception as e:
            logger.error(f"Error in notify_detector_activity: {e}")
    
    async def notify_vulnerability_discovered(self, session_id: str, vulnerability: Dict[str, Any]):
        """Notify when a new vulnerability is found."""
        try:
            vuln_data = {
                'id': vulnerability.get('id'),
                'title': vulnerability.get('title', 'Unknown Vulnerability'),
                'severity': vulnerability.get('severity', 'UNKNOWN'),
                'category': vulnerability.get('category', 'Unknown'),
                'endpoint': vulnerability.get('endpoint', ''),
                'method': vulnerability.get('method', ''),
                'description': vulnerability.get('description', ''),
                'cwe_id': vulnerability.get('cwe_id'),
                'cvss_score': vulnerability.get('cvss_score'),
                'found_at': vulnerability.get('found_at')
            }
            
            await self._safe_notify(
                self.websocket_manager.notify_vulnerability_found,
                session_id,
                vuln_data
            )
            logger.info(f"Notified vulnerability discovery in session {session_id}: {vuln_data['title']}")
        except Exception as e:
            logger.error(f"Error in notify_vulnerability_discovered: {e}")
    
    async def notify_endpoint_completed(self, session_id: str, endpoint_data: Dict[str, Any]):
        """Notify when an endpoint testing is completed."""
        try:
            endpoint_info = {
                'endpoint': endpoint_data.get('endpoint', ''),
                'method': endpoint_data.get('method', ''),
                'tests_run': endpoint_data.get('tests_run', 0),
                'vulnerabilities_found': endpoint_data.get('vulnerabilities_found', 0),
                'duration': endpoint_data.get('duration', 0),
                'status': endpoint_data.get('status', 'completed')
            }
            
            from .manager import WebSocketMessage
            message = WebSocketMessage(
                NotificationType.ENDPOINT_TESTED,
                {
                    'session_id': session_id,
                    'endpoint_info': endpoint_info,
                    'message': f"Completed testing {endpoint_info['method']} {endpoint_info['endpoint']}"
                },
                session_id
            )
            
            await self._safe_notify(
                self.websocket_manager.broadcast_to_session,
                session_id,
                message
            )
        except Exception as e:
            logger.error(f"Error in notify_endpoint_completed: {e}")
    
    async def notify_session_completed(self, session_id: str, summary: Dict[str, Any]):
        """Notify that a test session has completed."""
        try:
            test_summary = {
                'session_id': session_id,
                'status': summary.get('status', 'completed'),
                'total_tests': summary.get('total_tests', 0),
                'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
                'duration': summary.get('duration', 0),
                'endpoints_tested': summary.get('endpoints_tested', 0),
                'vulnerabilities_by_severity': summary.get('vulnerabilities_by_severity', {}),
                'completion_time': summary.get('completion_time')
            }
            
            await self._safe_notify(
                self.websocket_manager.notify_test_completed,
                session_id,
                test_summary
            )
            logger.info(f"Notified test completion for session {session_id}")
        except Exception as e:
            logger.error(f"Error in notify_session_completed: {e}")
    
    async def notify_session_failed(self, session_id: str, error: str, details: Dict = None):
        """Notify that a test session has failed."""
        try:
            await self._safe_notify(
                self.websocket_manager.notify_test_failed,
                session_id,
                error
            )
            
            if details:
                await self._safe_notify(
                    self.websocket_manager.notify_error,
                    session_id,
                    error,
                    details
                )
            
            logger.error(f"Notified test failure for session {session_id}: {error}")
        except Exception as e:
            logger.error(f"Error in notify_session_failed: {e}")
    
    async def notify_real_time_stats(self, session_id: str, stats: Dict[str, Any]):
        """Send real-time statistics during testing."""
        try:
            stats_data = {
                'requests_made': stats.get('requests_made', 0),
                'requests_per_second': stats.get('requests_per_second', 0),
                'current_detector': stats.get('current_detector', ''),
                'current_endpoint': stats.get('current_endpoint', ''),
                'memory_usage': stats.get('memory_usage', 0),
                'active_threads': stats.get('active_threads', 0),
                'queue_size': stats.get('queue_size', 0)
            }
            
            from .manager import WebSocketMessage
            message = WebSocketMessage(
                NotificationType.SESSION_UPDATE,
                {
                    'type': 'real_time_stats',
                    'session_id': session_id,
                    'stats': stats_data
                },
                session_id
            )
            
            await self._safe_notify(
                self.websocket_manager.broadcast_to_session,
                session_id,
                message
            )
        except Exception as e:
            logger.error(f"Error in notify_real_time_stats: {e}")
    
    async def notify_custom_event(self, session_id: str, event_type: str, 
                                 event_data: Dict[str, Any]):
        """Send custom event notifications."""
        try:
            from .manager import WebSocketMessage
            message = WebSocketMessage(
                NotificationType.SESSION_UPDATE,
                {
                    'type': 'custom_event',
                    'event_type': event_type,
                    'session_id': session_id,
                    'data': event_data
                },
                session_id
            )
            
            await self._safe_notify(
                self.websocket_manager.broadcast_to_session,
                session_id,
                message
            )
        except Exception as e:
            logger.error(f"Error in notify_custom_event: {e}")
    
    def is_session_connected(self, session_id: str) -> bool:
        """Check if any clients are connected to a session."""
        try:
            return session_id in self.websocket_manager.session_connections and \
                   len(self.websocket_manager.session_connections[session_id]) > 0
        except Exception as e:
            logger.error(f"Error checking session connection: {e}")
            return False
    
    def get_session_connection_count(self, session_id: str) -> int:
        """Get number of connections for a session."""
        try:
            if session_id in self.websocket_manager.session_connections:
                return len(self.websocket_manager.session_connections[session_id])
            return 0
        except Exception as e:
            logger.error(f"Error getting connection count: {e}")
            return 0
    
    async def retry_failed_notifications(self):
        """Retry notifications that failed previously."""
        if not self._failed_notifications:
            return
        
        retry_queue = self._failed_notifications.copy()
        self._failed_notifications.clear()
        
        for notification in retry_queue:
            try:
                func = notification['func']
                args = notification['args']
                kwargs = notification['kwargs']
                await func(*args, **kwargs)
                logger.info("Successfully retried failed notification")
            except Exception as e:
                logger.error(f"Failed to retry notification: {e}")
                # Don't add back to failed queue to avoid infinite retries


# Global test notifier instance
test_notifier = TestNotifier()
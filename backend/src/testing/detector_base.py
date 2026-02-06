"""Base vulnerability detector class and framework."""

import asyncio
import logging
import httpx
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, AsyncIterator
from datetime import datetime

from .models import (
    Vulnerability, VulnerabilityEvidence, TestResult, 
    VulnerabilitySeverity, VulnerabilityCategory, TestPriority
)
from parser.models import APISpecification, APIEndpoint
from auth.handler import AuthenticationHandler

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Base class for all vulnerability detectors."""
    
    def __init__(self, name: str, category: VulnerabilityCategory, 
                 priority: TestPriority = TestPriority.MEDIUM):
        self.name = name
        self.category = category
        self.priority = priority
        self.enabled = True
        self.timeout = 30.0
        self.max_retries = 3
    
    @abstractmethod
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect vulnerabilities for a specific endpoint."""
        pass
    
    @abstractmethod
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for this detector."""
        pass
    
    async def make_request(self, method: str, url: str, headers: Dict[str, str] = None,
                          data: Any = None, timeout: Optional[float] = None) -> VulnerabilityEvidence:
        """Make an HTTP request and return evidence."""
        headers = headers or {}
        timeout = timeout or self.timeout
        
        start_time = datetime.utcnow()
        
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=data if isinstance(data, (str, bytes)) else None,
                    json=data if isinstance(data, dict) else None
                )
                
                end_time = datetime.utcnow()
                response_time = (end_time - start_time).total_seconds()
                
                return VulnerabilityEvidence(
                    request_method=method,
                    request_url=url,
                    request_headers=dict(headers),
                    request_body=str(data) if data else None,
                    response_status=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=response.text,
                    response_time=response_time
                )
                
        except Exception as e:
            logger.error(f"Request failed: {e}")
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds()
            
            return VulnerabilityEvidence(
                request_method=method,
                request_url=url,
                request_headers=dict(headers),
                request_body=str(data) if data else None,
                response_time=response_time,
                additional_info={"error": str(e)}
            )
    
    def create_vulnerability(self, title: str, description: str, severity: VulnerabilitySeverity,
                           endpoint: APIEndpoint, evidence: List[VulnerabilityEvidence],
                           remediation: str = "", cwe_id: str = None,
                           cvss_score: float = None) -> Vulnerability:
        """Create a vulnerability instance."""
        return Vulnerability(
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            endpoint=endpoint.path,
            method=endpoint.method,
            evidence=evidence,
            remediation=remediation,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            test_module=self.name
        )
    
    def build_url(self, base_url: str, endpoint: APIEndpoint, 
                 path_params: Dict[str, Any] = None) -> str:
        """Build complete URL for an endpoint."""
        path = endpoint.path
        
        # Replace path parameters
        if path_params:
            for param, value in path_params.items():
                path = path.replace(f"{{{param}}}", str(value))
        
        # Ensure base_url doesn't end with slash and path starts with slash
        base_url = base_url.rstrip('/')
        if not path.startswith('/'):
            path = '/' + path
            
        return f"{base_url}{path}"
    
    def extract_path_parameters(self, endpoint: APIEndpoint) -> List[str]:
        """Extract path parameter names from endpoint."""
        import re
        pattern = r'\{([^}]+)\}'
        return re.findall(pattern, endpoint.path)
    
    def get_query_parameters(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Get query parameters for an endpoint."""
        query_params = []
        for param in endpoint.parameters:
            if param.get('in') == 'query':
                query_params.append(param)
        return query_params
    
    def get_header_parameters(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Get header parameters for an endpoint."""
        header_params = []
        for param in endpoint.parameters:
            if param.get('in') == 'header':
                header_params.append(param)
        return header_params


class VulnerabilityDetectionEngine:
    """Main engine for coordinating vulnerability detection."""
    
    def __init__(self):
        self.detectors: List[BaseDetector] = []
        self.auth_handler = AuthenticationHandler()
        self.session_store: Dict[str, Any] = {}
    
    def register_detector(self, detector: BaseDetector) -> None:
        """Register a vulnerability detector."""
        self.detectors.append(detector)
        logger.info(f"Registered detector: {detector.name}")
    
    def get_detectors_by_category(self, category: VulnerabilityCategory) -> List[BaseDetector]:
        """Get detectors for a specific category."""
        return [d for d in self.detectors if d.category == category and d.enabled]
    
    def get_enabled_detectors(self) -> List[BaseDetector]:
        """Get all enabled detectors."""
        return [d for d in self.detectors if d.enabled]
    
    async def run_detection(self, session_id: str, spec: APISpecification,
                          test_modules: List[str], auth_config: Dict[str, Any],
                          base_url: str, intensity: str = "medium") -> AsyncIterator[TestResult]:
        """Run vulnerability detection and yield results."""
        
        # Filter detectors based on test modules
        active_detectors = self._filter_detectors_by_modules(test_modules)
        
        # Sort by priority
        active_detectors.sort(key=lambda x: x.priority.value)
        
        total_tests = 0
        completed_tests = 0
        
        # Calculate total test count
        for detector in active_detectors:
            for endpoint in spec.endpoints:
                test_cases = detector.get_test_cases(endpoint, spec)
                total_tests += len(test_cases)
        
        # Run detection
        for detector in active_detectors:
            logger.info(f"Running detector: {detector.name}")
            
            for endpoint in spec.endpoints:
                # Get auth headers for this endpoint
                auth_headers = self._get_auth_headers_for_endpoint(
                    endpoint, auth_config, spec.id
                )
                
                # Notify detector started (import here to avoid circular imports)
                try:
                    from websocket import test_notifier
                    await test_notifier.notify_detector_activity(
                        session_id, detector.name, f"{endpoint.method} {endpoint.path}", "started"
                    )
                except ImportError:
                    pass  # WebSocket notifications not available
                
                try:
                    vulnerabilities = await detector.detect(
                        endpoint, spec, auth_headers, base_url
                    )
                    
                    for vuln in vulnerabilities:
                        result = TestResult(
                            test_name=f"{detector.name}_{endpoint.path}_{endpoint.method}",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            success=True,
                            vulnerability=vuln,
                            test_module=detector.name
                        )
                        yield result
                    
                    # Notify detector completed
                    try:
                        from websocket import test_notifier
                        await test_notifier.notify_detector_activity(
                            session_id, detector.name, f"{endpoint.method} {endpoint.path}", 
                            "completed", {'vulnerabilities_found': len(vulnerabilities)}
                        )
                    except ImportError:
                        pass
                        
                except Exception as e:
                    logger.error(f"Error in detector {detector.name} for endpoint {endpoint.path}: {e}")
                    
                    # Notify detector error
                    try:
                        from websocket import test_notifier
                        await test_notifier.notify_detector_activity(
                            session_id, detector.name, f"{endpoint.method} {endpoint.path}", 
                            "completed", {'error': str(e)}
                        )
                    except ImportError:
                        pass
                    
                    result = TestResult(
                        test_name=f"{detector.name}_{endpoint.path}_{endpoint.method}",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        success=False,
                        error=str(e),
                        test_module=detector.name
                    )
                    yield result
                
                completed_tests += 1
                
                # Update progress
                progress = int((completed_tests / total_tests) * 100) if total_tests > 0 else 0
                await self._update_session_progress(session_id, progress, detector.name)
    
    def _filter_detectors_by_modules(self, test_modules: List[str]) -> List[BaseDetector]:
        """Filter detectors based on requested test modules."""
        if not test_modules:
            return self.get_enabled_detectors()
        
        # Map test modules to detector categories
        module_mapping = {
            'owasp_top10': [cat for cat in VulnerabilityCategory if 'API' in cat.value],
            'input_validation': [VulnerabilityCategory.INPUT_VALIDATION, VulnerabilityCategory.INJECTION],
            'business_logic': [VulnerabilityCategory.BUSINESS_LOGIC],
            'authentication': [VulnerabilityCategory.API2_BROKEN_AUTH],
            'authorization': [VulnerabilityCategory.API1_BOLA, VulnerabilityCategory.API5_FUNCTION_AUTH],
            'rate_limiting': [VulnerabilityCategory.RATE_LIMITING],
            'cors_security': [VulnerabilityCategory.CORS_SECURITY]
        }
        
        target_categories = set()
        for module in test_modules:
            categories = module_mapping.get(module, [])
            target_categories.update(categories)
        
        filtered_detectors = []
        for detector in self.detectors:
            if not detector.enabled:
                continue
            if not target_categories or detector.category in target_categories:
                filtered_detectors.append(detector)
        
        return filtered_detectors
    
    def _get_auth_headers_for_endpoint(self, endpoint: APIEndpoint, 
                                     auth_config: Dict[str, Any], 
                                     spec_id: str) -> Dict[str, str]:
        """Get appropriate auth headers for an endpoint."""
        headers = {}
        
        # Check if endpoint requires authentication
        if endpoint.security_requirements:
            # Use first available role's credentials
            role_credentials = auth_config.get('role_credentials', {})
            if role_credentials:
                first_role = next(iter(role_credentials.keys()))
                headers = self.auth_handler.get_test_headers(spec_id, first_role)
        
        return headers
    
    async def _update_session_progress(self, session_id: str, progress: int, 
                                     current_test: str) -> None:
        """Update session progress."""
        if session_id in self.session_store:
            self.session_store[session_id].update({
                'progress_percentage': progress,
                'current_test': current_test,
                'last_updated': datetime.utcnow()
            })
    
    def get_available_detectors(self) -> List[Dict[str, Any]]:
        """Get information about available detectors."""
        return [
            {
                'name': detector.name,
                'category': detector.category.value,
                'priority': detector.priority.value,
                'enabled': detector.enabled,
                'description': getattr(detector, 'description', '')
            }
            for detector in self.detectors
        ]
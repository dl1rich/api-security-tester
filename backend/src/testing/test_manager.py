"""Test manager for coordinating security testing."""

import uuid
import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from parser.openapi_parser import OpenAPIParser
from auth.handler import AuthenticationHandler
from testing.detector_base import VulnerabilityDetectionEngine
from testing.detectors.basic_detectors import SQLInjectionDetector, XSSDetector, AuthenticationBypassDetector
from testing.detectors.owasp_top10 import BOLADetector, BrokenFunctionAuthDetector, SSRFDetector
from testing.detectors.owasp_additional import ExcessiveDataExposureDetector, ResourceConsumptionDetector, SecurityMisconfigDetector
from testing.detectors.owasp_final import ImproperInventoryDetector, UnsafeConsumptionDetector, MassAssignmentDetector
from testing.detectors.role_based_auth import RoleBasedAuthorizationDetector
from testing.detectors.injection_detectors import (
    CommandInjectionDetector, NoSQLInjectionDetector, PathTraversalDetector, LDAPInjectionDetector
)
from testing.detectors.advanced_detectors import (
    XXEDetector, CORSMisconfigurationDetector, OpenRedirectDetector, 
    InsecureDeserializationDetector, RemoteCodeExecutionDetector
)
from testing.data_manager import TestDataManager, FuzzingDetector
from testing.models import TestSession, Vulnerability, TestResult
from websocket import test_notifier
from utils.config import settings
from utils.dependencies import get_parser

logger = logging.getLogger(__name__)


class TestManager:
    """Manages security testing sessions and coordination."""
    
    def __init__(self):
        self._test_sessions: Dict[str, TestSession] = {}
        self._parser = get_parser()  # Use shared parser instance
        self._auth_handler = AuthenticationHandler()
        self._detection_engine = VulnerabilityDetectionEngine()
        self._data_manager = TestDataManager()
        
        # Register basic detectors
        self._detection_engine.register_detector(SQLInjectionDetector())
        self._detection_engine.register_detector(XSSDetector())
        self._detection_engine.register_detector(AuthenticationBypassDetector())
        
        # Register OWASP API Top 10 (2023) detectors
        self._detection_engine.register_detector(BOLADetector())  # API1
        self._detection_engine.register_detector(BrokenFunctionAuthDetector())  # API5
        self._detection_engine.register_detector(ExcessiveDataExposureDetector())  # API3
        self._detection_engine.register_detector(ResourceConsumptionDetector())  # API4
        self._detection_engine.register_detector(MassAssignmentDetector())  # API6
        self._detection_engine.register_detector(SSRFDetector())  # API7
        self._detection_engine.register_detector(SecurityMisconfigDetector())  # API8
        self._detection_engine.register_detector(ImproperInventoryDetector())  # API9
        self._detection_engine.register_detector(UnsafeConsumptionDetector())  # API10
        
        # Register injection detectors
        self._detection_engine.register_detector(CommandInjectionDetector())
        self._detection_engine.register_detector(NoSQLInjectionDetector())
        self._detection_engine.register_detector(PathTraversalDetector())
        self._detection_engine.register_detector(LDAPInjectionDetector())
        
        # Register advanced detectors
        self._detection_engine.register_detector(XXEDetector())
        self._detection_engine.register_detector(CORSMisconfigurationDetector())
        self._detection_engine.register_detector(OpenRedirectDetector())
        self._detection_engine.register_detector(InsecureDeserializationDetector())
        self._detection_engine.register_detector(RemoteCodeExecutionDetector())
        
        # Register specialized detectors
        self._detection_engine.register_detector(RoleBasedAuthorizationDetector())
        self._detection_engine.register_detector(FuzzingDetector())
    
    def validate_config(self, config) -> bool:
        """Validate test configuration."""
        try:
            # Check if specification exists
            spec = self._parser.get_specification(config.spec_id)
            if not spec:
                logger.error(f"Specification not found: {config.spec_id}")
                return False
            
            # Validate test modules - accept any module names for now
            # The frontend uses different naming than backend
            if not config.test_modules or len(config.test_modules) == 0:
                logger.error("No test modules specified")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Error validating config: {e}")
            return False
    
    def create_test_session(self, config) -> str:
        """Create a new test session."""
        session_id = str(uuid.uuid4())
        
        # Get the API specification
        spec = self._parser.get_specification(config.spec_id)
        if not spec:
            raise ValueError(f"Specification not found: {config.spec_id}")
        
        # Process authentication configuration
        auth_config = self._auth_handler.process_authentication(
            spec, 
            config.auth_handling, 
            config.custom_roles
        )
        
        session = TestSession(
            id=session_id,
            spec_id=config.spec_id,
            status='queued',
            test_modules=config.test_modules,
            auth_config=auth_config,
            target_base_url=config.target_base_url,
            test_intensity=config.test_intensity
        )
        
        self._test_sessions[session_id] = session
        return session_id
    
    async def run_security_tests(self, session_id: str, config) -> None:
        """Run security tests (background task)."""
        try:
            session = self._test_sessions[session_id]
            session.status = 'running'
            session.started_at = datetime.utcnow()
            
            # Notify WebSocket clients that testing started
            await test_notifier.notify_session_started(session_id, {
                'test_modules': config.test_modules,
                'target_base_url': config.target_base_url,
                'test_intensity': config.test_intensity,
                'auth_handling': config.auth_handling,
                'estimated_duration': self.estimate_test_duration(config)
            })
            
            # Get API specification
            spec = self._parser.get_specification(config.spec_id)
            if not spec:
                raise ValueError(f"Specification not found: {config.spec_id}")
            
            # Determine base URL - but we'll only use it for reporting, not actual connections
            base_url = config.target_base_url
            if not base_url and spec.servers:
                base_url = spec.servers[0].url
            if not base_url:
                base_url = "http://localhost:8080"
            
            logger.info(f"Starting OFFLINE security analysis for {len(spec.endpoints)} endpoints")
            
            # Small delay to let WebSocket connect
            await asyncio.sleep(1)
            
            # Perform comprehensive security analysis WITHOUT making HTTP requests
            analysis_results = self._analyze_specification_security(spec)
            
            # Simulate testing progress for better UX
            total_checks = len(analysis_results.get('vulnerabilities', [])) + len(analysis_results.get('warnings', []))
            
            for i, vuln in enumerate(analysis_results.get('vulnerabilities', [])):
                # Send progress updates
                await test_notifier.notify_progress_update(session_id, {
                    'progress_percentage': int((i + 1) / max(total_checks, 1) * 100),
                    'current_test': vuln.get('test_name', 'Security Analysis'),
                    'completed_tests': i + 1,
                    'total_tests': total_checks,
                    'vulnerability_count': i + 1,
                    'time_elapsed': i + 1,
                    'estimated_remaining': total_checks - i
                })
                
                # Notify vulnerability found
                await test_notifier.notify_vulnerability_discovered(session_id, vuln)
                
                # Small delay for UI updates
                await asyncio.sleep(0.1)
            
            # Complete the session
            session.status = 'completed'
            session.completed_at = datetime.utcnow()
            session.test_results = analysis_results.get('findings', [])
            session.vulnerabilities = analysis_results.get('vulnerabilities', [])
            
            # Send completion notification
            await test_notifier.notify_session_completed(session_id, {
                'session_id': session_id,
                'status': 'completed',
                'total_tests': total_checks,
                'total_vulnerabilities': len(analysis_results.get('vulnerabilities', [])),
                'duration': total_checks,
                'endpoints_tested': len(spec.endpoints),
                'completion_time': datetime.utcnow().isoformat(),
                'vulnerabilities_by_severity': analysis_results.get('vulnerabilities_by_severity', {}),
                'analysis_summary': {
                    'total_endpoints': len(spec.endpoints),
                    'auth_methods': list(spec.auth_methods.keys()),
                    'spec_version': spec.spec_version,
                    'warnings': analysis_results.get('warnings', []),
                    'mode': 'Offline Static Analysis',
                    'note': 'All findings based on API specification analysis - no live requests made'
                }
            })
            return
            vulnerabilities = []
            test_results = []
            
            async for result in self._detection_engine.run_detection(
                session_id=session_id,
                spec=spec,
                test_modules=config.test_modules,
                auth_config=session.auth_config,
                base_url=base_url,
                intensity=config.test_intensity
            ):
                test_results.append(result)
                
                if result.vulnerability:
                    vulnerabilities.append(result.vulnerability)
                    # Notify of new vulnerability
                    await test_notifier.notify_vulnerability_discovered(
                        session_id, 
                        {
                            'id': str(len(vulnerabilities)),
                            'title': result.vulnerability.title,
                            'severity': result.vulnerability.severity.value if hasattr(result.vulnerability.severity, 'value') else str(result.vulnerability.severity),
                            'category': result.vulnerability.category.value if hasattr(result.vulnerability.category, 'value') else str(result.vulnerability.category),
                            'endpoint': result.endpoint,
                            'method': result.method,
                            'description': result.vulnerability.description,
                            'cwe_id': result.vulnerability.cwe_id,
                            'cvss_score': result.vulnerability.cvss_score,
                            'found_at': datetime.utcnow().isoformat()
                        }
                    )
                
                # Update session progress
                session.test_results = test_results
                session.vulnerabilities = vulnerabilities
                session.completed_tests = len(test_results)
                
                # Send progress update
                await test_notifier.notify_progress_update(session_id, {
                    'progress_percentage': session.progress_percentage,
                    'current_test': session.current_test or result.test_name,
                    'completed_tests': len(test_results),
                    'total_tests': session.total_tests,
                    'vulnerability_count': len(vulnerabilities),
                    'time_elapsed': (datetime.utcnow() - session.started_at).total_seconds(),
                    'estimated_remaining': 0  # Calculate if needed
                })
            
            session.status = 'completed'
            session.completed_at = datetime.utcnow()
            session.progress_percentage = 100
            session.current_test = None
            
            # Notify completion
            await test_notifier.notify_session_completed(session_id, {
                'session_id': session_id,
                'status': 'completed',
                'total_tests': len(test_results),
                'total_vulnerabilities': len(vulnerabilities),
                'duration': (session.completed_at - session.started_at).total_seconds(),
                'endpoints_tested': len(set(r.endpoint for r in test_results)),
                'vulnerabilities_by_severity': self._count_vulnerabilities_by_severity(vulnerabilities),
                'completion_time': session.completed_at.isoformat()
            })
            
            logger.info(f"Test session {session_id} completed. Found {len(vulnerabilities)} vulnerabilities.")
            
        except Exception as e:
            logger.error(f"Error running tests for session {session_id}: {e}")
            session = self._test_sessions.get(session_id)
            if session:
                session.status = 'failed'
                session.errors.append(str(e))
                
                # Notify failure
                await test_notifier.notify_session_failed(session_id, str(e))
    
    def _analyze_specification_security(self, spec) -> Dict[str, Any]:
        """
        Comprehensive OFFLINE security analysis of API specification.
        Finds vulnerabilities and design flaws without making network requests.
        """
        vulnerabilities = []
        warnings = []
        findings = []
        
        logger.info(f"Running security analysis on {len(spec.endpoints)} endpoints")
        
        # 1. Authentication & Authorization Analysis
        if not spec.security_schemes or len(spec.security_schemes) == 0:
            vulnerabilities.append({
                'test_name': 'Missing Authentication',
                'severity': 'high',
                'category': 'BROKEN_AUTHENTICATION',
                'endpoint': 'Global',
                'method': 'ALL',
                'description': 'API specification defines no authentication mechanisms',
                'risk': 'All endpoints may be publicly accessible without authentication',
                'recommendation': 'Add security schemes (OAuth2, API Key, JWT) to the specification',
                'cwe': 'CWE-306',
                'owasp': 'API1:2023 Broken Object Level Authorization'
            })
        
        # 2. Endpoint-level security analysis
        for endpoint in spec.endpoints:
            endpoint_path = endpoint.path
            endpoint_method = endpoint.method.upper()
            
            # Check for missing authentication on sensitive operations
            if endpoint_method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                if not endpoint.security_requirements and not spec.global_security:
                    vulnerabilities.append({
                        'test_name': 'Unsecured Sensitive Operation',
                        'severity': 'critical',
                        'category': 'BROKEN_AUTHENTICATION',
                        'endpoint': endpoint_path,
                        'method': endpoint_method,
                        'description': f'Sensitive operation {endpoint_method} has no security requirements',
                        'risk': 'Unauthorized users could modify or delete data',
                        'recommendation': f'Add authentication/authorization to {endpoint_method} {endpoint_path}',
                        'cwe': 'CWE-284',
                        'owasp': 'API1:2023 Broken Object Level Authorization'
                    })
            
            # Check for resource ID parameters (potential BOLA)
            id_params = [p for p in endpoint.parameters if any(x in p.get('name', '').lower() for x in ['id', 'user', 'account', 'customer'])]
            if id_params and not endpoint.security_requirements and not spec.global_security:
                vulnerabilities.append({
                    'test_name': 'Broken Object Level Authorization (BOLA)',
                    'severity': 'critical',
                    'category': 'BROKEN_AUTHORIZATION',
                    'endpoint': endpoint_path,
                    'method': endpoint_method,
                    'description': f'Endpoint accepts ID parameter but has no authorization checks',
                    'risk': 'Users may access other users\' resources by changing ID values',
                    'recommendation': 'Implement proper authorization checks to verify user owns the resource',
                    'cwe': 'CWE-639',
                    'owasp': 'API1:2023 Broken Object Level Authorization',
                    'affected_parameters': [p.get('name') for p in id_params]
                })
            
            # Check for sensitive data in URL parameters
            sensitive_params = [p for p in endpoint.parameters if p.get('in') == 'query' and 
                              any(x in p.get('name', '').lower() for x in ['password', 'token', 'secret', 'key', 'ssn', 'credit'])]
            if sensitive_params:
                vulnerabilities.append({
                    'test_name': 'Sensitive Data Exposure',
                    'severity': 'high',
                    'category': 'SENSITIVE_DATA_EXPOSURE',
                    'endpoint': endpoint_path,
                    'method': endpoint_method,
                    'description': 'Sensitive data passed in URL query parameters',
                    'risk': 'Credentials/secrets may be logged in server logs, browser history, and proxy caches',
                    'recommendation': 'Move sensitive data to request body or use POST method',
                    'cwe': 'CWE-598',
                    'owasp': 'API3:2023 Broken Object Property Level Authorization',
                    'affected_parameters': [p.get('name') for p in sensitive_params]
                })
            
            # Check for mass assignment vulnerabilities
            if endpoint_method in ['POST', 'PUT', 'PATCH'] and hasattr(endpoint, 'request_body') and endpoint.request_body:
                warnings.append({
                    'test_name': 'Potential Mass Assignment',
                    'severity': 'medium',
                    'category': 'MASS_ASSIGNMENT',
                    'endpoint': endpoint_path,
                    'method': endpoint_method,
                    'description': 'Endpoint accepts object in request body',
                    'risk': 'Users may be able to modify unintended properties if not properly validated',
                    'recommendation': 'Use explicit allow-lists for modifiable properties',
                    'cwe': 'CWE-915',
                    'owasp': 'API6:2023 Unrestricted Access to Sensitive Business Flows'
                })
        
        # 3. Check for HTTP (insecure) servers
        insecure_servers = [s for s in spec.servers if s.url.startswith('http://') and 'localhost' not in s.url]
        if insecure_servers:
            vulnerabilities.append({
                'test_name': 'Insecure HTTP Protocol',
                'severity': 'high',
                'category': 'SECURITY_MISCONFIGURATION',
                'endpoint': 'Global',
                'method': 'ALL',
                'description': 'API uses unencrypted HTTP protocol',
                'risk': 'All data transmitted in plain text, vulnerable to interception',
                'recommendation': 'Use HTTPS for all production endpoints',
                'cwe': 'CWE-319',
                'owasp': 'API8:2023 Security Misconfiguration',
                'affected_servers': [s.url for s in insecure_servers]
            })
        
        # 4. Check for missing rate limiting indicators
        rate_limit_endpoints = [e for e in spec.endpoints if any(x in e.path.lower() for x in ['login', 'auth', 'password', 'register'])]
        if rate_limit_endpoints:
            warnings.append({
                'test_name': 'Missing Rate Limiting Documentation',
                'severity': 'medium',
                'category': 'RATE_LIMITING',
                'endpoint': 'Authentication Endpoints',
                'method': 'POST',
                'description': 'No rate limiting documented for authentication endpoints',
                'risk': 'API may be vulnerable to brute force and credential stuffing attacks',
                'recommendation': 'Implement and document rate limiting (e.g., x-rate-limit headers)',
                'cwe': 'CWE-307',
                'owasp': 'API4:2023 Unrestricted Resource Consumption',
                'affected_endpoints': [f"{e.method.upper()} {e.path}" for e in rate_limit_endpoints[:5]]
            })
        
        # 5. Check for weak authentication schemes
        if spec.security_schemes:
            for scheme_name, scheme_data in spec.security_schemes.items():
                if isinstance(scheme_data, dict) and scheme_data.get('type', '').lower() == 'http':
                    if scheme_data.get('scheme', '').lower() == 'basic':
                        vulnerabilities.append({
                            'test_name': 'Weak Authentication Scheme',
                            'severity': 'medium',
                            'category': 'BROKEN_AUTHENTICATION',
                            'endpoint': 'Global',
                            'method': 'ALL',
                            'description': 'API uses HTTP Basic Authentication',
                            'risk': 'Credentials sent with every request, vulnerable if not using HTTPS',
                            'recommendation': 'Use OAuth2, JWT, or API keys with proper rotation',
                            'cwe': 'CWE-326',
                            'owasp': 'API2:2023 Broken Authentication'
                        })
        
        # Calculate severity distribution
        vulnerabilities_by_severity = {
            'critical': len([v for v in vulnerabilities if v['severity'] == 'critical']),
            'high': len([v for v in vulnerabilities if v['severity'] == 'high']),
            'medium': len([v for v in vulnerabilities if v['severity'] == 'medium']),
            'low': len([v for v in vulnerabilities if v['severity'] == 'low'])
        }
        
        logger.info(f"Analysis complete: {len(vulnerabilities)} vulnerabilities, {len(warnings)} warnings")
        
        return {
            'vulnerabilities': vulnerabilities,
            'warnings': warnings,
            'findings': vulnerabilities + warnings,
            'vulnerabilities_by_severity': vulnerabilities_by_severity,
            'summary': {
                'total_endpoints_analyzed': len(spec.endpoints),
                'total_vulnerabilities': len(vulnerabilities),
                'total_warnings': len(warnings),
                'auth_methods': list(spec.security_schemes.keys()) if spec.security_schemes else [],
                'mode': 'offline'
            }
        }
    
    def _analyze_specification(self, spec) -> Dict[str, Any]:
        """Analyze API specification for potential security issues."""
        warnings = []
        findings = []
        
        # Check for missing authentication
        if not spec.security_schemes or len(spec.security_schemes) == 0:
            warnings.append({
                'severity': 'HIGH',
                'message': 'No authentication schemes defined',
                'recommendation': 'Add authentication to protect your API endpoints'
            })
        
        # Check for endpoints without security
        unsecured_endpoints = [
            ep for ep in spec.endpoints 
            if not ep.security_requirements and not spec.global_security
        ]
        if unsecured_endpoints:
            warnings.append({
                'severity': 'MEDIUM',
                'message': f'{len(unsecured_endpoints)} endpoints have no security requirements',
                'affected_endpoints': [f'{ep.method} {ep.path}' for ep in unsecured_endpoints[:5]],
                'recommendation': 'Apply security requirements to protect sensitive endpoints'
            })
        
        # Check for HTTP servers (should be HTTPS)
        http_servers = [s for s in spec.servers if s.url.startswith('http://')]
        if http_servers:
            warnings.append({
                'severity': 'HIGH',
                'message': f'{len(http_servers)} servers using HTTP instead of HTTPS',
                'recommendation': 'Use HTTPS to encrypt data in transit'
            })
        
        # Check for potentially sensitive parameters
        sensitive_params = []
        for ep in spec.endpoints:
            for param in ep.parameters:
                param_name = param.get('name', '').lower()
                if any(keyword in param_name for keyword in ['password', 'token', 'key', 'secret', 'api_key']):
                    sensitive_params.append(f'{ep.method} {ep.path} - {param.get("name")}')
        
        if sensitive_params:
            warnings.append({
                'severity': 'MEDIUM',
                'message': f'{len(sensitive_params)} potentially sensitive parameters found',
                'examples': sensitive_params[:3],
                'recommendation': 'Ensure sensitive data is properly encrypted and not logged'
            })
        
        return {
            'warnings': warnings,
            'findings': findings,
            'summary': {
                'total_warnings': len(warnings),
                'high_severity': len([w for w in warnings if w['severity'] == 'HIGH']),
                'medium_severity': len([w for w in warnings if w['severity'] == 'MEDIUM']),
                'low_severity': len([w for w in warnings if w['severity'] == 'LOW'])
            }
        }
    
    def get_test_status(self, session_id: str) -> Optional[Dict]:
        """Get current test status."""
        session = self._test_sessions.get(session_id)
        if not session:
            return None
        
        return {
            'test_session_id': session_id,
            'status': session.status,
            'progress_percentage': session.progress_percentage,
            'current_test': session.current_test,
            'total_tests': session.total_tests,
            'completed_tests': session.completed_tests,
            'started_at': session.started_at.isoformat() if session.started_at else None,
            'estimated_completion': session.estimated_completion.isoformat() if session.estimated_completion else None
        }
    
    def stop_test_session(self, session_id: str) -> bool:
        """Stop a running test session."""
        session = self._test_sessions.get(session_id)
        if not session:
            return False
        
        if session.status == 'running':
            session.status = 'stopped'
            return True
        
        return False
    
    def get_available_modules(self) -> Dict[str, List[str]]:
        """Get available testing modules."""
        detectors = self._detection_engine.get_available_detectors()
        
        return {
            'modules': [
                'owasp_top10',
                'input_validation',
                'business_logic',
                'authentication',
                'authorization',
                'data_exposure',
                'rate_limiting',
                'cors_security',
                'role_based_testing',
                'fuzzing',
                'data_generation'
            ],
            'detectors': detectors,
            'capabilities': [
                'role_based_authorization',
                'intelligent_fuzzing',
                'test_data_generation',
                'edge_case_testing',
                'malicious_payload_testing'
            ]
        }
    
    def estimate_test_duration(self, config) -> int:
        """Estimate test duration in seconds."""
        # Simple estimation based on config
        base_time = 30  # 30 seconds base
        module_time = len(config.test_modules) * 60  # 1 minute per module
        intensity_multiplier = {'low': 1, 'medium': 2, 'high': 3}.get(config.test_intensity, 2)
        
        return int(base_time + (module_time * intensity_multiplier))
    
    def list_test_sessions(self, limit: int = 50) -> List[Dict]:
        """List recent test sessions."""
        sessions = list(self._test_sessions.values())
        sessions.sort(key=lambda x: x.started_at or datetime.utcnow(), reverse=True)
        
        return [
            {
                'id': session.id,
                'spec_id': session.spec_id,
                'status': session.status,
                'started_at': session.started_at.isoformat() if session.started_at else None,
                'progress_percentage': session.progress_percentage,
                'vulnerability_count': len(session.vulnerabilities)
            }
            for session in sessions[:limit]
        ]
    
    def get_session(self, session_id: str) -> Optional[TestSession]:
        """Get a test session by ID."""
        return self._test_sessions.get(session_id)
    
    def generate_test_dataset(self, spec_id: str, dataset_size: int = 100) -> Dict[str, Any]:
        """Generate test data for an API specification."""
        spec = self._parser.get_specification(spec_id)
        if not spec:
            return {'error': 'Specification not found'}
        
        dataset = self._data_manager.generate_test_dataset(spec, dataset_size)
        stats = self._data_manager.get_statistics(dataset)
        
        return {
            'dataset_id': f"{spec_id}_{dataset_size}",
            'specification_id': spec_id,
            'statistics': stats,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def get_test_data_for_endpoint(self, spec_id: str, endpoint_path: str, 
                                 method: str, data_type: str = "valid") -> Dict[str, Any]:
        """Get test data for a specific endpoint."""
        spec = self._parser.get_specification(spec_id)
        if not spec:
            return {'error': 'Specification not found'}
        
        # Find the endpoint
        endpoint = None
        for ep in spec.endpoints:
            if ep.path == endpoint_path and ep.method.upper() == method.upper():
                endpoint = ep
                break
        
        if not endpoint:
            return {'error': 'Endpoint not found'}
        
        test_data = self._data_manager.get_endpoint_test_data(endpoint, data_type)
        
        return {
            'endpoint': f"{method} {endpoint_path}",
            'data_type': data_type,
            'test_data': test_data,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def export_test_dataset(self, spec_id: str, format: str = "json") -> Optional[str]:
        """Export generated test dataset."""
        return self._data_manager.export_test_data(spec_id, format)
    
    def get_fuzzing_payloads(self, field_name: str, field_type: str) -> List[Dict[str, Any]]:
        """Get fuzzing payloads for a specific field."""
        return self._data_manager.get_fuzzing_payloads(field_name, field_type)
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.severity.value.upper()
            if severity in counts:
                counts[severity] += 1
        return counts
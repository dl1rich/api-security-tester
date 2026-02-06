"""Final OWASP API Top 10 (2023) security testing detectors."""

import json
import re
import asyncio
from typing import List, Dict, Any, Union
from urllib.parse import urlencode, quote_plus

from testing.detector_base import BaseDetector
from testing.models import (
    Vulnerability, VulnerabilityEvidence, VulnerabilitySeverity, 
    VulnerabilityCategory, TestPriority
)
from parser.models import APISpecification, APIEndpoint


class ImproperInventoryDetector(BaseDetector):
    """API9:2023 - Improper Inventory Management detector."""
    
    def __init__(self):
        super().__init__(
            name="improper_inventory",
            category=VulnerabilityCategory.API9_INVENTORY,
            priority=TestPriority.LOW
        )
        self.description = "Tests for improper API inventory management"
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect improper inventory management issues."""
        vulnerabilities = []
        
        # Test for undocumented endpoints
        vulns = await self._test_undocumented_endpoints(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test for deprecated endpoints
        vulns = await self._test_deprecated_endpoints(endpoint, spec, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test for version exposure
        vulns = await self._test_version_exposure(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_undocumented_endpoints(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                         base_url: str) -> List[Vulnerability]:
        """Test for common undocumented endpoints."""
        vulnerabilities = []
        
        # Common undocumented paths to test
        undocumented_paths = [
            '/admin', '/admin/', '/administrator', '/api/admin',
            '/test', '/testing', '/debug', '/dev', '/development',
            '/staging', '/stage', '/beta', '/internal',
            '/health', '/status', '/info', '/version',
            '/docs', '/documentation', '/swagger', '/api-docs',
            '/backup', '/bak', '/old', '/legacy',
            '/.env', '/.git', '/.svn', '/.htaccess'
        ]
        
        base_path = self.extract_base_path(endpoint.path)
        
        for test_path in undocumented_paths:
            test_url = f"{base_url.rstrip('/')}{test_path}"
            
            evidence = await self.make_request(
                method='GET',
                url=test_url,
                headers=auth_headers
            )
            
            if self._is_undocumented_endpoint_accessible(evidence):
                vulnerability = self.create_vulnerability(
                    title=f"Undocumented Endpoint Accessible: {test_path}",
                    description=f"An undocumented endpoint '{test_path}' is accessible and may expose "
                               f"sensitive functionality or information not intended for public access.",
                    severity=VulnerabilitySeverity.LOW,
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Review and document all accessible endpoints. Remove or properly secure "
                              "any endpoints that should not be publicly accessible.",
                    cwe_id="CWE-200",
                    cvss_score=3.1
                )
                vulnerability.proof_of_concept = f"Undocumented path: {test_path}"
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _test_deprecated_endpoints(self, endpoint: APIEndpoint, spec: APISpecification,
                                       auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Test for deprecated endpoint usage."""
        vulnerabilities = []
        
        # Check if endpoint is marked as deprecated
        if self._is_endpoint_deprecated(endpoint):
            url = self.build_url(base_url, endpoint)
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers=auth_headers
            )
            
            # If deprecated endpoint is still accessible
            if evidence.response_status and 200 <= evidence.response_status < 300:
                vulnerability = self.create_vulnerability(
                    title="Deprecated Endpoint Still Accessible",
                    description="This endpoint is marked as deprecated but is still accessible and functional. "
                               "Deprecated endpoints may have security issues and should be properly decommissioned.",
                    severity=VulnerabilitySeverity.LOW,
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Properly decommission deprecated endpoints or redirect to supported alternatives.",
                    cwe_id="CWE-1127",
                    cvss_score=2.3
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _test_version_exposure(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test for API version information exposure."""
        vulnerabilities = []
        
        url = self.build_url(base_url, endpoint)
        evidence = await self.make_request(
            method=endpoint.method,
            url=url,
            headers=auth_headers
        )
        
        if self._has_version_exposure(evidence):
            vulnerability = self.create_vulnerability(
                title="API Version Information Disclosure",
                description="The API response contains version information that could help attackers "
                           "identify specific vulnerabilities or plan targeted attacks.",
                severity=VulnerabilitySeverity.LOW,
                endpoint=endpoint,
                evidence=[evidence],
                remediation="Remove version information from API responses and error messages.",
                cwe_id="CWE-200",
                cvss_score=2.3
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def extract_base_path(self, path: str) -> str:
        """Extract base path from endpoint path."""
        parts = path.strip('/').split('/')
        if len(parts) > 1:
            return '/' + parts[0]
        return '/'
    
    def _is_undocumented_endpoint_accessible(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if undocumented endpoint is accessible."""
        if not evidence.response_status:
            return False
        
        # If endpoint returns content (not 404)
        if evidence.response_status != 404:
            return True
        
        return False
    
    def _is_endpoint_deprecated(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint is marked as deprecated."""
        # Check if marked as deprecated in spec
        if hasattr(endpoint, 'deprecated') and endpoint.deprecated:
            return True
        
        # Check for deprecated indicators in description
        if endpoint.description:
            desc_lower = endpoint.description.lower()
            if any(term in desc_lower for term in ['deprecated', 'obsolete', 'legacy']):
                return True
        
        # Check for version indicators suggesting old version
        if endpoint.path:
            if re.search(r'/v[01]/', endpoint.path) or '/old/' in endpoint.path:
                return True
        
        return False
    
    def _has_version_exposure(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response exposes version information."""
        if not evidence.response_body and not evidence.response_headers:
            return False
        
        version_patterns = [
            r'version["\s]*:["\s]*[\d\.]+',
            r'api.version["\s]*:["\s]*[\d\.]+',
            r'server["\s]*:["\s]*[^"]*[\d\.]+',
            r'x-api-version',
            r'x-version'
        ]
        
        # Check response body
        if evidence.response_body:
            for pattern in version_patterns:
                if re.search(pattern, evidence.response_body, re.IGNORECASE):
                    return True
        
        # Check response headers
        if evidence.response_headers:
            headers_str = str(evidence.response_headers).lower()
            for pattern in version_patterns:
                if re.search(pattern, headers_str):
                    return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for inventory management."""
        test_cases = []
        
        test_cases.append({
            'name': f"inventory_undocumented_{endpoint.method}_{endpoint.path}",
            'test_type': 'undocumented_endpoints',
            'payload_count': 15  # Number of undocumented paths to test
        })
        
        if self._is_endpoint_deprecated(endpoint):
            test_cases.append({
                'name': f"inventory_deprecated_{endpoint.method}_{endpoint.path}",
                'test_type': 'deprecated_endpoint',
                'payload_count': 1
            })
        
        test_cases.append({
            'name': f"inventory_version_{endpoint.method}_{endpoint.path}",
            'test_type': 'version_exposure',
            'payload_count': 1
        })
        
        return test_cases


class UnsafeConsumptionDetector(BaseDetector):
    """API10:2023 - Unsafe Consumption of APIs detector."""
    
    def __init__(self):
        super().__init__(
            name="unsafe_consumption",
            category=VulnerabilityCategory.API10_UNSAFE_CONSUMPTION,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for unsafe consumption of third-party APIs"
        
        # Patterns that suggest third-party API consumption
        self.third_party_indicators = [
            'webhook', 'callback', 'proxy', 'forward', 'relay',
            'external', 'remote', 'fetch', 'import', 'sync'
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect unsafe consumption of third-party APIs."""
        vulnerabilities = []
        
        # Only test endpoints that likely consume third-party APIs
        if not self._endpoint_consumes_third_party_apis(endpoint):
            return vulnerabilities
        
        # Test for insufficient input validation
        vulns = await self._test_input_validation(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test for timeout handling
        vulns = await self._test_timeout_handling(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_input_validation(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test for insufficient input validation when consuming third-party APIs."""
        vulnerabilities = []
        
        # Test with malicious payloads that might be passed to third-party APIs
        malicious_payloads = [
            # XSS payloads
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            
            # SQL injection payloads
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            
            # Command injection payloads
            "; cat /etc/passwd",
            "| whoami",
            
            # XXE payloads
            "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            
            # LDAP injection
            "*)(uid=*))(|(uid=*",
            
            # NoSQL injection
            "';return true;var",
            
            # Large payload
            "A" * 10000
        ]
        
        url = self.build_url(base_url, endpoint)
        
        for payload in malicious_payloads:
            if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
                # Test in request body
                test_data = {"input": payload, "data": payload}
                
                evidence = await self.make_request(
                    method=endpoint.method,
                    url=url,
                    headers={**auth_headers, 'Content-Type': 'application/json'},
                    data=test_data
                )
                
                if self._indicates_unsafe_consumption(evidence, payload):
                    vulnerability = self.create_vulnerability(
                        title="Unsafe Third-Party API Consumption",
                        description="The endpoint appears to pass user input to third-party APIs without "
                                   "proper validation, which could lead to injection attacks or data corruption.",
                        severity=VulnerabilitySeverity.MEDIUM,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Implement strict input validation and sanitization before passing data "
                                  "to third-party APIs. Use allowlists for expected input formats.",
                        cwe_id="CWE-20",
                        cvss_score=5.3
                    )
                    vulnerability.proof_of_concept = f"Malicious payload: {payload[:100]}..."
                    vulnerabilities.append(vulnerability)
                    break  # One vulnerability per endpoint is enough
            
            else:  # GET requests - test query parameters
                # Find parameters that might be passed to third-party APIs
                for param in self.get_query_parameters(endpoint):
                    param_name = param.get('name')
                    test_url = f"{url}?{urlencode({param_name: payload})}"
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=test_url,
                        headers=auth_headers
                    )
                    
                    if self._indicates_unsafe_consumption(evidence, payload):
                        vulnerability = self.create_vulnerability(
                            title=f"Unsafe Third-Party API Consumption in parameter '{param_name}'",
                            description="The parameter appears to be passed to third-party APIs without validation.",
                            severity=VulnerabilitySeverity.MEDIUM,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Validate and sanitize all input before third-party API calls.",
                            cwe_id="CWE-20",
                            cvss_score=5.3
                        )
                        vulnerability.parameter = param_name
                        vulnerabilities.append(vulnerability)
                        break
        
        return vulnerabilities
    
    async def _test_timeout_handling(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test timeout handling for third-party API calls."""
        vulnerabilities = []
        
        url = self.build_url(base_url, endpoint)
        
        # Make request and check response time
        evidence = await self.make_request(
            method=endpoint.method,
            url=url,
            headers=auth_headers,
            timeout=30.0  # Long timeout to see if endpoint hangs
        )
        
        # If response takes very long, it might indicate poor timeout handling
        if evidence.response_time and evidence.response_time > 15.0:
            vulnerability = self.create_vulnerability(
                title="Poor Timeout Handling for Third-Party APIs",
                description="The endpoint takes an unusually long time to respond, which may indicate "
                           "poor timeout handling when consuming third-party APIs.",
                severity=VulnerabilitySeverity.LOW,
                endpoint=endpoint,
                evidence=[evidence],
                remediation="Implement proper timeout handling and circuit breakers for third-party API calls.",
                cwe_id="CWE-400",
                cvss_score=3.1
            )
            vulnerability.proof_of_concept = f"Response time: {evidence.response_time:.2f} seconds"
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _endpoint_consumes_third_party_apis(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint likely consumes third-party APIs."""
        # Check path for third-party indicators
        path_lower = endpoint.path.lower()
        for indicator in self.third_party_indicators:
            if indicator in path_lower:
                return True
        
        # Check operation ID and description
        if endpoint.operation_id:
            op_id_lower = endpoint.operation_id.lower()
            for indicator in self.third_party_indicators:
                if indicator in op_id_lower:
                    return True
        
        if endpoint.description:
            desc_lower = endpoint.description.lower()
            for indicator in self.third_party_indicators:
                if indicator in desc_lower:
                    return True
        
        return False
    
    def _indicates_unsafe_consumption(self, evidence: VulnerabilityEvidence, payload: str) -> bool:
        """Check if response indicates unsafe consumption of third-party APIs."""
        if not evidence.response_body:
            return False
        
        response_body = evidence.response_body.lower()
        
        # Look for error messages that indicate payload was passed to third-party service
        unsafe_indicators = [
            'third party', 'external service', 'remote server',
            'api error', 'service unavailable', 'timeout',
            'invalid request to', 'failed to connect',
            'upstream server', 'proxy error'
        ]
        
        for indicator in unsafe_indicators:
            if indicator in response_body:
                return True
        
        # Check if payload is reflected in response (could indicate it was processed)
        if len(payload) > 10 and payload[:10].lower() in response_body:
            return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for unsafe consumption detection."""
        test_cases = []
        
        if self._endpoint_consumes_third_party_apis(endpoint):
            test_cases.append({
                'name': f"unsafe_consumption_validation_{endpoint.method}_{endpoint.path}",
                'test_type': 'input_validation',
                'payload_count': 8  # Number of malicious payloads
            })
            
            test_cases.append({
                'name': f"unsafe_consumption_timeout_{endpoint.method}_{endpoint.path}",
                'test_type': 'timeout_handling',
                'payload_count': 1
            })
        
        return test_cases


class MassAssignmentDetector(BaseDetector):
    """API6:2023 - Unrestricted Resource Consumption (Mass Assignment) detector."""
    
    def __init__(self):
        super().__init__(
            name="mass_assignment",
            category=VulnerabilityCategory.API6_MASS_ASSIGNMENT,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for Mass Assignment vulnerabilities"
        
        # Common sensitive fields that shouldn't be mass-assignable
        self.sensitive_fields = [
            'id', 'user_id', 'admin', 'is_admin', 'role', 'roles', 'permissions',
            'is_active', 'status', 'created_at', 'updated_at', 'deleted_at',
            'password', 'token', 'api_key', 'secret', 'private_key',
            'balance', 'credits', 'points', 'subscription', 'plan'
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect mass assignment vulnerabilities."""
        vulnerabilities = []
        
        # Only test endpoints that modify data
        if endpoint.method.upper() not in ['POST', 'PUT', 'PATCH']:
            return vulnerabilities
        
        vulns = await self._test_mass_assignment(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_mass_assignment(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                  base_url: str) -> List[Vulnerability]:
        """Test for mass assignment vulnerabilities."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        # Test with additional sensitive fields
        for field in self.sensitive_fields:
            test_data = {
                "name": "test user",
                "email": "test@example.com",
                field: "unauthorized_value"  # Try to set sensitive field
            }
            
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers={**auth_headers, 'Content-Type': 'application/json'},
                data=test_data
            )
            
            if self._indicates_mass_assignment_vuln(evidence, field):
                vulnerability = self.create_vulnerability(
                    title=f"Mass Assignment Vulnerability - '{field}' field",
                    description=f"The endpoint allows modification of the sensitive field '{field}' "
                               f"through mass assignment, which could lead to privilege escalation "
                               f"or unauthorized data modification.",
                    severity=VulnerabilitySeverity.HIGH,
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Implement allowlists for updatable fields. Use DTOs or explicitly "
                              "define which fields can be modified by users.",
                    cwe_id="CWE-915",
                    cvss_score=7.3
                )
                vulnerability.parameter = field
                vulnerability.proof_of_concept = f"Sensitive field '{field}' can be set via mass assignment"
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _indicates_mass_assignment_vuln(self, evidence: VulnerabilityEvidence, field: str) -> bool:
        """Check if response indicates mass assignment vulnerability."""
        # If request was successful, the field might have been accepted
        if evidence.response_status and 200 <= evidence.response_status < 300:
            # Check if field is reflected in response
            if evidence.response_body and field in evidence.response_body.lower():
                return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for mass assignment detection."""
        test_cases = []
        
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            test_cases.append({
                'name': f"mass_assignment_{endpoint.method}_{endpoint.path}",
                'test_type': 'mass_assignment',
                'payload_count': len(self.sensitive_fields)
            })
        
        return test_cases
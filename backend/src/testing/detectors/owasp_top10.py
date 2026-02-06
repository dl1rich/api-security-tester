"""OWASP API Top 10 (2023) security testing detectors."""

import re
import json
import asyncio
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse

from testing.detector_base import BaseDetector
from testing.models import (
    Vulnerability, VulnerabilityEvidence, VulnerabilitySeverity, 
    VulnerabilityCategory, TestPriority
)
from parser.models import APISpecification, APIEndpoint


class BOLADetector(BaseDetector):
    """API1:2023 - Broken Object Level Authorization (BOLA/IDOR) detector."""
    
    def __init__(self):
        super().__init__(
            name="bola_idor",
            category=VulnerabilityCategory.API1_BOLA,
            priority=TestPriority.CRITICAL
        )
        self.description = "Tests for Broken Object Level Authorization vulnerabilities"
        
        # Common object ID patterns
        self.id_patterns = [
            r'/\d+',  # /123
            r'/[a-f0-9-]{36}',  # UUID
            r'/[a-zA-Z0-9]+',  # Generic alphanumeric
            r'\?id=\d+',  # ?id=123
            r'\?.*id=[a-zA-Z0-9-]+',  # Various ID patterns in query
        ]
        
        # Test ID variations
        self.test_ids = [
            "1", "2", "999", "1000", "-1", "0",
            "11111111-2222-3333-4444-555555555555",
            "00000000-0000-0000-0000-000000000000",
            "admin", "test", "user", "guest"
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect BOLA/IDOR vulnerabilities."""
        vulnerabilities = []
        
        # Only test endpoints that likely access objects
        if not self._endpoint_accesses_objects(endpoint):
            return vulnerabilities
        
        # Test path-based object access
        vulns = await self._test_path_based_bola(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test query-based object access
        vulns = await self._test_query_based_bola(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _endpoint_accesses_objects(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint likely accesses specific objects."""
        # Look for ID patterns in path
        for pattern in self.id_patterns:
            if re.search(pattern, endpoint.path):
                return True
        
        # Check for ID parameters
        for param in endpoint.parameters:
            param_name = param.get('name', '').lower()
            if any(id_term in param_name for id_term in ['id', 'key', 'uuid', 'guid']):
                return True
        
        # Check if it's a typical object access endpoint
        object_verbs = ['GET', 'PUT', 'PATCH', 'DELETE']
        if endpoint.method.upper() in object_verbs and '{' in endpoint.path:
            return True
        
        return False
    
    async def _test_path_based_bola(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test BOLA vulnerabilities in path parameters."""
        vulnerabilities = []
        
        path_params = self.extract_path_parameters(endpoint)
        if not path_params:
            return vulnerabilities
        
        # Test different ID values
        for param_name in path_params:
            # Test with original auth
            original_url = self.build_url(base_url, endpoint, {param_name: "123"})
            original_evidence = await self.make_request(
                method=endpoint.method,
                url=original_url,
                headers=auth_headers
            )
            
            # Test accessing other objects
            for test_id in self.test_ids:
                test_url = self.build_url(base_url, endpoint, {param_name: test_id})
                test_evidence = await self.make_request(
                    method=endpoint.method,
                    url=test_url,
                    headers=auth_headers
                )
                
                if self._is_bola_vulnerable(original_evidence, test_evidence, test_id):
                    vulnerability = self.create_vulnerability(
                        title=f"Broken Object Level Authorization in path parameter '{param_name}'",
                        description=f"The endpoint allows access to objects by manipulating the '{param_name}' parameter, "
                                   f"potentially exposing unauthorized data or allowing unauthorized actions.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[original_evidence, test_evidence],
                        remediation="Implement proper authorization checks to ensure users can only access "
                                  "objects they own or are authorized to access.",
                        cwe_id="CWE-639",
                        cvss_score=8.1
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nTest ID: {test_id}"
                    vulnerabilities.append(vulnerability)
                    break  # Found vulnerability for this parameter
        
        return vulnerabilities
    
    async def _test_query_based_bola(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                    base_url: str) -> List[Vulnerability]:
        """Test BOLA vulnerabilities in query parameters."""
        vulnerabilities = []
        
        # Look for ID-like query parameters
        id_params = []
        for param in self.get_query_parameters(endpoint):
            param_name = param.get('name', '').lower()
            if any(id_term in param_name for id_term in ['id', 'key', 'uuid', 'user']):
                id_params.append(param)
        
        for param in id_params:
            param_name = param.get('name')
            
            # Test with original value
            original_url = self.build_url(base_url, endpoint)
            original_query = urlencode({param_name: "123"})
            original_url_with_query = f"{original_url}?{original_query}"
            
            original_evidence = await self.make_request(
                method=endpoint.method,
                url=original_url_with_query,
                headers=auth_headers
            )
            
            # Test with different IDs
            for test_id in self.test_ids:
                test_query = urlencode({param_name: test_id})
                test_url = f"{original_url}?{test_query}"
                
                test_evidence = await self.make_request(
                    method=endpoint.method,
                    url=test_url,
                    headers=auth_headers
                )
                
                if self._is_bola_vulnerable(original_evidence, test_evidence, test_id):
                    vulnerability = self.create_vulnerability(
                        title=f"Broken Object Level Authorization in query parameter '{param_name}'",
                        description=f"The endpoint allows access to different objects by manipulating "
                                   f"the '{param_name}' query parameter.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[original_evidence, test_evidence],
                        remediation="Implement proper authorization checks for object access.",
                        cwe_id="CWE-639",
                        cvss_score=8.1
                    )
                    vulnerability.parameter = param_name
                    vulnerabilities.append(vulnerability)
                    break
        
        return vulnerabilities
    
    def _is_bola_vulnerable(self, original_evidence: VulnerabilityEvidence,
                           test_evidence: VulnerabilityEvidence, test_id: str) -> bool:
        """Check if BOLA vulnerability exists."""
        # Check if test request succeeded when it should be denied
        if (test_evidence.response_status and 
            200 <= test_evidence.response_status < 300 and
            test_evidence.response_body and
            len(test_evidence.response_body) > 50):
            
            # Different content suggests accessing different objects
            if (original_evidence.response_body and
                test_evidence.response_body != original_evidence.response_body):
                return True
                
            # Same successful response might indicate access to unauthorized object
            if test_id in ["999", "1000", "admin", "guest"]:
                return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for BOLA detection."""
        test_cases = []
        
        if self._endpoint_accesses_objects(endpoint):
            path_params = self.extract_path_parameters(endpoint)
            for param_name in path_params:
                test_cases.append({
                    'name': f"bola_path_{param_name}",
                    'parameter_type': 'path',
                    'parameter_name': param_name,
                    'payload_count': len(self.test_ids)
                })
            
            # Query parameters
            for param in self.get_query_parameters(endpoint):
                param_name = param.get('name', '').lower()
                if any(id_term in param_name for id_term in ['id', 'key', 'uuid']):
                    test_cases.append({
                        'name': f"bola_query_{param_name}",
                        'parameter_type': 'query',
                        'parameter_name': param_name,
                        'payload_count': len(self.test_ids)
                    })
        
        return test_cases


class BrokenFunctionAuthDetector(BaseDetector):
    """API5:2023 - Broken Function Level Authorization detector."""
    
    def __init__(self):
        super().__init__(
            name="broken_function_auth",
            category=VulnerabilityCategory.API5_FUNCTION_AUTH,
            priority=TestPriority.HIGH
        )
        self.description = "Tests for Broken Function Level Authorization vulnerabilities"
        
        # HTTP methods to test
        self.test_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect broken function level authorization."""
        vulnerabilities = []
        
        # Test HTTP method tampering
        vulns = await self._test_method_tampering(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test administrative function access
        if self._is_admin_function(endpoint):
            vulns = await self._test_admin_access(endpoint, auth_headers, base_url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_method_tampering(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test HTTP method tampering for unauthorized access."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        # Get baseline response with original method
        original_evidence = await self.make_request(
            method=endpoint.method,
            url=url,
            headers=auth_headers
        )
        
        # Test other HTTP methods
        for test_method in self.test_methods:
            if test_method.upper() == endpoint.method.upper():
                continue  # Skip original method
            
            test_evidence = await self.make_request(
                method=test_method,
                url=url,
                headers=auth_headers
            )
            
            if self._is_method_vulnerable(original_evidence, test_evidence, test_method):
                vulnerability = self.create_vulnerability(
                    title=f"HTTP Method Tampering - {test_method} method allowed",
                    description=f"The endpoint accepts {test_method} requests when only {endpoint.method} "
                               f"should be allowed, potentially bypassing authorization controls.",
                    severity=VulnerabilitySeverity.MEDIUM,
                    endpoint=endpoint,
                    evidence=[original_evidence, test_evidence],
                    remediation="Restrict HTTP methods to only those required by the endpoint functionality.",
                    cwe_id="CWE-425",
                    cvss_score=5.3
                )
                vulnerability.proof_of_concept = f"Method: {test_method}\nURL: {url}"
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _test_admin_access(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                               base_url: str) -> List[Vulnerability]:
        """Test access to administrative functions."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        # Test without authentication
        no_auth_evidence = await self.make_request(
            method=endpoint.method,
            url=url,
            headers={}
        )
        
        # Test with authentication
        auth_evidence = await self.make_request(
            method=endpoint.method,
            url=url,
            headers=auth_headers
        )
        
        if self._is_admin_accessible_without_auth(no_auth_evidence, auth_evidence):
            vulnerability = self.create_vulnerability(
                title="Administrative Function Accessible Without Authentication",
                description="This administrative endpoint can be accessed without proper authentication, "
                           "potentially allowing unauthorized administrative actions.",
                severity=VulnerabilitySeverity.CRITICAL,
                endpoint=endpoint,
                evidence=[no_auth_evidence, auth_evidence],
                remediation="Implement strong authentication and authorization for administrative functions.",
                cwe_id="CWE-306",
                cvss_score=9.1
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_admin_function(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint is an administrative function."""
        admin_indicators = [
            'admin', 'manage', 'config', 'setting', 'delete', 'create', 'update',
            'modify', 'edit', 'remove', 'add', 'grant', 'revoke', 'permission'
        ]
        
        # Check path
        path_lower = endpoint.path.lower()
        for indicator in admin_indicators:
            if indicator in path_lower:
                return True
        
        # Check operation ID and summary
        if endpoint.operation_id:
            op_id_lower = endpoint.operation_id.lower()
            for indicator in admin_indicators:
                if indicator in op_id_lower:
                    return True
        
        # Check if it's a destructive method
        if endpoint.method.upper() in ['DELETE', 'PUT']:
            return True
        
        return False
    
    def _is_method_vulnerable(self, original_evidence: VulnerabilityEvidence,
                            test_evidence: VulnerabilityEvidence, test_method: str) -> bool:
        """Check if method tampering reveals vulnerability."""
        # If test method succeeds when it shouldn't be allowed
        if (test_evidence.response_status and 
            200 <= test_evidence.response_status < 300 and
            test_evidence.response_status != 405):  # 405 = Method Not Allowed
            return True
        
        return False
    
    def _is_admin_accessible_without_auth(self, no_auth_evidence: VulnerabilityEvidence,
                                        auth_evidence: VulnerabilityEvidence) -> bool:
        """Check if admin function is accessible without auth."""
        if (no_auth_evidence.response_status and 
            200 <= no_auth_evidence.response_status < 300 and
            no_auth_evidence.response_status != 401 and 
            no_auth_evidence.response_status != 403):
            return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for function level auth detection."""
        test_cases = []
        
        # Method tampering tests
        test_cases.append({
            'name': f"method_tampering_{endpoint.method}_{endpoint.path}",
            'test_type': 'method_tampering',
            'payload_count': len(self.test_methods) - 1  # Exclude original method
        })
        
        # Admin access tests
        if self._is_admin_function(endpoint):
            test_cases.append({
                'name': f"admin_access_{endpoint.method}_{endpoint.path}",
                'test_type': 'admin_access',
                'payload_count': 1
            })
        
        return test_cases


class SSRFDetector(BaseDetector):
    """API7:2023 - Server Side Request Forgery detector."""
    
    def __init__(self):
        super().__init__(
            name="ssrf",
            category=VulnerabilityCategory.API7_SSRF,
            priority=TestPriority.HIGH
        )
        self.description = "Tests for Server Side Request Forgery vulnerabilities"
        
        # SSRF payloads
        self.ssrf_payloads = [
            # Internal network access
            "http://localhost/",
            "http://127.0.0.1/",
            "http://0.0.0.0/",
            "http://[:1]/",
            "http://[::1]/",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            
            # Cloud metadata services
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            
            # File protocol
            "file:///etc/passwd",
            "file:///c:/windows/system32/drivers/etc/hosts",
            
            # Different schemes
            "ftp://localhost/",
            "gopher://localhost:25/",
            "dict://localhost:11211/",
        ]
        
        # URL parameter names that might be vulnerable
        self.url_param_names = [
            'url', 'uri', 'link', 'callback', 'webhook', 'redirect', 'target',
            'endpoint', 'host', 'server', 'domain', 'site', 'path', 'source'
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect SSRF vulnerabilities."""
        vulnerabilities = []
        
        # Test URL parameters
        vulns = await self._test_url_parameters(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test request body URLs
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            vulns = await self._test_body_urls(endpoint, auth_headers, base_url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_url_parameters(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                 base_url: str) -> List[Vulnerability]:
        """Test URL parameters for SSRF."""
        vulnerabilities = []
        
        # Find URL-like parameters
        url_params = []
        for param in self.get_query_parameters(endpoint):
            param_name = param.get('name', '').lower()
            if any(url_name in param_name for url_name in self.url_param_names):
                url_params.append(param)
        
        for param in url_params:
            param_name = param.get('name')
            
            for payload in self.ssrf_payloads:
                try:
                    url = self.build_url(base_url, endpoint)
                    query_string = urlencode({param_name: payload})
                    test_url = f"{url}?{query_string}"
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=test_url,
                        headers=auth_headers,
                        timeout=10.0  # Shorter timeout for SSRF tests
                    )
                    
                    if self._is_ssrf_vulnerable(evidence, payload):
                        vulnerability = self.create_vulnerability(
                            title=f"Server Side Request Forgery in parameter '{param_name}'",
                            description=f"The parameter '{param_name}' allows making requests to arbitrary URLs, "
                                       f"potentially exposing internal networks or services.",
                            severity=VulnerabilitySeverity.HIGH,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Validate and whitelist allowed URLs/domains. Use URL parsing libraries "
                                      "and implement proper network segmentation.",
                            cwe_id="CWE-918",
                            cvss_score=7.7
                        )
                        vulnerability.parameter = param_name
                        vulnerability.proof_of_concept = f"Parameter: {param_name}\nSSRF Payload: {payload}"
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception as e:
                    # Timeout or connection errors might indicate SSRF
                    if "timeout" in str(e).lower() or "connection" in str(e).lower():
                        # This could be SSRF, but we need more evidence
                        pass
        
        return vulnerabilities
    
    async def _test_body_urls(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                            base_url: str) -> List[Vulnerability]:
        """Test request body for SSRF vulnerabilities."""
        vulnerabilities = []
        
        # Test common URL fields in JSON body
        for field_name in self.url_param_names:
            for payload in self.ssrf_payloads[:5]:  # Test fewer payloads for body
                try:
                    url = self.build_url(base_url, endpoint)
                    test_body = {field_name: payload}
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=url,
                        headers={**auth_headers, 'Content-Type': 'application/json'},
                        data=test_body,
                        timeout=10.0
                    )
                    
                    if self._is_ssrf_vulnerable(evidence, payload):
                        vulnerability = self.create_vulnerability(
                            title=f"Server Side Request Forgery in request body field '{field_name}'",
                            description=f"The request body field '{field_name}' allows making requests to arbitrary URLs.",
                            severity=VulnerabilitySeverity.HIGH,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Validate and whitelist allowed URLs in request body.",
                            cwe_id="CWE-918",
                            cvss_score=7.7
                        )
                        vulnerability.parameter = field_name
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def _is_ssrf_vulnerable(self, evidence: VulnerabilityEvidence, payload: str) -> bool:
        """Check if response indicates SSRF vulnerability."""
        if not evidence.response_body:
            return False
        
        response_body = evidence.response_body.lower()
        
        # Check for internal service responses
        internal_indicators = [
            "connection refused", "connection timeout", "name or service not known",
            "no route to host", "network is unreachable", "port 80: connection refused",
            "metadata", "aws", "gcp", "azure", "localhost", "127.0.0.1"
        ]
        
        for indicator in internal_indicators:
            if indicator in response_body:
                return True
        
        # Check for successful internal requests
        if "169.254.169.254" in payload and ("ami-" in response_body or "instance-id" in response_body):
            return True
        
        # Check response time - very long responses might indicate internal network access
        if evidence.response_time and evidence.response_time > 8.0:
            return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for SSRF detection."""
        test_cases = []
        
        # URL parameter tests
        for param in self.get_query_parameters(endpoint):
            param_name = param.get('name', '').lower()
            if any(url_name in param_name for url_name in self.url_param_names):
                test_cases.append({
                    'name': f"ssrf_query_{param_name}",
                    'parameter_type': 'query',
                    'parameter_name': param_name,
                    'payload_count': len(self.ssrf_payloads)
                })
        
        # Body URL tests
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            test_cases.append({
                'name': "ssrf_body",
                'parameter_type': 'body',
                'parameter_name': 'request_body',
                'payload_count': len(self.url_param_names) * 5  # 5 payloads per field
            })
        
        return test_cases
"""Sample vulnerability detectors for common security issues."""

import json
import re
from typing import List, Dict, Any
from urllib.parse import urlencode

from testing.detector_base import BaseDetector
from testing.models import (
    Vulnerability, VulnerabilityEvidence, VulnerabilitySeverity, 
    VulnerabilityCategory, TestPriority
)
from parser.models import APISpecification, APIEndpoint


class SQLInjectionDetector(BaseDetector):
    """Detects SQL injection vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="sql_injection", 
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.HIGH
        )
        self.description = "Tests for SQL injection vulnerabilities in API parameters"
        
        # SQL injection payloads
        self.payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' AND 1=1 --",
            "1' AND 1=2 --",
            "' UNION SELECT 1,2,3 --",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' OR 1=1#",
            "') OR '1'='1",
            "1; WAITFOR DELAY '00:00:05' --"
        ]
        
        # SQL error patterns
        self.error_patterns = [
            r"sql syntax.*mysql",
            r"warning.*mysql_.*",
            r"valid mysql result",
            r"postgresql.*error",
            r"warning.*pg_.*",
            r"valid postgresql result",
            r"sqlite error",
            r"sqlite3.operationalerror",
            r"microsoft access (\d+ )?driver",
            r"microsoft ole db provider for odbc drivers",
            r"oracle error",
            r"oracle.*driver",
            r"sql server.*jdbc",
            r"sqlexception"
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect SQL injection vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            vulns = await self._test_parameter_sql_injection(
                endpoint, param, 'query', auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        # Test path parameters
        path_params = self.extract_path_parameters(endpoint)
        for param_name in path_params:
            vulns = await self._test_path_parameter_sql_injection(
                endpoint, param_name, auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        # Test request body parameters (for POST/PUT/PATCH)
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            vulns = await self._test_body_sql_injection(
                endpoint, auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter_sql_injection(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                          param_type: str, auth_headers: Dict[str, str], 
                                          base_url: str) -> List[Vulnerability]:
        """Test a specific parameter for SQL injection."""
        vulnerabilities = []
        param_name = parameter.get('name', '')
        
        for payload in self.payloads:
            try:
                if param_type == 'query':
                    # Test query parameter
                    url = self.build_url(base_url, endpoint)
                    query_string = urlencode({param_name: payload})
                    test_url = f"{url}?{query_string}"
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=test_url,
                        headers=auth_headers
                    )
                
                else:  # header parameter
                    url = self.build_url(base_url, endpoint)
                    test_headers = {**auth_headers, param_name: payload}
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=url,
                        headers=test_headers
                    )
                
                # Check for SQL injection indicators
                if self._is_sql_injection_vulnerable(evidence):
                    vulnerability = self.create_vulnerability(
                        title=f"SQL Injection in {param_type} parameter '{param_name}'",
                        description=f"The {param_type} parameter '{param_name}' appears to be vulnerable to SQL injection attacks. "
                                   f"SQL injection can allow attackers to manipulate database queries, potentially leading to "
                                   f"unauthorized data access, data manipulation, or complete database compromise.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Use parameterized queries, prepared statements, or stored procedures. "
                                  "Validate and sanitize all user inputs. Implement least privilege database access.",
                        cwe_id="CWE-89",
                        cvss_score=8.8
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break  # Found vulnerability, no need to test other payloads for this param
                    
            except Exception as e:
                # Log error but continue testing
                pass
        
        return vulnerabilities
    
    async def _test_path_parameter_sql_injection(self, endpoint: APIEndpoint, param_name: str,
                                               auth_headers: Dict[str, str], 
                                               base_url: str) -> List[Vulnerability]:
        """Test path parameters for SQL injection."""
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                # Replace path parameter with payload
                path_params = {param_name: payload}
                url = self.build_url(base_url, endpoint, path_params)
                
                evidence = await self.make_request(
                    method=endpoint.method,
                    url=url,
                    headers=auth_headers
                )
                
                if self._is_sql_injection_vulnerable(evidence):
                    vulnerability = self.create_vulnerability(
                        title=f"SQL Injection in path parameter '{param_name}'",
                        description=f"The path parameter '{param_name}' appears to be vulnerable to SQL injection attacks.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Use parameterized queries and validate path parameters.",
                        cwe_id="CWE-89",
                        cvss_score=8.8
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Path parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    async def _test_body_sql_injection(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                     base_url: str) -> List[Vulnerability]:
        """Test request body parameters for SQL injection."""
        vulnerabilities = []
        
        if not endpoint.request_body:
            return vulnerabilities
        
        # Create a sample request body
        sample_body = {"id": 1, "name": "test", "email": "test@example.com"}
        
        for field_name in sample_body.keys():
            for payload in self.payloads:
                try:
                    test_body = sample_body.copy()
                    test_body[field_name] = payload
                    
                    url = self.build_url(base_url, endpoint)
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=url,
                        headers={**auth_headers, 'Content-Type': 'application/json'},
                        data=test_body
                    )
                    
                    if self._is_sql_injection_vulnerable(evidence):
                        vulnerability = self.create_vulnerability(
                            title=f"SQL Injection in request body field '{field_name}'",
                            description=f"The request body field '{field_name}' appears to be vulnerable to SQL injection attacks.",
                            severity=VulnerabilitySeverity.HIGH,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Use parameterized queries and validate request body data.",
                            cwe_id="CWE-89",
                            cvss_score=8.8
                        )
                        vulnerability.parameter = field_name
                        vulnerability.proof_of_concept = f"Body field: {field_name}\nPayload: {payload}"
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def _is_sql_injection_vulnerable(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response indicates SQL injection vulnerability."""
        if not evidence.response_body:
            return False
        
        response_text = evidence.response_body.lower()
        
        # Check for SQL error messages
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for database-specific errors
        sql_indicators = [
            "syntax error",
            "mysql_fetch",
            "oci_fetch_array",
            "ora-01756",
            "sqlstate",
            "quoted string not properly terminated",
            "unclosed quotation mark",
            "warning: mysql_"
        ]
        
        for indicator in sql_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for this detector."""
        test_cases = []
        
        # Query parameter tests
        for param in self.get_query_parameters(endpoint):
            test_cases.append({
                'name': f"sql_injection_query_{param.get('name')}",
                'parameter_type': 'query',
                'parameter_name': param.get('name'),
                'payload_count': len(self.payloads)
            })
        
        # Path parameter tests  
        for param_name in self.extract_path_parameters(endpoint):
            test_cases.append({
                'name': f"sql_injection_path_{param_name}",
                'parameter_type': 'path',
                'parameter_name': param_name,
                'payload_count': len(self.payloads)
            })
        
        # Body parameter tests
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            test_cases.append({
                'name': "sql_injection_body",
                'parameter_type': 'body',
                'parameter_name': 'request_body',
                'payload_count': len(self.payloads) * 3  # Estimate for multiple body fields
            })
        
        return test_cases


class XSSDetector(BaseDetector):
    """Detects Cross-Site Scripting (XSS) vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="xss_detection",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.HIGH
        )
        self.description = "Tests for XSS vulnerabilities in API responses"
        
        self.xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg/onload=alert('xss')>",
            "'><script>alert('xss')</script>",
            "\"><script>alert('xss')</script>",
            "<iframe src=javascript:alert('xss')>",
            "<body onload=alert('xss')>",
            "<script>alert(document.domain)</script>",
            "';alert('xss');//"
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect XSS vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            vulns = await self._test_xss_in_parameter(
                endpoint, param, 'query', auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_xss_in_parameter(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                   param_type: str, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test parameter for XSS vulnerabilities."""
        vulnerabilities = []
        param_name = parameter.get('name', '')
        
        for payload in self.xss_payloads:
            try:
                url = self.build_url(base_url, endpoint)
                query_string = urlencode({param_name: payload})
                test_url = f"{url}?{query_string}"
                
                evidence = await self.make_request(
                    method=endpoint.method,
                    url=test_url,
                    headers=auth_headers
                )
                
                if self._is_xss_vulnerable(evidence, payload):
                    vulnerability = self.create_vulnerability(
                        title=f"Cross-Site Scripting (XSS) in {param_type} parameter '{param_name}'",
                        description=f"The {param_type} parameter '{param_name}' reflects user input without proper encoding, "
                                   f"making it vulnerable to XSS attacks.",
                        severity=VulnerabilitySeverity.MEDIUM,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Encode all user input before including it in responses. Use Content Security Policy (CSP).",
                        cwe_id="CWE-79",
                        cvss_score=6.1
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def _is_xss_vulnerable(self, evidence: VulnerabilityEvidence, payload: str) -> bool:
        """Check if response reflects XSS payload."""
        if not evidence.response_body:
            return False
        
        # Check if payload is reflected in response
        return payload in evidence.response_body
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for XSS detection."""
        test_cases = []
        
        for param in self.get_query_parameters(endpoint):
            test_cases.append({
                'name': f"xss_query_{param.get('name')}",
                'parameter_type': 'query',
                'parameter_name': param.get('name'),
                'payload_count': len(self.xss_payloads)
            })
        
        return test_cases


class AuthenticationBypassDetector(BaseDetector):
    """Detects authentication bypass vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="auth_bypass",
            category=VulnerabilityCategory.API2_BROKEN_AUTH,
            priority=TestPriority.CRITICAL
        )
        self.description = "Tests for authentication bypass vulnerabilities"
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        # Only test endpoints that require authentication
        if not endpoint.security_requirements:
            return vulnerabilities
        
        # Test access without authentication
        url = self.build_url(base_url, endpoint)
        
        # Test without any auth headers
        evidence_no_auth = await self.make_request(
            method=endpoint.method,
            url=url,
            headers={}
        )
        
        # Test with authenticated request for comparison
        evidence_with_auth = await self.make_request(
            method=endpoint.method,
            url=url,
            headers=auth_headers
        )
        
        # Check if endpoint is accessible without authentication
        if self._is_bypass_successful(evidence_no_auth, evidence_with_auth):
            vulnerability = self.create_vulnerability(
                title="Authentication Bypass",
                description="This endpoint requires authentication but is accessible without providing credentials.",
                severity=VulnerabilitySeverity.HIGH,
                endpoint=endpoint,
                evidence=[evidence_no_auth, evidence_with_auth],
                remediation="Ensure all protected endpoints properly validate authentication credentials.",
                cwe_id="CWE-306",
                cvss_score=7.5
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_bypass_successful(self, no_auth_evidence: VulnerabilityEvidence,
                            auth_evidence: VulnerabilityEvidence) -> bool:
        """Check if authentication bypass was successful."""
        # If no auth request succeeds (2xx status) when auth request also succeeds
        if (no_auth_evidence.response_status and 
            200 <= no_auth_evidence.response_status < 300 and
            auth_evidence.response_status and
            200 <= auth_evidence.response_status < 300):
            return True
        
        # Check if response content is similar (indicating same functionality)
        if (no_auth_evidence.response_body and auth_evidence.response_body and
            len(no_auth_evidence.response_body) > 100 and
            no_auth_evidence.response_body == auth_evidence.response_body):
            return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for authentication bypass detection."""
        test_cases = []
        
        if endpoint.security_requirements:
            test_cases.append({
                'name': f"auth_bypass_{endpoint.method}_{endpoint.path}",
                'test_type': 'authentication_bypass',
                'payload_count': 1
            })
        
        return test_cases
"""Additional OWASP API Top 10 (2023) security testing detectors."""

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


class ExcessiveDataExposureDetector(BaseDetector):
    """API3:2023 - Excessive Data Exposure detector."""
    
    def __init__(self):
        super().__init__(
            name="excessive_data_exposure",
            category=VulnerabilityCategory.API3_DATA_EXPOSURE,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for Excessive Data Exposure vulnerabilities"
        
        # Sensitive field patterns
        self.sensitive_patterns = [
            r'"password"\s*:\s*"[^"]*"',
            r'"passwd"\s*:\s*"[^"]*"',
            r'"secret"\s*:\s*"[^"]*"',
            r'"private_key"\s*:\s*"[^"]*"',
            r'"api_key"\s*:\s*"[^"]*"',
            r'"token"\s*:\s*"[^"]*"',
            r'"access_token"\s*:\s*"[^"]*"',
            r'"refresh_token"\s*:\s*"[^"]*"',
            r'"ssn"\s*:\s*"[^"]*"',
            r'"social_security"\s*:\s*"[^"]*"',
            r'"credit_card"\s*:\s*"[^"]*"',
            r'"card_number"\s*:\s*"[^"]*"',
            r'"cvv"\s*:\s*"[^"]*"',
            r'"pin"\s*:\s*"[^"]*"',
        ]
        
        # Sensitive field names
        self.sensitive_fields = [
            'password', 'passwd', 'pwd', 'secret', 'private_key', 'api_key',
            'token', 'access_token', 'refresh_token', 'ssn', 'social_security',
            'credit_card', 'card_number', 'cvv', 'pin', 'bank_account',
            'phone', 'email', 'address', 'birth_date', 'salary', 'hash',
            'encrypted', 'private', 'confidential'
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect excessive data exposure."""
        vulnerabilities = []
        
        # Only test GET endpoints that return data
        if endpoint.method.upper() != 'GET':
            return vulnerabilities
        
        url = self.build_url(base_url, endpoint)
        evidence = await self.make_request(
            method=endpoint.method,
            url=url,
            headers=auth_headers
        )
        
        if self._has_excessive_data_exposure(evidence):
            vulnerability = self.create_vulnerability(
                title="Excessive Data Exposure",
                description="The API endpoint returns sensitive data that should not be exposed to the client. "
                           "This may include passwords, tokens, personal information, or internal system data.",
                severity=VulnerabilitySeverity.MEDIUM,
                endpoint=endpoint,
                evidence=[evidence],
                remediation="Filter response data to only include fields necessary for the client. "
                          "Implement response filtering based on user permissions.",
                cwe_id="CWE-200",
                cvss_score=5.3
            )
            vulnerability.proof_of_concept = self._extract_sensitive_data(evidence.response_body)
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _has_excessive_data_exposure(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response contains excessive data exposure."""
        if not evidence.response_body:
            return False
        
        response_body = evidence.response_body
        
        # Check for sensitive field patterns
        for pattern in self.sensitive_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        # Check for sensitive field names in JSON
        try:
            if response_body.strip().startswith(('{', '[')):
                data = json.loads(response_body)
                if self._check_json_for_sensitive_data(data):
                    return True
        except json.JSONDecodeError:
            pass
        
        return False
    
    def _check_json_for_sensitive_data(self, data: Union[Dict, List, Any], depth: int = 0) -> bool:
        """Recursively check JSON for sensitive data."""
        if depth > 10:  # Prevent infinite recursion
            return False
        
        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = key.lower()
                
                # Check if field name is sensitive
                if any(sensitive in key_lower for sensitive in self.sensitive_fields):
                    return True
                
                # Recursively check nested objects
                if isinstance(value, (dict, list)):
                    if self._check_json_for_sensitive_data(value, depth + 1):
                        return True
                        
        elif isinstance(data, list):
            for item in data[:10]:  # Check first 10 items to avoid performance issues
                if self._check_json_for_sensitive_data(item, depth + 1):
                    return True
        
        return False
    
    def _extract_sensitive_data(self, response_body: str) -> str:
        """Extract examples of sensitive data exposure."""
        if not response_body:
            return ""
        
        examples = []
        
        # Find sensitive patterns
        for pattern in self.sensitive_patterns[:5]:  # First 5 patterns
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            for match in matches[:2]:  # First 2 matches per pattern
                examples.append(f"Found: {match[:100]}...")  # Truncate long values
        
        return "\n".join(examples) if examples else "Sensitive data patterns detected"
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for excessive data exposure."""
        test_cases = []
        
        if endpoint.method.upper() == 'GET':
            test_cases.append({
                'name': f"data_exposure_{endpoint.method}_{endpoint.path}",
                'test_type': 'data_exposure_check',
                'payload_count': 1
            })
        
        return test_cases


class ResourceConsumptionDetector(BaseDetector):
    """API4:2023 - Lack of Resources & Rate Limiting detector."""
    
    def __init__(self):
        super().__init__(
            name="resource_consumption",
            category=VulnerabilityCategory.API4_RATE_LIMITING,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for lack of rate limiting and resource consumption controls"
        
        # Number of requests to test rate limiting
        self.rate_limit_test_count = 20
        self.burst_test_count = 50
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect rate limiting and resource consumption issues."""
        vulnerabilities = []
        
        # Test rate limiting
        vulns = await self._test_rate_limiting(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test resource consumption for POST/PUT endpoints
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            vulns = await self._test_resource_consumption(endpoint, auth_headers, base_url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_rate_limiting(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                base_url: str) -> List[Vulnerability]:
        """Test for rate limiting."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        # Send multiple requests rapidly
        successful_requests = 0
        rate_limited_requests = 0
        evidence_list = []
        
        for i in range(self.rate_limit_test_count):
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers=auth_headers,
                timeout=5.0
            )
            
            evidence_list.append(evidence)
            
            if evidence.response_status:
                if 200 <= evidence.response_status < 300:
                    successful_requests += 1
                elif evidence.response_status in [429, 503]:  # Too Many Requests, Service Unavailable
                    rate_limited_requests += 1
        
        # If all requests succeeded, there's likely no rate limiting
        if successful_requests >= self.rate_limit_test_count * 0.9:  # 90% success rate
            vulnerability = self.create_vulnerability(
                title="Missing Rate Limiting",
                description="The API endpoint does not implement rate limiting, allowing unlimited requests "
                           "which could lead to resource exhaustion and denial of service attacks.",
                severity=VulnerabilitySeverity.MEDIUM,
                endpoint=endpoint,
                evidence=evidence_list[:3],  # Include first 3 requests as evidence
                remediation="Implement rate limiting based on IP address, user account, or API key. "
                          "Consider implementing different rate limits for different types of operations.",
                cwe_id="CWE-770",
                cvss_score=5.3
            )
            vulnerability.proof_of_concept = f"Sent {self.rate_limit_test_count} requests, " \
                                           f"{successful_requests} succeeded, {rate_limited_requests} rate limited"
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _test_resource_consumption(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                       base_url: str) -> List[Vulnerability]:
        """Test resource consumption with large payloads."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        # Test with increasingly large payloads
        large_payloads = [
            "A" * 1024,      # 1KB
            "B" * 10240,     # 10KB
            "C" * 102400,    # 100KB
            "D" * 1048576,   # 1MB
        ]
        
        for i, payload in enumerate(large_payloads):
            test_data = {"data": payload, "test": f"large_payload_{i}"}
            
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers={**auth_headers, 'Content-Type': 'application/json'},
                data=test_data,
                timeout=30.0
            )
            
            # Check if large payload was accepted without proper validation
            if (evidence.response_status and 
                200 <= evidence.response_status < 300 and
                len(payload) > 100000):  # Payload > 100KB accepted
                
                vulnerability = self.create_vulnerability(
                    title="Lack of Resource Consumption Controls",
                    description="The API accepts extremely large payloads without proper size validation, "
                               "which could lead to resource exhaustion and denial of service.",
                    severity=VulnerabilitySeverity.MEDIUM,
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Implement payload size limits and request timeout controls. "
                              "Validate and sanitize all input data.",
                    cwe_id="CWE-770",
                    cvss_score=5.3
                )
                vulnerability.proof_of_concept = f"Large payload of {len(payload)} bytes accepted"
                vulnerabilities.append(vulnerability)
                break  # Don't test larger payloads if this one succeeded
        
        return vulnerabilities
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for resource consumption testing."""
        test_cases = []
        
        # Rate limiting test
        test_cases.append({
            'name': f"rate_limit_{endpoint.method}_{endpoint.path}",
            'test_type': 'rate_limiting',
            'payload_count': self.rate_limit_test_count
        })
        
        # Resource consumption test for endpoints that accept data
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            test_cases.append({
                'name': f"resource_consumption_{endpoint.method}_{endpoint.path}",
                'test_type': 'resource_consumption',
                'payload_count': 4  # 4 different payload sizes
            })
        
        return test_cases


class SecurityMisconfigDetector(BaseDetector):
    """API8:2023 - Security Misconfiguration detector."""
    
    def __init__(self):
        super().__init__(
            name="security_misconfig",
            category=VulnerabilityCategory.API8_MISCONFIG,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for security misconfigurations"
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect security misconfigurations."""
        vulnerabilities = []
        
        # Test security headers
        vulns = await self._test_security_headers(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test error handling
        vulns = await self._test_error_handling(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        # Test CORS configuration
        vulns = await self._test_cors_config(endpoint, auth_headers, base_url)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_security_headers(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test for missing security headers."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        evidence = await self.make_request(
            method=endpoint.method,
            url=url,
            headers=auth_headers
        )
        
        missing_headers = self._check_security_headers(evidence)
        if missing_headers:
            vulnerability = self.create_vulnerability(
                title="Missing Security Headers",
                description="The API response is missing important security headers that help protect "
                           "against various attacks and provide defense in depth.",
                severity=VulnerabilitySeverity.LOW,
                endpoint=endpoint,
                evidence=[evidence],
                remediation=f"Add the following security headers: {', '.join(missing_headers)}",
                cwe_id="CWE-16",
                cvss_score=3.1
            )
            vulnerability.proof_of_concept = f"Missing headers: {', '.join(missing_headers)}"
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _test_error_handling(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                 base_url: str) -> List[Vulnerability]:
        """Test error handling for information disclosure."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        # Test with invalid data to trigger errors
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            # Test with malformed JSON
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers={**auth_headers, 'Content-Type': 'application/json'},
                data='{"invalid": json}',  # Malformed JSON
                parse_json=False
            )
            
            if self._has_verbose_errors(evidence):
                vulnerability = self.create_vulnerability(
                    title="Verbose Error Messages",
                    description="The API returns detailed error messages that may reveal sensitive "
                               "information about the system architecture or data structure.",
                    severity=VulnerabilitySeverity.LOW,
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Implement generic error messages and log detailed errors server-side only.",
                    cwe_id="CWE-209",
                    cvss_score=3.1
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _test_cors_config(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                              base_url: str) -> List[Vulnerability]:
        """Test CORS configuration."""
        vulnerabilities = []
        url = self.build_url(base_url, endpoint)
        
        # Test with OPTIONS request
        evidence = await self.make_request(
            method='OPTIONS',
            url=url,
            headers={**auth_headers, 'Origin': 'https://evil.com'}
        )
        
        if self._has_permissive_cors(evidence):
            vulnerability = self.create_vulnerability(
                title="Permissive CORS Configuration",
                description="The API has overly permissive CORS settings that may allow unauthorized "
                           "cross-origin requests from malicious websites.",
                severity=VulnerabilitySeverity.MEDIUM,
                endpoint=endpoint,
                evidence=[evidence],
                remediation="Configure CORS to only allow trusted origins and required methods.",
                cwe_id="CWE-346",
                cvss_score=4.3
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_security_headers(self, evidence: VulnerabilityEvidence) -> List[str]:
        """Check for missing security headers."""
        if not evidence.response_headers:
            return []
        
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=',
            'Content-Security-Policy': '',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        missing = []
        headers_lower = {k.lower(): v for k, v in evidence.response_headers.items()}
        
        for header, expected in required_headers.items():
            if header.lower() not in headers_lower:
                missing.append(header)
        
        return missing
    
    def _has_verbose_errors(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if error messages are too verbose."""
        if not evidence.response_body:
            return False
        
        body_lower = evidence.response_body.lower()
        verbose_indicators = [
            'stack trace', 'stacktrace', 'exception', 'traceback',
            'file not found', 'permission denied', 'database error',
            'sql error', 'syntax error', 'parse error', 'connection failed'
        ]
        
        return any(indicator in body_lower for indicator in verbose_indicators)
    
    def _has_permissive_cors(self, evidence: VulnerabilityEvidence) -> bool:
        """Check for overly permissive CORS."""
        if not evidence.response_headers:
            return False
        
        headers_lower = {k.lower(): v.lower() for k, v in evidence.response_headers.items()}
        
        # Check for wildcard CORS
        cors_origin = headers_lower.get('access-control-allow-origin', '')
        if cors_origin == '*':
            return True
        
        # Check if evil origin is allowed
        if 'evil.com' in cors_origin:
            return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for security misconfiguration."""
        test_cases = []
        
        test_cases.append({
            'name': f"security_headers_{endpoint.method}_{endpoint.path}",
            'test_type': 'security_headers',
            'payload_count': 1
        })
        
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            test_cases.append({
                'name': f"error_handling_{endpoint.method}_{endpoint.path}",
                'test_type': 'error_handling',
                'payload_count': 1
            })
        
        test_cases.append({
            'name': f"cors_config_{endpoint.method}_{endpoint.path}",
            'test_type': 'cors_config',
            'payload_count': 1
        })
        
        return test_cases
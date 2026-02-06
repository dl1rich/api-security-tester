"""Role-based authorization testing detector."""

import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode

from testing.detector_base import BaseDetector
from testing.models import (
    Vulnerability, VulnerabilityEvidence, VulnerabilitySeverity, 
    VulnerabilityCategory, TestPriority
)
from parser.models import APISpecification, APIEndpoint
from auth.handler import AuthenticationHandler, RoleBasedTestCase


class RoleBasedAuthorizationDetector(BaseDetector):
    """Comprehensive role-based authorization testing detector."""
    
    def __init__(self):
        super().__init__(
            name="role_based_authorization",
            category=VulnerabilityCategory.API5_FUNCTION_AUTH,
            priority=TestPriority.HIGH
        )
        self.description = "Tests role-based authorization controls using detected user roles"
        self.auth_handler = AuthenticationHandler()
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List[Vulnerability]:
        """Detect role-based authorization vulnerabilities."""
        vulnerabilities = []
        
        # Get authentication configuration for this spec
        auth_config = self.auth_handler.get_auth_config(spec.id)
        if not auth_config or not auth_config.get('test_scenarios'):
            return vulnerabilities
        
        # Generate comprehensive role-based tests
        test_cases = self.auth_handler.generate_comprehensive_role_tests(spec)
        
        # Filter test cases for this specific endpoint
        endpoint_tests = [tc for tc in test_cases if tc.endpoint.path == endpoint.path and tc.endpoint.method == endpoint.method]
        
        for test_case in endpoint_tests:
            vulnerability = await self._execute_role_test(test_case, base_url, auth_config)
            if vulnerability:
                vulnerabilities.append(vulnerability)
        
        # Also run basic cross-role tests
        basic_vulns = await self._run_basic_cross_role_tests(endpoint, spec, base_url, auth_config)
        vulnerabilities.extend(basic_vulns)
        
        return vulnerabilities
    
    async def _execute_role_test(self, test_case: RoleBasedTestCase, base_url: str,
                               auth_config: Dict[str, Any]) -> Optional[Vulnerability]:
        """Execute a specific role-based test case."""
        
        # Get credentials for the source role
        role_credentials = auth_config.get('role_credentials', {})
        source_creds = role_credentials.get(test_case.source_role)
        
        if not source_creds:
            return None
        
        # Build the test URL
        url = self.build_url(base_url, test_case.endpoint)
        
        # Prepare auth headers
        auth_headers = self._build_auth_headers(source_creds)
        
        # Make the request
        evidence = await self.make_request(
            method=test_case.endpoint.method,
            url=url,
            headers=auth_headers
        )
        
        # Analyze the result based on test type and expected outcome
        is_vulnerable = self._analyze_role_test_result(test_case, evidence)
        
        if is_vulnerable:
            return self._create_role_based_vulnerability(test_case, evidence)
        
        return None
    
    async def _run_basic_cross_role_tests(self, endpoint: APIEndpoint, spec: APISpecification,
                                        base_url: str, auth_config: Dict[str, Any]) -> List[Vulnerability]:
        """Run basic cross-role access tests."""
        vulnerabilities = []
        test_scenarios = auth_config.get('test_scenarios', [])
        
        if len(test_scenarios) < 2:
            return vulnerabilities
        
        url = self.build_url(base_url, endpoint)
        endpoint_str = f"{endpoint.method} {endpoint.path}"
        
        # Test each role against endpoints they shouldn't access
        for scenario in test_scenarios:
            role_name = scenario['role']
            accessible_endpoints = set(scenario['accessible_endpoints'])
            role_credentials = auth_config.get('role_credentials', {}).get(role_name)
            
            if not role_credentials:
                continue
            
            # If this endpoint is not in the role's accessible list, test for unauthorized access
            if endpoint_str not in accessible_endpoints:
                auth_headers = self._build_auth_headers(role_credentials)
                
                evidence = await self.make_request(
                    method=endpoint.method,
                    url=url,
                    headers=auth_headers
                )
                
                # Check if unauthorized access was granted
                if self._is_unauthorized_access_granted(evidence):
                    vulnerability = self.create_vulnerability(
                        title=f"Unauthorized Access by Role '{role_name}'",
                        description=f"The role '{role_name}' was able to access endpoint {endpoint.path} "
                                   f"which should be restricted based on the detected role permissions.",
                        severity=VulnerabilitySeverity.HIGH,
                        endpoint=endpoint,
                        evidence=[evidence],
                        remediation="Implement proper role-based access controls to ensure users can only "
                                  "access endpoints appropriate for their assigned roles.",
                        cwe_id="CWE-285",
                        cvss_score=7.5
                    )
                    vulnerability.proof_of_concept = f"Role: {role_name}\nEndpoint: {endpoint_str}\nUnauthorized access granted"
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _build_auth_headers(self, credentials: Dict[str, Any]) -> Dict[str, str]:
        """Build authentication headers from role credentials."""
        headers = {}
        
        if not credentials:
            return headers
        
        # Handle different auth types
        auth_type = credentials.get('type', '').lower()
        
        if auth_type == 'bearer' or auth_type == 'jwt':
            token = credentials.get('token')
            if token:
                headers['Authorization'] = f"Bearer {token}"
        
        elif auth_type == 'api_key':
            key = credentials.get('key')
            header_name = credentials.get('header_name', 'X-API-Key')
            if key:
                headers[header_name] = key
        
        elif auth_type == 'basic':
            username = credentials.get('username')
            password = credentials.get('password')
            if username and password:
                import base64
                auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers['Authorization'] = f"Basic {auth_string}"
        
        elif auth_type == 'oauth2':
            access_token = credentials.get('access_token')
            if access_token:
                headers['Authorization'] = f"Bearer {access_token}"
        
        # Add any custom headers
        custom_headers = credentials.get('custom_headers', {})
        headers.update(custom_headers)
        
        return headers
    
    def _analyze_role_test_result(self, test_case: RoleBasedTestCase, 
                                evidence: VulnerabilityEvidence) -> bool:
        """Analyze the result of a role-based test."""
        
        if not evidence.response_status:
            return False
        
        status = evidence.response_status
        test_type = test_case.test_type
        expected = test_case.expected_outcome
        
        if test_type == "horizontal_escalation":
            # Should be forbidden (403) or not found (404)
            return status not in [401, 403, 404] and 200 <= status < 300
        
        elif test_type == "vertical_escalation":
            # Lower privilege accessing higher privilege should be denied
            return status not in [401, 403] and 200 <= status < 300
        
        elif test_type == "boundary_test":
            # Role accessing outside boundary should be denied
            return status not in [401, 403, 404] and 200 <= status < 300
        
        elif test_type == "permission_inheritance":
            if expected == "allowed":
                # Should succeed
                return not (200 <= status < 300)
            else:
                # Should be denied
                return status not in [401, 403] and 200 <= status < 300
        
        elif test_type == "context_based":
            if expected == "context_dependent":
                # Success might be valid depending on context
                # Check for context validation in response
                if status == 200 and evidence.response_body:
                    # Look for signs of proper context validation
                    body_lower = evidence.response_body.lower()
                    context_indicators = ['user_id', 'owner', 'belongs_to', 'authorized_for']
                    return not any(indicator in body_lower for indicator in context_indicators)
        
        return False
    
    def _is_unauthorized_access_granted(self, evidence: VulnerabilityEvidence) -> bool:
        """Check if unauthorized access was granted."""
        if not evidence.response_status:
            return False
        
        status = evidence.response_status
        
        # If we got a successful response when we should have been denied
        if 200 <= status < 300:
            return True
        
        # Some applications return 200 with error messages in body
        if status == 200 and evidence.response_body:
            error_indicators = ['unauthorized', 'forbidden', 'access denied', 'permission denied']
            body_lower = evidence.response_body.lower()
            return not any(indicator in body_lower for indicator in error_indicators)
        
        return False
    
    def _create_role_based_vulnerability(self, test_case: RoleBasedTestCase,
                                       evidence: VulnerabilityEvidence) -> Vulnerability:
        """Create a vulnerability from a role-based test result."""
        
        severity_map = {
            "horizontal_escalation": VulnerabilitySeverity.HIGH,
            "vertical_escalation": VulnerabilitySeverity.CRITICAL,
            "boundary_test": VulnerabilitySeverity.MEDIUM,
            "permission_inheritance": VulnerabilitySeverity.MEDIUM,
            "context_based": VulnerabilitySeverity.HIGH
        }
        
        severity = severity_map.get(test_case.test_type, VulnerabilitySeverity.MEDIUM)
        
        vulnerability = self.create_vulnerability(
            title=f"Role-Based Authorization Bypass - {test_case.test_type}",
            description=f"{test_case.description}. The system failed to properly enforce "
                       f"role-based access controls, allowing unauthorized access.",
            severity=severity,
            endpoint=test_case.endpoint,
            evidence=[evidence],
            remediation="Implement proper role-based access control checks for all endpoints. "
                      "Ensure that authorization checks validate both the user's identity and their role permissions.",
            cwe_id="CWE-285",
            cvss_score=8.5 if severity == VulnerabilitySeverity.CRITICAL else 7.1
        )
        
        vulnerability.proof_of_concept = (
            f"Test Type: {test_case.test_type}\n"
            f"Source Role: {test_case.source_role}\n"
            f"Target Role: {test_case.target_role}\n"
            f"Endpoint: {test_case.endpoint.method} {test_case.endpoint.path}\n"
            f"Expected: {test_case.expected_outcome}\n"
            f"Actual Response: {evidence.response_status}"
        )
        
        return vulnerability
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for role-based authorization detection."""
        test_cases = []
        
        # Check if we have role-based auth config
        auth_config = self.auth_handler.get_auth_config(spec.id)
        if not auth_config or not auth_config.get('test_scenarios'):
            return test_cases
        
        scenarios = auth_config['test_scenarios']
        endpoint_str = f"{endpoint.method} {endpoint.path}"
        
        # Count role-based tests for this endpoint
        role_tests = 0
        for scenario in scenarios:
            if endpoint_str in scenario.get('accessible_endpoints', []):
                role_tests += 1
            else:
                role_tests += 1  # Unauthorized access test
        
        if role_tests > 0:
            test_cases.append({
                'name': f"role_auth_{endpoint.method}_{endpoint.path}",
                'test_type': 'role_based_authorization',
                'payload_count': role_tests
            })
        
        return test_cases
"""Authentication handling and role management for testing."""

import logging
from typing import Dict, List, Optional, Any, Set
from copy import deepcopy
import itertools

from .analyzer import AuthenticationAnalyzer, AuthenticationScheme, UserRole
from parser.models import APISpecification, APIEndpoint

logger = logging.getLogger(__name__)


class RoleBasedTestCase:
    """Represents a role-based test case."""
    
    def __init__(self, name: str, description: str, source_role: str, 
                 target_role: str, test_type: str, endpoint: APIEndpoint,
                 expected_outcome: str):
        self.name = name
        self.description = description
        self.source_role = source_role
        self.target_role = target_role
        self.test_type = test_type
        self.endpoint = endpoint
        self.expected_outcome = expected_outcome
        self.auth_headers = {}


class AuthenticationHandler:
    """Handles authentication modification and role-based testing."""
    
    def __init__(self):
        self.analyzer = AuthenticationAnalyzer()
        self._auth_configs: Dict[str, Dict] = {}
    
    def process_authentication(self, spec: APISpecification, 
                             auth_handling: str = "preserve_roles",
                             custom_roles: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process authentication schemes for testing."""
        
        # Analyze authentication schemes
        analyzed_schemes = self.analyzer.analyze_authentication(spec)
        
        # Process based on handling strategy
        if auth_handling == "preserve_roles":
            config = self._preserve_roles_strategy(spec, analyzed_schemes)
        elif auth_handling == "bypass_all":
            config = self._bypass_all_strategy(spec, analyzed_schemes)
        elif auth_handling == "custom":
            config = self._custom_roles_strategy(spec, analyzed_schemes, custom_roles)
        else:
            raise ValueError(f"Unknown auth handling strategy: {auth_handling}")
        
        # Store configuration
        self._auth_configs[spec.id] = config
        
        logger.info(f"Processed authentication for spec {spec.id} with strategy: {auth_handling}")
        return config
    
    def _preserve_roles_strategy(self, spec: APISpecification, 
                               analyzed_schemes: Dict[str, AuthenticationScheme]) -> Dict[str, Any]:
        """Preserve existing roles while enabling testing."""
        
        config = {
            'strategy': 'preserve_roles',
            'test_scenarios': [],
            'role_credentials': {},
            'bypass_tests': [],
            'escalation_tests': []
        }
        
        for scheme_name, auth_scheme in analyzed_schemes.items():
            # Create test scenarios for each role
            if auth_scheme.role_based and auth_scheme.detected_roles:
                for role in auth_scheme.detected_roles:
                    scenario = {
                        'name': f"{scheme_name}_{role.name}",
                        'scheme': scheme_name,
                        'role': role.name,
                        'credentials': auth_scheme.test_credentials.get(role.name),
                        'accessible_endpoints': list(role.endpoints),
                        'permissions': list(role.permissions),
                        'privilege_level': role.level
                    }
                    config['test_scenarios'].append(scenario)
                    
                    if role.name not in config['role_credentials']:
                        config['role_credentials'][role.name] = auth_scheme.test_credentials.get(role.name)
                
                # Add escalation tests
                escalation_tests = self.analyzer.get_role_escalation_tests(auth_scheme.detected_roles)
                config['escalation_tests'].extend(escalation_tests)
            
            else:
                # Non-role-based auth - create single scenario
                scenario = {
                    'name': f"{scheme_name}_authenticated",
                    'scheme': scheme_name,
                    'role': 'authenticated_user',
                    'credentials': next(iter(auth_scheme.test_credentials.values())) if auth_scheme.test_credentials else None,
                    'accessible_endpoints': [f"{ep.method} {ep.path}" for ep in spec.endpoints],
                    'permissions': ['authenticated'],
                    'privilege_level': 1
                }
                config['test_scenarios'].append(scenario)
            
            # Add bypass tests
            for bypass_method in auth_scheme.bypass_methods:
                bypass_test = {
                    'scheme': scheme_name,
                    'method': bypass_method,
                    'description': f"Test {bypass_method} bypass for {scheme_name}"
                }
                config['bypass_tests'].append(bypass_test)
        
        return config
    
    def _bypass_all_strategy(self, spec: APISpecification,
                           analyzed_schemes: Dict[str, AuthenticationScheme]) -> Dict[str, Any]:
        """Bypass all authentication for unrestricted testing."""
        
        config = {
            'strategy': 'bypass_all',
            'test_scenarios': [{
                'name': 'unauthenticated_access',
                'scheme': None,
                'role': 'anonymous',
                'credentials': None,
                'accessible_endpoints': [f"{ep.method} {ep.path}" for ep in spec.endpoints],
                'permissions': ['none'],
                'privilege_level': 0
            }],
            'role_credentials': {},
            'bypass_tests': [],
            'escalation_tests': []
        }
        
        # Still add bypass tests to verify they work
        for scheme_name, auth_scheme in analyzed_schemes.items():
            for bypass_method in auth_scheme.bypass_methods:
                bypass_test = {
                    'scheme': scheme_name,
                    'method': bypass_method,
                    'description': f"Test {bypass_method} bypass for {scheme_name}"
                }
                config['bypass_tests'].append(bypass_test)
        
        return config
    
    def _custom_roles_strategy(self, spec: APISpecification,
                             analyzed_schemes: Dict[str, AuthenticationScheme],
                             custom_roles: Optional[List[str]]) -> Dict[str, Any]:
        """Use custom-defined roles for testing."""
        
        if not custom_roles:
            # Fall back to preserve roles if no custom roles provided
            return self._preserve_roles_strategy(spec, analyzed_schemes)
        
        config = {
            'strategy': 'custom',
            'test_scenarios': [],
            'role_credentials': {},
            'bypass_tests': [],
            'escalation_tests': []
        }
        
        for scheme_name, auth_scheme in analyzed_schemes.items():
            # Create scenarios for custom roles
            for i, role_name in enumerate(custom_roles):
                # Generate test credentials for custom role
                if auth_scheme.test_credentials:
                    # Use existing credential generation method but with custom role name
                    sample_cred = next(iter(auth_scheme.test_credentials.values()))
                    custom_cred = sample_cred.replace(
                        sample_cred.split('_')[1], 
                        role_name
                    ) if '_' in sample_cred else f"test_{role_name}_token"
                else:
                    custom_cred = f"test_{role_name}_token"
                
                scenario = {
                    'name': f"{scheme_name}_{role_name}",
                    'scheme': scheme_name,
                    'role': role_name,
                    'credentials': custom_cred,
                    'accessible_endpoints': [f"{ep.method} {ep.path}" for ep in spec.endpoints],
                    'permissions': [role_name],
                    'privilege_level': i  # Assign ascending privilege levels
                }
                config['test_scenarios'].append(scenario)
                config['role_credentials'][role_name] = custom_cred
            
            # Add bypass tests
            for bypass_method in auth_scheme.bypass_methods:
                bypass_test = {
                    'scheme': scheme_name,
                    'method': bypass_method,
                    'description': f"Test {bypass_method} bypass for {scheme_name}"
                }
                config['bypass_tests'].append(bypass_test)
        
        return config
    
    def get_test_headers(self, spec_id: str, role: str) -> Dict[str, str]:
        """Get test headers for a specific role."""
        config = self._auth_configs.get(spec_id)
        if not config:
            return {}
        
        headers = {}
        credentials = config['role_credentials'].get(role)
        
        if credentials:
            if credentials.startswith('Bearer '):
                headers['Authorization'] = credentials
            elif credentials.startswith('Basic '):
                headers['Authorization'] = credentials
            elif 'apikey' in credentials.lower():
                headers['X-API-Key'] = credentials
            else:
                headers['Authorization'] = credentials
        
        return headers
    
    def get_bypass_test_variations(self, spec_id: str, original_headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Get header variations for bypass testing."""
        config = self._auth_configs.get(spec_id)
        if not config:
            return []
        
        variations = []
        
        # Test with no auth headers
        variations.append({
            'name': 'no_auth',
            'headers': {},
            'description': 'No authentication headers'
        })
        
        # Test with empty auth header
        if 'Authorization' in original_headers:
            variations.append({
                'name': 'empty_auth',
                'headers': {**original_headers, 'Authorization': ''},
                'description': 'Empty authorization header'
            })
            
            # Test with malformed auth header
            variations.append({
                'name': 'malformed_auth',
                'headers': {**original_headers, 'Authorization': 'Malformed Token'},
                'description': 'Malformed authorization header'
            })
            
            # Test with wrong case
            auth_value = original_headers['Authorization']
            variations.append({
                'name': 'case_auth',
                'headers': {**{k: v for k, v in original_headers.items() if k != 'Authorization'}, 
                          'authorization': auth_value},
                'description': 'Case-sensitive header test'
            })
        
        # Test with API key variations
        if 'X-API-Key' in original_headers:
            variations.append({
                'name': 'empty_api_key',
                'headers': {**original_headers, 'X-API-Key': ''},
                'description': 'Empty API key'
            })
            
            # Test in different locations
            api_key = original_headers['X-API-Key']
            variations.append({
                'name': 'query_api_key',
                'headers': {k: v for k, v in original_headers.items() if k != 'X-API-Key'},
                'query_params': {'api_key': api_key},
                'description': 'API key in query parameter'
            })
        
        return variations
    
    def generate_role_matrix_tests(self, spec_id: str) -> List[Dict[str, Any]]:
        """Generate a test matrix for all role combinations."""
        config = self._auth_configs.get(spec_id)
        if not config:
            return []
        
        test_matrix = []
        scenarios = config['test_scenarios']
        
        for scenario in scenarios:
            for endpoint in scenario['accessible_endpoints']:
                test_case = {
                    'role': scenario['role'],
                    'endpoint': endpoint,
                    'expected_access': True,  # Should have access
                    'credentials': scenario['credentials'],
                    'test_type': 'authorized_access'
                }
                test_matrix.append(test_case)
        
        # Add unauthorized access tests
        for scenario in scenarios:
            # Test accessing endpoints that should be restricted
            all_endpoints = set()
            for other_scenario in scenarios:
                all_endpoints.update(other_scenario['accessible_endpoints'])
            
            restricted_endpoints = all_endpoints - set(scenario['accessible_endpoints'])
            
            for endpoint in restricted_endpoints:
                test_case = {
                    'role': scenario['role'], 
                    'endpoint': endpoint,
                    'expected_access': False,  # Should NOT have access
                    'credentials': scenario['credentials'],
                    'test_type': 'unauthorized_access'
                }
                test_matrix.append(test_case)
        
        return test_matrix
    
    def get_auth_config(self, spec_id: str) -> Optional[Dict[str, Any]]:
        """Get authentication configuration for a specification."""
        return self._auth_configs.get(spec_id)
    
    def generate_comprehensive_role_tests(self, spec: APISpecification) -> List[RoleBasedTestCase]:
        """Generate comprehensive role-based test cases."""
        test_cases = []
        config = self._auth_configs.get(spec.id)
        
        if not config or not config.get('test_scenarios'):
            return test_cases
        
        scenarios = config['test_scenarios']
        
        # 1. Horizontal Privilege Escalation Tests
        test_cases.extend(self._generate_horizontal_escalation_tests(spec, scenarios))
        
        # 2. Vertical Privilege Escalation Tests
        test_cases.extend(self._generate_vertical_escalation_tests(spec, scenarios))
        
        # 3. Role Boundary Tests
        test_cases.extend(self._generate_role_boundary_tests(spec, scenarios))
        
        # 4. Permission Inheritance Tests
        test_cases.extend(self._generate_permission_inheritance_tests(spec, scenarios))
        
        # 5. Context-Based Access Tests
        test_cases.extend(self._generate_context_based_tests(spec, scenarios))
        
        return test_cases
    
    def _generate_horizontal_escalation_tests(self, spec: APISpecification, 
                                            scenarios: List[Dict]) -> List[RoleBasedTestCase]:
        """Generate horizontal privilege escalation tests."""
        test_cases = []
        
        # Find scenarios at the same privilege level
        same_level_groups = {}
        for scenario in scenarios:
            level = scenario.get('privilege_level', 1)
            if level not in same_level_groups:
                same_level_groups[level] = []
            same_level_groups[level].append(scenario)
        
        for level, group in same_level_groups.items():
            if len(group) < 2:
                continue
                
            # Test cross-role access at the same privilege level
            for i, source_scenario in enumerate(group):
                for j, target_scenario in enumerate(group):
                    if i == j:
                        continue
                    
                    # Try to access target role's specific endpoints with source role's credentials
                    source_endpoints = set(source_scenario['accessible_endpoints'])
                    target_endpoints = set(target_scenario['accessible_endpoints'])
                    target_only = target_endpoints - source_endpoints
                    
                    for endpoint_str in target_only:
                        method, path = endpoint_str.split(' ', 1)
                        endpoint = self._find_endpoint(spec, method, path)
                        if endpoint:
                            test_case = RoleBasedTestCase(
                                name=f"horizontal_escalation_{source_scenario['role']}_to_{target_scenario['role']}_{endpoint.operation_id or path}",
                                description=f"Test if {source_scenario['role']} can access {target_scenario['role']}'s endpoint {path}",
                                source_role=source_scenario['role'],
                                target_role=target_scenario['role'],
                                test_type="horizontal_escalation",
                                endpoint=endpoint,
                                expected_outcome="forbidden"
                            )
                            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_vertical_escalation_tests(self, spec: APISpecification,
                                          scenarios: List[Dict]) -> List[RoleBasedTestCase]:
        """Generate vertical privilege escalation tests."""
        test_cases = []
        
        # Sort scenarios by privilege level
        sorted_scenarios = sorted(scenarios, key=lambda x: x.get('privilege_level', 1))
        
        for i, lower_scenario in enumerate(sorted_scenarios):
            for higher_scenario in sorted_scenarios[i+1:]:
                if lower_scenario['privilege_level'] >= higher_scenario['privilege_level']:
                    continue
                
                # Lower privilege role trying to access higher privilege endpoints
                lower_endpoints = set(lower_scenario['accessible_endpoints'])
                higher_endpoints = set(higher_scenario['accessible_endpoints'])
                privileged_only = higher_endpoints - lower_endpoints
                
                for endpoint_str in privileged_only:
                    method, path = endpoint_str.split(' ', 1)
                    endpoint = self._find_endpoint(spec, method, path)
                    if endpoint:
                        test_case = RoleBasedTestCase(
                            name=f"vertical_escalation_{lower_scenario['role']}_to_{higher_scenario['role']}_{endpoint.operation_id or path}",
                            description=f"Test if {lower_scenario['role']} can elevate to access {higher_scenario['role']}'s privileged endpoint {path}",
                            source_role=lower_scenario['role'],
                            target_role=higher_scenario['role'],
                            test_type="vertical_escalation",
                            endpoint=endpoint,
                            expected_outcome="forbidden"
                        )
                        test_cases.append(test_case)
        
        return test_cases
    
    def _generate_role_boundary_tests(self, spec: APISpecification,
                                    scenarios: List[Dict]) -> List[RoleBasedTestCase]:
        """Generate role boundary tests."""
        test_cases = []
        
        for scenario in scenarios:
            accessible_endpoints = set(scenario['accessible_endpoints'])
            all_endpoints = {f"{ep.method} {ep.path}" for ep in spec.endpoints}
            restricted_endpoints = all_endpoints - accessible_endpoints
            
            # Test accessing restricted endpoints
            for endpoint_str in list(restricted_endpoints)[:10]:  # Limit to first 10 for performance
                method, path = endpoint_str.split(' ', 1)
                endpoint = self._find_endpoint(spec, method, path)
                if endpoint:
                    test_case = RoleBasedTestCase(
                        name=f"boundary_test_{scenario['role']}_{endpoint.operation_id or path.replace('/', '_')}",
                        description=f"Test role boundary: {scenario['role']} accessing restricted endpoint {path}",
                        source_role=scenario['role'],
                        target_role="system",
                        test_type="boundary_test",
                        endpoint=endpoint,
                        expected_outcome="forbidden"
                    )
                    test_cases.append(test_case)
        
        return test_cases
    
    def _generate_permission_inheritance_tests(self, spec: APISpecification,
                                             scenarios: List[Dict]) -> List[RoleBasedTestCase]:
        """Generate permission inheritance tests."""
        test_cases = []
        
        # Group by permission patterns
        permission_groups = {}
        for scenario in scenarios:
            permissions = scenario.get('permissions', [])
            for permission in permissions:
                if permission not in permission_groups:
                    permission_groups[permission] = []
                permission_groups[permission].append(scenario)
        
        # Test if permissions are properly inherited/isolated
        for permission, scenarios_with_permission in permission_groups.items():
            if len(scenarios_with_permission) < 2:
                continue
            
            # Find endpoints that should be accessible by this permission
            common_endpoints = None
            for scenario in scenarios_with_permission:
                scenario_endpoints = set(scenario['accessible_endpoints'])
                if common_endpoints is None:
                    common_endpoints = scenario_endpoints
                else:
                    common_endpoints = common_endpoints.intersection(scenario_endpoints)
            
            if common_endpoints:
                for endpoint_str in list(common_endpoints)[:5]:  # Test first 5 common endpoints
                    method, path = endpoint_str.split(' ', 1)
                    endpoint = self._find_endpoint(spec, method, path)
                    if endpoint:
                        for scenario in scenarios_with_permission:
                            test_case = RoleBasedTestCase(
                                name=f"permission_inheritance_{permission}_{scenario['role']}_{endpoint.operation_id or path.replace('/', '_')}",
                                description=f"Test permission inheritance: {scenario['role']} accessing {permission} endpoint {path}",
                                source_role=scenario['role'],
                                target_role="permission_group",
                                test_type="permission_inheritance",
                                endpoint=endpoint,
                                expected_outcome="allowed"
                            )
                            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_context_based_tests(self, spec: APISpecification,
                                    scenarios: List[Dict]) -> List[RoleBasedTestCase]:
        """Generate context-based access control tests."""
        test_cases = []
        
        # Look for endpoints that might be context-sensitive (user-specific)
        context_sensitive_patterns = [
            r'/users/{[^}]+}',
            r'/profiles/{[^}]+}', 
            r'/accounts/{[^}]+}',
            r'/orders/{[^}]+}',
            r'/documents/{[^}]+}'
        ]
        
        for scenario in scenarios:
            for endpoint in spec.endpoints:
                path = endpoint.path
                
                # Check if endpoint is context-sensitive
                is_context_sensitive = any(
                    self._matches_pattern(path, pattern) for pattern in context_sensitive_patterns
                )
                
                if is_context_sensitive and f"{endpoint.method} {path}" in scenario['accessible_endpoints']:
                    test_case = RoleBasedTestCase(
                        name=f"context_test_{scenario['role']}_{endpoint.operation_id or path.replace('/', '_')}",
                        description=f"Test context-based access: {scenario['role']} accessing own vs others' resources at {path}",
                        source_role=scenario['role'],
                        target_role="resource_owner",
                        test_type="context_based",
                        endpoint=endpoint,
                        expected_outcome="context_dependent"
                    )
                    test_cases.append(test_case)
        
        return test_cases
    
    def _find_endpoint(self, spec: APISpecification, method: str, path: str) -> Optional[APIEndpoint]:
        """Find an endpoint by method and path."""
        for endpoint in spec.endpoints:
            if endpoint.method.upper() == method.upper() and endpoint.path == path:
                return endpoint
        return None
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches a pattern (simple regex-like matching)."""
        import re
        return bool(re.search(pattern, path))
    
    def generate_role_escalation_matrix(self, spec_id: str) -> Dict[str, List[Dict]]:
        """Generate a comprehensive role escalation test matrix."""
        config = self._auth_configs.get(spec_id)
        if not config:
            return {}
        
        matrix = {
            'horizontal_escalation': [],
            'vertical_escalation': [],
            'privilege_combinations': [],
            'role_bypasses': []
        }
        
        scenarios = config['test_scenarios']
        
        # Horizontal escalation matrix
        for source in scenarios:
            for target in scenarios:
                if source['role'] == target['role']:
                    continue
                if source.get('privilege_level') == target.get('privilege_level'):
                    matrix['horizontal_escalation'].append({
                        'source_role': source['role'],
                        'target_role': target['role'],
                        'privilege_level': source.get('privilege_level'),
                        'test_endpoints': list(set(target['accessible_endpoints']) - set(source['accessible_endpoints']))
                    })
        
        # Vertical escalation matrix
        sorted_scenarios = sorted(scenarios, key=lambda x: x.get('privilege_level', 1))
        for i, lower in enumerate(sorted_scenarios):
            for higher in sorted_scenarios[i+1:]:
                if lower['privilege_level'] < higher['privilege_level']:
                    matrix['vertical_escalation'].append({
                        'lower_role': lower['role'],
                        'higher_role': higher['role'],
                        'privilege_gap': higher['privilege_level'] - lower['privilege_level'],
                        'escalation_targets': list(set(higher['accessible_endpoints']) - set(lower['accessible_endpoints']))
                    })
        
        # Privilege combinations
        for combo_size in range(2, min(4, len(scenarios) + 1)):  # Test combinations of 2-3 roles
            for role_combo in itertools.combinations(scenarios, combo_size):
                combined_permissions = set()
                for role in role_combo:
                    combined_permissions.update(role.get('permissions', []))
                
                matrix['privilege_combinations'].append({
                    'roles': [r['role'] for r in role_combo],
                    'combined_permissions': list(combined_permissions),
                    'test_scenario': f"Test combined privileges of {', '.join(r['role'] for r in role_combo)}"
                })
        
        # Role bypass tests
        bypass_tests = config.get('bypass_tests', [])
        for bypass in bypass_tests:
            for scenario in scenarios:
                matrix['role_bypasses'].append({
                    'role': scenario['role'],
                    'bypass_method': bypass['method'],
                    'target_scheme': bypass['scheme'],
                    'description': f"Test {bypass['method']} bypass for {scenario['role']} on {bypass['scheme']}"
                })
        
        return matrix
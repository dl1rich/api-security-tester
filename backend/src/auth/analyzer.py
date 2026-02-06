"""Authentication analysis and role detection."""

import re
from jose import jwt
import base64
import json
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass

from parser.models import APISpecification, SecurityScheme

logger = logging.getLogger(__name__)


@dataclass
class UserRole:
    """Represents a detected user role."""
    name: str
    level: int  # 0=guest, 1=user, 2=staff, 3=admin, 4=super_admin
    permissions: Set[str]
    endpoints: Set[str]
    description: Optional[str] = None


@dataclass
class AuthenticationScheme:
    """Processed authentication scheme with testing context."""
    original_scheme: SecurityScheme
    auth_type: str  # jwt, api_key, basic, bearer, oauth2
    role_based: bool = False
    detected_roles: List[UserRole] = None
    test_credentials: Dict[str, str] = None
    bypass_methods: List[str] = None


class AuthenticationAnalyzer:
    """Analyzes API authentication and identifies roles for testing."""
    
    # Common role patterns found in API specifications
    ROLE_PATTERNS = [
        # Administrative roles
        (r'\b(super_?admin|root|sys_?admin|admin)', 'admin', 4),
        # Staff/moderator roles  
        (r'\b(staff|moderator|mod|manager|editor)', 'staff', 3),
        # Regular user roles
        (r'\b(user|member|customer|client)', 'user', 1),
        # Guest/public roles
        (r'\b(guest|public|anonymous|anon)', 'guest', 0),
        # Service roles
        (r'\b(service|bot|system|api)', 'service', 2),
        # Developer roles
        (r'\b(developer|dev|tester|qa)', 'developer', 3),
    ]
    
    def __init__(self):
        self._role_cache: Dict[str, List[UserRole]] = {}
    
    def analyze_authentication(self, spec: APISpecification) -> Dict[str, AuthenticationScheme]:
        """Analyze authentication schemes and detect roles."""
        analyzed_schemes = {}
        
        for scheme_name, security_scheme in spec.security_schemes.items():
            try:
                auth_scheme = self._analyze_security_scheme(spec, scheme_name, security_scheme)
                analyzed_schemes[scheme_name] = auth_scheme
                
                logger.info(f"Analyzed auth scheme '{scheme_name}': {auth_scheme.auth_type}, "
                          f"role-based: {auth_scheme.role_based}")
                
            except Exception as e:
                logger.error(f"Error analyzing auth scheme '{scheme_name}': {e}")
        
        return analyzed_schemes
    
    def _analyze_security_scheme(self, spec: APISpecification, scheme_name: str, 
                               security_scheme: SecurityScheme) -> AuthenticationScheme:
        """Analyze a single security scheme."""
        
        # Determine authentication type
        auth_type = self._determine_auth_type(security_scheme)
        
        # Detect if role-based
        role_based = self._is_role_based_auth(spec, scheme_name)
        
        # Detect roles if role-based
        detected_roles = []
        if role_based:
            detected_roles = self._detect_roles(spec, scheme_name)
        
        # Generate test credentials
        test_credentials = self._generate_test_credentials(security_scheme, detected_roles)
        
        # Identify bypass methods
        bypass_methods = self._identify_bypass_methods(security_scheme)
        
        return AuthenticationScheme(
            original_scheme=security_scheme,
            auth_type=auth_type,
            role_based=role_based,
            detected_roles=detected_roles,
            test_credentials=test_credentials,
            bypass_methods=bypass_methods
        )
    
    def _determine_auth_type(self, security_scheme: SecurityScheme) -> str:
        """Determine the type of authentication scheme."""
        scheme_type = security_scheme.type.lower()
        
        if scheme_type == 'http':
            if security_scheme.scheme and 'bearer' in security_scheme.scheme.lower():
                # Check if it's JWT
                if (security_scheme.bearer_format and 
                    'jwt' in security_scheme.bearer_format.lower()):
                    return 'jwt'
                return 'bearer'
            elif security_scheme.scheme and 'basic' in security_scheme.scheme.lower():
                return 'basic'
        elif scheme_type == 'apikey':
            return 'api_key'
        elif scheme_type == 'oauth2':
            return 'oauth2'
        elif scheme_type == 'openidconnect':
            return 'openid_connect'
        
        return scheme_type
    
    def _is_role_based_auth(self, spec: APISpecification, scheme_name: str) -> bool:
        """Determine if the authentication scheme supports roles."""
        
        # Check for role-based patterns in descriptions
        description_text = ""
        if spec.description:
            description_text += spec.description + " "
        if hasattr(spec, 'security_schemes') and scheme_name in spec.security_schemes:
            scheme = spec.security_schemes[scheme_name]
            if scheme.description:
                description_text += scheme.description + " "
        
        # Look for role indicators
        role_indicators = [
            'role', 'permission', 'scope', 'access', 'level',
            'admin', 'user', 'staff', 'moderator', 'guest'
        ]
        
        for indicator in role_indicators:
            if indicator in description_text.lower():
                return True
        
        # Check endpoint security requirements for role patterns
        for endpoint in spec.endpoints:
            for security_req in endpoint.security_requirements:
                if scheme_name in security_req:
                    scopes = security_req[scheme_name]
                    if scopes:  # OAuth2 scopes often indicate roles
                        return True
        
        # Check if endpoints have different security requirements (indicating roles)
        security_patterns = set()
        for endpoint in spec.endpoints:
            for security_req in endpoint.security_requirements:
                if scheme_name in security_req:
                    pattern = frozenset(security_req[scheme_name])
                    security_patterns.add(pattern)
        
        # If we have multiple different security patterns, likely role-based
        return len(security_patterns) > 1
    
    def _detect_roles(self, spec: APISpecification, scheme_name: str) -> List[UserRole]:
        """Detect user roles from the API specification."""
        
        if scheme_name in self._role_cache:
            return self._role_cache[scheme_name]
        
        detected_roles = []
        role_names = set()
        
        # Extract roles from OAuth2 scopes
        for endpoint in spec.endpoints:
            for security_req in endpoint.security_requirements:
                if scheme_name in security_req:
                    scopes = security_req[scheme_name]
                    for scope in scopes:
                        role_names.add(scope)
        
        # Extract roles from descriptions and documentation
        text_sources = [spec.description or ""]
        for endpoint in spec.endpoints:
            if endpoint.description:
                text_sources.append(endpoint.description)
            if endpoint.summary:
                text_sources.append(endpoint.summary)
        
        for text in text_sources:
            for pattern, role_type, level in self.ROLE_PATTERNS:
                matches = re.findall(pattern, text.lower())
                for match in matches:
                    role_names.add(match)
        
        # Create UserRole objects
        for role_name in role_names:
            role_level = self._determine_role_level(role_name)
            permissions = self._extract_permissions_for_role(spec, role_name, scheme_name)
            endpoints = self._get_endpoints_for_role(spec, role_name, scheme_name)
            
            detected_roles.append(UserRole(
                name=role_name,
                level=role_level,
                permissions=permissions,
                endpoints=endpoints,
                description=f"Auto-detected role: {role_name}"
            ))
        
        # If no specific roles detected, create default roles
        if not detected_roles:
            detected_roles = self._create_default_roles(spec, scheme_name)
        
        # Sort roles by level (lowest to highest privilege)
        detected_roles.sort(key=lambda x: x.level)
        
        self._role_cache[scheme_name] = detected_roles
        return detected_roles
    
    def _determine_role_level(self, role_name: str) -> int:
        """Determine the privilege level of a role."""
        role_name_lower = role_name.lower()
        
        for pattern, _, level in self.ROLE_PATTERNS:
            if re.search(pattern, role_name_lower):
                return level
        
        # Default to user level
        return 1
    
    def _extract_permissions_for_role(self, spec: APISpecification, role_name: str, 
                                   scheme_name: str) -> Set[str]:
        """Extract permissions associated with a role."""
        permissions = set()
        
        # Look for OAuth2 scopes that match this role
        for endpoint in spec.endpoints:
            for security_req in endpoint.security_requirements:
                if scheme_name in security_req:
                    scopes = security_req[scheme_name]
                    if role_name in scopes:
                        permissions.update(scopes)
        
        return permissions
    
    def _get_endpoints_for_role(self, spec: APISpecification, role_name: str, 
                              scheme_name: str) -> Set[str]:
        """Get endpoints accessible to a specific role."""
        accessible_endpoints = set()
        
        for endpoint in spec.endpoints:
            # Check if this endpoint requires the role
            for security_req in endpoint.security_requirements:
                if scheme_name in security_req:
                    scopes = security_req[scheme_name]
                    if not scopes or role_name in scopes:
                        accessible_endpoints.add(f"{endpoint.method} {endpoint.path}")
        
        return accessible_endpoints
    
    def _create_default_roles(self, spec: APISpecification, scheme_name: str) -> List[UserRole]:
        """Create default roles when none are detected."""
        default_roles = []
        
        # Check if there are any protected endpoints
        has_protected_endpoints = any(
            endpoint.security_requirements for endpoint in spec.endpoints
        )
        
        if has_protected_endpoints:
            # Create basic user and admin roles
            all_endpoints = {f"{ep.method} {ep.path}" for ep in spec.endpoints}
            
            default_roles = [
                UserRole(
                    name="user",
                    level=1,
                    permissions={"read"},
                    endpoints=all_endpoints,
                    description="Default user role"
                ),
                UserRole(
                    name="admin", 
                    level=4,
                    permissions={"read", "write", "delete", "admin"},
                    endpoints=all_endpoints,
                    description="Default admin role"
                )
            ]
        
        return default_roles
    
    def _generate_test_credentials(self, security_scheme: SecurityScheme, 
                                 roles: List[UserRole]) -> Dict[str, str]:
        """Generate test credentials for each role."""
        test_credentials = {}
        
        auth_type = self._determine_auth_type(security_scheme)
        
        for role in roles:
            if auth_type == 'jwt':
                # Generate mock JWT token
                payload = {
                    "sub": f"test_{role.name}",
                    "role": role.name,
                    "permissions": list(role.permissions),
                    "iat": 1640995200,  # Fixed timestamp for testing
                    "exp": 1640995200 + 3600  # 1 hour expiry
                }
                # Use a test key (in real implementation, use proper secret)
                token = jwt.encode(payload, "test_secret", algorithm="HS256")
                test_credentials[role.name] = f"Bearer {token}"
                
            elif auth_type == 'bearer':
                # Generate mock bearer token
                test_credentials[role.name] = f"Bearer test_{role.name}_token_12345"
                
            elif auth_type == 'api_key':
                # Generate mock API key
                test_credentials[role.name] = f"test_{role.name}_apikey_67890"
                
            elif auth_type == 'basic':
                # Generate mock basic auth
                credentials = f"test_{role.name}:password123"
                encoded = base64.b64encode(credentials.encode()).decode()
                test_credentials[role.name] = f"Basic {encoded}"
                
            else:
                # Generic token
                test_credentials[role.name] = f"test_{role.name}_token"
        
        return test_credentials
    
    def _identify_bypass_methods(self, security_scheme: SecurityScheme) -> List[str]:
        """Identify potential authentication bypass methods."""
        bypass_methods = []
        
        auth_type = self._determine_auth_type(security_scheme)
        
        # Common bypass techniques based on auth type
        if auth_type == 'jwt':
            bypass_methods.extend([
                'none_algorithm',
                'weak_secret',
                'key_confusion',
                'expired_token',
                'malformed_token'
            ])
        elif auth_type == 'bearer':
            bypass_methods.extend([
                'empty_token',
                'malformed_bearer',
                'case_sensitivity',
                'token_reuse'
            ])
        elif auth_type == 'api_key':
            bypass_methods.extend([
                'missing_key',
                'empty_key', 
                'wrong_location',
                'case_sensitivity'
            ])
        elif auth_type == 'basic':
            bypass_methods.extend([
                'empty_credentials',
                'malformed_basic',
                'sql_injection',
                'weak_password'
            ])
        
        # Universal bypass methods
        bypass_methods.extend([
            'http_verb_tampering',
            'parameter_pollution',
            'header_injection',
            'path_traversal'
        ])
        
        return bypass_methods
    
    def get_role_escalation_tests(self, roles: List[UserRole]) -> List[Dict[str, Any]]:
        """Generate role escalation test scenarios."""
        escalation_tests = []
        
        # Sort roles by privilege level
        sorted_roles = sorted(roles, key=lambda x: x.level)
        
        for i, lower_role in enumerate(sorted_roles[:-1]):
            for higher_role in sorted_roles[i+1:]:
                # Test if lower role can access higher role endpoints
                higher_only_endpoints = higher_role.endpoints - lower_role.endpoints
                
                for endpoint in higher_only_endpoints:
                    escalation_tests.append({
                        'test_type': 'privilege_escalation',
                        'from_role': lower_role.name,
                        'to_role': higher_role.name,
                        'target_endpoint': endpoint,
                        'description': f"Test if {lower_role.name} can access {higher_role.name} endpoint: {endpoint}"
                    })
        
        return escalation_tests
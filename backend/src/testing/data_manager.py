"""Test data management and integration for security testing."""

import json
import logging
from typing import Dict, List, Any, Optional, AsyncIterator
from datetime import datetime

from .data_generator import TestDataGenerator
from .detector_base import BaseDetector
from .models import VulnerabilityEvidence, TestResult
from parser.models import APISpecification, APIEndpoint

logger = logging.getLogger(__name__)


class FuzzingDetector(BaseDetector):
    """Detector that uses generated test data for fuzzing."""
    
    def __init__(self):
        super().__init__(
            name="data_fuzzing",
            category="Input Validation",
            priority="MEDIUM"
        )
        self.description = "Tests endpoints with generated fuzzing data"
        self.data_generator = TestDataGenerator()
    
    async def detect(self, endpoint: APIEndpoint, spec: APISpecification,
                    auth_headers: Dict[str, str], base_url: str) -> List:
        """Detect vulnerabilities using fuzzing data."""
        vulnerabilities = []
        
        # Generate different types of test data
        data_types = ["valid", "edge_case", "invalid", "malicious"]
        
        for data_type in data_types:
            test_data = self.data_generator.generate_endpoint_data(endpoint, data_type)
            vulnerability = await self._test_with_data(
                endpoint, test_data, data_type, auth_headers, base_url
            )
            if vulnerability:
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _test_with_data(self, endpoint: APIEndpoint, test_data: Dict,
                            data_type: str, auth_headers: Dict[str, str], 
                            base_url: str):
        """Test endpoint with specific test data."""
        
        # Build URL with path parameters
        url = self.build_url(base_url, endpoint, test_data)
        
        # Prepare request based on method
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            # Use request body
            request_data = test_data.get('body', {})
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers={**auth_headers, 'Content-Type': 'application/json'},
                data=request_data
            )
        else:
            # Add query parameters
            query_params = {k: v for k, v in test_data.items() 
                          if k not in ['body', '_metadata']}
            if query_params:
                url += "?" + "&".join([f"{k}={v}" for k, v in query_params.items()])
            
            evidence = await self.make_request(
                method=endpoint.method,
                url=url,
                headers=auth_headers
            )
        
        # Analyze response for issues
        return self._analyze_fuzzing_result(endpoint, evidence, data_type, test_data)
    
    def _analyze_fuzzing_result(self, endpoint: APIEndpoint, evidence: VulnerabilityEvidence,
                              data_type: str, test_data: Dict):
        """Analyze fuzzing result for vulnerabilities."""
        
        if not evidence.response_status:
            return None
        
        status = evidence.response_status
        body = evidence.response_body or ""
        
        # Check for different types of issues based on data type
        if data_type == "malicious":
            return self._check_malicious_data_issues(endpoint, evidence, test_data)
        elif data_type == "invalid":
            return self._check_invalid_data_handling(endpoint, evidence, test_data)
        elif data_type == "edge_case":
            return self._check_edge_case_handling(endpoint, evidence, test_data)
        
        return None
    
    def _check_malicious_data_issues(self, endpoint: APIEndpoint, 
                                   evidence: VulnerabilityEvidence, test_data: Dict):
        """Check for issues with malicious data."""
        
        body = evidence.response_body or ""
        body_lower = body.lower()
        
        # Check for XSS reflection
        malicious_patterns = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for pattern in malicious_patterns:
            if pattern.lower() in body_lower:
                return self.create_vulnerability(
                    title="Cross-Site Scripting (XSS) - Reflected",
                    description="The application reflects malicious script content without proper encoding.",
                    severity="HIGH",
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Implement proper input validation and output encoding.",
                    cwe_id="CWE-79"
                )
        
        # Check for SQL injection indicators
        sql_errors = [
            "sql syntax", "mysql error", "ora-", "sqlite", "postgresql",
            "syntax error", "unclosed quotation mark"
        ]
        
        if any(error in body_lower for error in sql_errors):
            return self.create_vulnerability(
                title="SQL Injection Vulnerability",
                description="The application may be vulnerable to SQL injection attacks.",
                severity="CRITICAL",
                endpoint=endpoint,
                evidence=[evidence],
                remediation="Use parameterized queries and proper input validation.",
                cwe_id="CWE-89"
            )
        
        return None
    
    def _check_invalid_data_handling(self, endpoint: APIEndpoint,
                                   evidence: VulnerabilityEvidence, test_data: Dict):
        """Check how application handles invalid data."""
        
        status = evidence.response_status
        
        # Should return 400 Bad Request for invalid data
        if status == 200:
            return self.create_vulnerability(
                title="Poor Input Validation",
                description="The application accepts invalid input data without proper validation.",
                severity="MEDIUM",
                endpoint=endpoint,
                evidence=[evidence],
                remediation="Implement proper input validation and return appropriate error codes.",
                cwe_id="CWE-20"
            )
        
        # Check for information disclosure in error messages
        body = evidence.response_body or ""
        if status >= 500:
            sensitive_info = [
                "stack trace", "file path", "database error", 
                "internal error", "exception"
            ]
            if any(info in body.lower() for info in sensitive_info):
                return self.create_vulnerability(
                    title="Information Disclosure in Error Messages",
                    description="Error messages contain sensitive information that could aid attackers.",
                    severity="LOW",
                    endpoint=endpoint,
                    evidence=[evidence],
                    remediation="Implement generic error messages for external users.",
                    cwe_id="CWE-209"
                )
        
        return None
    
    def _check_edge_case_handling(self, endpoint: APIEndpoint,
                                evidence: VulnerabilityEvidence, test_data: Dict):
        """Check handling of edge cases."""
        
        status = evidence.response_status
        
        # Server errors on edge cases might indicate poor handling
        if status >= 500:
            return self.create_vulnerability(
                title="Poor Edge Case Handling",
                description="The application fails to handle edge case inputs gracefully.",
                severity="LOW",
                endpoint=endpoint,
                evidence=[evidence],
                remediation="Implement proper input validation and error handling for edge cases.",
                cwe_id="CWE-20"
            )
        
        return None
    
    def get_test_cases(self, endpoint: APIEndpoint, spec: APISpecification) -> List[Dict[str, Any]]:
        """Get test cases for fuzzing."""
        return [
            {
                'name': f"fuzzing_{endpoint.method}_{endpoint.path}",
                'test_type': 'fuzzing',
                'payload_count': 4  # valid, edge_case, invalid, malicious
            }
        ]


class TestDataManager:
    """Manages test data generation and caching."""
    
    def __init__(self):
        self.generator = TestDataGenerator()
        self._data_cache: Dict[str, Dict] = {}
        self._dataset_cache: Dict[str, Dict] = {}
    
    def get_endpoint_test_data(self, endpoint: APIEndpoint, 
                              data_type: str = "valid") -> Dict[str, Any]:
        """Get test data for a specific endpoint."""
        
        cache_key = f"{endpoint.path}_{endpoint.method}_{data_type}"
        
        if cache_key in self._data_cache:
            return self._data_cache[cache_key]
        
        data = self.generator.generate_endpoint_data(endpoint, data_type)
        self._data_cache[cache_key] = data
        
        return data
    
    def generate_test_dataset(self, spec: APISpecification, 
                            dataset_size: int = 100) -> Dict[str, List[Dict]]:
        """Generate a complete test dataset for an API."""
        
        cache_key = f"{spec.id}_{dataset_size}"
        
        if cache_key in self._dataset_cache:
            return self._dataset_cache[cache_key]
        
        dataset = self.generator.generate_test_dataset(spec, dataset_size)
        self._dataset_cache[cache_key] = dataset
        
        logger.info(f"Generated test dataset with {len(dataset)} endpoint datasets")
        return dataset
    
    def get_fuzzing_payloads(self, field_name: str, field_type: str) -> List[Any]:
        """Get fuzzing payloads for a specific field."""
        
        payloads = []
        
        # Generate different types of payloads
        for data_type in ["valid", "edge_case", "invalid", "malicious"]:
            payload = self.generator._generate_field_value(field_name, field_type, data_type)
            payloads.append({
                'type': data_type,
                'value': payload,
                'description': f"{data_type} payload for {field_name} ({field_type})"
            })
        
        return payloads
    
    def export_test_data(self, spec_id: str, format: str = "json") -> str:
        """Export test data in specified format."""
        
        if spec_id not in self._dataset_cache:
            return ""
        
        dataset = self._dataset_cache[spec_id]
        
        if format == "json":
            return json.dumps(dataset, indent=2, default=str)
        elif format == "csv":
            return self._convert_to_csv(dataset)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _convert_to_csv(self, dataset: Dict) -> str:
        """Convert dataset to CSV format."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Endpoint', 'Method', 'Data_Type', 'Test_Data'])
        
        # Write data
        for endpoint_key, test_cases in dataset.items():
            for test_case in test_cases:
                metadata = test_case.get('_metadata', {})
                endpoint = metadata.get('endpoint', '')
                method = metadata.get('method', '')
                data_type = metadata.get('type', '')
                
                # Remove metadata for cleaner export
                clean_data = {k: v for k, v in test_case.items() if k != '_metadata'}
                test_data = json.dumps(clean_data, default=str)
                
                writer.writerow([endpoint, method, data_type, test_data])
        
        return output.getvalue()
    
    def load_custom_test_data(self, file_path: str) -> Dict[str, Any]:
        """Load custom test data from file."""
        
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith('.json'):
                    return json.load(f)
                else:
                    raise ValueError("Only JSON format is currently supported")
        except Exception as e:
            logger.error(f"Error loading test data from {file_path}: {e}")
            return {}
    
    def merge_test_datasets(self, *datasets: Dict) -> Dict[str, List[Dict]]:
        """Merge multiple test datasets."""
        
        merged = {}
        
        for dataset in datasets:
            for key, test_cases in dataset.items():
                if key not in merged:
                    merged[key] = []
                merged[key].extend(test_cases)
        
        return merged
    
    def filter_dataset(self, dataset: Dict, endpoint_pattern: str = None,
                      data_types: List[str] = None) -> Dict[str, List[Dict]]:
        """Filter dataset based on criteria."""
        
        filtered = {}
        
        for endpoint_key, test_cases in dataset.items():
            # Filter by endpoint pattern
            if endpoint_pattern and endpoint_pattern not in endpoint_key:
                continue
            
            # Filter by data types
            if data_types:
                filtered_cases = [
                    case for case in test_cases
                    if case.get('_metadata', {}).get('type') in data_types
                ]
            else:
                filtered_cases = test_cases
            
            if filtered_cases:
                filtered[endpoint_key] = filtered_cases
        
        return filtered
    
    def get_statistics(self, dataset: Dict) -> Dict[str, Any]:
        """Get statistics about a test dataset."""
        
        total_cases = sum(len(cases) for cases in dataset.values())
        
        data_type_counts = {}
        method_counts = {}
        
        for test_cases in dataset.values():
            for case in test_cases:
                metadata = case.get('_metadata', {})
                
                data_type = metadata.get('type', 'unknown')
                data_type_counts[data_type] = data_type_counts.get(data_type, 0) + 1
                
                method = metadata.get('method', 'unknown')
                method_counts[method] = method_counts.get(method, 0) + 1
        
        return {
            'total_test_cases': total_cases,
            'total_endpoints': len(dataset),
            'data_type_distribution': data_type_counts,
            'method_distribution': method_counts,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def clear_cache(self):
        """Clear all cached test data."""
        self._data_cache.clear()
        self._dataset_cache.clear()
        logger.info("Test data cache cleared")
"""Vulnerability detection models and data structures."""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import uuid


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    """OWASP API Security categories."""
    API1_BOLA = "API1:2023 - Broken Object Level Authorization"
    API2_BROKEN_AUTH = "API2:2023 - Broken Authentication"
    API3_DATA_EXPOSURE = "API3:2023 - Excessive Data Exposure"
    API4_RATE_LIMITING = "API4:2023 - Lack of Resources & Rate Limiting"
    API5_FUNCTION_AUTH = "API5:2023 - Broken Function Level Authorization"
    API6_MASS_ASSIGNMENT = "API6:2023 - Mass Assignment"
    API7_SSRF = "API7:2023 - Server Side Request Forgery"
    API8_MISCONFIG = "API8:2023 - Security Misconfiguration"
    API9_INVENTORY = "API9:2023 - Improper Inventory Management"
    API10_UNSAFE_CONSUMPTION = "API10:2023 - Unsafe Consumption of APIs"
    
    # Additional categories
    RATE_LIMITING = "Rate Limiting"
    INPUT_VALIDATION = "Input Validation"
    INJECTION = "Injection Attacks"
    BUSINESS_LOGIC = "Business Logic Flaws"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    CORS_SECURITY = "CORS Misconfiguration"


@dataclass
class VulnerabilityEvidence:
    """Evidence supporting a vulnerability finding."""
    request_method: str
    request_url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    response_time: Optional[float] = None
    payload_used: Optional[str] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    category: VulnerabilityCategory = VulnerabilityCategory.INPUT_VALIDATION
    
    # Technical details
    endpoint: str = ""
    method: str = ""
    parameter: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
    # Evidence and proof
    evidence: List[VulnerabilityEvidence] = field(default_factory=list)
    proof_of_concept: Optional[str] = None
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    detected_at: datetime = field(default_factory=datetime.utcnow)
    test_module: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    false_positive_risk: float = 0.0  # 0.0 to 1.0


@dataclass
class TestResult:
    """Result of a single vulnerability test."""
    test_name: str
    endpoint: str
    method: str
    success: bool
    vulnerability: Optional[Vulnerability] = None
    error: Optional[str] = None
    execution_time: Optional[float] = None
    
    # Test metadata
    test_module: str = ""
    payload_used: Optional[str] = None
    expected_result: Optional[str] = None
    actual_result: Optional[str] = None


@dataclass
class TestSession:
    """Represents a complete testing session."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    spec_id: str = ""
    status: str = "queued"  # queued, running, completed, failed, stopped
    
    # Configuration
    test_modules: List[str] = field(default_factory=list)
    auth_config: Dict[str, Any] = field(default_factory=dict)
    target_base_url: Optional[str] = None
    test_intensity: str = "medium"
    
    # Progress tracking
    progress_percentage: int = 0
    current_test: Optional[str] = None
    total_tests: int = 0
    completed_tests: int = 0
    
    # Results
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    test_results: List[TestResult] = field(default_factory=list)
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    
    # Errors and warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class TestPriority(Enum):
    """Test execution priority."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
"""Data models for API specifications."""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import uuid


@dataclass
class APIEndpoint:
    """Represents a single API endpoint."""
    path: str
    method: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    parameters: List[Dict] = field(default_factory=list)
    request_body: Optional[Dict] = None
    responses: Dict[str, Any] = field(default_factory=dict)
    security_requirements: List[Dict] = field(default_factory=list)
    deprecated: bool = False


@dataclass
class SecurityScheme:
    """Represents a security scheme definition."""
    name: str
    type: str  # apiKey, http, oauth2, openIdConnect
    scheme: Optional[str] = None  # bearer, basic, etc.
    bearer_format: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None  # query, header, cookie
    flows: Optional[Dict] = None
    open_id_connect_url: Optional[str] = None


@dataclass
class ServerInfo:
    """Represents server information."""
    url: str
    description: Optional[str] = None
    variables: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APISpecification:
    """Complete API specification representation."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = "Unknown API"
    version: str = "1.0.0"
    description: str = ""
    spec_version: str = "unknown"
    
    # Endpoints and paths
    endpoints: List[APIEndpoint] = field(default_factory=list)
    base_path: str = ""
    
    # Authentication and security
    security_schemes: Dict[str, SecurityScheme] = field(default_factory=dict)
    global_security: List[Dict] = field(default_factory=list)
    auth_methods: Dict[str, SecurityScheme] = field(default_factory=dict)
    
    # Server information
    servers: List[ServerInfo] = field(default_factory=list)
    host: Optional[str] = None
    schemes: List[str] = field(default_factory=list)
    
    # Metadata
    contact: Optional[Dict] = None
    license: Optional[Dict] = None
    external_docs: Optional[Dict] = None
    
    # Raw specification data
    raw_spec: Dict[str, Any] = field(default_factory=dict)
    
    # Processing metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    source_url: Optional[str] = None
    source_file: Optional[str] = None
    validation_errors: List[str] = field(default_factory=list)
    parsing_warnings: List[str] = field(default_factory=list)


@dataclass
class ParsedParameter:
    """Represents a parsed API parameter."""
    name: str
    location: str  # path, query, header, cookie
    type: str
    required: bool = False
    description: Optional[str] = None
    example: Any = None
    default: Any = None
    enum: Optional[List[Any]] = None
    format: Optional[str] = None
    minimum: Optional[Union[int, float]] = None
    maximum: Optional[Union[int, float]] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
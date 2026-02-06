"""Application configuration using Pydantic Settings."""

from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Basic app settings
    app_name: str = "API Security Tester"
    version: str = "0.1.0"
    debug: bool = False
    
    # API settings
    api_prefix: str = "/api/v1"
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"
    
    # CORS settings
    allowed_origins: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    allowed_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: List[str] = ["*"]
    
    # Database settings
    database_url: str = "sqlite:///./api_security_tester.db"
    
    # Testing settings
    max_concurrent_tests: int = 10
    default_timeout: int = 30
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    
    # Security settings
    rate_limit_per_minute: int = 1000
    enable_audit_logging: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
"""Health check endpoints."""

from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
import platform

from utils.config import settings

router = APIRouter()


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str
    timestamp: datetime
    version: str
    system_info: dict


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Get application health status."""
    try:
        system_info = {
            "platform": platform.system(),
            "python_version": platform.python_version(),
        }
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow(),
            version=settings.version,
            system_info=system_info
        )
    except Exception as e:
        return HealthResponse(
            status="unhealthy",
            timestamp=datetime.utcnow(),
            version=settings.version,
            system_info={"error": str(e)}
        )


@router.get("/ping")
async def ping():
    """Simple ping endpoint."""
    return {"message": "pong"}
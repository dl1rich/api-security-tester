"""Security testing endpoints."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime

from testing.test_manager import TestManager
from utils.config import settings
from utils.dependencies import get_test_manager

router = APIRouter()


class TestConfiguration(BaseModel):
    """Test configuration model."""
    spec_id: str
    test_modules: List[str] = ["owasp_top10", "input_validation", "business_logic"]
    auth_handling: str = "preserve_roles"  # preserve_roles, bypass_all, custom
    custom_roles: Optional[List[str]] = None
    target_base_url: Optional[str] = None
    test_intensity: str = "medium"  # low, medium, high
    concurrent_requests: int = 5
    timeout_seconds: int = 30


class TestStartResponse(BaseModel):
    """Test start response model."""
    success: bool
    test_session_id: str
    message: str
    estimated_duration: int  # seconds


class TestStatusResponse(BaseModel):
    """Test status response model."""
    test_session_id: str
    status: str  # queued, running, completed, failed
    progress_percentage: int
    current_test: Optional[str]
    total_tests: int
    completed_tests: int
    started_at: datetime
    estimated_completion: Optional[datetime]


@router.post("/testing/start", response_model=TestStartResponse)
async def start_security_test(config: TestConfiguration, background_tasks: BackgroundTasks):
    """Start security testing for a specification."""
    try:
        test_manager = get_test_manager()
        
        # Validate configuration
        if not test_manager.validate_config(config):
            raise HTTPException(status_code=400, detail="Invalid test configuration")
        
        # Create test session
        session_id = test_manager.create_test_session(config)
        
        # Start testing in background
        background_tasks.add_task(test_manager.run_security_tests, session_id, config)
        
        # Estimate duration based on endpoints and intensity
        estimated_duration = test_manager.estimate_test_duration(config)
        
        return TestStartResponse(
            success=True,
            test_session_id=session_id,
            message="Security testing started successfully",
            estimated_duration=estimated_duration
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting test: {str(e)}")


@router.get("/testing/status/{session_id}", response_model=TestStatusResponse)
async def get_test_status(session_id: str):
    """Get current status of a test session."""
    try:
        test_manager = get_test_manager()
        status = test_manager.get_test_status(session_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Test session not found")
        
        return TestStatusResponse(**status)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting test status: {str(e)}")


@router.post("/testing/stop/{session_id}")
async def stop_test(session_id: str):
    """Stop a running test session."""
    try:
        test_manager = get_test_manager()
        result = test_manager.stop_test_session(session_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Test session not found or already stopped")
        
        return {"success": True, "message": "Test session stopped successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stopping test: {str(e)}")


@router.get("/testing/modules")
async def get_available_test_modules():
    """Get list of available testing modules."""
    try:
        test_manager = get_test_manager()
        modules = test_manager.get_available_modules()
        
        return {
            "success": True,
            "modules": modules
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting test modules: {str(e)}")


@router.get("/testing/sessions")
async def list_test_sessions(limit: int = 50):
    """List recent test sessions."""
    try:
        test_manager = get_test_manager()
        sessions = test_manager.list_test_sessions(limit=limit)
        
        return {
            "success": True,
            "sessions": sessions
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing test sessions: {str(e)}")
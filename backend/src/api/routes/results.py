"""Test results and reporting endpoints."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
import io

from reporting.report_generator import ReportGenerator
from utils.config import settings

router = APIRouter()


class VulnerabilityResult(BaseModel):
    """Vulnerability result model."""
    id: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    endpoint: str
    method: str
    cwe_id: Optional[str]
    owasp_category: str
    evidence: Dict
    remediation: str
    cvss_score: Optional[float]


class TestResults(BaseModel):
    """Complete test results model."""
    session_id: str
    spec_id: str
    test_config: Dict
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    total_vulnerabilities: int
    vulnerabilities_by_severity: Dict[str, int]
    vulnerabilities: List[VulnerabilityResult]
    coverage_stats: Dict
    summary: str


@router.get("/results/{session_id}", response_model=TestResults)
async def get_test_results(session_id: str):
    """Get complete test results for a session."""
    try:
        report_generator = ReportGenerator()
        results = report_generator.get_test_results(session_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="Test results not found")
        
        return TestResults(**results)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting test results: {str(e)}")


@router.get("/results/{session_id}/vulnerabilities")
async def get_vulnerabilities(
    session_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Get filtered vulnerabilities from test results."""
    try:
        report_generator = ReportGenerator()
        vulnerabilities = report_generator.get_vulnerabilities(
            session_id=session_id,
            severity=severity,
            category=category,
            limit=limit,
            offset=offset
        )
        
        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
            "total_count": len(vulnerabilities)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting vulnerabilities: {str(e)}")


@router.get("/results/{session_id}/summary")
async def get_results_summary(session_id: str):
    """Get summary of test results."""
    try:
        report_generator = ReportGenerator()
        summary = report_generator.get_results_summary(session_id)
        
        if not summary:
            raise HTTPException(status_code=404, detail="Test results not found")
        
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting results summary: {str(e)}")


@router.get("/results/{session_id}/export/html")
async def export_html_report(session_id: str):
    """Export test results as HTML report."""
    try:
        report_generator = ReportGenerator()
        html_content = report_generator.generate_html_report(session_id)
        
        if not html_content:
            raise HTTPException(status_code=404, detail="Test results not found")
        
        return StreamingResponse(
            io.BytesIO(html_content.encode()),
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=security_report_{session_id}.html"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating HTML report: {str(e)}")


@router.get("/results/{session_id}/export/json")
async def export_json_report(session_id: str):
    """Export test results as JSON report."""
    try:
        report_generator = ReportGenerator()
        json_content = report_generator.generate_json_report(session_id)
        
        if not json_content:
            raise HTTPException(status_code=404, detail="Test results not found")
        
        return StreamingResponse(
            io.BytesIO(json_content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=security_report_{session_id}.json"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating JSON report: {str(e)}")


@router.get("/results/{session_id}/export/pdf")
async def export_pdf_report(session_id: str):
    """Export test results as PDF report."""
    try:
        report_generator = ReportGenerator()
        pdf_content = report_generator.generate_pdf_report(session_id)
        
        if not pdf_content:
            raise HTTPException(status_code=404, detail="Test results not found")
        
        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_{session_id}.pdf"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF report: {str(e)}")


@router.delete("/results/{session_id}")
async def delete_test_results(session_id: str):
    """Delete test results."""
    try:
        report_generator = ReportGenerator()
        result = report_generator.delete_test_results(session_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="Test results not found")
        
        return {"success": True, "message": "Test results deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting test results: {str(e)}")


@router.get("/results")
async def list_test_results(limit: int = 50, offset: int = 0):
    """List all test results."""
    try:
        report_generator = ReportGenerator()
        results = report_generator.list_test_results(limit=limit, offset=offset)
        
        return {
            "success": True,
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing test results: {str(e)}")
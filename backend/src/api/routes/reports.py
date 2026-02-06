"""API routes for report generation and export."""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from io import BytesIO

from reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("/test/{session_id}")
async def get_test_results(session_id: str):
    """Get complete test results for a session."""
    report_gen = ReportGenerator()
    results = report_gen.get_test_results(session_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return results

@router.get("/test/{session_id}/summary")
async def get_test_summary(session_id: str):
    """Get summary of test results."""
    report_gen = ReportGenerator()
    summary = report_gen.get_results_summary(session_id)
    
    if not summary:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return summary

@router.get("/test/{session_id}/executive")
async def get_executive_summary(session_id: str):
    """Get executive summary for leadership."""
    report_gen = ReportGenerator()
    summary = report_gen.generate_executive_summary(session_id)
    
    if "error" in summary:
        raise HTTPException(status_code=404, detail=summary["error"])
    
    return summary

@router.get("/test/{session_id}/export/json")
async def export_json_report(
    session_id: str, 
    include_evidence: bool = Query(True, description="Include vulnerability evidence")
):
    """Export test results as JSON."""
    report_gen = ReportGenerator()
    json_data = report_gen.export_json(session_id, include_evidence)
    
    if not json_data or "error" in json_data:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=security_report_{session_id}.json"}
    )

@router.get("/test/{session_id}/export/csv")
async def export_csv_report(session_id: str):
    """Export vulnerability findings as CSV."""
    report_gen = ReportGenerator()
    csv_data = report_gen.export_csv(session_id)
    
    if not csv_data or csv_data.startswith("Error"):
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=vulnerabilities_{session_id}.csv"}
    )

@router.get("/test/{session_id}/export/xml")
async def export_xml_report(session_id: str):
    """Export test results as XML."""
    report_gen = ReportGenerator()
    xml_data = report_gen.export_xml(session_id)
    
    if not xml_data or xml_data.startswith("<error>"):
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return Response(
        content=xml_data,
        media_type="application/xml",
        headers={"Content-Disposition": f"attachment; filename=security_report_{session_id}.xml"}
    )

@router.get("/test/{session_id}/export/html")
async def export_html_report(session_id: str):
    """Export test results as HTML."""
    report_gen = ReportGenerator()
    html_data = report_gen.generate_html_report(session_id)
    
    if not html_data:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return Response(
        content=html_data,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=security_report_{session_id}.html"}
    )

@router.get("/test/{session_id}/export/pdf")
async def export_pdf_report(session_id: str, report_type: str = Query("technical", description="Report type: executive or technical")):
    """Export test results as PDF."""
    report_gen = ReportGenerator()
    pdf_data = report_gen.generate_pdf_report(session_id)
    
    if not pdf_data:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return StreamingResponse(
        BytesIO(pdf_data),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=security_report_{session_id}_{report_type}.pdf"}
    )

@router.get("/vulnerabilities/{session_id}")
async def get_vulnerabilities(
    session_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    category: Optional[str] = Query(None, description="Filter by OWASP category"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Number of results to skip")
):
    """Get filtered vulnerabilities from test results."""
    report_gen = ReportGenerator()
    
    # Get full results and filter vulnerabilities
    results = report_gen.get_test_results(session_id)
    if not results:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    vulnerabilities = results.get("vulnerabilities", [])
    
    # Apply filters
    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.get("severity") == severity]
    
    if category:
        vulnerabilities = [v for v in vulnerabilities if category.lower() in v.get("owasp_category", "").lower()]
    
    # Apply pagination
    total_count = len(vulnerabilities)
    vulnerabilities = vulnerabilities[offset:offset + limit]
    
    return {
        "vulnerabilities": vulnerabilities,
        "pagination": {
            "total": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total_count
        }
    }

@router.delete("/test/{session_id}")
async def delete_test_results(session_id: str):
    """Delete test results."""
    report_gen = ReportGenerator()
    success = report_gen.delete_test_results(session_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    return {"success": True, "message": f"Test results for session {session_id} deleted"}

@router.get("/sessions")
async def list_test_sessions(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of sessions to return"),
    offset: int = Query(0, ge=0, description="Number of sessions to skip")
):
    """List all test sessions."""
    report_gen = ReportGenerator()
    sessions = report_gen.list_test_results(limit, offset)
    
    return {
        "sessions": sessions,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "count": len(sessions)
        }
    }

@router.get("/test/{session_id}/stats")
async def get_test_statistics(session_id: str):
    """Get detailed statistics for a test session."""
    report_gen = ReportGenerator()
    results = report_gen.get_test_results(session_id)
    
    if not results:
        raise HTTPException(status_code=404, detail="Test session not found")
    
    vulnerabilities = results.get("vulnerabilities", [])
    
    # Calculate detailed statistics
    stats = {
        "session_info": {
            "session_id": session_id,
            "spec_id": results["spec_id"],
            "status": results["status"],
            "duration_seconds": results["duration_seconds"],
            "started_at": results["started_at"],
            "completed_at": results.get("completed_at")
        },
        "vulnerability_stats": {
            "total_count": len(vulnerabilities),
            "severity_breakdown": results["vulnerabilities_by_severity"],
            "owasp_categories": _get_owasp_category_stats(vulnerabilities),
            "cwe_distribution": _get_cwe_distribution(vulnerabilities),
            "endpoint_risk_analysis": _analyze_endpoint_risks(vulnerabilities)
        },
        "coverage_stats": results["coverage_stats"],
        "risk_metrics": {
            "risk_score": report_gen._calculate_risk_score(vulnerabilities),
            "exploitability_rating": _assess_exploitability(vulnerabilities),
            "business_impact_score": _calculate_business_impact_score(vulnerabilities)
        }
    }
    
    return stats

def _get_owasp_category_stats(vulnerabilities: list) -> dict:
    """Get statistics by OWASP category."""
    categories = {}
    for vuln in vulnerabilities:
        category = vuln.get("owasp_category", "Uncategorized")
        if category not in categories:
            categories[category] = {"count": 0, "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
        categories[category]["count"] += 1
        severity = vuln.get("severity", "info")
        categories[category]["severities"][severity] += 1
    return categories

def _get_cwe_distribution(vulnerabilities: list) -> dict:
    """Get CWE ID distribution."""
    cwes = {}
    for vuln in vulnerabilities:
        cwe = vuln.get("cwe_id", "Unknown")
        cwes[cwe] = cwes.get(cwe, 0) + 1
    return cwes

def _analyze_endpoint_risks(vulnerabilities: list) -> dict:
    """Analyze risk by endpoint."""
    endpoints = {}
    for vuln in vulnerabilities:
        endpoint = f"{vuln.get('method', 'UNKNOWN')} {vuln.get('endpoint', 'unknown')}"
        if endpoint not in endpoints:
            endpoints[endpoint] = {"vulnerability_count": 0, "max_severity": "info", "risk_score": 0}
        endpoints[endpoint]["vulnerability_count"] += 1
        
        # Update max severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        current_severity = vuln.get("severity", "info")
        if severity_order[current_severity] > severity_order[endpoints[endpoint]["max_severity"]]:
            endpoints[endpoint]["max_severity"] = current_severity
    
    # Calculate risk scores for endpoints
    for endpoint_data in endpoints.values():
        severity_weights = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
        endpoint_data["risk_score"] = severity_weights[endpoint_data["max_severity"]] * endpoint_data["vulnerability_count"]
    
    return endpoints

def _assess_exploitability(vulnerabilities: list) -> str:
    """Assess overall exploitability of vulnerabilities."""
    if not vulnerabilities:
        return "None"
    
    critical_high = [v for v in vulnerabilities if v.get("severity") in ["critical", "high"]]
    if len(critical_high) > 0:
        return "High"
    elif len([v for v in vulnerabilities if v.get("severity") == "medium"]) > 0:
        return "Medium"
    else:
        return "Low"

def _calculate_business_impact_score(vulnerabilities: list) -> float:
    """Calculate business impact score (0-100)."""
    if not vulnerabilities:
        return 0.0
    
    impact_weights = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}
    total_impact = sum(impact_weights.get(v.get("severity", "info"), 0) for v in vulnerabilities)
    
    # Normalize to 0-100 scale
    max_possible = len(vulnerabilities) * 100
    return min(100.0, (total_impact / max_possible) * 100) if max_possible > 0 else 0.0
"""Report generation and export functionality."""

import json
import logging
import csv
from typing import Dict, List, Optional, Any
from datetime import datetime
from io import StringIO
import xml.etree.ElementTree as ET

from testing.test_manager import TestManager

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security testing reports in multiple formats."""
    
    def __init__(self):
        self._test_manager = TestManager()
    
    def get_test_results(self, session_id: str) -> Optional[Dict]:
        """Get complete test results for a session."""
        # This is a stub implementation
        # In a real implementation, this would fetch from database
        session = self._test_manager._test_sessions.get(session_id)
        if not session:
            return None

        # Simulate vulnerability findings
        sample_vulnerabilities = [
            {
                'id': 'vuln_001',
                'title': 'SQL Injection in User Endpoint',
                'severity': 'high',
                'cvss_score': 8.1,
                'description': 'SQL injection vulnerability allows attackers to manipulate database queries.',
                'endpoint': '/api/users/{id}',
                'method': 'GET',
                'cwe_id': 'CWE-89',
                'owasp_category': 'API3:2023 Broken Object Property Level Authorization',
                'evidence': {'request': 'GET /api/users/1\' OR 1=1--', 'response': 'Database error revealed'},
                'remediation': 'Use parameterized queries and input validation',
                'discovered_at': datetime.utcnow().isoformat()
            },
            {
                'id': 'vuln_002',
                'title': 'Missing Authentication on Admin Endpoint',
                'severity': 'critical',
                'cvss_score': 9.8,
                'description': 'Admin functionality accessible without authentication.',
                'endpoint': '/api/admin/users',
                'method': 'DELETE',
                'cwe_id': 'CWE-306',
                'owasp_category': 'API2:2023 Broken Authentication',
                'evidence': {'request': 'DELETE /api/admin/users/123', 'response': 'User deleted successfully'},
                'remediation': 'Implement proper authentication and authorization checks',
                'discovered_at': datetime.utcnow().isoformat()
            },
            {
                'id': 'vuln_003',
                'title': 'Information Disclosure in Error Messages',
                'severity': 'medium',
                'cvss_score': 5.3,
                'description': 'Error messages reveal sensitive system information.',
                'endpoint': '/api/data',
                'method': 'POST',
                'cwe_id': 'CWE-209',
                'owasp_category': 'API9:2023 Improper Inventory Management',
                'evidence': {'error_message': 'Database connection failed: mysql://admin:pass123@db:3306/prod'},
                'remediation': 'Implement generic error messages and proper error handling',
                'discovered_at': datetime.utcnow().isoformat()
            }
        ]
        
        return {
            'session_id': session_id,
            'spec_id': session['config'].spec_id,
            'test_config': session['config'].__dict__,
            'status': session['status'],
            'started_at': session['started_at'].isoformat(),
            'completed_at': datetime.utcnow().isoformat() if session['status'] == 'completed' else None,
            'duration_seconds': 1847,
            'total_vulnerabilities': len(sample_vulnerabilities),
            'vulnerabilities_by_severity': self._calculate_severity_breakdown(sample_vulnerabilities),
            'vulnerabilities': sample_vulnerabilities,
            'coverage_stats': {
                'endpoints_tested': 15,
                'total_endpoints': 18,
                'coverage_percentage': 83.3,
                'methods_tested': {'GET': 8, 'POST': 4, 'PUT': 2, 'DELETE': 1},
                'auth_methods_tested': ['Bearer', 'API Key'],
                'parameters_tested': 47
            },
            'summary': f'Security testing completed with {len(sample_vulnerabilities)} vulnerabilities found across {15} endpoints.',
            'metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'report_version': '1.0'
            }
        }
    
    def _calculate_severity_breakdown(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability count by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown
    
    def export_json(self, session_id: str, include_evidence: bool = True) -> Optional[str]:
        """Export results as JSON."""
        try:
            results = self.get_test_results(session_id)
            if not results:
                return json.dumps({"error": "Test session not found"})
            
            if not include_evidence:
                # Remove evidence to reduce size
                for vuln in results.get("vulnerabilities", []):
                    vuln.pop("evidence", None)
            
            return json.dumps(results, indent=2, default=str)
        
        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")
            return json.dumps({"error": str(e)})
    
    def export_csv(self, session_id: str) -> Optional[str]:
        """Export vulnerability findings as CSV."""
        try:
            results = self.get_test_results(session_id)
            if not results:
                return "Error: Test session not found"
            
            output = StringIO()
            writer = csv.writer(output)
            
            # CSV Headers
            headers = [
                "ID", "Title", "Severity", "CVSS Score", "Endpoint", "Method",
                "CWE ID", "OWASP Category", "Remediation", "Discovered At"
            ]
            writer.writerow(headers)
            
            # Write vulnerability findings
            for vuln in results.get("vulnerabilities", []):
                row = [
                    vuln.get("id", ""),
                    vuln.get("title", ""),
                    vuln.get("severity", ""),
                    vuln.get("cvss_score", ""),
                    vuln.get("endpoint", ""),
                    vuln.get("method", ""),
                    vuln.get("cwe_id", ""),
                    vuln.get("owasp_category", ""),
                    vuln.get("remediation", ""),
                    vuln.get("discovered_at", "")
                ]
                writer.writerow(row)
            
            return output.getvalue()
        
        except Exception as e:
            logger.error(f"Error exporting CSV: {e}")
            return f"Error: {e}"
    
    def export_xml(self, session_id: str) -> Optional[str]:
        """Export results as XML (compatible with security tools)."""
        try:
            results = self.get_test_results(session_id)
            if not results:
                return "<error>Test session not found</error>"
            
            root = ET.Element("security_test_report")
            root.set("version", "1.0")
            root.set("generated_at", datetime.utcnow().isoformat())
            
            # Summary section
            summary_elem = ET.SubElement(root, "summary")
            ET.SubElement(summary_elem, "session_id").text = results["session_id"]
            ET.SubElement(summary_elem, "status").text = results["status"]
            ET.SubElement(summary_elem, "total_vulnerabilities").text = str(results["total_vulnerabilities"])
            ET.SubElement(summary_elem, "duration_seconds").text = str(results["duration_seconds"])
            
            # Coverage section
            coverage_elem = ET.SubElement(summary_elem, "coverage")
            coverage_stats = results["coverage_stats"]
            for key, value in coverage_stats.items():
                ET.SubElement(coverage_elem, key).text = str(value)
            
            # Vulnerabilities section
            vulns_elem = ET.SubElement(root, "vulnerabilities")
            for vuln in results.get("vulnerabilities", []):
                vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                vuln_elem.set("id", vuln.get("id", ""))
                
                ET.SubElement(vuln_elem, "title").text = vuln.get("title", "")
                ET.SubElement(vuln_elem, "severity").text = vuln.get("severity", "")
                ET.SubElement(vuln_elem, "cvss_score").text = str(vuln.get("cvss_score", ""))
                ET.SubElement(vuln_elem, "endpoint").text = vuln.get("endpoint", "")
                ET.SubElement(vuln_elem, "method").text = vuln.get("method", "")
                ET.SubElement(vuln_elem, "cwe_id").text = vuln.get("cwe_id", "")
                ET.SubElement(vuln_elem, "owasp_category").text = vuln.get("owasp_category", "")
                ET.SubElement(vuln_elem, "description").text = vuln.get("description", "")
                ET.SubElement(vuln_elem, "remediation").text = vuln.get("remediation", "")
            
            return ET.tostring(root, encoding='unicode')
        
        except Exception as e:
            logger.error(f"Error exporting XML: {e}")
            return f"<error>{e}</error>"
    
    def generate_executive_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Generate executive summary for leadership."""
        results = self.get_test_results(session_id)
        if not results:
            return {"error": "Test session not found"}
        
        # Calculate risk metrics
        severity_breakdown = results["vulnerabilities_by_severity"]
        total_vulns = results["total_vulnerabilities"]
        critical_high_vulns = severity_breakdown.get('critical', 0) + severity_breakdown.get('high', 0)
        
        # Determine overall risk level
        risk_score = self._calculate_risk_score(results["vulnerabilities"])
        risk_level = self._determine_risk_level(risk_score)
        
        return {
            "api_name": f"API Spec {results['spec_id']}",
            "test_date": datetime.fromisoformat(results["started_at"]).strftime("%Y-%m-%d"),
            "overall_risk_level": risk_level,
            "risk_score": risk_score,
            "total_vulnerabilities": total_vulns,
            "critical_high_vulnerabilities": critical_high_vulns,
            "coverage_percentage": results["coverage_stats"]["coverage_percentage"],
            "test_duration_hours": results["duration_seconds"] / 3600,
            "key_findings": self._extract_key_findings(results["vulnerabilities"]),
            "remediation_priority": self._get_remediation_priorities(results["vulnerabilities"]),
            "business_impact": self._assess_business_impact(risk_score, critical_high_vulns),
            "compliance_status": self._check_compliance(results["vulnerabilities"]),
            "next_steps": self._recommend_next_steps(risk_score, results["coverage_stats"])
        }
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score (0-100)."""
        if not vulnerabilities:
            return 0.0
        
        severity_weights = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
        total_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info")
            total_score += severity_weights.get(severity, 0)
        
        # Normalize by number of vulnerabilities and scale to 0-100
        avg_score = total_score / len(vulnerabilities)
        return min(100.0, avg_score)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score."""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _extract_key_findings(self, vulnerabilities: List[Dict]) -> List[str]:
        """Extract key findings for executive summary."""
        findings = []
        
        # Count critical/high findings
        critical_high = [v for v in vulnerabilities if v.get("severity") in ["critical", "high"]]
        if critical_high:
            findings.append(f"Found {len(critical_high)} critical/high severity vulnerabilities requiring immediate attention")
        
        # Check for authentication issues
        auth_issues = [v for v in vulnerabilities if "auth" in v.get("title", "").lower()]
        if auth_issues:
            findings.append(f"Authentication vulnerabilities present in {len(auth_issues)} locations")
        
        # Check for injection vulnerabilities
        injection_issues = [v for v in vulnerabilities if "injection" in v.get("title", "").lower()]
        if injection_issues:
            findings.append("SQL injection vulnerabilities identified")
        
        # OWASP compliance issues
        owasp_categories = set(v.get("owasp_category", "") for v in vulnerabilities if v.get("owasp_category"))
        if owasp_categories:
            findings.append(f"API violates {len(owasp_categories)} OWASP API Top 10 categories")
        
        return findings[:5]  # Top 5 key findings
    
    def _get_remediation_priorities(self, vulnerabilities: List[Dict]) -> List[str]:
        """Get prioritized remediation recommendations."""
        priorities = []
        
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
        
        if critical_vulns:
            priorities.append("Immediately address all critical severity vulnerabilities")
        
        if high_vulns:
            priorities.append("Address high severity vulnerabilities within 30 days")
        
        if len(vulnerabilities) > 10:
            priorities.append("Implement security code review process to prevent future issues")
        
        priorities.append("Establish regular security testing schedule")
        
        return priorities
    
    def _assess_business_impact(self, risk_score: float, critical_high_count: int) -> str:
        """Assess business impact of vulnerabilities."""
        if risk_score >= 80 or critical_high_count > 0:
            return ("High business risk. Critical vulnerabilities present that could lead to data breaches, "
                   "regulatory violations, financial losses, and reputational damage.")
        elif risk_score >= 60:
            return ("Moderate business risk. Security vulnerabilities present that could impact business "
                   "operations and customer trust if exploited.")
        elif risk_score >= 40:
            return ("Low to moderate business risk. Some security issues identified that should be "
                   "addressed as part of regular security maintenance.")
        else:
            return ("Low business risk. Minor security issues identified. Continue regular security "
                   "testing and monitoring.")
    
    def _check_compliance(self, vulnerabilities: List[Dict]) -> Dict[str, bool]:
        """Check compliance against security standards."""
        owasp_violations = set()
        for vuln in vulnerabilities:
            if vuln.get("owasp_category") and vuln.get("severity") in ["critical", "high"]:
                owasp_violations.add(vuln["owasp_category"])
        
        return {
            "owasp_api_top_10_compliant": len(owasp_violations) == 0,
            "critical_vulnerabilities_present": any(v.get("severity") == "critical" for v in vulnerabilities),
            "auth_vulnerabilities_present": any("auth" in v.get("title", "").lower() for v in vulnerabilities)
        }
    
    def _recommend_next_steps(self, risk_score: float, coverage_stats: Dict) -> List[str]:
        """Recommend next steps based on findings."""
        steps = []
        
        if risk_score >= 80:
            steps.append("Form incident response team to address critical vulnerabilities immediately")
        
        if coverage_stats.get("coverage_percentage", 0) < 80:
            steps.append("Increase test coverage to identify additional potential vulnerabilities")
        
        steps.append("Implement automated security testing in CI/CD pipeline")
        steps.append("Conduct security code review for identified vulnerable endpoints")
        steps.append("Schedule follow-up security assessment in 30-60 days")
        
        return steps
    
    def get_results_summary(self, session_id: str) -> Optional[Dict]:
        """Get summary of test results."""
        results = self.get_test_results(session_id)
        if not results:
            return None
        
        return {
            'session_id': session_id,
            'status': results['status'],
            'total_vulnerabilities': results['total_vulnerabilities'],
            'vulnerabilities_by_severity': results['vulnerabilities_by_severity'],
            'coverage_percentage': 83,  # Placeholder
            'test_duration': results.get('duration_seconds', 0)
        }
    
    def generate_html_report(self, session_id: str) -> Optional[str]:
        """Generate HTML report."""
        results = self.get_test_results(session_id)
        if not results:
            return None
        
        # Simple HTML template - would use proper templating in real implementation
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Test Report - {session_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .vulnerability {{ border: 1px solid #ccc; margin: 10px 0; padding: 10px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>API Security Test Report</h1>
                <p>Session ID: {session_id}</p>
                <p>Status: {results['status']}</p>
                <p>Total Vulnerabilities: {results['total_vulnerabilities']}</p>
            </div>
            <div class="summary">
                <h2>Summary</h2>
                <p>{results['summary']}</p>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def generate_json_report(self, session_id: str) -> Optional[str]:
        """Generate JSON report."""
        results = self.get_test_results(session_id)
        if not results:
            return None
        
        return json.dumps(results, indent=2)
    
    def generate_pdf_report(self, session_id: str) -> Optional[bytes]:
        """Generate PDF report."""
        # Stub implementation - would use a PDF library like reportlab
        results = self.get_test_results(session_id)
        if not results:
            return None
        
        # For now, return empty bytes - real implementation would generate PDF
        return b"PDF content would be here"
    
    def delete_test_results(self, session_id: str) -> bool:
        """Delete test results."""
        if session_id in self._test_manager._test_sessions:
            del self._test_manager._test_sessions[session_id]
            return True
        return False
    
    def list_test_results(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """List all test results."""
        sessions = self._test_manager.list_test_sessions(limit)
        return [
            {
                'session_id': session['id'],
                'spec_id': session['config'].spec_id,
                'status': session['status'],
                'started_at': session['started_at'].isoformat(),
                'total_vulnerabilities': session.get('results', {}).get('total_vulnerabilities', 0)
            }
            for session in sessions[offset:offset+limit]
        ]
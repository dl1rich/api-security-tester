"""Improved report storage and management with better error handling."""

import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import asyncio

logger = logging.getLogger(__name__)


class ReportManager:
    """Manages test reports with improved storage and retrieval."""
    
    def __init__(self, storage_path: str = "./reports"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = asyncio.Lock()
        self._max_cache_size = 100
    
    async def save_report(self, session_id: str, report_data: Dict[str, Any]) -> bool:
        """Save a test report with error handling."""
        try:
            # Add metadata
            report_data['saved_at'] = datetime.utcnow().isoformat()
            report_data['session_id'] = session_id
            
            # Save to file
            report_file = self.storage_path / f"{session_id}.json"
            async with asyncio.Lock():
                with open(report_file, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
            
            # Update cache
            async with self._cache_lock:
                self._cache[session_id] = report_data
                await self._manage_cache_size()
            
            logger.info(f"Saved report for session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save report for session {session_id}: {e}")
            return False
    
    async def get_report(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a test report."""
        try:
            # Check cache first
            async with self._cache_lock:
                if session_id in self._cache:
                    logger.debug(f"Retrieved report from cache: {session_id}")
                    return self._cache[session_id]
            
            # Load from file
            report_file = self.storage_path / f"{session_id}.json"
            if not report_file.exists():
                logger.warning(f"Report not found: {session_id}")
                return None
            
            with open(report_file, 'r') as f:
                report_data = json.load(f)
            
            # Update cache
            async with self._cache_lock:
                self._cache[session_id] = report_data
            
            logger.debug(f"Retrieved report from file: {session_id}")
            return report_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve report for session {session_id}: {e}")
            return None
    
    async def update_report(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing report."""
        try:
            report = await self.get_report(session_id)
            if not report:
                logger.warning(f"Cannot update non-existent report: {session_id}")
                return False
            
            # Merge updates
            report.update(updates)
            report['updated_at'] = datetime.utcnow().isoformat()
            
            # Save updated report
            return await self.save_report(session_id, report)
            
        except Exception as e:
            logger.error(f"Failed to update report for session {session_id}: {e}")
            return False
    
    async def delete_report(self, session_id: str) -> bool:
        """Delete a test report."""
        try:
            # Remove from cache
            async with self._cache_lock:
                self._cache.pop(session_id, None)
            
            # Delete file
            report_file = self.storage_path / f"{session_id}.json"
            if report_file.exists():
                report_file.unlink()
                logger.info(f"Deleted report: {session_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete report for session {session_id}: {e}")
            return False
    
    async def list_reports(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List available reports."""
        try:
            reports = []
            
            # Get all report files
            report_files = sorted(
                self.storage_path.glob("*.json"),
                key=lambda f: f.stat().st_mtime,
                reverse=True
            )
            
            # Apply pagination
            for report_file in report_files[offset:offset + limit]:
                try:
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)
                    
                    # Return summary info
                    reports.append({
                        'session_id': report_data.get('session_id'),
                        'status': report_data.get('status'),
                        'started_at': report_data.get('started_at'),
                        'completed_at': report_data.get('completed_at'),
                        'total_vulnerabilities': report_data.get('total_vulnerabilities', 0),
                        'spec_id': report_data.get('spec_id')
                    })
                    
                except Exception as e:
                    logger.error(f"Error reading report file {report_file}: {e}")
                    continue
            
            return reports
            
        except Exception as e:
            logger.error(f"Failed to list reports: {e}")
            return []
    
    async def _manage_cache_size(self):
        """Manage cache size to prevent memory issues."""
        if len(self._cache) > self._max_cache_size:
            # Remove oldest entries
            items_to_remove = len(self._cache) - self._max_cache_size
            for _ in range(items_to_remove):
                self._cache.pop(next(iter(self._cache)))
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            'cached_reports': len(self._cache),
            'max_cache_size': self._max_cache_size
        }
    
    async def export_report(self, session_id: str, format: str = 'json') -> Optional[str]:
        """Export a report in specified format."""
        try:
            report = await self.get_report(session_id)
            if not report:
                return None
            
            if format == 'json':
                return json.dumps(report, indent=2, default=str)
            
            elif format == 'csv':
                return await self._export_as_csv(report)
            
            elif format == 'html':
                return await self._export_as_html(report)
            
            else:
                logger.warning(f"Unsupported export format: {format}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to export report {session_id} as {format}: {e}")
            return None
    
    async def _export_as_csv(self, report: Dict[str, Any]) -> str:
        """Export report as CSV."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Title', 'Severity', 'Endpoint', 'Method', 'CWE', 'CVSS'])
        
        # Write vulnerabilities
        for vuln in report.get('vulnerabilities', []):
            writer.writerow([
                vuln.get('title', ''),
                vuln.get('severity', ''),
                vuln.get('endpoint', ''),
                vuln.get('method', ''),
                vuln.get('cwe_id', ''),
                vuln.get('cvss_score', '')
            ])
        
        return output.getvalue()
    
    async def _export_as_html(self, report: Dict[str, Any]) -> str:
        """Export report as HTML."""
        html = f"""
        <html>
        <head>
            <title>Security Test Report - {report.get('session_id')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f5f5f5; padding: 15px; margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .critical {{ background-color: #f44336; color: white; }}
                .high {{ background-color: #ff9800; }}
                .medium {{ background-color: #ffeb3b; }}
                .low {{ background-color: #8bc34a; }}
            </style>
        </head>
        <body>
            <h1>Security Test Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Session ID:</strong> {report.get('session_id')}</p>
                <p><strong>Status:</strong> {report.get('status')}</p>
                <p><strong>Started:</strong> {report.get('started_at')}</p>
                <p><strong>Total Vulnerabilities:</strong> {report.get('total_vulnerabilities', 0)}</p>
            </div>
            
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Endpoint</th>
                    <th>CWE</th>
                    <th>CVSS</th>
                </tr>
        """
        
        for vuln in report.get('vulnerabilities', []):
            severity_class = vuln.get('severity', 'low').lower()
            html += f"""
                <tr class="{severity_class}">
                    <td>{vuln.get('severity', '')}</td>
                    <td>{vuln.get('title', '')}</td>
                    <td>{vuln.get('endpoint', '')}</td>
                    <td>{vuln.get('cwe_id', '')}</td>
                    <td>{vuln.get('cvss_score', '')}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        return html


# Global report manager instance
report_manager = ReportManager()

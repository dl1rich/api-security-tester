"""Enhanced statistics and pentester guidance module."""

import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict


class TestStatistics:
    """Tracks and calculates detailed testing statistics."""
    
    def __init__(self):
        self.endpoint_timings = defaultdict(list)  # endpoint -> [execution_times]
        self.test_type_timings = defaultdict(list)  # test_type -> [execution_times]
        self.vulnerability_patterns = defaultdict(int)  # pattern -> count
        self.endpoint_risk_scores = {}  # endpoint -> risk_score
        self.start_time = None
        self.end_time = None
        
    def record_test_execution(self, endpoint: str, test_type: str, execution_time: float):
        """Record a test execution time."""
        self.endpoint_timings[endpoint].append(execution_time)
        self.test_type_timings[test_type].append(execution_time)
    
    def start_testing(self):
        """Mark the start of testing."""
        self.start_time = datetime.utcnow()
    
    def end_testing(self):
        """Mark the end of testing."""
        self.end_time = datetime.utcnow()
    
    def get_average_time_per_endpoint(self) -> Dict[str, float]:
        """Calculate average test time per endpoint."""
        return {
            endpoint: sum(times) / len(times) if times else 0
            for endpoint, times in self.endpoint_timings.items()
        }
    
    def get_average_time_per_test_type(self) -> Dict[str, float]:
        """Calculate average test time per test type."""
        return {
            test_type: sum(times) / len(times) if times else 0
            for test_type, times in self.test_type_timings.items()
        }
    
    def get_total_testing_time(self) -> float:
        """Get total testing duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    def calculate_endpoint_risk_score(self, endpoint: str, vulnerabilities: List[Dict]) -> float:
        """Calculate risk score for an endpoint based on vulnerabilities found."""
        severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        endpoint_vulns = [v for v in vulnerabilities if v.get('endpoint') == endpoint]
        
        if not endpoint_vulns:
            return 0.0
        
        total_score = sum(
            severity_weights.get(v.get('severity', 'info').lower(), 1.0)
            for v in endpoint_vulns
        )
        
        # Normalize to 0-100 scale
        return min(total_score * 10, 100.0)
    
    def get_detailed_statistics(self, vulnerabilities: List[Dict], 
                               endpoints_tested: int, 
                               total_endpoints: int) -> Dict[str, Any]:
        """Generate comprehensive statistics report."""
        
        # Calculate timing statistics
        avg_time_per_endpoint = self.get_average_time_per_endpoint()
        avg_time_per_test_type = self.get_average_time_per_test_type()
        total_time = self.get_total_testing_time()
        
        # Calculate vulnerability statistics
        severity_breakdown = self._calculate_severity_breakdown(vulnerabilities)
        category_breakdown = self._calculate_category_breakdown(vulnerabilities)
        endpoint_breakdown = self._calculate_endpoint_breakdown(vulnerabilities)
        
        # Calculate risk scores
        for endpoint in endpoint_breakdown.keys():
            self.endpoint_risk_scores[endpoint] = self.calculate_endpoint_risk_score(
                endpoint, vulnerabilities
            )
        
        return {
            'timing_stats': {
                'total_duration_seconds': round(total_time, 2),
                'total_duration_formatted': self._format_duration(total_time),
                'average_time_per_endpoint': {
                    k: round(v, 2) for k, v in avg_time_per_endpoint.items()
                },
                'average_time_per_test_type': {
                    k: round(v, 2) for k, v in avg_time_per_test_type.items()
                },
                'overall_avg_time_per_endpoint': round(
                    sum(avg_time_per_endpoint.values()) / len(avg_time_per_endpoint)
                    if avg_time_per_endpoint else 0, 2
                ),
                'testing_efficiency': {
                    'endpoints_per_minute': round(
                        (endpoints_tested / (total_time / 60)) if total_time > 0 else 0, 2
                    ),
                    'tests_per_second': round(
                        len(vulnerabilities) / total_time if total_time > 0 else 0, 2
                    )
                }
            },
            'vulnerability_stats': {
                'total_count': len(vulnerabilities),
                'by_severity': severity_breakdown,
                'by_category': category_breakdown,
                'by_endpoint': endpoint_breakdown,
                'unique_endpoints_affected': len(endpoint_breakdown),
                'vulnerability_density': round(
                    len(vulnerabilities) / endpoints_tested if endpoints_tested > 0 else 0, 2
                )
            },
            'coverage_stats': {
                'endpoints_tested': endpoints_tested,
                'total_endpoints': total_endpoints,
                'coverage_percentage': round(
                    (endpoints_tested / total_endpoints * 100) if total_endpoints > 0 else 0, 2
                )
            },
            'risk_metrics': {
                'endpoint_risk_scores': self.endpoint_risk_scores,
                'highest_risk_endpoints': self._get_highest_risk_endpoints(5),
                'overall_api_risk_score': self._calculate_overall_risk_score(vulnerabilities)
            }
        }
    
    def _calculate_severity_breakdown(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability count by severity."""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown
    
    def _calculate_category_breakdown(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability count by category."""
        breakdown = defaultdict(int)
        for vuln in vulnerabilities:
            category = vuln.get('category', 'Unknown')
            breakdown[category] += 1
        return dict(breakdown)
    
    def _calculate_endpoint_breakdown(self, vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """Group vulnerabilities by endpoint."""
        breakdown = defaultdict(list)
        for vuln in vulnerabilities:
            endpoint = vuln.get('endpoint', 'Unknown')
            breakdown[endpoint].append({
                'title': vuln.get('title', ''),
                'severity': vuln.get('severity', 'info'),
                'category': vuln.get('category', '')
            })
        return dict(breakdown)
    
    def _get_highest_risk_endpoints(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get the highest risk endpoints."""
        sorted_endpoints = sorted(
            self.endpoint_risk_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        return [
            {'endpoint': endpoint, 'risk_score': round(score, 2)}
            for endpoint, score in sorted_endpoints
        ]
    
    def _calculate_overall_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall API risk score."""
        if not vulnerabilities:
            return 0.0
        
        severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        total_score = sum(
            severity_weights.get(v.get('severity', 'info').lower(), 1.0)
            for v in vulnerabilities
        )
        
        # Normalize to 0-100 scale
        return min(round(total_score, 2), 100.0)
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"


class PentesterGuidance:
    """Provides detailed guidance for pentesters based on vulnerabilities found."""
    
    @staticmethod
    def get_vulnerability_guidance(vulnerability_type: str) -> Dict[str, Any]:
        """Get detailed pentester guidance for a specific vulnerability type."""
        
        guidance_database = {
            'SQL_INJECTION': {
                'what_to_look_for': [
                    'Error messages revealing database structure',
                    'Time-based blind SQL injection (response delays)',
                    'Boolean-based blind SQL injection (different responses)',
                    'Union-based injection (additional data in response)',
                    'Stacked queries (multiple SQL statements)',
                    'Database fingerprinting information'
                ],
                'exploitation_steps': [
                    '1. Identify injection points in parameters',
                    '2. Test with single quote (\\') to trigger errors',
                    '3. Try Boolean-based payloads (AND 1=1, AND 1=2)',
                    '4. Attempt time-based delays (SLEEP, WAITFOR)',
                    '5. Extract database version and structure',
                    '6. Enumerate tables and columns',
                    '7. Extract sensitive data'
                ],
                'tools_recommended': [
                    'sqlmap - Automated SQL injection tool',
                    'Burp Suite - Manual testing and intruder',
                    'Manual payloads for precise control'
                ],
                'severity_indicators': {
                    'critical': 'Direct data extraction possible',
                    'high': 'Blind injection confirmed',
                    'medium': 'Error-based injection only'
                }
            },
            'XSS': {
                'what_to_look_for': [
                    'Reflected input in HTML response',
                    'Input rendered in JavaScript context',
                    'HTML tag injection capability',
                    'Event handler injection (onerror, onload)',
                    'Stored XSS in database fields',
                    'DOM-based XSS in client-side scripts'
                ],
                'exploitation_steps': [
                    '1. Identify reflection points in response',
                    '2. Test with simple payloads (<script>alert(1)</script>)',
                    '3. Bypass filters with encoding/obfuscation',
                    '4. Test different contexts (HTML, JavaScript, attributes)',
                    '5. Attempt DOM XSS through URL fragments',
                    '6. Test for stored XSS in user profiles/comments',
                    '7. Escalate to session hijacking or defacement'
                ],
                'tools_recommended': [
                    'XSStrike - Advanced XSS detection',
                    'Browser DevTools for DOM analysis',
                    'Burp Suite Repeater for manual testing'
                ],
                'severity_indicators': {
                    'critical': 'Stored XSS with admin context',
                    'high': 'Reflected XSS with no filters',
                    'medium': 'Limited XSS with encoding'
                }
            },
            'COMMAND_INJECTION': {
                'what_to_look_for': [
                    'System command output in response',
                    'File system paths revealed',
                    'Process execution indicators',
                    'Time delays from sleep commands',
                    'DNS lookups to attacker domain',
                    'Out-of-band data exfiltration'
                ],
                'exploitation_steps': [
                    '1. Identify command execution points',
                    '2. Test command separators (;, |, &, &&, ||)',
                    '3. Execute simple commands (whoami, id, pwd)',
                    '4. Attempt file read (cat /etc/passwd)',
                    '5. Test time-based detection (sleep, ping)',
                    '6. Establish reverse shell if possible',
                    '7. Escalate privileges on compromised system'
                ],
                'tools_recommended': [
                    'Commix - Automated command injection tool',
                    'Netcat for reverse shells',
                    'Manual payload testing'
                ],
                'severity_indicators': {
                    'critical': 'Full RCE with shell access',
                    'high': 'Command execution confirmed',
                    'medium': 'Limited execution scope'
                }
            },
            'SSRF': {
                'what_to_look_for': [
                    'Internal IP addresses in responses',
                    'Cloud metadata endpoints accessible',
                    'Port scanning capabilities',
                    'DNS resolution of internal hosts',
                    'Response time differences',
                    'Redirect following behavior'
                ],
                'exploitation_steps': [
                    '1. Identify URL/hostname parameters',
                    '2. Test internal IP ranges (127.0.0.1, 192.168.x.x)',
                    '3. Access cloud metadata (169.254.169.254)',
                    '4. Scan internal ports',
                    '5. Attempt protocol smuggling (file://, gopher://)',
                    '6. Chain with other vulnerabilities',
                    '7. Access internal services and APIs'
                ],
                'tools_recommended': [
                    'SSRFmap - SSRF exploitation tool',
                    'Burp Collaborator for OOB detection',
                    'Custom payloads for cloud environments'
                ],
                'severity_indicators': {
                    'critical': 'Cloud metadata access or RCE',
                    'high': 'Internal network access',
                    'medium': 'Limited SSRF scope'
                }
            },
            'PATH_TRAVERSAL': {
                'what_to_look_for': [
                    'File contents in response',
                    'Directory listings',
                    'System files (/etc/passwd, win.ini)',
                    'Application configuration files',
                    'Source code disclosure',
                    'Log file access'
                ],
                'exploitation_steps': [
                    '1. Identify file/path parameters',
                    '2. Test basic traversal (../../etc/passwd)',
                    '3. Try encoding variations (%2e%2e%2f)',
                    '4. Test null byte injection (%00)',
                    '5. Access sensitive configuration files',
                    '6. Read application source code',
                    '7. Look for credentials in config files'
                ],
                'tools_recommended': [
                    'DotDotPwn - Path traversal fuzzer',
                    'Manual testing with Burp Suite',
                    'FIMap for file inclusion'
                ],
                'severity_indicators': {
                    'critical': 'Source code or credentials exposed',
                    'high': 'System file access',
                    'medium': 'Limited file read'
                }
            },
            'NOSQL_INJECTION': {
                'what_to_look_for': [
                    'MongoDB/NoSQL error messages',
                    'Authentication bypass success',
                    'Data extraction through operators',
                    'JavaScript evaluation in queries',
                    'Operator injection ($ne, $gt, $where)',
                    'Regex-based extraction'
                ],
                'exploitation_steps': [
                    '1. Identify NoSQL database usage',
                    '2. Test operator injection ({"$ne": null})',
                    '3. Attempt authentication bypass',
                    '4. Extract data using $regex',
                    '5. Test JavaScript injection in $where',
                    '6. Enumerate collections and fields',
                    '7. Extract sensitive data systematically'
                ],
                'tools_recommended': [
                    'NoSQLMap - NoSQL injection tool',
                    'Burp Suite for manual testing',
                    'Custom scripts for MongoDB'
                ],
                'severity_indicators': {
                    'critical': 'Full data extraction possible',
                    'high': 'Authentication bypass',
                    'medium': 'Limited injection scope'
                }
            },
            'BOLA': {
                'what_to_look_for': [
                    'ID parameters in URLs',
                    'UUID/GUID patterns',
                    'Sequential numeric IDs',
                    'Accessible objects from other users',
                    'Missing authorization checks',
                    'Different responses for valid vs invalid IDs'
                ],
                'exploitation_steps': [
                    '1. Identify endpoints with ID parameters',
                    '2. Authenticate as User A, note resource IDs',
                    '3. Authenticate as User B',
                    '4. Attempt to access User A\'s resources',
                    '5. Test with sequential/predictable IDs',
                    '6. Enumerate all accessible resources',
                    '7. Document unauthorized access'
                ],
                'tools_recommended': [
                    'Autorize Burp extension',
                    'Custom Python scripts for enumeration',
                    'Postman for API testing'
                ],
                'severity_indicators': {
                    'critical': 'Full unauthorized access to all objects',
                    'high': 'Access to sensitive user data',
                    'medium': 'Limited information disclosure'
                }
            },
            'XXE': {
                'what_to_look_for': [
                    'File contents in XML responses',
                    'SSRF through XML entities',
                    'Blind XXE with OOB exfiltration',
                    'Error messages with file paths',
                    'DTD processing enabled',
                    'XML parser configuration'
                ],
                'exploitation_steps': [
                    '1. Identify XML input acceptance',
                    '2. Test basic XXE payload (<!ENTITY xxe SYSTEM "file:///etc/passwd">)',
                    '3. Attempt file read',
                    '4. Test blind XXE with OOB callbacks',
                    '5. Try SSRF through XXE',
                    '6. Test parameter entity injection',
                    '7. Exfiltrate data via HTTP/DNS'
                ],
                'tools_recommended': [
                    'XXEinjector - XXE exploitation tool',
                    'Burp Collaborator for OOB testing',
                    'Manual XXE payloads'
                ],
                'severity_indicators': {
                    'critical': 'File read and SSRF combined',
                    'high': 'Direct file access',
                    'medium': 'Blind XXE only'
                }
            }
        }
        
        return guidance_database.get(
            vulnerability_type.upper(),
            {
                'what_to_look_for': ['Manual investigation required'],
                'exploitation_steps': ['Refer to OWASP guidelines'],
                'tools_recommended': ['Standard pentesting toolkit'],
                'severity_indicators': {}
            }
        )
    
    @staticmethod
    def generate_pentester_report(vulnerabilities: List[Dict], 
                                 statistics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive pentester report with actionable guidance."""
        
        # Group vulnerabilities by type
        vuln_by_type = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_type = vuln.get('category', '').upper()
            if 'SQL' in vuln_type or 'INJECTION' in vuln.get('title', '').upper():
                vuln_by_type['SQL_INJECTION'].append(vuln)
            elif 'XSS' in vuln_type or 'XSS' in vuln.get('title', '').upper():
                vuln_by_type['XSS'].append(vuln)
            elif 'COMMAND' in vuln_type:
                vuln_by_type['COMMAND_INJECTION'].append(vuln)
            elif 'SSRF' in vuln_type:
                vuln_by_type['SSRF'].append(vuln)
            elif 'PATH' in vuln_type or 'TRAVERSAL' in vuln_type:
                vuln_by_type['PATH_TRAVERSAL'].append(vuln)
            elif 'NOSQL' in vuln_type:
                vuln_by_type['NOSQL_INJECTION'].append(vuln)
            elif 'BOLA' in vuln_type or 'AUTHORIZATION' in vuln_type:
                vuln_by_type['BOLA'].append(vuln)
            elif 'XXE' in vuln_type:
                vuln_by_type['XXE'].append(vuln)
        
        # Generate guidance for each vulnerability type found
        detailed_guidance = {}
        for vuln_type, vulns in vuln_by_type.items():
            guidance = PentesterGuidance.get_vulnerability_guidance(vuln_type)
            detailed_guidance[vuln_type] = {
                'count': len(vulns),
                'affected_endpoints': list(set(v.get('endpoint', '') for v in vulns)),
                'guidance': guidance,
                'examples': vulns[:3]  # Show first 3 examples
            }
        
        return {
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'unique_vulnerability_types': len(vuln_by_type),
                'testing_duration': statistics.get('timing_stats', {}).get('total_duration_formatted', 'Unknown'),
                'endpoints_tested': statistics.get('coverage_stats', {}).get('endpoints_tested', 0),
                'overall_risk_score': statistics.get('risk_metrics', {}).get('overall_api_risk_score', 0)
            },
            'prioritized_vulnerabilities': {
                'critical': [v for v in vulnerabilities if v.get('severity') == 'critical'],
                'high': [v for v in vulnerabilities if v.get('severity') == 'high'],
                'medium': [v for v in vulnerabilities if v.get('severity') == 'medium']
            },
            'attack_vectors': detailed_guidance,
            'pentester_recommendations': PentesterGuidance._generate_recommendations(vulnerabilities),
            'next_steps': PentesterGuidance._generate_next_steps(vuln_by_type)
        }
    
    @staticmethod
    def _generate_recommendations(vulnerabilities: List[Dict]) -> List[str]:
        """Generate actionable recommendations for pentesters."""
        recommendations = []
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        if severity_counts['critical'] > 0:
            recommendations.append(
                f"URGENT: {severity_counts['critical']} critical vulnerabilities found. "
                "Prioritize testing command injection, RCE, and authentication bypass."
            )
        
        if severity_counts['high'] > 3:
            recommendations.append(
                f"Focus manual testing on {severity_counts['high']} high-severity issues. "
                "These are likely exploitable and should be validated manually."
            )
        
        recommendations.append(
            "Review all injection vulnerabilities manually to confirm exploitability and impact."
        )
        
        recommendations.append(
            "Document all findings with proof-of-concept payloads for remediation teams."
        )
        
        return recommendations
    
    @staticmethod
    def _generate_next_steps(vuln_by_type: Dict[str, List]) -> List[str]:
        """Generate next steps for the pentester."""
        steps = []
        
        if 'SQL_INJECTION' in vuln_by_type:
            steps.append("1. Use sqlmap to fully exploit SQL injection vulnerabilities")
        
        if 'COMMAND_INJECTION' in vuln_by_type or 'RCE' in vuln_by_type:
            steps.append("2. Attempt to establish reverse shell on vulnerable endpoints")
        
        if 'BOLA' in vuln_by_type:
            steps.append("3. Enumerate all user objects to assess full BOLA impact")
        
        if 'SSRF' in vuln_by_type:
            steps.append("4. Test SSRF against cloud metadata and internal services")
        
        steps.append("5. Perform manual validation of all automated findings")
        steps.append("6. Test for privilege escalation possibilities")
        steps.append("7. Document exploitation chains combining multiple vulnerabilities")
        
        return steps

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
import uuid
from enum import Enum
from pathlib import Path
import logging

from sqlalchemy import Column, String, DateTime, Integer, Text, JSON, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine

Base = declarative_base()

class TestSessionStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class TestSession(Base):
    __tablename__ = "test_sessions"
    
    id = Column(String, primary_key=True)
    spec_id = Column(String, nullable=False)
    status = Column(String, nullable=False)
    config = Column(JSON, nullable=False)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime)
    duration_seconds = Column(Float)
    total_tests_run = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    vulnerabilities_critical = Column(Integer, default=0)
    vulnerabilities_high = Column(Integer, default=0)
    vulnerabilities_medium = Column(Integer, default=0)
    vulnerabilities_low = Column(Integer, default=0)
    vulnerabilities_info = Column(Integer, default=0)
    coverage_stats = Column(JSON)
    metadata = Column(JSON)
    error_message = Column(Text)

class VulnerabilityResult(Base):
    __tablename__ = "vulnerability_results"
    
    id = Column(String, primary_key=True)
    session_id = Column(String, nullable=False)
    detector_name = Column(String, nullable=False)
    vulnerability_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    endpoint = Column(String, nullable=False)
    method = Column(String, nullable=False)
    cwe_id = Column(String)
    owasp_category = Column(String)
    cvss_score = Column(Float)
    evidence = Column(JSON)
    remediation = Column(Text)
    false_positive_likelihood = Column(Float)
    exploit_difficulty = Column(String)  # easy, medium, hard
    business_impact = Column(Text)
    discovered_at = Column(DateTime, nullable=False)

@dataclass
class CoverageStats:
    endpoints_tested: int
    endpoints_total: int
    endpoints_coverage_percentage: float
    methods_tested: Dict[str, int]
    auth_methods_tested: List[str]
    parameters_tested: int
    response_codes_seen: List[int]
    test_duration_seconds: float

@dataclass 
class VulnerabilityStats:
    total: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    by_detector: Dict[str, int]
    by_endpoint: Dict[str, int]
    false_positive_count: int
    exploitable_count: int

@dataclass
class TestSummary:
    session_id: str
    test_status: str
    start_time: datetime
    end_time: Optional[datetime]
    duration: Optional[timedelta]
    spec_title: str
    spec_version: str
    endpoints_tested: int
    total_requests_made: int
    vulnerabilities: VulnerabilityStats
    coverage: CoverageStats
    risk_score: float  # 0-100
    compliance_status: Dict[str, bool]  # OWASP compliance checks

class ResultAnalyzer:
    """Analyzes test results and generates comprehensive reports"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.logger = logging.getLogger(__name__)
    
    def generate_test_summary(self, session_id: str) -> Optional[TestSummary]:
        """Generate comprehensive test summary"""
        try:
            # Get test session
            session = self.db.query(TestSession).filter(
                TestSession.id == session_id
            ).first()
            
            if not session:
                return None
            
            # Get vulnerabilities
            vulnerabilities = self.db.query(VulnerabilityResult).filter(
                VulnerabilityResult.session_id == session_id
            ).all()
            
            # Calculate vulnerability statistics
            vuln_stats = self._calculate_vulnerability_stats(vulnerabilities)
            
            # Calculate coverage statistics
            coverage_stats = self._parse_coverage_stats(session.coverage_stats or {})
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(vulnerabilities, coverage_stats)
            
            # Check OWASP compliance
            compliance_status = self._check_owasp_compliance(vulnerabilities)
            
            return TestSummary(
                session_id=session.id,
                test_status=session.status,
                start_time=session.started_at,
                end_time=session.completed_at,
                duration=timedelta(seconds=session.duration_seconds or 0),
                spec_title=session.metadata.get('spec_title', 'Unknown'),
                spec_version=session.metadata.get('spec_version', 'Unknown'),
                endpoints_tested=coverage_stats.endpoints_tested,
                total_requests_made=session.metadata.get('total_requests', 0),
                vulnerabilities=vuln_stats,
                coverage=coverage_stats,
                risk_score=risk_score,
                compliance_status=compliance_status
            )
            
        except Exception as e:
            self.logger.error(f"Error generating test summary: {e}")
            return None
    
    def _calculate_vulnerability_stats(self, vulnerabilities: List[VulnerabilityResult]) -> VulnerabilityStats:
        """Calculate detailed vulnerability statistics"""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_type = {}
        by_detector = {}
        by_endpoint = {}
        false_positive_count = 0
        exploitable_count = 0
        
        for vuln in vulnerabilities:
            # Severity breakdown
            by_severity[vuln.severity] += 1
            
            # Type breakdown
            vuln_type = vuln.vulnerability_type
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
            
            # Detector breakdown
            detector = vuln.detector_name
            by_detector[detector] = by_detector.get(detector, 0) + 1
            
            # Endpoint breakdown
            endpoint = f"{vuln.method} {vuln.endpoint}"
            by_endpoint[endpoint] = by_endpoint.get(endpoint, 0) + 1
            
            # False positive detection
            if vuln.false_positive_likelihood and vuln.false_positive_likelihood > 0.7:
                false_positive_count += 1
            
            # Exploitable vulnerabilities
            if vuln.exploit_difficulty in ["easy", "medium"] and vuln.severity in ["critical", "high"]:
                exploitable_count += 1
        
        return VulnerabilityStats(
            total=len(vulnerabilities),
            by_severity=by_severity,
            by_type=by_type,
            by_detector=by_detector,
            by_endpoint=by_endpoint,
            false_positive_count=false_positive_count,
            exploitable_count=exploitable_count
        )
    
    def _parse_coverage_stats(self, coverage_data: Dict) -> CoverageStats:
        """Parse coverage statistics from test session data"""
        return CoverageStats(
            endpoints_tested=coverage_data.get('endpoints_tested', 0),
            endpoints_total=coverage_data.get('endpoints_total', 0),
            endpoints_coverage_percentage=coverage_data.get('coverage_percentage', 0.0),
            methods_tested=coverage_data.get('methods_tested', {}),
            auth_methods_tested=coverage_data.get('auth_methods_tested', []),
            parameters_tested=coverage_data.get('parameters_tested', 0),
            response_codes_seen=coverage_data.get('response_codes_seen', []),
            test_duration_seconds=coverage_data.get('test_duration_seconds', 0.0)
        )
    
    def _calculate_risk_score(self, vulnerabilities: List[VulnerabilityResult], coverage: CoverageStats) -> float:
        """Calculate overall risk score (0-100)"""
        if not vulnerabilities:
            return 0.0
        
        # Severity weights
        severity_weights = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10
        }
        
        # Calculate weighted vulnerability score
        total_score = 0
        for vuln in vulnerabilities:
            base_score = severity_weights.get(vuln.severity, 0)
            
            # Adjust for exploitability
            if vuln.exploit_difficulty == "easy":
                base_score *= 1.5
            elif vuln.exploit_difficulty == "medium":
                base_score *= 1.2
            
            # Adjust for false positive likelihood
            if vuln.false_positive_likelihood:
                base_score *= (1 - vuln.false_positive_likelihood)
            
            total_score += base_score
        
        # Normalize by coverage (more coverage = more confidence in score)
        coverage_factor = min(1.0, coverage.endpoints_coverage_percentage / 100.0)
        if coverage_factor < 0.5:
            total_score *= 0.8  # Reduce confidence for low coverage
        
        # Cap at 100 and normalize
        risk_score = min(100.0, total_score / len(vulnerabilities))
        return round(risk_score, 2)
    
    def _check_owasp_compliance(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, bool]:
        """Check compliance against OWASP API Top 10 categories"""
        owasp_categories = [
            "API1:2023 Broken Object Level Authorization",
            "API2:2023 Broken Authentication", 
            "API3:2023 Broken Object Property Level Authorization",
            "API4:2023 Unrestricted Resource Consumption",
            "API5:2023 Broken Function Level Authorization",
            "API6:2023 Unrestricted Access to Sensitive Business Flows",
            "API7:2023 Server Side Request Forgery",
            "API8:2023 Security Misconfiguration",
            "API9:2023 Improper Inventory Management",
            "API10:2023 Unsafe Consumption of APIs"
        ]
        
        # Check if any vulnerabilities exist for each OWASP category
        compliance_status = {}
        for category in owasp_categories:
            has_vulnerabilities = any(
                vuln.owasp_category == category and vuln.severity in ["critical", "high"]
                for vuln in vulnerabilities
            )
            compliance_status[category] = not has_vulnerabilities  # Compliant if no critical/high vulns
        
        return compliance_status
    
    def get_vulnerability_trends(self, spec_id: str, days: int = 30) -> Dict[str, List]:
        """Get vulnerability trends over time for a specific API spec"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        sessions = self.db.query(TestSession).filter(
            TestSession.spec_id == spec_id,
            TestSession.started_at >= cutoff_date,
            TestSession.status == "completed"
        ).order_by(TestSession.started_at).all()
        
        trends = {
            "dates": [],
            "total_vulnerabilities": [],
            "critical_vulnerabilities": [],
            "high_vulnerabilities": [],
            "risk_scores": []
        }
        
        for session in sessions:
            trends["dates"].append(session.started_at.isoformat())
            trends["total_vulnerabilities"].append(session.total_vulnerabilities)
            trends["critical_vulnerabilities"].append(session.vulnerabilities_critical)
            trends["high_vulnerabilities"].append(session.vulnerabilities_high)
            
            # Calculate risk score for this session
            vulns = self.db.query(VulnerabilityResult).filter(
                VulnerabilityResult.session_id == session.id
            ).all()
            coverage_stats = self._parse_coverage_stats(session.coverage_stats or {})
            risk_score = self._calculate_risk_score(vulns, coverage_stats)
            trends["risk_scores"].append(risk_score)
        
        return trends
    
    def generate_detailed_findings(self, session_id: str) -> List[Dict[str, Any]]:
        """Generate detailed findings with evidence and remediation"""
        vulnerabilities = self.db.query(VulnerabilityResult).filter(
            VulnerabilityResult.session_id == session_id
        ).order_by(VulnerabilityResult.severity.desc(), VulnerabilityResult.cvss_score.desc()).all()
        
        findings = []
        for vuln in vulnerabilities:
            finding = {
                "id": vuln.id,
                "title": vuln.title,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "description": vuln.description,
                "location": {
                    "endpoint": vuln.endpoint,
                    "method": vuln.method
                },
                "classification": {
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "vulnerability_type": vuln.vulnerability_type
                },
                "evidence": vuln.evidence,
                "remediation": vuln.remediation,
                "business_impact": vuln.business_impact,
                "exploit_difficulty": vuln.exploit_difficulty,
                "false_positive_likelihood": vuln.false_positive_likelihood,
                "discovered_at": vuln.discovered_at.isoformat()
            }
            findings.append(finding)
        
        return findings

class ResultStorage:
    """Handles storage and retrieval of test results"""
    
    def __init__(self, database_url: str = "sqlite:///test_results.db"):
        self.engine = create_engine(database_url)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.logger = logging.getLogger(__name__)
    
    def get_session(self) -> Session:
        return self.SessionLocal()
    
    def store_test_session(self, session_id: str, spec_id: str, config: Dict, metadata: Dict = None) -> TestSession:
        """Create and store a new test session"""
        with self.get_session() as db:
            test_session = TestSession(
                id=session_id,
                spec_id=spec_id,
                status=TestSessionStatus.QUEUED.value,
                config=config,
                started_at=datetime.now(),
                metadata=metadata or {}
            )
            db.add(test_session)
            db.commit()
            db.refresh(test_session)
            return test_session
    
    def update_test_session_status(self, session_id: str, status: TestSessionStatus, **kwargs):
        """Update test session status and optional fields"""
        with self.get_session() as db:
            session = db.query(TestSession).filter(TestSession.id == session_id).first()
            if session:
                session.status = status.value
                
                if status == TestSessionStatus.COMPLETED:
                    session.completed_at = datetime.now()
                    session.duration_seconds = (session.completed_at - session.started_at).total_seconds()
                
                for key, value in kwargs.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
                
                db.commit()
    
    def store_vulnerability(self, session_id: str, vulnerability_data: Dict) -> VulnerabilityResult:
        """Store a discovered vulnerability"""
        with self.get_session() as db:
            vuln = VulnerabilityResult(
                id=str(uuid.uuid4()),
                session_id=session_id,
                discovered_at=datetime.now(),
                **vulnerability_data
            )
            db.add(vuln)
            db.commit()
            db.refresh(vuln)
            return vuln
    
    def get_test_results(self, session_id: str) -> Optional[Dict]:
        """Get complete test results for a session"""
        with self.get_session() as db:
            analyzer = ResultAnalyzer(db)
            summary = analyzer.generate_test_summary(session_id)
            
            if not summary:
                return None
            
            findings = analyzer.generate_detailed_findings(session_id)
            
            return {
                "summary": asdict(summary),
                "findings": findings,
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "report_version": "1.0"
                }
            }
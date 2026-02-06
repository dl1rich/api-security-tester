import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Typography,
  Card,
  CardContent,
  Box,
  Button,
  Alert,
  Grid,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  CircularProgress,
  Breadcrumbs,
  Link,
  Menu,
  MenuItem,
} from '@mui/material';
import {
  Assessment,
  Security,
  Warning,
  Error,
  Info,
  CheckCircle,
  Download,
  Share,
  Visibility,
  ArrowBack,
  FileDownload,
  MoreVert,
} from '@mui/icons-material';
import toast from 'react-hot-toast';

interface TestResults {
  session_id: string;
  spec_id: string;
  test_config?: any;
  status: string;
  started_at: string;
  completed_at?: string;
  duration_seconds: number;
  total_vulnerabilities: number;
  vulnerabilities_by_severity: Record<string, number>;
  vulnerabilities: Vulnerability[];
  coverage_stats: CoverageStats;
  summary: string;
  metadata: any;
}

interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss_score?: number;
  description: string;
  endpoint: string;
  method: string;
  cwe_id?: string;
  owasp_category?: string;
  evidence?: any;
  remediation?: string;
  discovered_at: string;
}

interface CoverageStats {
  endpoints_tested: number;
  total_endpoints: number;
  coverage_percentage: number;
  methods_tested: Record<string, number>;
  auth_methods_tested: string[];
  parameters_tested: number;
}

interface ExecutiveSummary {
  api_name: string;
  test_date: string;
  overall_risk_level: string;
  risk_score: number;
  total_vulnerabilities: number;
  critical_high_vulnerabilities: number;
  coverage_percentage: number;
  test_duration_hours: number;
  key_findings: string[];
  remediation_priority: string[];
  business_impact: string;
  compliance_status: Record<string, boolean>;
  next_steps: string[];
}

const ResultsPage: React.FC = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  
  const [results, setResults] = useState<TestResults | null>(null);
  const [executiveSummary, setExecutiveSummary] = useState<ExecutiveSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);

  useEffect(() => {
    if (sessionId) {
      loadTestResults();
      loadExecutiveSummary();
    } else {
      // List all test sessions
      loadTestSessions();
    }
  }, [sessionId]);

  const loadTestResults = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/reports/test/${sessionId}`);
      if (!response.ok) {
        throw new window.Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setResults(data);
    } catch (err) {
      console.error('Error loading test results:', err);
      setError('Failed to load test results');
      toast.error('Failed to load test results');
    } finally {
      setLoading(false);
    }
  };

  const loadExecutiveSummary = async () => {
    try {
      const response = await fetch(`/api/reports/test/${sessionId}/executive`);
      if (response.ok) {
        const data = await response.json();
        setExecutiveSummary(data);
      }
    } catch (err) {
      console.error('Error loading executive summary:', err);
    }
  };

  const loadTestSessions = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/reports/sessions');
      if (response.ok) {
        const data = await response.json();
        // Handle list of sessions - redirect to most recent or show selection
        if (data.sessions.length > 0) {
          navigate(`/results/${data.sessions[0].session_id}`);
        }
      }
    } catch (err) {
      console.error('Error loading test sessions:', err);
      setError('Failed to load test sessions');
    } finally {
      setLoading(false);
    }
  };

  const handleExportClick = (event: React.MouseEvent<HTMLElement>) => {
    setExportMenuAnchor(event.currentTarget);
  };

  const handleExportClose = () => {
    setExportMenuAnchor(null);
  };

  const handleExport = async (format: string) => {
    if (!sessionId) return;
    
    try {
      const response = await fetch(`/api/reports/test/${sessionId}/export/${format}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${sessionId}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        toast.success(`Report exported as ${format.toUpperCase()}`);
      } else {
        throw new window.Error('Export failed');
      }
    } catch (err) {
      console.error('Export error:', err);
      toast.error(`Failed to export as ${format.toUpperCase()}`);
    }
    handleExportClose();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <Error />;
      case 'high': return <Warning />;
      case 'medium': return <Info />;
      case 'low': return <CheckCircle />;
      default: return <Info />;
    }
  };

  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#1976d2';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  };

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  if (error || !results) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">
          {error || 'Test results not found'}
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      {/* Breadcrumb Navigation */}
      <Box sx={{ mb: 3 }}>
        <Breadcrumbs aria-label="breadcrumb">
          <Link
            color="inherit"
            href="#"
            onClick={(e) => {
              e.preventDefault();
              navigate('/');
            }}
            sx={{ textDecoration: 'none' }}
          >
            Home
          </Link>
          <Link
            color="inherit"
            href="#"
            onClick={(e) => {
              e.preventDefault();
              navigate('/testing');
            }}
            sx={{ textDecoration: 'none' }}
          >
            Testing
          </Link>
          <Typography color="text.primary">
            Results
          </Typography>
        </Breadcrumbs>
      </Box>

      {/* Header */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box>
              <Typography variant="h4" gutterBottom>
                <Assessment sx={{ mr: 2, verticalAlign: 'middle' }} />
                Security Test Results
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Session: {results.session_id} • Status: {results.status}
                {results.completed_at && ` • Completed: ${new Date(results.completed_at).toLocaleString()}`}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', gap: 2 }}>
              <Button
                variant="outlined"
                startIcon={<ArrowBack />}
                onClick={() => navigate('/testing')}
              >
                Back to Testing
              </Button>
              <IconButton onClick={handleExportClick}>
                <FileDownload />
              </IconButton>
            </Box>
          </Box>
        </CardContent>
      </Card>

      {/* Export Menu */}
      <Menu
        anchorEl={exportMenuAnchor}
        open={Boolean(exportMenuAnchor)}
        onClose={handleExportClose}
      >
        <MenuItem onClick={() => handleExport('json')}>Export as JSON</MenuItem>
        <MenuItem onClick={() => handleExport('csv')}>Export as CSV</MenuItem>
        <MenuItem onClick={() => handleExport('xml')}>Export as XML</MenuItem>
        <MenuItem onClick={() => handleExport('html')}>Export as HTML</MenuItem>
        <MenuItem onClick={() => handleExport('pdf')}>Export as PDF</MenuItem>
      </Menu>

      {/* Executive Summary Card */}
      {executiveSummary && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Executive Summary
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={3}>
                <Box textAlign="center">
                  <Typography variant="h3" sx={{ color: getRiskLevelColor(executiveSummary.overall_risk_level) }}>
                    {executiveSummary.risk_score}
                  </Typography>
                  <Typography variant="subtitle1">Risk Score</Typography>
                  <Chip 
                    label={executiveSummary.overall_risk_level} 
                    color={getSeverityColor(executiveSummary.overall_risk_level.toLowerCase()) as any}
                    size="small"
                  />
                </Box>
              </Grid>
              <Grid item xs={12} md={9}>
                <Typography variant="body2" paragraph>
                  {executiveSummary.business_impact}
                </Typography>
                <Typography variant="subtitle2" gutterBottom>Key Findings:</Typography>
                <List dense>
                  {executiveSummary.key_findings.slice(0, 3).map((finding, index) => (
                    <ListItem key={index} sx={{ py: 0 }}>
                      <ListItemIcon sx={{ minWidth: 30 }}>
                        <Warning fontSize="small" color="warning" />
                      </ListItemIcon>
                      <ListItemText primary={finding} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Statistics Overview */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="primary">
                {results.total_vulnerabilities}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total Vulnerabilities
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="success.main">
                {results.coverage_stats.coverage_percentage.toFixed(1)}%
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Endpoint Coverage
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="info.main">
                {Math.round(results.duration_seconds / 60)}m
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Test Duration
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="error.main">
                {(results.vulnerabilities_by_severity.critical || 0) + (results.vulnerabilities_by_severity.high || 0)}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Critical/High
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Detailed Results Tabs */}
      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={activeTab} onChange={(_, newValue) => setActiveTab(newValue)}>
            <Tab label="Vulnerabilities" />
            <Tab label="Coverage Analysis" />
            <Tab label="Executive Summary" />
            <Tab label="Technical Details" />
          </Tabs>
        </Box>

        <CardContent>
          {/* Vulnerabilities Tab */}
          {activeTab === 0 && (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Severity</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Endpoint</TableCell>
                    <TableCell>OWASP Category</TableCell>
                    <TableCell>CVSS</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {results.vulnerabilities.map((vuln) => (
                    <TableRow key={vuln.id} hover>
                      <TableCell>
                        <Chip
                          icon={getSeverityIcon(vuln.severity)}
                          label={vuln.severity.toUpperCase()}
                          color={getSeverityColor(vuln.severity) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {vuln.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace">
                          {vuln.method} {vuln.endpoint}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {vuln.owasp_category || 'N/A'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {vuln.cvss_score ? vuln.cvss_score.toFixed(1) : 'N/A'}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          {/* Coverage Analysis Tab */}
          {activeTab === 1 && (
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Endpoint Coverage</Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {results.coverage_stats.endpoints_tested} of {results.coverage_stats.total_endpoints} endpoints tested 
                  ({results.coverage_stats.coverage_percentage.toFixed(1)}% coverage)
                </Typography>
                
                <Typography variant="subtitle2" gutterBottom>Methods Tested:</Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {Object.entries(results.coverage_stats.methods_tested).map(([method, count]) => (
                    <Chip key={method} label={`${method}: ${count}`} variant="outlined" size="small" />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Authentication Methods</Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {results.coverage_stats.auth_methods_tested.map((method) => (
                    <Chip key={method} label={method} color="primary" variant="outlined" size="small" />
                  ))}
                </Box>
                
                <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                  Parameters Tested: {results.coverage_stats.parameters_tested}
                </Typography>
              </Grid>
            </Grid>
          )}

          {/* Executive Summary Tab */}
          {activeTab === 2 && executiveSummary && (
            <Grid container spacing={3}>
              <Grid item xs={12} md={8}>
                <Typography variant="h6" gutterBottom>Business Impact Assessment</Typography>
                <Typography variant="body1" paragraph>
                  {executiveSummary.business_impact}
                </Typography>
                
                <Typography variant="h6" gutterBottom>Key Findings</Typography>
                <List>
                  {executiveSummary.key_findings.map((finding, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <Security color="primary" />
                      </ListItemIcon>
                      <ListItemText primary={finding} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="h6" gutterBottom>Recommended Next Steps</Typography>
                <List>
                  {executiveSummary.next_steps.map((step, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText primary={step} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          )}

          {/* Technical Details Tab */}
          {activeTab === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>Test Configuration</Typography>
              <Paper elevation={1} sx={{ p: 2, mb: 2, bgcolor: 'grey.50' }}>
                <Typography variant="body2" component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                  {JSON.stringify(results.test_config || {}, null, 2)}
                </Typography>
              </Paper>
              
              <Typography variant="h6" gutterBottom>Test Summary</Typography>
              <Typography variant="body1">
                {results.summary}
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

export default ResultsPage;
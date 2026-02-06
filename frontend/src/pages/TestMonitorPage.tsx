import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Box,
  Button,
  Typography,
  Alert,
  Card,
  CardContent,
  Breadcrumbs,
  Link,
} from '@mui/material';
import { ArrowBack, Visibility } from '@mui/icons-material';
import TestMonitor from '../components/TestMonitor';

const TestMonitorPage: React.FC = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  const [testCompleted, setTestCompleted] = useState(false);
  const [testResults, setTestResults] = useState<any>(null);

  useEffect(() => {
    if (!sessionId) {
      navigate('/testing');
    }
  }, [sessionId, navigate]);

  const handleTestComplete = (results: any) => {
    setTestCompleted(true);
    setTestResults(results);
  };

  const handleViewResults = () => {
    if (sessionId) {
      navigate(`/results/${sessionId}`);
    }
  };

  const handleBackToTesting = () => {
    navigate('/testing');
  };

  if (!sessionId) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">
          Invalid test session ID. Please start a new test.
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ py: 2 }}>
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
            Monitor Test Session
          </Typography>
        </Breadcrumbs>
      </Box>

      {/* Header */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box>
              <Typography variant="h4" gutterBottom>
                Test Session Monitor
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Real-time monitoring of API security testing for session: {sessionId}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', gap: 2 }}>
              <Button
                variant="outlined"
                startIcon={<ArrowBack />}
                onClick={handleBackToTesting}
              >
                Back to Testing
              </Button>
              {testCompleted && (
                <Button
                  variant="contained"
                  startIcon={<Visibility />}
                  onClick={handleViewResults}
                  color="primary"
                >
                  View Results
                </Button>
              )}
            </Box>
          </Box>
        </CardContent>
      </Card>

      {/* Test Completion Alert */}
      {testCompleted && (
        <Alert 
          severity="success" 
          sx={{ mb: 3 }}
          action={
            <Button color="inherit" size="small" onClick={handleViewResults}>
              VIEW RESULTS
            </Button>
          }
        >
          Test completed successfully! {testResults?.totalVulnerabilities 
            ? `Found ${testResults.totalVulnerabilities} vulnerabilities.` 
            : 'No vulnerabilities found.'}
        </Alert>
      )}

      {/* Test Monitor Component */}
      <TestMonitor 
        sessionId={sessionId} 
        onTestComplete={handleTestComplete}
      />
    </Container>
  );
};

export default TestMonitorPage;
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Typography,
  Card,
  CardContent,
  Box,
  Button,
  Alert,
  FormControl,
  FormControlLabel,
  FormGroup,
  FormLabel,
  Checkbox,
  TextField,
  Select,
  MenuItem,
  Grid,
  CircularProgress,
  Chip,
  Breadcrumbs,
  Link,
} from '@mui/material';
import { PlayArrow, Security, Settings } from '@mui/icons-material';
import toast from 'react-hot-toast';
import { ApiSpec, TestConfiguration, TestStartResponse } from '../types';
import { ApiService } from '../services/api';

const TestingPage: React.FC = () => {
  const navigate = useNavigate();
  const [currentSpec, setCurrentSpec] = useState<ApiSpec | null>(null);
  const [isStartingTest, setIsStartingTest] = useState(false);
  const [testConfig, setTestConfig] = useState<TestConfiguration>({
    spec_id: '',
    test_modules: ['owasp_top10', 'auth_bypass', 'injection', 'data_exposure'],
    auth_handling: 'preserve_roles',
    test_intensity: 'medium',
    concurrent_requests: 5,
    timeout_seconds: 30,
  });

  const availableTestModules = [
    { id: 'owasp_top10', label: 'OWASP API Top 10 (2023)', description: 'Comprehensive OWASP testing' },
    { id: 'auth_bypass', label: 'Authentication Bypass', description: 'Authorization and authentication flaws' },
    { id: 'injection', label: 'Injection Attacks', description: 'SQL, NoSQL, Command injection tests' },
    { id: 'data_exposure', label: 'Data Exposure', description: 'Sensitive data leakage detection' },
    { id: 'rate_limiting', label: 'Rate Limiting', description: 'Rate limiting and DoS protection' },
    { id: 'input_validation', label: 'Input Validation', description: 'Input validation and sanitization' },
    { id: 'business_logic', label: 'Business Logic', description: 'Business logic vulnerabilities' },
    { id: 'security_headers', label: 'Security Headers', description: 'Missing security headers' },
  ];

  useEffect(() => {
    // Load current spec from localStorage or API
    const savedSpec = localStorage.getItem('currentApiSpec');
    if (savedSpec) {
      const spec = JSON.parse(savedSpec);
      setCurrentSpec(spec);
      setTestConfig(prev => ({ ...prev, spec_id: spec.id }));
    }
  }, []);

  const handleTestModuleChange = (moduleId: string) => {
    setTestConfig(prev => ({
      ...prev,
      test_modules: prev.test_modules.includes(moduleId)
        ? prev.test_modules.filter(m => m !== moduleId)
        : [...prev.test_modules, moduleId],
    }));
  };

  const handleStartTest = async () => {
    if (!currentSpec) {
      toast.error('Please upload an API specification first');
      return;
    }

    if (testConfig.test_modules.length === 0) {
      toast.error('Please select at least one test module');
      return;
    }

    setIsStartingTest(true);

    try {
      const result = await ApiService.startSecurityTest(testConfig);
      
      if (result.success) {
        toast.success('Test session started successfully!');
        // Navigate to the test monitor page
        navigate(`/testing/monitor/${result.test_session_id}`);
      } else {
        toast.error(result.message || 'Failed to start test session');
      }
    } catch (error: any) {
      console.error('Error starting test:', error);
      toast.error(error.response?.data?.detail || 'Failed to start test session. Please try again.');
    } finally {
      setIsStartingTest(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 3 }}>
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
          <Typography color="text.primary">
            Security Testing
          </Typography>
        </Breadcrumbs>
      </Box>

      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          <Security sx={{ mr: 2, verticalAlign: 'middle' }} />
          API Security Testing
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Perform OFFLINE security analysis of your API specification - no live requests made
        </Typography>
      </Box>

      {/* Current API Spec Info */}
      {currentSpec ? (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Current API Specification
            </Typography>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} sm={8}>
                <Typography variant="body1">
                  <strong>{currentSpec.title}</strong> v{currentSpec.version}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {currentSpec.endpoint_count} endpoints • {currentSpec.auth_methods.join(', ')} auth
                  {currentSpec.source_url && ` • Source: ${currentSpec.source_url}`}
                </Typography>
              </Grid>
              <Grid item xs={12} sm={4}>
                <Chip 
                  label={currentSpec.spec_version} 
                  color="primary" 
                  variant="outlined"
                  size="small"
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      ) : (
        <Alert severity="warning" sx={{ mb: 3 }}>
          No API specification loaded. Please{' '}
          <Link href="#" onClick={(e) => { e.preventDefault(); navigate('/'); }}>
            upload a specification
          </Link>{' '}
          first.
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Test Configuration */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <Settings sx={{ mr: 1, verticalAlign: 'middle' }} />
                Analysis Configuration
              </Typography>
              
              <Alert severity="info" sx={{ mb: 3 }}>
                This tool analyzes your API specification for security vulnerabilities without making any HTTP requests.
                All findings are based on static analysis of the API design.
              </Alert>

              {/* Test Modules */}
              <FormControl component="fieldset" sx={{ mb: 3, width: '100%' }}>
                <FormLabel component="legend">Security Checks</FormLabel>
                <FormGroup>
                  {availableTestModules.map((module) => (
                    <FormControlLabel
                      key={module.id}
                      control={
                        <Checkbox
                          checked={testConfig.test_modules.includes(module.id)}
                          onChange={() => handleTestModuleChange(module.id)}
                        />
                      }
                      label={
                        <Box>
                          <Typography variant="body2">{module.label}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {module.description}
                          </Typography>
                        </Box>
                      }
                    />
                  ))}
                </FormGroup>
              </FormControl>

              {/* Authentication Handling */}
              <FormControl fullWidth sx={{ mb: 3 }}>
                <FormLabel>Authentication Handling</FormLabel>
                <Select
                  value={testConfig.auth_handling}
                  onChange={(e) => setTestConfig(prev => ({ 
                    ...prev, 
                    auth_handling: e.target.value as any 
                  }))}
                >
                  <MenuItem value="preserve_roles">Preserve User Roles</MenuItem>
                  <MenuItem value="bypass_all">Attempt Auth Bypass</MenuItem>
                  <MenuItem value="custom">Custom Role Testing</MenuItem>
                </Select>
              </FormControl>
              {/* Target Base URL */}
              <TextField
                fullWidth
                label="Target API Base URL (Optional)"
                placeholder="https://api.example.com"
                value={testConfig.target_base_url || ''}
                onChange={(e) => setTestConfig(prev => ({ 
                  ...prev, 
                  target_base_url: e.target.value || undefined 
                }))}
                sx={{ mb: 3 }}
                helperText="Leave empty for spec analysis only. Provide URL for live vulnerability testing."
              />
              {/* Test Intensity */}
              <FormControl fullWidth sx={{ mb: 3 }}>
                <FormLabel>Test Intensity</FormLabel>
                <Select
                  value={testConfig.test_intensity}
                  onChange={(e) => setTestConfig(prev => ({ 
                    ...prev, 
                    test_intensity: e.target.value as any 
                  }))}
                >
                  <MenuItem value="low">Low - Basic checks</MenuItem>
                  <MenuItem value="medium">Medium - Balanced testing</MenuItem>
                  <MenuItem value="high">High - Comprehensive analysis</MenuItem>
                </Select>
              </FormControl>

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <TextField
                    fullWidth
                    label="Concurrent Requests"
                    type="number"
                    value={testConfig.concurrent_requests}
                    onChange={(e) => setTestConfig(prev => ({ 
                      ...prev, 
                      concurrent_requests: parseInt(e.target.value) || 5 
                    }))}
                    inputProps={{ min: 1, max: 20 }}
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    fullWidth
                    label="Timeout (seconds)"
                    type="number"
                    value={testConfig.timeout_seconds}
                    onChange={(e) => setTestConfig(prev => ({ 
                      ...prev, 
                      timeout_seconds: parseInt(e.target.value) || 30 
                    }))}
                    inputProps={{ min: 5, max: 300 }}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Start Test Panel */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Start Security Test
              </Typography>
              
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Selected modules: {testConfig.test_modules.length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Intensity: {testConfig.test_intensity}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Estimated duration: ~15-45 minutes
                </Typography>
              </Box>

              <Button
                fullWidth
                variant="contained"
                size="large"
                startIcon={isStartingTest ? <CircularProgress size={20} /> : <PlayArrow />}
                onClick={handleStartTest}
                disabled={!currentSpec || testConfig.test_modules.length === 0 || isStartingTest}
                sx={{ mb: 2 }}
              >
                {isStartingTest ? 'Starting Test...' : 'Start Security Test'}
              </Button>

              {!currentSpec && (
                <Typography variant="caption" color="error">
                  API specification required to start testing
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default TestingPage;
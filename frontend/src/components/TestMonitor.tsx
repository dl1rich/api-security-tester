import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Alert,
  Divider,
  Grid,
  Paper,
  CircularProgress,
} from '@mui/material';
import {
  PlayArrow,
  Stop,
  Warning,
  Error,
  CheckCircle,
  Security,
  BugReport,
  Timeline,
} from '@mui/icons-material';
import { websocketService } from '../services/websocket';
import {
  WebSocketMessage,
  TestProgressData,
  VulnerabilityData,
  TestStatusData,
  DetectorActivityData,
} from '../types';

interface TestMonitorProps {
  sessionId: string;
  onTestComplete?: (results: any) => void;
}

interface TestState {
  status: 'idle' | 'connecting' | 'running' | 'completed' | 'failed';
  progress: TestProgressData | null;
  vulnerabilities: VulnerabilityData[];
  detectorActivity: DetectorActivityData[];
  error?: string;
  startTime?: Date;
  endTime?: Date;
}

const TestMonitor: React.FC<TestMonitorProps> = ({ sessionId, onTestComplete }) => {
  const [testState, setTestState] = useState<TestState>({
    status: 'idle',
    progress: null,
    vulnerabilities: [],
    detectorActivity: [],
  });
  
  const [connectionState, setConnectionState] = useState<string>('disconnected');

  const handleWebSocketMessage = useCallback((message: WebSocketMessage) => {
    console.log('Received WebSocket message:', message);
    
    switch (message.type) {
      case 'test_started':
        setTestState(prev => ({
          ...prev,
          status: 'running',
          startTime: new Date(),
          error: undefined,
        }));
        break;

      case 'test_progress':
        setTestState(prev => ({
          ...prev,
          progress: message.data as TestProgressData,
        }));
        break;

      case 'test_completed':
        setTestState(prev => ({
          ...prev,
          status: 'completed',
          endTime: new Date(),
        }));
        if (onTestComplete) {
          onTestComplete(message.data);
        }
        break;

      case 'test_failed':
        setTestState(prev => ({
          ...prev,
          status: 'failed',
          endTime: new Date(),
          error: message.data?.error || 'Test failed',
        }));
        break;

      case 'vulnerability_found':
        setTestState(prev => ({
          ...prev,
          vulnerabilities: [...prev.vulnerabilities, message.data as VulnerabilityData],
        }));
        break;

      case 'detector_started':
      case 'detector_completed':
        setTestState(prev => {
          const activity = message.data as DetectorActivityData;
          const existing = prev.detectorActivity.find(d => d.detectorName === activity.detectorName);
          
          if (existing) {
            return {
              ...prev,
              detectorActivity: prev.detectorActivity.map(d =>
                d.detectorName === activity.detectorName ? activity : d
              ),
            };
          } else {
            return {
              ...prev,
              detectorActivity: [...prev.detectorActivity, activity],
            };
          }
        });
        break;

      case 'error':
        setTestState(prev => ({
          ...prev,
          error: message.data?.message || 'An error occurred',
        }));
        break;
    }
  }, [onTestComplete]);

  useEffect(() => {
    // Connect to WebSocket
    setTestState(prev => ({ ...prev, status: 'connecting' }));
    websocketService.connect(sessionId);
    
    // Subscribe to messages
    const unsubscribe = websocketService.subscribe(handleWebSocketMessage);
    
    // Monitor connection state
    const checkConnection = setInterval(() => {
      setConnectionState(websocketService.getConnectionState());
    }, 1000);

    return () => {
      unsubscribe();
      clearInterval(checkConnection);
      websocketService.disconnect();
    };
  }, [sessionId, handleWebSocketMessage]);

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
      case 'medium': return <BugReport />;
      case 'low': return <Security />;
      default: return <BugReport />;
    }
  };

  const getStatusIcon = () => {
    switch (testState.status) {
      case 'connecting': return <CircularProgress size={20} />;
      case 'running': return <PlayArrow color="primary" />;
      case 'completed': return <CheckCircle color="success" />;
      case 'failed': return <Error color="error" />;
      default: return <Stop />;
    }
  };

  const formatDuration = () => {
    if (!testState.startTime) return '';
    const end = testState.endTime || new Date();
    const duration = Math.floor((end.getTime() - testState.startTime.getTime()) / 1000);
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  return (
    <Box sx={{ width: '100%', maxWidth: 1200, margin: '0 auto', p: 2 }}>
      {/* Header Status */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Grid container alignItems="center" spacing={2}>
            <Grid item>
              {getStatusIcon()}
            </Grid>
            <Grid item xs>
              <Typography variant="h6">
                Test Session: {sessionId}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Status: {testState.status} • Connection: {connectionState}
                {testState.startTime && ` • Duration: ${formatDuration()}`}
              </Typography>
            </Grid>
            <Grid item>
              <Chip
                label={`${testState.vulnerabilities.length} Vulnerabilities Found`}
                color={testState.vulnerabilities.length > 0 ? 'warning' : 'success'}
                variant="outlined"
              />
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Error Display */}
      {testState.error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {testState.error}
        </Alert>
      )}

      <Grid container spacing={2}>
        {/* Progress Panel */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <Timeline sx={{ mr: 1, verticalAlign: 'middle' }} />
                Test Progress
              </Typography>
              
              {testState.progress && (
                <>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Step {testState.progress.current_step} of {testState.progress.total_steps}
                      {testState.progress.current_detector && ` • ${testState.progress.current_detector}`}
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={testState.progress.percentage || 
                        (testState.progress.current_step / testState.progress.total_steps) * 100}
                      sx={{ mt: 1 }}
                    />
                  </Box>
                  {testState.progress.message && (
                    <Typography variant="body2">
                      {testState.progress.message}
                    </Typography>
                  )}
                </>
              )}

              <Divider sx={{ my: 2 }} />
              
              <Typography variant="subtitle2" gutterBottom>
                Detector Activity
              </Typography>
              <List dense>
                {testState.detectorActivity.map((activity, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      {activity.status === 'completed' ? (
                        <CheckCircle color="success" />
                      ) : (
                        <CircularProgress size={20} />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={activity.detectorName}
                      secondary={
                        activity.status === 'completed' 
                          ? `Found ${activity.vulnerabilitiesFound || 0} vulnerabilities`
                          : 'Running...'
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Vulnerabilities Panel */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <Security sx={{ mr: 1, verticalAlign: 'middle' }} />
                Vulnerabilities ({testState.vulnerabilities.length})
              </Typography>
              
              {testState.vulnerabilities.length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  No vulnerabilities found yet.
                </Typography>
              ) : (
                <List dense>
                  {testState.vulnerabilities.slice(-10).map((vuln, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        {getSeverityIcon(vuln.severity)}
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="body2" component="span">
                              {vuln.title}
                            </Typography>
                            <Chip
                              label={vuln.severity}
                              size="small"
                              color={getSeverityColor(vuln.severity) as any}
                              variant="outlined"
                            />
                          </Box>
                        }
                        secondary={`${vuln.method} ${vuln.endpoint}`}
                      />
                    </ListItem>
                  ))}
                  {testState.vulnerabilities.length > 10 && (
                    <ListItem>
                      <ListItemText
                        primary={
                          <Typography variant="body2" color="text.secondary">
                            ... and {testState.vulnerabilities.length - 10} more
                          </Typography>
                        }
                      />
                    </ListItem>
                  )}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default TestMonitor;
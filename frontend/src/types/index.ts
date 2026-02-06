// API Types
export interface ApiSpec {
  id: string;
  title: string;
  version: string;
  endpoint_count: number;
  auth_methods: string[];
  spec_version: string;
  source_url?: string;
}

export interface UploadResponse {
  success: boolean;
  message: string;
  spec_id: string;
  spec_info: ApiSpec;
}

// Testing Types
export interface TestConfiguration {
  spec_id: string;
  test_modules: string[];
  auth_handling: 'preserve_roles' | 'bypass_all' | 'custom';
  custom_roles?: string[];
  target_base_url?: string;
  test_intensity: 'low' | 'medium' | 'high';
  concurrent_requests: number;
  timeout_seconds: number;
}

export interface TestStartResponse {
  success: boolean;
  test_session_id: string;
  message: string;
  estimated_duration: number;
}

export interface TestStatus {
  test_session_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress_percentage: number;
  current_test?: string;
  total_tests: number;
  completed_tests: number;
  started_at: string;
  estimated_completion?: string;
}

// Vulnerability Types
export interface VulnerabilityResult {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  endpoint: string;
  method: string;
  cwe_id?: string;
  owasp_category: string;
  evidence: Record<string, any>;
  remediation: string;
  cvss_score?: number;
}

export interface TestResults {
  session_id: string;
  spec_id: string;
  test_config?: TestConfiguration;
  status: string;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  total_vulnerabilities: number;
  vulnerabilities_by_severity: Record<string, number>;
  vulnerabilities: VulnerabilityResult[];
  coverage_stats: Record<string, any>;
  summary: string;
}

// UI State Types
export interface AppState {
  currentSpec?: ApiSpec;
  currentTest?: TestStatus;
  isLoading: boolean;
  error?: string;
}

export interface FileUploadState {
  isDragActive: boolean;
  isUploading: boolean;
  uploadProgress: number;
}

// WebSocket Types
export interface WebSocketMessage {
  type: 'test_started' | 'test_progress' | 'test_completed' | 'test_failed' | 
        'vulnerability_found' | 'detector_started' | 'detector_completed' |
        'ping' | 'pong' | 'error' | 'status_update';
  sessionId?: string;
  timestamp: string;
  data: any;
}

export interface TestProgressData {
  current_step: number;
  total_steps: number;
  current_detector?: string;
  message?: string;
  percentage?: number;
}

export interface VulnerabilityData {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  endpoint?: string;
  method?: string;
  evidence?: any;
  remediation?: string;
}

export interface TestStatusData {
  status: 'started' | 'running' | 'completed' | 'failed';
  sessionId: string;
  message?: string;
  error?: string;
  startTime?: string;
  endTime?: string;
  totalVulnerabilities?: number;
}

export interface DetectorActivityData {
  detectorName: string;
  status: 'started' | 'completed';
  message?: string;
  vulnerabilitiesFound?: number;
  testsRun?: number;
}
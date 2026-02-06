import axios, { AxiosResponse } from 'axios';
import { 
  UploadResponse, 
  TestConfiguration, 
  TestStartResponse, 
  TestStatus, 
  TestResults,
  VulnerabilityResult 
} from '../types';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000, // 120 seconds for large file parsing
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for logging
api.interceptors.request.use(
  (config) => {
    console.log(`Making ${config.method?.toUpperCase()} request to ${config.url}`);
    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Response error:', error);
    if (error.response?.status === 401) {
      // Handle unauthorized access
    } else if (error.response?.status === 500) {
      console.error('Server error occurred');
    }
    return Promise.reject(error);
  }
);

export class ApiService {
  // Health check
  static async healthCheck(): Promise<any> {
    const response: AxiosResponse = await api.get('/health');
    return response.data;
  }

  // File upload
  static async uploadFile(file: File): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append('file', file);
    
    const response: AxiosResponse<UploadResponse> = await api.post('/upload/file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      timeout: 180000, // 3 minutes for large files
    });
    
    return response.data;
  }

  // URL upload
  static async uploadUrl(url: string, authHeader?: string): Promise<UploadResponse> {
    const response: AxiosResponse<UploadResponse> = await api.post('/upload/url', {
      url,
      auth_header: authHeader,
    });
    
    return response.data;
  }

  // Validate specification
  static async validateSpecification(specId: string): Promise<any> {
    const response: AxiosResponse = await api.get(`/upload/validate/${specId}`);
    return response.data;
  }

  // Start security test
  static async startSecurityTest(config: TestConfiguration): Promise<TestStartResponse> {
    const response: AxiosResponse<TestStartResponse> = await api.post('/testing/start', config);
    return response.data;
  }

  // Get test status
  static async getTestStatus(sessionId: string): Promise<TestStatus> {
    const response: AxiosResponse<TestStatus> = await api.get(`/testing/status/${sessionId}`);
    return response.data;
  }

  // Stop test
  static async stopTest(sessionId: string): Promise<any> {
    const response: AxiosResponse = await api.post(`/testing/stop/${sessionId}`);
    return response.data;
  }

  // Get available test modules
  static async getTestModules(): Promise<any> {
    const response: AxiosResponse = await api.get('/testing/modules');
    return response.data;
  }

  // List test sessions
  static async listTestSessions(limit: number = 50): Promise<any> {
    const response: AxiosResponse = await api.get(`/testing/sessions?limit=${limit}`);
    return response.data;
  }

  // Get test results
  static async getTestResults(sessionId: string): Promise<TestResults> {
    const response: AxiosResponse<TestResults> = await api.get(`/results/${sessionId}`);
    return response.data;
  }

  // Get vulnerabilities
  static async getVulnerabilities(
    sessionId: string,
    severity?: string,
    category?: string,
    limit: number = 100,
    offset: number = 0
  ): Promise<{ vulnerabilities: VulnerabilityResult[]; total_count: number }> {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (category) params.append('category', category);
    params.append('limit', limit.toString());
    params.append('offset', offset.toString());

    const response: AxiosResponse = await api.get(`/results/${sessionId}/vulnerabilities?${params}`);
    return response.data;
  }

  // Get results summary
  static async getResultsSummary(sessionId: string): Promise<any> {
    const response: AxiosResponse = await api.get(`/results/${sessionId}/summary`);
    return response.data;
  }

  // Export reports
  static async exportHtmlReport(sessionId: string): Promise<Blob> {
    const response: AxiosResponse = await api.get(`/results/${sessionId}/export/html`, {
      responseType: 'blob',
    });
    return response.data;
  }

  static async exportJsonReport(sessionId: string): Promise<Blob> {
    const response: AxiosResponse = await api.get(`/results/${sessionId}/export/json`, {
      responseType: 'blob',
    });
    return response.data;
  }

  static async exportPdfReport(sessionId: string): Promise<Blob> {
    const response: AxiosResponse = await api.get(`/results/${sessionId}/export/pdf`, {
      responseType: 'blob',
    });
    return response.data;
  }

  // Delete test results
  static async deleteTestResults(sessionId: string): Promise<any> {
    const response: AxiosResponse = await api.delete(`/results/${sessionId}`);
    return response.data;
  }

  // List all test results
  static async listTestResults(limit: number = 50, offset: number = 0): Promise<any> {
    const response: AxiosResponse = await api.get(`/results?limit=${limit}&offset=${offset}`);
    return response.data;
  }
}

export default ApiService;
import React, { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Box,
  Paper,
  Typography,
  Button,
  TextField,
  CircularProgress,
  Alert,
  Card,
  CardContent,
  Divider,
} from '@mui/material';
import {
  CloudUpload,
  Link as LinkIcon,
  Description,
  CheckCircle,
} from '@mui/icons-material';
import { ApiService } from '../services/api';
import { UploadResponse, ApiSpec } from '../types';
import toast from 'react-hot-toast';

interface SpecUploadProps {
  onSpecUploaded: (spec: ApiSpec) => void;
}

const SpecUpload: React.FC<SpecUploadProps> = ({ onSpecUploaded }) => {
  const [isUploading, setIsUploading] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [authHeader, setAuthHeader] = useState('');
  const [uploadedSpec, setUploadedSpec] = useState<ApiSpec | null>(null);

  // File upload handler
  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    setIsUploading(true);

    try {
      const response: UploadResponse = await ApiService.uploadFile(file);
      
      if (response.success) {
        const specData = {
          ...response.spec_info,
          id: response.spec_id
        };
        setUploadedSpec(specData);
        
        // Save to localStorage for persistence
        localStorage.setItem('currentApiSpec', JSON.stringify(specData));
        
        onSpecUploaded(specData);
        toast.success('File uploaded successfully!');
      } else {
        toast.error(response.message || 'Upload failed');
      }
    } catch (error: any) {
      console.error('Upload error:', error);
      toast.error(error.response?.data?.detail || 'Upload failed');
    } finally {
      setIsUploading(false);
    }
  }, [onSpecUploaded]);

  // URL upload handler
  const handleUrlUpload = async () => {
    if (!urlInput.trim()) {
      toast.error('Please enter a valid URL');
      return;
    }

    setIsUploading(true);

    try {
      const response: UploadResponse = await ApiService.uploadUrl(
        urlInput.trim(),
        authHeader.trim() || undefined
      );

      if (response.success) {
        const specData = {
          ...response.spec_info,
          id: response.spec_id
        };
        setUploadedSpec(specData);
        
        // Save to localStorage for persistence
        localStorage.setItem('currentApiSpec', JSON.stringify(specData));
        
        onSpecUploaded(specData);
        toast.success('Specification fetched successfully!');
      } else {
        toast.error(response.message || 'URL fetch failed');
      }
    } catch (error: any) {
      console.error('URL upload error:', error);
      toast.error(error.response?.data?.detail || 'URL fetch failed');
    } finally {
      setIsUploading(false);
    }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/json': ['.json'],
      'application/x-yaml': ['.yaml', '.yml'],
      'text/yaml': ['.yaml', '.yml'],
    },
    maxFiles: 1,
    maxSize: 50 * 1024 * 1024, // 50MB
  });

  return (
    <Box sx={{ width: '100%', maxWidth: 800, mx: 'auto', p: 3 }}>
      <Typography variant="h4" gutterBottom align="center">
        Upload API Specification
      </Typography>
      
      <Typography variant="body1" color="text.secondary" align="center" sx={{ mb: 4 }}>
        Upload your OpenAPI/Swagger specification file or fetch it from a URL
      </Typography>

      {/* File Upload Section */}
      <Paper 
        {...getRootProps()} 
        sx={{
          p: 4,
          mb: 3,
          border: '2px dashed',
          borderColor: isDragActive ? 'primary.main' : 'grey.300',
          backgroundColor: isDragActive ? 'action.hover' : 'background.paper',
          cursor: 'pointer',
          transition: 'all 0.3s ease',
          '&:hover': {
            borderColor: 'primary.main',
            backgroundColor: 'action.hover',
          },
        }}
      >
        <input {...getInputProps()} />
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            textAlign: 'center',
          }}
        >
          {isUploading ? (
            <CircularProgress sx={{ mb: 2 }} />
          ) : (
            <CloudUpload sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
          )}
          
          <Typography variant="h6" gutterBottom>
            {isDragActive ? 'Drop your file here' : 'Drag & drop your API specification'}
          </Typography>
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Supports OpenAPI 3.x, Swagger 2.0, and legacy formats
          </Typography>
          
          <Typography variant="caption" color="text.secondary">
            Accepted formats: JSON, YAML (max 50MB)
          </Typography>
          
          <Button 
            variant="outlined" 
            sx={{ mt: 2 }}
            disabled={isUploading}
          >
            {isUploading ? 'Uploading...' : 'Choose File'}
          </Button>
        </Box>
      </Paper>

      {/* Divider */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Divider sx={{ flex: 1 }} />
        <Typography variant="body2" sx={{ px: 2, color: 'text.secondary' }}>
          OR
        </Typography>
        <Divider sx={{ flex: 1 }} />
      </Box>

      {/* URL Upload Section */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
          <LinkIcon sx={{ mr: 1 }} />
          Fetch from URL
        </Typography>
        
        <TextField
          fullWidth
          label="API Specification URL"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          placeholder="https://api.example.com/swagger.json"
          sx={{ mb: 2 }}
          disabled={isUploading}
        />
        
        <TextField
          fullWidth
          label="Authorization Header (Optional)"
          value={authHeader}
          onChange={(e) => setAuthHeader(e.target.value)}
          placeholder="Bearer token..."
          sx={{ mb: 2 }}
          disabled={isUploading}
        />
        
        <Button
          variant="contained"
          onClick={handleUrlUpload}
          disabled={isUploading || !urlInput.trim()}
          fullWidth
        >
          {isUploading ? 'Fetching...' : 'Fetch Specification'}
        </Button>
      </Paper>

      {/* Upload Success Display */}
      {uploadedSpec && (
        <Card sx={{ mt: 3, border: '1px solid', borderColor: 'success.main' }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <CheckCircle sx={{ color: 'success.main', mr: 1 }} />
              <Typography variant="h6" color="success.main">
                Specification Loaded Successfully
              </Typography>
            </Box>
            
            <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2 }}>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Title
                </Typography>
                <Typography variant="body1">{uploadedSpec.title}</Typography>
              </Box>
              
              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Version
                </Typography>
                <Typography variant="body1">{uploadedSpec.version}</Typography>
              </Box>
              
              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Endpoints
                </Typography>
                <Typography variant="body1">{uploadedSpec.endpoint_count}</Typography>
              </Box>
              
              <Box>
                <Typography variant="subtitle2" color="text.secondary">
                  Spec Version
                </Typography>
                <Typography variant="body1">{uploadedSpec.spec_version}</Typography>
              </Box>
            </Box>

            {uploadedSpec.auth_methods.length > 0 && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  Authentication Methods
                </Typography>
                <Typography variant="body1">
                  {uploadedSpec.auth_methods.join(', ')}
                </Typography>
              </Box>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default SpecUpload;
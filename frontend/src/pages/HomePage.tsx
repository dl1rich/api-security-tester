import React, { useState } from 'react';
import { Container, Box, Button } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import SpecUpload from '../components/SpecUpload';
import { ApiSpec } from '../types';

const HomePage: React.FC = () => {
  const [uploadedSpec, setUploadedSpec] = useState<ApiSpec | null>(null);
  const navigate = useNavigate();

  const handleSpecUploaded = (spec: ApiSpec) => {
    setUploadedSpec(spec);
  };

  const handleStartTesting = () => {
    if (uploadedSpec) {
      // Navigate to testing page with spec data
      navigate('/testing', { state: { spec: uploadedSpec } });
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <SpecUpload onSpecUploaded={handleSpecUploaded} />
      
      {uploadedSpec && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <Button
            variant="contained"
            size="large"
            onClick={handleStartTesting}
            sx={{ minWidth: 200 }}
          >
            Start Security Testing
          </Button>
        </Box>
      )}
    </Container>
  );
};

export default HomePage;
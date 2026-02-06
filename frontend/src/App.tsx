import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { Toaster } from 'react-hot-toast';

// Pages
import HomePage from './pages/HomePage';
import TestingPage from './pages/TestingPage';
import ResultsPage from './pages/ResultsPage';
import TestMonitorPage from './pages/TestMonitorPage';

// Components
import Header from './components/Header';
import Sidebar from './components/Sidebar';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
      dark: '#115293',
      light: '#42a5f5',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h4: {
      fontWeight: 600,
    },
    h6: {
      fontWeight: 500,
    },
  },
  shape: {
    borderRadius: 8,
  },
});

const App: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = React.useState(false);

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box sx={{ display: 'flex', minHeight: '100vh' }}>
          <Header onMenuClick={toggleSidebar} />
          <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
          
          <Box
            component="main"
            sx={{
              flexGrow: 1,
              pt: 8, // Account for header height
              backgroundColor: 'background.default',
              minHeight: '100vh',
            }}
          >
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/testing" element={<TestingPage />} />
              <Route path="/testing/monitor/:sessionId" element={<TestMonitorPage />} />
              <Route path="/results" element={<ResultsPage />} />
              <Route path="/results/:sessionId" element={<ResultsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Box>
        </Box>
        
        {/* Toast notifications */}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#363636',
              color: '#fff',
            },
            success: {
              duration: 3000,
              iconTheme: {
                primary: '#4caf50',
                secondary: '#fff',
              },
            },
            error: {
              duration: 5000,
              iconTheme: {
                primary: '#f44336',
                secondary: '#fff',
              },
            },
          }}
        />
      </Router>
    </ThemeProvider>
  );
};

export default App;
import React from 'react';
import { 
  AppBar, 
  Toolbar, 
  Typography, 
  IconButton, 
  Box,
  Chip
} from '@mui/material';
import { 
  Menu as MenuIcon, 
  Security,
  GitHub
} from '@mui/icons-material';

interface HeaderProps {
  onMenuClick: () => void;
}

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  return (
    <AppBar 
      position="fixed" 
      sx={{ 
        zIndex: (theme) => theme.zIndex.drawer + 1,
        backgroundColor: 'primary.main'
      }}
    >
      <Toolbar>
        <IconButton
          edge="start"
          color="inherit"
          aria-label="menu"
          onClick={onMenuClick}
          sx={{ mr: 2 }}
        >
          <MenuIcon />
        </IconButton>
        
        <Security sx={{ mr: 1 }} />
        
        <Typography 
          variant="h6" 
          component="div" 
          sx={{ flexGrow: 1, fontWeight: 'bold' }}
        >
          API Security Tester
        </Typography>
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Chip 
            label="v0.1.0" 
            size="small" 
            variant="outlined" 
            sx={{ 
              color: 'white', 
              borderColor: 'rgba(255, 255, 255, 0.5)',
              fontSize: '0.7rem'
            }} 
          />
          
          <IconButton
            color="inherit"
            href="https://github.com/your-repo/api-security-tester"
            target="_blank"
            rel="noopener noreferrer"
            size="small"
          >
            <GitHub />
          </IconButton>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Header;
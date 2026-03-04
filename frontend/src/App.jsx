/**
 * SmartPatch Frontend Main Application
 * Production-grade vulnerability patching UI
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  AppBar,
  Toolbar,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
  Container,
  CssBaseline,
  IconButton,
  Menu,
  MenuItem,
  Divider,
  Alert,
  CircularProgress
} from '@mui/material';
import {
  Menu as MenuIcon,
  Close as CloseIcon,
  Dashboard as DashboardIcon,
  Settings as SettingsIcon,
  Assessment as AssessmentIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  MoreVert as MoreVertIcon,
  Search as SearchIcon,
  CheckCircle as CheckCircleIcon,
  Update as UpdateIcon
} from '@mui/icons-material';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import AnalyzeSystemPage from './pages/AnalyzeSystem';
import SystemOverviewPage from './pages/SystemOverview';
import ExecutiveDashboardPage from './pages/ExecutiveDashboard';
import MissingPatchesPage from './pages/MissingPatches';
import VulnerabilitiesPage from './pages/Vulnerabilities';
import MitigationCenterPage from './pages/MitigationCenter';
import AuditLogsPage from './pages/AuditLogs';
import { healthAPI } from './api/backend';

// Application theme
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#f57c00',
    },
    success: {
      main: '#388e3c',
    },
    warning: {
      main: '#f57c00',
    },
    error: {
      main: '#d32f2f',
    },
  },
  typography: {
    fontFamily: [
      '-apple-system',
      'BlinkMacSystemFont',
      '"Segoe UI"',
      'Roboto',
      '"Helvetica Neue"',
      'Arial',
      'sans-serif',
    ].join(','),
  },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
        },
      },
    },
  },
});

const pages = [
  {
    id: 'dashboard',
    title: 'Executive Dashboard',
    icon: DashboardIcon,
    description: 'Real-time security risk intelligence'
  },
  {
    id: 'vulnerabilities',
    title: 'Detected Issues',
    icon: WarningIcon,
    description: 'All identified CVEs and vulnerabilities'
  },
  {
    id: 'patches',
    title: 'Missing Patches',
    icon: UpdateIcon,
    description: 'Required patches and updates'
  },
  {
    id: 'mitigations',
    title: 'Mitigation Center',
    icon: SettingsIcon,
    description: 'Remediation actions and guidance'
  },
  {
    id: 'audit',
    title: 'Audit Logs',
    icon: AssessmentIcon,
    description: 'Scan history and compliance'
  },
  {
    id: 'analyze',
    title: 'System Scanner',
    icon: SearchIcon,
    description: 'Trigger system analysis'
  },
  {
    id: 'overview',
    title: 'System Info',
    icon: InfoIcon,
    description: 'System metadata and configuration'
  }
];

const App = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [backendHealthy, setBackendHealthy] = useState(null);
  const [anchorEl, setAnchorEl] = useState(null);

  // Check backend health on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const healthy = await healthAPI.check();
        setBackendHealthy(healthy);
      } catch (err) {
        setBackendHealthy(false);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000); // Check every 30s
    return () => clearInterval(interval);
  }, []);

  const handleMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <ExecutiveDashboardPage />;
      case 'vulnerabilities':
        return <VulnerabilitiesPage />;
      case 'patches':
        return <MissingPatchesPage />;
      case 'mitigations':
        return <MitigationCenterPage />;
      case 'audit':
        return <AuditLogsPage />;
      case 'analyze':
        return <AnalyzeSystemPage />;
      case 'overview':
        return <SystemOverviewPage />;
      default:
        return <ExecutiveDashboardPage />;
    }
  };

  const currentPageObj = pages.find(p => p.id === currentPage);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ display: 'flex', minHeight: '100vh', backgroundColor: '#fafafa' }}>
        {/* Top AppBar */}
        <AppBar position="fixed" sx={{ zIndex: 1300 }}>
          <Toolbar>
            <IconButton
              edge="start"
              color="inherit"
              aria-label="menu"
              onClick={() => setDrawerOpen(!drawerOpen)}
              sx={{ mr: 2 }}
            >
              {drawerOpen ? <CloseIcon /> : <MenuIcon />}
            </IconButton>

            <Box sx={{ display: 'flex', alignItems: 'center', flex: 1 }}>
              <CheckCircleIcon sx={{ mr: 1 }} />
              <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                SmartPatch
              </Typography>
            </Box>

            {/* Health Status */}
            {backendHealthy !== null && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mr: 2 }}>
                <Box
                  sx={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    backgroundColor: backendHealthy ? '#4caf50' : '#f44336'
                  }}
                />
                <Typography variant="caption">
                  {backendHealthy ? 'Backend Ready' : 'Backend Error'}
                </Typography>
              </Box>
            )}

            <IconButton
              color="inherit"
              onClick={handleMenuOpen}
              aria-label="more options"
            >
              <MoreVertIcon />
            </IconButton>

            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
            >
              <MenuItem onClick={handleMenuClose}>
                <SettingsIcon sx={{ mr: 1 }} />
                Settings
              </MenuItem>
              <MenuItem onClick={handleMenuClose}>
                <InfoIcon sx={{ mr: 1 }} />
                About
              </MenuItem>
            </Menu>
          </Toolbar>
        </AppBar>

        {/* Left Sidebar */}
        <Drawer
          open={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          sx={{
            width: 280,
            '& .MuiDrawer-paper': {
              width: 280,
              mt: '64px'
            }
          }}
        >
          <Box sx={{ p: 2 }}>
            <Typography variant="overline" sx={{ color: 'textSecondary', fontWeight: '600' }}>
              Navigation
            </Typography>
          </Box>

          <List>
            {pages.map((page) => {
              const Icon = page.icon;
              const isActive = currentPage === page.id;
              return (
                <ListItemButton
                  key={page.id}
                  selected={isActive}
                  onClick={() => {
                    setCurrentPage(page.id);
                    setDrawerOpen(false);
                  }}
                  sx={{
                    mb: 1,
                    mx: 1,
                    borderRadius: '6px',
                    backgroundColor: isActive ? '#e3f2fd' : 'transparent',
                    '&.Mui-selected': {
                      backgroundColor: '#e3f2fd',
                      '&:hover': {
                        backgroundColor: '#e3f2fd'
                      }
                    }
                  }}
                >
                  <ListItemIcon sx={{ color: isActive ? '#1976d2' : 'inherit' }}>
                    <Icon />
                  </ListItemIcon>
                  <Box sx={{ flex: 1 }}>
                    <ListItemText
                      primary={page.title}
                      secondary={page.description}
                      primaryTypographyProps={{
                        sx: { fontWeight: isActive ? '600' : '400', fontSize: '0.95rem' }
                      }}
                      secondaryTypographyProps={{
                        sx: { fontSize: '0.75rem' }
                      }}
                    />
                  </Box>
                </ListItemButton>
              );
            })}
          </List>

          <Divider sx={{ my: 2 }} />

          <Box sx={{ p: 2 }}>
            <Typography variant="caption" color="textSecondary">
              SmartPatch v1.0.0
            </Typography>
            <Typography variant="caption" display="block" color="textSecondary" sx={{ mt: 1 }}>
              AI-driven vulnerability patching for Windows systems
            </Typography>
          </Box>
        </Drawer>

        {/* Main Content Area */}
        <Box sx={{ flex: 1, mt: '64px' }}>
          {/* Backend Connection Status */}
          {backendHealthy === false && (
            <Alert severity="error" sx={{ m: 2, borderRadius: 0 }}>
              Backend API is not responding. Ensure server is running (python api/backend_api.py).
            </Alert>
          )}

          {/* Page Header */}
          <Box sx={{ p: 3, borderBottom: '1px solid #eee', backgroundColor: '#fff' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              {currentPageObj && (
                <>
                  {currentPageObj.icon && (() => {
                    const Icon = currentPageObj.icon;
                    return <Icon sx={{ fontSize: '2rem', color: '#1976d2' }} />;
                  })()}
                  <Box>
                    <Typography variant="h5" sx={{ fontWeight: '600' }}>
                      {currentPageObj.title}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      {currentPageObj.description}
                    </Typography>
                  </Box>
                </>
              )}
            </Box>
          </Box>

          {/* Page Content */}
          <Box sx={{ pb: 4 }}>
            {renderPage()}
          </Box>
        </Box>
      </Box>
    </ThemeProvider>
  );
};

export default App;

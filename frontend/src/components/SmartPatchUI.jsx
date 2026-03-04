/**
 * Reusable components for SmartPatch frontend
 */

import React from 'react';
import {
  Card,
  CardContent,
  CardHeader,
  Box,
  Typography,
  Chip,
  LinearProgress,
  Alert,
  CircularProgress,
  Grid,
  Paper
} from '@mui/material';

/**
 * HARS Score Display Component
 */
export const HARSScoreCard = ({ score, cveId, compact = false }) => {
  if (!score) {
    return (
      <Paper sx={{ p: 2, textAlign: 'center', opacity: 0.6 }}>
        <Typography variant="body2" color="textSecondary">
          HARS scores not available
        </Typography>
      </Paper>
    );
  }

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'HIGH':
        return '#d32f2f';
      case 'MEDIUM':
        return '#f57c00';
      case 'LOW':
        return '#388e3c';
      default:
        return '#666';
    }
  };

  const getScoreColor = (finalScore) => {
    if (finalScore >= 0.7) return '#d32f2f';
    if (finalScore >= 0.35) return '#f57c00';
    return '#388e3c';
  };

  if (compact) {
    return (
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
        <Chip
          label={`Priority: ${score.priority}`}
          size="small"
          sx={{
            backgroundColor: getPriorityColor(score.priority),
            color: '#fff',
            fontWeight: 'bold'
          }}
        />
        <Chip
          label={`Score: ${score.final_score?.toFixed(3) || 'N/A'}`}
          size="small"
          sx={{
            backgroundColor: getScoreColor(score.final_score || 0),
            color: '#fff'
          }}
        />
      </Box>
    );
  }

  return (
    <Card sx={{ mb: 2 }}>
      <CardHeader
        title={`HARS Score - ${cveId || 'Vulnerability'}`}
        subheader={`Priority: ${score.priority || 'N/A'}`}
      />
      <CardContent>
        <Grid container spacing={2}>
          <Grid item xs={6} sm={3}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="caption" display="block" color="textSecondary">
                R Score
              </Typography>
              <Typography variant="h6" sx={{ color: getScoreColor(score.r_score) }}>
                {score.r_score?.toFixed(3) || 'N/A'}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="caption" display="block" color="textSecondary">
                A Score
              </Typography>
              <Typography variant="h6" sx={{ color: getScoreColor(score.a_score) }}>
                {score.a_score?.toFixed(3) || 'N/A'}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="caption" display="block" color="textSecondary">
                C Score
              </Typography>
              <Typography variant="h6" sx={{ color: getScoreColor(score.c_score) }}>
                {score.c_score?.toFixed(3) || 'N/A'}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="caption" display="block" color="textSecondary">
                Final Score
              </Typography>
              <Typography
                variant="h6"
                sx={{
                  color: getScoreColor(score.final_score),
                  fontWeight: 'bold'
                }}
              >
                {score.final_score?.toFixed(3) || 'N/A'}
              </Typography>
            </Box>
          </Grid>
        </Grid>

        {score.model_version && (
          <Typography variant="caption" color="textSecondary" sx={{ mt: 2, display: 'block' }}>
            Model: {score.model_version}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

/**
 * Risk Level Badge
 */
export const RiskBadge = ({ priority, compact = false }) => {
  const colors = {
    HIGH: { bg: '#d32f2f', text: '#fff' },
    MEDIUM: { bg: '#f57c00', text: '#fff' },
    LOW: { bg: '#388e3c', text: '#fff' },
  };

  const color = colors[priority] || colors.LOW;

  if (compact) {
    return (
      <Box
        sx={{
          display: 'inline-block',
          px: 1,
          py: 0.25,
          borderRadius: '4px',
          backgroundColor: color.bg,
          color: color.text,
          fontSize: '0.75rem',
          fontWeight: 'bold',
        }}
      >
        {priority}
      </Box>
    );
  }

  return (
    <Chip
      label={priority}
      sx={{
        backgroundColor: color.bg,
        color: color.text,
        fontWeight: 'bold',
        fontSize: '0.9rem',
      }}
    />
  );
};

/**
 * Progress Display for Scanning
 */
export const ScanProgress = ({ progress, status }) => {
  const getStatusMessage = () => {
    switch (status) {
      case 'initializing':
        return 'Initializing system analysis...';
      case 'running':
        return 'Running vulnerability scan...';
      case 'complete':
        return 'Scan complete!';
      case 'error':
        return 'Scan failed';
      default:
        return 'Starting scan...';
    }
  };

  return (
    <Box sx={{ mt: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Box sx={{ flexGrow: 1, mr: 2 }}>
          <LinearProgress
            variant="determinate"
            value={progress}
            sx={{ height: '8px', borderRadius: '4px' }}
          />
        </Box>
        <Typography variant="body2" color="textSecondary" sx={{ minWidth: '45px' }}>
          {progress}%
        </Typography>
      </Box>
      <Typography variant="body2" color="textSecondary">
        {getStatusMessage()}
      </Typography>
    </Box>
  );
};

/**
 * Loading State
 */
export const LoadingState = ({ message = 'Loading...' }) => {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4 }}>
      <CircularProgress />
      <Typography variant="body2" color="textSecondary" sx={{ mt: 2 }}>
        {message}
      </Typography>
    </Box>
  );
};

/**
 * Error State
 */
export const ErrorState = ({ error, onRetry = null }) => {
  return (
    <Alert
      severity="error"
      sx={{ mt: 2 }}
      onClose={onRetry ? () => onRetry() : undefined}
    >
      <Typography variant="body2">
        {error || 'An unexpected error occurred'}
      </Typography>
    </Alert>
  );
};

/**
 * Empty State
 */
export const EmptyState = ({ message = 'No data available' }) => {
  return (
    <Box sx={{ textAlign: 'center', py: 4, opacity: 0.6 }}>
      <Typography variant="body2" color="textSecondary">
        {message}
      </Typography>
    </Box>
  );
};

/**
 * System Info Display
 */
export const SystemInfoDisplay = ({ systemInfo }) => {
  if (!systemInfo) {
    return <EmptyState message="System information not available" />;
  }

  return (
    <Paper sx={{ p: 3 }}>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={6}>
          <Box>
            <Typography variant="caption" color="textSecondary" display="block">
              Hostname
            </Typography>
            <Typography variant="body1">
              {systemInfo.hostname || 'N/A'}
            </Typography>
          </Box>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Box>
            <Typography variant="caption" color="textSecondary" display="block">
              OS Version
            </Typography>
            <Typography variant="body1">
              {systemInfo.os_version || 'N/A'}
            </Typography>
          </Box>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Box>
            <Typography variant="caption" color="textSecondary" display="block">
              Build Number
            </Typography>
            <Typography variant="body1">
              {systemInfo.build_number || 'N/A'}
            </Typography>
          </Box>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Box>
            <Typography variant="caption" color="textSecondary" display="block">
              Architecture
            </Typography>
            <Typography variant="body1">
              {systemInfo.architecture || 'N/A'}
            </Typography>
          </Box>
        </Grid>
        <Grid item xs={12}>
          <Box>
            <Typography variant="caption" color="textSecondary" display="block">
              Last Scan
            </Typography>
            <Typography variant="body2">
              {systemInfo.scan_time
                ? new Date(systemInfo.scan_time).toLocaleString()
                : 'Never'}
            </Typography>
          </Box>
        </Grid>
      </Grid>
    </Paper>
  );
};

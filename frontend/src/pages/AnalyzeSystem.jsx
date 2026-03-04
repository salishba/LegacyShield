/**
 * Analyze System Page
 * Triggers REAL scanner backend with live progress tracking
 */

import React, { useState } from 'react';
import {
  Container,
  Paper,
  Button,
  Box,
  Typography,
  Grid,
  Divider,
  Chip,
  LinearProgress,
  CircularProgress,
  Stack,
  Alert
} from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import { useAnalysisScan, useSystemInfo } from '../hooks/useSmartPatch';
import { ScanProgress, SystemInfoDisplay, ErrorState } from '../components/SmartPatchUI';

export default function AnalyzeSystem() {
  const { scanning, progress, status, statusMessage, error, trigger } = useAnalysisScan();
  const { systemInfo, loading: sysLoading } = useSystemInfo();
  const [scanCompleted, setScanCompleted] = useState(false);
  const [scanResults, setScanResults] = useState(null);

  const handleStartAnalysis = async () => {
    setScanCompleted(false);
    setScanResults(null);
    
    try {
      const results = await trigger();
      setScanResults(results);
      setScanCompleted(true);
    } catch (err) {
      // Error is already set in the hook state
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 'bold', mb: 3 }}>
        Analyze System
      </Typography>

      {/* Pre-scan state */}
      {!scanning && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="body1" sx={{ mb: 3, color: 'text.secondary' }}>
                Click below to start a comprehensive system analysis. This will execute your real-time scanners to:
              </Typography>
              <Box sx={{ mb: 3 }}>
                <ul style={{ textAlign: 'left', display: 'inline-block' }}>
                  <li>Collect live system state and installed patches</li>
                  <li>Identify vulnerable software components</li>
                  <li>Compute HARS risk scores for each vulnerability</li>
                  <li>Generate actionable recommendations</li>
                </ul>
              </Box>
              <Button
                variant="contained"
                size="large"
                startIcon={<PlayArrowIcon />}
                onClick={handleStartAnalysis}
                disabled={scanning}
                sx={{ px: 4, py: 1.5 }}
              >
                {scanCompleted ? "Run Another Analysis" : "Start Analysis"}
              </Button>
            </Paper>
          </Grid>

          {/* Current system info */}
          {systemInfo && !sysLoading && (
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold' }}>
                  Current System
                </Typography>
                <Divider sx={{ my: 2 }} />
                <SystemInfoDisplay system={systemInfo} />
              </Paper>
            </Grid>
          )}
        </Grid>
      )}

      {/* Scanning state - Live progress */}
      {scanning && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 4, textAlign: 'center' }}>
              <Box sx={{ mb: 3 }}>
                <CircularProgress size={60} variant="determinate" value={progress} />
              </Box>
              <Typography variant="h6" sx={{ mb: 1, fontWeight: 'bold' }}>
                {status === 'initializing' ? 'Initializing...' : 'Scanning...'}
              </Typography>
              <Typography variant="body2" sx={{ mb: 3, color: 'text.secondary', minHeight: '48px', fontFamily: 'monospace', fontSize: '0.9rem' }}>
                {statusMessage}
              </Typography>

              <ScanProgress progress={progress} status={status} />

              {/* Stage breakdown */}
              <Box sx={{ mt: 4, textAlign: 'left' }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 2 }}>
                  Scanner Stages:
                </Typography>
                <Stack spacing={1}>
                  <ScanStage stage="Agent Initialization" progress={progress} threshold={10} />
                  <ScanStage stage="System State Checker" progress={progress} threshold={35} />
                  <ScanStage stage="Patch Collection" progress={progress} threshold={55} />
                  <ScanStage stage="HARS Scoring" progress={progress} threshold={75} />
                  <ScanStage stage="Finalization" progress={progress} threshold={100} />
                </Stack>
              </Box>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Error state */}
      {error && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <ErrorState 
              message={error} 
              onRetry={handleStartAnalysis}
            />
          </Grid>
        </Grid>
      )}

      {/* Scan completed state - Show results */}
      {scanCompleted && scanResults && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Alert severity="success" icon={<CheckCircleIcon />} sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                ✓ Analysis Complete
              </Typography>
              <Typography variant="body2">
                {scanResults.systemData?.hostname} scanned successfully. 
                Found {scanResults.vulnerabilities?.length || 0} vulnerabilities requiring assessment.
              </Typography>
            </Alert>
          </Grid>

          {/* System Info */}
          {scanResults.systemData && (
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold' }}>
                  System Information
                </Typography>
                <Divider sx={{ my: 2 }} />
                <SystemInfoDisplay system={scanResults.systemData} />
              </Paper>
            </Grid>
          )}

          {/* Scan Summary Stats */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold' }}>
                Scan Results
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Stack spacing={2}>
                <Box>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Vulnerabilities Found
                  </Typography>
                  <Typography variant="h5" sx={{ fontWeight: 'bold', color: 'error.main' }}>
                    {scanResults.vulnerabilities?.length || 0}
                  </Typography>
                </Box>
                {scanResults.riskSummary && (
                  <>
                    <Divider />
                    <Box>
                      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 1 }}>
                        Risk Distribution
                      </Typography>
                      <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
                        {scanResults.riskSummary.risk_distribution?.URGENT > 0 && (
                          <Chip 
                            label={`${scanResults.riskSummary.risk_distribution.URGENT} URGENT`} 
                            color="error"
                            size="small"
                          />
                        )}
                        {scanResults.riskSummary.risk_distribution?.IMPORTANT > 0 && (
                          <Chip 
                            label={`${scanResults.riskSummary.risk_distribution.IMPORTANT} IMPORTANT`} 
                            color="warning"
                            size="small"
                          />
                        )}
                        {scanResults.riskSummary.risk_distribution?.STANDARD > 0 && (
                          <Chip 
                            label={`${scanResults.riskSummary.risk_distribution.STANDARD} STANDARD`} 
                            color="info"
                            size="small"
                          />
                        )}
                      </Stack>
                    </Box>
                    <Divider />
                    <Box>
                      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                        Average HARS Score
                      </Typography>
                      <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                        {(scanResults.riskSummary.average_hars * 100).toFixed(1)}%
                      </Typography>
                    </Box>
                  </>
                )}
              </Stack>
            </Paper>
          </Grid>

          {/* Scan Output Logs */}
          {scanResults.scanOutput && (
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold' }}>
                  Scanner Output
                </Typography>
                <Divider sx={{ my: 2 }} />
                <Box
                  sx={{
                    bgcolor: '#1a1a1a',
                    color: '#00ff00',
                    p: 2,
                    borderRadius: 1,
                    fontFamily: 'monospace',
                    fontSize: '0.85rem',
                    maxHeight: '300px',
                    overflow: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    border: '1px solid #333'
                  }}
                >
                  {scanResults.scanOutput}
                </Box>
              </Paper>
            </Grid>
          )}

          {/* Start New Scan Button */}
          <Grid item xs={12}>
            <Button
              variant="contained"
              startIcon={<PlayArrowIcon />}
              onClick={handleStartAnalysis}
              fullWidth
              sx={{ py: 1.5 }}
            >
              Run Another Analysis
            </Button>
          </Grid>
        </Grid>
      )}
    </Container>
  );
}

/**
 * Component: Shows scanner stage with progress indicator
 */
function ScanStage({ stage, progress, threshold }) {
  const isComplete = progress >= threshold;
  const isActive = progress >= (threshold - 20) && progress < threshold;

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
      <Box sx={{ flex: 1 }}>
        <Typography variant="body2" sx={{ fontWeight: isActive ? 'bold' : 'normal' }}>
          {stage}
        </Typography>
      </Box>
      {isComplete && <CheckCircleIcon sx={{ color: 'success.main' }} />}
      {isActive && <CircularProgress size={20} />}
      {!isComplete && !isActive && <Box sx={{ width: 20, height: 20 }} />}
    </Box>
  );
}

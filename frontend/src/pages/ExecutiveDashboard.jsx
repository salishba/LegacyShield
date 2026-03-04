/**
 * Executive Dashboard - Business-Focused Risk Intelligence
 * What is risky, what is missing, what to fix, what is pending
 */

import React, { useState } from 'react';
import {
  Container,
  Box,
  Card,
  CardHeader,
  CardContent,
  Grid,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  CircularProgress
} from '@mui/material';
import {
  Warning as WarningIcon,
  Error as ErrorIcon,
  Security as SecurityIcon,
  Update as UpdateIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { 
  useRiskSummary, 
  useVulnerabilities, 
  useInstalledKbs,
  useSystemInfo,
  useAnalysisScan
} from '../hooks/useSmartPatch';


const ExecutiveDashboard = () => {
  const { summary, loading: summaryLoading, error: summaryError, refetch: refetchSummary } = useRiskSummary();
  const { vulnerabilities, loading: vulnLoading, error: vulnError, refetch: refetchVulns } = useVulnerabilities();
  const { kbs, loading: kbsLoading, refetch: refetchKbs } = useInstalledKbs();
  const { system: systemInfo, loading: systemLoading } = useSystemInfo();
  const { trigger, scanning } = useAnalysisScan();
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([refetchSummary(), refetchVulns(), refetchKbs()]);
    setRefreshing(false);
  };

  if (summaryLoading || vulnLoading || systemLoading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
        <CircularProgress />
      </Container>
    );
  }

  const riskDist = summary?.risk_distribution || {};
  const highCount = riskDist.HIGH || 0;
  const mediumCount = riskDist.MEDIUM || 0;
  const lowCount = riskDist.LOW || 0;
  const totalVulns = highCount + mediumCount + lowCount;

  // Determine exposure status based on risk
  const getExposureStatus = () => {
    if (highCount > 0) return { label: 'CRITICAL', color: '#d32f2f', bgcolor: '#ffebee' };
    if (mediumCount > 2) return { label: 'AT RISK', color: '#f57c00', bgcolor: '#fff3e0' };
    if (lowCount > 0) return { label: 'CAUTION', color: '#fbc02d', bgcolor: '#fffde7' };
    return { label: 'SECURE', color: '#388e3c', bgcolor: '#e8f5e9' };
  };

  const exposureStatus = getExposureStatus();

  // Get top 5 priority issues based on backend HARS ranking (highest risk first)
  const topIssues = [...(vulnerabilities || [])]
    .sort((a, b) => (b.hars_score || 0) - (a.hars_score || 0))
    .slice(0, 5);

  const getRiskColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return '#d32f2f';
      case 'MEDIUM':
        return '#f57c00';
      case 'LOW':
        return '#fbc02d';
      default:
        return '#757575';
    }
  };

  const getBusinessImpact = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'Critical';
      case 'MEDIUM':
        return 'High';
      case 'LOW':
        return 'Moderate';
      default:
        return 'Unknown';
    }
  };

  const lastScanTime = summary?.last_scan_time
    ? new Date(summary.last_scan_time).toLocaleString()
    : 'Never';

  if (summaryError || vulnError) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box sx={{ backgroundColor: '#ffebee', p: 3, borderRadius: 1, border: '1px solid #d32f2f' }}>
          <Typography color="error" variant="h6">
            Security Intelligence Service Unavailable
          </Typography>
          <Typography color="error" variant="body2" sx={{ mt: 1 }}>
            Unable to retrieve vulnerability data. Please ensure the backend service is running.
          </Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header with Refresh */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" sx={{ mb: 1, fontWeight: 'bold' }}>
            Security Intelligence Dashboard
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Real-time vulnerability prioritization and patch status
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={handleRefresh}
            disabled={refreshing}
            size="small"
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </Button>

          <Button
            variant="contained"
            color="primary"
            startIcon={<SecurityIcon />}
            onClick={async () => {
              await trigger();
              await handleRefresh();
            }}
            disabled={scanning}
            size="small"
          >
            {scanning ? 'Scanning...' : 'Run Analysis'}
          </Button>
        </Box>

      </Box>

      {/* Risk KPIs */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* System Status */}
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center', border: `3px solid ${exposureStatus.color}`, backgroundColor: exposureStatus.bgcolor }}>
            <Typography variant="caption" color="textSecondary" display="block" sx={{ mb: 1 }}>
              System Exposure
            </Typography>
            <Typography
              variant="h5"
              sx={{ fontWeight: 'bold', color: exposureStatus.color, mb: 1 }}
            >
              {exposureStatus.label}
            </Typography>
            <Chip
              label={`${highCount} Critical`}
              size="small"
              sx={{ backgroundColor: '#d32f2f', color: 'white', mr: 1 }}
            />
            <Chip
              label={`${mediumCount} High`}
              size="small"
              sx={{ backgroundColor: '#f57c00', color: 'white' }}
            />
          </Paper>
        </Grid>

        {/* Total Vulnerabilities */}
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <WarningIcon sx={{ fontSize: 32, color: '#f57c00', mb: 1 }} />
            <Typography variant="caption" color="textSecondary" display="block">
              Total Vulnerabilities
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#f57c00' }}>
              {totalVulns}
            </Typography>
          </Paper>
        </Grid>

        {/* Missing Patches */}
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <UpdateIcon sx={{ fontSize: 32, color: '#1976d2', mb: 1 }} />
            <Typography variant="caption" color="textSecondary" display="block">
              Missing Patches
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#1976d2' }}>
              {summary?.missing_kb_count || 0}
            </Typography>
          </Paper>
        </Grid>

        {/* Last Scan */}
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <SecurityIcon sx={{ fontSize: 32, color: '#388e3c', mb: 1 }} />
            <Typography variant="caption" color="textSecondary" display="block">
              Last Analysis
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 'bold', fontSize: '0.75rem' }}>
              {lastScanTime}
            </Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* Risk Distribution Breakdown */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="Risk Distribution" />
            <CardContent>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                    <Typography variant="body2">Critical Risk</Typography>
                    <Chip label={highCount} color="error" />
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                    <Typography variant="body2">High Risk</Typography>
                    <Chip label={mediumCount} sx={{ backgroundColor: '#f57c00', color: 'white' }} />
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="body2">Moderate Risk</Typography>
                    <Chip label={lowCount} sx={{ backgroundColor: '#fbc02d', color: 'black' }} />
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="System Information" />
            <CardContent>
              <Typography variant="body2" sx={{ mb: 1 }}>
                <strong>Hostname:</strong> {systemInfo?.hostname || 'Unknown'}
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                <strong>Operating System:</strong> {systemInfo?.os_caption || 'Unknown'}
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                <strong>Build:</strong> {systemInfo?.build_number || 'Unknown'}
              </Typography>
              <Typography variant="body2">
                <strong>Total Patches Installed:</strong> {kbs?.length || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Top 5 Priority Issues */}
      <Card>
        <CardHeader
          title="Top Priority Issues"
          subheader="Ranked by business risk impact - Address these first"
        />
        <CardContent>
          {topIssues.length === 0 ? (
            <Box sx={{ p: 2, textAlign: 'center', backgroundColor: '#e8f5e9', borderRadius: 1 }}>
              <SecurityIcon sx={{ fontSize: 48, color: '#388e3c', mb: 1 }} />
              <Typography color="success" sx={{ fontWeight: 'bold' }}>
                System is Secure
              </Typography>
              <Typography variant="caption" color="textSecondary">
                No critical vulnerabilities detected
              </Typography>
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
                    <TableCell><strong>Priority</strong></TableCell>
                    <TableCell><strong>Issue</strong></TableCell>
                    <TableCell><strong>Severity</strong></TableCell>
                    <TableCell><strong>Business Impact</strong></TableCell>
                    <TableCell><strong>Patch Available</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {topIssues.map((vuln, idx) => (
                    <TableRow key={vuln.cve_id}>
                      <TableCell sx={{ fontWeight: 'bold', color: getRiskColor(vuln.severity) }}>
                        #{idx + 1}
                      </TableCell>
                      <TableCell>{vuln.cve_id}</TableCell>
                      <TableCell>
                        <Chip
                          label={vuln.severity}
                          size="small"
                          sx={{
                            backgroundColor: getRiskColor(vuln.severity),
                            color: 'white'
                          }}
                        />
                      </TableCell>
                      <TableCell>{getBusinessImpact(vuln.severity)}</TableCell>
                      <TableCell>
                        {vuln.patch_available ? (
                          <Chip label="Available" color="success" size="small" />
                        ) : (
                          <Chip label="Pending" variant="outlined" size="small" />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>
    </Container>
  );
};

export default ExecutiveDashboard;

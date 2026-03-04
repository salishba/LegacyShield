/**
 * System Overview Page
 * Displays REAL system state checker output with installed patches
 * NO RISK SCORING - This is read-only system metadata
 */

import React from 'react';
import {
  Container,
  Paper,
  Box,
  Typography,
  Grid,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  Button
} from '@mui/material';
import InfoIcon from '@mui/icons-material/Info';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useSystemInfo, useInstalledKbs } from '../hooks/useSmartPatch';
import { LoadingState, ErrorState } from '../components/SmartPatchUI';

export default function SystemOverview() {
  const { system, loading: sysLoading, error: sysError, refetch: refetchSystem } = useSystemInfo();
  const { kbs, loading: kbsLoading, error: kbsError, refetch: refetchKbs } = useInstalledKbs();
  const [refreshing, setRefreshing] = React.useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refetchSystem();
      await refetchKbs();
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          System Overview
        </Typography>
        <Button 
          variant="outlined" 
          size="small"
          startIcon={<RefreshIcon />}
          onClick={handleRefresh}
          disabled={refreshing}
        >
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </Button>
      </Box>
      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 3 }}>
        Real system state from the most recent scan—no risk calculations here. See Risk Dashboard for HARS scoring.
      </Typography>

      <Grid container spacing={3}>
        {/* System Information Card */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold' }}>
              System Information
            </Typography>
            <Divider sx={{ my: 2 }} />

            {sysLoading ? (
              <LoadingState message="Loading system information..." />
            ) : sysError ? (
              <ErrorState message={sysError} />
            ) : system ? (
              <Grid container spacing={3}>
                {/* Row 1 */}
                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      HOSTNAME
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.95rem' }}>
                      {system.hostname || 'Unknown'}
                    </Typography>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      OS
                    </Typography>
                    <Typography variant="body2">
                      {system.os_caption || 'Unknown'}
                    </Typography>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      OS VERSION
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {system.os_version || 'Unknown'}
                    </Typography>
                  </Box>
                </Grid>

                {/* Row 2 */}
                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      BUILD NUMBER
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {system.build_number || 'Unknown'}
                    </Typography>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      ARCHITECTURE
                    </Typography>
                    <Typography variant="body2">
                      {system.architecture || 'Unknown'}
                    </Typography>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      DOMAIN
                    </Typography>
                    <Typography variant="body2">
                      {system.domain || 'Not joined'}
                    </Typography>
                  </Box>
                </Grid>

                {/* Row 3 */}
                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      DOMAIN MEMBER
                    </Typography>
                    <Typography variant="body2">
                      {system.part_of_domain ? 'Yes' : 'No'}
                    </Typography>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      ELEVATED (ADMIN)
                    </Typography>
                    <Typography variant="body2">
                      {system.elevated ? 'Yes' : 'No'}
                    </Typography>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      SCAN TIME
                    </Typography>
                    <Typography variant="body2" sx={{ fontSize: '0.85rem' }}>
                      {system.scan_time ? new Date(system.scan_time).toLocaleString() : 'Unknown'}
                    </Typography>
                  </Box>
                </Grid>

                {/* Row 4 */}
                <Grid item xs={12} sm={6} md={4}>
                  <Box>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                      AGENT VERSION
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {system.agent_version || 'Unknown'}
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            ) : (
              <Alert severity="info">
                <InfoIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                No system information available. Run "Analyze System" first.
              </Alert>
            )}
          </Paper>
        </Grid>

        {/* Installed Patches Table */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold' }}>
              Installed Patches
              {kbs && kbs.length > 0 && (
                <span style={{ marginLeft: '8px', color: '#666', fontSize: '0.85em' }}>
                  ({kbs.length} total)
                </span>
              )}
            </Typography>
            <Divider sx={{ my: 2 }} />

            {kbsLoading ? (
              <LoadingState message="Loading installed patches..." />
            ) : kbsError ? (
              <ErrorState message={kbsError} />
            ) : kbs && kbs.length > 0 ? (
              <TableContainer>
                <Table size="small" sx={{ '& td': { py: 1 } }}>
                  <TableHead>
                    <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
                      <TableCell sx={{ fontWeight: 'bold' }}>KB ID</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Install Date</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Source</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {kbs.map((kb) => (
                      <TableRow key={kb.kb_id} hover sx={{ '&:hover': { backgroundColor: '#fafafa' } }}>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>
                          {kb.kb_id}
                        </TableCell>
                        <TableCell>
                          {kb.install_date ? new Date(kb.install_date).toLocaleDateString() : 'Unknown'}
                        </TableCell>
                        <TableCell>{kb.source || 'N/A'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Alert severity="info">
                <InfoIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                No patch data available yet.
              </Alert>
            )}
          </Paper>
        </Grid>

        {/* Info Box */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, backgroundColor: '#f0f7ff', border: '1px solid #e0eeff' }}>
            <Typography variant="caption" sx={{ color: '#1976d2', fontWeight: 'bold', display: 'block', mb: 1 }}>
              ℹ️  DATA SOURCE
            </Typography>
            <Typography variant="body2" color="textSecondary">
              This page shows system state checker output—native Windows metadata only. No HARS calculations or AI scoring here. 
              For vulnerability assessment, risk scoring, and AI recommendations, visit the <strong>Risk & Priority Dashboard</strong>.
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
}

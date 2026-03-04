/**
 * Logs & Audit Page
 * Real audit trail of system scans, HARS decisions, and AI analysis
 */

import React, { useState } from 'react';
import {
  Container,
  Paper,
  Box,
  Typography,
  Card,
  CardHeader,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider,
  Alert,
  Chip
} from '@mui/material';
import {
  Info as InfoIcon,
  Assessment as AssessmentIcon,
  Check as CheckIcon
} from '@mui/icons-material';
import { useAuditLogs } from '../hooks/useSmartPatch';
import { LoadingState, ErrorState } from '../components/SmartPatchUI';

export default function AuditLogs() {
  const { logs, loading, error } = useAuditLogs();
  const [selectedLog, setSelectedLog] = useState(null);
  const [detailOpen, setDetailOpen] = useState(false);

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <LoadingState message="Loading audit logs..." />
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <ErrorState message={error} />
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 'bold', mb: 3 }}>
        Logs & Audit Trail
      </Typography>
      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 3 }}>
        Immutable audit history: system scans, HARS analysis, and AI decisions
      </Typography>

      <Grid container spacing={3}>
        {/* Summary Stats */}
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold' }}>
              TOTAL SCANS
            </Typography>
            <Typography variant="h4" sx={{ my: 1, fontWeight: 'bold', color: '#1976d2' }}>
              {logs.length}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold' }}>
              UNIQUE HOSTS
            </Typography>
            <Typography variant="h4" sx={{ my: 1, fontWeight: 'bold', color: '#388e3c' }}>
              {new Set(logs.map(l => l.scan_id)).size}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold' }}>
              TOTAL VULNS
            </Typography>
            <Typography variant="h4" sx={{ my: 1, fontWeight: 'bold', color: '#f57c00' }}>
              {logs.reduce((sum, l) => sum + (l.vulnerabilities_found || 0), 0)}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold' }}>
              URGENT
            </Typography>
            <Typography variant="h4" sx={{ my: 1, fontWeight: 'bold', color: '#d32f2f' }}>
              {logs.reduce((sum, l) => sum + (l.urgent_count || 0), 0)}
            </Typography>
          </Paper>
        </Grid>

        {/* Scan History Table */}
        <Grid item xs={12}>
          <Card>
            <CardHeader
              title="Scan History"
              subheader={`${logs.length} scans on record`}
            />
            <CardContent>
              {logs.length === 0 ? (
                <Alert severity="info">
                  <InfoIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  No scans yet. Run "Analyze System" to start.
                </Alert>
              ) : (
                <TableContainer>
                  <Table>
                    <TableHead sx={{ backgroundColor: '#f5f5f5' }}>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 'bold' }}>Scan Time</TableCell>
                        <TableCell sx={{ fontWeight: 'bold' }}>Hostname</TableCell>
                        <TableCell sx={{ fontWeight: 'bold' }}>OS</TableCell>
                        <TableCell align="center" sx={{ fontWeight: 'bold' }}>Vulnerabilities</TableCell>
                        <TableCell align="center" sx={{ fontWeight: 'bold' }}>URGENT</TableCell>
                        <TableCell align="center" sx={{ fontWeight: 'bold' }}>Action</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {logs.map((log, idx) => (
                        <TableRow key={idx} hover>
                          <TableCell sx={{ fontSize: '0.9rem' }}>
                            {new Date(log.scan_time).toLocaleString()}
                          </TableCell>
                          <TableCell sx={{ fontFamily: 'monospace', fontWeight: '600' }}>
                            {log.hostname}
                          </TableCell>
                          <TableCell sx={{ fontSize: '0.9rem' }}>{log.os}</TableCell>
                          <TableCell align="center">
                            <Typography
                              variant="body2"
                              sx={{
                                fontWeight: '600',
                                color: log.vulnerabilities_found > 0 ? '#d32f2f' : '#388e3c'
                              }}
                            >
                              {log.vulnerabilities_found}
                            </Typography>
                          </TableCell>
                          <TableCell align="center">
                            <Chip
                              label={log.urgent_count}
                              size="small"
                              color={log.urgent_count > 0 ? 'error' : 'default'}
                              variant="outlined"
                            />
                          </TableCell>
                          <TableCell align="center">
                            <Button
                              size="small"
                              variant="contained"
                              onClick={() => {
                                setSelectedLog(log);
                                setDetailOpen(true);
                              }}
                            >
                              Details
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Detail Dialog */}
      {selectedLog && (
        <Dialog open={detailOpen} onClose={() => setDetailOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <AssessmentIcon />
              <Typography variant="h6">Scan Details</Typography>
            </Box>
          </DialogTitle>

          <Divider />

          <DialogContent sx={{ pt: 3 }}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                  SCAN TIME
                </Typography>
                <Typography variant="body2">
                  {new Date(selectedLog.scan_time).toLocaleString()}
                </Typography>
              </Grid>

              <Grid item xs={12}>
                <Divider />
              </Grid>

              <Grid item xs={12} sm={6}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                  HOSTNAME
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {selectedLog.hostname}
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                  BUILD
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {selectedLog.build}
                </Typography>
              </Grid>

              <Grid item xs={12}>
                <Divider />
              </Grid>

              <Grid item xs={12} sm={6}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                  VULNERABILITIES FOUND
                </Typography>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: '600',
                    color: selectedLog.vulnerabilities_found > 0 ? '#d32f2f' : '#388e3c'
                  }}
                >
                  {selectedLog.vulnerabilities_found}
                </Typography>
              </Grid>

              <Grid item xs={12} sm={6}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                  URGENT PRIORITY
                </Typography>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: '600',
                    color: selectedLog.urgent_count > 0 ? '#d32f2f' : '#388e3c'
                  }}
                >
                  {selectedLog.urgent_count}
                </Typography>
              </Grid>

              <Grid item xs={12}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 'bold', display: 'block', mb: 0.5 }}>
                  DECISION TYPE
                </Typography>
                <Chip
                  icon={<CheckIcon />}
                  label={selectedLog.decision_type}
                  color="primary"
                  variant="outlined"
                />
              </Grid>
            </Grid>
          </DialogContent>

          <DialogActions sx={{ p: 2, borderTop: '1px solid #eee' }}>
            <Button onClick={() => setDetailOpen(false)} variant="contained">
              Close
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Container>
  );
}

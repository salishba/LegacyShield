/**
 * Mitigation Recommendations Workspace
 * Real AI/HARS-generated recommendations from the database
 * Displays actual mitigation techniques (registry, system, network)
 * Scripts are DISPLAY-ONLY, never auto-executed
 */

import React, { useState } from 'react';
import {
  Container,
  Box,
  Card,
  CardHeader,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TextField,
  InputAdornment,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Chip,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress
} from '@mui/material';
import {
  Search as SearchIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  Security as SecurityIcon,
  Router as RouterIcon,
  Warning as WarningIcon,
  FileCopy as FileCopyIcon
} from '@mui/icons-material';
import { useRecommendations, useMitigationDetails } from '../hooks/useSmartPatch';
import { LoadingState, ErrorState, RiskBadge } from '../components/SmartPatchUI';

const MitigationRecommendationsPage = () => {
  const { recommendations, loading, error } = useRecommendations();
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [selectedRec, setSelectedRec] = useState(null);
  const [detailOpen, setDetailOpen] = useState(false);

  // Filter by search term
  const filtered = recommendations.filter(
    r =>
      (r.cve_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        r.title?.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  // Sort by priority band and HARS score (highest risk first)
  const sorted = [...filtered].sort((a, b) => {
    const priorityOrder = { 'URGENT': 0, 'IMPORTANT': 1, 'STANDARD': 2 };
    const priorityA = priorityOrder[a.priority_band] ?? 99;
    const priorityB = priorityOrder[b.priority_band] ?? 99;
    if (priorityA !== priorityB) return priorityA - priorityB;
    return (b.hars_score || 0) - (a.hars_score || 0);
  });

  const paginated = sorted.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleOpenDetail = (rec) => {
    setSelectedRec(rec);
    setDetailOpen(true);
  };

  const handleCloseDetail = () => {
    setDetailOpen(false);
    setSelectedRec(null);
  };

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <LoadingState message="Loading AI recommendations..." />
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
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" sx={{ mb: 1 }}>
          Mitigation Recommendations
        </Typography>
        <Typography variant="body2" color="textSecondary">
          AI/HARS-generated recommendations prioritized by risk
        </Typography>
      </Box>

      <Card>
        <CardHeader
          title={`Actionable Recommendations (${sorted.length})`}
          subheader="Rows correspond to HARS-scored vulnerabilities requiring mitigation"
        />
        <CardContent>
          <Box sx={{ mb: 3 }}>
            <TextField
              placeholder="Search by CVE ID or title..."
              variant="outlined"
              size="small"
              fullWidth
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(0);
              }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ color: 'action.active', mr: 1 }} />
                  </InputAdornment>
                )
              }}
            />
          </Box>

          {sorted.length === 0 ? (
            <Alert severity="info">
              <InfoIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              No recommendations available. Run analysis to generate recommendations.
            </Alert>
          ) : (
            <>
              <TableContainer>
                <Table size="small">
                  <TableHead sx={{ backgroundColor: '#f5f5f5' }}>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 'bold' }}>Priority</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>CVE ID</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Risk Summary</TableCell>
                      <TableCell align="center" sx={{ fontWeight: 'bold' }}>
                        HARS Score
                      </TableCell>
                      <TableCell align="center" sx={{ fontWeight: 'bold' }}>
                        Confidence
                      </TableCell>
                      <TableCell align="center" sx={{ fontWeight: 'bold' }}>
                        Actions
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {paginated.map((rec, idx) => (
                      <TableRow key={idx} hover>
                        <TableCell>
                          <Chip
                            label={rec.priority_band}
                            size="small"
                            color={rec.priority_band === 'URGENT' ? 'error' : rec.priority_band === 'IMPORTANT' ? 'warning' : 'default'}
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85rem', fontWeight: '600' }}>
                          {rec.cve_id}
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ maxWidth: '250px' }}>
                            {rec.title || 'Vulnerability'}
                          </Typography>
                        </TableCell>
                        <TableCell align="center">
                          <Typography
                            variant="body2"
                            sx={{
                              fontWeight: '600',
                              color:
                                rec.hars_score >= 0.7
                                  ? '#d32f2f'
                                  : rec.hars_score >= 0.35
                                  ? '#f57c00'
                                  : '#388e3c'
                            }}
                          >
                            {rec.hars_score?.toFixed(3) || 'N/A'}
                          </Typography>
                        </TableCell>
                        <TableCell align="center">
                          <Typography variant="body2">
                            {(rec.ai_confidence?.toFixed ? (rec.ai_confidence * 100).toFixed(0) : 'N/A')}%
                          </Typography>
                        </TableCell>
                        <TableCell align="center">
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={() => handleOpenDetail(rec)}
                            startIcon={<InfoIcon />}
                          >
                            Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <TablePagination
                rowsPerPageOptions={[5, 10, 25, 50]}
                component="div"
                count={sorted.length}
                rowsPerPage={rowsPerPage}
                page={page}
                onPageChange={handleChangePage}
                onRowsPerPageChange={handleChangeRowsPerPage}
              />
            </>
          )}
        </CardContent>
      </Card>

      {/* Detail Dialog */}
      <RecommendationDetailDialog
        open={detailOpen}
        rec={selectedRec}
        onClose={handleCloseDetail}
      />
    </Container>
  );
};

/**
 * Recommendation Detail Dialog
 * Displays risk context, HARS breakdown, and mitigation techniques from database
 */
const RecommendationDetailDialog = ({ open, rec, onClose }) => {
  const { mitigation, loading } = useMitigationDetails(rec?.cve_id);

  if (!rec) return null;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ borderBottom: '1px solid #eee' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: '600' }}>
              Mitigation Details
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mt: 0.5 }}>
              {rec.cve_id}
            </Typography>
          </Box>
          <Chip
            label={rec.priority_band}
            size="small"
            color={rec.priority_band === 'URGENT' ? 'error' : rec.priority_band === 'IMPORTANT' ? 'warning' : 'default'}
            variant="outlined"
          />
        </Box>
      </DialogTitle>

      <DialogContent sx={{ mt: 2 }}>
        {/* Risk Context */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: '600', mb: 1 }}>
            📋 Risk Context
          </Typography>
          <Paper sx={{ p: 2, backgroundColor: '#f9f9f9' }}>
            <Typography variant="body2" paragraph>
              <strong>Vulnerability:</strong> {rec.title}
            </Typography>
            <Typography variant="body2">
              <strong>Risk Level:</strong> {rec.priority_band}
            </Typography>
          </Paper>
        </Box>

        {/* HARS Scoring Breakdown */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: '600', mb: 1 }}>
            📊 HARS Scoring Breakdown
          </Typography>
          <Paper sx={{ p: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={6} sm={3}>
                <Box>
                  <Typography variant="caption" color="textSecondary">
                    R Score (Reachability)
                  </Typography>
                  <Box sx={{ mt: 1, mb: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(rec.r_score || 0) * 100}
                      sx={{ height: 8, borderRadius: 1 }}
                    />
                  </Box>
                  <Typography variant="body2" sx={{ fontWeight: '600' }}>
                    {rec.r_score?.toFixed(3) || '0.000'}
                  </Typography>
                </Box>
              </Grid>

              <Grid item xs={6} sm={3}>
                <Box>
                  <Typography variant="caption" color="textSecondary">
                    A Score (Exploitability)
                  </Typography>
                  <Box sx={{ mt: 1, mb: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(rec.a_score || 0) * 100}
                      sx={{ height: 8, borderRadius: 1 }}
                    />
                  </Box>
                  <Typography variant="body2" sx={{ fontWeight: '600' }}>
                    {rec.a_score?.toFixed(3) || '0.000'}
                  </Typography>
                </Box>
              </Grid>

              <Grid item xs={6} sm={3}>
                <Box>
                  <Typography variant="caption" color="textSecondary">
                    C Score (Criticality)
                  </Typography>
                  <Box sx={{ mt: 1, mb: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(rec.c_score || 0) * 100}
                      sx={{ height: 8, borderRadius: 1 }}
                    />
                  </Box>
                  <Typography variant="body2" sx={{ fontWeight: '600' }}>
                    {rec.c_score?.toFixed(3) || '0.000'}
                  </Typography>
                </Box>
              </Grid>

              <Grid item xs={6} sm={3}>
                <Box>
                  <Typography variant="caption" color="textSecondary">
                    Final HARS Score
                  </Typography>
                  <Box sx={{ mt: 1, mb: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={(rec.hars_score || 0) * 100}
                      sx={{
                        height: 8,
                        borderRadius: 1,
                        '& .MuiLinearProgress-bar': {
                          backgroundColor: rec.hars_score >= 0.7 ? '#d32f2f' : rec.hars_score >= 0.35 ? '#f57c00' : '#388e3c'
                        }
                      }}
                    />
                  </Box>
                  <Typography
                    variant="body2"
                    sx={{
                      fontWeight: '600',
                      color: rec.hars_score >= 0.7 ? '#d32f2f' : rec.hars_score >= 0.35 ? '#f57c00' : '#388e3c'
                    }}
                  >
                    {rec.hars_score?.toFixed(3) || '0.000'}
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>
        </Box>

        {/* Mitigation Techniques */}
        <Box>
          <Typography variant="subtitle2" sx={{ fontWeight: '600', mb: 1 }}>
            🔧 Mitigation Techniques
          </Typography>

          {loading ? (
            <Box sx={{ p: 2, textAlign: 'center' }}>
              <Typography variant="body2" color="textSecondary">Loading mitigation options...</Typography>
            </Box>
          ) : mitigation ? (
            <>
              {/* Registry Mitigations */}
              {mitigation.registry_mitigations && mitigation.registry_mitigations.length > 0 && (
                <Accordion defaultExpanded>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <SecurityIcon sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">
                      Registry Mitigations ({mitigation.registry_mitigations.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ backgroundColor: '#f9f9f9' }}>
                    {mitigation.registry_mitigations.map((tech, idx) => (
                      <Box key={idx} sx={{ mb: 2, p: 1.5, backgroundColor: '#fff', borderRadius: 1, border: '1px solid #eee' }}>
                        <Typography variant="body2" sx={{ fontWeight: '600' }}>
                          {tech.description ||  `Registry Key: HKLM\\${tech.registry_key || 'Unknown'}`}
                        </Typography>
                        {tech.command && (
                          <Paper
                            sx={{
                              p: 1,
                              mt: 1,
                              backgroundColor: '#1a1a1a',
                              color: '#00ff00',
                              fontFamily: 'monospace',
                              fontSize: '0.8rem',
                              overflow: 'auto',
                              maxHeight: '120px'
                            }}
                          >
                            <Typography
                              component="pre"
                              variant="body2"
                              sx={{
                                m: 0,
                                color: '#00ff00',
                                fontFamily: 'monospace',
                                fontSize: '0.8rem',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word'
                              }}
                            >
                              {tech.command}
                            </Typography>
                          </Paper>
                        )}
                        <Alert severity="warning" sx={{ mt: 1, py: 0.5 }}>
                          <Typography variant="caption">
                            ⚠️ Display-only reference. Never auto-executed. Test in lab environment first.
                          </Typography>
                        </Alert>
                      </Box>
                    ))}
                  </AccordionDetails>
                </Accordion>
              )}

              {/* System Mitigations */}
              {mitigation.system_mitigations && mitigation.system_mitigations.length > 0 && (
                <Accordion sx={{ mt: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <CheckCircleIcon sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">
                      System Mitigations ({mitigation.system_mitigations.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ backgroundColor: '#f9f9f9' }}>
                    {mitigation.system_mitigations.map((tech, idx) => (
                      <Box key={idx} sx={{ mb: 2, p: 1.5, backgroundColor: '#fff', borderRadius: 1, border: '1px solid #eee' }}>
                        <Typography variant="body2" sx={{ fontWeight: '600' }}>
                          {tech.description || 'System Configuration'}
                        </Typography>
                        {tech.command && (
                          <Paper
                            sx={{
                              p: 1,
                              mt: 1,
                              backgroundColor: '#1a1a1a',
                              color: '#00ff00',
                              fontFamily: 'monospace',
                              fontSize: '0.8rem',
                              overflow: 'auto',
                              maxHeight: '120px'
                            }}
                          >
                            <Typography
                              component="pre"
                              variant="body2"
                              sx={{
                                m: 0,
                                color: '#00ff00',
                                fontFamily: 'monospace',
                                fontSize: '0.8rem',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word'
                              }}
                            >
                              {tech.command}
                            </Typography>
                          </Paper>
                        )}
                        <Alert severity="info" sx={{ mt: 1, py: 0.5 }}>
                          <Typography variant="caption">
                            ℹ️ System-level configuration. Requires administrative privileges.
                          </Typography>
                        </Alert>
                      </Box>
                    ))}
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Network Mitigations */}
              {mitigation.network_mitigations && mitigation.network_mitigations.length > 0 && (
                <Accordion sx={{ mt: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <RouterIcon sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">
                      Network Mitigations ({mitigation.network_mitigations.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ backgroundColor: '#f9f9f9' }}>
                    {mitigation.network_mitigations.map((tech, idx) => (
                      <Box key={idx} sx={{ mb: 2, p: 1.5, backgroundColor: '#fff', borderRadius: 1, border: '1px solid #eee' }}>
                        <Typography variant="body2" sx={{ fontWeight: '600' }}>
                          {tech.description || 'Network Configuration'}
                        </Typography>
                        {tech.command && (
                          <Paper
                            sx={{
                              p: 1,
                              mt: 1,
                              backgroundColor: '#1a1a1a',
                              color: '#00ff00',
                              fontFamily: 'monospace',
                              fontSize: '0.8rem',
                              overflow: 'auto',
                              maxHeight: '120px'
                            }}
                          >
                            <Typography
                              component="pre"
                              variant="body2"
                              sx={{
                                m: 0,
                                color: '#00ff00',
                                fontFamily: 'monospace',
                                fontSize: '0.8rem',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word'
                              }}
                            >
                              {tech.command}
                            </Typography>
                          </Paper>
                        )}
                        <Alert severity="warning" sx={{ mt: 1, py: 0.5 }}>
                          <Typography variant="caption">
                            🔒 Network-level rule. Impacts system connectivity. Coordinate with network team.
                          </Typography>
                        </Alert>
                      </Box>
                    ))}
                  </AccordionDetails>
                </Accordion>
              )}

              {!mitigation.registry_mitigations?.length && !mitigation.system_mitigations?.length && !mitigation.network_mitigations?.length && (
                <Alert severity="info">
                  <Typography variant="body2">
                    No specific mitigation techniques available. Please refer to Microsoft Security Advisory.
                  </Typography>
                </Alert>
              )}
            </>
          ) : (
            <Alert severity="info">
              <Typography variant="body2">
                Mitigation details not available. Check backend connectivity.
              </Typography>
            </Alert>
          )}
        </Box>
      </DialogContent>

      <DialogActions sx={{ p: 2, borderTop: '1px solid #eee' }}>
        <Button onClick={onClose} variant="contained">
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default MitigationRecommendationsPage;

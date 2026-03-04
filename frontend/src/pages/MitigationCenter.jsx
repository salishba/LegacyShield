/**
 * Mitigation Center - Remediation Recommendations & Execution
 * Displays recommended actions with status tracking and deployment guidance
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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Paper,
  Button,
  CircularProgress,
  Tabs,
  Tab,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Schedule as ScheduleIcon,
  Build as BuildIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Settings as SettingsIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { useRecommendations } from '../hooks/useSmartPatch';

const MitigationCenterPage = () => {
  const { recommendations, loading, error, refetch } = useRecommendations();
  const [activeTab, setActiveTab] = useState(0);
  const [selectedRec, setSelectedRec] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
  };

  const handleOpenDetails = (rec) => {
    setSelectedRec(rec);
    setDetailsOpen(true);
  };

  // Categorize recommendations by type
  const getCategoryCount = (category) => {
    return (recommendations || []).filter(r => r.mitigation_type?.toUpperCase() === category?.toUpperCase()).length;
  };

  const getPatchRecommendations = () =>
    (recommendations || []).filter(r => r.mitigation_type?.toUpperCase() === 'PATCH');

  const getConfigRecommendations = () =>
    (recommendations || []).filter(r => r.mitigation_type?.toUpperCase() === 'CONFIG');

  const getServiceRecommendations = () =>
    (recommendations || []).filter(r => r.mitigation_type?.toUpperCase() === 'SERVICE');

  const getRegistryRecommendations = () =>
    (recommendations || []).filter(r => r.mitigation_type?.toUpperCase() === 'REGISTRY');

  const getStatusColor = (status) => {
    switch (status?.toUpperCase()) {
      case 'COMPLETED':
      case 'SUCCESS':
        return '#388e3c';
      case 'FAILED':
        return '#d32f2f';
      case 'PENDING':
        return '#fbc02d';
      case 'IN_PROGRESS':
        return '#1976d2';
      default:
        return '#757575';
    }
  };

  const getStatusLabel = (status) => {
    switch (status?.toUpperCase()) {
      case 'COMPLETED':
      case 'SUCCESS':
        return 'Completed';
      case 'FAILED':
        return 'Failed';
      case 'PENDING':
        return 'Pending';
      case 'IN_PROGRESS':
        return 'In Progress';
      default:
        return 'Unknown';
    }
  };

  const getMitigationIcon = (type) => {
    switch (type?.toUpperCase()) {
      case 'PATCH':
        return <DownloadIcon />;
      case 'CONFIG':
        return <SettingsIcon />;
      case 'SERVICE':
        return <BuildIcon />;
      case 'REGISTRY':
        return <InfoIcon />;
      default:
        return <InfoIcon />;
    }
  };

  const RecommendationTable = ({ recs }) => {
    if (!recs || recs.length === 0) {
      return (
        <Box sx={{ p: 3, textAlign: 'center', backgroundColor: '#f5f5f5', borderRadius: 1 }}>
          <Typography color="textSecondary">No recommendations in this category</Typography>
        </Box>
      );
    }

    return (
      <TableContainer>
        <Table>
          <TableHead>
            <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
              <TableCell><strong>Action</strong></TableCell>
              <TableCell><strong>Component</strong></TableCell>
              <TableCell><strong>Type</strong></TableCell>
              <TableCell><strong>Reboot</strong></TableCell>
              <TableCell><strong>Downtime</strong></TableCell>
              <TableCell><strong>Status</strong></TableCell>
              <TableCell><strong>Action</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {recs.map((rec, idx) => (
              <TableRow key={idx} sx={{ '&:hover': { backgroundColor: '#f5f5f5' } }}>
                <TableCell>{rec.action || 'Apply patch'}</TableCell>
                <TableCell>{rec.component_name || 'System'}</TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {getMitigationIcon(rec.mitigation_type)}
                    <Typography variant="body2">
                      {rec.mitigation_type || 'Unknown'}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  {rec.requires_reboot ? (
                    <Chip label="Yes" color="warning" size="small" />
                  ) : (
                    <Chip label="No" size="small" />
                  )}
                </TableCell>
                <TableCell>
                  {rec.downtime_impact || 'Minimal'}
                </TableCell>
                <TableCell>
                  <Chip
                    label={getStatusLabel(rec.execution_status)}
                    sx={{
                      backgroundColor: getStatusColor(rec.execution_status),
                      color: 'white'
                    }}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<InfoIcon />}
                    onClick={() => handleOpenDetails(rec)}
                  >
                    Details
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    );
  };

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
        <CircularProgress />
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box sx={{ backgroundColor: '#ffebee', p: 3, borderRadius: 1, border: '1px solid #d32f2f' }}>
          <Typography color="error" variant="h6">
            Unable to Load Recommendations
          </Typography>
          <Typography color="error" variant="body2" sx={{ mt: 1 }}>
            {error}
          </Typography>
        </Box>
      </Container>
    );
  }

  const patches = getPatchRecommendations();
  const configs = getConfigRecommendations();
  const services = getServiceRecommendations();
  const registry = getRegistryRecommendations();

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" sx={{ mb: 1, fontWeight: 'bold' }}>
            Mitigation Center
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Recommended actions to remediate detected vulnerabilities
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={handleRefresh}
          disabled={refreshing}
          size="small"
        >
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </Button>
      </Box>

      {/* Summary Stats */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Total Recommendations
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#1976d2' }}>
              {recommendations?.length || 0}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Completed
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#388e3c' }}>
              {(recommendations || []).filter(r => r.execution_status?.toUpperCase() === 'COMPLETED' || r.execution_status?.toUpperCase() === 'SUCCESS').length}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Pending
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#fbc02d' }}>
              {(recommendations || []).filter(r => r.execution_status?.toUpperCase() === 'PENDING').length}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Failed
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#d32f2f' }}>
              {(recommendations || []).filter(r => r.execution_status?.toUpperCase() === 'FAILED').length}
            </Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* Info Alert */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          <strong>Deployment Strategy:</strong> Review all recommendations before applying. Test patches in staging environment first. Schedule critical patches during maintenance windows.
        </Typography>
      </Alert>

      {/* Tabs for Mitigation Types */}
      <Card>
        <CardHeader title="Mitigations by Type" />
        <CardContent>
          <Tabs value={activeTab} onChange={(e, val) => setActiveTab(val)}>
            <Tab label={`Patches (${patches.length})`} />
            <Tab label={`Config (${configs.length})`} />
            <Tab label={`Services (${services.length})`} />
            <Tab label={`Registry (${registry.length})`} />
          </Tabs>

          {activeTab === 0 && <Box sx={{ mt: 3 }}><RecommendationTable recs={patches} /></Box>}
          {activeTab === 1 && <Box sx={{ mt: 3 }}><RecommendationTable recs={configs} /></Box>}
          {activeTab === 2 && <Box sx={{ mt: 3 }}><RecommendationTable recs={services} /></Box>}
          {activeTab === 3 && <Box sx={{ mt: 3 }}><RecommendationTable recs={registry} /></Box>}
        </CardContent>
      </Card>

      {/* Details Dialog */}
      <Dialog open={detailsOpen} onClose={() => setDetailsOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Mitigation Details</DialogTitle>
        <DialogContent>
          {selectedRec && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 2 }}>
                {selectedRec.action || 'Apply recommended action'}
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="caption" color="textSecondary"><strong>Type:</strong></Typography>
                  <Typography variant="body2">{selectedRec.mitigation_type || 'Unknown'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="textSecondary"><strong>Component:</strong></Typography>
                  <Typography variant="body2">{selectedRec.component_name || 'System'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="textSecondary"><strong>Execution Steps:</strong></Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    {selectedRec.execution_steps || 'Follow standard deployment procedures'}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary"><strong>Reboot Required:</strong></Typography>
                  <Typography variant="body2">{selectedRec.requires_reboot ? 'Yes' : 'No'}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="textSecondary"><strong>Downtime:</strong></Typography>
                  <Typography variant="body2">{selectedRec.downtime_impact || 'Minimal'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="textSecondary"><strong>Rollback Available:</strong></Typography>
                  <Typography variant="body2">{selectedRec.rollback_available ? 'Yes' : 'No'}</Typography>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default MitigationCenterPage;

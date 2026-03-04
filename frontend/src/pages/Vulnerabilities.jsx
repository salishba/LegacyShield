/**
 * Vulnerabilities Page - Detailed CVE Analysis & Prioritization
 * Primary workspace for security analysts to review detected vulnerabilities
 */

import React, { useState, useMemo } from 'react';
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
  TextField,
  MenuItem,
  CircularProgress,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions
} from '@mui/material';
import {
  Warning as WarningIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { useVulnerabilities } from '../hooks/useSmartPatch';

// Expanded row component
const VulnerabilityDetails = ({ vuln }) => {
  return (
    <Box sx={{ p: 2, backgroundColor: '#f5f5f5', borderRadius: 1 }}>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={6}>
          <Typography variant="caption" color="textSecondary">
            <strong>Description:</strong>
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            {vuln.description || 'No description available'}
          </Typography>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Typography variant="caption" color="textSecondary">
            <strong>Remediation:</strong>
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            {vuln.remediation || 'Install latest patch for affected component'}
          </Typography>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Typography variant="caption" color="textSecondary">
            <strong>CVSS Score:</strong>
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            {vuln.cvss_score || 'Not available'}
          </Typography>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Typography variant="caption" color="textSecondary">
            <strong>Exploit Status:</strong>
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            {vuln.exploit_available ? 'Public exploit available' : 'No known public exploit'}
          </Typography>
        </Grid>
      </Grid>
    </Box>
  );
};

const VulnerabilitiesPage = () => {
  const { vulnerabilities, loading, error, refetch } = useVulnerabilities();
  const [searchText, setSearchText] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [patchFilter, setPatchFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
  };

  // Filter and search
  const filteredVulns = useMemo(() => {
    return (vulnerabilities || []).filter(vuln => {
      const matchesSearch = vuln.cve_id.toLowerCase().includes(searchText.toLowerCase()) ||
        (vuln.description && vuln.description.toLowerCase().includes(searchText.toLowerCase()));
      
      const matchesSeverity = severityFilter === 'ALL' || vuln.severity === severityFilter;
      
      let matchesPatch = true;
      if (patchFilter === 'AVAILABLE') {
        matchesPatch = vuln.patch_available === true;
      } else if (patchFilter === 'PENDING') {
        matchesPatch = vuln.patch_available !== true;
      }

      return matchesSearch && matchesSeverity && matchesPatch;
    });
  }, [vulnerabilities, searchText, severityFilter, patchFilter]);

  // Sort by business priority (highest risk first)
  const sortedVulns = useMemo(() => {
    return [...filteredVulns].sort((a, b) => {
      // Priority by severity
      const severityRank = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      const rankA = severityRank[a.severity?.toUpperCase()] || 0;
      const rankB = severityRank[b.severity?.toUpperCase()] || 0;
      
      if (rankB !== rankA) return rankB - rankA;
      
      // Then by HARS score (if available)
      return (b.hars_score || 0) - (a.hars_score || 0);
    });
  }, [filteredVulns]);

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

  const getSeverityLabel = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'Critical';
      case 'HIGH':
        return 'High';
      case 'MEDIUM':
        return 'Moderate';
      case 'LOW':
        return 'Low';
      default:
        return 'Unknown';
    }
  };

  const handleOpenDetails = (vuln) => {
    setSelectedVuln(vuln);
    setDetailsOpen(true);
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
            Unable to Load Vulnerabilities
          </Typography>
          <Typography color="error" variant="body2" sx={{ mt: 1 }}>
            {error}
          </Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" sx={{ mb: 1, fontWeight: 'bold' }}>
            Detected Vulnerabilities
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Full analysis of system vulnerabilities with prioritization
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
              Total Vulnerabilities
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#1976d2' }}>
              {vulnerabilities?.length || 0}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Critical / High
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#d32f2f' }}>
              {(vulnerabilities || []).filter(v => ['CRITICAL', 'HIGH'].includes(v.severity?.toUpperCase())).length}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              With Patches
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#388e3c' }}>
              {(vulnerabilities || []).filter(v => v.patch_available).length}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Pending Patches
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#f57c00' }}>
              {(vulnerabilities || []).filter(v => !v.patch_available).length}
            </Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                placeholder="Search CVE or description..."
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />
                }}
                size="small"
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                select
                label="Filter by Severity"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                size="small"
              >
                <MenuItem value="ALL">All Severities</MenuItem>
                <MenuItem value="CRITICAL">Critical</MenuItem>
                <MenuItem value="HIGH">High</MenuItem>
                <MenuItem value="MEDIUM">Moderate</MenuItem>
                <MenuItem value="LOW">Low</MenuItem>
              </TextField>
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                fullWidth
                select
                label="Filter by Patch Status"
                value={patchFilter}
                onChange={(e) => setPatchFilter(e.target.value)}
                size="small"
              >
                <MenuItem value="ALL">All Patches</MenuItem>
                <MenuItem value="AVAILABLE">Patch Available</MenuItem>
                <MenuItem value="PENDING">Patch Pending</MenuItem>
              </TextField>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Vulnerabilities Table */}
      <Card>
        <CardHeader
          title={`Vulnerabilities (${sortedVulns.length} of ${vulnerabilities?.length || 0})`}
          subheader="Sorted by risk severity and priority"
        />
        <CardContent>
          {sortedVulns.length === 0 ? (
            <Box sx={{ p: 3, textAlign: 'center', backgroundColor: '#e8f5e9', borderRadius: 1 }}>
              <WarningIcon sx={{ fontSize: 48, color: '#388e3c', mb: 1 }} />
              <Typography color="success" sx={{ fontWeight: 'bold' }}>
                No Vulnerabilities Match Filters
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Try adjusting your search criteria
              </Typography>
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
                    <TableCell><strong>CVE ID</strong></TableCell>
                    <TableCell><strong>Component</strong></TableCell>
                    <TableCell><strong>Severity</strong></TableCell>
                    <TableCell><strong>CVSS Score</strong></TableCell>
                    <TableCell><strong>Exploit</strong></TableCell>
                    <TableCell><strong>Patch</strong></TableCell>
                    <TableCell><strong>Action</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sortedVulns.map(vuln => (
                    <TableRow key={vuln.cve_id} sx={{ '&:hover': { backgroundColor: '#f5f5f5' }, cursor: 'pointer' }}>
                      <TableCell sx={{ fontWeight: 'bold', color: getRiskColor(vuln.severity) }}>
                        {vuln.cve_id}
                      </TableCell>
                      <TableCell>
                        {vuln.affected_component || 'System'}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={getSeverityLabel(vuln.severity)}
                          sx={{
                            backgroundColor: getRiskColor(vuln.severity),
                            color: 'white'
                          }}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {vuln.cvss_score ? (
                          <Chip
                            label={vuln.cvss_score.toFixed(1)}
                            size="small"
                            sx={{
                              backgroundColor: vuln.cvss_score >= 7 ? '#d32f2f' : vuln.cvss_score >= 4 ? '#f57c00' : '#388e3c',
                              color: 'white'
                            }}
                          />
                        ) : 'N/A'}
                      </TableCell>
                      <TableCell>
                        {vuln.exploit_available ? (
                          <Chip label="Yes" color="error" size="small" />
                        ) : (
                          <Chip label="No" size="small" />
                        )}
                      </TableCell>
                      <TableCell>
                        {vuln.patch_available ? (
                          <Chip label="Available" color="success" size="small" />
                        ) : (
                          <Chip label="Pending" variant="outlined" size="small" />
                        )}
                      </TableCell>
                      <TableCell>
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<InfoIcon />}
                          onClick={() => handleOpenDetails(vuln)}
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

      {/* Details Dialog */}
      <Dialog open={detailsOpen} onClose={() => setDetailsOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{selectedVuln?.cve_id}</DialogTitle>
        <DialogContent>
          {selectedVuln && <VulnerabilityDetails vuln={selectedVuln} />}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default VulnerabilitiesPage;

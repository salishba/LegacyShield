/**
 * Missing Patches Page - Critical Patch Requirements
 * Displays required KBs with risk assessment and priority
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
  Button
} from '@mui/material';
import {
  Update as UpdateIcon,
  Warning as WarningIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  GetApp as DownloadIcon
} from '@mui/icons-material';
import { useVulnerabilities, useInstalledKbs } from '../hooks/useSmartPatch';

const MissingPatchesPage = () => {
  const { vulnerabilities, loading: vulnLoading, error: vulnError, refetch: refetchVulns } = useVulnerabilities();
  const { kbs: installedKbs, loading: kbsLoading, refetch: refetchKbs } = useInstalledKbs();
  const [searchText, setSearchText] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([refetchVulns(), refetchKbs()]);
    setRefreshing(false);
  };

  // Extract KB requirements from vulnerabilities
  const requiredKbs = useMemo(() => {
    if (!vulnerabilities || vulnerabilities.length === 0) return [];

    const kbMap = new Map();
    const installedKbIds = new Set(installedKbs?.map(kb => kb.kb_id) || []);

    vulnerabilities.forEach(vuln => {
      if (vuln.kb_id && !installedKbIds.has(vuln.kb_id)) {
        if (!kbMap.has(vuln.kb_id)) {
          kbMap.set(vuln.kb_id, {
            kb_id: vuln.kb_id,
            cve_ids: [],
            severity: vuln.severity,
            release_date: vuln.release_date,
            patch_url: vuln.patch_url,
            downtime_impact: vuln.downtime_impact,
            requires_reboot: vuln.requires_reboot,
            supersedes: vuln.supersedes,
          });
        }
        const kb = kbMap.get(vuln.kb_id);
        if (!kb.cve_ids.includes(vuln.cve_id)) {
          kb.cve_ids.push(vuln.cve_id);
        }
        // Keep highest severity
        if (getSeverityRank(vuln.severity) > getSeverityRank(kb.severity)) {
          kb.severity = vuln.severity;
        }
      }
    });

    return Array.from(kbMap.values());
  }, [vulnerabilities, installedKbs]);

  // Filter and search
  const filteredPatches = useMemo(() => {
    return requiredKbs.filter(kb => {
      const matchesSearch = kb.kb_id.toLowerCase().includes(searchText.toLowerCase()) ||
        kb.cve_ids.join(',').toLowerCase().includes(searchText.toLowerCase());
      
      const matchesSeverity = severityFilter === 'ALL' || kb.severity === severityFilter;

      return matchesSearch && matchesSeverity;
    });
  }, [requiredKbs, searchText, severityFilter]);

  const getSeverityRank = (severity) => {
    const ranks = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    return ranks[severity?.toUpperCase()] || 0;
  };

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

  if (vulnLoading || kbsLoading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
        <CircularProgress />
      </Container>
    );
  }

  if (vulnError) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box sx={{ backgroundColor: '#ffebee', p: 3, borderRadius: 1, border: '1px solid #d32f2f' }}>
          <Typography color="error" variant="h6">
            Unable to Load Patch Data
          </Typography>
          <Typography color="error" variant="body2" sx={{ mt: 1 }}>
            {vulnError}
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
            Missing Patches
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Critical patches required for identified vulnerabilities
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

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <UpdateIcon sx={{ fontSize: 32, color: '#d32f2f', mb: 1 }} />
            <Typography variant="caption" color="textSecondary" display="block">
              Total Missing Patches
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#d32f2f' }}>
              {filteredPatches.length}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <WarningIcon sx={{ fontSize: 32, color: '#f57c00', mb: 1 }} />
            <Typography variant="caption" color="textSecondary" display="block">
              Requiring Reboot
            </Typography>
            <Typography variant="h3" sx={{ fontWeight: 'bold', color: '#f57c00' }}>
              {filteredPatches.filter(p => p.requires_reboot).length}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block" sx={{ mb: 1 }}>
              Critical Risk
            </Typography>
            <Chip
              label={filteredPatches.filter(p => getSeverityRank(p.severity) >= 4).length}
              sx={{ backgroundColor: '#d32f2f', color: 'white', fontSize: '1.2rem', height: '40px', minWidth: '60px' }}
            />
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block" sx={{ mb: 1 }}>
              High Risk
            </Typography>
            <Chip
              label={filteredPatches.filter(p => getSeverityRank(p.severity) === 3).length}
              sx={{ backgroundColor: '#f57c00', color: 'white', fontSize: '1.2rem', height: '40px', minWidth: '60px' }}
            />
          </Paper>
        </Grid>
      </Grid>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                placeholder="Search KB ID or CVE..."
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />
                }}
                size="small"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
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
          </Grid>
        </CardContent>
      </Card>

      {/* Patches Table */}
      <Card>
        <CardHeader
          title={`Patches (${filteredPatches.length} of ${requiredKbs.length})`}
          subheader="Install these patches in priority order"
        />
        <CardContent>
          {filteredPatches.length === 0 ? (
            <Box sx={{ p: 3, textAlign: 'center', backgroundColor: '#e8f5e9', borderRadius: 1 }}>
              <UpdateIcon sx={{ fontSize: 48, color: '#388e3c', mb: 1 }} />
              <Typography color="success" sx={{ fontWeight: 'bold' }}>
                All Patches Installed
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Your system has all required security patches
              </Typography>
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
                    <TableCell><strong>KB ID</strong></TableCell>
                    <TableCell><strong>Associated CVEs</strong></TableCell>
                    <TableCell><strong>Severity</strong></TableCell>
                    <TableCell><strong>Reboot Required</strong></TableCell>
                    <TableCell><strong>Downtime Impact</strong></TableCell>
                    <TableCell><strong>Action</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredPatches
                    .sort((a, b) => getSeverityRank(b.severity) - getSeverityRank(a.severity))
                    .map(patch => (
                      <TableRow key={patch.kb_id} sx={{ '&:hover': { backgroundColor: '#f5f5f5' } }}>
                        <TableCell sx={{ fontWeight: 'bold', color: getRiskColor(patch.severity) }}>
                          {patch.kb_id}
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {patch.cve_ids.map(cve => (
                              <Chip key={cve} label={cve} size="small" variant="outlined" />
                            ))}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={getSeverityLabel(patch.severity)}
                            sx={{
                              backgroundColor: getRiskColor(patch.severity),
                              color: 'white'
                            }}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {patch.requires_reboot ? (
                            <Chip label="Yes" color="warning" size="small" />
                          ) : (
                            <Chip label="No" size="small" />
                          )}
                        </TableCell>
                        <TableCell>
                          {patch.downtime_impact || 'Unknown'}
                        </TableCell>
                        <TableCell>
                          <Button
                            size="small"
                            variant="outlined"
                            startIcon={<DownloadIcon />}
                            disabled
                          >
                            Queue
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

      {/* Recommendations */}
      {filteredPatches.length > 0 && (
        <Card sx={{ mt: 3 }}>
          <CardHeader title="Installation Recommendations" />
          <CardContent>
            <Typography variant="body2" sx={{ mb: 2 }}>
              <strong>Priority Order:</strong>
            </Typography>
            <Typography variant="body2" sx={{ mb: 2, color: 'textSecondary' }}>
              1. Install all CRITICAL severity patches first<br />
              2. Then HIGH severity patches<br />
              3. Plan reboot windows for patches marked "Reboot Required"<br />
              4. Test in staging environment before production deployment
            </Typography>
          </CardContent>
        </Card>
      )}
    </Container>
  );
};

export default MissingPatchesPage;

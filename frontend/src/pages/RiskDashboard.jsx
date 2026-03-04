/**
 * HARS Risk & Priority Dashboard
 * Displays overall risk, HARS-based vulnerability prioritization
 */

import React from 'react';
import {
  Container,
  Box,
  Card,
  CardHeader,
  CardContent,
  Grid,
  Typography,
  Paper,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow
} from '@mui/material';
import {
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon
} from '@mui/icons-material';
import { useRiskSummary, useVulnerabilities } from '../hooks/useSmartPatch';
import { LoadingState, ErrorState, EmptyState, HARSScoreCard, RiskBadge } from '../components/SmartPatchUI';

const RiskDashboardPage = () => {
  const { summary, loading: summaryLoading, error: summaryError } = useRiskSummary();
  const { vulnerabilities, loading: vulnLoading, error: vulnError } = useVulnerabilities();

  if (summaryLoading || vulnLoading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <LoadingState message="Loading vulnerability data..." />
      </Container>
    );
  }

  if (summaryError || vulnError) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <ErrorState error={summaryError || vulnError} />
      </Container>
    );
  }

  const riskDistribution = summary?.risk_distribution || {};
  const highCount = riskDistribution.HIGH || 0;
  const mediumCount = riskDistribution.MEDIUM || 0;
  const lowCount = riskDistribution.LOW || 0;
  const totalCount = highCount + mediumCount + lowCount;

  const prioritizeVulnerabilities = (vulns) => {
    // Sort by HARS final_score (highest risk first)
    return [...vulns].sort((a, b) => {
      const scoreA = a.hars_score || 0;
      const scoreB = b.hars_score || 0;
      return scoreB - scoreA;
    });
  };

  const topVulnerabilities = prioritizeVulnerabilities(vulnerabilities).slice(0, 10);

  const getOverallRiskLevel = () => {
    if (highCount > 0) return { level: 'CRITICAL', pct: (highCount / totalCount) * 100 };
    if (mediumCount > 0) return { level: 'HIGH', pct: (mediumCount / totalCount) * 100 };
    if (lowCount > 0) return { level: 'MEDIUM', pct: (lowCount / totalCount) * 100 };
    return { level: 'LOW', pct: 0 };
  };

  const overallRisk = getOverallRiskLevel();

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" sx={{ mb: 1 }}>
          HARS Risk & Priority Dashboard
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Automated vulnerability prioritization using HARS (Hybrid Automated Risk Scoring)
        </Typography>
      </Box>

      {/* Overall Risk Summary */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center', position: 'relative' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Overall Risk Level
            </Typography>
            <Box
              sx={{
                mt: 2,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 1
              }}
            >
              <WarningIcon
                sx={{
                  fontSize: '2rem',
                  color:
                    overallRisk.level === 'CRITICAL'
                      ? '#d32f2f'
                      : overallRisk.level === 'HIGH'
                      ? '#f57c00'
                      : '#388e3c'
                }}
              />
              <Typography
                variant="h5"
                sx={{
                  fontWeight: 'bold',
                  color:
                    overallRisk.level === 'CRITICAL'
                      ? '#d32f2f'
                      : overallRisk.level === 'HIGH'
                      ? '#f57c00'
                      : '#388e3c'
                }}
              >
                {overallRisk.level}
              </Typography>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Total Vulnerabilities
            </Typography>
            <Typography variant="h4" sx={{ my: 1, fontWeight: 'bold' }}>
              {totalCount}
            </Typography>
            <Typography variant="body2" color="textSecondary">
              with HARS scores
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Urgent (HIGH Priority)
            </Typography>
            <Typography variant="h4" sx={{ my: 1, fontWeight: 'bold', color: '#d32f2f' }}>
              {highCount}
            </Typography>
            <Typography variant="body2" color="textSecondary">
              require immediate attention
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="caption" color="textSecondary" display="block">
              Average HARS Score
            </Typography>
            <Typography
              variant="h4"
              sx={{
                my: 1,
                fontWeight: 'bold',
                color: summary?.average_hars >= 0.7 ? '#d32f2f' : '#f57c00'
              }}
            >
              {summary?.average_hars?.toFixed(3) || 'N/A'}
            </Typography>
            <Typography variant="body2" color="textSecondary">
              (0.0 = Low, 1.0 = High)
            </Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* Risk Distribution */}
      <Card sx={{ mb: 4 }}>
        <CardHeader title="Risk Distribution by Priority" />
        <CardContent>
          <Grid container spacing={3}>
            <Grid item xs={12} sm={4}>
              <Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: '600' }}>
                    HIGH
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: '600', color: '#d32f2f' }}>
                    {highCount}
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={totalCount > 0 ? (highCount / totalCount) * 100 : 0}
                  sx={{
                    backgroundColor: '#ffebee',
                    '& .MuiLinearProgress-bar': { backgroundColor: '#d32f2f' }
                  }}
                />
              </Box>
            </Grid>

            <Grid item xs={12} sm={4}>
              <Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: '600' }}>
                    MEDIUM
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: '600', color: '#f57c00' }}>
                    {mediumCount}
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={totalCount > 0 ? (mediumCount / totalCount) * 100 : 0}
                  sx={{
                    backgroundColor: '#fff3e0',
                    '& .MuiLinearProgress-bar': { backgroundColor: '#f57c00' }
                  }}
                />
              </Box>
            </Grid>

            <Grid item xs={12} sm={4}>
              <Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: '600' }}>
                    LOW
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: '600', color: '#388e3c' }}>
                    {lowCount}
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={totalCount > 0 ? (lowCount / totalCount) * 100 : 0}
                  sx={{
                    backgroundColor: '#e8f5e9',
                    '& .MuiLinearProgress-bar': { backgroundColor: '#388e3c' }
                  }}
                />
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Top Vulnerabilities by HARS Score */}
      <Card>
        <CardHeader
          title="Top Vulnerabilities by HARS Score"
          subheader={`Sorted by risk priority (${topVulnerabilities.length} of ${vulnerabilities.length})`}
        />
        <CardContent>
          {topVulnerabilities.length === 0 ? (
            <EmptyState message="No vulnerabilities found" />
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead sx={{ backgroundColor: '#f5f5f5' }}>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>CVE ID</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Title</TableCell>
                    <TableCell align="center" sx={{ fontWeight: 'bold' }}>
                      Priority
                    </TableCell>
                    <TableCell align="right" sx={{ fontWeight: 'bold' }}>
                      HARS Score
                    </TableCell>
                    <TableCell align="right" sx={{ fontWeight: 'bold' }}>
                      R/A/C
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {topVulnerabilities.map((vuln, idx) => (
                    <TableRow key={idx} hover>
                      <TableCell
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '0.85rem',
                          fontWeight: '600'
                        }}
                      >
                        {vuln.cve_id || '—'}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ maxWidth: '300px' }}>
                          {vuln.title || '—'}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        <RiskBadge priority={vuln.priority} compact />
                      </TableCell>
                      <TableCell align="right">
                        <Typography
                          variant="body2"
                          sx={{
                            fontWeight: '600',
                            color:
                              vuln.hars_score >= 0.7
                                ? '#d32f2f'
                                : vuln.hars_score >= 0.35
                                ? '#f57c00'
                                : '#388e3c'
                          }}
                        >
                          {vuln.hars_score?.toFixed(3) || '—'}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                          {vuln.attack_surface_score?.toFixed(2) || '—'}/
                          {vuln.reachability_score?.toFixed(2) || '—'}/
                          {vuln.criticality_score?.toFixed(2) || '—'}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      <Card sx={{ mt: 3 }}>
        <CardHeader title="About HARS Scoring" />
        <CardContent>
          <Typography variant="body2" paragraph>
            Scores range from 0.0 (low risk) to 1.0 (high risk). HARS considers:
          </Typography>
          <Box component="ul" sx={{ pl: 2, mb: 0 }}>
            <Typography component="li" variant="body2">
              <strong>R Score:</strong> Reachability from network/local context
            </Typography>
            <Typography component="li" variant="body2">
              <strong>A Score:</strong> Exploitability and attack surface
            </Typography>
            <Typography component="li" variant="body2">
              <strong>C Score:</strong> Impact and criticality (compromise, confidentiality)
            </Typography>
            <Typography component="li" variant="body2">
              <strong>Final Score:</strong> Combined HARS value (HIGH ≥ 0.70, MEDIUM ≥ 0.35, LOW &lt; 0.35)
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </Container>
  );
};

export default RiskDashboardPage;

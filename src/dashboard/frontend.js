import React, { useState, useEffect, useCallback } from 'react';
import { AlertCircle, Check, Clock, ChevronRight, RefreshCw, Info } from 'lucide-react';

// ============================================================================
// BACKEND API SERVICE LAYER
// Abstraction over local SQLite-backed endpoints (http://localhost:8888)
// Read-only, no telemetry, all data sourced from real backend components
// ============================================================================

const API_BASE = 'http://localhost:8888';

const BackendAPI = {
  // Fetch system identity snapshot
  async getSystemIdentity() {
    try {
      const resp = await fetch(`${API_BASE}/api/system/identity`, { method: 'GET' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      return { error: 'Unable to fetch system identity', details: e.message };
    }
  },

  // Fetch latest scan metadata
  async getLatestScan() {
    try {
      const resp = await fetch(`${API_BASE}/api/scans/latest`, { method: 'GET' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      return { error: 'Unable to fetch scan metadata', details: e.message };
    }
  },

  // Fetch detected vulnerabilities for a scan
  async getVulnerabilities(scanId) {
    try {
      const resp = await fetch(`${API_BASE}/api/vulnerabilities?scan_id=${scanId}`, { method: 'GET' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      return { error: 'Unable to fetch vulnerabilities', details: e.message };
    }
  },

  // Fetch AI/rule decisions for vulnerabilities
  async getDecisions(scanId) {
    try {
      const resp = await fetch(`${API_BASE}/api/decisions?scan_id=${scanId}`, { method: 'GET' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      return { error: 'Unable to fetch decisions', details: e.message };
    }
  },

  // Fetch action/mitigation execution history
  async getActions(scanId) {
    try {
      const resp = await fetch(`${API_BASE}/api/actions?scan_id=${scanId}`, { method: 'GET' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      return { error: 'Unable to fetch action history', details: e.message };
    }
  },

  // Fetch audit log (immutable timeline)
  async getAuditLog(scanId) {
    try {
      const resp = await fetch(`${API_BASE}/api/audit?scan_id=${scanId}`, { method: 'GET' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      return { error: 'Unable to fetch audit log', details: e.message };
    }
  },

  // Fetch risk summary (computed by backend, not UI)
  async getRiskSummary(scanId) {
    try {
      const resp = await fetch(`${API_BASE}/api/summary/risk?scan_id=${scanId}`, { method: 'GET' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      return { error: 'Unable to fetch risk summary', details: e.message };
    }
  }
};

// ============================================================================
// UTILITY FUNCTIONS
// Non-UI logic: severity classification, risk labeling, date formatting
// ============================================================================

const Severity = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  UNKNOWN: 'unknown'
};

function normalizeSeverity(score) {
  // Convert numeric score to canonical label
  // Backend provides severity_score (0-10) and severity_label
  // Trust the label first, fall back to numeric thresholds
  if (typeof score === 'string') {
    const label = score.toLowerCase();
    if (label.includes('critical')) return Severity.CRITICAL;
    if (label.includes('high')) return Severity.HIGH;
    if (label.includes('medium')) return Severity.MEDIUM;
    if (label.includes('low')) return Severity.LOW;
  }
  if (typeof score === 'number') {
    if (score >= 9) return Severity.CRITICAL;
    if (score >= 7) return Severity.HIGH;
    if (score >= 4) return Severity.MEDIUM;
    if (score >= 0) return Severity.LOW;
  }
  return Severity.UNKNOWN;
}

function getSeverityColor(severity) {
  const normalized = normalizeSeverity(severity);
  const colors = {
    [Severity.CRITICAL]: '#dc2626', // red
    [Severity.HIGH]: '#ea580c',     // orange
    [Severity.MEDIUM]: '#facc15',   // yellow
    [Severity.LOW]: '#22c55e',      // green
    [Severity.UNKNOWN]: '#6b7280'   // gray
  };
  return colors[normalized] || colors[Severity.UNKNOWN];
}

function getSeverityLabel(severity) {
  const normalized = normalizeSeverity(severity);
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function getOverallRisk(vulns) {
  // Determine system-wide risk posture based on highest severity
  if (!vulns || vulns.length === 0) return { level: 'healthy', color: '#22c55e', label: 'HEALTHY' };
  
  const severities = vulns.map(v => normalizeSeverity(v.severity_label || v.severity_score));
  
  if (severities.includes(Severity.CRITICAL)) {
    return { level: 'critical', color: '#dc2626', label: 'CRITICAL' };
  }
  if (severities.includes(Severity.HIGH)) {
    return { level: 'at-risk', color: '#ea580c', label: 'AT RISK' };
  }
  if (severities.includes(Severity.MEDIUM)) {
    return { level: 'caution', color: '#facc15', label: 'CAUTION' };
  }
  return { level: 'healthy', color: '#22c55e', label: 'HEALTHY' };
}

function formatDate(ts) {
  // Safe date formatting for legacy systems
  if (!ts) return 'N/A';
  const d = new Date(typeof ts === 'number' ? ts * 1000 : ts);
  if (isNaN(d.getTime())) return 'N/A';
  return d.toLocaleString('en-US', { 
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function timeSinceLastScan(scanTs) {
  if (!scanTs) return 'Never';
  const now = Date.now();
  const scanMs = typeof scanTs === 'number' ? scanTs * 1000 : new Date(scanTs).getTime();
  const diffMs = now - scanMs;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

// ============================================================================
// COMPONENT: System Overview Screen
// Purpose: "Is this machine safe right now?" in under 5 seconds
// ============================================================================

function SystemOverview({ systemId, lastScan, riskSummary, criticalCount, onViewVulns }) {
  const riskStatus = riskSummary?.level || 'unknown';
  const color = riskSummary?.color || '#6b7280';
  
  return (
    <div style={{ padding: '24px', backgroundColor: '#f9fafb', borderRadius: '8px', marginBottom: '24px' }}>
      <h2 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '16px', color: '#1f2937' }}>
        System Health Overview
      </h2>
      
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
        {/* System ID Card */}
        <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
          <div style={{ fontSize: '12px', color: '#6b7280', fontWeight: '500', marginBottom: '4px', textTransform: 'uppercase' }}>
            System
          </div>
          <div style={{ fontSize: '14px', color: '#1f2937', fontFamily: 'monospace' }}>
            {systemId?.hostname || 'Unknown'}
          </div>
          <div style={{ fontSize: '11px', color: '#9ca3af', marginTop: '6px' }}>
            {systemId?.os_version || 'Unknown OS'} · {systemId?.architecture || 'Unknown arch'}
          </div>
        </div>

        {/* Last Scan Card */}
        <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
          <div style={{ fontSize: '12px', color: '#6b7280', fontWeight: '500', marginBottom: '4px', textTransform: 'uppercase' }}>
            Last Scan
          </div>
          <div style={{ fontSize: '14px', color: '#1f2937' }}>
            {timeSinceLastScan(lastScan?.timestamp)}
          </div>
          <div style={{ fontSize: '11px', color: '#9ca3af', marginTop: '6px' }}>
            {lastScan?.scanner_version || 'Unknown version'}
          </div>
        </div>
      </div>

      {/* Risk Status - Large, Prominent */}
      <div style={{
        backgroundColor: 'white',
        padding: '24px',
        borderRadius: '6px',
        border: `2px solid ${color}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div>
          <div style={{ fontSize: '12px', color: '#6b7280', fontWeight: '500', marginBottom: '8px', textTransform: 'uppercase' }}>
            Risk Posture
          </div>
          <div style={{
            fontSize: '32px',
            fontWeight: '700',
            color: color,
            marginBottom: '8px'
          }}>
            {riskSummary?.label || 'UNKNOWN'}
          </div>
          <div style={{ fontSize: '13px', color: '#4b5563' }}>
            {criticalCount > 0 
              ? `${criticalCount} issue${criticalCount > 1 ? 's' : ''} require${criticalCount > 1 ? '' : 's'} attention`
              : 'No urgent issues detected'
            }
          </div>
        </div>
        <div style={{
          width: '80px',
          height: '80px',
          borderRadius: '50%',
          backgroundColor: color,
          opacity: 0.15,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{
            width: '60px',
            height: '60px',
            borderRadius: '50%',
            backgroundColor: color,
            opacity: 0.3
          }} />
        </div>
      </div>

      {/* Action Button */}
      <button
        onClick={onViewVulns}
        style={{
          marginTop: '16px',
          padding: '10px 16px',
          backgroundColor: '#2563eb',
          color: 'white',
          border: 'none',
          borderRadius: '6px',
          cursor: 'pointer',
          fontSize: '13px',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}
      >
        View Details <ChevronRight size={16} />
      </button>
    </div>
  );
}

// ============================================================================
// COMPONENT: Vulnerability List
// Purpose: Prioritized, explainable, no raw CVSS dumps
// ============================================================================

function VulnerabilityList({ vulnerabilities, decisions, onSelectVuln }) {
  const [sortBy, setSortBy] = useState('severity');
  const [filterActionRequired, setFilterActionRequired] = useState(false);

  if (!vulnerabilities || vulnerabilities.length === 0) {
    return (
      <div style={{ padding: '24px', backgroundColor: '#f9fafb', borderRadius: '8px', textAlign: 'center', color: '#6b7280' }}>
        <Check size={32} style={{ margin: '0 auto 12px', color: '#22c55e' }} />
        <p>No vulnerabilities detected in latest scan.</p>
      </div>
    );
  }

  // Attach decisions to vulnerabilities
  const withDecisions = vulnerabilities.map(v => ({
    ...v,
    decision: decisions?.find(d => d.cve_id === v.cve_id) || null
  }));

  // Filter
  let filtered = withDecisions;
  if (filterActionRequired) {
    filtered = filtered.filter(v => v.decision?.decision_type && v.decision.decision_type !== 'Ignore');
  }

  // Sort
  filtered.sort((a, b) => {
    if (sortBy === 'severity') {
      const aScore = a.severity_score || 0;
      const bScore = b.severity_score || 0;
      return bScore - aScore; // descending
    }
    if (sortBy === 'cve') {
      return (a.cve_id || '').localeCompare(b.cve_id || '');
    }
    return 0;
  });

  return (
    <div style={{ backgroundColor: '#f9fafb', borderRadius: '8px', overflow: 'hidden' }}>
      <div style={{ padding: '16px', borderBottom: '1px solid #e5e7eb', display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={filterActionRequired}
            onChange={(e) => setFilterActionRequired(e.target.checked)}
            style={{ cursor: 'pointer' }}
          />
          <span style={{ fontSize: '13px', color: '#374151' }}>Action Required Only</span>
        </label>
        
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          style={{
            padding: '6px 8px',
            fontSize: '13px',
            border: '1px solid #d1d5db',
            borderRadius: '4px',
            cursor: 'pointer',
            backgroundColor: 'white'
          }}
        >
          <option value="severity">Sort by Risk</option>
          <option value="cve">Sort by CVE</option>
        </select>

        <div style={{ marginLeft: 'auto', fontSize: '12px', color: '#6b7280' }}>
          {filtered.length} {filtered.length === 1 ? 'issue' : 'issues'} shown
        </div>
      </div>

      <div style={{ backgroundColor: 'white' }}>
        {filtered.map((vuln, idx) => (
          <div
            key={vuln.cve_id || idx}
            onClick={() => onSelectVuln(vuln)}
            style={{
              padding: '12px 16px',
              borderBottom: idx < filtered.length - 1 ? '1px solid #e5e7eb' : 'none',
              cursor: 'pointer',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              gap: '12px',
              transition: 'background-color 0.2s',
              backgroundColor: idx % 2 === 1 ? '#f9fafb' : 'white'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#f3f4f6'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = idx % 2 === 1 ? '#f9fafb' : 'white'}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                <span style={{ fontSize: '13px', fontWeight: '600', color: '#1f2937', fontFamily: 'monospace' }}>
                  {vuln.cve_id || 'UNKNOWN'}
                </span>
                <span style={{
                  fontSize: '11px',
                  fontWeight: '600',
                  color: 'white',
                  backgroundColor: getSeverityColor(vuln.severity_label || vuln.severity_score),
                  padding: '2px 8px',
                  borderRadius: '12px',
                  textTransform: 'uppercase'
                }}>
                  {getSeverityLabel(vuln.severity_label || vuln.severity_score)}
                </span>
              </div>
              <div style={{ fontSize: '12px', color: '#374151', marginBottom: '4px', lineHeight: '1.4' }}>
                {vuln.affected_component || 'Unknown component'}
              </div>
              <div style={{ fontSize: '11px', color: '#6b7280' }}>
                {vuln.exploit_known ? '⚠ Exploit available' : ''} {vuln.patch_available ? '✓ Patch available' : ''}
              </div>
            </div>
            
            <div style={{ textAlign: 'right', fontSize: '12px', whiteSpace: 'nowrap', minWidth: '120px' }}>
              {vuln.decision?.decision_type ? (
                <div style={{ color: '#2563eb', fontWeight: '600', marginBottom: '4px' }}>
                  {vuln.decision.decision_type}
                </div>
              ) : (
                <div style={{ color: '#9ca3af' }}>No decision</div>
              )}
              {vuln.decision?.confidence_score !== undefined && (
                <div style={{ fontSize: '11px', color: '#6b7280' }}>
                  {Math.round(vuln.decision.confidence_score * 100)}% confident
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT: Vulnerability Detail Modal
// Purpose: Explain why the system thinks something matters
// ============================================================================

function VulnerabilityDetail({ vuln, decision, onClose }) {
  if (!vuln) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    }} onClick={onClose}>
      <div style={{
        backgroundColor: 'white',
        borderRadius: '8px',
        maxWidth: '600px',
        width: '90%',
        maxHeight: '80vh',
        overflowY: 'auto',
        padding: '24px',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)'
      }} onClick={(e) => e.stopPropagation()}>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#1f2937', margin: 0 }}>
            {vuln.cve_id || 'Unknown'}
          </h2>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '24px',
              cursor: 'pointer',
              color: '#6b7280',
              padding: 0
            }}
          >
            ×
          </button>
        </div>

        {/* Summary */}
        <div style={{ marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid #e5e7eb' }}>
          <div style={{ fontSize: '13px', color: '#6b7280', fontWeight: '500', marginBottom: '6px', textTransform: 'uppercase' }}>
            Summary
          </div>
          <div style={{ fontSize: '13px', color: '#374151', lineHeight: '1.6' }}>
            {vuln.summary || vuln.affected_component || 'No summary available'}
          </div>
        </div>

        {/* Severity & Exposure */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid #e5e7eb' }}>
          <div>
            <div style={{ fontSize: '12px', color: '#6b7280', fontWeight: '500', marginBottom: '6px', textTransform: 'uppercase' }}>
              Severity
            </div>
            <div style={{
              fontSize: '16px',
              fontWeight: '700',
              color: getSeverityColor(vuln.severity_label || vuln.severity_score)
            }}>
              {getSeverityLabel(vuln.severity_label || vuln.severity_score)}
            </div>
            {vuln.severity_score !== undefined && (
              <div style={{ fontSize: '11px', color: '#9ca3af', marginTop: '4px' }}>
                Score: {vuln.severity_score}/10
              </div>
            )}
          </div>

          <div>
            <div style={{ fontSize: '12px', color: '#6b7280', fontWeight: '500', marginBottom: '6px', textTransform: 'uppercase' }}>
              Exposure
            </div>
            <div style={{ fontSize: '13px', color: '#1f2937' }}>
              {vuln.exploit_known ? (
                <span style={{ color: '#dc2626', fontWeight: '600' }}>🔴 Actively exploited</span>
              ) : (
                <span style={{ color: '#6b7280' }}>No known exploit</span>
              )}
            </div>
            {vuln.patch_available && (
              <div style={{ fontSize: '11px', color: '#22c55e', marginTop: '4px', fontWeight: '500' }}>
                ✓ Patch is available
              </div>
            )}
          </div>
        </div>

        {/* Affected Component */}
        <div style={{ marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid #e5e7eb' }}>
          <div style={{ fontSize: '12px', color: '#6b7280', fontWeight: '500', marginBottom: '6px', textTransform: 'uppercase' }}>
            Affected Component
          </div>
          <div style={{ fontSize: '13px', color: '#1f2937', fontFamily: 'monospace', backgroundColor: '#f3f4f6', padding: '8px 12px', borderRadius: '4px', wordBreak: 'break-all' }}>
            {vuln.affected_component || 'Unknown'}
          </div>
        </div>

        {/* Decision & Reasoning */}
        {decision && (
          <div style={{ marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid #e5e7eb', backgroundColor: '#f0f9ff', padding: '12px', borderRadius: '6px' }}>
            <div style={{ fontSize: '12px', color: '#0c4a6e', fontWeight: '600', marginBottom: '8px', textTransform: 'uppercase' }}>
              Recommendation
            </div>
            <div style={{ fontSize: '14px', fontWeight: '600', color: '#2563eb', marginBottom: '8px' }}>
              {decision.decision_type || 'No decision'}
            </div>
            {decision.reasoning && (
              <div style={{ fontSize: '12px', color: '#064e3b', lineHeight: '1.5', marginBottom: '6px' }}>
                {decision.reasoning}
              </div>
            )}
            {decision.confidence_score !== undefined && (
              <div style={{ fontSize: '11px', color: '#0c4a6e', marginTop: '6px' }}>
                Confidence: {Math.round(decision.confidence_score * 100)}%
              </div>
            )}
            {decision.decision_source && (
              <div style={{ fontSize: '10px', color: '#075985', marginTop: '4px' }}>
                Source: {decision.decision_source}
              </div>
            )}
          </div>
        )}

        {/* No decision state */}
        {!decision && (
          <div style={{ marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid #e5e7eb', backgroundColor: '#f5f3ff', padding: '12px', borderRadius: '6px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280' }}>
              No recommendation yet. Backend analysis in progress.
            </div>
          </div>
        )}

        {/* Close Button */}
        <button
          onClick={onClose}
          style={{
            width: '100%',
            padding: '10px',
            backgroundColor: '#f3f4f6',
            border: '1px solid #d1d5db',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: '600',
            color: '#374151'
          }}
        >
          Close
        </button>
      </div>
    </div>
  );
}

// ============================================================================
// COMPONENT: Action & Mitigation Status
// Purpose: Prevent unsafe changes; show pending approvals, executed actions
// ============================================================================

function ActionStatus({ actions }) {
  if (!actions || actions.length === 0) {
    return (
      <div style={{ padding: '24px', backgroundColor: '#f9fafb', borderRadius: '8px', textAlign: 'center', color: '#6b7280' }}>
        <p>No actions executed yet.</p>
      </div>
    );
  }

  // Group by status
  const pending = actions.filter(a => a.approval_status === 'pending' || a.approval_status === 'awaiting');
  const executed = actions.filter(a => a.execution_status === 'success');
  const failed = actions.filter(a => a.execution_status === 'failed');
  const rolledBack = actions.filter(a => a.execution_status === 'rolled_back');

  const renderActionRow = (action, idx, bgColor) => (
    <div key={action.action_id || idx} style={{
      padding: '12px 16px',
      backgroundColor: bgColor,
      borderBottom: '1px solid #e5e7eb',
      display: 'grid',
      gridTemplateColumns: '100px 1fr auto',
      gap: '12px',
      alignItems: 'center'
    }}>
      <div style={{ fontSize: '11px', fontWeight: '600', color: '#6b7280', textTransform: 'uppercase' }}>
        {action.action_type || 'Unknown'}
      </div>
      <div>
        <div style={{ fontSize: '12px', color: '#1f2937', marginBottom: '2px' }}>
          {action.action_type === 'KB' ? 'Patch install' : action.action_type === 'registry' ? 'Registry change' : 'Service disable'}
        </div>
        {action.timestamp && (
          <div style={{ fontSize: '11px', color: '#9ca3af' }}>
            {formatDate(action.timestamp)}
          </div>
        )}
      </div>
      <div style={{ textAlign: 'right', fontSize: '11px', fontWeight: '600', whiteSpace: 'nowrap' }}>
        {action.execution_status === 'success' && (
          <span style={{ color: '#22c55e' }}>✓ Success</span>
        )}
        {action.execution_status === 'failed' && (
          <span style={{ color: '#dc2626' }}>✗ Failed</span>
        )}
        {action.execution_status === 'rolled_back' && (
          <span style={{ color: '#ea580c' }}>↻ Rolled back</span>
        )}
        {action.approval_status === 'pending' && (
          <span style={{ color: '#facc15' }}>⏳ Pending</span>
        )}
      </div>
    </div>
  );

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
      {/* Pending Approvals */}
      {pending.length > 0 && (
        <div style={{ backgroundColor: '#fefce8', borderRadius: '8px', overflow: 'hidden', border: '1px solid #fef08a' }}>
          <div style={{ padding: '12px 16px', backgroundColor: '#facc15', color: '#713f12', fontWeight: '600', fontSize: '13px', textTransform: 'uppercase' }}>
            {pending.length} Awaiting Approval
          </div>
          <div style={{ backgroundColor: 'white' }}>
            {pending.map((a, i) => renderActionRow(a, i, i % 2 === 1 ? '#fefce8' : 'white'))}
          </div>
        </div>
      )}

      {/* Executed & Outcomes */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {executed.length > 0 && (
          <div style={{ backgroundColor: '#f0ffdf', borderRadius: '8px', overflow: 'hidden', border: '1px solid #86efac' }}>
            <div style={{ padding: '12px 16px', backgroundColor: '#22c55e', color: 'white', fontWeight: '600', fontSize: '13px', textTransform: 'uppercase' }}>
              {executed.length} Successfully Executed Actions
            </div>
            <div style={{ backgroundColor: 'white' }}> 
              {executed.map((a, i) => renderActionRow(a, i, i % 2 === 1 ? '#f0ffdf' : 'white'))}
            </div>
          </div>
        )}
        {failed.length > 0 && (
          <div style={{ backgroundColor: '#ffebe6', borderRadius: '8px', overflow: 'hidden', border: '1px solid #fca5a5' }}>
            <div style={{ padding: '12px 16px', backgroundColor: '#dc2626', color: 'white', fontWeight: '600', fontSize: '13px', textTransform: 'uppercase' }}>
              {failed.length} Failed Actions
            </div>
            <div style={{ backgroundColor: 'white' }}>
              {failed.map((a, i) => renderActionRow(a, i, i % 2 === 1 ? '#ffebe6' : 'white'))}
            </div>
          </div>
        )}
        {rolledBack.length > 0 && (
          <div style={{ backgroundColor: '#fff7ed', borderRadius: '8px', overflow: 'hidden', border: '1px solid #fdba74' }}>
            <div style={{ padding: '12px 16px', backgroundColor: '#ea580c', color: 'white', fontWeight: '600', fontSize: '13px', textTransform: 'uppercase' }}>
              {rolledBack.length} Rolled Back Actions
            </div>
            <div style={{ backgroundColor: 'white' }}>
              {rolledBack.map((a, i) => renderActionRow(a, i, i % 2 === 1 ? '#fff7ed' : 'white'))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
// ============================================================================
// MAIN DASHBOARD COMPONENT
// Combines all sub-components into a cohesive UI
// ============================================================================




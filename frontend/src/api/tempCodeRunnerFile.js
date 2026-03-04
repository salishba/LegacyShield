/**
 * Backend API Client
 * Communicates with Flask backend for SmartPatch scanning and analysis
 */

import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8888/api';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  }
});

// Error handling interceptor
client.interceptors.response.use(
  response => response,
  error => Promise.reject(error)
);

/**
 * System API endpoints
 */
export const systemAPI = {
  getSystemInfo: async () => {
    const response = await client.get('/system');
    return response.data;
  },

  getSystemDetails: async () => {
    const response = await client.get('/system');
    return response.data;
  }
};

/**
 * Scanning API endpoints
 */
export const scanAPI = {
  triggerScan: async () => {
    const response = await client.post('/scan', {});
    return response.data;
  },

  getScans: async () => {
    const response = await client.get('/scans');
    return response.data.scans || [];
  },

  getScanDetail: async (scanId) => {
    const response = await client.get(`/scan/${scanId}`);
    return response.data;
  }
};

/**
 * Risk & Vulnerability API endpoints
 */
export const riskAPI = {
  getRiskSummary: async () => {
    const response = await client.get('/risk-summary');
    return response.data.summary || {};
  },

  getVulnerabilities: async (scanId = null) => {
    const params = scanId ? `?scan_id=${scanId}` : '';
    const response = await client.get(`/vulnerabilities${params}`);
    return response.data.vulnerabilities || [];
  },

  getInstalledKbs: async () => {
    const response = await client.get('/installed-kbs');
    return response.data.kbs || [];
  }
};

/**
 * Recommendations API endpoints - AI/HARS prioritized mitigations
 */
export const recommendationAPI = {
  getRecommendations: async () => {
    const response = await client.get('/recommendations');
    return response.data.recommendations || [];
  },

  getMitigationDetails: async (cveId) => {
    const response = await client.get(`/mitigation/${cveId}`);
    return response.data;
  }
};

/**
 * Audit & Logs API endpoints
 */
export const auditAPI = {
  getAuditLogs: async () => {
    const response = await client.get('/audit-logs');
    return response.data.audit_logs || [];
  }
};

/**
 * Health check
 */
export const healthAPI = {
  check: async () => {
    try {
      const response = await client.get('/health');
      return response.data.status === 'healthy' || response.data.status === 'no_data';
    } catch (error) {
      return false;
    }
  }
};

export default client;

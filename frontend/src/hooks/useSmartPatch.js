/**
 * Custom hooks for SmartPatch frontend
 * Data fetching, state management, and synchronization
 */

import { useState, useEffect, useCallback } from 'react';
import { systemAPI, scanAPI, riskAPI, recommendationAPI, auditAPI } from '../api/backend';

/**
 * Hook: Fetch system information
 */
export const useSystemInfo = () => {
  const [system, setSystem] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await systemAPI.getSystemInfo();
      setSystem(data);
    } catch (err) {
      setError(err.message);
      setSystem(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { system, loading, error, refetch: fetch };
};

/**
 * Hook: Fetch HARS-based risk summary
 */
export const useRiskSummary = () => {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await riskAPI.getRiskSummary();
      setSummary(data);
    } catch (err) {
      setError(err.message);
      setSummary(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { summary, loading, error, refetch: fetch };
};

/**
 * Hook: Fetch vulnerabilities with HARS scores
 */
export const useVulnerabilities = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async (scanId = null) => {
    setLoading(true);
    setError(null);
    try {
      const data = await riskAPI.getVulnerabilities(scanId);
      setVulnerabilities(data);
    } catch (err) {
      setError(err.message);
      setVulnerabilities([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { vulnerabilities, loading, error, refetch: fetch };
};

/**
 * Hook: Fetch scan history
 */
export const useScanHistory = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await scanAPI.getScans();
      setScans(data);
    } catch (err) {
      setError(err.message);
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { scans, loading, error, refetch: fetch };
};

/**
 * Hook: Installed KBs
 */
export const useInstalledKbs = () => {
  const [kbs, setKbs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await riskAPI.getInstalledKbs();
      setKbs(data);
    } catch (err) {
      setError(err.message);
      setKbs([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { kbs, loading, error, refetch: fetch };
};

/**
 * Hook: Trigger system analysis scan with REAL live progress
 */
export const useAnalysisScan = () => {
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('idle');
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState(null);

  const trigger = useCallback(async () => {
    setScanning(true);
    setProgress(0);
    setStatus('initializing');
    setStatusMessage('Starting real-time system analysis...');
    setError(null);

    try {
      // Stage 1: Initialize
      setProgress(5);
      setStatusMessage('Initializing scanner agent...');
      await new Promise(resolve => setTimeout(resolve, 500));

      // Stage 2: Execute real backend scan
      setProgress(15);
      setStatus('running');
      setStatusMessage('Executing system state checker...');
      
      const scanResult = await scanAPI.triggerScan();
      if (!scanResult.success) {
        throw new Error(scanResult.message || 'Scan failed');
      }

      // Stage 3: Poll for system data
      setProgress(35);
      setStatusMessage('Collecting system metadata...');
      let systemData = null;
      for (let i = 0; i < 10; i++) {
        try {
          const sys = await systemAPI.getSystemInfo();
          if (sys && sys.hostname) {
            systemData = sys;
            break;
          }
        } catch (e) {
          // Data not ready yet, continue polling
        }
        await new Promise(resolve => setTimeout(resolve, 500));
      }

      // Stage 4: Poll for vulnerability data
      setProgress(55);
      setStatusMessage('Analyzing installed patches...');
      let vulnData = [];
      for (let i = 0; i < 10; i++) {
        try {
          const vulns = await riskAPI.getVulnerabilities();
          if (vulns && vulns.length > 0) {
            vulnData = vulns;
            break;
          }
        } catch (e) {
          // Data not ready yet, continue polling
        }
        await new Promise(resolve => setTimeout(resolve, 500));
      }

      // Stage 5: Poll for HARS scores
      setProgress(75);
      setStatusMessage('Computing HARS risk scores...');
      let riskData = null;
      for (let i = 0; i < 10; i++) {
        try {
          const risk = await riskAPI.getRiskSummary();
          if (risk && risk.risk_distribution) {
            riskData = risk;
            break;
          }
        } catch (e) {
          // Data not ready yet, continue polling
        }
        await new Promise(resolve => setTimeout(resolve, 500));
      }

      // Final: All data collected
      setProgress(100);
      setStatus('complete');
      setStatusMessage(`✓ Analysis complete: ${systemData?.hostname || 'System'} scanned, ${vulnData.length} vulnerabilities found`);
      
      return {
        success: true,
        systemData,
        vulnerabilities: vulnData,
        riskSummary: riskData,
        scanOutput: scanResult.scan_output
      };
      
    } catch (err) {
      setError(err.message);
      setStatus('error');
      setStatusMessage(`Error: ${err.message}`);
      throw err;
    } finally {
      setScanning(false);
    }
  }, []);

  return { 
    scanning, 
    progress, 
    status, 
    statusMessage,
    error, 
    trigger 
  };
};

/**
 * Hook: Fetch AI/HARS recommendations with mitigations
 */
export const useRecommendations = () => {
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await recommendationAPI.getRecommendations();
      setRecommendations(data);
    } catch (err) {
      setError(err.message);
      setRecommendations([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { recommendations, loading, error, refetch: fetch };
};

/**
 * Hook: Fetch detailed mitigation options for a CVE
 */
export const useMitigationDetails = (cveId) => {
  const [mitigation, setMitigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    if (!cveId) {
      setMitigation(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await recommendationAPI.getMitigationDetails(cveId);
      setMitigation(data);
    } catch (err) {
      setError(err.message);
      setMitigation(null);
    } finally {
      setLoading(false);
    }
  }, [cveId]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { mitigation, loading, error, refetch: fetch };
};

/**
 * Hook: Fetch audit log history
 */
export const useAuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await auditAPI.getAuditLogs();
      setLogs(data);
    } catch (err) {
      setError(err.message);
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { logs, loading, error, refetch: fetch };
};

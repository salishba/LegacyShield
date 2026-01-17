"""
bootstrap.py - Main orchestrator with runtime context integration
Coordinates scanner execution using cached OS metadata
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib
import sys 
# Import the new modules
from environment import RuntimeContext, bootstrap_runtime_context
from os_fingerprint import get_os_metadata, get_capabilities, get_os_fingerprinter

# Import existing components
try:
    from runtime_db import (
        RuntimePaths,
        RuntimeDatabaseManager,
        init_runtime_database,
        insert_system_info,
        insert_finding
    )
    from scanner import (
        WindowsOSScanner,
        WindowsAuthenticationScanner,
        WindowsNetworkScanner,
        WindowsPrivilegeEscalationScanner,
        WindowsPersistenceScanner,
        WindowsServiceMisconfigurationScanner,
        WindowsAuditPolicyScanner,
        SecurityFinding
    )
    from risk import hars_prioritization_runtime
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Optional import failed: {e}")

logger = logging.getLogger(__name__)


class SmartPatchOrchestrator:
    """
    Main orchestrator that integrates runtime context and cached OS metadata.
    Manages the complete scan lifecycle.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.runtime_context = None
        self.os_metadata = None
        self.capabilities = None
        self.db = None
        self.scanners = {}
        self.scan_results = {}
        
    def initialize(self) -> bool:
        """Initialize orchestrator with runtime context and OS metadata"""
        try:
            logger.info("Initializing SmartPatch orchestrator...")
            
            # 1. Bootstrap runtime context
            self.runtime_context = bootstrap_runtime_context()
            
            # 2. Get OS metadata (cached)
            self.os_metadata = get_os_metadata()
            self.capabilities = self.os_metadata.get("capabilities", {})
            
            # 3. Initialize database
            self.db = init_runtime_database()
            
            # 4. Log initialization
            self.db.log_scan_action(
                action="initialize",
                message=f"Orchestrator initialized with context hash: {self.runtime_context.get_context_value('context_hash')}",
                component="orchestrator"
            )
            
            logger.info("Orchestrator initialized successfully")
            logger.info(f"OS: {self.os_metadata.get('os_info', {}).get('Caption', 'Unknown')}")
            logger.info(f"Build: {self.os_metadata.get('os_info', {}).get('BuildNumber', 'Unknown')}")
            logger.info(f"Capabilities: {', '.join([k for k, v in self.capabilities.items() if v])}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            return False
    
    def _get_active_scanners(self) -> Dict[str, Any]:
        """Determine which scanners can run based on capabilities"""
        active_scanners = {}
        
        # Base scanners that always run
        base_scanners = {
            "os_metadata": True,
            "service_scanner": True,
            "audit_scanner": True,
        }
        
        # Capability-dependent scanners
        capability_scanners = {
            "authentication_scanner": self.capabilities.get("wmi", False),
            "network_scanner": True,  # Always try network scanning
            "privilege_scanner": self.capabilities.get("powershell", False),
            "persistence_scanner": True,  # Registry-based, depends on win32api
            "update_scanner": self.capabilities.get("wmi", False),
        }
        
        active_scanners.update(base_scanners)
        active_scanners.update(capability_scanners)
        
        # Log active scanners
        active_list = [name for name, active in active_scanners.items() if active]
        logger.info(f"Active scanners: {', '.join(active_list)}")
        
        return active_scanners
    
    def _create_scanner_instances(self, active_scanners: Dict[str, bool]) -> Dict[str, Any]:
        """Create scanner instances based on active scanners"""
        scanners = {}
        
        try:
            if active_scanners.get("os_metadata", False):
                scanners["os"] = WindowsOSScanner()
            
            if active_scanners.get("authentication_scanner", False):
                scanners["authentication"] = WindowsAuthenticationScanner()
            
            if active_scanners.get("network_scanner", False):
                scanners["network"] = WindowsNetworkScanner()
            
            if active_scanners.get("privilege_scanner", False):
                scanners["privilege"] = WindowsPrivilegeEscalationScanner()
            
            if active_scanners.get("persistence_scanner", False):
                scanners["persistence"] = WindowsPersistenceScanner()
            
            if active_scanners.get("service_scanner", False):
                scanners["service"] = WindowsServiceMisconfigurationScanner()
            
            if active_scanners.get("audit_scanner", False):
                scanners["audit"] = WindowsAuditPolicyScanner()
            
        except Exception as e:
            logger.error(f"Failed to create scanner instances: {e}")
        
        return scanners
    
    def _generate_host_hash(self) -> str:
        """Generate stable host identifier"""
        os_info = self.os_metadata.get("os_info", {})
        hostname = os_info.get("CSName", "UNKNOWN")
        os_version = os_info.get("Version", "UNKNOWN")
        
        raw = f"{hostname}|{os_version}".encode()
        return hashlib.sha256(raw).hexdigest()
    
    def _insert_system_record(self) -> str:
        """Insert system information into database"""
        os_info = self.os_metadata.get("os_info", {})
        host_hash = self._generate_host_hash()
        
        system_record = {
            "host_hash": host_hash,
            "hostname": os_info.get("CSName", "UNKNOWN"),
            "os_version": os_info.get("Version", "UNKNOWN"),
            "build_number": os_info.get("BuildNumber", "0"),
            "architecture": os_info.get("OSArchitecture", "UNKNOWN"),
            "scan_time": datetime.utcnow().isoformat(),
            "agent_version": "smartpatch-2.0",
            "elevated": int(self.runtime_context.get_context_value("execution.is_elevated", False)),
        }
        
        insert_system_info(self.db, system_record)
        return host_hash
    
    def execute_scan(self) -> Dict[str, Any]:
        """Execute complete scan lifecycle"""
        try:
            logger.info("Starting scan execution...")
            
            # 1. Initialize if not already done
            if not self.runtime_context or not self.db:
                if not self.initialize():
                    raise RuntimeError("Failed to initialize orchestrator")
            
            # 2. Determine active scanners
            active_scanners = self._get_active_scanners()
            
            # 3. Create scanner instances
            self.scanners = self._create_scanner_instances(active_scanners)
            
            # 4. Insert system record
            host_hash = self._insert_system_record()
            
            # 5. Execute scanners
            all_findings = []
            for scanner_name, scanner in self.scanners.items():
                try:
                    logger.info(f"Executing scanner: {scanner_name}")
                    
                    # Execute scanner
                    findings = scanner.scan()
                    
                    # Store results
                    self.scan_results[scanner_name] = {
                        "findings_count": len(findings),
                        "execution_time": datetime.utcnow().isoformat()
                    }
                    
                    # Insert findings into database
                    for finding in findings:
                        if isinstance(finding, SecurityFinding):
                            insert_finding(
                                db=self.db,
                                finding={
                                    "domain": finding.domain,
                                    "finding_type": finding.finding_type,
                                    "status": finding.status,
                                    "risk": finding.risk,
                                    "description": finding.description,
                                    "actual_value": json.dumps(finding.actual_value) if finding.actual_value else None,
                                    "expected_value": json.dumps(finding.expected_value) if finding.expected_value else None,
                                    "remediation_hint": finding.remediation_hint,
                                    "evidence": json.dumps(finding.evidence) if finding.evidence else None,
                                    "source_scanner": scanner_name,
                                },
                                host_hash=host_hash
                            )
                    
                    all_findings.extend(findings)
                    logger.info(f"Scanner {scanner_name} completed with {len(findings)} findings")
                    
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
                    self.db.log_scan_action(
                        action="scanner_error",
                        message=f"Scanner {scanner_name} failed: {str(e)}",
                        component=scanner_name,
                        level="ERROR"
                    )
            
            # 6. Run risk prioritization
            logger.info("Running HARS risk prioritization...")
            try:
                hars_prioritization_runtime()
                self.db.log_scan_action(
                    action="risk_prioritization",
                    message="HARS risk prioritization completed",
                    component="risk"
                )
            except Exception as e:
                logger.error(f"HARS prioritization failed: {e}")
                self.db.log_scan_action(
                    action="risk_error",
                    message=f"HARS prioritization failed: {str(e)}",
                    component="risk",
                    level="ERROR"
                )
            
            # 7. Compile final results
            result = {
                "scan_id": self.runtime_context.get_context_value("context_hash"),
                "timestamp": datetime.utcnow().isoformat(),
                "runtime_context": self.runtime_context.get_context(),
                "os_metadata": {
                    "fingerprint_hash": self.os_metadata.get("fingerprint_hash"),
                    "os_info": {
                        "caption": self.os_metadata.get("os_info", {}).get("Caption"),
                        "version": self.os_metadata.get("os_info", {}).get("Version"),
                        "build": self.os_metadata.get("os_info", {}).get("BuildNumber"),
                        "architecture": self.os_metadata.get("os_info", {}).get("OSArchitecture")
                    }
                },
                "capabilities": self.capabilities,
                "scanners_executed": list(self.scanners.keys()),
                "findings_total": len(all_findings),
                "scanner_results": self.scan_results,
                "database_path": str(self.db.db_path) if self.db else None
            }
            
            # 8. Log completion
            self.db.log_scan_action(
                action="complete",
                message=f"Scan completed with {len(all_findings)} findings",
                component="orchestrator"
            )
            
            logger.info(f"Scan completed successfully with {len(all_findings)} findings")
            
            return result
            
        except Exception as e:
            logger.error(f"Scan execution failed: {e}")
            if self.db:
                self.db.log_scan_action(
                    action="execution_error",
                    message=f"Scan execution failed: {str(e)}",
                    component="orchestrator",
                    level="ERROR"
                )
            raise
    
    def cleanup(self):
        """Clean up resources"""
        try:
            if self.db:
                self.db.disconnect()
                logger.info("Database connection closed")
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")


def run_orchestrator(config: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    High-level function to run the orchestrator.
    Returns scan results.
    """
    orchestrator = None
    try:
        orchestrator = SmartPatchOrchestrator(config)
        
        if not orchestrator.initialize():
            raise RuntimeError("Failed to initialize orchestrator")
        
        results = orchestrator.execute_scan()
        return results
        
    except Exception as e:
        logger.error(f"Orchestrator run failed: {e}")
        raise
        
    finally:
        if orchestrator:
            orchestrator.cleanup()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(RuntimePaths.LOG_DIR / "orchestrator.log"),
            logging.StreamHandler()
        ]
    )
    
    try:
        logger.info("Starting SmartPatch orchestrator...")
        
        # Run orchestrator
        results = run_orchestrator()
        
        # Output results
        print("\n" + "="*80)
        print("SCAN COMPLETED SUCCESSFULLY")
        print("="*80)
        print(f"Scan ID: {results.get('scan_id')}")
        print(f"OS: {results.get('os_metadata', {}).get('os_info', {}).get('caption')}")
        print(f"Version: {results.get('os_metadata', {}).get('os_info', {}).get('version')}")
        print(f"Build: {results.get('os_metadata', {}).get('os_info', {}).get('build')}")
        print(f"Findings: {results.get('findings_total', 0)}")
        print(f"Database: {results.get('database_path')}")
        print("="*80)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
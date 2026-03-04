"""
bootstrap.py - Main orchestrator with runtime context integration
Coordinates all scanners and builds the complete AssetProfile.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib
import sys
import os

# Internal modules
from .environment import RuntimeContext, bootstrap_runtime_context
from .os_fingerprint import get_os_metadata, get_capabilities
from .exposure_scanner import ExposureScanner, ExposureData

# Existing components (assumed to exist)
try:
    from runtime_db import (
        RuntimePaths,
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
    logging.getLogger(__name__).warning(f"Optional import failed: {e}")

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Asset Profile (defined once here, used across orchestrator)
# ----------------------------------------------------------------------
@dataclass
class AssetProfile:
    """Complete asset profile combining OS, patches, and exposure."""
    hostname: str
    os_version: str
    os_build: str
    os_architecture: str
    domain_joined: bool
    domain_name: Optional[str]
    installed_kbs: List[str]
    open_ports: List[Dict]
    services: List[Dict]
    scan_time: str
    host_hash: str


class SmartPatchOrchestrator:
    """
    Main orchestrator: coordinates all scanners and builds AssetProfile.
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
        """Initialize runtime context, OS metadata, and database."""
        try:
            logger.info("Initializing SmartPatch orchestrator...")
            self.runtime_context = bootstrap_runtime_context()
            self.os_metadata = get_os_metadata()
            self.capabilities = self.os_metadata.get("capabilities", {})
            self.db = init_runtime_database()
            self.db.log_scan_action(
                action="initialize",
                message=f"Orchestrator initialized with context hash: {self.runtime_context.get_context_value('context_hash')}",
                component="orchestrator"
            )
            logger.info(f"OS: {self.os_metadata.get('os_info', {}).get('Caption', 'Unknown')}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            return False

    def _get_active_scanners(self) -> Dict[str, bool]:
        """Determine which scanners can run based on capabilities."""
        active = {
            "os_metadata": True,
            "service_scanner": True,
            "audit_scanner": True,
            "exposure_scanner": True,   # always run exposure scanner
        }
        # Capability-dependent scanners
        active["authentication_scanner"] = self.capabilities.get("wmi", False)
        active["network_scanner"] = True
        active["privilege_scanner"] = self.capabilities.get("powershell", False)
        active["persistence_scanner"] = True
        active["update_scanner"] = self.capabilities.get("wmi", False)
        logger.info(f"Active scanners: {', '.join([k for k, v in active.items() if v])}")
        return active

    def _create_scanner_instances(self, active_scanners: Dict[str, bool]) -> Dict[str, Any]:
        """Instantiate scanners."""
        scanners = {}
        try:
            if active_scanners.get("os_metadata"):        scanners["os"] = WindowsOSScanner()
            if active_scanners.get("authentication_scanner"): scanners["authentication"] = WindowsAuthenticationScanner()
            if active_scanners.get("network_scanner"):    scanners["network"] = WindowsNetworkScanner()
            if active_scanners.get("privilege_scanner"):  scanners["privilege"] = WindowsPrivilegeEscalationScanner()
            if active_scanners.get("persistence_scanner"):scanners["persistence"] = WindowsPersistenceScanner()
            if active_scanners.get("service_scanner"):    scanners["service"] = WindowsServiceMisconfigurationScanner()
            if active_scanners.get("audit_scanner"):      scanners["audit"] = WindowsAuditPolicyScanner()
            if active_scanners.get("exposure_scanner"):   scanners["exposure"] = ExposureScanner()  # no db path needed
        except Exception as e:
            logger.error(f"Failed to create scanner instances: {e}")
        return scanners

    def _generate_host_hash(self) -> str:
        """Stable host identifier (matches existing patch scanner)."""
        os_info = self.os_metadata.get("os_info", {})
        hostname = os_info.get("CSName", "UNKNOWN")
        os_version = os_info.get("Version", "UNKNOWN")
        raw = f"{hostname}|{os_version}".encode()
        return hashlib.sha256(raw).hexdigest()

    def _get_installed_kbs_from_db(self) -> List[str]:
        """Retrieve installed KBs from the latest scan in runtime DB."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute('''
                SELECT kb_id FROM installed_patches
                WHERE scan_time = (SELECT MAX(scan_time) FROM installed_patches)
            ''')
            return [row['kb_id'] for row in cursor.fetchall()]
        except Exception as e:
            logger.warning(f"Could not retrieve installed KBs: {e}")
            return []

    def _insert_system_record(self, host_hash: str) -> None:
        """Insert basic system info into runtime DB."""
        os_info = self.os_metadata.get("os_info", {})
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

    def _save_asset_profile(self, profile: AssetProfile) -> None:
        """Save the assembled asset profile to the database."""
        cursor = self.db.conn.cursor()
        # Ensure table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asset_profile (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_hash TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                hostname TEXT,
                os_version TEXT,
                os_build TEXT,
                os_architecture TEXT,
                domain_joined INTEGER,
                domain_name TEXT,
                installed_kbs TEXT,
                open_ports TEXT,
                services TEXT,
                UNIQUE(host_hash, scan_time)
            )
        ''')
        cursor.execute('''
            INSERT OR REPLACE INTO asset_profile
            (host_hash, scan_time, hostname, os_version, os_build, os_architecture,
             domain_joined, domain_name, installed_kbs, open_ports, services)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            profile.host_hash,
            profile.scan_time,
            profile.hostname,
            profile.os_version,
            profile.os_build,
            profile.os_architecture,
            1 if profile.domain_joined else 0,
            profile.domain_name,
            json.dumps(profile.installed_kbs),
            json.dumps(profile.open_ports),
            json.dumps(profile.services)
        ))
        self.db.conn.commit()
        logger.info(f"Asset profile saved for {profile.hostname}")

    def execute_scan(self) -> Dict[str, Any]:
        """Full scan: run all scanners, build asset profile, run risk."""
        try:
            if not self.runtime_context or not self.db:
                if not self.initialize():
                    raise RuntimeError("Failed to initialize orchestrator")

            active_scanners = self._get_active_scanners()
            self.scanners = self._create_scanner_instances(active_scanners)
            host_hash = self._generate_host_hash()
            self._insert_system_record(host_hash)

            # ------------------------------------------------------------------
            # 1. Run all security scanners (findings)
            # ------------------------------------------------------------------
            all_findings = []
            for scanner_name, scanner in self.scanners.items():
                if scanner_name == "exposure":
                    continue  # handled separately
                try:
                    logger.info(f"Executing scanner: {scanner_name}")
                    findings = scanner.scan()
                    self.scan_results[scanner_name] = {
                        "findings_count": len(findings),
                        "execution_time": datetime.utcnow().isoformat()
                    }
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
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
                    self.db.log_scan_action(
                        action="scanner_error",
                        message=f"Scanner {scanner_name} failed: {str(e)}",
                        component=scanner_name,
                        level="ERROR"
                    )

            # ------------------------------------------------------------------
            # 2. Run exposure scanner to get ports/services/domain
            # ------------------------------------------------------------------
            exposure_data = ExposureData(open_ports=[], services=[], domain_joined=False, domain_name=None)
            if "exposure" in self.scanners:
                try:
                    exposure_scanner = self.scanners["exposure"]
                    exposure_data = exposure_scanner.scan()
                    logger.info(f"Exposure scan complete: {len(exposure_data.open_ports)} ports, {len(exposure_data.services)} services")
                except Exception as e:
                    logger.error(f"Exposure scanner failed: {e}")

            # ------------------------------------------------------------------
            # 3. Build the complete AssetProfile
            # ------------------------------------------------------------------
            os_info = self.os_metadata.get("os_info", {})
            installed_kbs = self._get_installed_kbs_from_db()
            profile = AssetProfile(
                hostname=os_info.get("CSName", "UNKNOWN"),
                os_version=os_info.get("Caption", "Unknown"),
                os_build=os_info.get("BuildNumber", ""),
                os_architecture=os_info.get("OSArchitecture", ""),
                domain_joined=exposure_data.domain_joined,
                domain_name=exposure_data.domain_name,
                installed_kbs=installed_kbs,
                open_ports=exposure_data.open_ports,
                services=exposure_data.services,
                scan_time=datetime.utcnow().isoformat(),
                host_hash=host_hash
            )
            self._save_asset_profile(profile)

            # ------------------------------------------------------------------
            # 4. Risk prioritization (now with full profile)
            # ------------------------------------------------------------------
            logger.info("Running HARS risk prioritization...")
            try:
                # Pass the profile to risk engine if it accepts it
                hars_prioritization_runtime(asset_profile=profile)
                self.db.log_scan_action(
                    action="risk_prioritization",
                    message="HARS risk prioritization completed",
                    component="risk"
                )
            except Exception as e:
                logger.error(f"HARS prioritization failed: {e}")

            # ------------------------------------------------------------------
            # 5. Compile results
            # ------------------------------------------------------------------
            result = {
                "scan_id": self.runtime_context.get_context_value("context_hash"),
                "timestamp": datetime.utcnow().isoformat(),
                "runtime_context": self.runtime_context.get_context(),
                "os_metadata": {
                    "fingerprint_hash": self.os_metadata.get("fingerprint_hash"),
                    "os_info": {
                        "caption": os_info.get("Caption"),
                        "version": os_info.get("Version"),
                        "build": os_info.get("BuildNumber"),
                        "architecture": os_info.get("OSArchitecture")
                    }
                },
                "exposure": {
                    "open_ports": exposure_data.open_ports,
                    "services": exposure_data.services,
                    "domain_joined": exposure_data.domain_joined,
                    "domain_name": exposure_data.domain_name
                },
                "capabilities": self.capabilities,
                "scanners_executed": list(self.scanners.keys()),
                "findings_total": len(all_findings),
                "scanner_results": self.scan_results,
                "database_path": str(self.db.db_path) if hasattr(self.db, 'db_path') else None
            }

            self.db.log_scan_action(
                action="complete",
                message=f"Scan completed with {len(all_findings)} findings",
                component="orchestrator"
            )
            logger.info(f"Scan completed successfully")
            return result

        except Exception as e:
            logger.error(f"Scan execution failed: {e}", exc_info=True)
            if self.db:
                self.db.log_scan_action(
                    action="execution_error",
                    message=f"Scan execution failed: {str(e)}",
                    component="orchestrator",
                    level="ERROR"
                )
            raise

    def cleanup(self):
        if self.db:
            try:
                self.db.disconnect()
            except:
                pass


# ----------------------------------------------------------------------
# Helper to get latest runtime DB (used in __main__)
# ----------------------------------------------------------------------
def get_latest_runtime_db() -> Path:
    programdata = os.getenv("PROGRAMDATA", "C:/ProgramData")
    runtime_dir = Path(programdata) / "SmartPatch" / "runtime"
    db_files = sorted(runtime_dir.glob("runtime_*.sqlite"), reverse=True)
    if not db_files:
        # fallback to a default name
        return runtime_dir / "runtime.db"
    return db_files[0]


def run_orchestrator(config: Dict = None) -> Dict:
    orchestrator = None
    try:
        orchestrator = SmartPatchOrchestrator(config)
        if not orchestrator.initialize():
            raise RuntimeError("Failed to initialize orchestrator")
        return orchestrator.execute_scan()
    finally:
        if orchestrator:
            orchestrator.cleanup()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(Path(__file__).parent / "logs" / "orchestrator.log"),
            logging.StreamHandler()
        ]
    )
    try:
        logger.info("Starting SmartPatch orchestrator...")
        results = run_orchestrator()
        print("\n" + "="*80)
        print("SCAN COMPLETED SUCCESSFULLY")
        print("="*80)
        print(f"Scan ID: {results.get('scan_id')}")
        print(f"OS: {results.get('os_metadata', {}).get('os_info', {}).get('caption')}")
        print(f"Open ports: {len(results.get('exposure', {}).get('open_ports', []))}")
        print(f"Services: {len(results.get('exposure', {}).get('services', []))}")
        print(f"Findings: {results.get('findings_total', 0)}")
        print(f"Database: {results.get('database_path')}")
        print("="*80)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
"""
bootstrap.py - Main orchestrator with runtime context integration
Coordinates all scanners and builds the complete AssetProfile.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import hashlib
import sys
import os

# Support running as both module and direct script
_is_package = __name__ != "__main__"

# Add parent directory to path for direct script execution
if not _is_package:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    sys.path.insert(0, str(Path(__file__).parent))

# Internal modules - handle both relative and absolute imports
try:
    if _is_package:
        from .environment import RuntimeContext, bootstrap_runtime_context
        from .os_fingerprint import get_os_metadata, get_capabilities
        from .exposure_scanner import ExposureScanner, ExposureData
    else:
        from environment import RuntimeContext, bootstrap_runtime_context
        from os_fingerprint import get_os_metadata, get_capabilities
        from exposure_scanner import ExposureScanner, ExposureData
except ImportError as e:
    logging.getLogger(__name__).error(f"Failed to import internal modules: {e}")
    raise

# Tools for missing patch detection
try:
    sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
    from missing_patch import MissingPatchResolver
except ImportError as e:
    logging.getLogger(__name__).debug(f"Could not import MissingPatchResolver: {e}")
    MissingPatchResolver = None

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
    from riskengine.risk import hars_prioritization_runtime
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
        """Retrieve installed KBs from the latest scan in runtime DB, with fallback to OS metadata."""
        try:
            # First try database
            cursor = self.db.conn.cursor()
            cursor.execute('''
                SELECT kb_id FROM installed_patches
                WHERE scan_time = (SELECT MAX(scan_time) FROM installed_patches)
            ''')
            results = cursor.fetchall()
            if results:
                return [row['kb_id'] for row in results]
        except Exception as e:
            logger.warning(f"Could not retrieve installed KBs from database: {e}")
        
        # Fallback: Extract real KBs from OS metadata hotfixes (actual system data)
        try:
            hotfixes = self.os_metadata.get("hotfixes", [])
            installed_kbs = []
            import re
            kb_pattern = re.compile(r'\bKB\d{5,7}\b', re.IGNORECASE)
            
            for hotfix in hotfixes:
                # Try various KB field names
                kb_id = None
                if isinstance(hotfix, dict):
                    kb_id = (hotfix.get("HotFixID") or 
                            hotfix.get("HotFix") or 
                            hotfix.get("KB") or
                            hotfix.get("kb_id"))
                elif isinstance(hotfix, str):
                    match = kb_pattern.search(hotfix)
                    if match:
                        kb_id = match.group(0)
                
                if kb_id:
                    kb_normalized = kb_id.upper().strip()
                    if kb_normalized and kb_normalized not in installed_kbs:
                        installed_kbs.append(kb_normalized)
            
            if installed_kbs:
                logger.info(f"Retrieved {len(installed_kbs)} real installed KBs from system hotfixes")
                return installed_kbs
        except Exception as e:
            logger.warning(f"Could not extract KBs from OS metadata: {e}")
        
        # No data found
        logger.warning("No installed KBs found from database or hotfixes")
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

    def _save_host_context_to_db(self, host_context: Dict[str, Any], host_hash: str, scan_time: str) -> None:
        """Save the host_context to database with all real data."""
        try:
            cursor = self.db.conn.cursor()
            
            # Create host_context table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS host_context (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_hash TEXT NOT NULL,
                    scan_time TEXT NOT NULL,
                    os_name TEXT,
                    os_version TEXT,
                    architecture TEXT,
                    hostname TEXT,
                    build_number TEXT,
                    domain_joined INTEGER,
                    domain_name TEXT,
                    installed_kbs TEXT,
                    missing_kbs TEXT,
                    services TEXT,
                    applications TEXT,
                    UNIQUE(host_hash, scan_time)
                )
            ''')
            
            host = host_context.get("host", {})
            
            cursor.execute('''
                INSERT OR REPLACE INTO host_context
                (host_hash, scan_time, os_name, os_version, architecture, hostname,
                 build_number, domain_joined, domain_name, installed_kbs, missing_kbs,
                 services, applications)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                host_hash,
                scan_time,
                host.get("os_name", "Unknown"),
                host.get("os_version", "Unknown"),
                host.get("architecture", "Unknown"),
                host.get("hostname", "UNKNOWN"),
                host.get("build_number", ""),
                1 if host.get("domain_joined", False) else 0,
                host.get("domain_name", None),
                json.dumps(host.get("installed_kbs", [])),
                json.dumps(host.get("missing_kbs", [])),
                json.dumps(host.get("services", {})),
                json.dumps(host.get("applications", []))
            ))
            
            self.db.conn.commit()
            logger.info(f"Host context saved to database for {host.get('hostname', 'unknown')}")
            
            # Log database path for verification
            db_path = self.db.db_path if hasattr(self.db, 'db_path') else "unknown"
            logger.info(f"Data persisted to database: {db_path}")
        except Exception as e:
            logger.error(f"Failed to save host_context to database: {e}")

    def _save_os_metadata_for_patch_resolver(self) -> Path:
        """
        Save OS metadata to JSON file for MissingPatchResolver to use.
        Returns the path to the saved file.
        """
        try:
            os_meta_file = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData")) / "SmartPatch" / "runtime" / "os_metadata.json"
            os_meta_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Prepare metadata
            metadata = {
                "os_info": self.os_metadata.get("os_info", {}),
                "hotfixes": self.os_metadata.get("hotfixes", []),
                "capabilities": self.capabilities,
                "cache_timestamp": datetime.utcnow().isoformat()
            }
            
            with open(os_meta_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
            
            logger.info(f"OS metadata saved to: {os_meta_file}")
            return os_meta_file
        except Exception as e:
            logger.error(f"Failed to save OS metadata: {e}")
            return None

    def _resolve_missing_patches(self, os_meta_file: Path) -> List[Dict[str, str]]:
        """
        Use MissingPatchResolver to identify missing patches from dev_db.sqlite.
        Writes real data to runtime database.
        Returns list of dicts with 'cve_id' and 'kb_id' keys.
        """
        if not MissingPatchResolver:
            logger.warning("MissingPatchResolver not available; skipping missing patch resolution")
            return []
        
        try:
            # Find dev_db.sqlite
            dev_db_path = Path(__file__).parent.parent / "database" / "dev_db.sqlite"
            
            # Use the actual runtime database that bootstrap is using (self.db.db_path)
            if hasattr(self.db, 'db_path'):
                runtime_db_path = self.db.db_path
            else:
                # Fallback: create dated database in runtime directory
                runtime_dir = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData")) / "SmartPatch" / "runtime"
                runtime_dir.mkdir(parents=True, exist_ok=True)
                scan_time = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                runtime_db_path = runtime_dir / f"runtime_{scan_time}.sqlite"
            
            if not dev_db_path.exists():
                logger.warning(f"dev_db.sqlite not found at {dev_db_path}; cannot resolve missing patches")
                return []
            
            logger.info(f"Using runtime database: {runtime_db_path}")
            
            # ENABLE write_runtime=True to persist missing patches data to runtime database
            resolver = MissingPatchResolver(
                os_meta_path=os_meta_file,
                dev_db_path=dev_db_path,
                runtime_db_path=runtime_db_path,
                write_runtime=True  # ENABLED: Write real missing patches data to runtime DB
            )
            
            # Run resolution - this will now save patch_state and installed_kbs to the runtime database
            summary = resolver.resolve()
            missing_patches = summary.get("missing", [])
            
            logger.info(f"Resolved and persisted {len(missing_patches)} missing KBs to runtime database")
            return missing_patches
        
        except Exception as e:
            logger.error(f"Failed to resolve missing patches: {e}")
            return []

    def _build_host_context(self, exposure_data: ExposureData, installed_kbs: List[str], 
                           missing_kbs: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Build host context in the requested format using actual data from modules.
        Uses exposure_scanner for services and missing_patch.py for missing KBs.
        
        Returns a dict with 'host' section containing:
        - os_name, os_version, architecture
        - installed_kbs (from OS metadata)
        - missing_kbs (from dev_db via MissingPatchResolver)
        - services (from exposure_scanner)
        - applications (from OS metadata)
        """
        try:
            os_info = self.os_metadata.get("os_info", {})
            
            # Build services dict from exposure_data
            services_dict = {}
            for svc in exposure_data.services:
                service_name = svc.get("display_name") or svc.get("name", "Unknown")
                # Try to extract version from display_name or use status
                version = "Unknown"
                status = svc.get("status", "Unknown")
                services_dict[service_name] = version if version != "Unknown" else status
            
            # Extract applications from os_metadata (if available)
            applications = []
            if "applications" in self.os_metadata:
                apps = self.os_metadata.get("applications", [])
                if isinstance(apps, list):
                    applications = apps
                elif isinstance(apps, dict):
                    applications = list(apps.keys())
            
            # Build missing KBs list
            missing_kb_ids = [kb["kb_id"] for kb in missing_kbs if "kb_id" in kb]
            
            host_context = {
                "host": {
                    "os_name": os_info.get("Caption", "Unknown Windows OS"),
                    "os_version": os_info.get("Version", "Unknown"),
                    "architecture": os_info.get("OSArchitecture", "Unknown"),
                    "installed_kbs": installed_kbs,
                    "missing_kbs": missing_kb_ids,
                    "services": services_dict,
                    "applications": applications,
                    "hostname": os_info.get("CSName", "UNKNOWN"),
                    "build_number": os_info.get("BuildNumber", ""),
                    "domain_joined": any(svc for svc in exposure_data.services),  # At least has services
                    "domain_name": exposure_data.domain_name or None
                }
            }
            
            logger.info(f"Host context built with {len(installed_kbs)} installed KBs, {len(missing_kb_ids)} missing KBs")
            return host_context
        
        except Exception as e:
            logger.error(f"Failed to build host context: {e}")
            return {"host": {}}


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
            
            # Fallback: If exposure scanner didn't provide services, get them directly
            if not exposure_data.services:
                try:
                    # Direct scan for services using ExposureScanner
                    direct_scanner = ExposureScanner()
                    exposure_data = direct_scanner.scan()
                    logger.info(f"Direct exposure scan: {len(exposure_data.services)} services found")
                except Exception as e:
                    logger.warning(f"Direct service scan failed: {e}")

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
            # 3a. Build host context with missing patches - PERSIST TO RUNTIME DB
            # ------------------------------------------------------------------
            logger.info("Building host context with missing patch detection...")
            host_context = {}
            scan_time = datetime.utcnow().isoformat()
            try:
                # Save OS metadata for MissingPatchResolver
                os_meta_file = self._save_os_metadata_for_patch_resolver()
                if os_meta_file:
                    # Resolve missing patches from dev_db.sqlite (and save to runtime DB)
                    missing_patches = self._resolve_missing_patches(os_meta_file)
                    logger.info(f"Received {len(missing_patches)} missing patches from resolver")
                    
                    # Build formatted host context with REAL DATA
                    host_context = self._build_host_context(exposure_data, installed_kbs, missing_patches)
                    
                    # Save host_context to database with real system data (KBs, services, etc.)
                    self._save_host_context_to_db(host_context, host_hash, scan_time)
                    logger.info(f"Host context built and persisted successfully")
                else:
                    logger.warning("Could not save OS metadata; skipping host context")
            except Exception as e:
                logger.error(f"Failed to build host context: {e}")
                host_context = {"host": {}}

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
                "host_context": host_context,
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
            
            # Log runtime database path for verification
            db_path = str(self.db.db_path) if hasattr(self.db, 'db_path') else "unknown"
            logger.info(f"Scan completed successfully")
            logger.info(f"All data persisted to runtime database: {db_path}")
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
        
        # Extract and display host_context in the requested format
        host_context = results.get("host_context", {})
        
        print("\n" + "="*80)
        print("SCAN COMPLETED - HOST CONTEXT OUTPUT (REAL SYSTEM DATA)")
        print("="*80)
        print(json.dumps(host_context, indent=2))
        print("="*80)
        
        # Also show summary
        host = host_context.get("host", {})
        print(f"\nScan Summary:")
        print(f"  Hostname: {host.get('hostname', 'N/A')}")
        print(f"  OS: {host.get('os_name', 'N/A')} (Build {host.get('build_number', 'N/A')})")
        print(f"  Architecture: {host.get('architecture', 'N/A')}")
        print(f"  Installed KBs: {len(host.get('installed_kbs', []))}")
        print(f"  Missing KBs: {len(host.get('missing_kbs', []))}")
        print(f"  Running Services: {len(host.get('services', {}))}")
        print(f"  Domain: {host.get('domain_name', 'Not domain-joined')}")
        print("="*80)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
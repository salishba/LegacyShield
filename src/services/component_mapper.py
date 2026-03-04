"""
COMPONENT MAPPER - Vulnerability to Component and Control Mapping

Maps CVEs to:
- Affected components (DLL, EXE, service, registry key)
- Applicable mitigation controls
- Component-specific remediation procedures

Part of SmartPatch Execution Layer
"""

import sqlite3
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class ComponentType(str, Enum):
    """Types of affected components"""
    DLL = "dll"              # Dynamic library (.dll)
    EXE = "exe"             # Executable (.exe)
    DRIVER = "driver"       # System driver (.sys)
    REGISTRY_KEY = "registry"  # Registry key/value
    SERVICE = "service"     # System/user service
    FEATURE = "feature"     # Windows optional feature
    CONFIG = "config"       # Configuration file
    LIBRARY = "library"     # Software library/module


class ComponentSeverity(str, Enum):
    """Impact severity of component compromise"""
    CRITICAL = "critical"    # Core system function, affects all systems
    HIGH = "high"           # Important function, affects multiple systems
    MEDIUM = "medium"       # Significant function, affects some systems
    LOW = "low"            # Limited function, affects few systems


@dataclass
class ComponentInfo:
    """Information about a specific affected component"""
    component_id: str              # Unique ID (DLL name, service name, key path)
    component_type: ComponentType  # Type of component
    name: str                      # Human-readable name
    description: str               # What this component does
    path: Optional[str] = None     # File path or registry path
    severity: ComponentSeverity = ComponentSeverity.MEDIUM
    affected_cves: List[str] = field(default_factory=list)  # CVEs affecting this
    associated_services: List[str] = field(default_factory=list)  # Services using this
    registry_keys: List[str] = field(default_factory=list)  # Registry locations
    hardening_controls: List[str] = field(default_factory=list)  # Control IDs that mitigate


@dataclass
class VulnerabilityComponentMap:
    """Complete mapping of vulnerability to components and controls"""
    cve_id: str
    components: List[ComponentInfo] = field(default_factory=list)
    affected_services: Set[str] = field(default_factory=set)
    affected_features: Set[str] = field(default_factory=set)
    applicable_controls: Dict[str, List[str]] = field(default_factory=dict)  # {control_type: [control_ids]}
    hardening_available: bool = False
    exploit_uses_components: List[str] = field(default_factory=list)
    remediation_path: Optional[str] = None  # Patch or hardening sequence
    estimated_effort_hours: float = 0.0
    
    def add_component(self, component: ComponentInfo) -> None:
        """Add component to mapping"""
        self.components.append(component)
        
        if component.component_type == ComponentType.SERVICE:
            self.affected_services.add(component.name)
        elif component.component_type == ComponentType.FEATURE:
            self.affected_features.add(component.name)


class ComponentMapper:
    """
    Maps vulnerabilities to affected components and remediation controls
    
    Integrates with:
    - CVE database (dev_db) for component information
    - System data (runtime_db) for installed components
    - Control catalogue for remediation recommendations
    
    Usage:
        mapper = ComponentMapper(dev_db_path="dev_db.sqlite")
        comp_map = mapper.map_vulnerability("CVE-2021-1234", os_version="Windows 10")
    """
    
    def __init__(self, dev_db_path: str = "dev_db.sqlite", 
                 runtime_db_path: str = "runtime_scan.sqlite"):
        """Initialize component mapper with database paths"""
        self.dev_db_path = dev_db_path
        self.runtime_db_path = runtime_db_path
        
        # Component registry - maps known vulnerabilities to components
        self.component_registry: Dict[str, List[ComponentInfo]] = {}
        self._initialize_component_registry()
    
    def _initialize_component_registry(self):
        """Build in-memory component registry from known vulnerabilities"""
        # Pre-configured components for common Windows attack surfaces
        self.component_registry = {
            "smb": [
                ComponentInfo(
                    component_id="srv2.sys",
                    component_type=ComponentType.DRIVER,
                    name="Server Message Block v2/v3 Driver",
                    description="Handles SMB network protocol (file sharing, printer sharing)",
                    path="%SystemRoot%\\System32\\drivers\\srv2.sys",
                    severity=ComponentSeverity.CRITICAL,
                    associated_services=["LanmanServer"],
                    hardening_controls=["NET-01"]  # Disable SMBv1
                ),
            ],
            "rpc": [
                ComponentInfo(
                    component_id="rpcss.exe",
                    component_type=ComponentType.EXE,
                    name="RPC Service",
                    description="Remote Procedure Call service - inter-process communication",
                    path="%SystemRoot%\\System32\\svchost.exe -k rpcss",
                    severity=ComponentSeverity.CRITICAL,
                    associated_services=["RpcSs"],
                    hardening_controls=["NET-02", "SVC-01"]
                ),
                ComponentInfo(
                    component_id="rpcrt4.dll",
                    component_type=ComponentType.DLL,
                    name="RPC Runtime Library",
                    description="Runtime support for RPC calls",
                    path="%SystemRoot%\\System32\\rpcrt4.dll",
                    severity=ComponentSeverity.CRITICAL,
                    registry_keys=["HKLM:\\Software\\Microsoft\\Rpc"],
                    hardening_controls=["NET-02"]
                ),
            ],
            "lsass": [
                ComponentInfo(
                    component_id="lsass.exe",
                    component_type=ComponentType.EXE,
                    name="Local Security Authority Process",
                    description="Authenticates users, manages user credentials",
                    path="%SystemRoot%\\System32\\lsass.exe",
                    severity=ComponentSeverity.CRITICAL,
                    associated_services=["LSM"],
                    hardening_controls=["AUTH-01", "AUTH-02", "AUTH-03"],
                    registry_keys=["HKLM:\\System\\CurrentControlSet\\Control\\Lsa"]
                ),
            ],
            "spool": [
                ComponentInfo(
                    component_id="spoolsv.exe",
                    component_type=ComponentType.EXE,
                    name="Print Spooler Service",
                    description="Manages print jobs and print server connections",
                    path="%SystemRoot%\\System32\\spoolsv.exe",
                    severity=ComponentSeverity.HIGH,
                    associated_services=["spooler"],
                    hardening_controls=["SVC-02"]  # Can disable if not printing
                ),
            ],
            "kernel": [
                ComponentInfo(
                    component_id="kernel32.dll",
                    component_type=ComponentType.DLL,
                    name="Windows Kernel32 Library",
                    description="Core Windows API and kernel functions",
                    path="%SystemRoot%\\System32\\kernel32.dll",
                    severity=ComponentSeverity.CRITICAL,
                    hardening_controls=["APP-01", "NET-01"]
                ),
            ],
            "ntlm": [
                ComponentInfo(
                    component_id="ntlm.dll",
                    component_type=ComponentType.DLL,
                    name="NTLM Authentication",
                    description="Legacy NTLM authentication protocol",
                    path="%SystemRoot%\\System32\\ntlm.dll",
                    severity=ComponentSeverity.HIGH,
                    hardening_controls=["AUTH-04"],  # Restrict legacy auth
                    registry_keys=["HKLM:\\System\\CurrentControlSet\\Control\\Lsa"]
                ),
            ],
            "powershell": [
                ComponentInfo(
                    component_id="powershell.exe",
                    component_type=ComponentType.EXE,
                    name="Windows PowerShell",
                    description="Command-line shell and scripting language",
                    path="%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    severity=ComponentSeverity.HIGH,
                    hardening_controls=["APP-01"],  # Disable PS v2
                    associated_services=["WinRM"]
                ),
            ],
        }
    
    def map_vulnerability(self, cve_id: str, 
                         vulnerability_keywords: List[str],
                         os_version: str = "Windows 10") -> VulnerabilityComponentMap:
        """
        Map vulnerability to affected components and applicable controls
        
        Args:
            cve_id: CVE identifier
            vulnerability_keywords: Keywords from CVE (e.g., ["SMB", "RCE", "elevation"])
            os_version: Target OS version
        
        Returns:
            VulnerabilityComponentMap with components and controls
        """
        vuln_map = VulnerabilityComponentMap(cve_id=cve_id)
        
        # Query dev_db for component information
        try:
            components_from_db = self._query_components_from_db(cve_id)
            for comp in components_from_db:
                vuln_map.add_component(comp)
        except Exception as e:
            logger.warning("Could not query dev_db for components: %s", str(e))
        
        # Match keywords to known components
        for keyword in vulnerability_keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in self.component_registry:
                for component in self.component_registry[keyword_lower]:
                    if component not in vuln_map.components:
                        vuln_map.add_component(component)
        
        # Determine applicable controls
        vuln_map = self._determine_applicable_controls(vuln_map, vulnerability_keywords)
        
        # Estimate remediation effort
        vuln_map.estimated_effort_hours = self._estimate_effort(vuln_map)
        
        logger.info("Mapped %s to %d components with %d controls",
                   cve_id, len(vuln_map.components), 
                   sum(len(v) for v in vuln_map.applicable_controls.values()))
        
        return vuln_map
    
    def _query_components_from_db(self, cve_id: str) -> List[ComponentInfo]:
        """Query dev_db for component information"""
        components = []
        
        try:
            conn = sqlite3.connect(self.dev_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Query for CVE components
            cursor.execute("""
                SELECT component, component_type, severity
                FROM cve_components
                WHERE cve_id = ?
            """, (cve_id,))
            
            rows = cursor.fetchall()
            for row in rows:
                component = ComponentInfo(
                    component_id=row["component"],
                    component_type=ComponentType(row.get("component_type", "dll")),
                    name=row["component"],
                    description=f"Component affected by {cve_id}",
                    severity=ComponentSeverity(row.get("severity", "medium"))
                )
                components.append(component)
            
            conn.close()
        except Exception as e:
            logger.debug("Component query failed (normal if table doesn't exist): %s", str(e))
        
        return components
    
    def _determine_applicable_controls(self, 
                                      vuln_map: VulnerabilityComponentMap,
                                      keywords: List[str]) -> VulnerabilityComponentMap:
        """Determine which controls are applicable"""
        applicable_controls: Dict[str, List[str]] = {}
        
        # Map vulnerability keywords to control types
        keyword_to_control_mapping = {
            "smb": ["NET-01"],           # Disable SMBv1
            "rpc": ["NET-02", "SVC-01"],  # RPC hardening
            "lm": ["AUTH-01"],            # Disable LM hashes
            "ntlm": ["AUTH-04"],         # Restrict NTLM
            "powershell": ["APP-01"],    # Disable PS v2
            "credential": ["AUTH-01", "AUTH-02", "AUTH-03"],  # Auth controls
            "elevation": ["APP-02"],     # UAC controls
        }
        
        for keyword in keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in keyword_to_control_mapping:
                for control_id in keyword_to_control_mapping[keyword_lower]:
                    if control_id not in applicable_controls:
                        applicable_controls[control_id] = []
                    applicable_controls[control_id].append(keyword)
        
        # Get controls from component registry
        for component in vuln_map.components:
            for control_id in component.hardening_controls:
                if control_id not in applicable_controls:
                    applicable_controls[control_id] = []
                applicable_controls[control_id].append(f"component:{component.name}")
        
        vuln_map.applicable_controls = applicable_controls
        vuln_map.hardening_available = len(applicable_controls) > 0
        
        return vuln_map
    
    def _estimate_effort(self, vuln_map: VulnerabilityComponentMap) -> float:
        """Estimate time to remediate in hours"""
        effort = 0.0
        
        # Base effort per component type
        component_effort = {
            ComponentType.DLL: 0.5,        # Patch file - quick
            ComponentType.EXE: 0.5,        # Patch file - quick
            ComponentType.DRIVER: 1.0,    # Requires reboot
            ComponentType.REGISTRY_KEY: 0.25,  # Quick registry change
            ComponentType.SERVICE: 0.5,   # Disable/enable service
            ComponentType.FEATURE: 1.0,   # Feature disable/enable
            ComponentType.CONFIG: 0.5,    # Config change
        }
        
        for component in vuln_map.components:
            effort += component_effort.get(component.component_type, 0.5)
        
        # Add effort for applicable controls
        effort += len(vuln_map.applicable_controls) * 0.25
        
        # Add validation time per component
        effort += len(vuln_map.components) * 0.25
        
        return round(effort, 2)
    
    def get_affected_systems(self, cve_id: str, 
                            vuln_map: VulnerabilityComponentMap) -> List[str]:
        """
        Query runtime_db for systems affected by this vulnerability
        based on components installed
        """
        affected_hosts = []
        
        try:
            conn = sqlite3.connect(self.runtime_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find systems with affected services
            for service in vuln_map.affected_services:
                cursor.execute("""
                    SELECT DISTINCT host_hash FROM running_services
                    WHERE service_name = ?
                """, (service,))
                affected_hosts.extend([row["host_hash"] for row in cursor.fetchall()])
            
            # Find systems with affected optional features enabled
            for feature in vuln_map.affected_features:
                cursor.execute("""
                    SELECT DISTINCT host_hash FROM system_info
                    WHERE features LIKE ?
                """, (f"%{feature}%",))
                affected_hosts.extend([row["host_hash"] for row in cursor.fetchall()])
            
            conn.close()
            # Remove duplicates
            affected_hosts = list(set(affected_hosts))
            
        except Exception as e:
            logger.debug("Could not query affected systems: %s", str(e))
        
        return affected_hosts
    
    def generate_remediation_plan(self, 
                                 vuln_map: VulnerabilityComponentMap,
                                 component_controls: Dict[str, List[str]]) -> Dict[str, any]:
        """
        Generate step-by-step remediation plan
        
        Args:
            vuln_map: Vulnerability component mapping
            component_controls: Mapping of components to control IDs
        
        Returns:
            Structured remediation plan with phases
        """
        plan = {
            "phases": [],
            "total_effort": vuln_map.estimated_effort_hours,
            "components_affected": len(vuln_map.components),
            "controls_to_apply": len(vuln_map.applicable_controls)
        }
        
        # Phase 1: Pre-patch assessment
        plan["phases"].append({
            "phase": 1,
            "name": "Pre-Patch Assessment",
            "steps": [
                "Verify all affected components installed",
                "Check backup status",
                "Document current system state",
                "Plan maintenance window"
            ],
            "effort": 0.5
        })
        
        # Phase 2: Hardening (if applicable)
        if vuln_map.hardening_available:
            plan["phases"].append({
                "phase": 2,
                "name": "Apply Hardening Controls",
                "steps": [
                    f"Apply control: {cid}"
                    for cid in vuln_map.applicable_controls.keys()
                ],
                "effort": len(vuln_map.applicable_controls) * 0.25
            })
        
        # Phase 3: Patching
        plan["phases"].append({
            "phase": 3,
            "name": "Apply Patch",
            "steps": [
                "Schedule maintenance window",
                "Apply patches",
                "Verify patch installation",
                "Restart services"
            ],
            "effort": 0.5
        })
        
        # Phase 4: Validation
        plan["phases"].append({
            "phase": 4,
            "name": "Validation",
            "steps": [
                "Run component verification",
                "Validate affected services operational",
                "Check system logs for errors",
                "Confirm vulnerability remediated"
            ],
            "effort": 0.5
        })
        
        return plan


# Example usage and testing
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize mapper
    mapper = ComponentMapper(
        dev_db_path="dev_db.sqlite",
        runtime_db_path="runtime_scan.sqlite"
    )
    
    # Example: Map a vulnerability
    print("\n--- Mapping CVE-2021-1234 (SMB/Ransomware) ---")
    vuln_map = mapper.map_vulnerability(
        cve_id="CVE-2021-1234",
        vulnerability_keywords=["SMB", "RCE", "ransomware", "wormable"],
        os_version="Windows 7 SP1"
    )
    
    print(f"Components Affected: {len(vuln_map.components)}")
    for comp in vuln_map.components:
        print(f"  - {comp.name} ({comp.component_type.value}): {comp.severity.value}")
    
    print(f"\nApplicable Controls: {len(vuln_map.applicable_controls)}")
    for control_id, keywords in vuln_map.applicable_controls.items():
        print(f"  - {control_id}: {', '.join(keywords)}")
    
    print(f"\nAffected Services: {vuln_map.affected_services}")
    print(f"Estimated Effort: {vuln_map.estimated_effort_hours} hours")
    print(f"Hardening Available: {vuln_map.hardening_available}")
    
    # Generate remediation plan
    plan = mapper.generate_remediation_plan(vuln_map, {})
    print(f"\nRemediation Plan:")
    for phase in plan["phases"]:
        print(f"  Phase {phase['phase']}: {phase['name']} ({phase['effort']}h)")
        for step in phase["steps"]:
            print(f"    - {step}")

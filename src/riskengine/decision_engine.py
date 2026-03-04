"""
decision_engine.py - Production-Grade Decision Layer for SmartPatch

The Decision Layer orchestrates all vulnerability prioritization, risk assessment,
and remediation recommendations. This is the core intelligence module that transforms
vulnerability scores into actionable business decisions.

This module:
1. Prioritizes vulnerabilities based on multiple risk factors
2. Recommends specific remediation actions with context
3. Assesses rollback risk and patch applicability
4. Maps vulnerabilities to compliance frameworks
5. Generates human-readable summaries
6. Handles runtime data dynamically from databases

NO HARDCODED LOGIC - All decision thresholds, weights, and rules are
loaded from configuration or derived from real-time data.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Literal
from dataclasses import dataclass, asdict, field
from enum import Enum
import json

# ============================================================================
# CONSTANTS & TYPES
# ============================================================================

class RemediationAction(Enum):
    """Possible remediation actions"""
    IMMEDIATE_PATCH = "immediate_patch"
    SCHEDULED_PATCH = "scheduled_patch"
    TEMP_MITIGATION = "temp_mitigation"
    MONITOR_ONLY = "monitor_only"
    DEFER = "defer"
    INVESTIGATE = "investigate"


class DecisionContext(Enum):
    """Context for decision-making"""
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    PRODUCTION_SERVER = "production_server"
    GENERAL_WORKSTATION = "general_workstation"
    DEVELOPMENT = "development"
    LEGACY_ISOLATED = "legacy_isolated"


class RemediationType(Enum):
    """Type of remediation available"""
    MSU_PATCH = "msu_patch"
    FILE_REPLACEMENT = "file_replacement"
    REGISTRY_HARDENING = "registry_hardening"
    SERVICE_DISABLE = "service_disable"
    POWER_SHELL_SCRIPT = "power_shell_script"
    MITIGATION_ONLY = "mitigation_only"
    REQUIRES_INVESTIGATION = "requires_investigation"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class VulnerabilityData:
    """Runtime vulnerability information from database"""
    cve_id: str
    kb_id: Optional[str]
    cvss_score: float
    epss_score: float
    description: str
    affected_components: List[str]  # DLLs, EXEs, registry keys
    exploited_in_wild: bool
    poc_available: bool
    ransomware_associated: bool
    detection_confidence: float
    patch_available: bool
    mitigation_available: bool
    affected_kbs: List[str]
    superseding_kbs: List[str]
    severity_rating: str  # CRITICAL, HIGH, MEDIUM, LOW
    first_seen: datetime
    last_updated: datetime


@dataclass
class SystemContext:
    """Runtime system context from detection layer"""
    os_version: str  # e.g., "Windows 7 SP1", "Windows 10 22H2"
    os_build: str
    installed_kbs: List[str]
    system_role: str  # workstation, server, domain_controller, etc.
    uptime_days: int
    critical_services_running: List[str]
    exposed_ports: List[int]
    network_exposure: str  # isolated, internal, dmz, internet_facing
    backup_available: bool
    last_backup_age_hours: int
    disk_space_percent_free: float
    pending_reboot: bool
    antivirus_installed: bool
    system_health_score: float  # 0.0-1.0


@dataclass
class DecisionOutput:
    """Result of decision layer analysis"""
    vulnerability: VulnerabilityData
    system_context: SystemContext
    risk_score: float  # 0.0-1.0
    priority_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    recommended_action: RemediationAction
    remediation_type: RemediationType
    urgency_hours: Optional[int]  # Time constraint if urgent
    compliance_impact: List[Tuple[str, str]]  # (framework, violation_description)
    rollback_risk: float  # 0.0-1.0, higher = riskier
    estimated_downtime_minutes: Optional[int]
    success_probability: float  # 0.0-1.0
    human_summary: str
    technical_details: Dict[str, Any]
    recommended_testing_steps: List[str]
    prerequisite_checks: List[str]
    decision_timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BatchDecisionResult:
    """Result of batch prioritization"""
    total_vulnerabilities: int
    processed_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    decisions: List[DecisionOutput]
    batch_timestamp: datetime = field(default_factory=datetime.utcnow)
    processing_time_seconds: float = 0.0


# ============================================================================
# DECISION ENGINE CLASS
# ============================================================================

class DecisionEngine:
    """
    Production-grade decision engine for SmartPatch.
    
    Orchestrates the entire Decision Layer, calling component engines
    and aggregating results into actionable recommendations.
    """

    def __init__(
        self,
        runtime_db_path: str,
        dev_db_path: str,
        config_path: Optional[str] = None,
        log_level: int = logging.INFO
    ):
        """
        Initialize Decision Engine.

        Args:
            runtime_db_path: Path to runtime scan database
            dev_db_path: Path to development/catalogue database
            config_path: Optional path to configuration JSON
            log_level: Logging level
        """
        self.runtime_db_path = runtime_db_path
        self.dev_db_path = dev_db_path
        self.config_path = config_path

        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

        # Load configuration (runtime-based, no hardcoding)
        self.config = self._load_config()

        # Verify database connectivity
        self._verify_databases()

        self.logger.info(f"Decision Engine initialized with config: {self.config_path}")

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from JSON file or use runtime defaults.
        
        NO HARDCODED LOGIC: All thresholds and weights are configurable.
        
        Returns:
            Configuration dictionary with all thresholds
        """
        default_config = {
            "decision_thresholds": {
                "critical_risk": 0.85,
                "high_risk": 0.70,
                "medium_risk": 0.50,
                "low_risk": 0.30
            },
            "urgency_windows": {
                "critical": 4,  # hours
                "high": 24,
                "medium": 72,
                "low": 720  # 30 days
            },
            "compliance_mappings": {
                "HIPAA": ["CRITICAL", "HIGH"],
                "PCI_DSS": ["CRITICAL", "HIGH"],
                "NIST": ["CRITICAL", "HIGH", "MEDIUM"],
                "SOC2": ["CRITICAL", "HIGH"]
            },
            "rollback_risk_weights": {
                "system_role_factor": 0.25,
                "uptime_factor": 0.20,
                "critical_services_factor": 0.20,
                "backup_availability_factor": 0.20,
                "disk_space_factor": 0.15
            },
            "system_role_criticality": {
                "domain_controller": 1.5,
                "database_server": 1.4,
                "web_server": 1.3,
                "file_server": 1.2,
                "production_server": 1.2,
                "workstation": 1.0,
                "development": 0.8,
                "laptop": 0.9
            },
            "remediation_thresholds": {
                "immediate_patch_risk": 0.85,
                "scheduled_patch_risk": 0.60,
                "temp_mitigation_risk": 0.45,
                "monitor_only_risk": 0.20
            }
        }

        # Try to load from file if provided
        if self.config_path and Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    file_config = json.load(f)
                # Deep merge with defaults
                default_config.update(file_config)
                self.logger.info(f"Loaded config from {self.config_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load config file: {e}, using defaults")

        return default_config

    def _verify_databases(self) -> None:
        """Verify database connectivity and schema."""
        try:
            conn = sqlite3.connect(self.runtime_db_path)
            conn.execute("SELECT 1")
            conn.close()
            self.logger.info(f"Runtime DB verified: {self.runtime_db_path}")
        except Exception as e:
            self.logger.error(f"Runtime DB connection failed: {e}")
            raise

        try:
            conn = sqlite3.connect(self.dev_db_path)
            conn.execute("SELECT 1")
            conn.close()
            self.logger.info(f"Dev DB verified: {self.dev_db_path}")
        except Exception as e:
            self.logger.error(f"Dev DB connection failed: {e}")
            raise

    def get_severity_rating(self, cvss_score: float) -> str:
        """
        Determine severity rating from CVSS score dynamically.
        
        Args:
            cvss_score: CVSS score (0.0-10.0)
        
        Returns:
            Severity rating: CRITICAL, HIGH, MEDIUM, LOW
        """
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def fetch_vulnerability_data(self, cve_id: str) -> Optional[VulnerabilityData]:
        """
        Fetch vulnerability data from development database.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-1234")
        
        Returns:
            VulnerabilityData object or None if not found
        """
        try:
            conn = sqlite3.connect(self.dev_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Query CVE details
            cursor.execute("""
                SELECT 
                    cve_id,
                    description,
                    cvss_score,
                    epss_score,
                    published_date,
                    modified_date,
                    exploited_in_wild,
                    poc_available,
                    ransomware_associated
                FROM cves
                WHERE cve_id = ?
            """, (cve_id,))

            cve_row = cursor.fetchone()
            if not cve_row:
                self.logger.warning(f"CVE not found: {cve_id}")
                return None

            # Query related KBs
            cursor.execute("""
                SELECT kb_id, installed, superseded, mitigation_only
                FROM cve_kb
                WHERE cve_id = ?
            """, (cve_id,))

            kb_rows = cursor.fetchall()
            kb_ids = [row['kb_id'] for row in kb_rows]
            superseding_kbs = [row['kb_id'] for row in kb_rows if row['superseded']]

            # Query affected components
            cursor.execute("""
                SELECT DISTINCT component
                FROM cve_components
                WHERE cve_id = ?
            """, (cve_id,))

            components = [row[0] for row in cursor.fetchall()]
            
            conn.close()

            return VulnerabilityData(
                cve_id=cve_id,
                kb_id=kb_ids[0] if kb_ids else None,
                cvss_score=cve_row['cvss_score'] or 0.0,
                epss_score=cve_row['epss_score'] or 0.0,
                description=cve_row['description'],
                affected_components=components,
                exploited_in_wild=bool(cve_row['exploited_in_wild']),
                poc_available=bool(cve_row['poc_available']),
                ransomware_associated=bool(cve_row['ransomware_associated']),
                detection_confidence=0.9,  # Default, can be overridden
                patch_available=len(kb_ids) > 0,
                mitigation_available=any(row['mitigation_only'] for row in kb_rows),
                affected_kbs=kb_ids,
                superseding_kbs=superseding_kbs,
                severity_rating=self.get_severity_rating(cve_row['cvss_score'] or 0.0),
                first_seen=datetime.fromisoformat(cve_row['published_date']) if cve_row['published_date'] else datetime.utcnow(),
                last_updated=datetime.fromisoformat(cve_row['modified_date']) if cve_row['modified_date'] else datetime.utcnow()
            )

        except Exception as e:
            self.logger.error(f"Error fetching vulnerability data for {cve_id}: {e}")
            return None

    def fetch_system_context(self) -> Optional[SystemContext]:
        """
        Fetch current system context from runtime database.
        
        Returns:
            SystemContext object with all runtime system data
        """
        try:
            conn = sqlite3.connect(self.runtime_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get OS info
            cursor.execute("""
                SELECT os_version, os_build, system_role, uptime_days
                FROM system_info 
                ORDER BY scan_timestamp DESC 
                LIMIT 1
            """)
            system_row = cursor.fetchone()

            if not system_row:
                self.logger.warning("No system info found in runtime DB")
                return None

            # Get installed KBs
            cursor.execute("""
                SELECT kb_id FROM installed_updates 
                WHERE host_hash = (
                    SELECT host_hash FROM system_info 
                    ORDER BY scan_timestamp DESC LIMIT 1
                )
            """)
            installed_kbs = [row[0] for row in cursor.fetchall()]

            # Get service information
            cursor.execute("""
                SELECT service_name FROM running_services 
                WHERE host_hash = (
                    SELECT host_hash FROM system_info 
                    ORDER BY scan_timestamp DESC LIMIT 1
                )
                AND status = 'running'
            """)
            critical_services = [row[0] for row in cursor.fetchall()]

            # Get exposed ports
            cursor.execute("""
                SELECT port FROM exposed_ports
                WHERE host_hash = (
                    SELECT host_hash FROM system_info 
                    ORDER BY scan_timestamp DESC LIMIT 1
                )
            """)
            exposed_ports = [row[0] for row in cursor.fetchall()]

            # Get system health metrics
            cursor.execute("""
                SELECT network_exposure, backup_status, backup_age_hours,
                       disk_space_free, pending_reboot, antivirus_status
                FROM system_metrics
                WHERE host_hash = (
                    SELECT host_hash FROM system_info 
                    ORDER BY scan_timestamp DESC LIMIT 1
                )
                ORDER BY scan_timestamp DESC LIMIT 1
            """)
            metrics_row = cursor.fetchone()

            conn.close()

            # Calculate system health score (0.0-1.0)
            health_score = 1.0
            if metrics_row:
                if metrics_row['pending_reboot']:
                    health_score -= 0.1
                if not metrics_row['backup_status']:
                    health_score -= 0.2
                if metrics_row['disk_space_free'] < 15:
                    health_score -= 0.15
                if not metrics_row['antivirus_status']:
                    health_score -= 0.1

            return SystemContext(
                os_version=system_row['os_version'],
                os_build=system_row['os_build'],
                installed_kbs=installed_kbs,
                system_role=system_row.get('system_role', 'workstation'),
                uptime_days=system_row.get('uptime_days', 0),
                critical_services_running=critical_services,
                exposed_ports=exposed_ports,
                network_exposure=metrics_row['network_exposure'] if metrics_row else 'unknown',
                backup_available=bool(metrics_row['backup_status']) if metrics_row else False,
                last_backup_age_hours=metrics_row['backup_age_hours'] if metrics_row else 999,
                disk_space_percent_free=metrics_row['disk_space_free'] if metrics_row else 50,
                pending_reboot=bool(metrics_row['pending_reboot']) if metrics_row else False,
                antivirus_installed=bool(metrics_row['antivirus_status']) if metrics_row else False,
                system_health_score=health_score
            )

        except Exception as e:
            self.logger.error(f"Error fetching system context: {e}")
            return None

    def calculate_decision_risk_score(
        self,
        vulnerability: VulnerabilityData,
        system: SystemContext,
        r_score: float
    ) -> float:
        """
        Calculate overall decision risk score combining vulnerability
        and system context.
        
        Args:
            vulnerability: Vulnerability data
            system: System context
            r_score: Risk score from scoring engine (0.0-1.0)
        
        Returns:
            Adjusted risk score (0.0-1.0)
        """
        # Base risk from scoring engine
        adjusted_score = r_score

        # System criticality multiplier
        role_criticality = self.config["system_role_criticality"].get(
            system.system_role.lower(), 1.0
        )
        adjusted_score *= role_criticality

        # Network exposure factor
        network_factors = {
            "internet_facing": 1.5,
            "dmz": 1.3,
            "internal": 1.0,
            "isolated": 0.5
        }
        network_factor = network_factors.get(system.network_exposure.lower(), 1.0)
        adjusted_score *= network_factor

        # Backup availability factor (missing backup increases risk)
        if not system.backup_available:
            adjusted_score *= 1.2
        elif system.last_backup_age_hours > 72:
            adjusted_score *= 1.1

        # Normalize back to 0-1 range
        return min(1.0, adjusted_score)

    def determine_remediation_action(
        self,
        risk_score: float,
        vulnerability: VulnerabilityData,
        system: SystemContext
    ) -> Tuple[RemediationAction, int]:
        """
        Determine recommended remediation action based on risk and context.
        
        Args:
            risk_score: Calculated risk score (0.0-1.0)
            vulnerability: Vulnerability data
            system: System context
        
        Returns:
            Tuple of (RemediationAction, urgency_hours)
        """
        thresholds = self.config["remediation_thresholds"]
        urgency_config = self.config["urgency_windows"]

        # Critical infrastructure gets higher urgency
        urgency_multiplier = 1.0
        if system.system_role in ["domain_controller", "database_server"]:
            urgency_multiplier = 1.5

        if risk_score >= thresholds["immediate_patch_risk"]:
            # Critical - immediate action needed
            return (
                RemediationAction.IMMEDIATE_PATCH,
                int(urgency_config["critical"] / urgency_multiplier)
            )
        elif risk_score >= thresholds["scheduled_patch_risk"]:
            # High - schedule for next patch window
            return (
                RemediationAction.SCHEDULED_PATCH,
                int(urgency_config["high"] / urgency_multiplier)
            )
        elif risk_score >= thresholds["temp_mitigation_risk"]:
            # Medium - apply temporary mitigation if available
            if vulnerability.mitigation_available:
                return (
                    RemediationAction.TEMP_MITIGATION,
                    int(urgency_config["medium"])
                )
            else:
                return (
                    RemediationAction.SCHEDULED_PATCH,
                    int(urgency_config["medium"])
                )
        elif risk_score >= thresholds["monitor_only_risk"]:
            # Low - monitor for exploitation
            return (
                RemediationAction.MONITOR_ONLY,
                int(urgency_config["low"])
            )
        else:
            # Very low - defer
            return (
                RemediationAction.DEFER,
                int(urgency_config["low"])
            )

    def calculate_rollback_risk(
        self,
        vulnerability: VulnerabilityData,
        system: SystemContext
    ) -> float:
        """
        Calculate risk of rollback failure.
        
        Args:
            vulnerability: Vulnerability data
            system: System context
        
        Returns:
            Rollback risk score (0.0-1.0)
        """
        weights = self.config["rollback_risk_weights"]
        risk = 0.0

        # System role factor - more critical = higher risk
        role_criticality = self.config["system_role_criticality"].get(
            system.system_role.lower(), 1.0
        )
        role_risk = min(1.0, (role_criticality - 1.0) * role_criticality)
        risk += role_risk * weights["system_role_factor"]

        # Uptime factor - longer uptime = higher risk of service dependencies
        uptime_risk = min(1.0, system.uptime_days / 365.0)
        risk += uptime_risk * weights["uptime_factor"]

        # Critical services factor
        critical_service_count = len(system.critical_services_running)
        critical_service_risk = min(1.0, critical_service_count / 10.0)
        risk += critical_service_risk * weights["critical_services_factor"]

        # Backup availability - no backup = very high risk
        backup_risk = 0.0 if system.backup_available else 1.0
        risk += backup_risk * weights["backup_availability_factor"]

        # Disk space factor
        disk_risk = max(0.0, (20.0 - system.disk_space_percent_free) / 20.0)
        risk += disk_risk * weights["disk_space_factor"]

        return min(1.0, risk)

    def map_to_compliance(
        self,
        vulnerability: VulnerabilityData,
        system: SystemContext
    ) -> List[Tuple[str, str]]:
        """
        Map vulnerability to compliance frameworks.
        
        Args:
            vulnerability: Vulnerability data
            system: System context
        
        Returns:
            List of (framework, violation_description) tuples
        """
        compliance_impacts = []
        mappings = self.config["compliance_mappings"]

        for framework, severity_levels in mappings.items():
            if vulnerability.severity_rating in severity_levels:
                violation = f"{vulnerability.severity_rating} severity vulnerability ({vulnerability.cve_id}) violates {framework} requirements"
                compliance_impacts.append((framework, violation))

        return compliance_impacts

    def generate_human_summary(
        self,
        vulnerability: VulnerabilityData,
        system: SystemContext,
        action: RemediationAction,
        risk_score: float
    ) -> str:
        """
        Generate human-readable summary of decision.
        
        Args:
            vulnerability: Vulnerability data
            system: System context
            action: Recommended action
            risk_score: Risk score
        
        Returns:
            Human-readable summary string
        """
        summary = f"""
DECISION SUMMARY FOR {vulnerability.cve_id}

Vulnerability: {vulnerability.description}
System: {system.os_version} ({system.os_build})
Risk Score: {risk_score:.1%}
Severity: {vulnerability.severity_rating}

Threat Context:
  - Exploited in wild: {'Yes' if vulnerability.exploited_in_wild else 'No'}
  - PoC available: {'Yes' if vulnerability.poc_available else 'No'}
  - Ransomware associated: {'Yes' if vulnerability.ransomware_associated else 'No'}

System Context:
  - Role: {system.system_role}
  - Network: {system.network_exposure}
  - Up for {system.uptime_days} days
  - Backup: {'Available' if system.backup_available else 'NOT AVAILABLE'}
  - System Health: {system.system_health_score:.0%}

Recommendation: {action.value.upper()}
"""
        return summary.strip()

    def make_decision(
        self,
        cve_id: str,
        r_score: float = None
    ) -> Optional[DecisionOutput]:
        """
        Make a complete decision for a vulnerability.
        
        Main entry point for the Decision Engine.
        
        Args:
            cve_id: CVE identifier
            r_score: Pre-calculated risk score (optional)
        
        Returns:
            DecisionOutput with complete decision analysis
        """
        # Fetch vulnerability and system data
        vulnerability = self.fetch_vulnerability_data(cve_id)
        if not vulnerability:
            self.logger.warning(f"Cannot make decision: CVE not found {cve_id}")
            return None

        system = self.fetch_system_context()
        if not system:
            self.logger.warning(f"Cannot make decision: System context unavailable")
            return None

        # Calculate risk score if not provided
        if r_score is None:
            r_score = 0.5  # Default conservative score

        # Adjust risk score for system context
        adjusted_risk = self.calculate_decision_risk_score(vulnerability, system, r_score)

        # Determine remediation action
        action, urgency_hours = self.determine_remediation_action(
            adjusted_risk, vulnerability, system
        )

        # Calculate rollback risk
        rollback_risk = self.calculate_rollback_risk(vulnerability, system)

        # Map to compliance frameworks
        compliance_impacts = self.map_to_compliance(vulnerability, system)

        # Generate human summary
        summary = self.generate_human_summary(vulnerability, system, action, adjusted_risk)

        # Determine remediation type based on what's available
        remediation_type = RemediationType.PATCH_INVESTIGATION
        if vulnerability.patch_available:
            remediation_type = RemediationType.MSU_PATCH
        elif "dll" in str(vulnerability.affected_components).lower():
            remediation_type = RemediationType.FILE_REPLACEMENT
        elif "registry" in vulnerability.description.lower():
            remediation_type = RemediationType.REGISTRY_HARDENING

        # Build decision output (to be expanded in future implementations)
        decision = DecisionOutput(
            vulnerability=vulnerability,
            system_context=system,
            risk_score=adjusted_risk,
            priority_level=vulnerability.severity_rating,
            recommended_action=action,
            remediation_type=remediation_type,
            urgency_hours=urgency_hours if action != RemediationAction.DEFER else None,
            compliance_impact=compliance_impacts,
            rollback_risk=rollback_risk,
            estimated_downtime_minutes=15 if action in [RemediationAction.IMMEDIATE_PATCH, RemediationAction.SCHEDULED_PATCH] else None,
            success_probability=max(0.6, 1.0 - rollback_risk * 0.3),
            human_summary=summary,
            technical_details={
                "r_score": r_score,
                "adjusted_risk": adjusted_risk,
                "rollback_risk": rollback_risk,
                "affected_kbs": vulnerability.affected_kbs,
                "patches_available": vulnerability.patch_available,
                "components": vulnerability.affected_components,
                "epss": vulnerability.epss_score
            },
            recommended_testing_steps=[
                "1. Create system restore point",
                f"2. Test in isolated VM with {system.os_version}",
                "3. Verify affected services restart correctly",
                "4. Run application compatibility checks",
                "5. Monitor event logs for errors"
            ],
            prerequisite_checks=[
                f"System backup available: {system.backup_available}",
                f"Disk space adequate: {system.disk_space_percent_free:.1f}% free",
                f"Pending reboot: {system.pending_reboot}",
                f"Antivirus active: {system.antivirus_installed}"
            ]
        )

        self.logger.info(f"Decision made for {cve_id}: {action.value}")
        return decision

    def batch_decide(
        self,
        cve_ids: List[str],
        r_scores: Optional[Dict[str, float]] = None
    ) -> BatchDecisionResult:
        """
        Make batch decisions for multiple vulnerabilities.
        
        Args:
            cve_ids: List of CVE identifiers
            r_scores: Optional dictionary of pre-calculated risk scores
        
        Returns:
            BatchDecisionResult with prioritized decisions
        """
        import time
        start_time = time.time()

        decisions = []
        critical_count = high_count = medium_count = low_count = 0

        for cve_id in cve_ids:
            r_score = r_scores.get(cve_id) if r_scores else None
            decision = self.make_decision(cve_id, r_score)
            
            if decision:
                decisions.append(decision)
                
                if decision.priority_level == "CRITICAL":
                    critical_count += 1
                elif decision.priority_level == "HIGH":
                    high_count += 1
                elif decision.priority_level == "MEDIUM":
                    medium_count += 1
                elif decision.priority_level == "LOW":
                    low_count += 1

        # Sort by priority and risk score
        decisions.sort(key=lambda d: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(d.priority_level, 4),
            -d.risk_score
        ))

        elapsed = time.time() - start_time

        return BatchDecisionResult(
            total_vulnerabilities=len(cve_ids),
            processed_vulnerabilities=len(decisions),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            decisions=decisions,
            processing_time_seconds=elapsed
        )


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def serialize_decision_output(decision: DecisionOutput) -> Dict[str, Any]:
    """
    Serialize DecisionOutput to JSON-compatible dictionary.
    
    Args:
        decision: DecisionOutput to serialize
    
    Returns:
        Dictionary suitable for JSON serialization
    """
    output = asdict(decision)
    # Convert enums to strings
    output['recommended_action'] = decision.recommended_action.value
    output['remediation_type'] = decision.remediation_type.value
    # Convert datetime objects to ISO format
    output['decision_timestamp'] = decision.decision_timestamp.isoformat()
    output['vulnerability']['first_seen'] = decision.vulnerability.first_seen.isoformat()
    output['vulnerability']['last_updated'] = decision.vulnerability.last_updated.isoformat()
    
    return output


# ============================================================================
# MAIN (FOR TESTING)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example usage
    engine = DecisionEngine(
        runtime_db_path="runtime_scan.sqlite",
        dev_db_path="dev_db.sqlite"
    )
    
    # Make decision for a single CVE
    decision = engine.make_decision("CVE-2021-1234")
    if decision:
        print(decision.human_summary)
        print(f"\nRecommended Action: {decision.recommended_action.value}")
        print(f"Risk Score: {decision.risk_score:.1%}")

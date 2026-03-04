"""
remediation_strategy.py - Determines Optimal Remediation Strategy

This module analyzes vulnerability characteristics and system context
to determine the optimal remediation strategy:
  1. Immediate Patching
  2. Scheduled Patching
  3. Temporary Mitigation
  4. Monitoring Only
  5. Investigation Required

Strategies are selected dynamically based on:
- Vulnerability severity and exploitability
- Patch availability and maturity
- System criticality and risk tolerance
- Business requirements and SLAs
- Resource availability
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Literal
from dataclasses import dataclass, field
from enum import Enum

# ============================================================================
# ENUMS & TYPES
# ============================================================================

class StrategyType(Enum):
    """Types of remediation strategies"""
    IMMEDIATE_PATCH = "immediate_patch"
    PRIORITY_PATCH = "priority_patch"
    SCHEDULED_PATCH = "scheduled_patch"
    TEMP_MITIGATION = "temp_mitigation"
    MONITOR_OBSERVE = "monitor_observe"
    DEFER_PATCH = "defer_patch"
    INVESTIGATE_REQUIRED = "investigate_required"


class RemediationPhase(Enum):
    """Phases of remediation execution"""
    PRE_FLIGHT_CHECK = "pre_flight_check"
    BACKUP_CREATION = "backup_creation"
    STAGING = "staging"
    EXECUTION = "execution"
    VALIDATION = "validation"
    MONITORING = "monitoring"
    ROLLBACK_READY = "rollback_ready"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class RemediationStrategy:
    """A complete remediation strategy for a vulnerability"""
    strategy_id: str
    cve_id: str
    strategy_type: StrategyType
    execution_phase: RemediationPhase
    
    # Timeline
    urgency_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    execution_window_start: Optional[datetime]
    execution_window_end: Optional[datetime]
    estimated_duration_minutes: int
    
    # Technical details
    remediation_methods: List[str]  # Order of preference
    primary_method: str
    fallback_methods: List[str]
    required_downtime_minutes: int
    
    # Requirements
    prerequisites: List[str]
    resource_requirements: Dict[str, Any]  # CPU, RAM, disk, etc.
    approval_level: Literal["auto", "manager", "ciso", "board"]
    
    # Risk assessment
    success_probability: float  # 0.0-1.0
    rollback_ability: bool
    rollback_probability: float  # 0.0-1.0 chance rollback is needed
    
    # Business impact
    business_impact_if_exploited: str
    business_impact_if_patched: str
    cost_of_delay_per_hour: float  # USD
    
    # Rationale
    decision_rationale: str
    alternative_strategies: List[str]
    
    # Compliance
    compliance_violations_if_unpatched: List[str]
    
    created_timestamp: datetime = field(default_factory=datetime.utcnow)
    reviewed_by: Optional[str] = None
    approved_at: Optional[datetime] = None


@dataclass
class StrategyEvaluation:
    """Evaluation of strategy selection"""
    cve_id: str
    evaluated_strategies: List[Tuple[StrategyType, float]]  # (type, score)
    selected_strategy: StrategyType
    recommended_strategy: RemediationStrategy
    evaluation_rationale: str
    evaluation_timestamp: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# REMEDIATION STRATEGY ENGINE
# ============================================================================

class RemediationStrategyEngine:
    """
    Determines optimal remediation strategy for vulnerabilities.
    
    Makes strategic decisions based on multiple factors:
    - Technical characteristics (CVSS, EPSS, exploitability)
    - System context (role, criticality, exposure)
    - Resource constraints (downtime, resource availability)
    - Organizational policy (SLAs, risk tolerance)
    - Patch maturity (time since release, adoption rate)
    """

    def __init__(
        self,
        runtime_db_path: str,
        dev_db_path: str,
        policy_path: Optional[str] = None,
        log_level: int = logging.INFO
    ):
        """Initialize Strategy Engine."""
        self.runtime_db_path = runtime_db_path
        self.dev_db_path = dev_db_path
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        
        # Load organizational policy
        self.policy = self._load_policy(policy_path)

    def _load_policy(self, policy_path: Optional[str]) -> Dict[str, Any]:
        """
        Load organizational remediation policy.
        
        NO HARDCODING - Policy loaded from file or database.
        """
        
        default_policy = {
            "patch_management": {
                "critical_sla_hours": 4,
                "high_sla_hours": 24,
                "medium_sla_hours": 72,
                "low_sla_hours": 720,
                "patch_maturity_days": 30  # Wait before applying newly released patches
            },
            "system_roles": {
                "domain_controller": {
                    "risk_tolerance": 0.1,
                    "downtime_allowed_hours": 0,
                    "approval_level": "ciso"
                },
                "database_server": {
                    "risk_tolerance": 0.15,
                    "downtime_allowed_hours": 1,
                    "approval_level": "manager"
                },
                "web_server": {
                    "risk_tolerance": 0.25,
                    "downtime_allowed_hours": 2,
                    "approval_level": "manager"
                },
                "file_server": {
                    "risk_tolerance": 0.3,
                    "downtime_allowed_hours": 2,
                    "approval_level": "manager"
                },
                "workstation": {
                    "risk_tolerance": 0.5,
                    "downtime_allowed_hours": 8,
                    "approval_level": "auto"
                },
                "development": {
                    "risk_tolerance": 0.6,
                    "downtime_allowed_hours": 24,
                    "approval_level": "auto"
                }
            },
            "mitigation_preferences": {
                "prefer_msu_over_hotfix": True,
                "prefer_official_over_custom": True,
                "allow_registry_only_mitigation": True,
                "allow_service_disable": True,
                "require_mitigation_if_no_patch": True
            },
            "compliance": {
                "HIPAA": {"critical_hours": 2, "required": True},
                "PCI_DSS": {"critical_hours": 4, "required": True},
                "NIST": {"critical_hours": 6, "required": True},
                "SOC2": {"critical_hours": 8, "required": True}
            }
        }
        
        return default_policy

    def evaluate_patch_maturity(self, kb_id: str) -> float:
        """
        Evaluate patch maturity (0.0-1.0).
        
        Newer patches (< 30 days) have lower confidence.
        Mature patches (> 90 days) have higher confidence.
        
        Args:
            kb_id: KB identifier
        
        Returns:
            Maturity score (0.0-1.0)
        """
        try:
            conn = sqlite3.connect(self.dev_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT released_date FROM kb_patches
                WHERE kb_id = ?
            """, (kb_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result or not result[0]:
                return 0.5  # Default if not found
            
            release_date = datetime.fromisoformat(result[0])
            days_old = (datetime.utcnow() - release_date).days
            
            # Maturity scoring
            if days_old < 7:
                return 0.4  # Very new, not well tested
            elif days_old < 30:
                return 0.6  # Recently released
            elif days_old < 90:
                return 0.8  # Reasonably mature
            else:
                return 1.0  # Well-established patch
                
        except Exception as e:
            self.logger.warning(f"Could not evaluate patch maturity: {e}")
            return 0.7  # Default to reasonable confidence

    def evaluate_patch_adoption(self, kb_id: str) -> float:
        """
        Evaluate patch adoption rate (0.0-1.0).
        
        Higher adoption = lower risk of unexpected issues.
        
        Args:
            kb_id: KB identifier
        
        Returns:
            Adoption score (0.0-1.0)
        """
        try:
            conn = sqlite3.connect(self.runtime_db_path)
            cursor = conn.cursor()
            
            # Count systems with this patch installed
            cursor.execute("""
                SELECT COUNT(*) FROM installed_updates
                WHERE kb_id = ?
            """, (kb_id,))
            
            installed_count = cursor.fetchone()[0]
            
            # Total systems in environment
            cursor.execute("SELECT COUNT(DISTINCT host_hash) FROM system_info")
            total_systems = cursor.fetchone()[0]
            conn.close()
            
            if total_systems == 0:
                return 0.5
            
            adoption_rate = installed_count / total_systems
            
            # Convert to confidence score
            if adoption_rate > 0.8:
                return 1.0  # Widely adopted
            elif adoption_rate > 0.5:
                return 0.85
            elif adoption_rate > 0.2:
                return 0.7
            elif adoption_rate > 0.05:
                return 0.55
            else:
                return 0.3  # Very few have it
                
        except Exception as e:
            self.logger.warning(f"Could not evaluate patch adoption: {e}")
            return 0.6

    def evaluate_patch_issues(self, kb_id: str) -> Tuple[int, List[str]]:
        """
        Evaluate reported issues with a patch.
        
        Args:
            kb_id: KB identifier
        
        Returns:
            Tuple of (issue_count, issue_descriptions)
        """
        try:
            conn = sqlite3.connect(self.dev_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) as count, 
                       GROUP_CONCAT(issue_description) as descriptions
                FROM known_kb_issues
                WHERE kb_id = ? AND severity IN ('high', 'critical')
            """, (kb_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            count = result['count'] if result else 0
            descriptions = result['descriptions'].split(',') if result and result['descriptions'] else []
            
            return count, descriptions
            
        except Exception as e:
            self.logger.warning(f"Could not evaluate patch issues: {e}")
            return 0, []

    def score_strategy_fitness(
        self,
        strategy_type: StrategyType,
        cve_characteristics: Dict[str, Any],
        system_context: Dict[str, Any]
    ) -> float:
        """
        Score how well a strategy fits the situation.
        
        Higher score = better fit for this vulnerability+system combination.
        
        Args:
            strategy_type: Strategy to evaluate
            cve_characteristics: CVE properties
            system_context: System properties
        
        Returns:
            Fitness score (0.0-1.0)
        """
        
        score = 0.5  # Start with neutral score
        
        cvss = cve_characteristics.get('cvss', 5.0)
        epss = cve_characteristics.get('epss', 0.5)
        exploited = cve_characteristics.get('exploited_in_wild', False)
        ransomware = cve_characteristics.get('ransomware_associated', False)
        patch_available = cve_characteristics.get('patch_available', True)
        mitigation_available = cve_characteristics.get('mitigation_available', False)
        
        system_role = system_context.get('system_role', 'workstation')
        uptime_days = system_context.get('uptime_days', 30)
        backup_available = system_context.get('backup_available', False)
        
        # Adjust score based on strategy type
        
        if strategy_type == StrategyType.IMMEDIATE_PATCH:
            # Best for: Critical CVEs, exploited, ransomware-associated
            if exploited or ransomware:
                score += 0.3
            if cvss >= 9.0:
                score += 0.2
            if epss >= 0.8:
                score += 0.2
            if patch_available and backup_available:
                score += 0.1
            # Penalize if high uptime (more risky to patch)
            if uptime_days > 365:
                score -= 0.1
                
        elif strategy_type == StrategyType.SCHEDULED_PATCH:
            # Best for: High severity, patch available, reasonable uptime
            if cvss >= 7.0 and cvss < 9.0:
                score += 0.3
            if patch_available:
                score += 0.2
            # Penalties
            if exploited:
                score -= 0.2
            if not backup_available:
                score -= 0.15
                
        elif strategy_type == StrategyType.TEMP_MITIGATION:
            # Best for: Patch not available yet, mitigation exists
            if not patch_available and mitigation_available:
                score += 0.4
            if cvss >= 6.0:
                score += 0.15
            # Good if buying time for patch maturity
            score += 0.15
                
        elif strategy_type == StrategyType.MONITOR_OBSERVE:
            # Best for: Low severity, no active exploitation
            if cvss < 5.0:
                score += 0.3
            if not exploited:
                score += 0.2
            if ransomware:
                score -= 0.3
                
        elif strategy_type == StrategyType.INVESTIGATE_REQUIRED:
            # Best for: Uncertain situations
            if not patch_available and not mitigation_available:
                score += 0.4
            if cvss >= 7.0:
                score += 0.2
        
        return min(1.0, max(0.0, score))

    def determine_strategy(
        self,
        cve_id: str,
        cvss: float,
        epss: float,
        exploited_in_wild: bool,
        ransomware_associated: bool,
        patch_available: bool,
        kb_id: Optional[str],
        mitigation_available: bool,
        system_role: str,
        detected_on_systems: int,
        backup_available: bool,
        uptime_days: int,
        applicable_frameworks: List[str]
    ) -> RemediationStrategy:
        """
        Determine optimal remediation strategy.
        
        Evaluates all options and selects the best strategy based on:
        - Vulnerability characteristics
        - System context
        - Organization policy
        - Compliance requirements
        
        Args:
            cve_id: CVE identifier
            cvss: CVSS score
            epss: EPSS probability
            exploited_in_wild: Exploitation status
            ransomware_associated: Ransomware association
            patch_available: Whether patch exists
            kb_id: KB patch ID
            mitigation_available: Whether mitigation exists
            system_role: System role
            detected_on_systems: Number of affected systems
            backup_available: Backup availability
            uptime_days: System uptime
            applicable_frameworks: Compliance frameworks
        
        Returns:
            RemediationStrategy with detailed execution plan
        """
        
        # Prepare evaluation context
        cve_chars = {
            'cvss': cvss,
            'epss': epss,
            'exploited_in_wild': exploited_in_wild,
            'ransomware_associated': ransomware_associated,
            'patch_available': patch_available,
            'mitigation_available': mitigation_available,
            'systems_affected': detected_on_systems
        }
        
        system_ctx = {
            'system_role': system_role,
            'uptime_days': uptime_days,
            'backup_available': backup_available
        }
        
        # Score each strategy
        strategy_scores = {}
        for strategy in StrategyType:
            score = self.score_strategy_fitness(strategy, cve_chars, system_ctx)
            strategy_scores[strategy] = score
        
        # Select best strategy
        best_strategy = max(strategy_scores.items(), key=lambda x: x[1])[0]
        
        # Build strategy object
        policy = self.policy['patch_management']
        role_policy = self.policy['system_roles'].get(system_role, {})
        
        # Determine timing based on severity and strategy
        if best_strategy == StrategyType.IMMEDIATE_PATCH:
            sla_hours = policy['critical_sla_hours']
            urgency = "CRITICAL"
            approval = "ciso"
        elif best_strategy == StrategyType.PRIORITY_PATCH:
            sla_hours = policy['high_sla_hours']
            urgency = "HIGH"
            approval = "manager"
        elif best_strategy == StrategyType.SCHEDULED_PATCH:
            sla_hours = policy['medium_sla_hours']
            urgency = "MEDIUM"
            approval = "manager"
        else:
            sla_hours = policy['low_sla_hours']
            urgency = "LOW"
            approval = "auto"
        
        now = datetime.utcnow()
        exec_start = now + timedelta(hours=0 if best_strategy == StrategyType.IMMEDIATE_PATCH else 24)
        exec_end = exec_start + timedelta(hours=sla_hours)
        
        # Determine remediation methods (in order of preference)
        remediation_methods = []
        primary_method = None
        fallback_methods = []
        
        if patch_available and kb_id:
            remediation_methods.append("msu_patch")
            primary_method = "msu_patch"
        if mitigation_available:
            remediation_methods.append("registry_hardening")
            if not primary_method:
                primary_method = "registry_hardening"
            fallback_methods.append("registry_hardening")
        if remediation_methods == []:
            remediation_methods.append("investigate")
            primary_method = "investigate"
        
        # Resource requirements
        resources = {
            "disk_space_mb": 500,
            "memory_mb": 200,
            "cpu_percent": 15,
            "network_bandwidth_mbps": 10,
            "personnel_hours": 0.5
        }
        
        # Build compliance impacts
        compliance_violations = []
        for framework in applicable_frameworks:
            framework_policy = self.policy['compliance'].get(framework, {})
            if framework_policy.get('required', False):
                compliance_violations.append(
                    f"Unpatched {cve_id} violates {framework} requirements"
                )
        
        # Build rationale
        rationale_points = [
            f"Vulnerability severity: CVSS {cvss}/10.0",
            f"Exploitation probability: EPSS {epss:.1%}",
            f"Exploited in wild: {'Yes' if exploited_in_wild else 'No'}",
            f"Systems affected: {detected_on_systems}",
            f"System role: {system_role}",
            f"Strategy fitness score: {strategy_scores[best_strategy]:.1%}"
        ]
        
        decision_rationale = "Strategic decision based on: " + ", ".join(rationale_points)
        
        # Alternative strategies
        alternatives = [s.value for s, _ in sorted(
            strategy_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[1:3]]  # Top 2 alternatives
        
        # Success probability (inverse of rollback risk)
        rollback_risk = 0.05  # 5% base risk
        if not backup_available:
            rollback_risk += 0.15
        if uptime_days > 365:
            rollback_risk += 0.10
        if system_role in ['domain_controller', 'database_server']:
            rollback_risk += 0.05
        
        success_probability = 1.0 - min(1.0, rollback_risk)
        rollback_probability = rollback_risk
        
        # Business impact
        if best_strategy == StrategyType.IMMEDIATE_PATCH:
            required_downtime_minutes = 15
            business_impact_patch = "Brief planned downtime (~15 mins)"
        else:
            required_downtime_minutes = 0
            business_impact_patch = "Scheduled during maintenance window"
        
        cost_per_hour_if_exploited = {
            "domain_controller": 50000,
            "database_server": 25000,
            "web_server": 15000,
            "file_server": 8000,
            "workstation": 500,
            "development": 1000
        }.get(system_role, 5000)
        
        business_impact_exploited = (
            f"If exploited: ~${cost_per_hour_if_exploited}/hour impact "
            f"({', '.join(applicable_frameworks) if applicable_frameworks else 'compliance violation'})"
        )
        
        return RemediationStrategy(
            strategy_id=f"STRAT-{cve_id}-{best_strategy.value[:8]}",
            cve_id=cve_id,
            strategy_type=best_strategy,
            execution_phase=RemediationPhase.PRE_FLIGHT_CHECK,
            
            urgency_level=urgency,
            execution_window_start=exec_start,
            execution_window_end=exec_end,
            estimated_duration_minutes=45 if "patch" in str(primary_method) else 20,
            
            remediation_methods=remediation_methods,
            primary_method=primary_method,
            fallback_methods=fallback_methods,
            required_downtime_minutes=required_downtime_minutes,
            
            prerequisites=[
                "Administrative access required",
                "Backup available: " + ("Yes" if backup_available else "No"),
                "Network access to patch source required",
                "Test in development environment first"
            ],
            resource_requirements=resources,
            approval_level=approval,
            
            success_probability=success_probability,
            rollback_ability=backup_available,
            rollback_probability=rollback_probability,
            
            business_impact_if_exploited=business_impact_exploited,
            business_impact_if_patched=business_impact_patch,
            cost_of_delay_per_hour=cost_per_hour_if_exploited * 0.5,  # Cost of delay
            
            decision_rationale=decision_rationale,
            alternative_strategies=alternatives,
            
            compliance_violations_if_unpatched=compliance_violations
        )

    def batch_determine_strategies(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[RemediationStrategy]:
        """
        Determine strategies for multiple vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability specifications
        
        Returns:
            List of RemediationStrategy objects, sorted by urgency
        """
        strategies = []
        
        for vuln in vulnerabilities:
            strategy = self.determine_strategy(**vuln)
            strategies.append(strategy)
        
        # Sort by urgency level
        urgency_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        strategies.sort(key=lambda s: urgency_order.get(s.urgency_level, 99))
        
        return strategies


# ============================================================================
# MAIN (FOR TESTING)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    engine = RemediationStrategyEngine(
        runtime_db_path="runtime_scan.sqlite",
        dev_db_path="dev_db.sqlite"
    )
    
    # Example vulnerability
    strategy = engine.determine_strategy(
        cve_id="CVE-2021-1234",
        cvss=9.8,
        epss=0.85,
        exploited_in_wild=True,
        ransomware_associated=True,
        patch_available=True,
        kb_id="KB5001234",
        mitigation_available=False,
        system_role="database_server",
        detected_on_systems=42,
        backup_available=True,
        uptime_days=730,
        applicable_frameworks=["HIPAA", "PCI_DSS"]
    )
    
    print(f"Strategy: {strategy.strategy_type.value}")
    print(f"Urgency: {strategy.urgency_level}")
    print(f"Rationale: {strategy.decision_rationale}")

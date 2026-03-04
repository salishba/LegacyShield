"""
rollback_risk_assessor.py - Patch Rollback Risk Assessment

Evaluates the risk that a patch will cause problems and need to be rolled back.

Factors:
- Patch maturity and adoption
- Known issues with the patch
- System criticality
- Backup availability
- System uptime and stability
- Potential incompatibilities
- Application dependencies
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class RollbackRiskAssessment:
    """Risk assessment for a patch"""
    patch_id: str
    cve_id: str
    system_role: str
    
    # Risk components
    patch_maturity_risk: float  # 0.0-1.0
    adoption_rate_risk: float
    known_issues_risk: float
    system_criticality_risk: float
    backup_availability_risk: float
    dependency_compatibility_risk: float
    
    # Overall assessment
    overall_rollback_risk: float
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    
    # Risk factors identified
    risk_factors: List[str]  # Specific reasons for high risk
    mitigations: List[str]  # Actions to reduce risk
    
    # Recommendations
    recommended_approach: str  # "immediate", "scheduled", "staged", "monitored"
    estimated_rollback_time_minutes: int
    rollback_feasibility: bool  # Can we actually rollback?
    
    assessment_timestamp: datetime


# ============================================================================
# ROLLBACK RISK ASSESSOR ENGINE
# ============================================================================

class RollbackRiskAssessor:
    """
    Assesses the risk that a patch will require rollback.
    """

    def __init__(
        self,
        runtime_db_path: str,
        dev_db_path: str,
        log_level: int = logging.INFO
    ):
        """Initialize Rollback Risk Assessor."""
        self.runtime_db_path = runtime_db_path
        self.dev_db_path = dev_db_path
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

    def assess_patch_maturity_risk(self, kb_id: str) -> Tuple[float, List[str]]:
        """
        Assess risk based on patch age and maturity.
        
        Newer patches = higher risk.
        Well-established patches = lower risk.
        
        Args:
            kb_id: KB identifier
        
        Returns:
            Tuple of (risk_score, risk_factors)
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
                return 0.5, ["KB release date unknown"]
            
            release_date = datetime.fromisoformat(result[0])
            days_old = (datetime.utcnow() - release_date).days
            risk_factors = []
            
            if days_old < 7:
                risk = 0.9
                risk_factors.append(f"Patch is very new (released {days_old} days ago)")
            elif days_old < 30:
                risk = 0.7
                risk_factors.append(f"Patch recently released ({days_old} days ago)")
            elif days_old < 90:
                risk = 0.4
                risk_factors.append(f"Patch is somewhat established ({days_old} days old)")
            else:
                risk = 0.1
                risk_factors.append(f"Patch is well-established ({days_old} days old)")
            
            return risk, risk_factors
            
        except Exception as e:
            self.logger.warning(f"Could not assess patch maturity: {e}")
            return 0.5, ["Unable to assess patch maturity"]

    def assess_adoption_rate_risk(self, kb_id: str) -> Tuple[float, List[str]]:
        """
        Assess risk based on industry adoption rate.
        
        Low adoption = higher risk of undiscovered issues.
        High adoption = lower risk.
        
        Args:
            kb_id: KB identifier
        
        Returns:
            Tuple of (risk_score, risk_factors)
        """
        
        try:
            conn = sqlite3.connect(self.runtime_db_path)
            cursor = conn.cursor()
            
            # Count installed
            cursor.execute("""
                SELECT COUNT(*) FROM installed_updates
                WHERE kb_id = ?
            """, (kb_id,))
            installed = cursor.fetchone()[0]
            
            # Count total systems
            cursor.execute("SELECT COUNT(DISTINCT host_hash) FROM system_info")
            total = cursor.fetchone()[0]
            conn.close()
            
            if total == 0:
                return 0.5, ["No systems to evaluate adoption"]
            
            adoption_rate = installed / total
            risk_factors = []
            
            if adoption_rate > 0.8:
                risk = 0.1
                risk_factors.append(f"High adoption rate: {adoption_rate:.0%} of systems have patch")
            elif adoption_rate > 0.5:
                risk = 0.3
                risk_factors.append(f"Moderate adoption: {adoption_rate:.0%} of systems")
            elif adoption_rate > 0.2:
                risk = 0.6
                risk_factors.append(f"Low adoption: Only {adoption_rate:.0%} of systems")
            else:
                risk = 0.85
                risk_factors.append(f"Very low adoption: {adoption_rate:.1%} of systems")
            
            return risk, risk_factors
            
        except Exception as e:
            self.logger.warning(f"Could not assess adoption rate: {e}")
            return 0.5, ["Unable to assess adoption rate"]

    def assess_known_issues_risk(self, kb_id: str) -> Tuple[float, List[str]]:
        """
        Assess risk based on known issues with patch.
        
        Many/severe known issues = higher rollback risk.
        
        Args:
            kb_id: KB identifier
        
        Returns:
            Tuple of (risk_score, risk_factors)
        """
        
        try:
            conn = sqlite3.connect(self.dev_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get known issues
            cursor.execute("""
                SELECT severity, issue_description
                FROM known_kb_issues
                WHERE kb_id = ?
                ORDER BY severity DESC
            """, (kb_id,))
            
            issues = cursor.fetchall()
            conn.close()
            
            risk_factors = []
            
            if not issues:
                return 0.0, ["No known issues reported"]
            
            # Count by severity
            critical_issues = len([i for i in issues if i['severity'].lower() == 'critical'])
            high_issues = len([i for i in issues if i['severity'].lower() == 'high'])
            medium_issues = len([i for i in issues if i['severity'].lower() == 'medium'])
            
            risk = 0.0
            
            # Critical issues = major risk
            if critical_issues > 0:
                risk += critical_issues * 0.3
                risk_factors.append(f"{critical_issues} CRITICAL known issues reported")
            
            # High issues = moderate risk
            if high_issues > 0:
                risk += high_issues * 0.15
                risk_factors.append(f"{high_issues} HIGH severity known issues")
            
            # Medium issues = minor risk
            if medium_issues > 0:
                risk += medium_issues * 0.05
                risk_factors.append(f"{medium_issues} MEDIUM severity known issues")
            
            return min(1.0, risk), risk_factors
            
        except Exception as e:
            self.logger.warning(f"Could not assess known issues: {e}")
            return 0.3, ["Unable to assess known issues"]

    def assess_system_criticality_risk(
        self,
        system_role: str,
        uptime_days: int,
        backup_available: bool,
        critical_services: int
    ) -> Tuple[float, List[str]]:
        """
        Assess risk based on system criticality.
        
        Critical systems = higher rollback risk (more impact if patch fails).
        
        Args:
            system_role: System role
            uptime_days: Days since last reboot
            backup_available: Backup exists
            critical_services: Number of critical services
        
        Returns:
            Tuple of (risk_score, risk_factors)
        """
        
        risk = 0.0
        risk_factors = []
        
        # System role criticality
        role_risks = {
            "domain_controller": 0.9,
            "database_server": 0.85,
            "web_server": 0.70,
            "file_server": 0.60,
            "production_server": 0.65,
            "workstation": 0.20,
            "development": 0.15,
            "laptop": 0.10
        }
        
        role_risk = role_risks.get(system_role.lower(), 0.5)
        risk += role_risk * 0.4  # 40% weight on role
        
        if role_risk >= 0.8:
            risk_factors.append(f"Highly critical system role: {system_role}")
        
        # Uptime factor (long uptime = less time for testing post-patch)
        if uptime_days > 365:
            risk += 0.15
            risk_factors.append(f"Long uptime ({uptime_days} days) - potential dependency issues")
        elif uptime_days > 180:
            risk += 0.08
        
        # Backup factor (no backup = cannot easily rollback)
        if not backup_available:
            risk += 0.25
            risk_factors.append("No backup available - full rollback may not be possible")
        
        # Critical services factor
        if critical_services > 0:
            service_risk = min(0.2, critical_services * 0.05)
            risk += service_risk
            risk_factors.append(f"{critical_services} critical services running")
        
        return min(1.0, risk), risk_factors

    def assess_dependency_compatibility_risk(
        self,
        kb_id: str,
        affected_components: List[str],
        installed_applications: List[str]
    ) -> Tuple[float, List[str]]:
        """
        Assess risk of incompatibility with installed applications.
        
        Many affected components + many applications = higher risk.
        
        Args:
            kb_id: KB identifier
            affected_components: Components modified by patch (DLLs, exes, etc.)
            installed_applications: Applications installed on system
        
        Returns:
            Tuple of (risk_score, risk_factors)
        """
        
        risk = 0.0
        risk_factors = []
        
        if not affected_components or not installed_applications:
            return 0.0, ["Unable to assess component compatibility"]
        
        try:
            conn = sqlite3.connect(self.dev_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check for known incompatibilities
            incompatibilities_found = []
            
            for app in installed_applications:
                cursor.execute("""
                    SELECT COUNT(*) as count FROM known_incompatibilities
                    WHERE kb_id = ? AND application LIKE ?
                """, (kb_id, f"%{app}%"))
                
                result = cursor.fetchone()
                if result and result['count'] > 0:
                    incompatibilities_found.append(app)
            
            conn.close()
            
            if incompatibilities_found:
                risk = 0.0 + len(incompatibilities_found) * 0.2
                risk_factors.append(f"Known incompatibilities: {', '.join(incompatibilities_found)}")
            
            # Risk proportional to number of affected components
            component_risk = min(0.3, len(affected_components) * 0.05)
            risk += component_risk
            
            if len(affected_components) > 5:
                risk_factors.append(f"Patch affects {len(affected_components)} system components")
            
        except Exception as e:
            self.logger.warning(f"Could not assess compatibility: {e}")
            risk = 0.2
        
        return min(1.0, risk), risk_factors

    def assess_rollback_feasibility(
        self,
        backup_available: bool,
        backup_age_hours: int,
        system_critical: bool,
        can_disconnect: bool
    ) -> Tuple[bool, List[str]]:
        """
        Assess whether rollback is actually feasible.
        
        Args:
            backup_available: Backup exists
            backup_age_hours: Age of backup in hours
            system_critical: Critical system
            can_disconnect: Can system be disconnected for rollback
        
        Returns:
            Tuple of (is_feasible, concerns)
        """
        
        feasible = True
        concerns = []
        
        if not backup_available:
            feasible = False
            concerns.append("No backup available - rollback may not be possible")
        
        if backup_age_hours > 72:
            concerns.append(f"Backup is {backup_age_hours} hours old - data loss possible")
        
        if system_critical and backup_age_hours > 24:
            concerns.append("Critical system with stale backup - rollback risk")
        
        if system_critical and not can_disconnect:
            concerns.append("Critical system cannot be disconnected - rollback complex")
        
        return feasible, concerns

    def assess_overall_rollback_risk(
        self,
        kb_id: str,
        cve_id: str,
        system_role: str,
        uptime_days: int,
        backup_available: bool,
        backup_age_hours: int,
        affected_components: List[str],
        installed_applications: List[str],
        critical_services: int,
        can_disconnect: bool
    ) -> RollbackRiskAssessment:
        """
        Assess overall rollback risk for a patch on a system.
        
        Args:
            kb_id: KB identifier
            cve_id: CVE identifier
            system_role: System role
            uptime_days: System uptime
            backup_available: Backup exists
            backup_age_hours: Backup age
            affected_components: Affected components
            installed_applications: Installed applications
            critical_services: Number of critical services
            can_disconnect: Can system be disconnected
        
        Returns:
            RollbackRiskAssessment with detailed analysis
        """
        
        # Get component risks
        maturity_risk, maturity_factors = self.assess_patch_maturity_risk(kb_id)
        adoption_risk, adoption_factors = self.assess_adoption_rate_risk(kb_id)
        issues_risk, issues_factors = self.assess_known_issues_risk(kb_id)
        criticality_risk, criticality_factors = self.assess_system_criticality_risk(
            system_role, uptime_days, backup_available, critical_services
        )
        compat_risk, compat_factors = self.assess_dependency_compatibility_risk(
            kb_id, affected_components, installed_applications
        )
        
        # Calculate overall rollback risk
        # Weights emphasize patch maturity and known issues
        overall_risk = (
            maturity_risk * 0.30 +
            adoption_risk * 0.15 +
            issues_risk * 0.30 +
            criticality_risk * 0.15 +
            compat_risk * 0.10
        )
        
        # Determine risk level
        if overall_risk >= 0.80:
            risk_level = "CRITICAL"
        elif overall_risk >= 0.60:
            risk_level = "HIGH"
        elif overall_risk >= 0.40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Determine recommended approach
        if overall_risk >= 0.80:
            recommended = "staged"  # Test on non-critical system first
        elif overall_risk >= 0.60:
            recommended = "monitored"  # Monitor closely after patching
        elif overall_risk >= 0.40:
            recommended = "scheduled"  # Standard scheduling
        else:
            recommended = "immediate"  # Can apply quickly
        
        # Check rollback feasibility
        feasible, rollback_concerns = self.assess_rollback_feasibility(
            backup_available, backup_age_hours,
            system_role in ["domain_controller", "database_server"],
            can_disconnect
        )
        
        # Estimate rollback time
        rollback_time = 30  # Base time
        if backup_age_hours > 24:
            rollback_time += 30  # Data recovery time
        if system_role in ["domain_controller", "database_server"]:
            rollback_time += 30  # Extra care needed
        
        # Collect risk factors and mitigations
        all_risk_factors = (
            maturity_factors + adoption_factors + issues_factors +
            criticality_factors + compat_factors + rollback_concerns
        )
        
        mitigations = [
            "Create fresh backup before patching",
            "Test patch in controlled environment first",
            "Schedule patch during maintenance window",
            "Have rollback procedure documented and tested",
            "Monitor system closely for first 24 hours post-patch",
            "Have support team on standby during patch",
            "Verify backup restoration capability before patching"
        ]
        
        return RollbackRiskAssessment(
            patch_id=f"{kb_id}-{system_role[:3]}",
            cve_id=cve_id,
            system_role=system_role,
            patch_maturity_risk=maturity_risk,
            adoption_rate_risk=adoption_risk,
            known_issues_risk=issues_risk,
            system_criticality_risk=criticality_risk,
            backup_availability_risk=0.0 if backup_available else 1.0,
            dependency_compatibility_risk=compat_risk,
            overall_rollback_risk=overall_risk,
            risk_level=risk_level,
            risk_factors=list(set(all_risk_factors))[:10],  # Top 10 unique
            mitigations=mitigations,
            recommended_approach=recommended,
            estimated_rollback_time_minutes=rollback_time,
            rollback_feasibility=feasible,
            assessment_timestamp=datetime.utcnow()
        )


# ============================================================================
# MAIN (FOR TESTING)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    assessor = RollbackRiskAssessor(
        runtime_db_path="runtime_scan.sqlite",
        dev_db_path="dev_db.sqlite"
    )
    
    # Example assessment
    assessment = assessor.assess_overall_rollback_risk(
        kb_id="KB5001234",
        cve_id="CVE-2021-1234",
        system_role="database_server",
        uptime_days=730,
        backup_available=True,
        backup_age_hours=24,
        affected_components=["kernel32.dll", "ntdll.dll", "msvcrt.dll"],
        installed_applications=["SQL Server 2019", "IIS", "Exchange"],
        critical_services=3,
        can_disconnect=False
    )
    
    print(f"Rollback Risk: {assessment.overall_rollback_risk:.0%}")
    print(f"Risk Level: {assessment.risk_level}")
    print(f"Recommended Approach: {assessment.recommended_approach}")
    print(f"Risk Factors:")
    for factor in assessment.risk_factors:
        print(f"  - {factor}")

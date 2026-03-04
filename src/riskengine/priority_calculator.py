"""
priority_calculator.py - Batch Vulnerability Prioritization

Calculates and prioritizes vulnerabilities for a complete system scan.

Features:
- Dynamic priority scoring based on multiple factors
- Batch processing and sorting
- SLA tracking and escalation
- Resource-aware scheduling
- Historical priority trending
- What-if analysis for priority adjustments
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import heapq

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class PrioritizedVulnerability:
    """A vulnerability with priority score"""
    vuln_id: str  # Unique identifier
    cve_id: str
    priority_score: float  # 0.0-1.0
    priority_rank: int  # 1-N (1 = highest)
    priority_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    
    # Scoring components
    severity_component: float
    exploitability_component: float
    business_impact_component: float
    system_density_component: float
    sla_component: float
    
    # Timing information
    sla_deadline: datetime
    hours_until_sla: float
    sla_status: str  # "at_risk", "compliant", "urgent"
    
    # Context
    affected_systems_count: int
    remediation_effort_hours: float
    
    ranking_timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PriorityBatch:
    """Batch of prioritized vulnerabilities"""
    batch_id: str
    total_vulns: int
    prioritized_vulns: List[PrioritizedVulnerability]
    
    # Summary statistics
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    # Scheduling
    total_remediation_effort_hours: float
    recommended_batch_size: int
    estimated_completion_days: float
    
    batch_timestamp: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# PRIORITY CALCULATOR ENGINE
# ============================================================================

class PriorityCalculatorEngine:
    """
    Calculates vulnerability priorities for batch processing and planning.
    """

    def __init__(
        self,
        runtime_db_path: str,
        dev_db_path: str,
        log_level: int = logging.INFO
    ):
        """Initialize Priority Calculator Engine."""
        self.runtime_db_path = runtime_db_path
        self.dev_db_path = dev_db_path
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

    def calculate_severity_score(
        self,
        cvss: float,
        severity_rating: str,
        exploited_in_wild: bool,
        ransomware_associated: bool,
        poc_available: bool
    ) -> float:
        """
        Calculate severity component score.
        
        Args:
            cvss: CVSS score (0.0-10.0)
            severity_rating: Severity rating string
            exploited_in_wild: Exploitation status
            ransomware_associated: Ransomware flag
            poc_available: PoC availability
        
        Returns:
            Severity score (0.0-1.0)
        """
        
        # Base from CVSS
        score = cvss / 10.0
        
        # Boost if actively exploited
        if exploited_in_wild:
            score = min(1.0, score * 1.5)
        
        # Significant boost if ransomware-associated
        if ransomware_associated:
            score = min(1.0, score * 1.8)
        
        # Moderate boost if PoC available
        if poc_available:
            score = min(1.0, score * 1.3)
        
        return min(1.0, score)

    def calculate_exploitability_score(
        self,
        epss: float,
        attack_complexity: str,              # low, medium, high
        privileges_required: str,             # none, low, high
        user_interaction_required: bool,
        network_accessible: bool
    ) -> float:
        """
        Calculate exploitability component score.
        
        Args:
            epss: EPSS probability (0.0-1.0)
            attack_complexity: CVSS attack complexity
            privileges_required: CVSS privileges required
            user_interaction_required: CVSS user interaction flag
            network_accessible: Accessible from network
        
        Returns:
            Exploitability score (0.0-1.0)
        """
        
        # Base from EPSS
        score = epss
        
        # Complexity factor
        complexity_factors = {"low": 1.3, "medium": 1.0, "high": 0.6}
        score *= complexity_factors.get(attack_complexity.lower(), 1.0)
        
        # Privileges factor
        priv_factors = {"none": 1.5, "low": 1.2, "high": 0.8}
        score *= priv_factors.get(privileges_required.lower(), 1.0)
        
        # User interaction factor
        if not user_interaction_required:
            score *= 1.4  # More exploitable without user interaction
        
        # Network accessibility factor
        if network_accessible:
            score *= 1.3  # More exploitable from network
        
        return min(1.0, score)

    def calculate_business_impact_score(
        self,
        system_role: str,
        data_classification: str,
        compliance_violations: List[str]
    ) -> float:
        """
        Calculate business impact component score.
        
        Args:
            system_role: System role
            data_classification: Data classification level
            compliance_violations: List of compliance frameworks violated
        
        Returns:
            Impact score (0.0-1.0)
        """
        
        score = 0.5  # Base score
        
        # System role impact
        role_impact = {
            "domain_controller": 1.0,
            "database_server": 0.95,
            "web_server": 0.85,
            "file_server": 0.80,
            "production_server": 0.85,
            "workstation": 0.40,
            "development": 0.30,
            "laptop": 0.35
        }
        score = role_impact.get(system_role.lower(), 0.5)
        
        # Data classification impact
        data_impact = {
            "restricted": 1.0,
            "confidential": 0.90,
            "internal": 0.60,
            "public": 0.30
        }
        data_factor = data_impact.get(data_classification.lower(), 0.5)
        score = (score + data_factor) / 2.0  # Average with data classification
        
        # Compliance violation impact
        if compliance_violations:
            score = min(1.0, score * (1.0 + len(compliance_violations) * 0.2))
        
        return min(1.0, score)

    def calculate_system_density_score(
        self,
        affected_systems: int,
        total_systems: int,
        deployed_on_critical: bool,
        deployed_in_dmz: bool,
        network_exposure: str
    ) -> float:
        """
        Calculate system density component score.
        
        More systems affected = higher impact; critical infrastructure = higher impact.
        
        Args:
            affected_systems: Number of affected systems
            total_systems: Total systems in environment
            deployed_on_critical: On critical infrastructure
            deployed_in_dmz: In DMZ
            network_exposure: Network exposure level
        
        Returns:
            Density score (0.0-1.0)
        """
        
        # Calculate spread ratio
        if total_systems > 0:
            spread_ratio = affected_systems / total_systems
        else:
            spread_ratio = 0.0
        
        # Base score from spread
        score = spread_ratio
        
        # Boost for critical infrastructure
        if deployed_on_critical:
            score = min(1.0, score * 1.5)
        
        # Boost for DMZ deployment
        if deployed_in_dmz:
            score = min(1.0, score * 1.4)
        
        # Network exposure factor
        exposure_factors = {
            "internet_facing": 1.5,
            "dmz": 1.3,
            "internal": 1.0,
            "isolated": 0.5
        }
        score *= exposure_factors.get(network_exposure.lower(), 1.0)
        
        return min(1.0, score)

    def calculate_sla_score(
        self,
        sla_deadline: datetime,
        current_time: Optional[datetime] = None
    ) -> Tuple[float, str]:
        """
        Calculate SLA urgency component score.
        
        Closer to deadline = higher score.
        
        Args:
            sla_deadline: SLA deadline datetime
            current_time: Current time (default: now)
        
        Returns:
            Tuple of (SLA_score, SLA_status)
        """
        
        if current_time is None:
            current_time = datetime.utcnow()
        
        hours_until = (sla_deadline - current_time).total_seconds() / 3600
        
        if hours_until < 0:
            # Past deadline - CRITICAL
            return 1.0, "breached"
        elif hours_until < 4:
            # Within 4 hours - URGENT
            score = 1.0 - (hours_until / 4.0) * 0.2  # 0.8-1.0
            return score, "urgent"
        elif hours_until < 24:
            # Within 24 hours - AT RISK
            score = 0.7 + (1.0 - hours_until / 24.0) * 0.15  # 0.7-0.85
            return score, "at_risk"
        elif hours_until < 72:
            # Within 3 days - SOON
            score = 0.5 + (1.0 - hours_until / 72.0) * 0.2  # 0.5-0.7
            return score, "soon"
        else:
            # > 3 days - COMPLIANT
            score = 0.0 + min(0.5, hours_until / 720.0 * 0.5)  # 0.0-0.5
            return score, "compliant"

    def calculate_overall_priority(
        self,
        severity_score: float,
        exploitability_score: float,
        business_impact_score: float,
        system_density_score: float,
        sla_score: float,
        weights: Optional[Dict[str, float]] = None
    ) -> Tuple[float, str]:
        """
        Calculate overall priority score from components.
        
        Args:
            severity_score: Severity component (0.0-1.0)
            exploitability_score: Exploitability component (0.0-1.0)
            business_impact_score: Business impact component (0.0-1.0)
            system_density_score: System density component (0.0-1.0)
            sla_score: SLA component (0.0-1.0)
            weights: Component weights (default: equal)
        
        Returns:
            Tuple of (priority_score, priority_level)
        """
        
        # Default equal weights
        if weights is None:
            weights = {
                "severity": 0.25,
                "exploitability": 0.20,
                "business_impact": 0.25,
                "system_density": 0.15,
                "sla": 0.15
            }
        
        # Calculate weighted average
        priority_score = (
            severity_score * weights["severity"] +
            exploitability_score * weights["exploitability"] +
            business_impact_score * weights["business_impact"] +
            system_density_score * weights["system_density"] +
            sla_score * weights["sla"]
        )
        
        # Determine priority level
        if priority_score >= 0.85:
            priority_level = "CRITICAL"
        elif priority_score >= 0.70:
            priority_level = "HIGH"
        elif priority_score >= 0.50:
            priority_level = "MEDIUM"
        else:
            priority_level = "LOW"
        
        return priority_score, priority_level

    def prioritize_vulnerability(
        self,
        cve_id: str,
        cvss: float,
        epss: float,
        severity_rating: str,
        exploited_in_wild: bool,
        ransomware_associated: bool,
        poc_available: bool,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: bool,
        network_accessible: bool,
        system_role: str,
        data_classification: str,
        compliance_violations: List[str],
        affected_systems: int,
        total_systems: int,
        deployed_critical: bool,
        deployed_dmz: bool,
        network_exposure: str,
        sla_hours: int,
        remediation_effort_hours: float = 1.0,
        weights: Optional[Dict[str, float]] = None
    ) -> PrioritizedVulnerability:
        """
        Calculate priority for a single vulnerability.
        
        Args:
            cve_id: CVE identifier
            (... all vulnerability characteristics ...)
            remediation_effort_hours: Estimated effort to remediate
            weights: Custom component weights
        
        Returns:
            PrioritizedVulnerability with scores and ranking
        """
        
        # Calculate component scores
        severity_score = self.calculate_severity_score(
            cvss, severity_rating, exploited_in_wild,
            ransomware_associated, poc_available
        )
        
        exploitability_score = self.calculate_exploitability_score(
            epss, attack_complexity, privileges_required,
            user_interaction, network_accessible
        )
        
        business_impact_score = self.calculate_business_impact_score(
            system_role, data_classification, compliance_violations
        )
        
        system_density_score = self.calculate_system_density_score(
            affected_systems, total_systems, deployed_critical,
            deployed_dmz, network_exposure
        )
        
        sla_deadline = datetime.utcnow() + timedelta(hours=sla_hours)
        sla_score, sla_status = self.calculate_sla_score(sla_deadline)
        
        # Calculate overall priority
        priority_score, priority_level = self.calculate_overall_priority(
            severity_score, exploitability_score, business_impact_score,
            system_density_score, sla_score, weights
        )
        
        hours_until_sla = (sla_deadline - datetime.utcnow()).total_seconds() / 3600
        
        return PrioritizedVulnerability(
            vuln_id=f"{cve_id}-{system_role[:3]}",
            cve_id=cve_id,
            priority_score=priority_score,
            priority_rank=0,  # Set during batch processing
            priority_level=priority_level,
            severity_component=severity_score,
            exploitability_component=exploitability_score,
            business_impact_component=business_impact_score,
            system_density_component=system_density_score,
            sla_component=sla_score,
            sla_deadline=sla_deadline,
            hours_until_sla=hours_until_sla,
            sla_status=sla_status,
            affected_systems_count=affected_systems,
            remediation_effort_hours=remediation_effort_hours
        )

    def batch_prioritize(
        self,
        vulnerabilities: List[Dict[str, Any]],
        weights: Optional[Dict[str, float]] = None
    ) -> PriorityBatch:
        """
        Prioritize a batch of vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability specifications
            weights: Custom component weights
        
        Returns:
            PriorityBatch with sorted vulnerabilities
        """
        
        import time
        batch_id = f"BATCH-{int(time.time())}"
        
        prioritized = []
        for vuln in vulnerabilities:
            pv = self.prioritize_vulnerability(**vuln, weights=weights)
            prioritized.append(pv)
        
        # Sort by priority score (descending)
        prioritized.sort(key=lambda v: (-v.priority_score, v.sla_deadline))
        
        # Assign ranks
        for rank, pv in enumerate(prioritized, 1):
            pv.priority_rank = rank
        
        # Calculate batch statistics
        critical_count = len([v for v in prioritized if v.priority_level == "CRITICAL"])
        high_count = len([v for v in prioritized if v.priority_level == "HIGH"])
        medium_count = len([v for v in prioritized if v.priority_level == "MEDIUM"])
        low_count = len([v for v in prioritized if v.priority_level == "LOW"])
        
        total_effort = sum(v.remediation_effort_hours for v in prioritized)
        
        # Estimate batch sizing and completion
        # Assume 8 hour workday, 4 hours available for patching
        hours_per_day = 4.0
        estimated_days = total_effort / hours_per_day
        
        # Recommended batch size: prioritize top 20% or max 10 at a time
        recommended_batch = max(1, int(len(prioritized) * 0.2))
        recommended_batch = min(recommended_batch, 10)
        
        return PriorityBatch(
            batch_id=batch_id,
            total_vulns=len(vulnerabilities),
            prioritized_vulns=prioritized,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            total_remediation_effort_hours=total_effort,
            recommended_batch_size=recommended_batch,
            estimated_completion_days=estimated_days
        )

    def format_priority_report(self, batch: PriorityBatch) -> str:
        """Format priority batch as readable report."""
        
        lines = []
        lines.append("=" * 120)
        lines.append("VULNERABILITY PRIORITIZATION REPORT")
        lines.append(f"Batch ID: {batch.batch_id}")
        lines.append(f"Generated: {batch.batch_timestamp.isoformat()}")
        lines.append("=" * 120)
        lines.append("")
        
        lines.append("SUMMARY")
        lines.append("-" * 120)
        lines.append(f"Total Vulnerabilities: {batch.total_vulns}")
        lines.append(f"  CRITICAL: {batch.critical_count}")
        lines.append(f"  HIGH: {batch.high_count}")
        lines.append(f"  MEDIUM: {batch.medium_count}")
        lines.append(f"  LOW: {batch.low_count}")
        lines.append("")
        lines.append(f"Total Remediation Effort: {batch.total_remediation_effort_hours:.1f} hours")
        lines.append(f"Recommended Batch Size: {batch.recommended_batch_size} items")
        lines.append(f"Estimated Completion: {batch.estimated_completion_days:.1f} days")
        lines.append("")
        
        lines.append("PRIORITIZED VULNERABILITIES")
        lines.append("-" * 120)
        lines.append(f"{'Rank':<5} {'CVE ID':<20} {'Score':<8} {'Priority':<10} {'SLA Status':<12} {'Effort (hrs)':<12} {'Systems':<10}")
        lines.append("-" * 120)
        
        for pv in batch.prioritized_vulns[:50]:  # Top 50
            lines.append(
                f"{pv.priority_rank:<5} {pv.cve_id:<20} {pv.priority_score:>6.1%}  "
                f"{pv.priority_level:<10} {pv.sla_status:<12} {pv.remediation_effort_hours:>10.1f}  "
                f"{pv.affected_systems_count:>8}"
            )
        
        if len(batch.prioritized_vulns) > 50:
            lines.append(f"... and {len(batch.prioritized_vulns) - 50} more vulnerabilities")
        
        lines.append("")
        lines.append("=" * 120)
        
        return "\n".join(lines)


# ============================================================================
# MAIN (FOR TESTING)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    engine = PriorityCalculatorEngine(
        runtime_db_path="runtime_scan.sqlite",
        dev_db_path="dev_db.sqlite"
    )
    
    # Example vulnerabilities
    vulns = [
        {
            "cve_id": "CVE-2021-1001",
            "cvss": 9.8,
            "epss": 0.95,
            "severity_rating": "CRITICAL",
            "exploited_in_wild": True,
            "ransomware_associated": True,
            "poc_available": True,
            "attack_complexity": "low",
            "privileges_required": "none",
            "user_interaction": False,
            "network_accessible": True,
            "system_role": "database_server",
            "data_classification": "restricted",
            "compliance_violations": ["HIPAA", "PCI_DSS"],
            "affected_systems": 25,
            "total_systems": 100,
            "deployed_critical": True,
            "deployed_dmz": False,
            "network_exposure": "internal",
            "sla_hours": 4,
            "remediation_effort_hours": 2.0
        }
    ]
    
    batch = engine.batch_prioritize(vulns)
    print(engine.format_priority_report(batch))

"""
compliance_mapper.py - Maps Vulnerabilities to Compliance Frameworks

This module handles regulatory compliance mapping and assessment:
- HIPAA (Healthcare)
- PCI DSS (Payment Card Industry)
- NIST (National Institute of Standards)
- SOC 2 (Service Organization Control)
- ISO 27001 (Information Security)
- GDPR (Privacy)

Provides:
- Compliance violation detection
- SLA requirement calculation
- Audit trail generation
- Compliance reporting
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    NIST = "NIST"
    SOC2 = "SOC2"
    ISO_27001 = "ISO_27001"
    GDPR = "GDPR"
    FEDRAMP = "FedRAMP"


class ComplianceSeverity(Enum):
    """Severity of compliance violation"""
    CRITICAL = "critical"      # Immediate action required
    HIGH = "high"             # Urgent - within days
    MEDIUM = "medium"         # Standard patching cycle
    LOW = "low"               # Regular maintenance


@dataclass
class ComplianceViolation:
    """A compliance violation"""
    framework: ComplianceFramework
    regulation_id: str  # e.g., "HIPAA-164.308(a)(3)(ii)(B)"
    violation_description: str
    severity: ComplianceSeverity
    sla_hours: int
    remediation_required: bool
    audit_trail_required: bool


@dataclass
class ComplianceAssessment:
    """Complete compliance assessment for a vulnerability"""
    cve_id: str
    applicable_frameworks: List[ComplianceFramework]
    violations: List[ComplianceViolation]
    criticality_for_compliance: str  # CRITICAL, HIGH, MEDIUM, LOW
    sla_hours: int  # Most stringent SLA
    audit_requirements: List[str]
    remediation_evidence_required: List[str]
    reporting_deadlines: Dict[str, datetime]
    assessment_timestamp: datetime


# ============================================================================
# COMPLIANCE FRAMEWORK DEFINITIONS
# ============================================================================

class ComplianceDefinitions:
    """Compliance framework definitions and requirements"""
    
    FRAMEWORKS = {
        ComplianceFramework.HIPAA: {
            "name": "Health Insurance Portability and Accountability Act",
            "industry": "Healthcare",
            "applies_to": ["healthcare_providers", "health_plans", "healthcare_clearinghouses"],
            "regulations": {
                "164.308(a)(3)(ii)(B)": {
                    "title": "Periodic Vulnerability Assessment",
                    "requirement": "Periodic vulnerability scans and assessment results",
                    "patch_requirement": "Critical vulns within 24 hours",
                    "audit_trail": True
                },
                "164.308(a)(5)(ii)(A)": {
                    "title": "Security Awareness and Training",
                    "requirement": "Employee training on security",
                    "patch_requirement": "Security updates documented",
                    "audit_trail": True
                }
            },
            "severity_mapping": {
                "CRITICAL": (ComplianceSeverity.CRITICAL, 4),
                "HIGH": (ComplianceSeverity.HIGH, 24),
                "MEDIUM": (ComplianceSeverity.MEDIUM, 72),
                "LOW": (ComplianceSeverity.LOW, 720)
            }
        },
        
        ComplianceFramework.PCI_DSS: {
            "name": "Payment Card Industry Data Security Standard",
            "industry": "Financial/eCommerce",
            "applies_to": ["payment_processors", "merchants", "service_providers"],
            "regulations": {
                "6.2": {
                    "title": "Security Patches",
                    "requirement": "Install security patches within defined SL",
                    "patch_requirement": "Critical within 1 month, others within 3 months",
                    "audit_trail": True
                },
                "11.2": {
                    "title": "Vulnerability Scanning",
                    "requirement": "Quarterly vulnerability scans",
                    "patch_requirement": "Remediate scan findings",
                    "audit_trail": True
                }
            },
            "severity_mapping": {
                "CRITICAL": (ComplianceSeverity.CRITICAL, 24),
                "HIGH": (ComplianceSeverity.HIGH, 72),
                "MEDIUM": (ComplianceSeverity.MEDIUM, 180),
                "LOW": (ComplianceSeverity.LOW, 365)
            }
        },
        
        ComplianceFramework.NIST: {
            "name": "National Institute of Standards & Technology",
            "industry": "Federal/Critical Infrastructure",
            "applies_to": ["federal_agencies", "contractors", "critical_infra"],
            "regulations": {
                "SI-2": {
                    "title": "Flaw Remediation",
                    "requirement": "Identify, report, and correct system flaws",
                    "patch_requirement": "Critical within 7 days, others within 30 days",
                    "audit_trail": True
                },
                "RA-2": {
                    "title": "Security Categorization",
                    "requirement": "Categorize systems by security impact",
                    "patch_requirement": "Patch per system categorization",
                    "audit_trail": True
                }
            },
            "severity_mapping": {
                "CRITICAL": (ComplianceSeverity.CRITICAL, 6),
                "HIGH": (ComplianceSeverity.HIGH, 30),
                "MEDIUM": (ComplianceSeverity.MEDIUM, 60),
                "LOW": (ComplianceSeverity.LOW, 365)
            }
        },
        
        ComplianceFramework.SOC2: {
            "name": "Service Organization Control 2",
            "industry": "SaaS/Cloud/Tech Services",
            "applies_to": ["service_providers", "cloud_providers"],
            "regulations": {
                "CC6.1": {
                    "title": "Logical and Physical Access Controls",
                    "requirement": "Logical security controls over IT systems",
                    "patch_requirement": "Patches applied per policy",
                    "audit_trail": True
                },
                "CC7.2": {
                    "title": "System Monitoring",
                    "requirement": "Monitor systems for security issues",
                    "patch_requirement": "Monitoring and patching",
                    "audit_trail": True
                }
            },
            "severity_mapping": {
                "CRITICAL": (ComplianceSeverity.CRITICAL, 24),
                "HIGH": (ComplianceSeverity.HIGH, 72),
                "MEDIUM": (ComplianceSeverity.MEDIUM, 120),
                "LOW": (ComplianceSeverity.LOW, 365)
            }
        },
        
        ComplianceFramework.ISO_27001: {
            "name": "Information Security Management",
            "industry": "All Industries",
            "applies_to": ["all_organizations"],
            "regulations": {
                "A.12.6.1": {
                    "title": "Management of Technical Vulnerabilities",
                    "requirement": "Obtain timely information about technical vulnerabilities",
                    "patch_requirement": "Evaluate and apply patches",
                    "audit_trail": True
                }
            },
            "severity_mapping": {
                "CRITICAL": (ComplianceSeverity.CRITICAL, 14),
                "HIGH": (ComplianceSeverity.HIGH, 30),
                "MEDIUM": (ComplianceSeverity.MEDIUM, 60),
                "LOW": (ComplianceSeverity.LOW, 365)
            }
        },
        
        ComplianceFramework.GDPR: {
            "name": "General Data Protection Regulation",
            "industry": "All Industries (if EU data processed)",
            "applies_to": ["all_organizations_with_eu_data"],
            "regulations": {
                "Article 32": {
                    "title": "Security of Processing",
                    "requirement": "Appropriate technical and organizational measures",
                    "patch_requirement": "Maintain appropriate security",
                    "audit_trail": True
                }
            },
            "severity_mapping": {
                "CRITICAL": (ComplianceSeverity.CRITICAL, 24),
                "HIGH": (ComplianceSeverity.HIGH, 72),
                "MEDIUM": (ComplianceSeverity.MEDIUM, 168),
                "LOW": (ComplianceSeverity.LOW, 720)
            }
        }
    }


# ============================================================================
# COMPLIANCE MAPPER ENGINE
# ============================================================================

class ComplianceMapperEngine:
    """
    Maps vulnerabilities to compliance requirements and generates
    compliance assessments and reporting.
    """

    def __init__(
        self,
        runtime_db_path: str,
        dev_db_path: str,
        organization_profile_path: Optional[str] = None,
        log_level: int = logging.INFO
    ):
        """Initialize Compliance Mapper Engine."""
        self.runtime_db_path = runtime_db_path
        self.dev_db_path = dev_db_path
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        
        # Load organization compliance profile
        self.org_profile = self._load_org_profile(organization_profile_path)
        
        # Load compliance definitions
        self.frameworks = ComplianceDefinitions.FRAMEWORKS

    def _load_org_profile(self, profile_path: Optional[str]) -> Dict[str, Any]:
        """
        Load organization's compliance profile.
        
        Defines which frameworks apply and any custom requirements.
        """
        default_profile = {
            "organization_name": "Unknown Organization",
            "industry": "General",
            "applicable_frameworks": [],
            "custom_sla_multipliers": {},  # e.g., {"HIPAA": 0.5} for 50% faster SLA
            "internal_policy_overrides": {},
            "audit_contact": None,
            "compliance_officer": None
        }
        
        # TODO: Load from file if provided
        
        return default_profile

    def detect_applicable_frameworks(
        self,
        system_role: str,
        industry: str,
        data_classification: str
    ) -> List[ComplianceFramework]:
        """
        Detect which compliance frameworks apply to this system.
        
        Args:
            system_role: System role (workstation, server, db_server, etc.)
            industry: Organization industry
            data_classification: Sensitivity of data (public, internal, confidential, restricted)
        
        Returns:
            List of applicable frameworks
        """
        applicable = []
        
        # Healthcare data → HIPAA, NIST
        if industry.lower() in ['healthcare', 'medical', 'pharmaceutical']:
            applicable.extend([ComplianceFramework.HIPAA, ComplianceFramework.NIST])
        
        # Payment processing → PCI DSS
        if industry.lower() in ['financial', 'ecommerce', 'retail']:
            applicable.append(ComplianceFramework.PCI_DSS)
        
        # Critical infrastructure → NIST, FedRAMP
        if industry.lower() in ['government', 'critical_infrastructure', 'energy']:
            applicable.extend([ComplianceFramework.NIST, ComplianceFramework.FEDRAMP])
        
        # All organizations → ISO 27001
        applicable.append(ComplianceFramework.ISO_27001)
        
        # Confidential/Restricted data → GDPR if international
        if data_classification in ['confidential', 'restricted']:
            if industry.lower() not in ['us_only']:  # Simple heuristic
                applicable.append(ComplianceFramework.GDPR)
        
        # Remove duplicates
        return list(set(applicable))

    def assess_compliance_impact(
        self,
        cve_id: str,
        severity_rating: str,
        applicable_frameworks: List[str],
        system_role: str,
        data_classification: str,
        exploited_in_wild: bool
    ) -> ComplianceAssessment:
        """
        Assess compliance impact of a vulnerability.
        
        Args:
            cve_id: CVE identifier
            severity_rating: Severity (CRITICAL, HIGH, MEDIUM, LOW)
            applicable_frameworks: List of framework names as strings
            system_role: System role
            data_classification: Data classification
            exploited_in_wild: Exploitation status
        
        Returns:
            ComplianceAssessment with all requirements
        """
        
        violations = []
        framework_objs = []
        sla_hours_list = []
        audit_requirements = []
        remediation_evidence = []
        reporting_deadlines = {}
        
        # Convert framework strings to enums
        for fw_name in applicable_frameworks:
            try:
                fw = ComplianceFramework[fw_name]
                framework_objs.append(fw)
            except KeyError:
                self.logger.warning(f"Unknown framework: {fw_name}")
                continue
        
        # Assess each applicable framework
        now = datetime.utcnow()
        
        for framework in framework_objs:
            fw_def = self.frameworks.get(framework)
            if not fw_def:
                continue
            
            # Get severity mapping for this framework
            severity_map = fw_def.get("severity_mapping", {})
            compliance_severity, base_sla = severity_map.get(
                severity_rating, 
                (ComplianceSeverity.LOW, 365)
            )
            
            # Apply custom multiplier if exists
            multiplier = self.org_profile.get("custom_sla_multipliers", {}).get(
                framework.value, 1.0
            )
            sla_hours = int(base_sla * multiplier)
            sla_hours_list.append(sla_hours)
            
            # Create violation record
            for reg_id, reg_def in fw_def.get("regulations", {}).items():
                violation = ComplianceViolation(
                    framework=framework,
                    regulation_id=reg_id,
                    violation_description=f"Unpatched {cve_id} ({severity_rating}) violates {reg_def.get('title', 'regulation')}",
                    severity=compliance_severity,
                    sla_hours=sla_hours,
                    remediation_required=True,
                    audit_trail_required=reg_def.get("audit_trail", False)
                )
                violations.append(violation)
            
            # Track audit requirements
            if fw_def.get("regulations", {}).get(list(fw_def["regulations"].keys())[0], {}).get("audit_trail"):
                audit_requirements.extend([
                    f"{framework.value} requires patch documentation",
                    f"Submit {framework.value} compliance report within {sla_hours} hours",
                    f"Maintain audit logs of patch activities"
                ])
            
            # Track remediation evidence needed
            remediation_evidence.extend([
                f"Patch installation proof for {framework.value}",
                f"Change request approval from {framework.value} perspective",
                f"Testing and validation results"
            ])
            
            # Calculate reporting deadline
            reporting_deadline = now + timedelta(hours=sla_hours + 24)  # +24h for reporting
            reporting_deadlines[framework.value] = reporting_deadline
        
        # Determine overall criticality
        if not violations:
            criticality = "LOW"
        elif any(v.severity == ComplianceSeverity.CRITICAL for v in violations):
            criticality = "CRITICAL"
        elif any(v.severity == ComplianceSeverity.HIGH for v in violations):
            criticality = "HIGH"
        elif any(v.severity == ComplianceSeverity.MEDIUM for v in violations):
            criticality = "MEDIUM"
        else:
            criticality = "LOW"
        
        # Get most stringent SLA
        most_stringent_sla = min(sla_hours_list) if sla_hours_list else 720
        
        # Increase urgency if exploited in wild
        if exploited_in_wild and most_stringent_sla > 4:
            most_stringent_sla = min(4, most_stringent_sla)
        
        return ComplianceAssessment(
            cve_id=cve_id,
            applicable_frameworks=framework_objs,
            violations=violations,
            criticality_for_compliance=criticality,
            sla_hours=most_stringent_sla,
            audit_requirements=audit_requirements,
            remediation_evidence_required=remediation_evidence,
            reporting_deadlines=reporting_deadlines,
            assessment_timestamp=now
        )

    def generate_compliance_report(
        self,
        assessments: List[ComplianceAssessment]
    ) -> str:
        """
        Generate compliance report for management.
        
        Args:
            assessments: List of ComplianceAssessment objects
        
        Returns:
            Formatted compliance report
        """
        
        report_lines = []
        report_lines.append("=" * 100)
        report_lines.append("COMPLIANCE IMPACT REPORT - VULNERABILITIES")
        report_lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        report_lines.append("=" * 100)
        report_lines.append("")
        
        # Summary statistics
        total_vulns = len(assessments)
        critical_vulns = len([a for a in assessments if a.criticality_for_compliance == "CRITICAL"])
        high_vulns = len([a for a in assessments if a.criticality_for_compliance == "HIGH"])
        medium_vulns = len([a for a in assessments if a.criticality_for_compliance == "MEDIUM"])
        
        report_lines.append("SUMMARY")
        report_lines.append("-" * 100)
        report_lines.append(f"Total Vulnerabilities: {total_vulns}")
        report_lines.append(f"  - CRITICAL Compliance Impact: {critical_vulns}")
        report_lines.append(f"  - HIGH Compliance Impact: {high_vulns}")
        report_lines.append(f"  - MEDIUM Compliance Impact: {medium_vulns}")
        report_lines.append("")
        
        # Frameworks & violations
        framework_violations = {}
        for assessment in assessments:
            for fw in assessment.applicable_frameworks:
                if fw not in framework_violations:
                    framework_violations[fw] = 0
                framework_violations[fw] += len([v for v in assessment.violations if v.framework == fw])
        
        report_lines.append("COMPLIANCE FRAMEWORK IMPACT")
        report_lines.append("-" * 100)
        for fw, count in sorted(framework_violations.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"  {fw.value}: {count} violations")
        report_lines.append("")
        
        # Critical items requiring immediate action
        report_lines.append("CRITICAL ITEMS REQUIRING IMMEDIATE ACTION")
        report_lines.append("-" * 100)
        critical_items = [a for a in assessments if a.criticality_for_compliance == "CRITICAL"]
        if critical_items:
            for item in critical_items[:10]:  # Top 10
                report_lines.append(f"  • {item.cve_id}")
                report_lines.append(f"    SLA: {item.sla_hours} hours")
                report_lines.append(f"    Frames: {', '.join([f.value for f in item.applicable_frameworks])}")
                report_lines.append("")
        else:
            report_lines.append("  None - All vulnerabilities have been addressed")
        report_lines.append("")
        
        # Upcoming reporting deadlines
        all_deadlines = {}
        for assessment in assessments:
            for fw, deadline in assessment.reporting_deadlines.items():
                if fw not in all_deadlines or deadline < all_deadlines[fw]:
                    all_deadlines[fw] = deadline
        
        report_lines.append("COMPLIANCE REPORTING DEADLINES")
        report_lines.append("-" * 100)
        for fw, deadline in sorted(all_deadlines.items(), key=lambda x: x[1]):
            hours_until = (deadline - datetime.utcnow()).total_seconds() / 3600
            report_lines.append(f"  {fw}: {deadline.isoformat()}")
            report_lines.append(f"       ({hours_until:.0f} hours remaining)")
        report_lines.append("")
        
        report_lines.append("=" * 100)
        
        return "\n".join(report_lines)

    def calculate_compliance_risk_score(
        self,
        assessments: List[ComplianceAssessment]
    ) -> Dict[str, float]:
        """
        Calculate compliance risk scores per framework.
        
        Args:
            assessments: List of assessments
        
        Returns:
            Dictionary of framework → risk score (0.0-1.0)
        """
        
        framework_scores = {}
        
        for assessment in assessments:
            for violation in assessment.violations:
                fw = violation.framework.value
                if fw not in framework_scores:
                    framework_scores[fw] = 0.0
                
                # Weight by severity
                severity_weight = {
                    ComplianceSeverity.CRITICAL: 1.0,
                    ComplianceSeverity.HIGH: 0.7,
                    ComplianceSeverity.MEDIUM: 0.4,
                    ComplianceSeverity.LOW: 0.1
                }
                
                framework_scores[fw] += severity_weight.get(violation.severity, 0.5)
        
        # Normalize to 0-1 scale
        max_score = max(framework_scores.values()) if framework_scores else 1.0
        if max_score > 1.0:
            normalized_scores = {
                fw: score / max_score for fw, score in framework_scores.items()
            }
        else:
            normalized_scores = framework_scores
        
        return normalized_scores


# ============================================================================
# MAIN (FOR TESTING)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    engine = ComplianceMapperEngine(
        runtime_db_path="runtime_scan.sqlite",
        dev_db_path="dev_db.sqlite"
    )
    
    # Example assessment
    assessment = engine.assess_compliance_impact(
        cve_id="CVE-2021-1234",
        severity_rating="CRITICAL",
        applicable_frameworks=["HIPAA", "PCI_DSS", "NIST"],
        system_role="database_server",
        data_classification="restricted",
        exploited_in_wild=True
    )
    
    print(f"CVE: {assessment.cve_id}")
    print(f"Criticality: {assessment.criticality_for_compliance}")
    print(f"SLA: {assessment.sla_hours} hours")
    print(f"Violations: {len(assessment.violations)}")

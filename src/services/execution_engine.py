"""
EXECUTION ENGINE - Intelligent Remediation Orchestration

Main execution layer for SmartPatch
Consumes decisions from Decision Layer and executes remediation using Catalogue controls

Features:
- Mitigation type categorization (APP, AUTH, NET, REG, SVC)
- Component mapping to specific affected files/services/registry
- Catalogue-based control selection
- Test mode / dry-run capability
- Detailed reasoning/explainability per decision
- Progress tracking and audit logging
"""

import sqlite3
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from uuid import uuid4

from src.services.mitigation_catalogue_loader import (
    MitigationCatalogueLoader, MitigationType, ControlSeverity, ControlStatus
)
from src.services.component_mapper import ComponentMapper, VulnerabilityComponentMap

logger = logging.getLogger(__name__)


class ExecutionMode(str, Enum):
    """Execution modes for remediation"""
    DRY_RUN = "dry_run"      # Simulate without making changes
    SANDBOX = "sandbox"      # Test on isolated system
    STAGED = "staged"        # Staged rollout to subset
    PRODUCTION = "production"  # Full production deployment


class ExecutionPhase(str, Enum):
    """Phases of execution"""
    DISCOVERY = "discovery"         # Identify affected systems/components
    PLANNING = "planning"           # Generate execution plan
    VALIDATION = "validation"       # Pre-flight validation
    DEPLOYMENT = "deployment"       # Apply remediation
    VERIFICATION = "verification"   # Post-deployment checks
    ROLLBACK = "rollback"          # Rollback on failure


@dataclass
class RemediationControl:
    """A specific control ready for execution"""
    control_id: str
    catalog_id: str                          # Reference to catalog control
    mitigation_type: MitigationType
    name: str
    description: str
    commands: List[Dict[str, Any]]           # Commands to execute
    validation_commands: List[Dict[str, Any]]  # Validation after execution
    rollback_commands: List[Dict[str, Any]] = field(default_factory=list)  # Rollback steps
    os_applicable: List[str] = field(default_factory=list)
    requires_reboot: bool = False
    requires_admin: bool = True


@dataclass
class RemediationStep:
    """Individual execution step"""
    step_id: str
    control: RemediationControl
    system_id: str
    command: str
    command_type: str        # PowerShell, Registry, DISM, etc.
    requires_admin: bool
    estimated_duration_seconds: int
    status: str = "pending"  # pending, queued, running, completed, failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output: Optional[str] = None
    error: Optional[str] = None
    validated: bool = False


@dataclass
class ExecutionPlan:
    """Complete execution plan for vulnerability remediation"""
    plan_id: str
    cve_id: str
    decision_id: str
    affected_systems: List[str]
    controls: List[RemediationControl]
    phases: Dict[ExecutionPhase, List[RemediationStep]] = field(default_factory=dict)
    mode: ExecutionMode = ExecutionMode.DRY_RUN
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "draft"  # draft, approved, staged, in_progress, completed, failed, rolled_back


@dataclass
class ExecutionReasoning:
    """Detailed reasoning for execution decisions"""
    decision_id: str
    cve_id: str
    reasoning_chain: List[str] = field(default_factory=list)
    component_analysis: Dict[str, Any] = field(default_factory=dict)
    control_selection_rationale: Dict[str, Any] = field(default_factory=dict)
    risk_factors: Dict[str, float] = field(default_factory=dict)
    confidence_score: float = 0.0
    alternatives_considered: List[Dict[str, Any]] = field(default_factory=list)


class ExecutionEngine:
    """
    Orchestrates vulnerability remediation using catalogue controls
    
    Workflow:
    1. Load Decision Layer output and vulnerability mapping
    2. Query catalogue for applicable controls
    3. Map to affected components (via ComponentMapper)
    4. Generate execution plan with steps
    5. Validate pre-flight (test mode option)
    6. Execute remediation
    7. Verify and log results
    
    Usage:
        engine = ExecutionEngine()
        engine.load_catalogues()
        plan = engine.generate_remediation_plan(
            decision_output, 
            mode=ExecutionMode.DRY_RUN
        )
        results = engine.execute_plan(plan, mode=ExecutionMode.SANDBOX)
    """
    
    def __init__(self, 
                 catalogue_dir: str = "src/catalogues",
                 dev_db_path: str = "dev_db.sqlite",
                 runtime_db_path: str = "runtime_scan.sqlite",
                 execution_db_path: str = "execution_log.sqlite"):
        """Initialize execution engine"""
        self.catalogue_dir = catalogue_dir
        self.dev_db_path = dev_db_path
        self.runtime_db_path = runtime_db_path
        self.execution_db_path = execution_db_path
        
        # Initialize components
        self.catalogue_loader: Optional[MitigationCatalogueLoader] = None
        self.component_mapper = ComponentMapper(dev_db_path, runtime_db_path)
        
        # Execution tracking
        self.execution_plans: Dict[str, ExecutionPlan] = {}
        self.execution_logs: List[Dict[str, Any]] = []
        
        # Initialize execution log database
        self._initialize_execution_db()
    
    def _initialize_execution_db(self):
        """Create execution log database schema"""
        try:
            conn = sqlite3.connect(self.execution_db_path)
            cursor = conn.cursor()
            
            # Execution plans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS execution_plans (
                    plan_id TEXT PRIMARY KEY,
                    cve_id TEXT,
                    decision_id TEXT,
                    mode TEXT,
                    status TEXT,
                    affected_systems INTEGER,
                    total_controls INTEGER,
                    created_at TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    plan_json TEXT
                )
            """)
            
            # Execution steps table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS execution_steps (
                    step_id TEXT PRIMARY KEY,
                    plan_id TEXT,
                    control_id TEXT,
                    system_id TEXT,
                    command TEXT,
                    command_type TEXT,
                    status TEXT,
                    output TEXT,
                    error TEXT,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    validated BOOLEAN,
                    FOREIGN KEY(plan_id) REFERENCES execution_plans(plan_id)
                )
            """)
            
            # Reasoning trace table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS execution_reasoning (
                    reasoning_id TEXT PRIMARY KEY,
                    decision_id TEXT,
                    cve_id TEXT,
                    reasoning_json TEXT,
                    created_at TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("Execution database initialized: %s", self.execution_db_path)
        except Exception as e:
            logger.error("Failed to initialize execution database: %s", str(e))
    
    def load_catalogues(self) -> bool:
        """Load mitigation control catalogues"""
        logger.info("Loading mitigation catalogues from %s", self.catalogue_dir)
        
        self.catalogue_loader = MitigationCatalogueLoader(self.catalogue_dir)
        success = self.catalogue_loader.load_all_catalogues()
        
        if success:
            stats = self.catalogue_loader.get_statistics()
            logger.info("✓ Catalogues loaded - %d total controls", stats["total_controls"])
        else:
            logger.error("✗ Failed to load catalogues")
        
        return success
    
    def generate_remediation_plan(self, 
                                 cve_id: str,
                                 decision_output: Dict[str, Any],
                                 vulnerability_components: List[str],
                                 affected_os: str = "Windows 10",
                                 mode: ExecutionMode = ExecutionMode.DRY_RUN) -> ExecutionPlan:
        """
        Generate complete remediation plan for a vulnerability
        
        Args:
            cve_id: CVE identifier
            decision_output: Output from Decision Layer
            vulnerability_components: Components affected (e.g., ["SMB", "RPC"])
            affected_os: Target OS
            mode: Execution mode (dry_run, sandbox, staged, production)
        
        Returns:
            ExecutionPlan with all remediation steps
        """
        logger.info("Generating remediation plan for %s in %s mode", cve_id, mode.value)
        
        plan_id = str(uuid4())
        plan = ExecutionPlan(
            plan_id=plan_id,
            cve_id=cve_id,
            decision_id=decision_output.get("decision_id", ""),
            affected_systems=[],
            controls=[],
            mode=mode,
            status="draft"
        )
        
        # Step 1: Map vulnerability to components
        vuln_map = self.component_mapper.map_vulnerability(
            cve_id,
            vulnerability_components,
            affected_os
        )
        
        logger.info("Mapped %s to %d components", cve_id, len(vuln_map.components))
        
        # Step 2: Get affected systems  
        affected_hosts = self.component_mapper.get_affected_systems(cve_id, vuln_map)
        plan.affected_systems = affected_hosts
        logger.info("Found %d affected systems", len(affected_hosts))
        
        # Step 3: Select applicable controls from catalogue
        controls = self._select_applicable_controls(
            vuln_map,
            affected_os
        )
        plan.controls = controls
        logger.info("Selected %d applicable controls", len(controls))
        
        # Step 4: Generate reasoning/explainability
        reasoning = self._generate_reasoning(
            cve_id,
            vuln_map,
            controls,
            decision_output
        )
        self._save_reasoning(reasoning)
        
        # Step 5: Build execution phases
        plan.phases = self._build_execution_phases(
            plan_id,
            controls,
            affected_hosts,
            mode
        )
        
        # Store plan
        self.execution_plans[plan_id] = plan
        self._save_execution_plan(plan)
        
        logger.info("✓ Remediation plan generated: %s with %d phases",
                   plan_id, len(plan.phases))
        
        return plan
    
    def _select_applicable_controls(self, 
                                   vuln_map: VulnerabilityComponentMap,
                                   os_version: str) -> List[RemediationControl]:
        """Select applicable controls from catalogue"""
        if not self.catalogue_loader:
            logger.warning("Catalogue loader not initialized")
            return []
        
        controls = []
        
        for control_id in vuln_map.applicable_controls.keys():
            # Get control from catalogue
            control_def = self.catalogue_loader.get_control(control_id)
            if not control_def:
                logger.warning("Control not found in catalogue: %s", control_id)
                continue
            
            # Check OS applicability
            is_applicable = any(
                app.get("supported", False) and (
                    os_version.lower() in app.get("os_name", "").lower() or
                    "all" in app.get("os_name", "").lower()
                )
                for app in control_def.os_applicability
            )
            
            if not is_applicable:
                logger.debug("Control %s not applicable to %s", control_id, os_version)
                continue
            
            # Create remediation control from catalogue control
            remediation_control = RemediationControl(
                control_id=str(uuid4()),
                catalog_id=control_def.control_id,
                mitigation_type=control_def.category,
                name=control_def.name,
                description=control_def.description,
                commands=[
                    {
                        "command": method.get("command", method.get("commands", [""])[0]),
                        "type": method.get("type", "Unknown"),
                        "requires_reboot": method.get("requires_reboot", False)
                    }
                    for method in control_def.enforcement_methods
                ],
                validation_commands=[
                    {
                        "command": check.get("command", check.get("reference_command", "")),
                        "success_criteria": check.get("success_criteria", "")
                    }
                    for check in control_def.validation_checks
                ],
                os_applicable=[app.get("os_name", "") for app in control_def.os_applicability],
                requires_admin=control_def.privilege_required.lower() == "administrator"
            )
            
            controls.append(remediation_control)
        
        return controls
    
    def _generate_reasoning(self,
                           cve_id: str,
                           vuln_map: VulnerabilityComponentMap,
                           controls: List[RemediationControl],
                           decision_output: Dict[str, Any]) -> ExecutionReasoning:
        """Generate detailed reasoning for execution decisions"""
        reasoning = ExecutionReasoning(
            decision_id=decision_output.get("decision_id", ""),
            cve_id=cve_id
        )
        
        # Build reasoning chain
        reasoning.reasoning_chain = [
            f"CVE-{cve_id[4:]} identified as {decision_output.get('priority_level', 'UNKNOWN')} priority",
            f"Mapped to {len(vuln_map.components)} affected components",
            f"Found {len(vuln_map.affected_services)} affected services",
            f"Selected {len(controls)} applicable controls from catalogue",
            f"Estimated remediation effort: {vuln_map.estimated_effort_hours} hours"
        ]
        
        # Component analysis
        reasoning.component_analysis = {
            "total_components": len(vuln_map.components),
            "by_type": {
                comp_type.value: len([c for c in vuln_map.components if c.component_type == comp_type])
                for comp_type in vuln_map.components[0].component_type.__class__
            },
            "affected_services": list(vuln_map.affected_services),
            "affected_features": list(vuln_map.affected_features)
        }
        
        # Control selection rationale
        reasoning.control_selection_rationale = {
            "controls_available": len(controls),
            "by_type": {},
            "rationale": "Controls selected based on affected components and catalogue mapping"
        }
        
        for control in controls:
            if control.mitigation_type.value not in reasoning.control_selection_rationale["by_type"]:
                reasoning.control_selection_rationale["by_type"][control.mitigation_type.value] = 0
            reasoning.control_selection_rationale["by_type"][control.mitigation_type.value] += 1
        
        # Risk factors
        reasoning.risk_factors = {
            "cvss_score": decision_output.get("cvss_score", 0.0),
            "epss_score": decision_output.get("epss_score", 0.0),
            "affected_systems_count": len(vuln_map.components),
            "hardening_available": vuln_map.hardening_available,
            "patch_available": decision_output.get("patch_available", False)
        }
        
        # Calculate confidence
        confidence = 0.0
        confidence += 0.5 if len(controls) > 0 else 0.0       # Controls available
        confidence += 0.3 if len(vuln_map.components) > 0 else 0.0  # Components identified
        confidence += 0.2 if vuln_map.hardening_available else 0.0  # Hardening path exists
        reasoning.confidence_score = min(confidence, 1.0)
        
        logger.info("Generated reasoning for %s with confidence %.1f%%",
                   cve_id, reasoning.confidence_score * 100)
        
        return reasoning
    
    def _build_execution_phases(self,
                               plan_id: str,
                               controls: List[RemediationControl],
                               affected_systems: List[str],
                               mode: ExecutionMode) -> Dict[ExecutionPhase, List[RemediationStep]]:
        """Build execution phases"""
        phases = {}
        
        # Discovery phase
        discovery_step = RemediationStep(
            step_id=str(uuid4()),
            control=controls[0] if controls else None,
            system_id="all",
            command="Get-WmiObject -Class Win32_OperatingSystem; Get-Service",
            command_type="PowerShell",
            requires_admin=True,
            estimated_duration_seconds=30,
            status="pending"
        )
        phases[ExecutionPhase.DISCOVERY] = [discovery_step]
        
        # Validation phase
        validation_steps = []
        for i, control in enumerate(controls):
            for cmd in control.validation_commands:
                step = RemediationStep(
                    step_id=str(uuid4()),
                    control=control,
                    system_id="all",
                    command=cmd.get("command", ""),
                    command_type="PowerShell",
                    requires_admin=control.requires_admin,
                    estimated_duration_seconds=15,
                    status="pending"
                )
                validation_steps.append(step)
        phases[ExecutionPhase.VALIDATION] = validation_steps
        
        # Deployment phase - control per system
        deployment_steps = []
        for control in controls:
            for system_id in affected_systems:
                for cmd in control.commands:
                    step = RemediationStep(
                        step_id=str(uuid4()),
                        control=control,
                        system_id=system_id,
                        command=cmd.get("command", ""),
                        command_type=cmd.get("type", "PowerShell"),
                        requires_admin=control.requires_admin,
                        estimated_duration_seconds=60,
                        status="pending"
                    )
                    deployment_steps.append(step)
        phases[ExecutionPhase.DEPLOYMENT] = deployment_steps
        
        # Verification phase
        verification_steps = []
        for system_id in affected_systems:
            step = RemediationStep(
                step_id=str(uuid4()),
                control=controls[0] if controls else None,
                system_id=system_id,
                command="Get-HotFix; Get-EventLog -LogName System -Newest 20",
                command_type="PowerShell",
                requires_admin=True,
                estimated_duration_seconds=30,
                status="pending"
            )
            verification_steps.append(step)
        phases[ExecutionPhase.VERIFICATION] = verification_steps
        
        return phases
    
    def _save_reasoning(self, reasoning: ExecutionReasoning):
        """Save reasoning to execution database"""
        try:
            conn = sqlite3.connect(self.execution_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO execution_reasoning (reasoning_id, decision_id, cve_id, reasoning_json, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                str(uuid4()),
                reasoning.decision_id,
                reasoning.cve_id,
                json.dumps(reasoning.__dict__, default=str),
                datetime.utcnow()
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to save reasoning: %s", str(e))
    
    def _save_execution_plan(self, plan: ExecutionPlan):
        """Save execution plan to database"""
        try:
            conn = sqlite3.connect(self.execution_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO execution_plans 
                (plan_id, cve_id, decision_id, mode, status, affected_systems, total_controls, created_at, plan_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                plan.plan_id,
                plan.cve_id,
                plan.decision_id,
                plan.mode.value,
                plan.status,
                len(plan.affected_systems),
                len(plan.controls),
                plan.created_at,
                json.dumps(plan.__dict__, default=str)
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to save execution plan: %s", str(e))
    
    def execute_plan(self, plan: ExecutionPlan, 
                    mode: Optional[ExecutionMode] = None,
                    dry_run: bool = False) -> Dict[str, Any]:
        """
        Execute remediation plan
        
        Args:
            plan: ExecutionPlan to execute
            mode: Override plan mode (dry_run, sandbox, etc.)
            dry_run: If True, simulate without making changes
        
        Returns:
            Execution results dictionary
        """
        mode = mode or plan.mode
        logger.info("Executing plan %s in %s mode %s",
                   plan.plan_id, mode.value,
                   "(DRY RUN)" if dry_run else "")
        
        results = {
            "plan_id": plan.plan_id,
            "cve_id": plan.cve_id,
            "mode": mode.value,
            "dry_run": dry_run,
            "started": datetime.utcnow(),
            "phases": {},
            "summary": {}
        }
        
        for phase, steps in plan.phases.items():
            phase_result = self._execute_phase(phase, steps, dry_run)
            results["phases"][phase.value] = phase_result
        
        # Calculate summary
        total_steps = sum(len(steps) for steps in plan.phases.values())
        completed = sum(
            len([s for s in phase_result["steps"] if s["status"] == "completed"])
            for phase_result in results["phases"].values()
        )
        failed = sum(
            len([s for s in phase_result["steps"] if s["status"] == "failed"])
            for phase_result in results["phases"].values()
        )
        
        results["summary"] = {
            "total_steps": total_steps,
            "completed": completed,
            "failed": failed,
            "success_rate": completed / total_steps if total_steps > 0 else 0.0,
            "status": "success" if failed == 0 else "partial_failure" if completed > 0 else "failed"
        }
        
        logger.info("Plan %s completed: %d/%d steps successful",
                   plan.plan_id, completed, total_steps)
        
        return results
    
    def _execute_phase(self, phase: ExecutionPhase, 
                      steps: List[RemediationStep],
                      dry_run: bool = False) -> Dict[str, Any]:
        """Execute single phase"""
        logger.info("Executing phase: %s (%d steps)", phase.value, len(steps))
        
        phase_result = {
            "phase": phase.value,
            "steps": [],
            "status": "completed"
        }
        
        for step in steps:
            if dry_run:
                # Dry run - simulate successful execution
                result = {
                    "step_id": step.step_id,
                    "status": "completed",
                    "output": f"[DRY RUN] Would execute: {step.command[:50]}...",
                    "validated": True
                }
            else:
                # Real execution would happen here
                result = {
                    "step_id": step.step_id,
                    "status": "pending",  # Would be queued for execution
                    "output": None
                }
            
            phase_result["steps"].append(result)
        
        return phase_result


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize execution engine
    engine = ExecutionEngine()
    engine.load_catalogues()
    
    # Create mock decision output
    mock_decision = {
        "decision_id": "DEC-001",
        "cve_id": "CVE-2021-1234",
        "priority_level": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.85,
        "patch_available": True
    }
    
    # Generate remediation plan
    plan = engine.generate_remediation_plan(
        cve_id="CVE-2021-1234",
        decision_output=mock_decision,
        vulnerability_components=["SMB", "RCE"],
        affected_os="Windows 10",
        mode=ExecutionMode.DRY_RUN
    )
    
    print(f"\n✓ Remediation plan generated: {plan.plan_id}")
    print(f"  Controls: {len(plan.controls)}")
    print(f"  Affected Systems: {len(plan.affected_systems)}")
    print(f"  Phases: {len(plan.phases)}")
    
    # Execute in dry-run mode
    results = engine.execute_plan(plan, dry_run=True)
    print(f"\n✓ Execution completed (DRY RUN)")
    print(f"  Total Steps: {results['summary']['total_steps']}")
    print(f"  Completed: {results['summary']['completed']}")
    print(f"  Status: {results['summary']['status']}")

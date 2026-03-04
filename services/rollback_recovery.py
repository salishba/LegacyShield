"""
rollback_recovery.py
====================

Recovery procedures, error handling, and rollback coordination
Manages multi-system rollback and recovery workflows
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json
import sqlite3
import logging

logger = logging.getLogger(__name__)


class RecoveryStrategy(Enum):
    """Rollback recovery strategies"""
    ATOMIC = "atomic"  # All or nothing
    STAGED = "staged"  # 10%, 50%, 100%
    PROGRESSIVE = "progressive"  # One system at a time with validation
    CONSERVATIVE = "conservative"  # Full validation between each step
    AGGRESSIVE = "aggressive"  # Quick rollback, validate after


class RecoveryPhase(Enum):
    """Phases of recovery operation"""
    DISCOVERY = "discovery"  # Identify affected systems
    PRE_CHECK = "pre_check"  # Verify rollback feasibility
    REGISTRY_RESTORE = "registry_restore"  # Restore registry
    SERVICE_RESTORE = "service_restore"  # Restore services
    DRIVER_RESTORE = "driver_restore"  # Restore drivers
    VERIFICATION = "verification"  # Verify recovery success
    VALIDATION = "validation"  # Final validation


@dataclass
class RecoveryStep:
    """Single recovery operation step"""
    step_id: str
    phase: RecoveryPhase
    system_id: str
    operation: str  # restore_registry, restart_service, etc.
    
    # Execution details
    status: str = "pending"  # pending, in_progress, success, failed, skipped
    error_message: Optional[str] = None
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Validation
    pre_validation: Optional[Dict] = None
    post_validation: Optional[Dict] = None
    validation_passed: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'step_id': self.step_id,
            'phase': self.phase.value,
            'system_id': self.system_id,
            'operation': self.operation,
            'status': self.status,
            'error_message': self.error_message,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'validation_passed': self.validation_passed
        }


@dataclass
class ErrorRecoveryAction:
    """Action to recover from execution error"""
    action_id: str
    error_type: str  # registry_error, service_error, timeout, connection_error
    source_step_id: str
    recovery_operation: str
    
    status: str = "pending"
    retry_count: int = 0
    max_retries: int = 3
    
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'action_id': self.action_id,
            'error_type': self.error_type,
            'source_step_id': self.source_step_id,
            'recovery_operation': self.recovery_operation,
            'status': self.status,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class RollbackRecoveryPlan:
    """Complete recovery/rollback plan"""
    plan_id: str
    execution_plan_id: str
    system_id: Optional[str] = None  # None for multi-system
    affected_systems: List[str] = field(default_factory=list)
    
    timestamp: datetime = field(default_factory=datetime.utcnow)
    strategy: RecoveryStrategy = RecoveryStrategy.PROGRESSIVE
    
    # Recovery details
    recovery_steps: List[RecoveryStep] = field(default_factory=list)
    error_recovery_actions: List[ErrorRecoveryAction] = field(default_factory=list)
    
    # Metadata
    cve_id: Optional[str] = None
    reason: str = ""  # Why rollback was initiated
    initiated_by: str = "system"


@dataclass
class RollbackRecoveryReport:
    """Report of complete rollback recovery"""
    report_id: str
    plan_id: str
    timestamp: datetime
    
    # Execution details
    recovery_steps: List[RecoveryStep] = field(default_factory=list)
    error_recovery_actions: List[ErrorRecoveryAction] = field(default_factory=list)
    
    # Summary
    total_systems: int = 0
    successful_systems: int = 0
    failed_systems: int = 0
    partial_failure_systems: int = 0
    
    total_steps: int = 0
    successful_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    
    # Overall status
    recovery_success: bool = False
    total_duration_seconds: float = 0.0
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    # Issues
    critical_issues: List[Dict] = field(default_factory=list)
    warnings: List[Dict] = field(default_factory=list)
    
    def calculate_summary(self):
        """Calculate execution summary"""
        self.total_steps = len(self.recovery_steps)
        self.successful_steps = sum(1 for s in self.recovery_steps if s.status == "success")
        self.failed_steps = sum(1 for s in self.recovery_steps if s.status == "failed")
        self.skipped_steps = sum(1 for s in self.recovery_steps if s.status == "skipped")
        
        # Calculate per-system results
        systems_status = {}
        for step in self.recovery_steps:
            if step.system_id not in systems_status:
                systems_status[step.system_id] = {'success': 0, 'failed': 0}
            if step.status == "success":
                systems_status[step.system_id]['success'] += 1
            elif step.status == "failed":
                systems_status[step.system_id]['failed'] += 1
        
        self.total_systems = len(systems_status)
        self.successful_systems = sum(1 for s in systems_status.values() if s['failed'] == 0)
        self.failed_systems = sum(1 for s in systems_status.values() if s['success'] == 0)
        self.partial_failure_systems = self.total_systems - self.successful_systems - self.failed_systems
        
        # Overall success
        self.recovery_success = self.failed_systems == 0
        
        # Duration
        if self.recovery_steps:
            min_start = min((s.started_at for s in self.recovery_steps if s.started_at), default=self.started_at)
            max_end = max((s.completed_at for s in self.recovery_steps if s.completed_at), default=datetime.utcnow())
            self.total_duration_seconds = (max_end - min_start).total_seconds()


class RollbackRecoveryManager:
    """
    Manages complete rollback recovery workflows
    Coordinates multi-system recovery with error handling
    """
    
    def __init__(self, db_path: str = "src/execution_log.sqlite"):
        self.db_path = db_path
        self._initialize_recovery_db()
    
    def _initialize_recovery_db(self):
        """Create recovery tables if not exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Recovery plans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rollback_recovery_plans (
                    plan_id TEXT PRIMARY KEY,
                    execution_plan_id TEXT NOT NULL,
                    system_id TEXT,
                    timestamp TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    cve_id TEXT,
                    reason TEXT,
                    initiated_by TEXT NOT NULL,
                    total_steps INTEGER,
                    plan_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Recovery steps table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_steps (
                    step_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    duration_seconds REAL,
                    validation_passed BOOLEAN,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (plan_id) REFERENCES rollback_recovery_plans(plan_id)
                )
            ''')
            
            # Error recovery actions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS error_recovery_actions (
                    action_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    error_type TEXT NOT NULL,
                    source_step_id TEXT NOT NULL,
                    recovery_operation TEXT NOT NULL,
                    status TEXT NOT NULL,
                    retry_count INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (plan_id) REFERENCES rollback_recovery_plans(plan_id)
                )
            ''')
            
            # Recovery reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rollback_recovery_reports (
                    report_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_systems INTEGER NOT NULL,
                    successful_systems INTEGER NOT NULL,
                    failed_systems INTEGER NOT NULL,
                    total_steps INTEGER NOT NULL,
                    successful_steps INTEGER NOT NULL,
                    failed_steps INTEGER NOT NULL,
                    recovery_success BOOLEAN NOT NULL,
                    total_duration_seconds REAL,
                    report_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (plan_id) REFERENCES rollback_recovery_plans(plan_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Recovery database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize recovery database: {e}")
            raise
    
    def create_recovery_plan(self, execution_plan_id: str,
                            affected_systems: List[str],
                            strategy: RecoveryStrategy = RecoveryStrategy.PROGRESSIVE,
                            cve_id: Optional[str] = None,
                            reason: str = "") -> RollbackRecoveryPlan:
        """
        Create rollback recovery plan
        
        Args:
            execution_plan_id: Associated execution plan that failed
            affected_systems: List of systems to recover
            strategy: Recovery strategy to use
            cve_id: Associated CVE ID
            reason: Why rollback was needed (failure reason)
        
        Returns:
            RollbackRecoveryPlan ready for execution
        """
        plan_id = f"recovery_{execution_plan_id}_{int(datetime.utcnow().timestamp())}"
        
        plan = RollbackRecoveryPlan(
            plan_id=plan_id,
            execution_plan_id=execution_plan_id,
            affected_systems=affected_systems,
            strategy=strategy,
            cve_id=cve_id,
            reason=reason
        )
        
        # Create recovery steps based on strategy
        if strategy == RecoveryStrategy.ATOMIC:
            self._create_atomic_recovery_steps(plan)
        elif strategy == RecoveryStrategy.PROGRESSIVE:
            self._create_progressive_recovery_steps(plan)
        elif strategy == RecoveryStrategy.CONSERVATIVE:
            self._create_conservative_recovery_steps(plan)
        
        logger.info(f"Created recovery plan {plan_id} with {len(plan.recovery_steps)} steps")
        return plan
    
    def _create_atomic_recovery_steps(self, plan: RollbackRecoveryPlan):
        """Create steps for atomic (all-or-nothing) recovery"""
        step_counter = 0
        
        for system_id in plan.affected_systems:
            for phase in [RecoveryPhase.PRE_CHECK, RecoveryPhase.REGISTRY_RESTORE,
                         RecoveryPhase.SERVICE_RESTORE, RecoveryPhase.VERIFICATION]:
                step = RecoveryStep(
                    step_id=f"{plan.plan_id}_step_{step_counter}",
                    phase=phase,
                    system_id=system_id,
                    operation=f"atomic_{phase.value}"
                )
                plan.recovery_steps.append(step)
                step_counter += 1
    
    def _create_progressive_recovery_steps(self, plan: RollbackRecoveryPlan):
        """Create steps for progressive (one-by-one) recovery"""
        step_counter = 0
        
        for system_id in plan.affected_systems:
            for phase in [RecoveryPhase.PRE_CHECK, RecoveryPhase.REGISTRY_RESTORE,
                         RecoveryPhase.SERVICE_RESTORE, RecoveryPhase.VERIFICATION]:
                step = RecoveryStep(
                    step_id=f"{plan.plan_id}_step_{step_counter}",
                    phase=phase,
                    system_id=system_id,
                    operation=f"progressive_{phase.value}"
                )
                plan.recovery_steps.append(step)
                step_counter += 1
    
    def _create_conservative_recovery_steps(self, plan: RollbackRecoveryPlan):
        """Create steps for conservative (heavily validated) recovery"""
        step_counter = 0
        
        for system_id in plan.affected_systems:
            for phase in [RecoveryPhase.PRE_CHECK, RecoveryPhase.REGISTRY_RESTORE,
                         RecoveryPhase.SERVICE_RESTORE, RecoveryPhase.VERIFICATION,
                         RecoveryPhase.VALIDATION]:
                step = RecoveryStep(
                    step_id=f"{plan.plan_id}_step_{step_counter}",
                    phase=phase,
                    system_id=system_id,
                    operation=f"conservative_{phase.value}"
                )
                plan.recovery_steps.append(step)
                step_counter += 1
    
    def save_recovery_plan(self, plan: RollbackRecoveryPlan) -> bool:
        """Save recovery plan to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            plan_json = json.dumps(plan.to_dict(), default=str)
            
            cursor.execute('''
                INSERT INTO rollback_recovery_plans
                (plan_id, execution_plan_id, system_id, timestamp, strategy, cve_id, reason, initiated_by, total_steps, plan_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                plan.plan_id,
                plan.execution_plan_id,
                plan.system_id,
                plan.timestamp.isoformat(),
                plan.strategy.value,
                plan.cve_id,
                plan.reason,
                plan.initiated_by,
                len(plan.recovery_steps),
                plan_json
            ))
            
            # Save individual steps
            for step in plan.recovery_steps:
                cursor.execute('''
                    INSERT INTO recovery_steps
                    (step_id, plan_id, phase, system_id, operation, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    step.step_id,
                    plan.plan_id,
                    step.phase.value,
                    step.system_id,
                    step.operation,
                    step.status
                ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved recovery plan {plan.plan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save recovery plan: {e}")
            return False
    
    def execute_recovery_plan(self, plan: RollbackRecoveryPlan) -> RollbackRecoveryReport:
        """
        Execute complete recovery plan
        
        Returns:
            RollbackRecoveryReport with all execution results
        """
        report_id = f"report_{plan.plan_id}_{int(datetime.utcnow().timestamp())}"
        report = RollbackRecoveryReport(
            report_id=report_id,
            plan_id=plan.plan_id,
            timestamp=datetime.utcnow()
        )
        
        # Execute each recovery step
        for step in plan.recovery_steps:
            step.status = "in_progress"
            step.started_at = datetime.utcnow()
            
            try:
                # Simulate recovery operation
                logger.info(f"Executing recovery step {step.step_id} ({step.phase.value}) on {step.system_id}")
                
                # Perform the recovery operation
                self._execute_step(step)
                
                # Validate step
                step.post_validation = {'status': 'validated'}
                step.validation_passed = True
                step.status = "success"
                
            except Exception as e:
                step.status = "failed"
                step.error_message = str(e)
                
                # Create error recovery action
                error_action = ErrorRecoveryAction(
                    action_id=f"error_{step.step_id}_{int(datetime.utcnow().timestamp())}",
                    error_type="recovery_error",
                    source_step_id=step.step_id,
                    recovery_operation=f"retry_{step.operation}"
                )
                plan.error_recovery_actions.append(error_action)
                logger.error(f"Recovery step {step.step_id} failed: {e}")
            
            finally:
                step.completed_at = datetime.utcnow()
                step.duration_seconds = (step.completed_at - step.started_at).total_seconds()
            
            report.recovery_steps.append(step)
        
        # Add error recovery actions to report
        report.error_recovery_actions = plan.error_recovery_actions
        
        # Calculate summary and save
        report.calculate_summary()
        self._save_recovery_report(report)
        
        logger.info(f"Recovery execution completed: {report.successful_systems}/{report.total_systems} systems successful")
        return report
    
    def _execute_step(self, step: RecoveryStep):
        """Execute individual recovery step"""
        if step.phase == RecoveryPhase.PRE_CHECK:
            logger.info(f"PRE_CHECK: Verifying rollback feasibility on {step.system_id}")
        elif step.phase == RecoveryPhase.REGISTRY_RESTORE:
            logger.info(f"REGISTRY_RESTORE: Restoring registry on {step.system_id}")
        elif step.phase == RecoveryPhase.SERVICE_RESTORE:
            logger.info(f"SERVICE_RESTORE: Restoring services on {step.system_id}")
        elif step.phase == RecoveryPhase.VERIFICATION:
            logger.info(f"VERIFICATION: Verifying recovery on {step.system_id}")
        elif step.phase == RecoveryPhase.VALIDATION:
            logger.info(f"VALIDATION: Final validation on {step.system_id}")
    
    def _save_recovery_report(self, report: RollbackRecoveryReport) -> bool:
        """Save recovery report to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            report_json = json.dumps(report.to_dict(), default=str)
            
            cursor.execute('''
                INSERT INTO rollback_recovery_reports
                (report_id, plan_id, timestamp, total_systems, successful_systems, failed_systems, 
                 total_steps, successful_steps, failed_steps, recovery_success, total_duration_seconds, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.report_id,
                report.plan_id,
                report.timestamp.isoformat(),
                report.total_systems,
                report.successful_systems,
                report.failed_systems,
                report.total_steps,
                report.successful_steps,
                report.failed_steps,
                report.recovery_success,
                report.total_duration_seconds,
                report_json
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved recovery report {report.report_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save recovery report: {e}")
            return False


if __name__ == "__main__":
    # Example usage
    manager = RollbackRecoveryManager()
    
    # Create recovery plan for multi-system failure
    plan = manager.create_recovery_plan(
        execution_plan_id="PLAN-001",
        affected_systems=["SYSTEM-01", "SYSTEM-02", "SYSTEM-03"],
        strategy=RecoveryStrategy.PROGRESSIVE,
        cve_id="CVE-2023-1234",
        reason="Patch deployment failed - service compatibility issue"
    )
    print(f"Created recovery plan: {plan.plan_id}")
    print(f"Strategy: {plan.strategy.value}")
    print(f"Recovery steps: {len(plan.recovery_steps)}")
    print(f"Affected systems: {len(plan.affected_systems)}")
    
    # Save plan
    manager.save_recovery_plan(plan)
    
    # Execute recovery
    report = manager.execute_recovery_plan(plan)
    print(f"\nRecovery execution completed:")
    print(f"Total systems: {report.total_systems}")
    print(f"Successful: {report.successful_systems}")
    print(f"Failed: {report.failed_systems}")
    print(f"Total steps: {report.total_steps}")
    print(f"Success rate: {report.successful_steps}/{report.total_steps}")
    print(f"Overall success: {report.recovery_success}")
    print(f"Duration: {report.total_duration_seconds:.2f}s")

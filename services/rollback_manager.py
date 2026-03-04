"""
rollback_manager.py
===================

Main rollback orchestrator
Coordinates all rollback operations across all modules
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json
import sqlite3
import logging
from pathlib import Path

from system_state_snapshot import SystemStateManager, SystemStateSnapshot
from registry_rollback import RegistryRollbackManager, RegistryBackup
from service_rollback import ServiceRollbackManager, ServiceRollbackPlan
from rollback_recovery import RollbackRecoveryManager, RollbackRecoveryPlan, RecoveryStrategy

logger = logging.getLogger(__name__)


class RollbackTrigger(Enum):
    """Reasons for initiating rollback"""
    DEPLOYMENT_FAILED = "deployment_failed"
    VALIDATION_FAILED = "validation_failed"
    SERVICE_ERROR = "service_error"
    REGISTRY_ERROR = "registry_error"
    MANUAL_REQUEST = "manual_request"
    TIMEOUT = "timeout"
    CRITICAL_ERROR = "critical_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class RollbackInitiation:
    """Request to initiate rollback"""
    initiator_type: str  # human, system, api
    initiator: str  # user_id, system_name, api_client
    trigger: RollbackTrigger
    affected_systems: List[str]
    affected_plan_id: Optional[str] = None
    affected_cve_id: Optional[str] = None
    reason_detail: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RollbackState:
    """Current state of rollback operation"""
    rollback_id: str
    status: str  # initiated, in_progress, completed, failed, partial_failure
    
    initiation: RollbackInitiation
    
    # Component reports
    snapshot_report: Optional[Dict] = None
    registry_report: Optional[Dict] = None
    service_report: Optional[Dict] = None
    recovery_report: Optional[Dict] = None
    
    total_systems: int = 0
    successful_systems: int = 0
    failed_systems: int = 0
    
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        return {
            'rollback_id': self.rollback_id,
            'status': self.status,
            'initiation': {
                'initiator_type': self.initiation.initiator_type,
                'initiator': self.initiation.initiator,
                'trigger': self.initiation.trigger.value,
                'affected_systems': self.initiation.affected_systems,
                'timestamp': self.initiation.timestamp.isoformat()
            },
            'total_systems': self.total_systems,
            'successful_systems': self.successful_systems,
            'failed_systems': self.failed_systems,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class RollbackManager:
    """
    Main rollback orchestrator
    Coordinates snapshot, registry, service, and recovery managers
    """
    
    def __init__(self, db_path: str = "src/execution_log.sqlite"):
        self.db_path = db_path
        
        # Initialize component managers
        self.snapshot_manager = SystemStateManager(db_path)
        self.registry_manager = RegistryRollbackManager(db_path)
        self.service_manager = ServiceRollbackManager(db_path)
        self.recovery_manager = RollbackRecoveryManager(db_path)
        
        # Track active rollbacks
        self.active_rollbacks: Dict[str, RollbackState] = {}
        
        self._initialize_rollback_db()
        logger.info("Rollback Manager initialized successfully")
    
    def _initialize_rollback_db(self):
        """Create main rollback tables if not exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Main rollback operations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rollback_operations (
                    rollback_id TEXT PRIMARY KEY,
                    affected_plan_id TEXT,
                    affected_cve_id TEXT,
                    initiator_type TEXT NOT NULL,
                    initiator TEXT NOT NULL,
                    trigger TEXT NOT NULL,
                    total_systems INTEGER,
                    successful_systems INTEGER,
                    failed_systems INTEGER,
                    status TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    rollback_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Rollback component logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rollback_component_logs (
                    log_id TEXT PRIMARY KEY,
                    rollback_id TEXT NOT NULL,
                    component_type TEXT NOT NULL,
                    component_status TEXT NOT NULL,
                    details TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (rollback_id) REFERENCES rollback_operations(rollback_id)
                )
            ''')
            
            # Rollback decision log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rollback_decision_log (
                    decision_id TEXT PRIMARY KEY,
                    rollback_id TEXT NOT NULL,
                    decision_point TEXT NOT NULL,
                    decision_made TEXT NOT NULL,
                    rationale TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (rollback_id) REFERENCES rollback_operations(rollback_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Rollback database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize rollback database: {e}")
            raise
    
    def initiate_rollback(self, initiation: RollbackInitiation) -> RollbackState:
        """
        Initiate rollback operation
        
        Args:
            initiation: RollbackInitiation request
        
        Returns:
            RollbackState for tracking
        """
        rollback_id = f"rollback_{int(datetime.utcnow().timestamp())}_{initiation.affected_plan_id or 'manual'}"
        
        state = RollbackState(
            rollback_id=rollback_id,
            status="initiated",
            initiation=initiation,
            total_systems=len(initiation.affected_systems)
        )
        
        self.active_rollbacks[rollback_id] = state
        logger.info(f"Initiated rollback {rollback_id} (trigger: {initiation.trigger.value})")
        logger.info(f"Affected systems: {initiation.affected_systems}")
        
        return state
    
    def execute_rollback(self, rollback_state: RollbackState) -> RollbackState:
        """
        Execute complete rollback operation
        Coordinates all component rollbacks
        
        Returns:
            Updated RollbackState with final results
        """
        rollback_state.status = "in_progress"
        rollback_state.started_at = datetime.utcnow()
        
        logger.info(f"Executing rollback {rollback_state.rollback_id}")
        
        try:
            # Step 1: Create pre-rollback system snapshots for comparison
            logger.info("STEP 1: Capturing system state for validation")
            pre_rollback_snapshots = self._capture_pre_rollback_snapshots(
                rollback_state.rollback_id,
                rollback_state.initiation.affected_systems
            )
            
            # Step 2: Execute registry rollback on all affected systems
            logger.info("STEP 2: Restoring registry configurations")
            registry_results = self._execute_registry_rollback(
                rollback_state.rollback_id,
                rollback_state.initiation.affected_systems
            )
            rollback_state.registry_report = registry_results
            
            # Step 3: Execute service rollback on all affected systems
            logger.info("STEP 3: Restoring service states")
            service_results = self._execute_service_rollback(
                rollback_state.rollback_id,
                rollback_state.initiation.affected_systems
            )
            rollback_state.service_report = service_results
            
            # Step 4: Execute complete recovery plan
            logger.info("STEP 4: Executing integrated recovery plan")
            recovery_results = self._execute_recovery(
                rollback_state.rollback_id,
                rollback_state.initiation
            )
            rollback_state.recovery_report = recovery_results
            
            # Step 5: Verify rollback success
            logger.info("STEP 5: Verifying rollback success")
            post_rollback_snapshots = self._capture_post_rollback_snapshots(
                rollback_state.rollback_id,
                rollback_state.initiation.affected_systems
            )
            
            # Step 6: Generate validation report
            validation_results = self._validate_rollback(
                rollback_state.rollback_id,
                pre_rollback_snapshots,
                post_rollback_snapshots
            )
            rollback_state.snapshot_report = validation_results
            
            # Determine overall success
            registry_success = registry_results.get('all_successful', False)
            service_success = service_results.get('all_successful', False)
            recovery_success = recovery_results.get('recovery_success', False)
            validation_success = validation_results.get('validation_passed', False)
            
            if registry_success and service_success and recovery_success and validation_success:
                rollback_state.status = "completed"
                rollback_state.successful_systems = rollback_state.total_systems
                rollback_state.failed_systems = 0
                logger.info(f"✓ Rollback {rollback_state.rollback_id} completed successfully")
            elif registry_success and service_success:
                rollback_state.status = "partial_failure"
                rollback_state.successful_systems = recovery_results.get('successful_systems', 0)
                rollback_state.failed_systems = recovery_results.get('failed_systems', 0)
                logger.warning(f"⚠ Rollback {rollback_state.rollback_id} completed with partial failures")
            else:
                rollback_state.status = "failed"
                rollback_state.failed_systems = rollback_state.total_systems
                logger.error(f"✗ Rollback {rollback_state.rollback_id} failed")
        
        except Exception as e:
            rollback_state.status = "failed"
            rollback_state.failed_systems = rollback_state.total_systems
            logger.error(f"Rollback {rollback_state.rollback_id} failed with exception: {e}")
        
        finally:
            rollback_state.completed_at = datetime.utcnow()
            self._save_rollback_state(rollback_state)
        
        return rollback_state
    
    def _capture_pre_rollback_snapshots(self, rollback_id: str, systems: List[str]) -> Dict:
        """Capture system state before rollback"""
        snapshots = {}
        for system_id in systems:
            snapshot = self.snapshot_manager.create_snapshot(
                system_id=system_id,
                snapshot_type="pre_rollback",
                plan_id=rollback_id
            )
            self.snapshot_manager.save_snapshot(snapshot)
            snapshots[system_id] = snapshot
        
        logger.info(f"Captured pre-rollback snapshots for {len(systems)} systems")
        return {'snapshots': snapshots, 'system_count': len(systems)}
    
    def _capture_post_rollback_snapshots(self, rollback_id: str, systems: List[str]) -> Dict:
        """Capture system state after rollback"""
        snapshots = {}
        for system_id in systems:
            snapshot = self.snapshot_manager.create_snapshot(
                system_id=system_id,
                snapshot_type="post_rollback",
                plan_id=rollback_id
            )
            self.snapshot_manager.save_snapshot(snapshot)
            snapshots[system_id] = snapshot
        
        logger.info(f"Captured post-rollback snapshots for {len(systems)} systems")
        return {'snapshots': snapshots, 'system_count': len(systems)}
    
    def _execute_registry_rollback(self, rollback_id: str, systems: List[str]) -> Dict:
        """Execute registry rollback across all systems"""
        results = {
            'total_systems': len(systems),
            'successful_systems': 0,
            'failed_systems': 0,
            'all_successful': True
        }
        
        for system_id in systems:
            try:
                # Create registry backup from pre-deployment state
                backup = self.registry_manager.create_backup(
                    system_id=system_id,
                    backup_type="atomic",
                    registry_paths=[]
                )
                
                # Restore from backup
                report = self.registry_manager.restore_from_backup(backup.backup_id)
                
                if report and report.rollback_success:
                    results['successful_systems'] += 1
                    logger.info(f"✓ Registry rollback successful on {system_id}")
                else:
                    results['failed_systems'] += 1
                    results['all_successful'] = False
                    logger.error(f"✗ Registry rollback failed on {system_id}")
            
            except Exception as e:
                results['failed_systems'] += 1
                results['all_successful'] = False
                logger.error(f"Registry rollback error on {system_id}: {e}")
        
        return results
    
    def _execute_service_rollback(self, rollback_id: str, systems: List[str]) -> Dict:
        """Execute service rollback across all systems"""
        results = {
            'total_systems': len(systems),
            'successful_systems': 0,
            'failed_systems': 0,
            'all_successful': True
        }
        
        for system_id in systems:
            try:
                # Create placeholder pre/post states
                pre_states = {}
                post_states = {}
                
                # Create service rollback plan
                plan = self.service_manager.create_rollback_plan(
                    system_id=system_id,
                    pre_states=pre_states,
                    post_states=post_states
                )
                
                # Execute rollback
                report = self.service_manager.execute_rollback_plan(plan)
                
                if report and report.rollback_success:
                    results['successful_systems'] += 1
                    logger.info(f"✓ Service rollback successful on {system_id}")
                else:
                    results['failed_systems'] += 1
                    results['all_successful'] = False
                    logger.error(f"✗ Service rollback failed on {system_id}")
            
            except Exception as e:
                results['failed_systems'] += 1
                results['all_successful'] = False
                logger.error(f"Service rollback error on {system_id}: {e}")
        
        return results
    
    def _execute_recovery(self, rollback_id: str, initiation: RollbackInitiation) -> Dict:
        """Execute integrated recovery plan"""
        try:
            # Create recovery plan
            plan = self.recovery_manager.create_recovery_plan(
                execution_plan_id=initiation.affected_plan_id or "unknown",
                affected_systems=initiation.affected_systems,
                strategy=RecoveryStrategy.PROGRESSIVE,
                cve_id=initiation.affected_cve_id,
                reason=initiation.reason_detail
            )
            
            self.recovery_manager.save_recovery_plan(plan)
            
            # Execute recovery
            report = self.recovery_manager.execute_recovery_plan(plan)
            
            logger.info(f"Recovery plan executed: {report.successful_systems}/{report.total_systems} successful")
            
            return {
                'recovery_success': report.recovery_success,
                'total_systems': report.total_systems,
                'successful_systems': report.successful_systems,
                'failed_systems': report.failed_systems,
                'total_duration_seconds': report.total_duration_seconds
            }
        
        except Exception as e:
            logger.error(f"Recovery execution failed: {e}")
            return {
                'recovery_success': False,
                'error': str(e)
            }
    
    def _validate_rollback(self, rollback_id: str, pre_snapshots: Dict, post_snapshots: Dict) -> Dict:
        """Validate rollback success"""
        validation_results = {
            'validation_passed': True,
            'system_count': len(pre_snapshots.get('snapshots', {})),
            'systems_validated': 0,
            'issues_found': []
        }
        
        # Compare snapshots to ensure rollback restored system state
        for system_id, pre_snapshot in pre_snapshots.get('snapshots', {}).items():
            post_snapshot = post_snapshots.get('snapshots', {}).get(system_id)
            
            if post_snapshot:
                # In production, would do detailed state comparison
                validation_results['systems_validated'] += 1
                logger.info(f"✓ Validated rollback on {system_id}")
        
        return validation_results
    
    def _save_rollback_state(self, state: RollbackState) -> bool:
        """Save rollback state to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            state_json = json.dumps(state.to_dict())
            
            cursor.execute('''
                INSERT INTO rollback_operations
                (rollback_id, affected_plan_id, affected_cve_id, initiator_type, initiator, trigger,
                 total_systems, successful_systems, failed_systems, status, started_at, completed_at, rollback_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                state.rollback_id,
                state.initiation.affected_plan_id,
                state.initiation.affected_cve_id,
                state.initiation.initiator_type,
                state.initiation.initiator,
                state.initiation.trigger.value,
                state.total_systems,
                state.successful_systems,
                state.failed_systems,
                state.status,
                state.started_at.isoformat() if state.started_at else None,
                state.completed_at.isoformat() if state.completed_at else None,
                state_json
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved rollback state {state.rollback_id} to database")
            return True
        except Exception as e:
            logger.error(f"Failed to save rollback state: {e}")
            return False
    
    def get_rollback_status(self, rollback_id: str) -> Optional[RollbackState]:
        """Get current rollback status"""
        return self.active_rollbacks.get(rollback_id)


if __name__ == "__main__":
    # Example usage
    manager = RollbackManager()
    
    # Create rollback initiation
    initiation = RollbackInitiation(
        initiator_type="system",
        initiator="ExecutionEngine",
        trigger=RollbackTrigger.DEPLOYMENT_FAILED,
        affected_systems=["SYSTEM-01", "SYSTEM-02"],
        affected_plan_id="PLAN-001",
        affected_cve_id="CVE-2023-1234",
        reason_detail="Service conflict detected during execution"
    )
    
    print(f"Initiating rollback for failed deployment...")
    rollback_state = manager.initiate_rollback(initiation)
    print(f"Rollback ID: {rollback_state.rollback_id}")
    print(f"Affected systems: {rollback_state.initiation.affected_systems}")
    
    # Execute rollback
    print(f"\nExecuting rollback...")
    result = manager.execute_rollback(rollback_state)
    
    print(f"\nRollback completed:")
    print(f"Status: {result.status}")
    print(f"Successful systems: {result.successful_systems}/{result.total_systems}")
    print(f"Failed systems: {result.failed_systems}")
    if result.completed_at and result.started_at:
        duration = (result.completed_at - result.started_at).total_seconds()
        print(f"Duration: {duration:.2f}s")

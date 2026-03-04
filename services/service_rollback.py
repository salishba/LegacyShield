"""
service_rollback.py
===================

Handles service state management and recovery during rollback
Manages service startup/stop, configuration, and dependencies
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime
import json
import sqlite3
import logging

logger = logging.getLogger(__name__)


class ServiceStatus(Enum):
    """Windows service status"""
    RUNNING = "Running"
    STOPPED = "Stopped"
    PAUSED = "Paused"
    STARTING = "Starting"
    STOPPING = "Stopping"
    UNKNOWN = "Unknown"


class ServiceStartupType(Enum):
    """Windows service startup types"""
    AUTO = "Automatic"
    MANUAL = "Manual"
    DISABLED = "Disabled"
    AUTO_DELAYED = "Automatic (Delayed Start)"
    BOOT = "Boot"
    SYSTEM = "System"


@dataclass
class ServiceSnapshot:
    """Service state at specific point in time"""
    service_name: str
    display_name: str
    status: ServiceStatus
    startup_type: ServiceStartupType
    
    # Service details
    executable_path: Optional[str] = None
    service_account: str = "LocalSystem"
    dependencies: List[str] = field(default_factory=list)
    dependent_services: List[str] = field(default_factory=list)
    
    # Service configuration
    error_control: str = "critical"  # critical, severe, ignorable
    service_type: str = "own_process"  # own_process, share_process, kernel_driver
    
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'service_name': self.service_name,
            'display_name': self.display_name,
            'status': self.status.value,
            'startup_type': self.startup_type.value,
            'executable_path': self.executable_path,
            'service_account': self.service_account,
            'dependencies': self.dependencies,
            'dependent_services': self.dependent_services,
            'error_control': self.error_control,
            'service_type': self.service_type,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ServiceRestoreAction:
    """Action to restore service to previous state"""
    action_id: str
    service_name: str
    action_type: str  # start, stop, restart, set_startup_type, set_account
    
    from_state: ServiceSnapshot
    to_state: ServiceSnapshot
    
    status: str = "pending"  # pending, in_progress, success, failed
    error_message: Optional[str] = None
    duration_seconds: float = 0.0
    
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'action_id': self.action_id,
            'service_name': self.service_name,
            'action_type': self.action_type,
            'from_state': self.from_state.to_dict(),
            'to_state': self.to_state.to_dict(),
            'status': self.status,
            'error_message': self.error_message,
            'duration_seconds': self.duration_seconds,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ServiceRollbackPlan:
    """Plan for service recovery/rollback"""
    plan_id: str
    system_id: str
    timestamp: datetime
    
    # Pre and post-remediation states
    pre_remediation_states: Dict[str, ServiceSnapshot] = field(default_factory=dict)
    post_remediation_states: Dict[str, ServiceSnapshot] = field(default_factory=dict)
    
    # Actions needed
    restore_actions: List[ServiceRestoreAction] = field(default_factory=list)
    
    # Metadata
    cve_id: Optional[str] = None
    plan_id_ref: Optional[str] = None
    description: str = ""


@dataclass
class ServiceRollbackReport:
    """Report of service rollback execution"""
    report_id: str
    plan_id: str
    system_id: str
    timestamp: datetime
    
    # Results
    restore_actions: List[ServiceRestoreAction] = field(default_factory=list)
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    partial_failures: List[Dict] = field(default_factory=list)
    
    # Status
    rollback_success: bool = False
    total_duration_seconds: float = 0.0
    error_summary: str = ""
    
    def calculate_summary(self):
        """Calculate action summary"""
        self.total_actions = len(self.restore_actions)
        self.successful_actions = sum(1 for a in self.restore_actions if a.status == "success")
        self.failed_actions = sum(1 for a in self.restore_actions if a.status == "failed")
        self.rollback_success = self.failed_actions == 0
        self.total_duration_seconds = sum(a.duration_seconds for a in self.restore_actions)


class ServiceRollbackManager:
    """
    Manages service state snapshots and recovery procedures
    """
    
    def __init__(self, db_path: str = "src/execution_log.sqlite"):
        self.db_path = db_path
        self._initialize_service_db()
        self.service_snapshots = {}
    
    def _initialize_service_db(self):
        """Create service rollback tables if not exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Service snapshots table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    system_id TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    plan_id TEXT,
                    cve_id TEXT,
                    snapshot_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Service rollback plans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_rollback_plans (
                    plan_id TEXT PRIMARY KEY,
                    system_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    cve_id TEXT,
                    execution_plan_id TEXT,
                    description TEXT,
                    total_actions INTEGER,
                    plan_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Service restore actions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_restore_actions (
                    action_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    duration_seconds REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (report_id) REFERENCES service_rollback_reports(report_id),
                    FOREIGN KEY (plan_id) REFERENCES service_rollback_plans(plan_id)
                )
            ''')
            
            # Service rollback reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_rollback_reports (
                    report_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_actions INTEGER NOT NULL,
                    successful_actions INTEGER NOT NULL,
                    failed_actions INTEGER NOT NULL,
                    rollback_success BOOLEAN NOT NULL,
                    total_duration_seconds REAL,
                    error_summary TEXT,
                    report_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (plan_id) REFERENCES service_rollback_plans(plan_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Service rollback database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize service rollback database: {e}")
            raise
    
    def snapshot_service(self, system_id: str, service_name: str,
                        display_name: str, status: ServiceStatus,
                        startup_type: ServiceStartupType,
                        snapshot_type: str = "pre_remediation",
                        plan_id: Optional[str] = None,
                        cve_id: Optional[str] = None) -> ServiceSnapshot:
        """
        Create snapshot of service state
        
        Args:
            system_id: System identifier
            service_name: Windows service name
            display_name: Service display name
            status: Current service status
            startup_type: Service startup type
            snapshot_type: pre_remediation, post_remediation, verification
            plan_id: Associated execution plan
            cve_id: Associated CVE
        
        Returns:
            ServiceSnapshot object
        """
        snapshot_id = f"{system_id}_{service_name}_{snapshot_type}_{int(datetime.utcnow().timestamp())}"
        
        snapshot = ServiceSnapshot(
            service_name=service_name,
            display_name=display_name,
            status=status,
            startup_type=startup_type
        )
        
        # Store for reference
        self.service_snapshots[snapshot_id] = snapshot
        logger.info(f"Created service snapshot {snapshot_id} ({snapshot_type})")
        
        return snapshot
    
    def save_snapshot(self, system_id: str, service_name: str, snapshot: ServiceSnapshot,
                     snapshot_type: str, plan_id: Optional[str] = None,
                     cve_id: Optional[str] = None) -> bool:
        """Save service snapshot to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            snapshot_id = f"{system_id}_{service_name}_{snapshot_type}_{int(datetime.utcnow().timestamp())}"
            snapshot_json = json.dumps(snapshot.to_dict())
            
            cursor.execute('''
                INSERT INTO service_snapshots
                (snapshot_id, system_id, service_name, timestamp, snapshot_type, plan_id, cve_id, snapshot_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                snapshot_id,
                system_id,
                service_name,
                snapshot.timestamp.isoformat(),
                snapshot_type,
                plan_id,
                cve_id,
                snapshot_json
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved service snapshot {snapshot_id} to database")
            return True
        except Exception as e:
            logger.error(f"Failed to save service snapshot: {e}")
            return False
    
    def create_rollback_plan(self, system_id: str,
                            pre_states: Dict[str, ServiceSnapshot],
                            post_states: Dict[str, ServiceSnapshot],
                            cve_id: Optional[str] = None,
                            plan_id_ref: Optional[str] = None) -> ServiceRollbackPlan:
        """
        Create service rollback plan from pre/post snapshots
        
        Args:
            system_id: System identifier
            pre_states: Dict of service_name -> pre-remediation snapshot
            post_states: Dict of service_name -> post-remediation snapshot
            cve_id: Associated CVE
            plan_id_ref: Associated execution plan
        
        Returns:
            ServiceRollbackPlan with all needed restore actions
        """
        plan_id = f"svc_rollback_{system_id}_{int(datetime.utcnow().timestamp())}"
        plan = ServiceRollbackPlan(
            plan_id=plan_id,
            system_id=system_id,
            timestamp=datetime.utcnow(),
            pre_remediation_states=pre_states,
            post_remediation_states=post_states,
            cve_id=cve_id,
            plan_id_ref=plan_id_ref
        )
        
        # Compare states and create restore actions
        for service_name, pre_state in pre_states.items():
            if service_name not in post_states:
                # Service removed - skip for now
                continue
            
            post_state = post_states[service_name]
            
            # Determine needed actions
            if pre_state.status != post_state.status:
                action = ServiceRestoreAction(
                    action_id=f"{plan_id}_action_{len(plan.restore_actions)}",
                    service_name=service_name,
                    action_type="start" if pre_state.status == ServiceStatus.RUNNING else "stop",
                    from_state=post_state,
                    to_state=pre_state
                )
                plan.restore_actions.append(action)
                logger.info(f"Planned service {service_name} status restore")
            
            if pre_state.startup_type != post_state.startup_type:
                action = ServiceRestoreAction(
                    action_id=f"{plan_id}_action_{len(plan.restore_actions)}",
                    service_name=service_name,
                    action_type="set_startup_type",
                    from_state=post_state,
                    to_state=pre_state
                )
                plan.restore_actions.append(action)
                logger.info(f"Planned service {service_name} startup type restore")
        
        logger.info(f"Created service rollback plan {plan_id} with {len(plan.restore_actions)} actions")
        return plan
    
    def save_rollback_plan(self, plan: ServiceRollbackPlan) -> bool:
        """Save service rollback plan to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            plan_json = json.dumps(plan.to_dict(), default=str)
            
            cursor.execute('''
                INSERT INTO service_rollback_plans
                (plan_id, system_id, timestamp, cve_id, execution_plan_id, description, total_actions, plan_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                plan.plan_id,
                plan.system_id,
                plan.timestamp.isoformat(),
                plan.cve_id,
                plan.plan_id_ref,
                plan.description,
                len(plan.restore_actions),
                plan_json
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved service rollback plan {plan.plan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save service rollback plan: {e}")
            return False
    
    def execute_rollback_plan(self, plan: ServiceRollbackPlan) -> ServiceRollbackReport:
        """
        Execute service rollback plan
        
        Returns:
            ServiceRollbackReport with execution results
        """
        report_id = f"report_{plan.plan_id}_{int(datetime.utcnow().timestamp())}"
        report = ServiceRollbackReport(
            report_id=report_id,
            plan_id=plan.plan_id,
            system_id=plan.system_id,
            timestamp=datetime.utcnow()
        )
        
        # Execute each restore action
        for action in plan.restore_actions:
            action.status = "in_progress"
            
            try:
                start_time = datetime.utcnow()
                
                if action.action_type == "start":
                    # Simulate service start
                    logger.info(f"Starting service {action.service_name}")
                    action.status = "success"
                elif action.action_type == "stop":
                    # Simulate service stop
                    logger.info(f"Stopping service {action.service_name}")
                    action.status = "success"
                elif action.action_type == "set_startup_type":
                    # Simulate startup type change
                    logger.info(f"Setting startup type for {action.service_name} to {action.to_state.startup_type.value}")
                    action.status = "success"
                
                action.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
                report.restore_actions.append(action)
                
            except Exception as e:
                action.status = "failed"
                action.error_message = str(e)
                action.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
                report.restore_actions.append(action)
                logger.error(f"Failed to restore service {action.service_name}: {e}")
        
        # Calculate summary and save
        report.calculate_summary()
        self._save_restore_report(report)
        
        logger.info(f"Service rollback completed: {report.successful_actions}/{report.total_actions} successful")
        return report
    
    def _save_restore_report(self, report: ServiceRollbackReport) -> bool:
        """Save service rollback report to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            report_json = json.dumps(report.to_dict(), default=str)
            
            cursor.execute('''
                INSERT INTO service_rollback_reports
                (report_id, plan_id, system_id, timestamp, total_actions, successful_actions,
                 failed_actions, rollback_success, total_duration_seconds, error_summary, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.report_id,
                report.plan_id,
                report.system_id,
                report.timestamp.isoformat(),
                report.total_actions,
                report.successful_actions,
                report.failed_actions,
                report.rollback_success,
                report.total_duration_seconds,
                report.error_summary,
                report_json
            ))
            
            # Save individual restore actions
            for action in report.restore_actions:
                cursor.execute('''
                    INSERT INTO service_restore_actions
                    (action_id, report_id, plan_id, service_name, action_type, status, error_message, duration_seconds)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    action.action_id,
                    report.report_id,
                    report.plan_id,
                    action.service_name,
                    action.action_type,
                    action.status,
                    action.error_message,
                    action.duration_seconds
                ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved service rollback report {report.report_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save service rollback report: {e}")
            return False


if __name__ == "__main__":
    # Example usage
    manager = ServiceRollbackManager()
    
    # Create pre-remediation snapshots
    pre_states = {
        'Spooler': manager.snapshot_service(
            system_id="SYSTEM-01",
            service_name="Spooler",
            display_name="Print Spooler",
            status=ServiceStatus.RUNNING,
            startup_type=ServiceStartupType.AUTO,
            snapshot_type="pre_remediation"
        ),
        'RpcSs': manager.snapshot_service(
            system_id="SYSTEM-01",
            service_name="RpcSs",
            display_name="Remote Procedure Call (RPC)",
            status=ServiceStatus.RUNNING,
            startup_type=ServiceStartupType.AUTO,
            snapshot_type="pre_remediation"
        )
    }
    
    # Create post-remediation snapshots (e.g., some services disabled)
    post_states = {
        'Spooler': manager.snapshot_service(
            system_id="SYSTEM-01",
            service_name="Spooler",
            display_name="Print Spooler",
            status=ServiceStatus.STOPPED,
            startup_type=ServiceStartupType.DISABLED,
            snapshot_type="post_remediation"
        ),
        'RpcSs': manager.snapshot_service(
            system_id="SYSTEM-01",
            service_name="RpcSs",
            display_name="Remote Procedure Call (RPC)",
            status=ServiceStatus.RUNNING,
            startup_type=ServiceStartupType.AUTO,
            snapshot_type="post_remediation"
        )
    }
    
    # Create rollback plan
    plan = manager.create_rollback_plan(
        system_id="SYSTEM-01",
        pre_states=pre_states,
        post_states=post_states,
        cve_id="CVE-2023-1234"
    )
    print(f"Created service rollback plan: {plan.plan_id}")
    print(f"Restore actions needed: {len(plan.restore_actions)}")
    
    # Save plan
    manager.save_rollback_plan(plan)
    
    # Execute plan
    report = manager.execute_rollback_plan(plan)
    print(f"\nService rollback completed:")
    print(f"Total actions: {report.total_actions}")
    print(f"Successful: {report.successful_actions}")
    print(f"Failed: {report.failed_actions}")
    print(f"Total duration: {report.total_duration_seconds:.2f}s")

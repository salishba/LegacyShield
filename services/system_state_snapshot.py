"""
system_state_snapshot.py
========================

Captures, stores, and compares system state snapshots
Enables rollback by comparing pre/post-deployment state
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import sqlite3
from pathlib import Path
import hashlib
import logging

logger = logging.getLogger(__name__)


class StateComponentType(Enum):
    """Types of system components to track"""
    REGISTRY = "registry"
    SERVICE = "service"
    FILE = "file"
    DRIVER = "driver"
    FIREWALL_RULE = "firewall_rule"
    GROUP_POLICY = "group_policy"
    SCHEDULED_TASK = "scheduled_task"
    SYSTEM_SETTING = "system_setting"


class StateChangeType(Enum):
    """Types of changes detected"""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class RegistryKeySnapshot:
    """Single registry key snapshot"""
    hive: str  # HKLM, HKCU, etc.
    path: str
    value_name: str
    value_data: Any
    value_type: str  # REG_DWORD, REG_SZ, etc.
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict:
        return {
            'hive': self.hive,
            'path': self.path,
            'value_name': self.value_name,
            'value_data': str(self.value_data),
            'value_type': self.value_type,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ServiceSnapshot:
    """Single service state snapshot"""
    service_name: str
    display_name: str
    status: str  # Running, Stopped
    startup_type: str  # Auto, Manual, Disabled
    account: str  # Service logon account
    dependencies: List[str] = field(default_factory=list)
    executable_path: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict:
        return {
            'service_name': self.service_name,
            'display_name': self.display_name,
            'status': self.status,
            'startup_type': self.startup_type,
            'account': self.account,
            'dependencies': self.dependencies,
            'executable_path': self.executable_path,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class FileSnapshot:
    """Single file state snapshot"""
    file_path: str
    file_hash: str  # SHA256 hash of content
    file_size: int
    modified_time: datetime
    attributes: str  # File attributes (hidden, system, etc.)
    version: Optional[str] = None  # For executables
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'modified_time': self.modified_time.isoformat(),
            'attributes': self.attributes,
            'version': self.version,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class DriverSnapshot:
    """Driver/kernel module state snapshot"""
    driver_name: str
    driver_path: str
    status: str  # Running, Stopped
    start_type: str  # Boot, System, Auto, Manual, Disabled
    version: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict:
        return {
            'driver_name': self.driver_name,
            'driver_path': self.driver_path,
            'status': self.status,
            'start_type': self.start_type,
            'version': self.version,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class SystemStateSnapshot:
    """Complete system state snapshot"""
    snapshot_id: str
    system_id: str
    timestamp: datetime
    snapshot_type: str  # pre_deployment, post_deployment, verification
    
    # Component snapshots
    registry_keys: List[RegistryKeySnapshot] = field(default_factory=list)
    services: List[ServiceSnapshot] = field(default_factory=list)
    files: List[FileSnapshot] = field(default_factory=list)
    drivers: List[DriverSnapshot] = field(default_factory=list)
    
    # Metadata
    description: str = ""
    plan_id: Optional[str] = None
    cve_id: Optional[str] = None
    operator: str = "system"
    
    def to_dict(self) -> Dict:
        return {
            'snapshot_id': self.snapshot_id,
            'system_id': self.system_id,
            'timestamp': self.timestamp.isoformat(),
            'snapshot_type': self.snapshot_type,
            'registry_keys': [k.to_dict() for k in self.registry_keys],
            'services': [s.to_dict() for s in self.services],
            'files': [f.to_dict() for f in self.files],
            'drivers': [d.to_dict() for d in self.drivers],
            'description': self.description,
            'plan_id': self.plan_id,
            'cve_id': self.cve_id,
            'operator': self.operator
        }


@dataclass
class StateChange:
    """Single detected change"""
    component_type: StateComponentType
    component_id: str  # registry path, service name, file path
    change_type: StateChangeType
    pre_state: Optional[Dict] = None
    post_state: Optional[Dict] = None
    differences: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"  # critical, high, medium, low, info


@dataclass
class StateChangeReport:
    """Report of all changes detected"""
    report_id: str
    pre_snapshot_id: str
    post_snapshot_id: str
    system_id: str
    timestamp: datetime
    
    total_changes: int = 0
    changes: List[StateChange] = field(default_factory=list)
    
    # Summary counts
    added_count: int = 0
    removed_count: int = 0
    modified_count: int = 0
    unchanged_count: int = 0
    
    # Critical changes
    critical_changes: List[StateChange] = field(default_factory=list)
    rollback_required: bool = False
    rollback_feasible: bool = True
    
    def calculate_summary(self):
        """Calculate summary statistics"""
        self.total_changes = len(self.changes)
        self.added_count = sum(1 for c in self.changes if c.change_type == StateChangeType.ADDED)
        self.removed_count = sum(1 for c in self.changes if c.change_type == StateChangeType.REMOVED)
        self.modified_count = sum(1 for c in self.changes if c.change_type == StateChangeType.MODIFIED)
        self.unchanged_count = sum(1 for c in self.changes if c.change_type == StateChangeType.UNCHANGED)
        
        # Identify critical changes
        self.critical_changes = [c for c in self.changes if c.severity == "critical"]
        self.rollback_required = len(self.critical_changes) > 0


class SystemStateManager:
    """
    Manages system state snapshots and change detection
    """
    
    def __init__(self, db_path: str = "src/execution_log.sqlite"):
        self.db_path = db_path
        self._initialize_snapshot_db()
    
    def _initialize_snapshot_db(self):
        """Create snapshot tables if not exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # System snapshots table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    system_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    plan_id TEXT,
                    cve_id TEXT,
                    operator TEXT NOT NULL,
                    description TEXT,
                    snapshot_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # State changes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS state_changes (
                    change_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    component_type TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    pre_state TEXT,
                    post_state TEXT,
                    differences TEXT,
                    severity TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (report_id) REFERENCES state_change_reports(report_id)
                )
            ''')
            
            # State change reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS state_change_reports (
                    report_id TEXT PRIMARY KEY,
                    pre_snapshot_id TEXT NOT NULL,
                    post_snapshot_id TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_changes INTEGER,
                    added_count INTEGER,
                    removed_count INTEGER,
                    modified_count INTEGER,
                    unchanged_count INTEGER,
                    critical_changes_count INTEGER,
                    rollback_required BOOLEAN,
                    rollback_feasible BOOLEAN,
                    report_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Snapshot database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize snapshot database: {e}")
            raise
    
    def create_snapshot(self, system_id: str, snapshot_type: str, 
                       plan_id: Optional[str] = None, cve_id: Optional[str] = None) -> SystemStateSnapshot:
        """
        Create a new system state snapshot
        
        Args:
            system_id: System identifier
            snapshot_type: pre_deployment, post_deployment, verification
            plan_id: Associated execution plan ID
            cve_id: Associated CVE ID
        
        Returns:
            SystemStateSnapshot with captured state
        """
        snapshot_id = f"{system_id}_{snapshot_type}_{int(datetime.utcnow().timestamp())}"
        
        snapshot = SystemStateSnapshot(
            snapshot_id=snapshot_id,
            system_id=system_id,
            timestamp=datetime.utcnow(),
            snapshot_type=snapshot_type,
            plan_id=plan_id,
            cve_id=cve_id
        )
        
        # In production, would capture actual system state via PowerShell/WMI
        # For now, initializing empty for demonstration
        logger.info(f"Created snapshot {snapshot_id} for {system_id} ({snapshot_type})")
        
        return snapshot
    
    def save_snapshot(self, snapshot: SystemStateSnapshot) -> bool:
        """Save snapshot to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            snapshot_json = json.dumps(snapshot.to_dict())
            
            cursor.execute('''
                INSERT INTO system_snapshots 
                (snapshot_id, system_id, timestamp, snapshot_type, plan_id, cve_id, operator, description, snapshot_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                snapshot.snapshot_id,
                snapshot.system_id,
                snapshot.timestamp.isoformat(),
                snapshot.snapshot_type,
                snapshot.plan_id,
                snapshot.cve_id,
                snapshot.operator,
                snapshot.description,
                snapshot_json
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved snapshot {snapshot.snapshot_id} to database")
            return True
        except Exception as e:
            logger.error(f"Failed to save snapshot: {e}")
            return False
    
    def get_snapshot(self, snapshot_id: str) -> Optional[SystemStateSnapshot]:
        """Retrieve snapshot from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT snapshot_json FROM system_snapshots WHERE snapshot_id = ?', (snapshot_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                snapshot_data = json.loads(row[0])
                # Reconstruct snapshot object
                logger.info(f"Retrieved snapshot {snapshot_id}")
                return snapshot_data
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve snapshot: {e}")
            return None
    
    def compare_snapshots(self, pre_snapshot_id: str, post_snapshot_id: str) -> StateChangeReport:
        """
        Compare two snapshots and generate change report
        
        Returns:
            StateChangeReport with all detected changes
        """
        pre_snapshot = self.get_snapshot(pre_snapshot_id)
        post_snapshot = self.get_snapshot(post_snapshot_id)
        
        if not pre_snapshot or not post_snapshot:
            logger.error(f"Could not retrieve snapshots for comparison")
            return None
        
        report_id = f"report_{pre_snapshot_id}_{post_snapshot_id}"
        report = StateChangeReport(
            report_id=report_id,
            pre_snapshot_id=pre_snapshot_id,
            post_snapshot_id=post_snapshot_id,
            system_id=pre_snapshot.get('system_id', ''),
            timestamp=datetime.utcnow()
        )
        
        # Compare registry keys
        pre_registry = {k['path']: k for k in pre_snapshot.get('registry_keys', [])}
        post_registry = {k['path']: k for k in post_snapshot.get('registry_keys', [])}
        
        # Detect registry changes
        for path, pre_key in pre_registry.items():
            if path not in post_registry:
                report.changes.append(StateChange(
                    component_type=StateComponentType.REGISTRY,
                    component_id=path,
                    change_type=StateChangeType.REMOVED,
                    pre_state=pre_key,
                    severity="high"
                ))
            elif pre_key != post_registry[path]:
                report.changes.append(StateChange(
                    component_type=StateComponentType.REGISTRY,
                    component_id=path,
                    change_type=StateChangeType.MODIFIED,
                    pre_state=pre_key,
                    post_state=post_registry[path],
                    differences={'value_data_changed': True},
                    severity="medium"
                ))
        
        for path, post_key in post_registry.items():
            if path not in pre_registry:
                report.changes.append(StateChange(
                    component_type=StateComponentType.REGISTRY,
                    component_id=path,
                    change_type=StateChangeType.ADDED,
                    post_state=post_key,
                    severity="info"
                ))
        
        # Compare services
        pre_services = {s['service_name']: s for s in pre_snapshot.get('services', [])}
        post_services = {s['service_name']: s for s in post_snapshot.get('services', [])}
        
        for svc_name, pre_svc in pre_services.items():
            if svc_name not in post_services:
                report.changes.append(StateChange(
                    component_type=StateComponentType.SERVICE,
                    component_id=svc_name,
                    change_type=StateChangeType.REMOVED,
                    pre_state=pre_svc,
                    severity="high"
                ))
            elif pre_svc.get('status') != post_services[svc_name].get('status'):
                report.changes.append(StateChange(
                    component_type=StateComponentType.SERVICE,
                    component_id=svc_name,
                    change_type=StateChangeType.MODIFIED,
                    pre_state=pre_svc,
                    post_state=post_services[svc_name],
                    differences={'status_changed': True},
                    severity="high"
                ))
        
        # Calculate summary and save
        report.calculate_summary()
        self._save_change_report(report)
        
        logger.info(f"Completed state comparison: {report.total_changes} changes detected")
        return report
    
    def _save_change_report(self, report: StateChangeReport) -> bool:
        """Save state change report to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            report_json = json.dumps(asdict(report), default=str)
            
            cursor.execute('''
                INSERT INTO state_change_reports 
                (report_id, pre_snapshot_id, post_snapshot_id, system_id, timestamp, 
                 total_changes, added_count, removed_count, modified_count, unchanged_count,
                 critical_changes_count, rollback_required, rollback_feasible, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.report_id,
                report.pre_snapshot_id,
                report.post_snapshot_id,
                report.system_id,
                report.timestamp.isoformat(),
                report.total_changes,
                report.added_count,
                report.removed_count,
                report.modified_count,
                report.unchanged_count,
                len(report.critical_changes),
                report.rollback_required,
                report.rollback_feasible,
                report_json
            ))
            
            # Save individual changes
            for change in report.changes:
                change_id = f"{report.report_id}_{change.component_id}"
                cursor.execute('''
                    INSERT INTO state_changes
                    (change_id, report_id, component_type, component_id, change_type, 
                     pre_state, post_state, differences, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    change_id,
                    report.report_id,
                    change.component_type.value,
                    change.component_id,
                    change.change_type.value,
                    json.dumps(change.pre_state) if change.pre_state else None,
                    json.dumps(change.post_state) if change.post_state else None,
                    json.dumps(change.differences),
                    change.severity
                ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved change report {report.report_id} to database")
            return True
        except Exception as e:
            logger.error(f"Failed to save change report: {e}")
            return False


if __name__ == "__main__":
    # Example usage
    manager = SystemStateManager()
    
    # Create pre-deployment snapshot
    pre_snapshot = manager.create_snapshot(
        system_id="SYSTEM-01",
        snapshot_type="pre_deployment",
        plan_id="PLAN-001",
        cve_id="CVE-2023-1234"
    )
    print(f"Created pre-deployment snapshot: {pre_snapshot.snapshot_id}")
    
    # Save snapshot
    manager.save_snapshot(pre_snapshot)
    
    # Create post-deployment snapshot
    post_snapshot = manager.create_snapshot(
        system_id="SYSTEM-01",
        snapshot_type="post_deployment",
        plan_id="PLAN-001",
        cve_id="CVE-2023-1234"
    )
    print(f"Created post-deployment snapshot: {post_snapshot.snapshot_id}")
    manager.save_snapshot(post_snapshot)
    
    print(f"\nSnapshots initialized for rollback capability")
    print(f"Total snapshots: 2 (pre + post deployment)")

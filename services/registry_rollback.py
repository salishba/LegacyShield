"""
registry_rollback.py
====================

Handles registry backup, restoration, and rollback procedures
Maintains registry snapshots for safe rollback
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json
import sqlite3
import logging

logger = logging.getLogger(__name__)


class RegistryHive(Enum):
    """Windows registry hives"""
    HKLM = "HKEY_LOCAL_MACHINE"
    HKCU = "HKEY_CURRENT_USER"
    HKCR = "HKEY_CLASSES_ROOT"
    HKU = "HKEY_USERS"
    HKCC = "HKEY_CURRENT_CONFIG"


class RegistryValueType(Enum):
    """Registry value types"""
    REG_SZ = "REG_SZ"
    REG_DWORD = "REG_DWORD"
    REG_BINARY = "REG_BINARY"
    REG_MULTI_SZ = "REG_MULTI_SZ"
    REG_EXPAND_SZ = "REG_EXPAND_SZ"


@dataclass
class RegistryValue:
    """Single registry value"""
    hive: RegistryHive
    path: str
    name: str
    value: str
    value_type: RegistryValueType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'hive': self.hive.name,
            'path': self.path,
            'name': self.name,
            'value': str(self.value),
            'value_type': self.value_type.name,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class RegistryBackup:
    """Registry backup for a set of keys"""
    backup_id: str
    system_id: str
    timestamp: datetime
    backup_type: str  # pre_remediation, pre_patch, atomic
    
    backed_up_values: List[RegistryValue] = field(default_factory=list)
    affected_keys: List[str] = field(default_factory=list)
    
    plan_id: Optional[str] = None
    cve_id: Optional[str] = None
    description: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'backup_id': self.backup_id,
            'system_id': self.system_id,
            'timestamp': self.timestamp.isoformat(),
            'backup_type': self.backup_type,
            'backed_up_values': [v.to_dict() for v in self.backed_up_values],
            'affected_keys': self.affected_keys,
            'plan_id': self.plan_id,
            'cve_id': self.cve_id,
            'description': self.description
        }


@dataclass
class RegistryRestoreAction:
    """Single registry restore action"""
    action_id: str
    backup_id: str
    registry_value: RegistryValue
    restore_operation: str  # set_value, delete_value, delete_key
    status: str = "pending"  # pending, in_progress, success, failed
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'action_id': self.action_id,
            'backup_id': self.backup_id,
            'registry_value': self.registry_value.to_dict(),
            'restore_operation': self.restore_operation,
            'status': self.status,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class RegistryRollbackReport:
    """Report of registry rollback operations"""
    report_id: str
    backup_id: str
    system_id: str
    timestamp: datetime
    
    restore_actions: List[RegistryRestoreAction] = field(default_factory=list)
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    
    rollback_success: bool = False
    error_summary: str = ""
    
    def calculate_summary(self):
        """Calculate action summary"""
        self.total_actions = len(self.restore_actions)
        self.successful_actions = sum(1 for a in self.restore_actions if a.status == "success")
        self.failed_actions = sum(1 for a in self.restore_actions if a.status == "failed")
        self.rollback_success = self.failed_actions == 0


class RegistryRollbackManager:
    """
    Manages registry backups and restoration procedures
    """
    
    def __init__(self, db_path: str = "src/execution_log.sqlite"):
        self.db_path = db_path
        self._initialize_registry_db()
    
    def _initialize_registry_db(self):
        """Create registry backup tables if not exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Registry backups table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registry_backups (
                    backup_id TEXT PRIMARY KEY,
                    system_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    backup_type TEXT NOT NULL,
                    plan_id TEXT,
                    cve_id TEXT,
                    description TEXT,
                    backup_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Backed up registry values table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS backed_up_values (
                    value_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    hive TEXT NOT NULL,
                    path TEXT NOT NULL,
                    name TEXT NOT NULL,
                    value TEXT,
                    value_type TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (backup_id) REFERENCES registry_backups(backup_id)
                )
            ''')
            
            # Registry restore actions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registry_restore_actions (
                    action_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    backup_id TEXT NOT NULL,
                    hive TEXT NOT NULL,
                    path TEXT NOT NULL,
                    name TEXT NOT NULL,
                    restore_operation TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (report_id) REFERENCES registry_rollback_reports(report_id),
                    FOREIGN KEY (backup_id) REFERENCES registry_backups(backup_id)
                )
            ''')
            
            # Registry rollback reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registry_rollback_reports (
                    report_id TEXT PRIMARY KEY,
                    backup_id TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_actions INTEGER NOT NULL,
                    successful_actions INTEGER NOT NULL,
                    failed_actions INTEGER NOT NULL,
                    rollback_success BOOLEAN NOT NULL,
                    error_summary TEXT,
                    report_json TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (backup_id) REFERENCES registry_backups(backup_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Registry backup database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize registry backup database: {e}")
            raise
    
    def create_backup(self, system_id: str, backup_type: str,
                     registry_paths: List[Tuple[RegistryHive, str]],
                     plan_id: Optional[str] = None,
                     cve_id: Optional[str] = None) -> RegistryBackup:
        """
        Create registry backup for specified paths
        
        Args:
            system_id: System identifier
            backup_type: pre_remediation, pre_patch, atomic
            registry_paths: List of (hive, path) tuples to backup
            plan_id: Associated execution plan ID
            cve_id: Associated CVE ID
        
        Returns:
            RegistryBackup object with backed up values
        """
        backup_id = f"{system_id}_reg_{int(datetime.utcnow().timestamp())}"
        
        backup = RegistryBackup(
            backup_id=backup_id,
            system_id=system_id,
            timestamp=datetime.utcnow(),
            backup_type=backup_type,
            plan_id=plan_id,
            cve_id=cve_id
        )
        
        # In production, would enumerate registry keys via WMI/PowerShell
        # For now, creating structure for demonstration
        for hive, path in registry_paths:
            backup.affected_keys.append(f"{hive.name}\\{path}")
            
            # Create placeholder registry values
            backup.backed_up_values.append(RegistryValue(
                hive=hive,
                path=path,
                name="example_value",
                value="backed_up_value",
                value_type=RegistryValueType.REG_SZ
            ))
        
        logger.info(f"Created registry backup {backup_id} for {len(registry_paths)} paths")
        return backup
    
    def save_backup(self, backup: RegistryBackup) -> bool:
        """Save registry backup to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            backup_json = json.dumps(backup.to_dict())
            
            cursor.execute('''
                INSERT INTO registry_backups
                (backup_id, system_id, timestamp, backup_type, plan_id, cve_id, description, backup_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                backup.backup_id,
                backup.system_id,
                backup.timestamp.isoformat(),
                backup.backup_type,
                backup.plan_id,
                backup.cve_id,
                backup.description,
                backup_json
            ))
            
            # Save individual backed-up values
            for i, value in enumerate(backup.backed_up_values):
                value_id = f"{backup.backup_id}_value_{i}"
                cursor.execute('''
                    INSERT INTO backed_up_values
                    (value_id, backup_id, hive, path, name, value, value_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    value_id,
                    backup.backup_id,
                    value.hive.name,
                    value.path,
                    value.name,
                    value.value,
                    value.value_type.name
                ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved registry backup {backup.backup_id} ({len(backup.backed_up_values)} values)")
            return True
        except Exception as e:
            logger.error(f"Failed to save registry backup: {e}")
            return False
    
    def restore_from_backup(self, backup_id: str) -> RegistryRollbackReport:
        """
        Restore registry from backup
        
        Returns:
            RegistryRollbackReport with all restore actions and results
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get backup
            cursor.execute('SELECT backup_json FROM registry_backups WHERE backup_id = ?', (backup_id,))
            row = cursor.fetchone()
            
            if not row:
                logger.error(f"Backup {backup_id} not found")
                return None
            
            backup_data = json.loads(row[0])
            system_id = backup_data['system_id']
            
            # Create rollback report
            report_id = f"report_{backup_id}_{int(datetime.utcnow().timestamp())}"
            report = RegistryRollbackReport(
                report_id=report_id,
                backup_id=backup_id,
                system_id=system_id,
                timestamp=datetime.utcnow()
            )
            
            # Restore each registry value
            for i, value_data in enumerate(backup_data['backed_up_values']):
                action_id = f"{report_id}_action_{i}"
                action = RegistryRestoreAction(
                    action_id=action_id,
                    backup_id=backup_id,
                    registry_value=RegistryValue(
                        hive=RegistryHive[value_data['hive']],
                        path=value_data['path'],
                        name=value_data['name'],
                        value=value_data['value'],
                        value_type=RegistryValueType[value_data['value_type']]
                    ),
                    restore_operation="set_value"
                )
                
                # Simulate restore (in production, execute PowerShell)
                action.status = "success"
                report.restore_actions.append(action)
                logger.info(f"Restored registry value: {value_data['path']}\\{value_data['name']}")
            
            # Calculate summary and save
            report.calculate_summary()
            self._save_restore_report(report)
            
            conn.close()
            logger.info(f"Registry restore completed: {report.successful_actions}/{report.total_actions} successful")
            return report
        except Exception as e:
            logger.error(f"Failed to restore registry: {e}")
            return None
    
    def _save_restore_report(self, report: RegistryRollbackReport) -> bool:
        """Save registry restore report to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            report_json = json.dumps(report.to_dict(), default=str)
            
            cursor.execute('''
                INSERT INTO registry_rollback_reports
                (report_id, backup_id, system_id, timestamp, total_actions, successful_actions, 
                 failed_actions, rollback_success, error_summary, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.report_id,
                report.backup_id,
                report.system_id,
                report.timestamp.isoformat(),
                report.total_actions,
                report.successful_actions,
                report.failed_actions,
                report.rollback_success,
                report.error_summary,
                report_json
            ))
            
            # Save individual restore actions
            for action in report.restore_actions:
                cursor.execute('''
                    INSERT INTO registry_restore_actions
                    (action_id, report_id, backup_id, hive, path, name, restore_operation, status, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    action.action_id,
                    report.report_id,
                    report.backup_id,
                    action.registry_value.hive.name,
                    action.registry_value.path,
                    action.registry_value.name,
                    action.restore_operation,
                    action.status,
                    action.error_message
                ))
            
            conn.commit()
            conn.close()
            logger.info(f"Saved restore report {report.report_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save restore report: {e}")
            return False
    
    def get_backup_history(self, system_id: str, limit: int = 10) -> List[Dict]:
        """Get registry backup history for system"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT backup_id, timestamp, backup_type, description
                FROM registry_backups
                WHERE system_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (system_id, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            backups = [
                {
                    'backup_id': row[0],
                    'timestamp': row[1],
                    'backup_type': row[2],
                    'description': row[3]
                }
                for row in rows
            ]
            
            logger.info(f"Retrieved {len(backups)} backups for {system_id}")
            return backups
        except Exception as e:
            logger.error(f"Failed to retrieve backup history: {e}")
            return []


if __name__ == "__main__":
    # Example usage
    manager = RegistryRollbackManager()
    
    # Create backup
    registry_paths = [
        (RegistryHive.HKLM, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (RegistryHive.HKLM, "SYSTEM\\CurrentControlSet\\Services"),
    ]
    
    backup = manager.create_backup(
        system_id="SYSTEM-01",
        backup_type="pre_patch",
        registry_paths=registry_paths,
        cve_id="CVE-2023-1234"
    )
    print(f"Created registry backup: {backup.backup_id}")
    print(f"Affected keys: {len(backup.affected_keys)}")
    print(f"Backed up values: {len(backup.backed_up_values)}")
    
    # Save backup
    manager.save_backup(backup)
    
    # Restore from backup
    report = manager.restore_from_backup(backup.backup_id)
    if report:
        print(f"\nRegistry restore completed:")
        print(f"Total actions: {report.total_actions}")
        print(f"Successful: {report.successful_actions}")
        print(f"Failed: {report.failed_actions}")
        print(f"Rollback success: {report.rollback_success}")

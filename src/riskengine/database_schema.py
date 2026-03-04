"""
database_schema.py - Decision Layer Database Schema

Defines SQL schemas for all Decision Layer tables and provides utilities
for schema initialization, migration, and integrity checking.

Tables:
- decision_batches: Batch processing records
- vulnerability_decisions: Individual vulnerability decisions
- prioritization_results: Priority calculation results
- remediation_strategies: Strategy records
- compliance_assessments: Compliance impact records
- rollback_risk_assessments: Rollback risk evaluations
- recommendations: Generated recommendations
- audit_trail: Complete audit log of all decisions
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# ============================================================================
# SCHEMA DEFINITIONS
# ============================================================================

class DecisionLayerSchema:
    """SQL schemas for Decision Layer tables"""

    # Tables needed
    TABLES = {
        "decision_batches": """
            CREATE TABLE IF NOT EXISTS decision_batches (
                batch_id TEXT PRIMARY KEY,
                batch_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                total_vulnerabilities INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                processing_time_seconds REAL,
                status TEXT NOT NULL DEFAULT 'pending',
                engine_version TEXT,
                configuration_hash TEXT,
                notes TEXT
            );
        """,

        "vulnerability_decisions": """
            CREATE TABLE IF NOT EXISTS vulnerability_decisions (
                decision_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                system_role TEXT NOT NULL,
                
                -- Scores
                risk_score REAL NOT NULL,
                priority_level TEXT NOT NULL,
                
                -- Decision details
                recommended_action TEXT NOT NULL,
                remediation_type TEXT NOT NULL,
                urgency_hours INTEGER,
                
                -- System context
                os_version TEXT,
                os_build TEXT,
                affected_components TEXT,  -- JSON array
                
                -- Compliance
                compliance_violations TEXT,  -- JSON array
                
                -- Risk assessment
                rollback_risk REAL,
                success_probability REAL,
                estimated_downtime_minutes INTEGER,
                
                -- Execution planning
                execution_window_start TIMESTAMP,
                execution_window_end TIMESTAMP,
                required_resources TEXT,  -- JSON
                
                -- Decision metadata
                decision_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                decision_rationale TEXT,
                approved_by TEXT,
                approval_timestamp TIMESTAMP,
                executed BOOLEAN DEFAULT 0,
                execution_timestamp TIMESTAMP,
                execution_result TEXT,  -- success, failed, rolled_back
                
                -- Audit
                created_by TEXT,
                modified_at TIMESTAMP,
                
                FOREIGN KEY (batch_id) REFERENCES decision_batches(batch_id),
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );
        """,

        "prioritization_results": """
            CREATE TABLE IF NOT EXISTS prioritization_results (
                priority_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                system_role TEXT NOT NULL,
                
                -- Priority metrics
                priority_score REAL NOT NULL,
                priority_rank INTEGER NOT NULL,
                priority_level TEXT NOT NULL,
                
                -- Component scores
                severity_component REAL,
                exploitability_component REAL,
                business_impact_component REAL,
                system_density_component REAL,
                sla_component REAL,
                
                -- SLA details
                sla_deadline TIMESTAMP NOT NULL,
                hours_until_sla REAL,
                sla_status TEXT,  -- at_risk, compliant, urgent, breached
                
                -- Effort estimation
                affected_systems_count INTEGER,
                remediation_effort_hours REAL,
                
                -- Metadata
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                
                FOREIGN KEY (batch_id) REFERENCES decision_batches(batch_id),
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );
        """,

        "remediation_strategies": """
            CREATE TABLE IF NOT EXISTS remediation_strategies (
                strategy_id TEXT PRIMARY KEY,
                batch_id TEXT,
                cve_id TEXT NOT NULL,
                
                -- Strategy details
                strategy_type TEXT NOT NULL,
                execution_phase TEXT,
                urgency_level TEXT,
                
                -- Timeline
                execution_window_start TIMESTAMP,
                execution_window_end TIMESTAMP,
                estimated_duration_minutes INTEGER,
                
                -- Methods
                remediation_methods TEXT NOT NULL,  -- JSON array
                primary_method TEXT,
                fallback_methods TEXT,  -- JSON array
                required_downtime_minutes INTEGER,
                
                -- Requirements
                prerequisites TEXT,  -- JSON array
                resource_requirements TEXT,  -- JSON object
                approval_level TEXT,
                
                -- Risk assessment
                success_probability REAL,
                rollback_ability BOOLEAN,
                rollback_probability REAL,
                
                -- Business context
                business_impact_if_exploited TEXT,
                business_impact_if_patched TEXT,
                cost_of_delay_per_hour REAL,
                
                -- Decision logic
                decision_rationale TEXT,
                alternative_strategies TEXT,  -- JSON array
                
                -- Compliance
                compliance_violations TEXT,  -- JSON array
                
                -- Status
                status TEXT NOT NULL DEFAULT 'draft',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                approved_by TEXT,
                approved_at TIMESTAMP,
                executed_at TIMESTAMP,
                
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );
        """,

        "compliance_assessments": """
            CREATE TABLE IF NOT EXISTS compliance_assessments (
                assessment_id TEXT PRIMARY KEY,
                batch_id TEXT,
                cve_id TEXT NOT NULL,
                
                -- Frameworks
                applicable_frameworks TEXT NOT NULL,  -- JSON array
                
                -- Violations
                violation_count INTEGER,
                regulations_violated TEXT,  -- JSON array of {framework, reg_id, severity}
                criticality_for_compliance TEXT,  -- CRITICAL, HIGH, MEDIUM, LOW
                
                -- SLAs
                sla_hours INTEGER,
                most_stringent_framework TEXT,
                
                -- Requirements
                audit_requirements TEXT,  -- JSON array
                remediation_evidence_required TEXT,  -- JSON array
                
                -- Deadlines
                reporting_deadlines TEXT,  -- JSON object {framework: timestamp}
                
                -- Metadata
                assessment_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                assessed_by TEXT,
                
                FOREIGN KEY (batch_id) REFERENCES decision_batches(batch_id),
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );
        """,

        "rollback_risk_assessments": """
            CREATE TABLE IF NOT EXISTS rollback_risk_assessments (
                assessment_id TEXT PRIMARY KEY,
                strategy_id TEXT,
                kb_id TEXT,
                cve_id TEXT NOT NULL,
                system_role TEXT NOT NULL,
                
                -- Risk components
                patch_maturity_risk REAL,
                adoption_rate_risk REAL,
                known_issues_risk REAL,
                system_criticality_risk REAL,
                backup_availability_risk REAL,
                dependency_compatibility_risk REAL,
                
                -- Overall assessment
                overall_rollback_risk REAL NOT NULL,
                risk_level TEXT NOT NULL,
                
                -- Details
                risk_factors TEXT NOT NULL,  -- JSON array
                mitigations TEXT,  -- JSON array
                
                -- Recommendations
                recommended_approach TEXT,
                estimated_rollback_time_minutes INTEGER,
                rollback_feasibility BOOLEAN,
                
                -- Metadata
                assessment_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                assessed_by TEXT,
                
                FOREIGN KEY (kb_id) REFERENCES kb_patches(kb_id),
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );
        """,

        "recommendations": """
            CREATE TABLE IF NOT EXISTS recommendations (
                recommendation_id TEXT PRIMARY KEY,
                batch_id TEXT,
                strategy_id TEXT,
                cve_id TEXT NOT NULL,
                
                -- Recommendation details
                title TEXT NOT NULL,
                scope TEXT,
                action_steps TEXT NOT NULL,  -- JSON array
                
                -- Execution
                execution_method TEXT,
                execution_script TEXT,
                estimated_time_minutes INTEGER,
                risk_level TEXT,
                
                -- Procedures
                rollback_procedure TEXT,
                validation_steps TEXT,  -- JSON array
                prerequisites TEXT,  -- JSON array
                known_issues TEXT,  -- JSON array
                
                -- References
                references TEXT,  -- JSON object
                owner_team TEXT,
                approval_required BOOLEAN,
                
                -- Status
                status TEXT NOT NULL DEFAULT 'draft',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                approved_by TEXT,
                approved_at TIMESTAMP,
                executed_at TIMESTAMP,
                execution_result TEXT,
                
                FOREIGN KEY (strategy_id) REFERENCES remediation_strategies(strategy_id),
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );
        """,

        "audit_trail": """
            CREATE TABLE IF NOT EXISTS audit_trail (
                audit_id TEXT PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                
                -- Action details
                action_type TEXT NOT NULL,  -- created, updated, approved, executed, etc.
                entity_type TEXT NOT NULL,  -- decision, strategy, recommendation, etc.
                entity_id TEXT NOT NULL,
                
                -- Changes
                old_value TEXT,
                new_value TEXT,
                
                -- Context
                user_id TEXT,
                reason TEXT,
                notes TEXT,
                
                -- Impact
                cve_id TEXT,
                system_affected TEXT,
                
                -- Indexes
                INDEX idx_timestamp (timestamp),
                INDEX idx_entity (entity_type, entity_id),
                INDEX idx_user (user_id)
            );
        """,

        "priority_historical": """
            CREATE TABLE IF NOT EXISTS priority_historical (
                record_id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                system_role TEXT NOT NULL,
                
                -- Priority at time of record
                priority_score REAL NOT NULL,
                priority_rank INTEGER,
                priority_level TEXT,
                
                -- SLA tracking
                sla_deadline TIMESTAMP,
                sla_status TEXT,
                
                -- Status progression
                status TEXT,  -- escalated, downgraded, resolved
                
                -- History
                recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                changed_by TEXT,
                change_reason TEXT,
                
                INDEX idx_cve (cve_id),
                INDEX idx_recorded (recorded_at)
            );
        """,

        "decision_metrics": """
            CREATE TABLE IF NOT EXISTS decision_metrics (
                metric_id TEXT PRIMARY KEY,
                batch_id TEXT,
                
                -- Quality metrics
                avg_decision_time_seconds REAL,
                median_priority_score REAL,
                std_dev_priority_score REAL,
                
                -- Processing metrics
                total_vulnerabilities_processed INTEGER,
                successful_decisions INTEGER,
                failed_decisions INTEGER,
                
                -- SLA metrics
                sla_compliant_count INTEGER,
                sla_at_risk_count INTEGER,
                sla_breached_count INTEGER,
                
                -- Compliance metrics
                compliance_critical_count INTEGER,
                compliance_violations_total INTEGER,
                
                -- Execution metrics
                executed_successfully INTEGER,
                rollback_count INTEGER,
                rollback_success_rate REAL,
                
                -- Recorded at
                recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                
                FOREIGN KEY (batch_id) REFERENCES decision_batches(batch_id)
            );
        """
    }

    # Indexes for performance
    INDEXES = [
        ("idx_decisions_batch", "decision_batches", "idx_decisions_batch", """
            CREATE INDEX IF NOT EXISTS idx_decisions_batch 
            ON vulnerability_decisions(batch_id)
        """),
        ("idx_decisions_cve", "vulnerability_decisions", "idx_decisions_cve", """
            CREATE INDEX IF NOT EXISTS idx_decisions_cve 
            ON vulnerability_decisions(cve_id)
        """),
        ("idx_decisions_timestamp", "vulnerability_decisions", "idx_decisions_timestamp", """
            CREATE INDEX IF NOT EXISTS idx_decisions_timestamp 
            ON vulnerability_decisions(decision_timestamp)
        """),
        ("idx_priority_batch", "prioritization_results", "idx_priority_batch", """
            CREATE INDEX IF NOT EXISTS idx_priority_batch 
            ON prioritization_results(batch_id)
        """),
        ("idx_priority_score", "prioritization_results", "idx_priority_score", """
            CREATE INDEX IF NOT EXISTS idx_priority_score 
            ON prioritization_results(priority_score DESC)
        """),
        ("idx_strategy_status", "remediation_strategies", "idx_strategy_status", """
            CREATE INDEX IF NOT EXISTS idx_strategy_status 
            ON remediation_strategies(status)
        """),
        ("idx_compliance_frameworks", "compliance_assessments", "idx_compliance_frameworks", """
            CREATE INDEX IF NOT EXISTS idx_compliance_frameworks 
            ON compliance_assessments(applicable_frameworks)
        """),
        ("idx_audit_timestamp", "audit_trail", "idx_audit_timestamp", """
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
            ON audit_trail(timestamp DESC)
        """),
        ("idx_audit_entity", "audit_trail", "idx_audit_entity", """
            CREATE INDEX IF NOT EXISTS idx_audit_entity 
            ON audit_trail(entity_type, entity_id)
        """)
    ]


# ============================================================================
# SCHEMA MANAGER
# ============================================================================

class DecisionLayerSchemaManager:
    """Manages Decision Layer schema initialization and maintenance"""

    def __init__(self, db_path: str, log_level: int = logging.INFO):
        """Initialize Schema Manager."""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

    def initialize_schema(self) -> bool:
        """
        Initialize all Decision Layer tables.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create tables
            for table_name, schema in DecisionLayerSchema.TABLES.items():
                self.logger.debug(f"Creating table: {table_name}")
                cursor.execute(schema)

            # Create indexes
            for index_name, table_name, idx_name, index_sql in DecisionLayerSchema.INDEXES:
                self.logger.debug(f"Creating index: {index_name}")
                cursor.execute(index_sql)

            conn.commit()
            conn.close()
            
            self.logger.info(f"Schema initialized successfully in {self.db_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error initializing schema: {e}")
            return False

    def verify_schema(self) -> Dict[str, bool]:
        """
        Verify that all tables exist.
        
        Returns:
            Dictionary of table_name -> exists
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            verification = {}

            # Check each table
            for table_name in DecisionLayerSchema.TABLES.keys():
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name=?
                """, (table_name,))
                
                verification[table_name] = cursor.fetchone() is not None

            conn.close()
            return verification

        except Exception as e:
            self.logger.error(f"Error verifying schema: {e}")
            return {t: False for t in DecisionLayerSchema.TABLES.keys()}

    def get_schema_version(self) -> Optional[str]:
        """Get version information of initialized schema."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Try to get version from a metadata table
            cursor.execute("""
                SELECT value FROM schema_metadata 
                WHERE key='version'
            """)

            result = cursor.fetchone()
            conn.close()

            return result[0] if result else None

        except:
            return None

    def backup_schema(self) -> Optional[Path]:
        """
        Create a backup of the database file.
        
        Returns:
            Path to backup file
        """
        try:
            db_path = Path(self.db_path)
            backup_path = db_path.parent / f"{db_path.stem}_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.sqlite"

            # Copy file
            import shutil
            shutil.copy2(db_path, backup_path)

            self.logger.info(f"Schema backup created: {backup_path}")
            return backup_path

        except Exception as e:
            self.logger.error(f"Error backing up schema: {e}")
            return None

    def export_decision_data(self, output_path: str) -> bool:
        """
        Export decision data to CSV for analysis.
        
        Args:
            output_path: Path to export to
        
        Returns:
            True if successful
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Export vulnerability decisions
            cursor.execute("SELECT * FROM vulnerability_decisions")
            decisions = cursor.fetchall()
            
            # Get column names
            cursor.execute("PRAGMA table_info(vulnerability_decisions)")
            columns = [col[1] for col in cursor.fetchall()]

            # Write CSV
            import csv
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(decisions)

            conn.close()
            self.logger.info(f"Decision data exported to {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            return False


# ============================================================================
# MAIN (FOR TESTING)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    # Initialize schema
    manager = DecisionLayerSchemaManager("decision_layer.sqlite")
    
    if manager.initialize_schema():
        print("✓ Schema initialized successfully")
        
        # Verify
        verification = manager.verify_schema()
        print("\nTable Verification:")
        for table, exists in verification.items():
            status = "✓" if exists else "✗"
            print(f"  {status} {table}")
    else:
        print("✗ Failed to initialize schema")

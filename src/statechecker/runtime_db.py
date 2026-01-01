#runtime_db.py

import sqlite3
import os
import hashlib
from pathlib import Path
from datetime import datetime


class RuntimePaths:
    BASE_DIR = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData")) / "SmartPatch"
    LOG_DIR = BASE_DIR / "logs"
    DB_DIR = BASE_DIR / "runtime"
    SNAPSHOT_DIR = BASE_DIR / "snapshots"

    @staticmethod
    def init_dirs():
        for d in [
            RuntimePaths.BASE_DIR,
            RuntimePaths.LOG_DIR,
            RuntimePaths.DB_DIR,
            RuntimePaths.SNAPSHOT_DIR
        ]:
            d.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def generate_runtime_db_path() -> Path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return RuntimePaths.DB_DIR / f"runtime_{ts}.sqlite"


class RuntimeDatabaseManager:

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = None

    def connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.execute("PRAGMA foreign_keys = ON;")
            self.conn.execute("PRAGMA journal_mode = WAL;")
            return self.conn
        except Exception as e:
            raise RuntimeError(f"Failed to connect to runtime DB: {e}")
        
    def log_scan_action(
        self,
        action: str,
        message: str,
        component: str = "runtime",
        level: str = "INFO"
    ):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO scan_log (component, action, message, level)
            VALUES (?, ?, ?, ?)
        """, (component, action, message, level))
        self.conn.commit()


    def disconnect(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def create_runtime_tables(self):
        if not self.conn:
            raise RuntimeError("Runtime DB not connected.")

        cursor = self.conn.cursor()
        try:
            cursor.executescript("""
            -- =====================================================
            -- SYSTEM IDENTITY (SCANNER OWNED)
            -- =====================================================
            CREATE TABLE IF NOT EXISTS system_info (
                host_hash TEXT PRIMARY KEY,
                hostname TEXT,
                os_version TEXT NOT NULL,
                build_number TEXT NOT NULL,
                architecture TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                elevated INTEGER DEFAULT 0
            );

            -- =====================================================
            -- INSTALLED UPDATES (SCANNER OWNED)
            -- =====================================================
            CREATE TABLE IF NOT EXISTS installed_kbs (
                kb_id TEXT NOT NULL,
                install_date TEXT,
                source TEXT,
                host_hash TEXT NOT NULL,
                PRIMARY KEY (kb_id, host_hash),
                FOREIGN KEY (host_hash) REFERENCES system_info(host_hash)
            );

            -- =====================================================
            -- RAW SECURITY FINDINGS (SINGLE SOURCE OF TRUTH)
            -- SCANNER WRITES HERE ONLY
            -- =====================================================
            CREATE TABLE IF NOT EXISTS raw_security_findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                status TEXT NOT NULL,
                risk TEXT NOT NULL,
                description TEXT NOT NULL,
                actual_value TEXT,
                expected_value TEXT,
                remediation_hint TEXT,
                evidence TEXT,
                source_scanner TEXT NOT NULL,
                host_hash TEXT NOT NULL,
                detected_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (host_hash) REFERENCES system_info(host_hash)
            );

            -- =====================================================
            -- AI-DERIVED VULNERABILITIES (AI OWNED)
            -- NO DIRECT SCANNER WRITES
            -- =====================================================
            CREATE TABLE IF NOT EXISTS derived_vulnerabilities (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                confidence_score REAL CHECK(confidence_score BETWEEN 0 AND 1),
                derived_from_finding_id INTEGER NOT NULL,
                reasoning TEXT,
                model_version TEXT,
                host_hash TEXT NOT NULL,
                generated_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (derived_from_finding_id)
                    REFERENCES raw_security_findings(finding_id),
                FOREIGN KEY (host_hash)
                    REFERENCES system_info(host_hash)
            );

            -- =====================================================
            -- AI-DERIVED MITIGATIONS (AI OWNED)
            -- =====================================================
            CREATE TABLE IF NOT EXISTS derived_mitigations (
                mitigation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id INTEGER NOT NULL,
                mitigation_type TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                reversible INTEGER DEFAULT 1,
                requires_reboot INTEGER DEFAULT 0,
                confidence_score REAL CHECK(confidence_score BETWEEN 0 AND 1),
                model_version TEXT,
                generated_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (vuln_id)
                    REFERENCES derived_vulnerabilities(vuln_id)
            );

            -- =====================================================
            -- OPERATIONAL LOGGING
            -- =====================================================
            CREATE TABLE IF NOT EXISTS scan_log (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT (datetime('now')),
                component TEXT NOT NULL,
                action TEXT NOT NULL,
                message TEXT,
                level TEXT CHECK(level IN ('INFO','WARN','ERROR','DEBUG'))
            );
                                 
            -- =====================================================
            -- RISK SCORING (DETERMINISTIC OR ML-DERIVED)
            -- AI AND POLICY ENGINE READ THIS
            -- =====================================================
            CREATE TABLE IF NOT EXISTS hars_scores (
                hars_id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                cve_id TEXT,
                a_score REAL CHECK(a_score BETWEEN 0 AND 1),
                r_score REAL CHECK(r_score BETWEEN 0 AND 1),
                c_score REAL CHECK(c_score BETWEEN 0 AND 1),
                final_score REAL CHECK(final_score BETWEEN 0 AND 1),
                priority TEXT CHECK(priority IN ('LOW','MEDIUM','HIGH')),
                scoring_model TEXT NOT NULL,
                generated_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (finding_id)
                    REFERENCES raw_security_findings(finding_id)
            );

            """)
            self.conn.commit()

        except Exception as e:
            raise RuntimeError(f"Failed creating tables: {e}")


def init_runtime_database() -> RuntimeDatabaseManager:
    """
    High-level init. Call this once per scan.
    """
    RuntimePaths.init_dirs()
    db_path = RuntimePaths.generate_runtime_db_path()

    db = RuntimeDatabaseManager(db_path)
    db.connect()
    db.create_runtime_tables()
    db.log_scan_action("init", "Runtime database initialized")

    return db

def insert_system_info(db: RuntimeDatabaseManager, system_info: dict):
    """
    Insert or replace system metadata for the current scan
    """
    cursor = db.conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO system_info (
            host_hash,
            hostname,
            os_version,
            build_number,
            architecture,
            scan_time,
            agent_version,
            elevated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        system_info["host_hash"],
        system_info["hostname"],
        system_info["os_version"],
        system_info["build_number"],
        system_info["architecture"],
        system_info["scan_time"],
        system_info["agent_version"],
        system_info.get("elevated", 0)
    ))
    db.conn.commit()
def insert_finding(db: RuntimeDatabaseManager, finding: dict, host_hash: str):
    """
    Insert a single raw security finding
    """
    cursor = db.conn.cursor()
    cursor.execute("""
        INSERT INTO raw_security_findings (
            domain,
            finding_type,
            status,
            risk,
            description,
            actual_value,
            expected_value,
            remediation_hint,
            evidence,
            source_scanner,
            host_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding["domain"],
        finding["finding_type"],
        finding["status"],
        finding["risk"],
        finding["description"],
        finding.get("actual_value"),
        finding.get("expected_value"),
        finding.get("remediation_hint"),
        finding.get("evidence"),
        finding["source_scanner"],
        host_hash
    ))
    db.conn.commit()

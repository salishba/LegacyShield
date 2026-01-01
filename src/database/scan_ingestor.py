# scan_ingestor.py
import sqlite3
from datetime import datetime
from typing import List, Dict

class ScanIngestor:
    def __init__(self, runtime_db="runtime_scan.sqlite"):
        self.db = runtime_db
        self._ensure_schema()

    def _ensure_schema(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                control_id TEXT,
                category TEXT,
                severity TEXT,
                evidence TEXT,
                detected_value TEXT,
                expected_value TEXT,
                scanner TEXT,
                timestamp TEXT
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS finding_mappings (
                finding_id TEXT,
                technique_id TEXT,
                confidence REAL,
                PRIMARY KEY (finding_id, technique_id)
            )
            """)

    def ingest(self, findings: List[Dict]):
        with sqlite3.connect(self.db) as conn:
            for f in findings:
                conn.execute("""
                INSERT OR REPLACE INTO findings
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f["id"],
                    f["control_id"],
                    f["category"],
                    f["severity"],
                    f["evidence"],
                    f.get("detected"),
                    f.get("expected"),
                    f["scanner"],
                    datetime.utcnow().isoformat()
                ))

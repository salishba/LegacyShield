# patch_state.py
# Deterministic patch applicability resolver

import sqlite3
from typing import List, Dict


class PatchStateResolver:
    def __init__(self, runtime_db_path: str, catalogue_db_path: str):
        self.runtime_db_path = runtime_db_path
        self.catalogue_db_path = catalogue_db_path

    def resolve(self):
        runtime = sqlite3.connect(self.runtime_db_path)
        runtime.row_factory = sqlite3.Row
        catalogue = sqlite3.connect(self.catalogue_db_path)
        catalogue.row_factory = sqlite3.Row

        system = runtime.execute("""
            SELECT *
            FROM system_info
            ORDER BY scan_time DESC
            LIMIT 1
        """).fetchone()

        if not system:
            raise RuntimeError("No system_info found")

        installed_kbs = runtime.execute("""
            SELECT kb_id
            FROM installed_kbs
            WHERE host_hash = ?
              AND scan_time = ?
        """, (system["host_hash"], system["scan_time"])).fetchall()

        installed_kb_set = {r["kb_id"] for r in installed_kbs}

        cve_map = catalogue.execute("""
            SELECT cve_id, kb_id
            FROM cve_kb_map
        """).fetchall()

        rows_to_insert = []

        for row in cve_map:
            cve_id = row["cve_id"]
            kb_id = row["kb_id"]

            if kb_id in installed_kb_set:
                state = "INSTALLED"
                confidence = "HIGH"
                reasoning = f"{kb_id} installed on host"
            else:
                state = "MISSING"
                confidence = "HIGH"
                reasoning = f"{kb_id} not present in installed KB inventory"

            rows_to_insert.append((
                cve_id,
                kb_id,
                state,
                confidence,
                reasoning,
                system["host_hash"],
                system["scan_time"]
            ))

        runtime.executemany("""
            INSERT INTO patch_state (
                cve_id,
                kb_id,
                state,
                confidence,
                reasoning,
                host_hash,
                scan_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, rows_to_insert)

        runtime.commit()
        runtime.close()
        catalogue.close()

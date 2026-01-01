from pathlib import Path
import glob
import sqlite3
import json
from datetime import datetime

DEV_DB = "patch_catalogue.sqlite"
RUNTIME_DB = "runtime_scan.sqlite"

class DataSeeder:
    def __init__(self, dev_db_path=DEV_DB, runtime_db_path=RUNTIME_DB):
        self.dev_db_path = dev_db_path
        self.runtime_db_path = runtime_db_path
        self.seed_time = datetime.utcnow().isoformat()

    def seed_all_data(self):
        print("="*60)
        print("SMARTPATCH DATA SEEDER")
        print(f"Seeding started at {self.seed_time}")
        print("="*60)

        self.ensure_dev_db_schema()
        self.seed_from_json("msrc_catalogue.json", "msrc_catalogue")
        self.seed_from_json("cve_kb_map.json", "cve_kb_map")
        self.seed_from_json("mitigation_controls.json")  # Auto-detect table per control
        self.seed_runtime_tables()

        print("\n[✓] Data seeding complete")
        self.generate_seeding_report()

    def ensure_dev_db_schema(self):
        with sqlite3.connect(self.dev_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS msrc_catalogue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                release_date TEXT, product TEXT, platform TEXT, impact TEXT,
                max_severity TEXT, article TEXT, article_link TEXT,
                download TEXT, download_link TEXT, build_number TEXT,
                details TEXT, details_link TEXT
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_kb_map (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT, kb_article TEXT
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS registry_mitigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT, cve_id TEXT, description TEXT,
                registry_path TEXT, value_name TEXT, recommended_value TEXT,
                risk_level TEXT, source_reference TEXT
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_mitigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT, cve_id TEXT, description TEXT,
                risk_level TEXT, source_reference TEXT
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_mitigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT, cve_id TEXT, description TEXT,
                risk_level TEXT, source_reference TEXT
            )
            """)
        print(f"[✓] Verified developer database schema: {self.dev_db_path}")

    def seed_from_json(self, json_file, table_name=None):
        path = Path("catalogues") / json_file
        if not path.exists():
            print(f"[!] File not found: {path}")
            return

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if table_name:  # Static table
            columns = ", ".join(data[0].keys())
            placeholders = ", ".join("?" for _ in data[0])
            values = [tuple(d.values()) for d in data]
            with sqlite3.connect(self.dev_db_path) as conn:
                cursor = conn.cursor()
                cursor.executemany(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})", values)
            print(f"[✓] Seeded {len(data)} entries into {table_name}")
        else:  # Dynamic mitigations
            mitigations_to_insert = []
            for control in data.get("controls", []):
                table = "registry_mitigations" if control.get("type") == "registry" else \
                        "system_mitigations" if control.get("type") == "system" else \
                        "network_mitigations"
                mitigations_to_insert.append({
                    "table": table,
                    "technique_id": control.get("id", ""),
                    "cve_id": control.get("representative_cve", ""),
                    "description": control.get("description", ""),
                    "registry_path": control.get("registry_path", ""),
                    "value_name": control.get("registry_value", ""),
                    "recommended_value": control.get("registry_data", ""),
                    "risk_level": control.get("risk_level", "Medium"),
                    "source_reference": f"JSON: {json_file}"
                })

            with sqlite3.connect(self.dev_db_path) as conn:
                cursor = conn.cursor()
                for m in mitigations_to_insert:
                    if m['table'] == "registry_mitigations":
                        cursor.execute(f"""
                        INSERT INTO {m['table']} 
                        (technique_id, cve_id, description, registry_path, value_name, recommended_value, risk_level, source_reference)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            m['technique_id'], m['cve_id'], m['description'],
                            m['registry_path'], m['value_name'], m['recommended_value'],
                            m['risk_level'], m['source_reference']
                        ))
                    else:
                        cursor.execute(f"""
                        INSERT INTO {m['table']} (technique_id, cve_id, description, risk_level, source_reference)
                        VALUES (?, ?, ?, ?, ?)
                        """, (
                            m['technique_id'], m['cve_id'], m['description'],
                            m['risk_level'], m['source_reference']
                        ))
                conn.commit()
            print(f"[✓] Seeded {len(mitigations_to_insert)} mitigations from {json_file}")

    def seed_runtime_tables(self):
        with sqlite3.connect(self.runtime_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS required_kbs (
                kb_id TEXT PRIMARY KEY
            )
            """)
        print("[✓] Verified runtime tables")

    def generate_seeding_report(self):
        with sqlite3.connect(self.dev_db_path) as conn:
            cursor = conn.cursor()
            tables = ['msrc_catalogue', 'cve_kb_map', 'registry_mitigations', 'system_mitigations', 'network_mitigations']
            print("\n[=== SEEDING REPORT ===]")
            print(f"Timestamp: {self.seed_time}")
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                print(f"{table}: {cursor.fetchone()[0]} entries")

def main(auto_confirm=True):
    seeder = DataSeeder()
    seeder.seed_all_data()

if __name__ == "__main__":
    main()

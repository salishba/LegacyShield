#dev_db.py
from pathlib import Path
import sqlite3
import csv
from datetime import datetime

DEV_DB = "dev_db.sqlite"
RUNTIME_DB = "runtime_scan.sqlite"


class DataSeeder:
    def __init__(self, dev_db_path=DEV_DB, runtime_db_path=RUNTIME_DB):
        self.dev_db_path = dev_db_path
        self.runtime_db_path = runtime_db_path
        self.seed_time = datetime.utcnow().isoformat()

    def seed_all_data(self):
        print("=" * 60)
        print("SMARTPATCH DATA SEEDER (JSON SEEDING DISABLED)")
        print(f"Seeding started at {self.seed_time}")
        print("=" * 60)

        self.ensure_dev_db_schema()

        # MSRC CSV seeding ONLY
        if Path("MSRC_Catalogue.csv").exists():
            self.seed_msrc_from_csv("MSRC_Catalogue.csv")
        else:
            print("[!] MSRC CSV not found, skipping")

        self.seed_runtime_tables()

        print("\n[✓] Data seeding complete")
        self.generate_seeding_report()

    # -------------------- CSV SEEDING --------------------

    def seed_msrc_from_csv(self, csv_file):
        path = Path(csv_file)

        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        if not rows:
            print("[!] MSRC CSV is empty")
            return

        clean_rows = []
        for row in rows:
            clean_row = {}
            for key, value in row.items():
                clean_key = (
                    key.replace(" ", "_")
                       .replace("-", "_")
                       .replace("(", "")
                       .replace(")", "")
                       .lower()
                )
                if clean_key == "date":
                    clean_key = "release_date"
                clean_row[clean_key] = value
            clean_rows.append(clean_row)

        columns = ", ".join(clean_rows[0].keys())
        placeholders = ", ".join("?" for _ in clean_rows[0])
        values = [tuple(row.values()) for row in clean_rows]

        with sqlite3.connect(self.dev_db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("DROP TABLE IF EXISTS msrc_catalogue")
            cursor.execute(f"""
                CREATE TABLE msrc_catalogue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    {', '.join(f'{c} TEXT' for c in clean_rows[0].keys())}
                );
            """)

            cursor.executemany(
                f"INSERT INTO msrc_catalogue ({columns}) VALUES ({placeholders})",
                values
            )
            conn.commit()

        print(f"[✓] Seeded {len(clean_rows)} MSRC entries from CSV")

    # -------------------- SCHEMA (UNCHANGED) --------------------

    def ensure_dev_db_schema(self):
        with sqlite3.connect(self.dev_db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS msrc_catalogue (
                id INTEGER PRIMARY KEY AUTOINCREMENT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor TEXT,
                product_name TEXT,
                major_version TEXT,
                minor_version TEXT,
                edition TEXT,
                architecture TEXT,
                language TEXT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                published_date TEXT,
                severity TEXT,
                cvss_score REAL,
                exploitability_score REAL,
                impact_score REAL,
                description TEXT,
                source TEXT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS patches (
                kb_id TEXT PRIMARY KEY,
                title TEXT,
                release_date TEXT,
                patch_type TEXT,
                reboot_required INTEGER,
                source TEXT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS patch_applicability (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                kb_id TEXT,
                product_id INTEGER,
                build_min INTEGER,
                build_max INTEGER,
                service_pack TEXT,
                is_superseded INTEGER DEFAULT 0,
                superseded_by TEXT,
                applicability_confidence REAL,
                detection_method TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
                FOREIGN KEY (kb_id) REFERENCES patches(kb_id),
                FOREIGN KEY (product_id) REFERENCES products(product_id)
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_kb_map (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                kb_article TEXT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitigation_techniques (
                technique_id TEXT PRIMARY KEY,
                cve_id TEXT,
                technique_type TEXT,
                title TEXT,
                description TEXT,
                implementation TEXT,
                validation TEXT,
                effectiveness TEXT,
                windows_versions TEXT,
                potential_impact TEXT,
                source TEXT,
                source_url TEXT,
                confidence REAL,
                verified INTEGER,
                ingested_at TEXT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS registry_mitigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT,
                cve_id TEXT,
                description TEXT,
                registry_path TEXT,
                value_name TEXT,
                recommended_value TEXT,
                risk_level TEXT,
                source_reference TEXT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_mitigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT,
                cve_id TEXT,
                mitigation_type TEXT,
                feature_name TEXT,
                service_name TEXT,
                action TEXT,
                powershell_command TEXT,
                wmi_query TEXT,
                notes TEXT,
                verified INTEGER,
                source_reference TEXT
            );
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_mitigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT,
                cve_id TEXT,
                rule_name TEXT,
                protocol TEXT,
                port_range TEXT,
                action TEXT,
                netsh_command TEXT,
                verified INTEGER,
                notes TEXT,
                source_reference TEXT
            );
            """)

        print(f"[✓] Verified developer database schema: {self.dev_db_path}")

    # -------------------- RUNTIME (UNCHANGED) --------------------

    def seed_runtime_tables(self):
        with sqlite3.connect(self.runtime_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS required_kbs (
                kb_id TEXT PRIMARY KEY
            );
            """)
        print("[✓] Verified runtime tables")

    # -------------------- REPORT --------------------

    def generate_seeding_report(self):
        with sqlite3.connect(self.dev_db_path) as conn:
            cursor = conn.cursor()
            tables = [
                "msrc_catalogue",
                "cve_kb_map",
                "registry_mitigations",
                "system_mitigations",
                "network_mitigations",
                "mitigation_techniques"
            ]

            print("\n[=== SEEDING REPORT ===]")
            print(f"Timestamp: {self.seed_time}")

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    print(f"{table:25}: {cursor.fetchone()[0]} entries")
                except sqlite3.OperationalError:
                    print(f"{table:25}: Table does not exist")


def main():
    seeder = DataSeeder()
    seeder.seed_all_data()


if __name__ == "__main__":
    main()

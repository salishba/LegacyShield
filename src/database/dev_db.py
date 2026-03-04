# dev_db.py
from pathlib import Path
import sqlite3
import csv
from datetime import datetime
import json

# new dependency
try:
    import pandas as pd
except Exception as e:
    raise ImportError("pandas (and openpyxl) are required for Excel/JSON seeding. Install with: pip install pandas openpyxl") from e

DEV_DB = "dev_db.sqlite"
RUNTIME_DB = "runtime_scan.sqlite"

# Excel files the user listed (relative paths)
DEFAULT_MSRC_XLSX = [
    "src/catalogues/windows10_2021.xlsx",
    "src/catalogues/windows10_2022.xlsx",
    "src/catalogues/windows10_2023.xlsx",
    "src/catalogues/windows10_2024.xlsx",
    "src/catalogues/windows10_2025.xlsx",
]

# JSON filenames the script will look for (you can save your KB array into one of these)
DEFAULT_MSRC_JSON = [
    "msrc_kb_data.json",
    "kb_records.json",
    "src/catalogues/kb_records.json",
]

# Desired/expected fields (not strictly required; we use union of whatever columns are found)
DESIRED_FIELDS = [
    "Release date",
    "Product Family",
    "Product",
    "Platform",
    "Impact",
    "Max Severity",
    "Article",
    "Supercedence",
    "Download",
    "Build Number",
    "Details",
    "CWE",
    "Customer Action Required",
]


class DataSeeder:
    def __init__(self, dev_db_path=DEV_DB, runtime_db_path=RUNTIME_DB):
        self.dev_db_path = dev_db_path
        self.runtime_db_path = runtime_db_path
        self.seed_time = datetime.utcnow().isoformat()

    def seed_all_data(self):
        print("=" * 60)
        print("SMARTPATCH DATA SEEDER (JSON + EXCEL + CSV)")
        print(f"Seeding started at {self.seed_time}")
        print("=" * 60)

        self.ensure_dev_db_schema()

        # discover sources
        existing_xlsx = [p for p in DEFAULT_MSRC_XLSX if Path(p).exists()]
        existing_json = [p for p in DEFAULT_MSRC_JSON if Path(p).exists()]
        csv_exists = Path("MSRC_Catalogue.csv").exists()

        if existing_xlsx or existing_json or csv_exists:
            self.seed_msrc_from_sources(existing_xlsx, existing_json, csv_exists)
        else:
            print("[!] No MSRC Excel/JSON/CSV files found; skipping MSRC seeding")

        self.seed_runtime_tables()

        print("\n[✓] Data seeding complete")
        self.generate_seeding_report()

    # -------------------- HELPERS --------------------

    def _clean_key(self, s: str) -> str:
        if not isinstance(s, str):
            return ""
        return (
            s.replace(" ", "_")
             .replace("-", "_")
             .replace("(", "")
             .replace(")", "")
             .strip()
             .lower()
        )

    def _normalize_json_like_value(self, v):
        # Convert lists/dicts/other non-primitive to compact JSON string for DB storage
        if v is None:
            return ""
        if isinstance(v, (list, dict)):
            try:
                return json.dumps(v, ensure_ascii=False)
            except Exception:
                return str(v)
        # pandas may box scalars as floats/ints/NaN; handle those
        if isinstance(v, float) and pd.isna(v):
            return ""
        return str(v)

    # -------------------- COMBINED SEEDING --------------------

    def seed_msrc_from_sources(self, excel_paths, json_paths, csv_exists):
        frames = []

        # 1) Read Excel files (if any)
        for fp in excel_paths:
            try:
                df = pd.read_excel(fp, engine="openpyxl", dtype=object)
                print(f"[i] Loaded {len(df):,} rows from {fp}")
                frames.append(df)
            except Exception as e:
                print(f"[!] Failed to read {fp}: {e}")

        # 2) Read JSON files (if any)
        for jf in json_paths:
            try:
                with open(jf, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    # assume single object or {"items": [...]}
                    # try to find the list under common keys
                    if "items" in data and isinstance(data["items"], list):
                        records = data["items"]
                    else:
                        # wrap single object
                        records = [data]
                elif isinstance(data, list):
                    records = data
                else:
                    print(f"[!] JSON file {jf} does not contain a list or dict; skipping")
                    continue

                if not records:
                    print(f"[!] JSON file {jf} is empty; skipping")
                    continue

                # Use json_normalize to flatten top-level dicts to columns
                df = pd.json_normalize(records, sep="_")
                # Convert nested/list columns (object dtype) to JSON strings so they can be stored in DB
                for col in df.columns:
                    # Apply normalization per cell
                    df[col] = df[col].apply(self._normalize_json_like_value)
                print(f"[i] Loaded {len(df):,} KB records from {jf}")
                frames.append(df)
            except Exception as e:
                print(f"[!] Failed to read/parse {jf}: {e}")

        # 3) Fallback: if no excel/json but CSV exists, read original CSV format
        if not frames and csv_exists:
            try:
                path = Path("MSRC_Catalogue.csv")
                with open(path, newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                if rows:
                    df = pd.DataFrame(rows)
                    frames.append(df)
                    print(f"[i] Loaded {len(df):,} rows from MSRC_Catalogue.csv")
            except Exception as e:
                print(f"[!] Failed to read MSRC_Catalogue.csv: {e}")

        if not frames:
            print("[!] No data frames loaded for MSRC seeding")
            return

        # Concatenate all frames, union of columns
        df_all = pd.concat(frames, ignore_index=True, sort=False)

        # Rename columns to cleaned names (lower_snake_case)
        rename_map = {}
        for col in df_all.columns:
            clean = self._clean_key(col)
            if not clean:
                clean = col
            # avoid collisions: if clean name already used, append numeric suffix
            base = clean
            i = 1
            while clean in rename_map.values():
                i += 1
                clean = f"{base}_{i}"
            rename_map[col] = clean

        df_all = df_all.rename(columns=rename_map)

        # Standardize release_date if present (try common names)
        possible_date_cols = [c for c in df_all.columns if c in ("release_date", "releasedate", "release_date_0", "release_date_1")]
        if possible_date_cols:
            # pick primary as 'release_date' if present
            primary = "release_date" if "release_date" in df_all.columns else possible_date_cols[0]
            try:
                parsed = pd.to_datetime(df_all[primary], errors="coerce", utc=False)
                df_all[primary] = parsed.dt.strftime("%Y-%m-%d").fillna(df_all[primary].astype(str))
            except Exception:
                df_all[primary] = df_all[primary].astype(str)

        # Ensure all cells are strings (for DB insertion) and convert nested/list/dict types to JSON strings where necessary
        for col in df_all.columns:
            # For object dtype, convert nested structures to JSON strings
            if df_all[col].dtype == object:
                df_all[col] = df_all[col].apply(self._normalize_json_like_value)
            else:
                # convert numeric/other types to string, but preserve NaN as empty string
                df_all[col] = df_all[col].apply(lambda v: "" if (pd.isna(v)) else str(v))

        # Final columns order: deterministic sorted order but keep 'kb_id' and 'title' at front if present
        cols = list(df_all.columns)
        ordered = []
        for preferred in ("kb_id", "title"):
            if preferred in cols:
                ordered.append(preferred)
                cols.remove(preferred)
        ordered.extend(sorted(cols))

        df_final = df_all[ordered].fillna("").astype(str)

        # Create table with union columns and insert all rows
        clean_columns = list(df_final.columns)
        columns_sql = ", ".join(clean_columns)
        placeholders = ", ".join("?" for _ in clean_columns)
        values = [tuple(df_final.loc[i, clean_columns]) for i in range(len(df_final))]

        with sqlite3.connect(self.dev_db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("DROP TABLE IF EXISTS msrc_catalogue")
            cursor.execute(f"""
                CREATE TABLE msrc_catalogue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    {', '.join(f'{c} TEXT' for c in clean_columns)}
                );
            """)

            cursor.executemany(
                f"INSERT INTO msrc_catalogue ({columns_sql}) VALUES ({placeholders})",
                values
            )
            conn.commit()

        print(f"[✓] Seeded {len(df_final)} MSRC entries from sources (excel/json/csv)")

    # -------------------- ORIGINAL CSV SEEDING (kept for compatibility) --------------------

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
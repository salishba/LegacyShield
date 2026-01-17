#scoped_catalogue.py
import argparse
import json
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import logging
import csv
import re


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("ingest")

# --------------------------- Helpers ---------------------------

CONTROL_CATEGORY_MAP = {
    "REGISTRY": "registry",
    "SERVICES": "system",
    "APPLICATION": "application",
    "AUTHENTICATION": "authentication",
    "NETWORK": "network"
}


def load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def short_hash(s: str) -> str:
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()[:8]

def gen_technique_id(cve_id: Optional[str], mtype: str, description: str) -> str:
    base = f"{cve_id}|{mtype}|{description}"
    return f"MIT-{short_hash(base)}"

def safe_list(x):
    if not x:
        return []
    return x if isinstance(x, list) else [x]

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
KB_REGEX = re.compile(r"KB\d{6,8}", re.IGNORECASE)

def extract_cves(text: str):
    if not text:
        return []
    return list(set(m.upper() for m in CVE_REGEX.findall(text)))

def extract_kb(text: str):
    if not text:
        return None
    m = KB_REGEX.search(text)
    return m.group(0).upper() if m else None

# --------------------------- DB Init ---------------------------

def init_db(db_path: Path) -> sqlite3.Connection:
    if not db_path.exists():
        raise FileNotFoundError(f"Database does not exist: {db_path}")
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

# --------------------------- Build Mitigations ---------------------------
def build_mitigations(control: Dict[str, Any], source_file: str):
    name = control.get("name") or ""
    category = (control.get("category") or "").upper().strip()

    # CVE is OPTIONAL and often NULL — this is correct
    rep_cves = safe_list(
        control.get("representative_cves") or
        control.get("mappings", {}).get("representative_cves")
    )
    cve_id = rep_cves[0] if rep_cves else None

    # Derive mitigation table type STRICTLY from control category
    mtype = CONTROL_CATEGORY_MAP.get(category, "system")

    mitigations = []

    for method in control.get("enforcement_methods", []):
        commands = safe_list(method.get("commands"))

        if not commands:
            commands = [method.get("description", "Policy enforcement")]

        for cmd in commands:
            desc = f"{name} | {cmd}"
            technique_id = gen_technique_id(cve_id, mtype, desc)

            mitigations.append({
                "technique_id": technique_id,
                "cve_id": cve_id,            # MAY BE NULL — correct
                "technique_type": mtype,     # registry | network | system
                "description": desc,
                "command": cmd,
                "source": source_file
            })

    return mitigations
# --------------------------- Inserts ---------------------------

def insert_mitigation(conn, m):
    conn.execute("""
        INSERT OR IGNORE INTO mitigation_techniques
        (technique_id, cve_id, technique_type, title, description,
         implementation, validation, effectiveness, windows_versions,
         potential_impact, source, source_url, confidence, verified, ingested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        m["technique_id"],
        m["cve_id"],
        m["technique_type"],
        "",
        m["description"],
        "",
        "",
        "",
        "",
        "",
        m["source"],
        "",
        0.8,
        0,
        datetime.utcnow().isoformat()
    ))

    if m["technique_type"] == "registry":
        conn.execute("""
            INSERT OR IGNORE INTO registry_mitigations
            (technique_id, cve_id, description, registry_path,
             value_name, recommended_value, risk_level, source_reference)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            m["technique_id"],
            m["cve_id"],
            m["description"],
            "",
            "",
            "",
            "Medium",
            m["source"]
        ))

    elif m["technique_type"] == "network":
        conn.execute("""
            INSERT OR IGNORE INTO network_mitigations
            (technique_id, cve_id, rule_name, protocol,
             port_range, action, netsh_command, verified,
             notes, source_reference)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            m["technique_id"],
            m["cve_id"],
            "",
            "",
            "",
            "block",
            m["command"],
            0,
            m["description"],
            m["source"]
        ))

    else:
        conn.execute("""
            INSERT OR IGNORE INTO system_mitigations
            (technique_id, cve_id, mitigation_type, feature_name,
             service_name, action, powershell_command, wmi_query,
             notes, verified, source_reference)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            m["technique_id"],
            m["cve_id"],
            "policy",
            "",
            "",
            "disable",
            m["command"],
            "",
            m["description"],
            0,
            m["source"]
        ))

# --------------------------- Ingest ---------------------------

def ingest_directory(json_dir: Path, db_path: Path, msrc_csv: Optional[Path] = None):

    conn = init_db(db_path)
    files = sorted(p for p in json_dir.iterdir() if p.suffix.lower() == ".json")

    total = 0

    conn = init_db(db_path)

    if msrc_csv:
        ingest_cves_from_msrc_csv(msrc_csv, conn)

    for f in files:
        log.info("Processing %s", f.name)
        data = load_json(f)

        for control in data.get("controls", []):
            mitigations = build_mitigations(control, f.name)
            for m in mitigations:
                insert_mitigation(conn, m)
                total += 1

    conn.commit()
    conn.close()
    log.info("Ingest complete. Techniques inserted: %d", total)

def ingest_cves_from_msrc_csv(csv_path: Path, conn: sqlite3.Connection):
    """
    EXACT port of the WORKING logic from your old database.py
    Populates:
      - cves
      - cve_kb_map
    """

    log.info("Ingesting CVEs + CVE↔KB mapping from MSRC CSV: %s", csv_path.name)

    inserted_cves = 0
    inserted_maps = 0

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            details = row.get("Details", "")
            article = row.get("Article", "")
            release_date = row.get("Release date", "")
            severity = row.get("Max Severity", "")
            impact = row.get("Impact", "")

            if not details or not article:
                continue

            # ---- EXACT CVE EXTRACTION (THIS IS WHY IT WORKS) ----
            cves = CVE_REGEX.findall(details)
            if not cves:
                continue

            # ---- EXACT KB EXTRACTION ----
            kb_match = KB_REGEX.search(article)
            if not kb_match:
                continue

            kb_id = kb_match.group(0).upper()

            for cve in set(cves):
                cve = cve.upper()

                # ---- CVE TABLE ----
                conn.execute("""
                    INSERT OR IGNORE INTO cves
                    (cve_id, published_date, severity, description, source)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    cve,
                    release_date,
                    severity,
                    impact,
                    "MSRC"
                ))
                inserted_cves += 1

                # ---- CVE ↔ KB MAP ----
                conn.execute("""
                    INSERT OR IGNORE INTO cve_kb_map
                    (cve_id, kb_article)
                    VALUES (?, ?)
                """, (
                    cve,
                    kb_id
                ))
                inserted_maps += 1

    log.info(
        "MSRC CVE ingestion complete | CVEs=%d | CVE-KB mappings=%d",
        inserted_cves,
        inserted_maps
    )


# --------------------------- CLI ---------------------------

def cli():
    p = argparse.ArgumentParser(description="JSON mitigation ingestion (schema-safe)")
    p.add_argument("--json-dir", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--msrc-csv", required=False)
    args = p.parse_args()
    ingest_directory(
        Path(args.json_dir),
        Path(args.db),
        Path(args.msrc_csv) if args.msrc_csv else None
    )
 


if __name__ == "__main__":
    cli()

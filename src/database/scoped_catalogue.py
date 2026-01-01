import argparse
import json
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("ingest")

# --------------------------- Helpers ---------------------------
def load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def short_hash(s: str) -> str:
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()[:8]

def gen_tech_id(control_id: str, name: Optional[str]) -> str:
    base = (control_id or "") + "|" + (name or "")
    return f"TECH-{short_hash(base)}"

def safe_get_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def json_dumps_or_none(obj):
    if obj is None:
        return None
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)

# --------------------------- DB Init ---------------------------
def init_db(db_path: Path) -> sqlite3.Connection:
    if not db_path.exists():
        raise FileNotFoundError(f"Database file does not exist: {db_path}")
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

# --------------------------- Insert Functions ---------------------------
def insert_mitigation_technique(conn: sqlite3.Connection, tech: Dict[str, Any]):
    conn.execute("""
        INSERT OR REPLACE INTO mitigation_techniques
        (technique_id, cve_id, technique_type, title, description, implementation, validation,
         effectiveness, windows_versions, potential_impact, source, source_url, confidence, verified, ingested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        tech.get("technique_id"),
        tech.get("cve_id"),
        tech.get("technique_type"),
        tech.get("title"),
        tech.get("description"),
        tech.get("implementation"),
        tech.get("validation"),
        tech.get("effectiveness"),
        tech.get("windows_versions"),
        tech.get("potential_impact"),
        tech.get("source"),
        tech.get("source_url"),
        tech.get("confidence"),
        1 if tech.get("verified") else 0,
        datetime.utcnow().isoformat()
    ))
    conn.commit()

def insert_registry_mitigation(conn: sqlite3.Connection, rec: Dict[str, Any]):
    if rec.get("technique_id") and rec.get("registry_path"):
        conn.execute("DELETE FROM registry_mitigations WHERE technique_id=? AND registry_path=?", 
                     (rec.get("technique_id"), rec.get("registry_path")))
    conn.execute("""
        INSERT INTO registry_mitigations
        (technique_id, cve_id, description, registry_path, value_name, recommended_value, risk_level, source_reference)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rec.get("technique_id"),
        rec.get("cve_id"),
        rec.get("description"),
        rec.get("registry_path"),
        rec.get("value_name"),
        rec.get("recommended_value"),
        rec.get("risk_level"),
        rec.get("source_reference")
    ))
    conn.commit()

def insert_system_mitigation(conn: sqlite3.Connection, rec: Dict[str, Any]):
    key = rec.get("technique_id"), rec.get("service_name")
    if key[0] and key[1]:
        conn.execute("DELETE FROM system_mitigations WHERE technique_id=? AND service_name=?", key)
    conn.execute("""
        INSERT INTO system_mitigations
        (technique_id, cve_id, mitigation_type, feature_name, service_name, action, powershell_command, wmi_query, notes, verified, source_reference)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rec.get("technique_id"),
        rec.get("cve_id"),
        rec.get("mitigation_type"),
        rec.get("feature_name"),
        rec.get("service_name"),
        rec.get("action"),
        rec.get("powershell_command"),
        rec.get("wmi_query"),
        rec.get("notes"),
        1 if rec.get("verified") else 0,
        rec.get("source_reference")
    ))
    conn.commit()

def insert_network_mitigation(conn: sqlite3.Connection, rec: Dict[str, Any]):
    key = rec.get("technique_id"), rec.get("rule_name")
    if key[0] and key[1]:
        conn.execute("DELETE FROM network_mitigations WHERE technique_id=? AND rule_name=?", key)
    conn.execute("""
        INSERT INTO network_mitigations
        (technique_id, cve_id, rule_name, protocol, port_range, action, netsh_command, verified, notes, source_reference)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rec.get("technique_id"),
        rec.get("cve_id"),
        rec.get("rule_name"),
        rec.get("protocol"),
        rec.get("port_range"),
        rec.get("action"),
        rec.get("netsh_command"),
        1 if rec.get("verified") else 0,
        rec.get("notes"),
        rec.get("source_reference")
    ))
    conn.commit()

# --------------------------- Build Rows ---------------------------
def build_rows_from_control(control: Dict[str, Any], source_file: str) -> Dict[str, Any]:
    ctl = control
    control_id = ctl.get("control_id") or ctl.get("id") or ""
    name = ctl.get("name") or ctl.get("title") or ""
    technique_id = gen_tech_id(control_id, name)
    rep_cves = safe_get_list(ctl.get("representative_cves") or ctl.get("mappings", {}).get("representative_cves") or [])
    cve0 = rep_cves[0] if rep_cves else None

    technique = {
        "technique_id": technique_id,
        "cve_id": cve0,
        "technique_type": (ctl.get("implementation_type") or ctl.get("category") or "").lower(),
        "title": name,
        "description": ctl.get("description"),
        "implementation": json_dumps_or_none(ctl.get("implementation_steps") or ctl.get("implementation_commands") or ctl.get("implementation")),
        "validation": json_dumps_or_none(ctl.get("test_verification") or ctl.get("test") or ctl.get("validation")),
        "effectiveness": ctl.get("effectiveness"),
        "windows_versions": ",".join([o.get("os_name") if isinstance(o, dict) else str(o) for o in ctl.get("os_applicability") or []]),
        "potential_impact": ctl.get("functional_impact") or ctl.get("potential_impact"),
        "source": (ctl.get("metadata", {}) or {}).get("source") or source_file,
        "source_url": None,
        "confidence": (ctl.get("risk") or {}).get("confidence", 0.0),
        "verified": bool(ctl.get("auto_apply") or (ctl.get("risk") or {}).get("verified"))
    }

    out = {"technique": technique}

    # Registry
    registry = ctl.get("registry") or {}
    if registry or ctl.get("registry_path") or ctl.get("registry_value"):
        reg_rec = {
            "technique_id": technique_id,
            "cve_id": cve0,
            "description": ctl.get("description"),
            "registry_path": registry.get("registry_path") or ctl.get("registry_path"),
            "value_name": registry.get("value_name") or ctl.get("registry_value") or ctl.get("value_name"),
            "recommended_value": registry.get("expected_data") or ctl.get("registry_data") or ctl.get("recommended_value"),
            "risk_level": (ctl.get("risk") or {}).get("impact_level") or (ctl.get("risk_level") or ctl.get("risk")),
            "source_reference": (ctl.get("metadata") or {}).get("source_of_truth") or source_file,
        }
        out["registry"] = reg_rec

    # System
    svc = ctl.get("service") or {}
    if svc or ctl.get("service_name") or ctl.get("powershell_command") or ctl.get("implementation_type") in ("service","feature","system","powershell"):
        system_rec = {
            "technique_id": technique_id,
            "cve_id": cve0,
            "mitigation_type": ctl.get("implementation_type") or "service",
            "feature_name": ctl.get("feature_name"),
            "service_name": svc.get("service_name") or ctl.get("service_name"),
            "action": svc.get("action") or ctl.get("action"),
            "powershell_command": ctl.get("powershell_command") or (svc.get("powershell_command") if isinstance(svc, dict) else None),
            "wmi_query": None,
            "notes": ctl.get("description"),
            "verified": bool(ctl.get("auto_apply") or (ctl.get("risk") or {}).get("verified")),
            "source_reference": (ctl.get("metadata") or {}).get("source_of_truth") or source_file
        }
        out["system"] = system_rec

    # Network
    net = ctl.get("firewall") or ctl.get("network") or {}
    if net or ctl.get("implementation_type") == "firewall" or ctl.get("category", "").upper() == "NETWORK":
        net_rec = {
            "technique_id": technique_id,
            "cve_id": cve0,
            "rule_name": net.get("rule_name") or ctl.get("name"),
            "protocol": net.get("protocol") or ctl.get("protocol"),
            "port_range": net.get("port") or net.get("port_range") or ctl.get("port_range"),
            "action": net.get("action") or ctl.get("action"),
            "netsh_command": net.get("netsh_command"),
            "verified": bool(ctl.get("auto_apply") or (ctl.get("risk") or {}).get("verified")),
            "notes": ctl.get("description"),
            "source_reference": (ctl.get("metadata") or {}).get("source_of_truth") or source_file
        }
        out["network"] = net_rec

    return out

# --------------------------- Ingest Directory ---------------------------
def ingest_directory(json_dir: Path, db_path: Path):
    if not json_dir.exists() or not json_dir.is_dir():
        raise FileNotFoundError(f"JSON directory not found: {json_dir}")

    conn = init_db(db_path)
    files = sorted([p for p in json_dir.iterdir() if p.suffix.lower() == ".json"])

    total_controls = 0
    new_techniques = 0
    for f in files:
        log.info("Processing: %s", f)
        try:
            data = load_json(f)
        except Exception as e:
            log.error("Failed to load JSON %s: %s", f, e)
            continue

        controls = data.get("controls") or []
        for c in controls:
            total_controls += 1
            rows = build_rows_from_control(c, source_file=str(f.name))
            try:
                insert_mitigation_technique(conn, rows["technique"])
                new_techniques += 1
            except Exception as e:
                log.error("Failed to insert technique for %s: %s", c.get("control_id"), e)
                continue

            if "registry" in rows and rows["registry"].get("registry_path"):
                try:
                    insert_registry_mitigation(conn, rows["registry"])
                except Exception as e:
                    log.error("Failed to insert registry mitigation for %s: %s", c.get("control_id"), e)

            if "system" in rows and (rows["system"].get("service_name") or rows["system"].get("powershell_command") or rows["system"].get("feature_name")):
                try:
                    insert_system_mitigation(conn, rows["system"])
                except Exception as e:
                    log.error("Failed to insert system mitigation for %s: %s", c.get("control_id"), e)

            if "network" in rows and rows["network"].get("rule_name"):
                try:
                    insert_network_mitigation(conn, rows["network"])
                except Exception as e:
                    log.error("Failed to insert network mitigation for %s: %s", c.get("control_id"), e)

    conn.close()
    log.info("Ingest complete. Files: %d Controls: %d Techniques inserted/updated: %d", len(files), total_controls, new_techniques)

# --------------------------- CLI ---------------------------
def cli():
    p = argparse.ArgumentParser(description="Ingest JSON mitigation catalogues into patch_catalogue.sqlite")
    p.add_argument("--json-dir", required=True, help="Directory containing JSON catalogue files")
    p.add_argument("--db", required=True, help="Existing SQLite DB path (must exist)")
    args = p.parse_args()

    json_dir = Path(args.json_dir).resolve()
    db_path = Path(args.db).resolve()

    ingest_directory(json_dir, db_path)

if __name__ == "__main__":
    cli()

"""
generate_training_dataset.py

Input: patch_catalogue.sqlite (production schema)
Output: training_dataset.csv (tabular features + deterministic labels)

Deterministic labeling rules (examiner-defensible):
 - If any SUPPORTED patch exists for this CVE -> action_label = "PATCH"
 - Else if any patch exists but none supported -> action_label = "MITIGATE"
 - Else if mitigation exists with effectiveness == "STRONG" -> action_label = "MITIGATE"
 - Else if exploited/poc/ransomware flags present -> action_label = "MITIGATE"
 - Else -> action_label = "MONITOR"

Priority score (0-10) computed from:
 - base = cvss (0-10, 0 if unknown)
 - +2 if exploited True
 - +1 if poc_available True
 - +2 if ransomware_used True
 - -3 if has_supported_patch True (patch reduces priority)
 - -2 if mitigation_effectiveness == "STRONG"
 clamp to [0,10]
 Priority class:
 - >=8 -> CRITICAL
 - >=6 -> HIGH
 - >=4 -> MEDIUM
 - <4  -> LOW

Usage:
  python3 generate_training_dataset.py --db patch_catalogue.sqlite --out training_dataset.csv
"""

import sqlite3
import csv
import argparse
from typing import Dict, Any, List, Optional, Tuple

DEFAULT_DB = "E:/download/uni/FYP/code/new code/src/database/mitigations_catalogue.sqlite"
DEFAULT_OUT = "training_dataset.csv"

# ----------------------------
# Helpers: DB queries
# ----------------------------
def connect_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def fetch_all_cves(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM vulnerabilities")
    return [dict(r) for r in cur.fetchall()]

def fetch_patches_for_cve(conn: sqlite3.Connection, cve_id: str) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute("""
    SELECT p.kb_id, p.product_id, p.release_date, p.supersedes_kb, p.reboot_required, p.patch_type, p.support_status
    FROM cve_kb_map ck
    JOIN patches p ON ck.kb_id = p.kb_id
    WHERE ck.cve_id = ?
    """, (cve_id,))
    return [dict(r) for r in cur.fetchall()]

def fetch_cve_kb_map(conn: sqlite3.Connection, cve_id: str) -> List[Dict[str,Any]]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM cve_kb_map WHERE cve_id = ?", (cve_id,))
    return [dict(r) for r in cur.fetchall()]

def fetch_mitigations_for_cve(conn: sqlite3.Connection, cve_id: str) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute("""
    SELECT m.mitigation_id, m.type, m.description, m.reversible, m.risk_level, m.requires_reboot,
           cm.effectiveness, cm.side_effects
    FROM cve_mitigation_map cm
    JOIN mitigations m ON cm.mitigation_id = m.mitigation_id
    WHERE cm.cve_id = ?
    """, (cve_id,))
    return [dict(r) for r in cur.fetchall()]

def count_products_for_cve(conn: sqlite3.Connection, cve_id: str) -> int:
    cur = conn.cursor()
    cur.execute("""
    SELECT COUNT(DISTINCT p.product_id) AS cnt
    FROM cve_kb_map ck
    JOIN patches p ON ck.kb_id = p.kb_id
    WHERE ck.cve_id = ?
    """, (cve_id,))
    row = cur.fetchone()
    return int(row['cnt']) if row else 0

def has_superseded_patches(conn: sqlite3.Connection, cve_id: str) -> bool:
    cur = conn.cursor()
    cur.execute("""
    SELECT 1 FROM cve_kb_map ck
    JOIN supersedence_map s ON ck.kb_id = s.kb_id
    WHERE ck.cve_id = ? LIMIT 1
    """, (cve_id,))
    return cur.fetchone() is not None

# ----------------------------
# Feature / label logic
# ----------------------------
def derive_features_and_label(conn: sqlite3.Connection, cve: Dict[str, Any]) -> Dict[str, Any]:
    cve_id = cve.get("cve_id")
    cvss = safe_float(cve.get("cvss"))
    exploited = bool(cve.get("exploited"))
    poc_available = bool(cve.get("poc_available"))
    ransomware_used = bool(cve.get("ransomware_used"))
    attack_vector = (cve.get("attack_vector") or "").upper()
    privilege_required = (cve.get("privilege_required") or "").upper()
    affected_component = cve.get("affected_component") or ""
    last_updated = cve.get("last_updated")

    patches = fetch_patches_for_cve(conn, cve_id)
    total_patches = len(patches)
    supported_patch_count = sum(1 for p in patches if (p.get("support_status") or "").upper() == "SUPPORTED")
    has_supported_patch = supported_patch_count > 0
    has_any_patch = total_patches > 0

    mitigations = fetch_mitigations_for_cve(conn, cve_id)
    mitigation_count = len(mitigations)
    mitigation_effectiveness = "NONE"
    if any((m.get("effectiveness") or "").upper() == "STRONG" for m in mitigations):
        mitigation_effectiveness = "STRONG"
    elif any((m.get("effectiveness") or "").upper() == "PARTIAL" for m in mitigations):
        mitigation_effectiveness = "PARTIAL"

    products_affected = count_products_for_cve(conn, cve_id)
    superseded = has_superseded_patches(conn, cve_id)

    # Deterministic label rules (production defensible)
    if has_supported_patch:
        action_label = "PATCH"
    elif has_any_patch:
        action_label = "MITIGATE"
    elif mitigation_effectiveness == "STRONG":
        action_label = "MITIGATE"
    elif exploited or poc_available or ransomware_used:
        action_label = "MITIGATE"
    else:
        action_label = "MONITOR"

    # Priority score
    final_score = compute_priority_score(cvss=cvss,
                                        exploited=exploited,
                                        poc=poc_available,
                                        ransomware=ransomware_used,
                                        has_supported_patch=has_supported_patch,
                                        mitigation_effectiveness=mitigation_effectiveness)
    priority_class = score_to_class(final_score)

    features = {
        "cve_id": cve_id,
        "cvss": cvss,
        "attack_vector": attack_vector,
        "privilege_required": privilege_required,
        "affected_component": affected_component,
        "exploited": int(exploited),
        "poc_available": int(poc_available),
        "ransomware_used": int(ransomware_used),
        "total_patches": total_patches,
        "supported_patch_count": supported_patch_count,
        "has_supported_patch": int(has_supported_patch),
        "mitigation_count": mitigation_count,
        "mitigation_effectiveness": mitigation_effectiveness,
        "products_affected": products_affected,
        "superseded": int(superseded),
        "action_label": action_label,
        "final_score": final_score,
        "priority_class": priority_class,
        "last_updated": last_updated
    }
    return features

def safe_float(x: Optional[Any]) -> float:
    try:
        if x is None:
            return 0.0
        return float(x)
    except Exception:
        return 0.0

def compute_priority_score(cvss: float, exploited: bool, poc: bool, ransomware: bool,
                           has_supported_patch: bool, mitigation_effectiveness: str) -> float:
    score = float(max(0.0, min(10.0, cvss)))  # base
    if exploited:
        score += 2.0
    if poc:
        score += 1.0
    if ransomware:
        score += 2.0
    if has_supported_patch:
        score -= 3.0
    if mitigation_effectiveness == "STRONG":
        score -= 2.0
    # clamp
    score = max(0.0, min(10.0, score))
    # round to 2 decimals
    return round(score, 2)

def score_to_class(score: float) -> str:
    if score >= 8.0:
        return "CRITICAL"
    if score >= 6.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

# ----------------------------
# CSV writing
# ----------------------------
CSV_FIELDS = [
    "cve_id", "cvss", "attack_vector", "privilege_required", "affected_component",
    "exploited", "poc_available", "ransomware_used",
    "total_patches", "supported_patch_count", "has_supported_patch",
    "mitigation_count", "mitigation_effectiveness", "products_affected", "superseded",
    "action_label", "final_score", "priority_class", "last_updated"
]

def write_csv(rows: List[Dict[str, Any]], out_path: str):
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in rows:
            # ensure all fields exist
            out = {k: (r.get(k) if r.get(k) is not None else "") for k in CSV_FIELDS}
            writer.writerow(out)

# ----------------------------
# Main
# ----------------------------
def build_dataset(db_path: str, out_csv: str, sample_limit: Optional[int] = None) -> Tuple[int,int]:
    conn = connect_db(db_path)
    cves = fetch_all_cves(conn)
    if sample_limit:
        cves = cves[:sample_limit]

    rows = []
    for c in cves:
        features = derive_features_and_label(conn, c)
        rows.append(features)

    write_csv(rows, out_csv)
    conn.close()
    return (len(rows), len([r for r in rows if r.get("action_label") == "PATCH"]))

def parse_args():
    p = argparse.ArgumentParser(description="Generate training dataset from SmartPatch catalogue DB")
    p.add_argument("--db", default=DEFAULT_DB, help="Path to patch_catalogue sqlite DB")
    p.add_argument("--out", default=DEFAULT_OUT, help="Output CSV path")
    p.add_argument("--limit", type=int, default=None, help="Limit number of CVEs processed (for testing)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    count, patch_count = build_dataset(args.db, args.out, args.limit)
    print(f"[✓] Dataset generated: {args.out} (rows={count}, patch-labels={patch_count})")

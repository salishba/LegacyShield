# config.py config file

import sqlite3
import json
from pathlib import Path
from typing import Optional

# -------------------------------
# CONSTANTS (FIXED BY SPEC)
# -------------------------------

W_A = 0.40
W_R = 0.35
W_C = 0.25

SCORING_MODEL = "HARS_v1"

OS_METADATA_PATH = Path("C:/ProgramData/SmartPatch/runtime/os_metadata.json")

# -------------------------------
# HELPERS
# -------------------------------

def load_os_metadata():
    if not OS_METADATA_PATH.exists():
        return {}
    with open(OS_METADATA_PATH, "r") as f:
        return json.load(f)


def clamp(val: float) -> float:
    return max(0.0, min(1.0, val))


# -------------------------------
# SCORE COMPUTATION
# -------------------------------

def compute_attack_surface(finding_type: str, description: str) -> float:
    score = 0.0
    desc = description.lower()

    if "network" in desc or "remote" in desc:
        score += 0.35
    if "service" in desc:
        score += 0.20
    if "kernel" in desc or "system" in desc:
        score += 0.30
    if "user" in desc:
        score += 0.15
    if "exploit" in desc or "public" in desc:
        score += 0.20

    return clamp(score)


def compute_reachability(description: str) -> float:
    desc = description.lower()

    if "remote unauthenticated" in desc:
        base = 1.0
    elif "remote authenticated" in desc:
        base = 0.75
    elif "local authenticated" in desc:
        base = 0.50
    elif "admin only" in desc:
        base = 0.30
    else:
        base = 0.10

    if "segmented" in desc:
        base *= 0.8
    if "firewall" in desc:
        base *= 0.5
    if "disabled" in desc:
        base *= 0.3

    return clamp(base)


def compute_criticality(
    cvss: Optional[float],
    os_metadata: dict,
    elevated: int
) -> float:

    # ---- Base from CVSS
    if cvss is None:
        base = 0.4
    elif cvss >= 9.0:
        base = 0.9
    elif cvss >= 7.0:
        base = 0.7
    elif cvss >= 4.0:
        base = 0.4
    else:
        base = 0.2

    # ---- Modifiers
    modifiers = 0.0

    os_version = os_metadata.get("os_info", {}).get("Version", "")
    if os_version.startswith(("6.0", "6.1", "6.2", "6.3")):
        modifiers += 0.15  # unsupported OS

    if elevated:
        modifiers += 0.05

    return clamp(base + modifiers)


# -------------------------------
# MAIN ENGINE
# -------------------------------

def run_risk_engine(runtime_db_path: Path, dev_db_path: Path):

    os_metadata = load_os_metadata()

    rt = sqlite3.connect(runtime_db_path)
    rt.row_factory = sqlite3.Row

    dev = sqlite3.connect(dev_db_path)
    dev.row_factory = sqlite3.Row

    findings = rt.execute("""
        SELECT f.finding_id,
               f.description,
               f.finding_type,
               f.host_hash,
               s.elevated,
               dv.cve_id
        FROM raw_security_findings f
        LEFT JOIN derived_vulnerabilities dv
            ON dv.derived_from_finding_id = f.finding_id
        JOIN system_info s
            ON s.host_hash = f.host_hash
    """).fetchall()

    for f in findings:
        cvss = None

        if f["cve_id"]:
            row = dev.execute("""
                SELECT cvss_score FROM cves WHERE cve_id = ?
            """, (f["cve_id"],)).fetchone()
            if row:
                cvss = row["cvss_score"]

        a = compute_attack_surface(f["finding_type"], f["description"])
        r = compute_reachability(f["description"])
        c = compute_criticality(cvss, os_metadata, f["elevated"])

        final = clamp((W_A * a) + (W_R * r) + (W_C * c))

        if final >= 0.70:
            priority = "HIGH"
        elif final >= 0.40:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        rt.execute("""
            INSERT INTO hars_scores (
                finding_id,
                cve_id,
                a_score,
                r_score,
                c_score,
                final_score,
                priority,
                scoring_model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f["finding_id"],
            f["cve_id"],
            a,
            r,
            c,
            final,
            priority,
            SCORING_MODEL
        ))

    rt.commit()
    rt.close()
    dev.close()

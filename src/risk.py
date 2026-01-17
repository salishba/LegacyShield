#risk.py

import sqlite3
from typing import List, Dict
from math import sqrt

# -----------------------------
# CONFIG
# -----------------------------
CATALOGUE_DB = "smartpatch_catalogue.sqlite"
RUNTIME_DB = "runtime_scan.sqlite"

# -----------------------------
# UTILITIES
# -----------------------------
def normalize_cvss(cvss: float) -> float:
    return min(max(cvss / 10.0, 0.0), 1.0)

def clamp(v: float) -> float:
    return max(0.0, min(1.0, v))

# -----------------------------
# DATABASE LOADERS
# -----------------------------
def load_system_info(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM system_info LIMIT 1")
    return dict(zip([c[0] for c in cur.description], cur.fetchone()))

def load_installed_kbs(conn) -> set:
    cur = conn.cursor()
    cur.execute("SELECT kb_id FROM installed_kbs")
    return {row[0] for row in cur.fetchall()}

# -----------------------------
# PATCH MATCHING
# -----------------------------
def resolve_supersedence(catalogue_conn, kb_id: str) -> List[str]:
    cur = catalogue_conn.cursor()
    chain = [kb_id]

    while True:
        cur.execute(
            "SELECT superseding_kb FROM supersedence_map WHERE kb_id = ?",
            (kb_id,)
        )
        row = cur.fetchone()
        if not row or not row[0]:
            break
        kb_id = row[0]
        chain.append(kb_id)

    return chain

def patch_matching():
    cat = sqlite3.connect(CATALOGUE_DB)
    run = sqlite3.connect(RUNTIME_DB)

    system = load_system_info(run)
    installed_kbs = load_installed_kbs(run)

    cat_cur = cat.cursor()
    run_cur = run.cursor()

    # Applicable CVEs
    cat_cur.execute("""
        SELECT cve_id, kb_article, product, build_min, build_max
        FROM cve_kb_map
        WHERE product = ?
          AND (? BETWEEN build_min AND build_max)
    """, (system["os_version"], system["build_number"]))

    for cve_id, kb, product, bmin, bmax in cat_cur.fetchall():
        status = "COVERED"
        matched_kb = None

        if kb:
            chain = resolve_supersedence(cat, kb)
            if not any(k in installed_kbs for k in chain):
                status = "MISSING"
            else:
                matched_kb = next(k for k in chain if k in installed_kbs)
        else:
            status = "MITIGATION_ONLY"

        confidence = (
            "HIGH" if system["build_number"] == bmax
            else "MEDIUM"
        )

        run_cur.execute("""
            INSERT INTO missing_patches
            (cve_id, kb_id, status, confidence)
            VALUES (?, ?, ?, ?)
        """, (cve_id, kb, status, confidence))

    run.commit()
    cat.close()
    run.close()

# -----------------------------
# HARS RISK PRIORITIZATION
# -----------------------------
def hars_prioritization():
    cat = sqlite3.connect(CATALOGUE_DB)
    run = sqlite3.connect(RUNTIME_DB)

    run_cur = run.cursor()
    cat_cur = cat.cursor()

    run_cur.execute("SELECT * FROM missing_patches")
    missing = run_cur.fetchall()
    columns = [c[0] for c in run_cur.description]

    for row in missing:
        record = dict(zip(columns, row))
        cve = record["cve_id"]

        # Load CVE metadata
        cat_cur.execute("""
            SELECT cvss, epss, exploited, poc, ransomware
            FROM vulnerabilities
            WHERE cve_id = ?
        """, (cve,))
        vuln = cat_cur.fetchone()
        if not vuln:
            continue

        cvss, epss, exploited, poc, ransomware = vuln

        # -------------------------
        # R SCORE
        # -------------------------
        R = clamp(
            0.40 * epss +
            0.20 * exploited +
            0.15 * poc +
            0.15 * ransomware +
            0.10 * normalize_cvss(cvss)
        )

        # -------------------------
        # A SCORE
        # -------------------------
        A = 1.0 if record["status"] == "MISSING" else 0.5

        # -------------------------
        # C SCORE
        # -------------------------
        C = 1.0
        if record["confidence"] == "MEDIUM":
            C *= 0.8
        elif record["confidence"] == "LOW":
            C *= 0.6

        final = clamp(A * R * C)

        priority = (
            "HIGH" if final >= 0.70 else
            "MEDIUM" if final >= 0.35 else
            "LOW"
        )

        run_cur.execute("""
            INSERT INTO risk_prioritization
            (cve_id, kb_id, a_score, r_score, c_score, final_score, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            cve,
            record["kb_id"],
            A, R, C, final, priority
        ))

    run.commit()
    cat.close()
    run.close()

def hars_prioritization_runtime():
    cat = sqlite3.connect(CATALOGUE_DB)
    run = sqlite3.connect(RUNTIME_DB)

    run_cur = run.cursor()
    cat_cur = cat.cursor()

    # Join findings with missing patches (contextual mapping)
    run_cur.execute("""
        SELECT
            f.finding_id,
            f.finding_type,
            mp.cve_id,
            mp.status,
            mp.confidence
        FROM raw_security_findings f
        JOIN missing_patches mp
            ON f.finding_type = mp.cve_id
    """)

    rows = run_cur.fetchall()

    for finding_id, finding_type, cve, status, confidence in rows:
        cat_cur.execute("""
            SELECT cvss, epss, exploited, poc, ransomware
            FROM vulnerabilities
            WHERE cve_id = ?
        """, (cve,))
        vuln = cat_cur.fetchone()
        if not vuln:
            continue

        cvss, epss, exploited, poc, ransomware = vuln

        R = clamp(
            0.40 * epss +
            0.20 * exploited +
            0.15 * poc +
            0.15 * ransomware +
            0.10 * normalize_cvss(cvss)
        )

        A = 1.0 if status == "MISSING" else 0.5

        C = 1.0
        if confidence == "MEDIUM":
            C *= 0.8
        elif confidence == "LOW":
            C *= 0.6

        final = clamp(A * R * C)

        priority = (
            "HIGH" if final >= 0.70 else
            "MEDIUM" if final >= 0.35 else
            "LOW"
        )

        run_cur.execute("""
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
            finding_id,
            cve,
            A, R, C, final, priority,
            "HARS-v1-deterministic"
        ))

    run.commit()
    cat.close()
    run.close()

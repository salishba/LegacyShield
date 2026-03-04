"""
unified_patch_cve_seeder_win78_full.py

Seeder that ingests Windows 7 / Windows 8 KB JSONs (structure: { "os":..., "kb":[ ... ] })
and fills the dev_db.sqlite schema (patches, products, cves, cve_kb_map, patch_applicability,
mitigation_techniques). Supersedence logic applied: if KB has 'superseded_by' entries we mark
applicability rows as superseded and store the superseded_by list.

Usage:
    python unified_patch_cve_seeder_win78_full.py
"""
from pathlib import Path
import sqlite3
import json
import re
from datetime import datetime

DB_PATH = "dev_db.sqlite"
JSON_FILES = [
    "src/catalogues/windows7_kb_cve.json",
    "src/catalogues/windows8_kb_cve.json"
]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def load_kb_list(path: Path):
    """Load KB entries as a list. Supports { 'os':..., 'kb':[...]} and plain lists."""
    if not path.exists():
        print(f"[!] file not found: {path}")
        return []

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"[!] json decode error for {path}: {e}")
        return []

    # If top-level dict and contains 'kb' list, return it
    if isinstance(obj, dict):
        if "kb" in obj and isinstance(obj["kb"], list):
            return obj["kb"]
        # sometimes they may wrap as { "kbs": [...] } or "KBs"
        for alt in ("kbs", "KB", "KBs", "kb_list"):
            if alt in obj and isinstance(obj[alt], list):
                return obj[alt]
        # if object itself looks like one KB (has kb_id), return [obj]
        if "kb_id" in obj or "kbId" in obj:
            return [obj]
        # otherwise nothing useful
        return []
    elif isinstance(obj, list):
        return obj
    else:
        return []


def canonical_kb_id(raw):
    if not raw:
        return ""
    m = re.search(r"(KB\d{5,})", str(raw), re.I)
    return m.group(1).upper() if m else str(raw).upper()


def extract_cve_list(kb_obj):
    cves = set()
    for candidate in (kb_obj.get("cve_ids") or []) + [d.get("cve_id") for d in (kb_obj.get("cve_details") or []) if isinstance(d, dict)]:
        if not candidate:
            continue
        if isinstance(candidate, (list, tuple)):
            for c in candidate:
                if c and CVE_RE.search(str(c)):
                    cves.add(CVE_RE.search(str(c)).group(0).upper())
        else:
            s = str(candidate)
            m = CVE_RE.search(s)
            if m:
                cves.add(m.group(0).upper())
    return sorted(cves)


def ensure_schema(conn):
    cur = conn.cursor()
    # Keep schema compatible with your dev_db.ensure_dev_db_schema
    cur.execute("""
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
    cur.execute("""
    CREATE TABLE IF NOT EXISTS patches (
        kb_id TEXT PRIMARY KEY,
        title TEXT,
        release_date TEXT,
        patch_type TEXT,
        reboot_required INTEGER,
        source TEXT
    );
    """)
    cur.execute("""
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
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve_kb_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        kb_article TEXT
    );
    """)
    cur.execute("""
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
    cur.execute("""
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
    conn.commit()


def upsert_product(conn, vendor, name, arch=None, edition=None):
    cur = conn.cursor()
    # try to find existing product
    cur.execute("""
      SELECT product_id FROM products
      WHERE vendor=? AND product_name=? AND (architecture IS ? OR architecture=?)
      LIMIT 1
    """, (vendor, name, arch, arch))
    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("""
      INSERT INTO products (vendor, product_name, architecture, edition)
      VALUES (?, ?, ?, ?)
    """, (vendor, name, arch or "", edition or ""))
    return cur.lastrowid


def insert_patch(conn, kb_id, title, release_date, patch_type, source, reboot_required=0):
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO patches (kb_id, title, release_date, patch_type, reboot_required, source)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (kb_id, title, release_date or "", patch_type or "", int(bool(reboot_required)), source or ""))
    return True


def insert_cve(conn, cve_id, description=None, source=None):
    cur = conn.cursor()
    if not cve_id:
        return False
    # Upsert minimal CVE metadata (do not overwrite real data if already present)
    cur.execute("SELECT cve_id FROM cves WHERE cve_id=? LIMIT 1", (cve_id,))
    if cur.fetchone():
        return True
    cur.execute("""
        INSERT OR IGNORE INTO cves (cve_id, description, source)
        VALUES (?, ?, ?)
    """, (cve_id, (description or "")[:2000], source or "catalogue"))
    return True


def insert_cve_kb_map(conn, cve_id, kb_id):
    cur = conn.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO cve_kb_map (cve_id, kb_article)
        VALUES (?, ?)
    """, (cve_id or None, kb_id))
    return True


def insert_patch_applicability(conn, kb_id, product_id=None, cve_id=None,
                               service_pack=None, is_superseded=0, superseded_by=None,
                               detection_method=None, confidence=1.0):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO patch_applicability
        (cve_id, kb_id, product_id, service_pack, is_superseded, superseded_by, applicability_confidence, detection_method)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (cve_id, kb_id, product_id, service_pack or "", int(bool(is_superseded)), superseded_by or "", float(confidence), detection_method or ""))
    return cur.lastrowid


def insert_mitigation_technique(conn, technique_id, cve_id, technique_type, title, description, implementation, source, source_url):
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO mitigation_techniques
        (technique_id, cve_id, technique_type, title, description, implementation, source, source_url, ingested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (technique_id, cve_id or "", technique_type or "", title or "", (description or "")[:2000], json.dumps(implementation or {}), source or "catalogue", source_url or "", datetime.utcnow().isoformat()))
    return True


def map_os_id_to_product(os_id):
    # minimal mapping; extend as needed
    mapping = {
        "win7_sp1": ("microsoft", "windows_7", "6.1"),
        "win2008r2_sp1": ("microsoft", "windows_server_2008_r2", "6.1"),
        "win8": ("microsoft", "windows_8", "6.2"),
        "win8_1": ("microsoft", "windows_8.1", "6.3"),
        "windows_10": ("microsoft", "windows_10", "10.0"),
        "win10": ("microsoft", "windows_10", "10.0"),
    }
    return mapping.get(os_id.lower(), ("microsoft", os_id.lower(), "")) if os_id else ("microsoft", "unknown", "")


def main():
    conn = sqlite3.connect(DB_PATH)
    ensure_schema(conn)
    cur = conn.cursor()

    total_kbs = 0
    total_products = 0
    total_cves = 0
    total_mappings = 0
    total_applicabilities = 0
    total_mitigations = 0

    for jf in JSON_FILES:
        path = Path(jf)
        kbs = load_kb_list(path)
        print(f"[i] Loaded {len(kbs)} KB entries from {jf}")

        for kb in kbs:
            # canonical KB id
            kb_id = canonical_kb_id(kb.get("kb_id") or kb.get("kbId") or kb.get("Article") or kb.get("title"))
            if not kb_id:
                # skip if no KB id found
                continue

            title = kb.get("title") or ""
            release_date = kb.get("release_date") or kb.get("releaseDate") or ""
            patch_type = kb.get("type") or ""
            source = kb.get("download_url") or kb.get("downloadUrl") or ""
            reboot_required = bool(kb.get("reboot_required") or kb.get("reboot") or False)

            # insert patch
            try:
                insert_patch(conn, kb_id, title, release_date, patch_type, source, reboot_required=reboot_required)
                total_kbs += 1
            except Exception as e:
                print(f"[!] failed insert patch {kb_id}: {e}")
                continue

            # store mitigation technique for KB (if mitigation_hints present)
            mitigation_hints = kb.get("mitigation_hints") or []
            if mitigation_hints:
                technique_id = f"kb:{kb_id}"
                try:
                    insert_mitigation_technique(conn, technique_id, None, "patch", f"Mitigation for {kb_id}", kb.get("notes") or "", mitigation_hints, "catalogue", source)
                    total_mitigations += 1
                except Exception as e:
                    print(f"[!] failed insert mitigation_technique for {kb_id}: {e}")

            # handle os_targets -> product rows and applicability rows
            os_targets = kb.get("os_targets") or []
            if not os_targets:
                # if top-level doc had root 'os' object, try to use that as product
                root_os = kb.get("os") or {}
                if root_os and ("name" in root_os or "version" in root_os):
                    os_targets = [{"os_id": root_os.get("name") or root_os.get("version") or "unknown", "architecture": root_os.get("architecture") or ""}]

            # determine supersedence
            superseded_by = kb.get("superseded_by") or []
            supersedes = kb.get("supersedes") or []
            is_superseded_flag = 1 if superseded_by else 0
            superseded_by_join = ",".join(superseded_by) if superseded_by else ""

            # for each os_target, create product and applicability row (cve_id maybe null)
            for target in os_targets or []:
                os_id = target.get("os_id") or target.get("os") or ""
                arch = target.get("architecture") or ""
                service_pack = target.get("service_pack") or target.get("sp") or ""
                vendor, product_name, ver = map_os_id_to_product(os_id)
                try:
                    product_id = upsert_product(conn, vendor, product_name, arch, edition=service_pack)
                    total_products += 1
                except Exception:
                    product_id = None

                # applicability without CVE (KB applies to product, may later be linked to CVEs)
                try:
                    insert_patch_applicability(conn, kb_id, product_id=product_id, cve_id=None,
                                               service_pack=service_pack, is_superseded=is_superseded_flag,
                                               superseded_by=superseded_by_join,
                                               detection_method=json.dumps(kb.get("detection_hints") or []),
                                               confidence=1.0)
                    total_applicabilities += 1
                except Exception as e:
                    print(f"[!] failed insert applicability for {kb_id} product {product_id}: {e}")

            # handle CVEs mapped to this KB
            cve_list = extract_cve_list(kb)
            for cve in (cve_list or []):
                # insert minimal CVE record (description may be in cve_details)
                description = ""
                # try to find description from cve_details
                for cd in kb.get("cve_details") or []:
                    if isinstance(cd, dict) and cd.get("cve_id") and cd.get("cve_id").upper() == cve:
                        description = cd.get("description") or cd.get("value") or description
                        break
                try:
                    inserted = insert_cve(conn, cve, description=description, source="catalogue")
                    if inserted:
                        total_cves += 1
                except Exception as e:
                    print(f"[!] failed insert cve {cve}: {e}")

                # insert mapping table
                try:
                    insert_cve_kb_map(conn, cve, kb_id)
                    total_mappings += 1
                except Exception as e:
                    print(f"[!] failed insert cve_kb_map {cve}->{kb_id}: {e}")

                # create patch_applicability rows per product for this CVE too (so patch <-> cve <-> product)
                for target in os_targets or []:
                    os_id = target.get("os_id") or ""
                    vendor, product_name, ver = map_os_id_to_product(os_id)
                    # find product id (should exist)
                    cur.execute("SELECT product_id FROM products WHERE vendor=? AND product_name=? LIMIT 1", (vendor, product_name))
                    pr = cur.fetchone()
                    product_id = pr[0] if pr else None
                    try:
                        insert_patch_applicability(conn, kb_id, product_id=product_id, cve_id=cve,
                                                   service_pack=target.get("service_pack") or "",
                                                   is_superseded=is_superseded_flag,
                                                   superseded_by=superseded_by_join,
                                                   detection_method=json.dumps(kb.get("detection_hints") or []),
                                                   confidence=1.0)
                        total_applicabilities += 1
                    except Exception as e:
                        print(f"[!] failed insert applicability for {kb_id} cve {cve}: {e}")

    conn.commit()
    conn.close()

    print("\n[✓] Seeding summary")
    print(f"  KBs processed...........: {total_kbs}")
    print(f"  products touched........: {total_products}")
    print(f"  CVEs inserted (min).....: {total_cves}")
    print(f"  CVE->KB mappings........: {total_mappings}")
    print(f"  patch_applicabilities...: {total_applicabilities}")
    print(f"  mitigation_techniques..: {total_mitigations}")


if __name__ == "__main__":
    main()
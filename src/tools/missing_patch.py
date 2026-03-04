"""
missing_kb_resolver.py

Resolve missing KBs using cached OS metadata JSON (offline) and your dev catalogue.
Writes / updates runtime DB tables: installed_kbs (optional) and patch_state.

Usage:
  python tools/missing_kb_resolver.py \
    --os-meta "C:\ProgramData\SmartPatch\runtime\os_metadata.json" \
    --dev-db ./dev_db.sqlite \
    --runtime-db ./runtime_scan.sqlite
"""

from pathlib import Path
import sqlite3
import json
import re
import logging
import argparse
from datetime import datetime
import hashlib
from typing import List, Set, Tuple, Dict, Any, Optional

LOG = logging.getLogger("missing_kb_resolver")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

KB_RE = re.compile(r"\bKB\d{5,7}\b", flags=re.IGNORECASE)


class MissingPatchResolver:
    def __init__(
        self,
        os_meta_path: Path,
        dev_db_path: Path,
        runtime_db_path: Path,
        write_runtime: bool = True,
    ):
        self.os_meta_path = Path(os_meta_path)
        self.dev_db_path = Path(dev_db_path)
        self.runtime_db_path = Path(runtime_db_path)
        self.write_runtime = bool(write_runtime)
        self.os_meta: Dict[str, Any] = {}
        self.installed_kbs: Set[str] = set()
        self.host_hash: str = ""
        self.scan_time: str = datetime.utcnow().isoformat()

    # ---------- Load / parse OS metadata ----------
    def load_os_metadata(self) -> None:
        if not self.os_meta_path.exists():
            raise FileNotFoundError(f"os metadata not found: {self.os_meta_path}")
        with open(self.os_meta_path, "r", encoding="utf-8") as f:
            self.os_meta = json.load(f)

        # prefer cache timestamp if available
        self.scan_time = self.os_meta.get("cache_timestamp") or self.os_meta.get("timestamp") or self.scan_time

        # build host hash similar to orchestrator
        os_info = self.os_meta.get("os_info", {})
        hostname = os_info.get("CSName") or os_info.get("ComputerName") or os_info.get("Caption") or "UNKNOWN"
        version = os_info.get("Version") or os_info.get("BuildNumber") or ""
        raw = f"{hostname}|{version}".encode("utf-8")
        self.host_hash = hashlib.sha256(raw).hexdigest()

    # ---------- Extract installed KBs from JSON ----------
    def extract_installed_kbs_from_meta(self) -> List[Dict[str, Any]]:
        hotfixes = self.os_meta.get("hotfixes") or []
        rows: List[Dict[str, Any]] = []
        for h in hotfixes:
            # Try several common shapes
            kb = h.get("HotFixID") or h.get("HotFix") or h.get("HotFixId") or h.get("KB") or ""
            if not kb and isinstance(h, str):
                # sometimes a plain string list
                match = KB_RE.search(h)
                kb = match.group(0) if match else ""
            kb_norm = kb.upper().strip() if kb else ""
            if not kb_norm:
                continue
            # installed date
            inst = None
            installed_on = h.get("InstalledOn") or h.get("InstalledDate") or h.get("Installed")
            if isinstance(installed_on, dict):
                inst = installed_on.get("DateTime") or installed_on.get("value") or None
            elif isinstance(installed_on, str):
                inst = installed_on
            rows.append({"kb_id": kb_norm, "install_date": inst or None, "source": str(self.os_meta_path)})
        # deduplicate by kb_id preserving first
        seen = set()
        dedup = []
        for r in rows:
            if r["kb_id"] in seen:
                continue
            seen.add(r["kb_id"])
            dedup.append(r)
        self.installed_kbs = {r["kb_id"] for r in dedup}
        return dedup

    # ---------- DB helpers ----------
    def _connect(self, path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def ensure_runtime_tables(self) -> None:
        """Create minimal runtime tables if they don't exist so we can insert canonical records."""
        conn = self._connect(self.runtime_db_path)
        cur = conn.cursor()
        # installed_kbs table (non-destructive create)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS installed_kbs (
                kb_id TEXT,
                install_date TEXT,
                source TEXT,
                host_hash TEXT,
                scan_time TEXT,
                PRIMARY KEY (kb_id, host_hash, scan_time)
            );
            """
        )
        # patch_state table similar to your patch_state resolver
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS patch_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                kb_id TEXT,
                state TEXT,
                confidence TEXT,
                reasoning TEXT,
                host_hash TEXT,
                scan_time TEXT
            );
            """
        )
        conn.commit()
        conn.close()

    # ---------- Insert installed_kbs (optional) ----------
    def upsert_installed_kbs_to_runtime(self, rows: List[Dict[str, Any]]) -> None:
        if not self.write_runtime:
            LOG.info("write_runtime disabled: skipping installed_kbs upsert")
            return
        conn = self._connect(self.runtime_db_path)
        cur = conn.cursor()
        # Insert or ignore duplicates (primary key defined)
        cur.executemany(
            "INSERT OR REPLACE INTO installed_kbs (kb_id, install_date, source, host_hash, scan_time) VALUES (?, ?, ?, ?, ?)",
            [(r["kb_id"], r["install_date"], r["source"], self.host_hash, self.scan_time) for r in rows],
        )
        conn.commit()
        conn.close()

    # ---------- Read CVE->KB mappings from dev DB ----------
    def load_cve_kb_mappings(self) -> List[Tuple[str, str]]:
        """
        Returns list of (cve_id, kb_token).
        Operates defensively over multiple possible schema shapes.
        """
        if not self.dev_db_path.exists():
            LOG.warning("dev_db not found; will not resolve CVE->KB mappings")
            return []

        conn = self._connect(self.dev_db_path)
        cur = conn.cursor()

        # Best-effort: discover a column that contains a KB token in cve_kb_map or msrc_catalogue
        mappings: List[Tuple[str, str]] = []

        # If cve_kb_map exists, try to use it
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_kb_map'")
            if cur.fetchone():
                # read rows and extract KB token with regex
                cur.execute("PRAGMA table_info(cve_kb_map)")
                cols = [r["name"] for r in cur.fetchall()]
                # fetch all rows
                cur.execute("SELECT * FROM cve_kb_map")
                for row in cur.fetchall():
                    rowd = dict(row)
                    cve = None
                    kb_field_val = None
                    # try to find cve id column
                    for candidate in ("cve_id", "cve", "cveid"):
                        if candidate in rowd:
                            cve = rowd[candidate]
                            break
                    # find a KB-like column
                    for candidate in ("kb_article", "kb_id", "kb", "kb_article_id", "kbid"):
                        if candidate in rowd and rowd[candidate]:
                            kb_field_val = str(rowd[candidate])
                            break
                    # fallback: any column that contains 'KB' token
                    if not kb_field_val:
                        for v in rowd.values():
                            if isinstance(v, str) and KB_RE.search(v):
                                kb_field_val = v
                                break
                    if not cve:
                        # fallback: try first text column
                        for k, v in rowd.items():
                            if isinstance(v, str) and v.upper().startswith("CVE-"):
                                cve = v
                                break
                    if not cve or not kb_field_val:
                        continue
                    m = KB_RE.search(str(kb_field_val))
                    if m:
                        mappings.append((cve, m.group(0).upper()))
                conn.close()
                return mappings
        except Exception as e:
            LOG.debug(f"Error reading cve_kb_map: {e}")

        # Fallback: try msrc_catalogue table for KB/CVE pairs
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='msrc_catalogue'")
            if cur.fetchone():
                cur.execute("SELECT * FROM msrc_catalogue")
                for row in cur.fetchall():
                    rowd = dict(row)
                    text = " ".join([str(v) for v in rowd.values() if v])
                    cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", text, flags=re.IGNORECASE)
                    kb_match = KB_RE.search(text)
                    if cve_match and kb_match:
                        mappings.append((cve_match.group(1).upper(), kb_match.group(0).upper()))
                conn.close()
                return mappings
        except Exception as e:
            LOG.debug(f"Error reading msrc_catalogue: {e}")

        conn.close()
        LOG.warning("No CVE->KB mappings found in dev DB (or dev DB missing).")
        return mappings

    # ---------- Query patches for specific scanned OS from dev_db ----------
    def _determine_windows_release(self, version: str, build_num: int) -> Optional[str]:
        """
        Determine Windows release (7, 8, 8.1, 10, 11) from version and build number.
        Returns the release identifier for table matching (can include fallbacks).
        No hardcoding - uses actual version/build info from scanned system.
        """
        if build_num == 0:
            return None
        
        # Windows version to release mapping based on official Microsoft specs
        if 7600 <= build_num <= 7601:
            return "win7"  # Windows 7
        elif build_num == 9200:
            return "win8"  # Windows 8
        elif 9200 < build_num <= 9600:
            return "win81"  # Windows 8.1
        elif 10240 <= build_num <= 19044:
            return "win10"  # Windows 10 legacy (10240-19044)
        elif build_num >= 19045:
            return "win11"  # Windows 11 (19045+) - also check win10 as fallback
        else:
            return None

    def _should_query_table_for_os(self, table_name: str, target_release: str) -> bool:
        """
        Determine if this table should be queried for the target OS release.
        For generic tables without OS names, query them and filter by content.
        No hardcoding - dynamically checks table relevance to patch data.
        """
        table_lower = table_name.lower()
        
        # Skip internal sqlite tables
        if table_lower.startswith('sqlite_') or table_lower == 'sqlite_sequence':
            return False
        
        # Generic patch-related tables should be queried and filtered by OS data
        patch_tables = ['cve_kb_map', 'cves', 'msrc_catalogue', 'patches', 'patch_applicability']
        if any(x in table_lower for x in patch_tables):
            LOG.debug(f"Table {table_name} is a patch table - will query with OS-level filtering")
            return True
        
        # Skip non-patch tables (mitigations, products, etc.)
        LOG.debug(f"Skipping table {table_name}: not a patch-related table")
        return False
    def _query_patches_for_os_from_dev_db(self) -> List[Tuple[str, str]]:
        """
        Query dev_db for ONLY patches applicable to this specific OS.
        Uses patch_applicability table to filter by build_min/build_max ranges.
        Returns REAL patches from dev_db - no hardcoding, no assumptions.
        
        Returns:
            List of (cve_id, kb_id) tuples from dev_db for this OS only
        """
        if not self.dev_db_path.exists():
            LOG.warning("dev_db not found; cannot query OS-specific patches")
            return []
        
        try:
            os_info = self.os_meta.get("os_info", {})
            host_version = os_info.get("Version") or os_info.get("version") or ""
            host_build_str = os_info.get("BuildNumber") or os_info.get("build_number") or ""
            host_arch = os_info.get("OSArchitecture") or os_info.get("architecture") or ""
            
            # Parse build number to determine applicability
            try:
                host_build = int(host_build_str) if host_build_str else 0
            except (ValueError, TypeError):
                host_build = 0
            
            target_release = self._determine_windows_release(host_version, host_build)
            LOG.info(f"Host OS: Version={host_version}, Build={host_build}, Architecture={host_arch}")
            LOG.info(f"Detected Windows release: {target_release}")
            
            if not host_build:
                LOG.warning(f"Could not parse host build number '{host_build_str}'; cannot filter by build")
                return []
            
            conn = self._connect(self.dev_db_path)
            cur = conn.cursor()
            
            # Query patch_applicability table to get patches applicable to this build
            # patch_applicability has build_min and build_max ranges
            LOG.info(f"Querying patches applicable to build {host_build}...")
            
            all_mappings = []
            
            # First, get CVE->KB mappings that apply to this build
            try:
                # Query patch_applicability for patches within this host's build range
                # build_min and build_max define the applicability range
                cur.execute("""
                    SELECT DISTINCT kb_id, cve_id
                    FROM patch_applicability
                    WHERE (build_min IS NULL OR build_min <= ?)
                      AND (build_max IS NULL OR build_max >= ?)
                """, (host_build, host_build))
                
                for row in cur.fetchall():
                    kb_id = row[0]
                    cve_id = row[1]
                    if cve_id and kb_id:
                        all_mappings.append((cve_id.upper(), kb_id.upper()))
                        LOG.debug(f"Found applicable patch: {cve_id.upper()} -> {kb_id.upper()} (build {host_build} in range)")
                
                LOG.info(f"Found {len(all_mappings)} patches in patch_applicability for build {host_build}")
            
            except Exception as e:
                LOG.warning(f"Error querying patch_applicability table: {e}")
            
            # Also try cve_kb_map as fallback (may have patches without applicability data)
            try:
                if not all_mappings:
                    LOG.info("Attempting fallback query from cve_kb_map...")
                    cur.execute("SELECT cve_id, kb_article FROM cve_kb_map")
                    for row in cur.fetchall():
                        cve_id = row[0]
                        kb_id = row[1]
                        if cve_id and kb_id:
                            all_mappings.append((cve_id.upper(), kb_id.upper()))
                    LOG.info(f"Fallback: found {len(all_mappings)} patches from cve_kb_map (unfiltered)")
            except Exception as e:
                LOG.debug(f"Error with fallback query: {e}")
            
            conn.close()
            
            LOG.info(f"Total patches found for {target_release} (build {host_build}): {len(all_mappings)}")
            return all_mappings
        
        except Exception as e:
            LOG.error(f"Error querying OS-specific patches from dev_db: {e}")
            return []

    def _check_supersedence(self, kb_id: str, installed_kbs: Set[str], supersedence_map: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, Optional[str]]:
        """
        Check if KB is superseded by an already-installed KB.
        
        Returns:
            (is_superseded, covering_kb_id)
        """
        if not supersedence_map:
            return False, None
        
        # Get list of KBs that would supersede this KB
        # (i.e., newer KBs that replace this one)
        superseding_kbs = supersedence_map.get(kb_id, [])
        
        for superseding_kb in superseding_kbs:
            if superseding_kb in installed_kbs:
                return True, superseding_kb
        
        return False, None

    def _load_supersedence_map(self) -> Optional[Dict[str, List[str]]]:
        """
        Load KB supersedence relationships from dev_db if available.
        Dynamically discover tables that contain supersedence info.
        
        Returns:
            Dict mapping KB_ID -> List[KB_IDs that supersede it]
        """
        if not self.dev_db_path.exists():
            return None
        
        try:
            conn = self._connect(self.dev_db_path)
            cur = conn.cursor()
            
            # Dynamically discover tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            available_tables = [row[0] for row in cur.fetchall()]
            
            supersedence_map: Dict[str, List[str]] = {}
            
            # Search for supersedence info in any table
            for table_name in available_tables:
                try:
                    cur.execute(f"PRAGMA table_info({table_name})")
                    columns = [row[1] for row in cur.fetchall()]
                    
                    # Check if table has supersedence-related columns
                    has_kb = any(c.lower() in ['kb_id', 'kb', 'kbid'] for c in columns)
                    has_supersedence = any(c.lower() in ['superseded_by', 'supersedes', 'replacement_kb'] for c in columns)
                    
                    if not (has_kb and has_supersedence):
                        continue
                    
                    # Query for supersedence info
                    cur.execute(f"SELECT * FROM {table_name}")
                    cols = [description[0] for description in cur.description] if cur.description else []
                    
                    for row in cur.fetchall():
                        rowd = dict(zip(cols, row)) if isinstance(row, tuple) else dict(row)
                        
                        kb_id = None
                        for col in ['kb_id', 'kb', 'kbid', 'KB_ID', 'KB']:
                            if col in rowd and rowd[col]:
                                kb_id = str(rowd[col]).upper().strip()
                                break
                        
                        if not kb_id:
                            continue
                        
                        # Extract superseded_by field
                        superseded_by = rowd.get("superseded_by") or rowd.get("SUPERSEDED_BY") or rowd.get("supersedes") or rowd.get("SUPERSEDES") or None
                        if superseded_by:
                            if isinstance(superseded_by, str):
                                # Parse as JSON list or comma-separated
                                try:
                                    if superseded_by.startswith("["):
                                        superseded_kbs = json.loads(superseded_by)
                                    else:
                                        superseded_kbs = [s.strip() for s in superseded_by.split(",") if s.strip()]
                                except:
                                    superseded_kbs = [s.strip() for s in str(superseded_by).split(",") if s.strip()]
                                
                                for superseding_kb in superseded_kbs:
                                    kb_upper = superseding_kb.upper().strip() if superseding_kb else ""
                                    if kb_upper:
                                        if kb_id not in supersedence_map:
                                            supersedence_map[kb_id] = []
                                        supersedence_map[kb_id].append(kb_upper)
                    
                    if supersedence_map:
                        LOG.info(f"Found supersedence info in table {table_name}")
                        break
                
                except Exception as e:
                    LOG.debug(f"Could not extract supersedence from {table_name}: {e}")
                    continue
            
            conn.close()
            return supersedence_map if supersedence_map else None
        
        except Exception as e:
            LOG.warning(f"Failed to load supersedence map: {e}")
            return None

    def _log_filtered_kb(self, kb_id: str, reason: str) -> None:
        """
        Log KB filtering action to scan_log table in runtime DB.
        """
        if not self.write_runtime:
            return
        
        try:
            conn = self._connect(self.runtime_db_path)
            cur = conn.cursor()
            
            # Check if scan_log table exists
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_log'")
            if not cur.fetchone():
                LOG.debug("scan_log table not found; skipping logging")
                conn.close()
                return
            
            cur.execute(
                """
                INSERT INTO scan_log (component, action, message, level)
                VALUES (?, ?, ?, ?)
                """,
                ("patch_resolver", "kb_filtered", f"KB {kb_id}: {reason}", "DEBUG")
            )
            conn.commit()
            conn.close()
        except Exception as e:
            LOG.debug(f"Could not log filtered KB {kb_id}: {e}")

    def compute_missing(self, mappings: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """
        Compute missing patches using ONLY real patches from dev_db for this OS.
        No assumptions - only patches that dev_db says apply to this host.
        """
        missing = []
        supersedence_map = self._load_supersedence_map()
        
        for cve, kb in mappings:
            kb_norm = kb.upper()
            
            # Check supersedence first (if in dev_db)
            if supersedence_map:
                is_superseded, superseding_kb = self._check_supersedence(kb_norm, self.installed_kbs, supersedence_map)
                if is_superseded:
                    self._log_filtered_kb(kb_norm, f"Superseded by {superseding_kb} (installed)")
                    continue
            
            # Standard check: is KB already installed?
            if kb_norm not in self.installed_kbs:
                missing.append({"cve_id": cve, "kb_id": kb_norm})
            else:
                LOG.debug(f"KB {kb_norm} already installed (CVE {cve})")
        
        return missing

    # ---------- Persist patch_state ----------
    def write_patch_state(self, missing_rows: List[Dict[str, Any]]) -> None:
        if not self.write_runtime:
            LOG.info("write_runtime disabled: skipping patch_state write")
            return
        conn = self._connect(self.runtime_db_path)
        cur = conn.cursor()
        # remove old state for this host/scan_time to keep idempotent
        cur.execute("DELETE FROM patch_state WHERE host_hash = ? AND scan_time = ?", (self.host_hash, self.scan_time))
        to_insert = []
        for r in missing_rows:
            to_insert.append(
                (
                    r["cve_id"],
                    r["kb_id"],
                    "MISSING",
                    "HIGH",
                    f"{r['kb_id']} not present in installed KB inventory",
                    self.host_hash,
                    self.scan_time,
                )
            )
        if to_insert:
            cur.executemany(
                "INSERT INTO patch_state (cve_id, kb_id, state, confidence, reasoning, host_hash, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                to_insert,
            )
        conn.commit()
        conn.close()

    # ---------- Top-level resolve ----------
    def resolve(self) -> Dict[str, Any]:
        LOG.info("Loading OS metadata...")
        self.load_os_metadata()
        LOG.info("Extracting installed KBs from OS metadata...")
        installed_rows = self.extract_installed_kbs_from_meta()
        LOG.info(f"Found {len(installed_rows)} installed KBs in metadata")

        # optionally write installed_kbs table and patch_state
        if self.write_runtime:
            LOG.info("Ensuring runtime tables exist...")
            self.ensure_runtime_tables()
            LOG.info("Upserting installed_kbs into runtime DB...")
            self.upsert_installed_kbs_to_runtime(installed_rows)

        # Query ONLY patches applicable to this specific OS from dev_db - NO assumptions
        LOG.info("Querying dev_db for patches specific to this OS...")
        mappings = self._query_patches_for_os_from_dev_db()
        LOG.info(f"Found {len(mappings)} patches in dev_db applicable to this OS")

        missing = self.compute_missing(mappings)
        LOG.info(f"Computed missing KBs: {len(missing)} entries")

        # write patch_state
        if missing:
            LOG.info("Writing patch_state into runtime DB...")
            self.write_patch_state(missing)
        else:
            LOG.info("No missing KBs to write to patch_state")

        # build summary
        summary = {
            "host_hash": self.host_hash,
            "scan_time": self.scan_time,
            "installed_kbs_count": len(self.installed_kbs),
            "mappings_examined": len(mappings),
            "missing_count": len(missing),
            "missing": missing[:200],  # avoid huge payloads
        }
        return summary


def main():
    p = argparse.ArgumentParser(description="Resolve missing KBs using cached OS metadata")
    p.add_argument("--os-meta", required=True, help="Path to os_metadata.json")
    p.add_argument("--dev-db", default="dev_db.sqlite", help="Path to developer catalogue DB")
    p.add_argument("--runtime-db", default="runtime_scan.sqlite", help="Path to runtime DB")
    p.add_argument("--no-write", dest="no_write", action="store_true", help="Do not write results into runtime DB (dry-run)")
    args = p.parse_args()

    resolver = MissingPatchResolver(
        os_meta_path=Path(args.os_meta),
        dev_db_path=Path(args.dev_db),
        runtime_db_path=Path(args.runtime_db),
        write_runtime=not args.no_write,
    )

    try:
        summary = resolver.resolve()
        print(json.dumps(summary, indent=2))
    except Exception as e:
        LOG.exception("Resolver failed")
        raise


if __name__ == "__main__":
    main()

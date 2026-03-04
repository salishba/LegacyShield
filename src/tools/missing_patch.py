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

# ========================================================================
# LEGACY WINDOWS OS BUILD RANGES (For applicability checking)
# ========================================================================
LEGACY_OS_SPECS = {
    "7": {"name": "Windows 7", "builds": (7600, 7601), "versions": ("6.1",)},
    "8": {"name": "Windows 8", "builds": (9200, 9200), "versions": ("6.2",)},
    "8.1": {"name": "Windows 8.1", "builds": (9200, 9600), "versions": ("6.3",)},
    "10_legacy": {"name": "Windows 10 (Legacy)", "builds": (10240, 19044), "versions": ("10.0",)},
}


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

    # ---------- Resolve missing vs installed ----------
    def _is_kb_applicable_to_host(self, kb_id: str, kb_metadata: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str]]:
        """
        Check if KB is applicable to this host based on OS version, build, and architecture.
        
        Returns:
            (is_applicable, reason_if_not_applicable)
        """
        try:
            # Get host OS details from cached metadata
            os_info = self.os_meta.get("os_info", {})
            host_os_version = os_info.get("Version") or os_info.get("version") or ""
            host_build = os_info.get("BuildNumber") or os_info.get("build_number") or ""
            host_arch = os_info.get("OSArchitecture") or os_info.get("architecture") or "unknown"
            
            # Parse to integers for range checking
            try:
                build_num = int(host_build) if host_build else 0
            except (ValueError, TypeError):
                build_num = 0
            
            # If KB metadata provided (from catalogue), use it to validate
            if kb_metadata:
                os_targets = kb_metadata.get("os_targets", [])
                if os_targets:
                    # Check if any os_target matches this host
                    arch_match = any(
                        (t.get("architecture", "").lower() in host_arch.lower() or 
                         not t.get("architecture")) 
                        for t in os_targets
                    )
                    if not arch_match and host_arch.lower() not in ["unknown", ""]:
                        return False, f"Architecture mismatch: KB requires {[t.get('architecture') for t in os_targets]}, host is {host_arch}"
            
            # LEGACY-ONLY: Check build ranges for Windows 7, 8, 8.1, legacy Windows 10
            if build_num == 0:
                LOG.debug(f"Could not parse host build number '{host_build}'; assuming applicable")
                return True, None  # Assume applicable if we can't parse
            
            # Determine which legacy Windows version this host is
            if 7600 <= build_num <= 7601:
                expected_version = "6.1"
            elif 9200 <= build_num <= 9600:
                expected_version = "6.2" if build_num == 9200 else "6.3"
            elif 10240 <= build_num <= 19044:
                expected_version = "10.0"
            else:
                # Non-legacy build (too new for legacy-only system)
                return False, f"Build {build_num} is outside legacy Windows range"
            
            # If metadata specifies target version, check it
            if kb_metadata:
                os_targets = kb_metadata.get("os_targets", [])
                if os_targets:
                    # Validate KB targets this OS version
                    for target in os_targets:
                        os_id = target.get("os_id", "").lower()
                        # Map os_id like "win8_1" or "win7" to version check
                        if "win7" in os_id and 7600 <= build_num <= 7601:
                            return True, None
                        elif "win8_1" in os_id and 9200 <= build_num <= 9600:
                            return True, None
                        elif "win10" in os_id and 10240 <= build_num <= 19044:
                            return True, None
                    return False, f"KB targets {[t.get('os_id') for t in os_targets]}, not applicable to build {build_num}"
            
            return True, None
        
        except Exception as e:
            LOG.warning(f"Exception in KB applicability check for {kb_id}: {e}")
            return True, None  # Assume applicable on any error to avoid blocking

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
        
        Returns:
            Dict mapping KB_ID -> List[KB_IDs that supersede it]
        """
        if not self.dev_db_path.exists():
            return None
        
        try:
            conn = self._connect(self.dev_db_path)
            cur = conn.cursor()
            
            # If all KB metadata is in a single table with supersedence info,
            # extract it here. This is defensive - different schemas may store
            # supersedence differently.
            supersedence_map: Dict[str, List[str]] = {}
            
            # Try to query supersedence info from any metadata table
            tables_to_check = ["windows8_kb_cve", "kb_metadata", "msrc_catalogue", "kb_info"]
            
            for table_name in tables_to_check:
                try:
                    cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
                    if not cur.fetchone():
                        continue
                    
                    # Read all KB rows and extract supersedence
                    cur.execute(f"SELECT * FROM {table_name}")
                    cols = [description[0] for description in cur.description] if cur.description else []
                    
                    for row in cur.fetchall():
                        rowd = dict(zip(cols, row)) if isinstance(row, tuple) else dict(row)
                        kb_id = rowd.get("kb_id") or rowd.get("KB_ID") or None
                        if not kb_id:
                            continue
                        
                        # Extract superseded_by field if it exists
                        superseded_by = rowd.get("superseded_by") or rowd.get("SUPERSEDED_BY") or None
                        if superseded_by:
                            if isinstance(superseded_by, str):
                                # Could be JSON string or comma-separated list
                                if superseded_by.startswith("["):
                                    try:
                                        superseded_kbs = json.loads(superseded_by)
                                    except:
                                        superseded_kbs = [s.strip() for s in superseded_by.split(",")]
                                else:
                                    superseded_kbs = [s.strip() for s in superseded_by.split(",") if s.strip()]
                                
                                for superseding_kb in superseded_kbs:
                                    if kb_id not in supersedence_map:
                                        supersedence_map[kb_id] = []
                                    supersedence_map[kb_id].append(superseding_kb)
                    
                    if supersedence_map:
                        LOG.info(f"Loaded {len(supersedence_map)} KB supersedence relationships from {table_name}")
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
        Enhanced missing patch computation with OS applicability and supersedence checking.
        """
        missing = []
        supersedence_map = self._load_supersedence_map()
        
        for cve, kb in mappings:
            kb_norm = kb.upper()
            
            # FIX 3: Check supersedence first (fastest check)
            if supersedence_map:
                is_superseded, superseding_kb = self._check_supersedence(kb_norm, self.installed_kbs, supersedence_map)
                if is_superseded:
                    self._log_filtered_kb(kb_norm, f"Superseded by {superseding_kb} (installed)")
                    continue
            
            # FIX 1: Check KB applicability to this host's OS/build/arch
            is_applicable, reason = self._is_kb_applicable_to_host(kb_norm)
            if not is_applicable:
                self._log_filtered_kb(kb_norm, reason or "Not applicable to host OS/build/architecture")
                continue
            
            # Standard check: is KB installed?
            if kb_norm not in self.installed_kbs:
                missing.append({"cve_id": cve, "kb_id": kb_norm})
        
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

        # load mappings
        LOG.info("Loading CVE->KB mappings from dev DB...")
        mappings = self.load_cve_kb_mappings()
        LOG.info(f"Loaded {len(mappings)} CVE->KB mappings")

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

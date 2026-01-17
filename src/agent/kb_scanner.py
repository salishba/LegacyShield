# statechecker/scanner.py
# Stabilized single-file scanner (NO modularization)

import os
import re
import json
import subprocess
import hashlib
import logging
import datetime
import sqlite3
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from environment import RuntimeContext

ctx = RuntimeContext().read_context_file()

os_caption = ctx.get("system", {}).get("platform", "")
os_build = ctx.get("system", {}).get("release", "")
host_hash = ctx.get("context_hash")
scan_time = ctx.get("timestamp")

# -------------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("statechecker")

# -------------------------------------------------------------------
# OPTIONAL WINDOWS DEPENDENCIES
# -------------------------------------------------------------------

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False
    logger.warning("winreg unavailable")

# -------------------------------------------------------------------
# ENUMS / DATA MODELS
# -------------------------------------------------------------------

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNKNOWN = "UNKNOWN"

@dataclass
class SecurityFinding:
    domain: str
    finding_type: str
    status: str
    risk: str
    description: str
    actual_value: Any = None
    expected_value: Any = None
    remediation_hint: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None

# -------------------------------------------------------------------
# UTILITIES
# -------------------------------------------------------------------

def run_powershell(ps: str, timeout=30) -> Optional[Any]:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if r.returncode != 0 or not r.stdout.strip():
            return None
        return json.loads(r.stdout)
    except Exception:
        return None

def run_cmd(cmd: str) -> str:
    try:
        r = subprocess.run(
            ["cmd", "/c", cmd],
            capture_output=True,
            text=True,
            errors="ignore"
        )
        return r.stdout
    except Exception:
        return ""

def read_reg(path: str, value: str) -> Optional[Any]:
    if not HAS_WINREG:
        return None
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        data, _ = winreg.QueryValueEx(key, value)
        winreg.CloseKey(key)
        return data
    except Exception:
        return None

# -------------------------------------------------------------------
# OS + KB COLLECTION (FIXED)
# -------------------------------------------------------------------

class WindowsEnvironment:
    def collect_os_info(self) -> Dict[str, Any]:
        ps = """
        Get-CimInstance Win32_OperatingSystem |
        Select Caption,Version,BuildNumber,OSArchitecture |
        ConvertTo-Json -Compress
        """
        data = run_powershell(ps)
        if isinstance(data, dict):
            return data
        return {
            "Caption": "Unknown",
            "Version": "0",
            "BuildNumber": "0",
            "OSArchitecture": "Unknown"
        }

    def collect_installed_kbs(self) -> List[str]:
        ps = """
        Get-HotFix |
        Select HotFixID |
        ConvertTo-Json -Compress
        """
        data = run_powershell(ps)
        if not data:
            return []

        if isinstance(data, dict):
            data = [data]

        kbs = set()
        for item in data:
            kb = item.get("HotFixID")
            if kb:
                kbs.add(kb.upper())
        return sorted(kbs)

# -------------------------------------------------------------------
# KB SCANNER (NO MORE BROKEN METHODS)
# -------------------------------------------------------------------

KB_RE = re.compile(r"\bKB\d{3,7}\b", re.I)

class KBScanner:
    def __init__(self, dev_db_path: str):
        self.dev_db = dev_db_path

    def find_missing(self, installed: List[str], product: str) -> List[Dict]:
        missing = []

        with sqlite3.connect(self.dev_db) as conn:
            cur = conn.cursor()

            cur.execute("""
                SELECT cve_id, kb_id, severity
                FROM cve_kb_map
                WHERE product LIKE ?
            """, (f"%{product}%",))

            for cve, kb, sev in cur.fetchall():
                kb_norm = KB_RE.search(kb)
                if not kb_norm:
                    continue
                kb_norm = kb_norm.group(0).upper()
                if kb_norm not in installed:
                    missing.append({
                        "cve": cve,
                        "kb": kb_norm,
                        "severity": sev
                    })

        return missing

# -------------------------------------------------------------------
# BASIC SECURITY CHECK (EXAMPLE ONLY)
# -------------------------------------------------------------------

def check_smbv1() -> Optional[SecurityFinding]:
    val = read_reg(
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1"
    )
    if val == 1:
        return SecurityFinding(
            domain="Network",
            finding_type="protocol",
            status=ComplianceStatus.NON_COMPLIANT.value,
            risk=RiskLevel.CRITICAL.value,
            description="SMBv1 is enabled",
            actual_value=1,
            expected_value=0,
            remediation_hint="Disable SMBv1"
        )
    return None

# -------------------------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------------------------

def main():
    logger.info("Starting statechecker scan")

    env = WindowsEnvironment()
    os_info = env.collect_os_info()
    installed_kbs = env.collect_installed_kbs()

    logger.info(f"OS: {os_info.get('Caption')} build {os_info.get('BuildNumber')}")
    logger.info(f"Installed KBs: {len(installed_kbs)}")

    findings: List[SecurityFinding] = []

    smb = check_smbv1()
    if smb:
        findings.append(smb)

    # KB analysis (optional)
    DEV_DB = "dev_db.sqlite"
    if os.path.exists(DEV_DB):
        kb = KBScanner(DEV_DB)
        missing = kb.find_missing(installed_kbs, os_info.get("Caption", ""))
        logger.info(f"Missing KBs: {len(missing)}")
    else:
        logger.warning("Dev catalogue DB not found, skipping KB analysis")

    logger.info(f"Total findings: {len(findings)}")

    print(json.dumps(
        [f.__dict__ for f in findings],
        indent=2
    ))

if __name__ == "__main__":
    main()

"""
StateChecker driver

Execution order:
1. Initialize runtime database
2. Collect system metadata
3. Run all scanners
4. Persist raw findings
5. Run HARS risk prioritization

Run with:
    python -m statechecker.driver
"""

from datetime import datetime
import hashlib
import json

from .scanner import run_all_scanners
from .runtime_db import (
    init_runtime_database,
    insert_system_info,
    insert_finding,
)
from .risk import hars_prioritization_runtime


def _generate_host_hash(hostname: str, os_version: str) -> str:
    """
    Stable anonymized host identifier.
    """
    raw = f"{hostname}|{os_version}".encode()
    return hashlib.sha256(raw).hexdigest()


def main():
    # --------------------------------------------------
    # 1. Init runtime DB
    # --------------------------------------------------
    db = init_runtime_database()

    # --------------------------------------------------
    # 2. Run scanners
    # --------------------------------------------------
    scan_result = run_all_scanners()

    os_info = scan_result["os_info"]
    findings = scan_result["findings"]

    # --------------------------------------------------
    # 3. System identity
    # --------------------------------------------------
    host_hash = _generate_host_hash(
        os_info.get("hostname", "UNKNOWN"),
        os_info.get("os_version", "UNKNOWN"),
    )

    system_record = {
        "host_hash": host_hash,
        "hostname": os_info.get("hostname", "UNKNOWN"),
        "os_version": os_info.get("os_version", "UNKNOWN"),
        "build_number": os_info.get("build_number", "0"),
        "architecture": os_info.get("architecture", "UNKNOWN"),
        "scan_time": datetime.utcnow().isoformat(),
        "agent_version": "statechecker-2.0",
        "elevated": int(os_info.get("elevated", False)),
    }

    insert_system_info(db, system_record)

    # --------------------------------------------------
    # 4. Persist findings (raw truth)
    # --------------------------------------------------
    for f in findings:
        insert_finding(
            db=db,
            finding={
                "domain": f.domain,
                "finding_type": f.finding_type,
                "status": f.status,
                "risk": f.risk,
                "description": f.description,
                "actual_value": json.dumps(f.actual_value)
                if f.actual_value is not None else None,
                "expected_value": json.dumps(f.expected_value)
                if f.expected_value is not None else None,
                "remediation_hint": f.remediation_hint,
                "evidence": json.dumps(f.evidence)
                if f.evidence else None,
                "source_scanner": "statechecker",
            },
            host_hash=host_hash,
        )

    # --------------------------------------------------
    # 5. Deterministic risk prioritization (HARS)
    # --------------------------------------------------
    hars_prioritization_runtime()

    db.log_scan_action(
        action="complete",
        message=f"Scan completed with {len(findings)} findings",
        component="driver",
    )

    db.disconnect()


if __name__ == "__main__":
    main()

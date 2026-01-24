import sqlite3
from typing import Tuple

def resolve_patch_context(
    db_path: str,
    cve_id: str
) -> Tuple[str, bool, float]:
    """
    Resolve patch status for a CVE using cve_kb table.

    Returns:
        patch_status (str)
        patch_missing (bool)
        patch_confidence (float)
    """

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT
            kb_id,
            installed,
            superseded,
            mitigation_only
        FROM cve_kb
        WHERE cve_id = ?
    """, (cve_id,))

    rows = cur.fetchall()
    conn.close()

    if not rows:
        return "UNKNOWN", True, 0.4

    # Any installed KB covers it
    if any(r["installed"] == 1 for r in rows):
        return "PATCHED", False, 1.0

    # Superseded KB but not installed
    if any(r["superseded"] == 1 for r in rows):
        return "SUPERSEDED", True, 0.8

    # Mitigation only
    if any(r["mitigation_only"] == 1 for r in rows):
        return "MITIGATION_ONLY", True, 0.6

    # KB exists but not installed
    return "APPLICABLE_MISSING", True, 0.9

# ai_features.py
import sqlite3
import pandas as pd
from typing import Tuple

RUNTIME_DB = "path/to/runtime.sqlite"  # replace with dynamic path in production

def load_features_from_db(db_path: str) -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Join raw findings with patch_state, hars_scores, system_info, installed_kbs counts
    query = """
    SELECT
      f.finding_id,
      f.cve_id,
      f.finding_type,
      f.risk AS finding_risk,
      f.description,
      f.source_scanner,
      p.state AS patch_state,
      p.confidence AS patch_confidence_text,
      h.r_score, h.a_score, h.c_score, h.final_score, h.priority AS hars_priority,
      si.os_version, si.build_number, si.architecture,
      (SELECT COUNT(*) FROM installed_kbs ik WHERE ik.host_hash = f.host_hash) AS installed_kb_count,
      (SELECT COUNT(*) FROM raw_security_findings rf WHERE rf.host_hash = f.host_hash AND rf.risk='CRITICAL') AS critical_findings_on_host
    FROM raw_security_findings f
    LEFT JOIN patch_state p ON p.cve_id = f.cve_id AND p.host_hash = f.host_hash
    LEFT JOIN hars_scores h ON h.finding_id = f.finding_id
    LEFT JOIN system_info si ON si.host_hash = f.host_hash
    WHERE f.cve_id IS NOT NULL
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df
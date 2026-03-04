"""
generate_security_trend_graph.py

- Locate runtime DB (or use --db)
- Ensure scan_snapshots table exists
- If not enough historical snapshots ( < 2 ), generate a snapshot from current DB state:
    * Prefer aggregation from hars_scores joined to raw_security_findings (per-host)
    * Fallback to patch_state counts if hars_scores absent
- Insert snapshot(s)
- Plot historical total_risk_score trend per-host (matplotlib)
- Optionally export PNG with --export

Usage:
    python generate_security_trend_graph.py --db path/to/runtime.sqlite --export trend.png

Requirements:
    pip install matplotlib
"""
from pathlib import Path
import sqlite3
import os
import sys
from datetime import datetime
import argparse
import matplotlib.pyplot as plt

DEFAULT_RUNTIME_SUBDIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "SmartPatch" / "runtime"
DEFAULT_DB_FILENAME = "runtime_scan.sqlite"  # fallback if nothing found


SCAN_SNAPSHOTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_hash TEXT,
    scan_time TEXT,
    total_vulnerabilities INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    avg_risk_score REAL,
    total_risk_score REAL
);
"""


def find_most_recent_runtime_db(search_dir: Path) -> Path:
    if not search_dir.exists():
        return None
    files = sorted(search_dir.glob("runtime_*.sqlite"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def connect_db(db_path: Path) -> sqlite3.Connection:
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_scan_snapshots_table(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.executescript(SCAN_SNAPSHOTS_SCHEMA)
    conn.commit()


def count_snapshots(conn: sqlite3.Connection) -> int:
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) as cnt FROM scan_snapshots")
        return cur.fetchone()["cnt"]
    except sqlite3.Error:
        return 0


def hosts_from_system_info(conn: sqlite3.Connection):
    cur = conn.cursor()
    try:
        cur.execute("SELECT host_hash FROM system_info")
        return [r["host_hash"] for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def aggregate_from_hars(conn: sqlite3.Connection, host_hash: str):
    """
    Preferred aggregation: read hars_scores joined to raw_security_findings to produce:
      total_vulnerabilities, counts per priority, avg_score, total_risk_score
    Returns None if no hars data for host.
    """
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN priority = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN priority = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN priority = 'LOW' THEN 1 ELSE 0 END) as low_count,
                AVG(final_score) as avg_score,
                SUM(final_score) as total_risk_score
            FROM hars_scores hs
            JOIN raw_security_findings f ON hs.finding_id = f.finding_id
            WHERE f.host_hash = ?
        """, (host_hash,))
        row = cur.fetchone()
        if not row or row["total"] is None or row["total"] == 0:
            return None
        return {
            "total_vulnerabilities": int(row["total"]),
            "critical_count": 0,  # explicit 'critical' bucket not present in hars_scores schema; kept 0
            "high_count": int(row["high_count"] or 0),
            "medium_count": int(row["medium_count"] or 0),
            "low_count": int(row["low_count"] or 0),
            "avg_risk_score": float(row["avg_score"]) if row["avg_score"] is not None else None,
            "total_risk_score": float(row["total_risk_score"]) if row["total_risk_score"] is not None else None
        }
    except sqlite3.Error:
        return None


def aggregate_from_patch_state(conn: sqlite3.Connection, host_hash: str):
    """
    Fallback aggregation: use patch_state table for missing patches.
    Produces total_vulnerabilities (count of MISSING).
    Other fields left as zero/None because insufficient info to synthesize priorities/scores.
    """
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COUNT(*) as missing_count
            FROM patch_state
            WHERE host_hash = ? AND state = 'MISSING'
        """, (host_hash,))
        row = cur.fetchone()
        missing = int(row["missing_count"] or 0)
        return {
            "total_vulnerabilities": missing,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "avg_risk_score": None,
            "total_risk_score": float(missing)  # lightweight proxy: 1 point per missing vuln
        }
    except sqlite3.Error:
        return {
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "avg_risk_score": None,
            "total_risk_score": 0.0
        }


def insert_snapshot(conn: sqlite3.Connection, host_hash: str, snapshot_time: str, agg: dict):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scan_snapshots (
            host_hash,
            scan_time,
            total_vulnerabilities,
            critical_count,
            high_count,
            medium_count,
            low_count,
            avg_risk_score,
            total_risk_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        host_hash,
        snapshot_time,
        agg["total_vulnerabilities"],
        agg.get("critical_count", 0),
        agg.get("high_count", 0),
        agg.get("medium_count", 0),
        agg.get("low_count", 0),
        agg.get("avg_risk_score"),
        agg.get("total_risk_score")
    ))
    conn.commit()


def build_snapshot_if_needed(conn: sqlite3.Connection):
    """
    If fewer than 2 historical snapshots exist, build a current snapshot for each host
    by aggregating available data (hars_scores preferred, then patch_state).
    """
    existing = count_snapshots(conn)
    if existing >= 2:
        return {"made_snapshot": False, "reason": "enough historical snapshots present", "created_count": 0}

    hosts = hosts_from_system_info(conn)
    if not hosts:
        # If system_info empty, attempt to infer a host_hash from hars_scores -> raw_security_findings
        cur = conn.cursor()
        try:
            cur.execute("SELECT DISTINCT f.host_hash FROM raw_security_findings f LIMIT 1")
            row = cur.fetchone()
            if row:
                hosts = [row["host_hash"]]
        except sqlite3.Error:
            pass

    if not hosts:
        return {"made_snapshot": False, "reason": "no hosts found in system_info or findings", "created_count": 0}

    created = 0
    snapshot_time = datetime.utcnow().isoformat()
    for host in hosts:
        agg = aggregate_from_hars(conn, host)
        method = "hars_scores"
        if not agg:
            agg = aggregate_from_patch_state(conn, host)
            method = "patch_state_fallback"

        insert_snapshot(conn, host, snapshot_time, agg)
        created += 1

    return {"made_snapshot": True, "reason": f"created {created} snapshot(s) using available data", "created_count": created}


def fetch_snapshots(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("""
        SELECT scan_time, host_hash, total_vulnerabilities, total_risk_score
        FROM scan_snapshots
        ORDER BY scan_time ASC
    """)
    return cur.fetchall()


def parse_scan_time(ts: str):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        # common fallback formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(ts, fmt)
            except Exception:
                continue
    return None


def plot_trend(snapshots, export_path: Path = None):
    """
    snapshots: list of rows with scan_time, host_hash, total_vulnerabilities, total_risk_score
    Group by single host if multiple exist; if multiple hosts, plot aggregated total_risk_score sum per timestamp.
    """
    if not snapshots:
        print("No snapshots to plot.")
        return

    # Group by scan_time (aggregate across hosts)
    aggregated = {}
    for r in snapshots:
        ts = parse_scan_time(r["scan_time"])
        if not ts:
            continue
        key = ts
        aggregated.setdefault(key, 0.0)
        val = r["total_risk_score"] if (r["total_risk_score"] is not None) else 0.0
        aggregated[key] += float(val)

    if len(aggregated) < 2:
        print("Not enough data points to draw a trend. Need at least 2 snapshots.")
        return

    times = sorted(aggregated.keys())
    scores = [aggregated[t] for t in times]

    plt.figure()
    plt.plot(times, scores)
    plt.xlabel("Scan Time")
    plt.ylabel("Total Risk Score (aggregated)")
    plt.title("Security Risk Trend Over Time (aggregated)")
    plt.xticks(rotation=45)
    plt.tight_layout()

    if export_path:
        plt.savefig(str(export_path))
        print(f"Saved graph to {export_path}")

    plt.show()


def main():
    parser = argparse.ArgumentParser(description="Generate security risk trend graph from runtime DB")
    parser.add_argument("--db", type=str, help="Path to runtime sqlite DB (optional)")
    parser.add_argument("--export", type=str, help="Optional PNG path to export graph")
    args = parser.parse_args()

    db_path = None
    if args.db:
        db_path = Path(args.db)
    else:
        cand = find_most_recent_runtime_db(DEFAULT_RUNTIME_SUBDIR)
        if cand:
            db_path = cand
        else:
            # fallback to working directory expected name
            alt = Path.cwd() / DEFAULT_DB_FILENAME
            if alt.exists():
                db_path = alt
            else:
                print(f"No runtime DB provided and none found in {DEFAULT_RUNTIME_SUBDIR}. Exiting.")
                sys.exit(1)

    try:
        conn = connect_db(db_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        ensure_scan_snapshots_table(conn)
    except Exception as e:
        print(f"Failed to ensure scan_snapshots table: {e}")
        conn.close()
        sys.exit(1)

    snapshot_info = build_snapshot_if_needed(conn)
    if snapshot_info["made_snapshot"]:
        print(f"Snapshot(s) created: {snapshot_info['created_count']} ({snapshot_info['reason']})")
    else:
        print(f"No new snapshot created: {snapshot_info['reason']}")

    snaps = fetch_snapshots(conn)
    if not snaps:
        print("No snapshot rows available after attempted creation. Exiting.")
        conn.close()
        sys.exit(1)

    export_path = Path(args.export) if args.export else None
    plot_trend(snaps, export_path)

    conn.close()


if __name__ == "__main__":
    main()
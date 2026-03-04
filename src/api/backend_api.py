"""
backend_api.py - Flask REST API for Vulnerability Assessment Dashboard

Serves data from canonical SQLite database to React frontend.

Endpoints:
  GET  /api/system          - Get system info for latest scan
  GET  /api/scans           - List all scans
  GET  /api/scan/<scan_id>  - Get scan details
  GET  /api/vulnerabilities - Get vulns for latest scan
  GET  /api/risk-summary    - Risk level summary
  GET  /api/installed-kbs   - Installed KBs for latest scan
  GET  /api/health          - Health check
  POST /api/scan            - Trigger new scan

USAGE:
  python backend_api.py [--db <path>] [--port 8888]

CORS enabled for localhost development.
"""

import sqlite3
import json
import logging
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import argparse
from agent.bootstrap import get_latest_runtime_db
from flask import Flask, jsonify, request, make_response

# ============================================================================
# CONFIGURATION
# ============================================================================

LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

DEFAULT_DB = str(get_latest_runtime_db())
DEFAULT_PORT = 8888

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app = Flask(__name__)

# ============================================================================
# CORS SUPPORT (Inline, no external dependency)
# ============================================================================

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to all responses for localhost development."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/api/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    """Handle CORS preflight requests."""
    return '', 204

# ============================================================================
# STATIC FILE SERVING (React Frontend)
# ============================================================================

@app.route('/', methods=['GET'])
def index():
    """Serve index.html for root path."""
    static_dir = Path(__file__).parent / 'static'
    index_file = static_dir / 'index.html'
    if index_file.exists():
        with open(index_file, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/html; charset=utf-8'}
    return jsonify({"error": "Frontend not found"}), 404

@app.route('/<path:path>', methods=['GET'])
def serve_static(path):
    """Serve static files and fallback to index.html for SPA routes."""
    static_dir = Path(__file__).parent / 'static'
    file_path = static_dir / path
    
    if file_path.exists() and file_path.is_file():
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            content_type = 'text/plain'
            if path.endswith('.html'):
                content_type = 'text/html; charset=utf-8'
            elif path.endswith('.js'):
                content_type = 'application/javascript; charset=utf-8'
            elif path.endswith('.css'):
                content_type = 'text/css; charset=utf-8'
            elif path.endswith('.json'):
                content_type = 'application/json; charset=utf-8'
            elif path.endswith('.svg'):
                content_type = 'image/svg+xml'
            elif path.endswith('.png'):
                content_type = 'image/png'
            elif path.endswith('.jpg') or path.endswith('.jpeg'):
                content_type = 'image/jpeg'
            
            return content, 200, {'Content-Type': content_type}
        except Exception as e:
            logger.error(f"Error serving file {path}: {e}")
            return jsonify({"error": "File error"}), 500
    
    index_file = static_dir / 'index.html'
    if index_file.exists():
        try:
            with open(index_file, 'r', encoding='utf-8') as f:
                return f.read(), 200, {'Content-Type': 'text/html; charset=utf-8'}
        except Exception as e:
            logger.error(f"Error serving index.html: {e}")
            return jsonify({"error": "Frontend error"}), 500
    
    return jsonify({"error": "Endpoint not found"}), 404

# Global database connection (will be set at startup)
_db_path = None

def find_database(suggested_path: str = None) -> str:
    """Find database in common locations."""
    if suggested_path:
        path = Path(suggested_path)
        if path.exists():
            return str(path.resolve())
    
    candidates = [
        Path("../runtime_scan.sqlite"),
        Path("../runtime_scan.sqlite"),
        Path("../../runtime_scan.sqlite"),
        Path("../../src/runtime_scan.sqlite"),
        Path("runtime_scan.sqlite"),
    ]
    
    for candidate in candidates:
        if candidate.exists():
            full_path = str(candidate.resolve())
            logger.info(f"Found database at: {full_path}")
            return full_path
    
    raise FileNotFoundError(f"Database not found in common locations")

def init_db(db_path: str):
    """Initialize database connection."""
    global _db_path
    try:
        _db_path = find_database(db_path)
    except FileNotFoundError as e:
        logger.error(f"Database not found: {e}")
        raise
    logger.info(f"Using database: {_db_path}")

def get_latest_runtime_db_path():
    """Get database path."""
    global _db_path
    if _db_path:
        return _db_path
    return find_database()

def get_latest_runtime_db_conn():
    """Get database connection."""
    db_path = get_latest_runtime_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# ============================================================================
# HEALTH CHECK & INIT
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM system_info LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        
        status = "healthy" if result else "no_data"
        return jsonify({"status": status}), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# ============================================================================
# SYSTEM INFO
# ============================================================================

@app.route('/api/system', methods=['GET'])
def get_system():
    """Get system info from latest scan."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT host_hash, hostname, os_caption, os_version, build_number,
                   architecture, domain, part_of_domain, scan_time, agent_version, elevated
            FROM system_info
            ORDER BY scan_time DESC
            LIMIT 1
        """)
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return jsonify({"error": "No system info found"}), 404
        
        return jsonify({
            "host_hash": row[0],
            "hostname": row[1],
            "os_caption": row[2],
            "os_version": row[3],
            "build_number": row[4],
            "architecture": row[5],
            "domain": row[6],
            "part_of_domain": row[7] == 1,
            "scan_time": row[8],
            "agent_version": row[9],
            "elevated": row[10] == 1
        }), 200
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({"error": str(e)}), 500
# ============================================================================
# SCAN
# ============================================================================
from agent.bootstrap import SmartPatchOrchestrator

# ============================================================================
# EXECUTE SCAN
# ============================================================================

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Trigger a new system scan."""
    try:
        logger.info("Starting SmartPatch scan...")

        orchestrator = SmartPatchOrchestrator()

        if not orchestrator.initialize():
            return jsonify({"error": "Failed to initialize orchestrator"}), 500

        result = orchestrator.execute_scan()

        logger.info("Scan completed successfully")

        return jsonify({
            "message": "Scan completed",
            "scan_id": result.get("scan_id"),
            "hostname": result.get("os_metadata", {}).get("os_info", {}).get("caption"),
            "findings_total": result.get("findings_total"),
            "database_path": result.get("database_path")
        }), 200

    except Exception as e:
        logger.error(f"Scan execution failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ============================================================================
# Report
# ============================================================================

@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get list of all scans."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT DISTINCT host_hash, hostname, os_caption, build_number, scan_time
            FROM system_info
            ORDER BY scan_time DESC
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        scans = [{
            "host_hash": row[0],
            "hostname": row[1],
            "os_caption": row[2],
            "build_number": row[3],
            "scan_time": row[4]
        } for row in rows]
        
        return jsonify({"scans": scans}), 200
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id: str):
    """Get details of a specific scan."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT host_hash, hostname, os_caption, os_version, build_number,
                   architecture, domain, part_of_domain, scan_time, agent_version
            FROM system_info
            WHERE host_hash = ?
            ORDER BY scan_time DESC
            LIMIT 1
        """, (scan_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Scan not found"}), 404
        
        cursor.execute("""
            SELECT COUNT(*) FROM risk_scores
            WHERE host_hash = ? AND scan_time = ?
        """, (row[0], row[8]))
        vuln_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            "host_hash": row[0],
            "hostname": row[1],
            "os_caption": row[2],
            "os_version": row[3],
            "build_number": row[4],
            "architecture": row[5],
            "domain": row[6],
            "part_of_domain": row[7] == 1,
            "scan_time": row[8],
            "agent_version": row[9],
            "vulnerability_count": vuln_count
        }), 200
    except Exception as e:
        logger.error(f"Error getting scan: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# VULNERABILITIES
# ============================================================================

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get vulnerabilities for latest scan."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        scan_id = request.args.get('scan_id')
        
        if scan_id:
            cursor.execute("""
                SELECT scan_time FROM system_info WHERE host_hash = ?
                ORDER BY scan_time DESC LIMIT 1
            """, (scan_id,))
        else:
            cursor.execute("""
                SELECT host_hash, scan_time FROM system_info
                ORDER BY scan_time DESC LIMIT 1
            """)
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return jsonify({"vulnerabilities": []}), 200
        
        if scan_id:
            host_hash = scan_id
            scan_time = result[0]
        else:
            host_hash = result[0]
            scan_time = result[1]
        
        # cursor.execute("""
        #     SELECT v.cve_id, v.title, v.description, v.cvss_score, v.severity,
        #            v.attack_vector, v.kb_id,
        #            r.hars_score, r.priority, r.attack_surface_score,
        #            r.reachability_score, r.criticality_score
        #     FROM vulnerabilities v
        #     LEFT JOIN risk_scores r ON v.cve_id = r.cve_id 
        #         AND r.host_hash = ? AND r.scan_time = ?
        #     ORDER BY COALESCE(r.hars_score, 0) DESC
        # """, (host_hash, scan_time))

        cursor.execute("""
            SELECT dv.cve_id,
                dv.reasoning, hs.a_score, hs.r_score, hs.c_score, hs.final_score, hs.priority
            FROM derived_vulnerabilities dv
            LEFT JOIN hars_scores hs 
                       ON dv.derived_from_finding_id = hs.finding_id 
            ORDER BY COALESCE(hs.final_score, 0) DESC
    """)

        
        rows = cursor.fetchall()
        conn.close()
        
        vulns = [{
            "cve_id": row[0],
            "reasoning": row[1],
            "attack_surface_score": row[2],
            "reachability_score": row[3],
            "criticality_score": row[4],
            "final_score": row[5],
            "priority": row[6]
        } for row in rows]

        return jsonify({"vulnerabilities": vulns}), 200
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# RISK SUMMARY
# ============================================================================

@app.route('/api/risk-summary', methods=['GET'])
def get_risk_summary():
    """Get risk level summary for latest scan."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT host_hash, scan_time FROM system_info
            ORDER BY scan_time DESC LIMIT 1
        """)
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return jsonify({"summary": {}}), 200
        
        host_hash, scan_time = result[0], result[1]
        
        cursor.execute("""
            SELECT priority, COUNT(*) as count
            FROM hars_scores
            GROUP BY priority
        """,)
        
        rows = cursor.fetchall()
        
        cursor.execute("""
            SELECT AVG(final_score), MAX(final_score), MIN(final_score)
            FROM hars_scores
        """)
        
        avg_result = cursor.fetchone()
        conn.close()
        
        summary = {
            "scan_time": scan_time,
            "host_hash": host_hash,
            "risk_distribution": {},
            "average_hars": round(avg_result[0], 4) if avg_result[0] else 0,
            "max_hars": round(avg_result[1], 4) if avg_result[1] else 0,
            "min_hars": round(avg_result[2], 4) if avg_result[2] else 0
        }
        
        for row in rows:
            summary["risk_distribution"][row[0]] = row[1]
        
        return jsonify({"summary": summary}), 200
    except Exception as e:
        logger.error(f"Error getting risk summary: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# INSTALLED KBS
# ============================================================================

@app.route('/api/installed-kbs', methods=['GET'])
def get_installed_kbs():
    """Get installed KBs for latest scan."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT host_hash, scan_time FROM system_info
            ORDER BY scan_time DESC LIMIT 1
        """)
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return jsonify({"kbs": []}), 200
        
        host_hash, scan_time = result[0], result[1]
        
        cursor.execute("""
            SELECT kb_id, install_date, source
            FROM installed_kbs
            WHERE host_hash = ? AND scan_time = ?
            ORDER BY kb_id
        """, (host_hash, scan_time))
        
        rows = cursor.fetchall()
        conn.close()
        
        kbs = [{
            "kb_id": row[0],
            "install_date": row[1],
            "source": row[2]
        } for row in rows]
        
        return jsonify({"kbs": kbs}), 200
    except Exception as e:
        logger.error(f"Error getting installed KBs: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# RECOMMENDATIONS (NEW ENDPOINT - Links HARS scores to mitigations)
# ============================================================================

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    """Get AI/HARS-recommended mitigations for vulnerabilities."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        # Get latest scan data
        cursor.execute("""
            SELECT host_hash, scan_time FROM system_info
            ORDER BY scan_time DESC LIMIT 1
        """)
        result = cursor.fetchone()
        if not result:
            conn.close()
            return jsonify({"recommendations": []}), 200
        
        host_hash, scan_time = result[0], result[1]
        
        # Get vulns with HARS scores for this host/scan
        cursor.execute("""
            SELECT v.cve_id, v.title, v.description, v.cvss_score, v.severity,
                   r.final_score, r.priority, r.confidence,
                   r.r_score, r.a_score, r.c_score,
                   r.attack_surface_score, r.reachability_score, r.criticality_score,
                   v.kb_id
            FROM derived_vulnerabilities v
            LEFT JOIN hars_scores r ON v.cve_id = r.cve_id AND r.host_hash = ? AND r.scan_time = ?
            ORDER BY COALESCE(r.hars_score, 0) DESC
        """, (host_hash, scan_time))
        
        rows = cursor.fetchall()
        
        recommendations = []
        for row in rows:
            cve_id = row[0]
            
            # Try to get mitigation techniques from mitigations DB
            mitigations = []
            try:
                miti_conn = sqlite3.connect(Path(__file__).parent.parent.parent / 'src/database/mitigations_catalogue.sqlite')
                miti_cursor = miti_conn.cursor()
                
                miti_cursor.execute("""
                    SELECT technique_id, title, description, implementation, effectiveness, confidence
                    FROM mitigation_techniques
                    WHERE cve_id = ?
                    LIMIT 5
                """, (cve_id,))
                
                miti_rows = miti_cursor.fetchall()
                mitigations = [{
                    "technique_id": m[0],
                    "title": m[1],
                    "description": m[2],
                    "implementation": m[3],
                    "effectiveness": m[4],
                    "confidence": m[5] or 0.8
                } for m in miti_rows]
                
                miti_conn.close()
            except Exception as e:
                logger.debug(f"Could not fetch mitigations for {cve_id}: {e}")
            
            recommendations.append({
                "cve_id": cve_id,
                "title": row[1],
                "description": row[2],
                "cvss_score": row[3],
                "severity": row[4],
                "hars_score": row[5] or 0.0,
                "final_score": row[6] or 0.0,
                "priority": row[7] or "UNKNOWN",
                "ai_confidence": row[8] or 0.8,
                "r_score": row[9] or 0.0,
                "a_score": row[10] or 0.0,
                "c_score": row[11] or 0.0,
                "attack_surface_score": row[12] or 0.0,
                "reachability_score": row[13] or 0.0,
                "criticality_score": row[14] or 0.0,
                "kb_id": row[15],
                "mitigations": mitigations
            })
        
        conn.close()
        return jsonify({"recommendations": recommendations}), 200
    except Exception as e:
        logger.error(f"Error getting recommendations: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# AUDIT LOG
# ============================================================================

@app.route('/api/audit-logs', methods=['GET'])
def get_audit_logs():
    """Get audit history of scans and HARS decisions."""
    try:
        conn = get_latest_runtime_db_conn()
        cursor = conn.cursor()
        
        # Get all scans ordered by date
        cursor.execute("""
            SELECT DISTINCT host_hash, hostname, os_caption, build_number, scan_time, agent_version
            FROM system_info
            ORDER BY scan_time DESC
        """)
        
        scans = cursor.fetchall()
        
        audit_logs = []
        for scan in scans:
            host_hash, hostname, os_caption, build_number, scan_time, agent_ver = scan
            
            # Count vulns and HARS scores for this scan
            cursor.execute("""
                SELECT COUNT(*) FROM hars_scores
                WHERE host_hash = ? AND scan_time = ?
            """, (host_hash, scan_time))
            vuln_count = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM risk_scores
                WHERE host_hash = ? AND scan_time = ? AND priority = 'URGENT'
            """, (host_hash, scan_time))
            urgent_count = cursor.fetchone()[0]
            
            audit_logs.append({
                "scan_id": host_hash,
                "hostname": hostname,
                "os": os_caption,
                "build": build_number,
                "scan_time": scan_time,
                "agent_version": agent_ver,
                "vulnerabilities_found": vuln_count,
                "urgent_count": urgent_count,
                "decision_type": "SYSTEM_SCAN"
            })
        
        conn.close()
        return jsonify({"audit_logs": audit_logs}), 200
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# MITIGATION DETAILS
# ============================================================================

@app.route('/api/mitigation/<cve_id>', methods=['GET'])
def get_mitigation_details(cve_id: str):
    """Get detailed mitigation options for a CVE."""
    try:
        mitigation_data = {
            "cve_id": cve_id,
            "registry_mitigations": [],
            "system_mitigations": [],
            "network_mitigations": []
        }
        
        miti_path = Path(__file__).parent.parent.parent / 'src/database/mitigations_catalogue.sqlite'
        if not miti_path.exists():
            return jsonify(mitigation_data), 200
        
        miti_conn = sqlite3.connect(str(miti_path))
        miti_conn.row_factory = sqlite3.Row
        miti_cursor = miti_conn.cursor()
        
        # Registry mitigations
        miti_cursor.execute("""
            SELECT description, registry_path, value_name, recommended_value, risk_level
            FROM registry_mitigations
            WHERE cve_id = ?
        """, (cve_id,))
        
        for row in miti_cursor.fetchall():
            mitigation_data["registry_mitigations"].append({
                "description": row['description'],
                "registry_path": row['registry_path'],
                "value_name": row['value_name'],
                "recommended_value": row['recommended_value'],
                "risk_level": row['risk_level']
            })
        
        # System mitigations (e.g., service/feature disabling)
        miti_cursor.execute("""
            SELECT mitigation_type, feature_name, service_name, action, powershell_command
            FROM system_mitigations
            WHERE cve_id = ?
        """, (cve_id,))
        
        for row in miti_cursor.fetchall():
            mitigation_data["system_mitigations"].append({
                "mitigation_type": row['mitigation_type'],
                "feature_name": row['feature_name'],
                "service_name": row['service_name'],
                "action": row['action'],
                "powershell_command": row['powershell_command']
            })
        
        # Network mitigations (firewall rules, etc)
        miti_cursor.execute("""
            SELECT rule_name, protocol, port_range, action, netsh_command
            FROM network_mitigations
            WHERE cve_id = ?
        """, (cve_id,))
        
        for row in miti_cursor.fetchall():
            mitigation_data["network_mitigations"].append({
                "rule_name": row['rule_name'],
                "protocol": row['protocol'],
                "port_range": row['port_range'],
                "action": row['action'],
                "netsh_command": row['netsh_command']
            })
        
        miti_conn.close()
        
        return jsonify(mitigation_data), 200
    except Exception as e:
        logger.error(f"Error getting mitigation details for {cve_id}: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================================
# SCAN TRIGGER
# ============================================================================

# @app.route('/api/scan', methods=['POST'])
# def trigger_scan():
#     """Trigger a new scan by running pipeline.py."""
#     try:
#         logger.info("Scan trigger requested")
        
#         pipeline_path = Path(__file__).parent.parent / 'pipeline.py'
#         if not pipeline_path.exists():
#             pipeline_path = Path(__file__).parent.parent.parent / 'pipeline.py'
        
#         if not pipeline_path.exists():
#             return jsonify({
#                 "success": False,
#                 "message": "Pipeline script not found",
#                 "error": f"Expected at: {pipeline_path}"
#             }), 404
        
#         logger.info(f"Starting scan: {pipeline_path}")
#         result = subprocess.run(
#             [sys.executable, str(pipeline_path)],
#             capture_output=True,
#             text=True,
#             timeout=300
#         )
        
#         if result.returncode == 0:
#             logger.info("Scan completed successfully")
            
#             # Extract scan result from pipeline output (JSON in stdout)
#             scan_data = None
#             try:
#                 lines = result.stdout.split('\n')
#                 for line in lines:
#                     if line.strip().startswith('{'):
#                         scan_data = json.loads(line)
#                         break
#             except:
#                 pass
            
#             # Sync latest runtime database to shared workspace database
#             try:
#                 import shutil
#                 runtime_dir = Path("C:\\ProgramData\\SmartPatch\\runtime")
#                 if runtime_dir.exists():
#                     runtime_dbs = sorted(
#                         runtime_dir.glob("runtime_*.sqlite"),
#                         key=lambda p: p.stat().st_mtime,
#                         reverse=True
#                     )
                    
#                     if runtime_dbs:
#                         latest_db = runtime_dbs[0]
#                         logger.info(f"Syncing data from {latest_db} to shared database")
                        
#                         try:
#                             # Open latest runtime database and query system_info
#                             runtime_conn = sqlite3.connect(str(latest_db))
#                             runtime_cursor = runtime_conn.cursor()
                            
#                             # Get latest system_info
#                             runtime_cursor.execute("SELECT * FROM system_info ORDER BY scan_time DESC LIMIT 1")
#                             system_info_row = runtime_cursor.fetchone()
                            
#                             if system_info_row:
#                                 # Get column names from schema
#                                 runtime_cursor.execute("PRAGMA table_info(system_info)")
#                                 columns = [col[1] for col in runtime_cursor.fetchall()]
                                
#                                 logger.info(f"Found system_info record with hostname: {system_info_row[2] if len(system_info_row) > 2 else 'UNKNOWN'}")
                                
#                                 # Open shared workspace database
#                                 shared_conn = get_latest_runtime_db_conn()
#                                 shared_cursor = shared_conn.cursor()
                                
#                                 # Clear old data
#                                 try:
#                                     shared_cursor.execute("DELETE FROM system_info")
#                                     logger.info("Cleared old system_info records")
#                                 except:
#                                     logger.debug("Could not clear old records (table may be empty)")
                                
#                                 # Insert fresh system info
#                                 placeholders = ','.join(['?' for _ in columns])
#                                 col_names = ','.join(columns)
#                                 shared_cursor.execute(
#                                     f"INSERT INTO system_info ({col_names}) VALUES ({placeholders})",
#                                     system_info_row
#                                 )
#                                 shared_conn.commit()
#                                 logger.info(f"Successfully synced system info to shared database: {system_info_row[2] if len(system_info_row) > 2 else 'UNKNOWN'}")
#                             else:
#                                 logger.warning("No system_info found in runtime database")
                            
#                             runtime_conn.close()
#                         except Exception as sync_err:
#                             logger.error(f"Sync error: {sync_err}", exc_info=True)
#                 else:
#                     logger.info(f"Runtime directory not found: {runtime_dir}")
#             except Exception as e:
#                 logger.warning(f"Failed to sync runtime database: {e}", exc_info=True)
            
#             return jsonify({
#                 "success": True,
#                 "message": "Scan completed successfully",
#                 "scan_output": result.stdout[-500:] if result.stdout else "",
#                 "scan_data": scan_data
#             }), 200
#         else:
#             logger.error(f"Scan failed with return code {result.returncode}")
#             return jsonify({
#                 "success": False,
#                 "message": "Scan failed",
#                 "error": result.stderr[-500:] if result.stderr else "Unknown error"
#             }), 500
            
#     except subprocess.TimeoutExpired:
#         logger.error("Scan timeout after 5 minutes")
#         return jsonify({
#             "success": False,
#             "message": "Scan timeout",
#             "error": "Scan took too long (>5 minutes)"
#         }), 504
#     except Exception as e:
#         logger.error(f"Error triggering scan: {e}")
#         return jsonify({
#             "success": False,
#             "message": "Error triggering scan",
#             "error": str(e)
#         }), 500

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Backend API for vulnerability dashboard")
    parser.add_argument('--db', default=DEFAULT_DB, help=f"Database path (default: {DEFAULT_DB})")
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        init_db(args.db)
    except FileNotFoundError as e:
        logger.error(f"Failed to initialize database: {e}")
        print(f"\nERROR: {e}")
        print("\nPlease run the pipeline first:")
        print("  python pipeline.py")
        sys.exit(1)
    
    print("\n" + "="*70)
    print("VULNERABILITY DASHBOARD API")
    print("="*70)
    print(f"\nDatabase:   {_db_path}")
    print(f"Listening:  http://localhost:{args.port}")
    print(f"\nAPI Endpoints:")
    print(f"  GET  http://localhost:{args.port}/api/system                    - System metadata")
    print(f"  GET  http://localhost:{args.port}/api/scans                     - Scan history")
    print(f"  GET  http://localhost:{args.port}/api/vulnerabilities          - CVEs with HARS scores")
    print(f"  GET  http://localhost:{args.port}/api/risk-summary             - Risk statistics")
    print(f"  GET  http://localhost:{args.port}/api/installed-kbs            - Installed patches")
    print(f"  GET  http://localhost:{args.port}/api/recommendations          - AI recommendations")
    print(f"  GET  http://localhost:{args.port}/api/audit-logs               - Audit trail")
    print(f"  GET  http://localhost:{args.port}/api/mitigation/<cve_id>      - Mitigation details")
    print(f"  GET  http://localhost:{args.port}/api/health                   - Health check")
    print(f"  POST http://localhost:{args.port}/api/scan                     - Trigger scan")
    print("="*70 + "\n")
    
    app.run(host='127.0.0.1', port=args.port, debug=False)

if __name__ == "__main__":
    main()

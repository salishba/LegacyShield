"""
hars.py - HARS (Hybrid Automated Risk Scoring) Orchestrator
Reads vulnerability data from databases, calculates HARS scores, and stores results.
"""

import sqlite3
import logging
from datetime import datetime, date
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import json

# Import pure scoring functions
from scoring import (
    calculate_hars_scores,
    validate_scoring_inputs,
    clamp,
    normalize_cvss
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database paths (configurable)
RUNTIME_DB = "runtime_scan.sqlite"
CATALOGUE_DB = "smartpatch_cataloguecv.sqlite"
PRIORITIZATION_DB = "prioritization.db"

# Model configuration
MODEL_VERSION = "HARS-v1-deterministic"
MODEL_CONFIG = {
    'high_threshold': 0.70,
    'medium_threshold': 0.35,
    'r_weights': {'epss': 0.40, 'exploited': 0.20, 'poc': 0.15, 'ransomware': 0.15, 'cvss': 0.10},
    'default_system_role': 'workstation',
    'default_patch_confidence': 0.8,
    'default_data_freshness': 0.9,
    'default_verification_status': 'unverified'
}

# ========================================================================
# FIX 2: SYSTEM ROLE AUTO-DETECTION
# ========================================================================
def detect_system_role(system_info: Dict[str, Any], installed_services: Optional[List[str]] = None) -> str:
    """
    Auto-detect system role based on OS metadata and installed services.
    
    Priority:
    1. WMI ProductType (if available)
    2. Installed services heuristic
    3. Default to workstation
    
    Args:
        system_info: Dictionary with os_info fields (ProductType, etc.)
        installed_services: List of installed service names
    
    Returns:
        One of: 'domain_controller', 'server', 'database_server', 'web_server', 
                'file_server', 'workstation', 'laptop'
    """
    try:
        # Method 1: Check WMI ProductType if available
        # ProductType: 1=workstation, 2=server, 3=domain_controller
        product_type = system_info.get("ProductType")
        if product_type is not None:
            try:
                pt = int(product_type)
                if pt == 3:
                    return "domain_controller"
                elif pt == 2:
                    # It's a server; check services for specialization
                    pass  # Fall through to service heuristic
                elif pt == 1:
                    return "workstation"
            except (ValueError, TypeError):
                pass
        
        # Method 2: Check installed services for specialization
        if installed_services:
            services_upper = [s.upper() for s in installed_services]
            
            # Check for domain controller indicators
            if any(svc in services_upper for svc in ["ADDS", "NTDS", "DFSR", "DFS"]):
                return "domain_controller"
            
            # Check for database server
            if any(svc in services_upper for svc in ["MSSQLSERVER", "MSSQL$", "MYSQL", "POSTGRESQL"]):
                return "database_server"
            
            # Check for web server
            if any(svc in services_upper for svc in ["W3SVC", "IIS", "HTTPD", "APACHE"]):
                return "web_server"
            
            # Check for file server
            if any(svc in services_upper for svc in ["LANMANSERVER", "CIFS"]):
                return "file_server"
            
            # If ProductType was 2 (server) but no specialty, generic server
            if product_type == 2:
                return "server"
        
        # Default fallback
        return MODEL_CONFIG['default_system_role']
    
    except Exception as e:
        logger.warning(f"Error in system role detection: {e}; defaulting to workstation")
        return MODEL_CONFIG['default_system_role']



class HARSEngine:
    """
    HARS Engine orchestrates risk scoring across the vulnerability pipeline.
    Reads from runtime and catalogue databases, calculates scores, writes to prioritization DB.
    """
    
    def __init__(
        self,
        runtime_db_path: str = RUNTIME_DB,
        catalogue_db_path: str = CATALOGUE_DB,
        prioritization_db_path: str = PRIORITIZATION_DB
    ):
        """
        Initialize HARS Engine with database paths.
        
        Args:
            runtime_db_path: Path to runtime_scan.sqlite
            catalogue_db_path: Path to smartpatch_catalogue.sqlite
            prioritization_db_path: Path to prioritization.db
        """
        self.runtime_db_path = Path(runtime_db_path)
        self.catalogue_db_path = Path(catalogue_db_path)
        self.prioritization_db_path = Path(prioritization_db_path)
        
        # Validate database existence
        if not self.runtime_db_path.exists():
            raise FileNotFoundError(f"Runtime database not found: {self.runtime_db_path}")
        if not self.catalogue_db_path.exists():
            raise FileNotFoundError(f"Catalogue database not found: {self.catalogue_db_path}")
        
        # Initialize prioritization database
        self._init_prioritization_db()
        
        logger.info(f"HARS Engine initialized with model: {MODEL_VERSION}")
        logger.info(f"Runtime DB: {self.runtime_db_path}")
        logger.info(f"Catalogue DB: {self.catalogue_db_path}")
        logger.info(f"Prioritization DB: {self.prioritization_db_path}")
    
    def _init_prioritization_db(self) -> None:
        """Initialize prioritization database schema"""
        with sqlite3.connect(self.prioritization_db_path) as conn:
            cursor = conn.cursor()
            
            # Create risk_scores table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_scores (
                score_id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL CHECK(entity_type IN ('CVE', 'FINDING')),
                entity_id TEXT NOT NULL,
                cve_id TEXT,
                finding_id INTEGER,
                host_hash TEXT NOT NULL,
                
                -- Component scores
                r_score REAL NOT NULL CHECK(r_score >= 0.0 AND r_score <= 1.0),
                a_score REAL NOT NULL CHECK(a_score >= 0.0 AND a_score <= 1.0),
                c_score REAL NOT NULL CHECK(c_score >= 0.0 AND c_score <= 1.0),
                final_score REAL NOT NULL CHECK(final_score >= 0.0 AND final_score <= 1.0),
                
                -- Priority classification
                priority TEXT NOT NULL CHECK(priority IN ('LOW', 'MEDIUM', 'HIGH')),
                
                -- Scoring metadata
                model_version TEXT NOT NULL,
                scoring_timestamp TEXT NOT NULL,
                calculation_duration_ms INTEGER,
                
                -- Input features (for traceability)
                cvss_score REAL,
                epss_probability REAL,
                exploited_flag INTEGER,
                poc_flag INTEGER,
                ransomware_flag INTEGER,
                patch_status TEXT,
                patch_missing_flag INTEGER,
                detection_confidence REAL,
                system_role TEXT,
                
                -- Additional context
                scoring_context TEXT,
                
                -- Indexes for performance
                UNIQUE(entity_type, entity_id, host_hash, model_version),
                FOREIGN KEY (host_hash) REFERENCES system_info(host_hash) ON DELETE CASCADE
            )
            """)
            
            # Create indexes for common queries
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk_scores_priority 
            ON risk_scores(priority, final_score DESC)
            """)
            
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk_scores_host 
            ON risk_scores(host_hash, entity_type)
            """)
            
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk_scores_cve 
            ON risk_scores(cve_id, final_score DESC)
            """)
            
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk_scores_timestamp 
            ON risk_scores(scoring_timestamp DESC)
            """)
            
            # Create system_info table for reference
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_info (
                host_hash TEXT PRIMARY KEY,
                hostname TEXT,
                os_version TEXT,
                build_number TEXT,
                architecture TEXT,
                system_role TEXT DEFAULT 'workstation',
                last_seen_timestamp TEXT,
                inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            
            # Create scoring_history table for audit trail
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scoring_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT NOT NULL,
                total_entities_scored INTEGER,
                high_priority_count INTEGER,
                medium_priority_count INTEGER,
                low_priority_count INTEGER,
                scoring_start_timestamp TEXT,
                scoring_end_timestamp TEXT,
                duration_seconds REAL,
                model_version TEXT,
                parameters_used TEXT,
                inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            
            conn.commit()
        
        logger.info(f"Prioritization database initialized: {self.prioritization_db_path}")
    
    def _get_system_context(self, host_hash: str) -> Dict[str, Any]:
        """Get system context from runtime database"""
        try:
            with sqlite3.connect(self.runtime_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get system info
                cursor.execute("""
                    SELECT hostname, os_version, build_number, architecture, 
                           part_of_domain, domain_role
                    FROM system_info 
                    WHERE host_hash = ?
                """, (host_hash,))
                
                system_row = cursor.fetchone()
                if not system_row:
                    logger.warning(f"No system info found for host_hash: {host_hash}")
                    return {'system_role': MODEL_CONFIG['default_system_role']}
                
                system_info = dict(system_row)
                
                # Determine system role
                system_role = self._determine_system_role(system_info)
                
                return {
                    'hostname': system_info.get('hostname'),
                    'os_version': system_info.get('os_version'),
                    'build_number': system_info.get('build_number'),
                    'architecture': system_info.get('architecture'),
                    'system_role': system_role,
                    'is_domain_member': bool(system_info.get('part_of_domain')),
                    'domain_role': system_info.get('domain_role')
                }
                
        except Exception as e:
            logger.error(f"Error getting system context for {host_hash}: {e}")
            return {'system_role': MODEL_CONFIG['default_system_role']}
    
    def _determine_system_role(self, system_info: Dict[str, Any]) -> str:
        """
        Determine system role from system information.
        
        Enhanced to use ProductType and installed services for accurate detection.
        Falls back to hostname patterns for compatibility with legacy data.
        """
        # FIX 2: Use improved detection function
        # Try to get installed_services from system_info if available
        installed_services = system_info.get('installed_services')
        if isinstance(installed_services, str):
            try:
                installed_services = json.loads(installed_services)
            except:
                installed_services = None
        
        # Call the module-level detection function
        role = detect_system_role(system_info, installed_services)
        
        # If we got anything but the default, return it
        if role != MODEL_CONFIG['default_system_role']:
            return role
        
        # Fallback: use legacy hostname pattern detection for old systems
        hostname = str(system_info.get('hostname', '')).upper()
        if hostname:
            server_patterns = ['SRV', 'SERVER', 'SQL', 'EXCH', 'WEB', 'APP', 'FS']
            for pattern in server_patterns:
                if pattern in hostname:
                    if 'DC' in hostname:
                        return 'domain_controller'
                    return 'server'
        
        # Fallback: check legacy domain_role field
        domain_role = system_info.get('domain_role')
        if domain_role:
            try:
                dr = int(domain_role)
                if dr in [3, 4]:  # Primary or Backup Domain Controller
                    return 'domain_controller'
                elif dr in [2, 5]:  # Member server
                    return 'server'
            except (ValueError, TypeError):
                pass
        
        # Default to workstation
        return 'workstation'
    
    def _get_vulnerability_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get vulnerability data from catalogue database"""
        try:
            with sqlite3.connect(self.catalogue_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get vulnerability details
                cursor.execute("""
                    SELECT cvss, epss, exploited, poc, ransomware,
                           published_date, last_modified_date
                    FROM vulnerabilities 
                    WHERE cve_id = ?
                """, (cve_id,))
                
                vuln_row = cursor.fetchone()
                if not vuln_row:
                    logger.warning(f"CVE {cve_id} not found in catalogue")
                    return None
                
                vuln_data = dict(vuln_row)
                
                # Calculate days since publication
                days_since_publication = None
                if vuln_data.get('published_date'):
                    try:
                        pub_date = date.fromisoformat(vuln_data['published_date'])
                        days_since_publication = (date.today() - pub_date).days
                    except (ValueError, TypeError):
                        pass
                
                return {
                    'cvss': float(vuln_data.get('cvss', 0.0)),
                    'epss': float(vuln_data.get('epss', 0.0)),
                    'exploited': bool(vuln_data.get('exploited', 0)),
                    'poc_available': bool(vuln_data.get('poc', 0)),
                    'ransomware_used': bool(vuln_data.get('ransomware', 0)),
                    'days_since_publication': days_since_publication,
                    'published_date': vuln_data.get('published_date'),
                    'last_modified_date': vuln_data.get('last_modified_date')
                }
                
        except Exception as e:
            logger.error(f"Error getting vulnerability data for {cve_id}: {e}")
            return None
    
    def _get_missing_cves(self, host_hash: str) -> List[Dict[str, Any]]:
        """Get CVEs with missing patches for a specific host"""
        try:
            with sqlite3.connect(self.runtime_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get missing patches with confidence
                cursor.execute("""
                    SELECT mp.cve_id, mp.kb_id, mp.status, mp.confidence,
                           f.finding_id, f.detected_at
                    FROM missing_patches mp
                    LEFT JOIN raw_security_findings f ON mp.cve_id = f.finding_type
                    WHERE mp.status = 'MISSING' 
                    AND f.host_hash = ?
                    GROUP BY mp.cve_id
                """, (host_hash,))
                
                missing_cves = []
                for row in cursor.fetchall():
                    missing_cves.append({
                        'cve_id': row['cve_id'],
                        'kb_id': row['kb_id'],
                        'status': row['status'],
                        'detection_confidence': self._map_confidence_to_numeric(row['confidence']),
                        'finding_id': row['finding_id'],
                        'detected_at': row['detected_at']
                    })
                
                return missing_cves
                
        except Exception as e:
            logger.error(f"Error getting missing CVEs for {host_hash}: {e}")
            return []
    
    def _map_confidence_to_numeric(self, confidence_str: str) -> float:
        """Map textual confidence to numeric value"""
        confidence_map = {
            'HIGH': 0.9,
            'VERIFIED': 0.95,
            'CONFIRMED': 0.9,
            'MEDIUM': 0.7,
            'MED': 0.7,
            'LOW': 0.4,
            'TENTATIVE': 0.3,
            'UNKNOWN': 0.5,
            'POSSIBLE': 0.6,
            'PROBABLE': 0.8
        }
        return confidence_map.get(str(confidence_str).upper(), 0.5)
    
    def _check_mitigation_availability(self, cve_id: str) -> bool:
        """Check if mitigation is available for CVE"""
        try:
            with sqlite3.connect(self.catalogue_db_path) as conn:
                cursor = conn.cursor()
                
                # Check any mitigation tables
                tables_to_check = [
                    'registry_mitigations',
                    'system_mitigations', 
                    'network_mitigations',
                    'mitigation_techniques'
                ]
                
                for table in tables_to_check:
                    cursor.execute(f"""
                        SELECT COUNT(*) FROM {table} 
                        WHERE cve_id = ?
                    """, (cve_id,))
                    
                    if cursor.fetchone()[0] > 0:
                        return True
                
                return False
                
        except Exception as e:
            logger.debug(f"Error checking mitigation for {cve_id}: {e}")
            return False
    
    def calculate_cve_score(
        self,
        cve_id: str,
        host_hash: str,
        patch_status: str = "MISSING",
        detection_confidence: float = 0.8,
        adjustment_factors: Optional[Dict[str, float]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Calculate HARS score for a single CVE on a specific host.
        
        Args:
            cve_id: CVE identifier
            host_hash: Host identifier hash
            patch_status: Patch status
            detection_confidence: Detection confidence (0.0-1.0)
            adjustment_factors: Optional scoring adjustments
        
        Returns:
            Dictionary with scores and metadata, or None if calculation fails
        """
        start_time = datetime.now()
        
        try:
            # 1. Get vulnerability data from catalogue
            vuln_data = self._get_vulnerability_data(cve_id)
            if not vuln_data:
                logger.warning(f"Skipping CVE {cve_id} - no vulnerability data")
                return None
            
            # 2. Get system context
            system_context = self._get_system_context(host_hash)
            
            # 3. Check mitigation availability
            mitigation_available = self._check_mitigation_availability(cve_id)
            
            # 4. Validate inputs
            is_valid, error_msg = validate_scoring_inputs(
                cvss=vuln_data['cvss'],
                epss=vuln_data['epss'],
                detection_confidence=detection_confidence
            )
            
            if not is_valid:
                logger.error(f"Invalid inputs for CVE {cve_id}: {error_msg}")
                return None
            
            # 5. Calculate HARS scores
            scores = calculate_hars_scores(
                cvss=vuln_data['cvss'],
                epss=vuln_data['epss'],
                exploited=vuln_data['exploited'],
                poc_available=vuln_data['poc_available'],
                ransomware_used=vuln_data['ransomware_used'],
                patch_status=patch_status,
                patch_missing=(patch_status == "MISSING"),
                detection_confidence=detection_confidence,
                days_since_publication=vuln_data.get('days_since_publication'),
                mitigation_available=mitigation_available,
                system_role=system_context.get('system_role', MODEL_CONFIG['default_system_role']),
                patch_confidence=MODEL_CONFIG['default_patch_confidence'],
                data_freshness=MODEL_CONFIG['default_data_freshness'],
                verification_status=MODEL_CONFIG['default_verification_status'],
                adjustment_factors=adjustment_factors
            )
            
            # 6. Add metadata
            calculation_duration = (datetime.now() - start_time).total_seconds() * 1000
            
            result = {
                'entity_type': 'CVE',
                'entity_id': cve_id,
                'cve_id': cve_id,
                'host_hash': host_hash,
                'r_score': scores['r_score'],
                'a_score': scores['a_score'],
                'c_score': scores['c_score'],
                'final_score': scores['final_score'],
                'priority': scores['priority'],
                'model_version': MODEL_VERSION,
                'scoring_timestamp': datetime.utcnow().isoformat(),
                'calculation_duration_ms': round(calculation_duration, 2),
                'cvss_score': vuln_data['cvss'],
                'epss_probability': vuln_data['epss'],
                'exploited_flag': int(vuln_data['exploited']),
                'poc_flag': int(vuln_data['poc_available']),
                'ransomware_flag': int(vuln_data['ransomware_used']),
                'patch_status': patch_status,
                'patch_missing_flag': int(patch_status == "MISSING"),
                'detection_confidence': detection_confidence,
                'system_role': system_context.get('system_role', MODEL_CONFIG['default_system_role']),
                'scoring_context': json.dumps({
                    'vulnerability_data': {k: v for k, v in vuln_data.items() if k != 'days_since_publication'},
                    'system_context': system_context,
                    'mitigation_available': mitigation_available,
                    'adjustment_factors': adjustment_factors
                }, default=str)
            }
            
            logger.debug(f"Calculated scores for CVE {cve_id}: {scores['priority']} ({scores['final_score']:.3f})")
            return result
            
        except Exception as e:
            logger.error(f"Error calculating score for CVE {cve_id}: {e}")
            return None
    
    def calculate_finding_score(
        self,
        finding_id: int,
        host_hash: str,
        adjustment_factors: Optional[Dict[str, float]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Calculate HARS score for a security finding.
        
        Args:
            finding_id: Finding identifier from raw_security_findings
            host_hash: Host identifier hash
            adjustment_factors: Optional scoring adjustments
        
        Returns:
            Dictionary with scores and metadata, or None if calculation fails
        """
        try:
            with sqlite3.connect(self.runtime_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get finding details
                cursor.execute("""
                    SELECT f.finding_id, f.finding_type, f.status, f.risk, f.description,
                           f.evidence, f.detected_at, mp.cve_id, mp.status as patch_status,
                           mp.confidence
                    FROM raw_security_findings f
                    LEFT JOIN missing_patches mp ON f.finding_type = mp.cve_id
                    WHERE f.finding_id = ? AND f.host_hash = ?
                """, (finding_id, host_hash))
                
                finding_row = cursor.fetchone()
                if not finding_row:
                    logger.warning(f"Finding {finding_id} not found for host {host_hash}")
                    return None
                
                finding = dict(finding_row)
                
                # If finding is linked to a CVE, use CVE scoring
                if finding.get('cve_id'):
                    return self.calculate_cve_score(
                        cve_id=finding['cve_id'],
                        host_hash=host_hash,
                        patch_status=finding.get('patch_status', 'UNKNOWN'),
                        detection_confidence=self._map_confidence_to_numeric(finding.get('confidence', 'MEDIUM')),
                        adjustment_factors=adjustment_factors
                    )
                
                # For non-CVE findings, use heuristic scoring
                return self._calculate_heuristic_score(finding, host_hash, adjustment_factors)
                
        except Exception as e:
            logger.error(f"Error calculating score for finding {finding_id}: {e}")
            return None
    
    def _calculate_heuristic_score(
        self,
        finding: Dict[str, Any],
        host_hash: str,
        adjustment_factors: Optional[Dict[str, float]] = None
    ) -> Optional[Dict[str, Any]]:
        """Calculate heuristic score for non-CVE findings"""
        try:
            # Map finding risk to CVSS-like score
            risk_to_cvss = {
                'CRITICAL': 9.0,
                'HIGH': 7.0,
                'MEDIUM': 5.0,
                'LOW': 3.0,
                'INFO': 1.0
            }
            
            cvss_estimate = risk_to_cvss.get(finding.get('risk', 'MEDIUM'), 5.0)
            
            # Get system context
            system_context = self._get_system_context(host_hash)
            
            # Estimate EPSS based on finding type and risk
            epss_estimate = 0.3  # Default for configuration findings
            
            # Calculate scores using estimated values
            scores = calculate_hars_scores(
                cvss=cvss_estimate,
                epss=epss_estimate,
                exploited=False,  # Non-CVE findings rarely have exploitation data
                poc_available=False,
                ransomware_used=False,
                patch_status='UNKNOWN',
                patch_missing=True,  # Assume missing until verified
                detection_confidence=self._map_confidence_to_numeric(finding.get('confidence', 'MEDIUM')),
                system_role=system_context.get('system_role', MODEL_CONFIG['default_system_role']),
                adjustment_factors=adjustment_factors
            )
            
            result = {
                'entity_type': 'FINDING',
                'entity_id': f"FINDING-{finding['finding_id']}",
                'finding_id': finding['finding_id'],
                'host_hash': host_hash,
                'r_score': scores['r_score'],
                'a_score': scores['a_score'],
                'c_score': scores['c_score'],
                'final_score': scores['final_score'],
                'priority': scores['priority'],
                'model_version': MODEL_VERSION,
                'scoring_timestamp': datetime.utcnow().isoformat(),
                'cvss_score': cvss_estimate,
                'epss_probability': epss_estimate,
                'exploited_flag': 0,
                'poc_flag': 0,
                'ransomware_flag': 0,
                'patch_status': 'UNKNOWN',
                'patch_missing_flag': 1,
                'detection_confidence': self._map_confidence_to_numeric(finding.get('confidence', 'MEDIUM')),
                'system_role': system_context.get('system_role', MODEL_CONFIG['default_system_role']),
                'scoring_context': json.dumps({
                    'finding_type': finding.get('finding_type'),
                    'finding_risk': finding.get('risk'),
                    'finding_description': finding.get('description'),
                    'heuristic_scoring': True
                }, default=str)
            }
            
            logger.debug(f"Calculated heuristic scores for finding {finding['finding_id']}: "
                        f"{scores['priority']} ({scores['final_score']:.3f})")
            return result
            
        except Exception as e:
            logger.error(f"Error in heuristic scoring: {e}")
            return None
    
    def store_score(self, score_data: Dict[str, Any]) -> bool:
        """
        Store calculated score in prioritization database.
        
        Args:
            score_data: Score data from calculate_cve_score or calculate_finding_score
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with sqlite3.connect(self.prioritization_db_path) as conn:
                cursor = conn.cursor()
                
                # Prepare data for insertion
                columns = [
                    'entity_type', 'entity_id', 'cve_id', 'finding_id', 'host_hash',
                    'r_score', 'a_score', 'c_score', 'final_score', 'priority',
                    'model_version', 'scoring_timestamp', 'calculation_duration_ms',
                    'cvss_score', 'epss_probability', 'exploited_flag', 'poc_flag',
                    'ransomware_flag', 'patch_status', 'patch_missing_flag',
                    'detection_confidence', 'system_role', 'scoring_context'
                ]
                
                values = [score_data.get(col) for col in columns]
                
                # Insert with conflict resolution (update if exists)
                placeholders = ', '.join(['?' for _ in columns])
                columns_str = ', '.join(columns)
                
                cursor.execute(f"""
                    INSERT OR REPLACE INTO risk_scores ({columns_str})
                    VALUES ({placeholders})
                """, values)
                
                conn.commit()
                
                logger.debug(f"Stored score for {score_data['entity_type']} {score_data['entity_id']}")
                return True
                
        except Exception as e:
            logger.error(f"Error storing score for {score_data.get('entity_id', 'unknown')}: {e}")
            return False
    
    def run_host_prioritization(self, host_hash: str) -> Dict[str, Any]:
        """
        Run complete HARS prioritization for a host.
        
        Args:
            host_hash: Host identifier hash
        
        Returns:
            Dictionary with prioritization results
        """
        start_time = datetime.now()
        batch_id = f"BATCH-{host_hash}-{start_time.strftime('%Y%m%d%H%M%S')}"
        
        logger.info(f"Starting HARS prioritization for host {host_hash} (batch: {batch_id})")
        
        results = {
            'batch_id': batch_id,
            'host_hash': host_hash,
            'start_time': start_time.isoformat(),
            'total_cves_processed': 0,
            'total_findings_processed': 0,
            'scores_stored': 0,
            'priorities': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'errors': []
        }
        
        try:
            # 1. Process missing CVEs
            missing_cves = self._get_missing_cves(host_hash)
            results['total_cves_processed'] = len(missing_cves)
            
            for cve_data in missing_cves:
                try:
                    score_result = self.calculate_cve_score(
                        cve_id=cve_data['cve_id'],
                        host_hash=host_hash,
                        patch_status=cve_data['status'],
                        detection_confidence=cve_data['detection_confidence']
                    )
                    
                    if score_result and self.store_score(score_result):
                        results['scores_stored'] += 1
                        results['priorities'][score_result['priority']] += 1
                    else:
                        results['errors'].append(f"Failed to score CVE {cve_data['cve_id']}")
                        
                except Exception as e:
                    error_msg = f"Error processing CVE {cve_data.get('cve_id', 'unknown')}: {e}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
            
            # 2. Process security findings (non-CVE)
            try:
                with sqlite3.connect(self.runtime_db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT DISTINCT finding_id 
                        FROM raw_security_findings 
                        WHERE host_hash = ? 
                        AND finding_type NOT LIKE 'CVE-%'
                    """, (host_hash,))
                    
                    finding_ids = [row[0] for row in cursor.fetchall()]
                    results['total_findings_processed'] = len(finding_ids)
                    
                    for finding_id in finding_ids:
                        try:
                            score_result = self.calculate_finding_score(finding_id, host_hash)
                            
                            if score_result and self.store_score(score_result):
                                results['scores_stored'] += 1
                                results['priorities'][score_result['priority']] += 1
                            else:
                                results['errors'].append(f"Failed to score finding {finding_id}")
                                
                        except Exception as e:
                            error_msg = f"Error processing finding {finding_id}: {e}"
                            logger.error(error_msg)
                            results['errors'].append(error_msg)
                            
            except Exception as e:
                error_msg = f"Error fetching findings: {e}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
            
            # 3. Record scoring history
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self._record_scoring_history(
                batch_id=batch_id,
                total_entities=results['scores_stored'],
                priorities=results['priorities'],
                start_time=start_time,
                end_time=end_time,
                duration=duration
            )
            
            # 4. Update results
            results.update({
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'success': True,
                'model_version': MODEL_VERSION
            })
            
            logger.info(f"HARS prioritization complete for host {host_hash}: "
                       f"{results['scores_stored']} scores stored, "
                       f"Priorities: {results['priorities']}")
            
            return results
            
        except Exception as e:
            error_msg = f"Critical error in host prioritization: {e}"
            logger.error(error_msg)
            results.update({
                'end_time': datetime.now().isoformat(),
                'success': False,
                'error': error_msg
            })
            return results
    
    def _record_scoring_history(
        self,
        batch_id: str,
        total_entities: int,
        priorities: Dict[str, int],
        start_time: datetime,
        end_time: datetime,
        duration: float
    ) -> None:
        """Record scoring batch in history table"""
        try:
            with sqlite3.connect(self.prioritization_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO scoring_history (
                        batch_id, total_entities_scored, high_priority_count,
                        medium_priority_count, low_priority_count, scoring_start_timestamp,
                        scoring_end_timestamp, duration_seconds, model_version,
                        parameters_used
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    batch_id,
                    total_entities,
                    priorities.get('HIGH', 0),
                    priorities.get('MEDIUM', 0),
                    priorities.get('LOW', 0),
                    start_time.isoformat(),
                    end_time.isoformat(),
                    duration,
                    MODEL_VERSION,
                    json.dumps(MODEL_CONFIG, default=str)
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error recording scoring history: {e}")
    
    def get_priority_summary(self, host_hash: Optional[str] = None) -> Dict[str, Any]:
        """
        Get priority summary from stored scores.
        
        Args:
            host_hash: Optional host filter
        
        Returns:
            Dictionary with priority summary
        """
        try:
            with sqlite3.connect(self.prioritization_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                if host_hash:
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total,
                            SUM(CASE WHEN priority = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                            SUM(CASE WHEN priority = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                            SUM(CASE WHEN priority = 'LOW' THEN 1 ELSE 0 END) as low_count,
                            AVG(final_score) as avg_score,
                            MAX(final_score) as max_score,
                            MIN(final_score) as min_score
                        FROM risk_scores 
                        WHERE host_hash = ?
                        AND model_version = ?
                    """, (host_hash, MODEL_VERSION))
                else:
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total,
                            SUM(CASE WHEN priority = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                            SUM(CASE WHEN priority = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                            SUM(CASE WHEN priority = 'LOW' THEN 1 ELSE 0 END) as low_count,
                            AVG(final_score) as avg_score,
                            MAX(final_score) as max_score,
                            MIN(final_score) as min_score
                        FROM risk_scores 
                        WHERE model_version = ?
                    """, (MODEL_VERSION,))
                
                row = cursor.fetchone()
                if not row:
                    return {'total': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0}
                
                summary = dict(row)
                
                # Calculate percentages
                total = summary['total'] or 0
                if total > 0:
                    summary['high_percentage'] = (summary['high_count'] / total) * 100
                    summary['medium_percentage'] = (summary['medium_count'] / total) * 100
                    summary['low_percentage'] = (summary['low_count'] / total) * 100
                else:
                    summary.update({
                        'high_percentage': 0.0,
                        'medium_percentage': 0.0,
                        'low_percentage': 0.0
                    })
                
                return summary
                
        except Exception as e:
            logger.error(f"Error getting priority summary: {e}")
            return {'total': 0, 'high_count': 0, 'medium_count': 0, 'low_count': 0}


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def main():
    """Command-line interface for HARS prioritization"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='HARS (Hybrid Automated Risk Scoring) Prioritization Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run prioritization for all hosts
  python hars.py --run-all
  
  # Run for specific host hash
  python hars.py --host-hash abc123def456
  
  # Get summary for host
  python hars.py --summary --host-hash abc123def456
  
  # Test with specific CVE
  python hars.py --test-cve CVE-2023-1234 --host-hash abc123def456
        """
    )
    
    parser.add_argument('--run-all', action='store_true',
                       help='Run prioritization for all hosts in runtime DB')
    parser.add_argument('--host-hash', type=str,
                       help='Run prioritization for specific host hash')
    parser.add_argument('--summary', action='store_true',
                       help='Show priority summary')
    parser.add_argument('--test-cve', type=str,
                       help='Test scoring for specific CVE')
    parser.add_argument('--runtime-db', default=RUNTIME_DB,
                       help=f'Runtime database path (default: {RUNTIME_DB})')
    parser.add_argument('--catalogue-db', default=CATALOGUE_DB,
                       help=f'Catalogue database path (default: {CATALOGUE_DB})')
    parser.add_argument('--output-db', default=PRIORITIZATION_DB,
                       help=f'Output database path (default: {PRIORITIZATION_DB})')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize engine
    try:
        engine = HARSEngine(
            runtime_db_path=args.runtime_db,
            catalogue_db_path=args.catalogue_db,
            prioritization_db_path=args.output_db
        )
        
        if args.test_cve and args.host_hash:
            # Test scoring for specific CVE
            print(f"\nTesting HARS scoring for CVE {args.test_cve} on host {args.host_hash}")
            print("=" * 60)
            
            score = engine.calculate_cve_score(
                cve_id=args.test_cve,
                host_hash=args.host_hash
            )
            
            if score:
                print(f"\nResults:")
                print(f"  CVE ID: {score['cve_id']}")
                print(f"  R Score: {score['r_score']:.3f}")
                print(f"  A Score: {score['a_score']:.3f}")
                print(f"  C Score: {score['c_score']:.3f}")
                print(f"  Final Score: {score['final_score']:.3f}")
                print(f"  Priority: {score['priority']}")
                print(f"  Model: {score['model_version']}")
            else:
                print(f"Failed to calculate score for CVE {args.test_cve}")
        
        elif args.summary:
            # Show summary
            print(f"\nHARS Priority Summary")
            print("=" * 60)
            
            summary = engine.get_priority_summary(args.host_hash)
            
            if args.host_hash:
                print(f"Host: {args.host_hash}")
            
            print(f"\nTotal Scores: {summary['total']}")
            print(f"High Priority: {summary['high_count']} ({summary.get('high_percentage', 0):.1f}%)")
            print(f"Medium Priority: {summary['medium_count']} ({summary.get('medium_percentage', 0):.1f}%)")
            print(f"Low Priority: {summary['low_count']} ({summary.get('low_percentage', 0):.1f}%)")
            
            if summary['total'] > 0:
                print(f"\nScore Statistics:")
                print(f"  Average: {summary.get('avg_score', 0):.3f}")
                print(f"  Maximum: {summary.get('max_score', 0):.3f}")
                print(f"  Minimum: {summary.get('min_score', 0):.3f}")
        
        elif args.host_hash:
            # Run for specific host
            print(f"\nRunning HARS prioritization for host {args.host_hash}")
            print("=" * 60)
            
            results = engine.run_host_prioritization(args.host_hash)
            
            if results['success']:
                print(f"\n✓ Prioritization completed successfully")
                print(f"  Duration: {results['duration_seconds']:.2f}s")
                print(f"  Scores Stored: {results['scores_stored']}")
                print(f"  Priorities:")
                print(f"    HIGH: {results['priorities']['HIGH']}")
                print(f"    MEDIUM: {results['priorities']['MEDIUM']}")
                print(f"    LOW: {results['priorities']['LOW']}")
                
                if results['errors']:
                    print(f"\n  Errors encountered: {len(results['errors'])}")
                    for error in results['errors'][:5]:  # Show first 5 errors
                        print(f"    - {error}")
            else:
                print(f"\n✗ Prioritization failed: {results.get('error', 'Unknown error')}")
        
        elif args.run_all:
            # Run for all hosts (simplified implementation)
            print("\nRunning HARS prioritization for all hosts")
            print("=" * 60)
            
            # Get all host hashes from runtime DB
            try:
                with sqlite3.connect(args.runtime_db) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT DISTINCT host_hash FROM system_info")
                    host_hashes = [row[0] for row in cursor.fetchall()]
                
                total_results = {
                    'total_hosts': len(host_hashes),
                    'successful_hosts': 0,
                    'failed_hosts': 0,
                    'total_scores': 0,
                    'priorities': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                }
                
                for host_hash in host_hashes:
                    print(f"\nProcessing host: {host_hash}")
                    results = engine.run_host_prioritization(host_hash)
                    
                    if results['success']:
                        total_results['successful_hosts'] += 1
                        total_results['total_scores'] += results['scores_stored']
                        for priority in ['HIGH', 'MEDIUM', 'LOW']:
                            total_results['priorities'][priority] += results['priorities'][priority]
                    else:
                        total_results['failed_hosts'] += 1
                
                print(f"\n" + "=" * 60)
                print("BATCH PROCESSING COMPLETE")
                print("=" * 60)
                print(f"Total Hosts: {total_results['total_hosts']}")
                print(f"Successful: {total_results['successful_hosts']}")
                print(f"Failed: {total_results['failed_hosts']}")
                print(f"Total Scores: {total_results['total_scores']}")
                print(f"Priority Distribution:")
                print(f"  HIGH: {total_results['priorities']['HIGH']}")
                print(f"  MEDIUM: {total_results['priorities']['MEDIUM']}")
                print(f"  LOW: {total_results['priorities']['LOW']}")
                
            except Exception as e:
                print(f"\n✗ Batch processing failed: {e}")
        
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"\n✗ HARS Engine initialization failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
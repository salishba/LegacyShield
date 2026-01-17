"""
feature_extractor.py - ML Feature Extractor for Vulnerability Prioritization
Extracts numeric features from SQLite databases for ML model training.
"""

import sqlite3
import pandas as pd
import numpy as np
import logging
from datetime import datetime, date
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import json
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extracts ML features from runtime scan and catalogue databases.
    All features are numeric for ML compatibility.
    """
    
    def __init__(self, runtime_db_path: str, catalogue_db_path: str):
        self.runtime_db_path = Path(runtime_db_path)
        self.catalogue_db_path = Path(catalogue_db_path)
        
        if not self.runtime_db_path.exists():
            raise FileNotFoundError(f"Runtime database not found: {self.runtime_db_path}")
        if not self.catalogue_db_path.exists():
            raise FileNotFoundError(f"Catalogue database not found: {self.catalogue_db_path}")
        
        self.system_info = self._load_system_info()
        logger.info(f"Initialized FeatureExtractor for host: {self.system_info.get('hostname', 'Unknown')}")
    
    def _load_system_info(self) -> Dict[str, Any]:
        """Load system information from runtime database"""
        try:
            with sqlite3.connect(self.runtime_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM system_info LIMIT 1")
                row = cursor.fetchone()
                return dict(row) if row else {}
        except Exception as e:
            logger.error(f"Failed to load system info: {e}")
            return {}
    
    def _calculate_os_age_score(self, build_number: str) -> float:
        """
        Calculate OS age score based on build number.
        Higher score = older, more vulnerable OS.
        Returns normalized score between 0.0 (newest) and 1.0 (oldest).
        """
        try:
            build = int(build_number) if build_number.isdigit() else 0
            
            # Windows version reference build numbers
            # Source: https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
            windows_versions = {
                'Windows XP': 2600,
                'Windows Vista': 6000,
                'Windows 7': 7600,
                'Windows 8': 9200,
                'Windows 8.1': 9600,
                'Windows 10 1507': 10240,
                'Windows 10 1511': 10586,
                'Windows 10 1607': 14393,
                'Windows 10 1703': 15063,
                'Windows 10 1709': 16299,
                'Windows 10 1803': 17134,
                'Windows 10 1809': 17763,
                'Windows 10 1903': 18362,
                'Windows 10 1909': 18363,
                'Windows 10 2004': 19041,
                'Windows 10 20H2': 19042,
                'Windows 10 21H1': 19043,
                'Windows 10 21H2': 19044,
                'Windows 11': 22000,
            }
            
            # Find closest version
            closest_version = None
            min_diff = float('inf')
            
            for version, version_build in windows_versions.items():
                diff = abs(build - version_build)
                if diff < min_diff:
                    min_diff = diff
                    closest_version = version_build
            
            if closest_version:
                # Calculate age relative to newest Windows 11
                newest_build = 22621  # Windows 11 22H2
                age_score = max(0, (newest_build - closest_version) / newest_build)
                return min(1.0, age_score)
            
            return 0.5  # Default for unknown builds
        except Exception as e:
            logger.warning(f"Error calculating OS age score: {e}")
            return 0.5
    
    def _calculate_system_role_score(self, system_info: Dict[str, Any]) -> float:
        """
        Calculate system role/importance score.
        Higher score = more critical system.
        """
        score = 0.0
        
        try:
            hostname = system_info.get('hostname', '').upper()
            
            # Domain controller detection
            if 'DC' in hostname or 'DOMAIN' in hostname:
                score += 0.5
            
            # Server detection
            if 'SRV' in hostname or 'SERVER' in hostname:
                score += 0.3
            
            # Critical infrastructure patterns
            critical_patterns = ['SQL', 'EXCH', 'AD', 'FS', 'PRINT', 'WEB', 'APP']
            for pattern in critical_patterns:
                if pattern in hostname:
                    score += 0.2
                    break
            
            # Check domain role from system info
            domain_role = system_info.get('domain_role', 0)
            if isinstance(domain_role, str):
                try:
                    domain_role = int(domain_role)
                except ValueError:
                    domain_role = 0
            
            # Domain roles: 0=Standalone, 1=Member, 2=Backup DC, 3=Primary DC, 4=Unknown
            if domain_role >= 3:  # Domain controller
                score = max(score, 0.7)
            elif domain_role == 2:  # Backup DC
                score = max(score, 0.5)
            elif domain_role == 1:  # Domain member
                score = max(score, 0.3)
            
            return min(1.0, score)
        except Exception as e:
            logger.warning(f"Error calculating system role score: {e}")
            return 0.3
    
    def _map_detection_confidence(self, confidence: str) -> float:
        """Map textual confidence to numeric value"""
        confidence_map = {
            'HIGH': 1.0,
            'MEDIUM': 0.7,
            'MED': 0.7,  # Handle abbreviation
            'LOW': 0.3,
            'VERIFIED': 0.9,
            'UNKNOWN': 0.5,
            'CONFIRMED': 1.0,
            'PROBABLE': 0.8,
            'POSSIBLE': 0.6,
            'TENTATIVE': 0.4,
        }
        return confidence_map.get(str(confidence).upper(), 0.5)
    
    def _check_patch_missing(self, cve_id: str, installed_kbs: set) -> Tuple[bool, float]:
        """
        Check if patch is missing for CVE.
        Returns (is_missing, confidence)
        """
        try:
            with sqlite3.connect(self.catalogue_db_path) as conn:
                cursor = conn.cursor()
                
                # Get KBs for this CVE
                cursor.execute("""
                    SELECT kb_article FROM cve_kb_map 
                    WHERE cve_id = ?
                """, (cve_id,))
                
                kb_rows = cursor.fetchall()
                if not kb_rows:
                    # No patch information available
                    return (False, 0.3)
                
                # Check supersedence chain
                for (kb,) in kb_rows:
                    if kb and self._is_kb_installed(kb, installed_kbs):
                        return (False, 0.9)  # Patch is installed
                
                # Patch is missing
                return (True, 0.8)
                
        except Exception as e:
            logger.error(f"Error checking patch for CVE {cve_id}: {e}")
            return (False, 0.5)
    
    def _is_kb_installed(self, kb: str, installed_kbs: set) -> bool:
        """Check if KB is installed directly or via supersedence"""
        # Direct match
        if kb in installed_kbs:
            return True
        
        # Check supersedence chain
        try:
            with sqlite3.connect(self.catalogue_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT superseding_kb FROM supersedence_map 
                    WHERE kb_id = ? AND superseding_kb IN ({})
                """.format(','.join(['?'] * len(installed_kbs))), [kb] + list(installed_kbs))
                
                return cursor.fetchone() is not None
        except Exception:
            return False
    
    def _get_installed_kbs(self) -> set:
        """Get set of installed KBs from runtime database"""
        try:
            with sqlite3.connect(self.runtime_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT kb_id FROM installed_kbs")
                return {row[0] for row in cursor.fetchall()}
        except Exception as e:
            logger.error(f"Error fetching installed KBs: {e}")
            return set()
    
    def _check_mitigation_available(self, cve_id: str) -> Tuple[bool, float]:
        """Check if mitigation is available for CVE"""
        try:
            with sqlite3.connect(self.catalogue_db_path) as conn:
                cursor = conn.cursor()
                
                # Check registry mitigations
                cursor.execute("""
                    SELECT COUNT(*) FROM registry_mitigations 
                    WHERE cve_id = ?
                """, (cve_id,))
                reg_count = cursor.fetchone()[0]
                
                # Check system mitigations
                cursor.execute("""
                    SELECT COUNT(*) FROM system_mitigations 
                    WHERE cve_id = ?
                """, (cve_id,))
                sys_count = cursor.fetchone()[0]
                
                # Check network mitigations
                cursor.execute("""
                    SELECT COUNT(*) FROM network_mitigations 
                    WHERE cve_id = ?
                """, (cve_id,))
                net_count = cursor.fetchone()[0]
                
                total_mitigations = reg_count + sys_count + net_count
                has_mitigation = total_mitigations > 0
                
                # Calculate confidence based on mitigation count
                confidence = min(1.0, total_mitigations * 0.3) if has_mitigation else 0.0
                
                return (has_mitigation, confidence)
                
        except Exception as e:
            logger.error(f"Error checking mitigation for CVE {cve_id}: {e}")
            return (False, 0.0)
    
    def extract_features_for_cve(self, cve_id: str) -> Optional[Dict[str, float]]:
        """
        Extract all numeric features for a single CVE.
        Returns None if CVE not found in catalogue.
        """
        try:
            with sqlite3.connect(self.catalogue_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get CVE vulnerability data
                cursor.execute("""
                    SELECT cvss, epss, exploited, poc, ransomware 
                    FROM vulnerabilities 
                    WHERE cve_id = ?
                """, (cve_id,))
                
                row = cursor.fetchone()
                if not row:
                    logger.warning(f"CVE {cve_id} not found in catalogue")
                    return None
                
                vuln_data = dict(row)
                
                # Get patch availability
                cursor.execute("""
                    SELECT COUNT(*) FROM cve_kb_map 
                    WHERE cve_id = ? AND kb_article IS NOT NULL
                """, (cve_id,))
                patch_count = cursor.fetchone()[0]
                
                # Get installed KBs
                installed_kbs = self._get_installed_kbs()
                
                # Calculate features
                features = {
                    'cvss_score': float(vuln_data.get('cvss', 0.0)) / 10.0,  # Normalize 0-10 to 0-1
                    'epss_probability': float(vuln_data.get('epss', 0.0)),
                    'exploited_in_wild': 1.0 if vuln_data.get('exploited') else 0.0,
                    'ransomware_associated': 1.0 if vuln_data.get('ransomware') else 0.0,
                    'proof_of_concept': 1.0 if vuln_data.get('poc') else 0.0,
                    'patch_available': 1.0 if patch_count > 0 else 0.0,
                }
                
                # Check patch missing
                patch_missing, patch_confidence = self._check_patch_missing(cve_id, installed_kbs)
                features['patch_missing'] = 1.0 if patch_missing else 0.0
                features['detection_confidence'] = patch_confidence
                
                # Check mitigation available
                mitigation_available, mitigation_confidence = self._check_mitigation_available(cve_id)
                features['mitigation_available'] = 1.0 if mitigation_available else 0.0
                features['mitigation_confidence'] = mitigation_confidence
                
                # OS age score
                build_number = self.system_info.get('build_number', '0')
                features['os_age_score'] = self._calculate_os_age_score(build_number)
                
                # System role score
                features['system_role_score'] = self._calculate_system_role_score(self.system_info)
                
                # Add context features
                features['is_domain_member'] = 1.0 if self.system_info.get('part_of_domain') else 0.0
                features['is_server'] = 1.0 if 'SERVER' in str(self.system_info.get('hostname', '')).upper() else 0.0
                
                # Calculate combined threat score (intermediate feature)
                features['threat_score'] = (
                    0.4 * features['cvss_score'] +
                    0.3 * features['epss_probability'] +
                    0.2 * features['exploited_in_wild'] +
                    0.1 * features['ransomware_associated']
                )
                
                # Add CVE identifier for tracking
                features['cve_id_hash'] = float(int(hashlib.md5(cve_id.encode()).hexdigest()[:8], 16)) / 0xffffffff
                
                return features
                
        except Exception as e:
            logger.error(f"Error extracting features for CVE {cve_id}: {e}")
            return None
    
    def extract_all_features(self) -> pd.DataFrame:
        """
        Extract features for all CVEs detected in the system.
        Returns DataFrame with features only (no CVE IDs in index).
        """
        try:
            # Get all CVEs with missing patches from runtime DB
            missing_cves = self._get_missing_cves()
            
            if not missing_cves:
                logger.warning("No missing CVEs found in runtime database")
                return pd.DataFrame()
            
            logger.info(f"Found {len(missing_cves)} CVEs with missing patches")
            
            features_list = []
            successful = 0
            failed = 0
            
            for cve_id in missing_cves:
                features = self.extract_features_for_cve(cve_id)
                if features:
                    features['cve_id'] = cve_id  # Keep for debugging/tracking
                    features_list.append(features)
                    successful += 1
                else:
                    failed += 1
            
            logger.info(f"Feature extraction complete: {successful} successful, {failed} failed")
            
            if not features_list:
                return pd.DataFrame()
            
            # Create DataFrame
            df = pd.DataFrame(features_list)
            
            # Set index to hash for anonymity, keep CVE ID as column
            if 'cve_id_hash' in df.columns:
                df.set_index('cve_id_hash', inplace=True)
            
            # Ensure all features are numeric
            for col in df.columns:
                if col != 'cve_id':  # Keep CVE ID as string column
                    df[col] = pd.to_numeric(df[col], errors='coerce')
            
            # Fill NaN values with column means
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())
            
            # Drop any remaining non-numeric columns except cve_id
            cols_to_keep = ['cve_id'] + [col for col in df.columns if col != 'cve_id']
            df = df[cols_to_keep]
            
            logger.info(f"Final feature matrix shape: {df.shape}")
            return df
            
        except Exception as e:
            logger.error(f"Error in extract_all_features: {e}")
            return pd.DataFrame()
    
    def _get_missing_cves(self) -> List[str]:
        """Get list of CVEs with missing patches from runtime database"""
        try:
            with sqlite3.connect(self.runtime_db_path) as conn:
                cursor = conn.cursor()
                
                # Get CVEs from missing_patches table
                cursor.execute("""
                    SELECT DISTINCT cve_id FROM missing_patches 
                    WHERE status = 'MISSING'
                """)
                
                rows = cursor.fetchall()
                return [row[0] for row in rows if row[0]]
                
        except Exception as e:
            logger.error(f"Error fetching missing CVEs: {e}")
            return []
    
    def get_feature_descriptions(self) -> Dict[str, str]:
        """Return descriptions of all extracted features"""
        return {
            'cvss_score': 'CVSS base score normalized to 0-1',
            'epss_probability': 'EPSS probability of exploitation (0-1)',
            'exploited_in_wild': 'Boolean: Known exploitation in wild',
            'ransomware_associated': 'Boolean: Associated with ransomware',
            'proof_of_concept': 'Boolean: Proof of concept available',
            'patch_available': 'Boolean: Patch exists in catalogue',
            'patch_missing': 'Boolean: Patch not installed on system',
            'detection_confidence': 'Confidence in patch detection (0-1)',
            'mitigation_available': 'Boolean: Mitigation exists in catalogue',
            'mitigation_confidence': 'Confidence in mitigation availability (0-1)',
            'os_age_score': 'OS age/obsolescence score (0-1, higher=older)',
            'system_role_score': 'System importance/role score (0-1, higher=more critical)',
            'is_domain_member': 'Boolean: System is domain member',
            'is_server': 'Boolean: System is server role',
            'threat_score': 'Combined threat score weighted average',
            'cve_id_hash': 'Anonymized CVE identifier hash',
            'cve_id': 'Original CVE identifier (for reference only)',
        }


# Factory function for easy use
def extract_features(runtime_db: str, catalogue_db: str) -> pd.DataFrame:
    """
    High-level function to extract features from databases.
    
    Args:
        runtime_db: Path to runtime_scan.sqlite
        catalogue_db: Path to smartpatch_catalogue.sqlite
        
    Returns:
        pandas DataFrame with features
    """
    extractor = FeatureExtractor(runtime_db, catalogue_db)
    return extractor.extract_all_features()


if __name__ == "__main__":
    # Test the feature extractor
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python feature_extractor.py <runtime_db> <catalogue_db>")
        sys.exit(1)
    
    runtime_db = sys.argv[1]
    catalogue_db = sys.argv[2]
    
    print(f"Extracting features from:")
    print(f"  Runtime DB: {runtime_db}")
    print(f"  Catalogue DB: {catalogue_db}")
    
    df = extract_features(runtime_db, catalogue_db)
    
    if df.empty:
        print("No features extracted - check database contents")
    else:
        print(f"\nExtracted {len(df)} CVEs with {df.shape[1]} features")
        print("\nFirst few rows:")
        print(df.head())
        print("\nFeature descriptions:")
        extractor = FeatureExtractor(runtime_db, catalogue_db)
        for feat, desc in extractor.get_feature_descriptions().items():
            if feat in df.columns:
                print(f"  {feat}: {desc}")
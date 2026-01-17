"""
dataset_builder.py - ML Dataset Builder for Vulnerability Prioritization
Orchestrates feature extraction and label generation to create ML-ready datasets.
"""

import pandas as pd
import numpy as np
import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import the modules we'll use
try:
    from feature_extractor import FeatureExtractor, extract_features
    from label_generator import LabelGenerator, generate_labels
except ImportError:
    # For testing when modules are in same directory
    logger.warning("Could not import modules directly, using relative imports")
    import sys
    sys.path.append('.')
    from feature_extractor import FeatureExtractor, extract_features
    from label_generator import LabelGenerator, generate_labels


class DatasetBuilder:
    """
    Orchestrates the complete dataset building pipeline.
    Creates ML-ready datasets from runtime and catalogue databases.
    """
    
    def __init__(self, runtime_db_path: str, catalogue_db_path: str):
        self.runtime_db_path = Path(runtime_db_path)
        self.catalogue_db_path = Path(catalogue_db_path)
        
        if not self.runtime_db_path.exists():
            raise FileNotFoundError(f"Runtime database not found: {self.runtime_db_path}")
        if not self.catalogue_db_path.exists():
            raise FileNotFoundError(f"Catalogue database not found: {self.catalogue_db_path}")
        
        self.dataset_id = self._generate_dataset_id()
        self.metadata = {}
        
        logger.info(f"Initialized DatasetBuilder with ID: {self.dataset_id}")
        logger.info(f"Runtime DB: {self.runtime_db_path}")
        logger.info(f"Catalogue DB: {self.catalogue_db_path}")
    
    def _generate_dataset_id(self) -> str:
        """Generate unique dataset ID based on database timestamps"""
        try:
            # Get runtime database timestamp
            runtime_mtime = self.runtime_db_path.stat().st_mtime
            runtime_time = datetime.fromtimestamp(runtime_mtime)
            
            # Get catalogue database timestamp
            catalogue_mtime = self.catalogue_db_path.stat().st_mtime
            catalogue_time = datetime.fromtimestamp(catalogue_mtime)
            
            # Generate ID
            timestamp_str = runtime_time.strftime("%Y%m%d_%H%M%S")
            return f"dataset_{timestamp_str}"
            
        except Exception as e:
            logger.warning(f"Error generating dataset ID: {e}")
            return f"dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _load_system_context(self) -> Dict[str, Any]:
        """Load system context from runtime database"""
        try:
            with sqlite3.connect(self.runtime_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get system info
                cursor.execute("SELECT * FROM system_info LIMIT 1")
                system_row = cursor.fetchone()
                system_info = dict(system_row) if system_row else {}
                
                # Get scan statistics
                cursor.execute("SELECT COUNT(*) as total_findings FROM raw_security_findings")
                findings_count = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(DISTINCT cve_id) as missing_cves 
                    FROM missing_patches 
                    WHERE status = 'MISSING'
                """)
                missing_cves = cursor.fetchone()[0]
                
                context = {
                    'system_info': system_info,
                    'findings_count': findings_count,
                    'missing_cves_count': missing_cves,
                    'runtime_db_timestamp': datetime.fromtimestamp(self.runtime_db_path.stat().st_mtime).isoformat(),
                    'catalogue_db_timestamp': datetime.fromtimestamp(self.catalogue_db_path.stat().st_mtime).isoformat(),
                }
                
                return context
                
        except Exception as e:
            logger.error(f"Error loading system context: {e}")
            return {}
    
    def _extract_features_with_validation(self) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Extract features with validation and statistics"""
        logger.info("Starting feature extraction...")
        
        try:
            extractor = FeatureExtractor(self.runtime_db_path, self.catalogue_db_path)
            
            # Extract features
            features_df = extractor.extract_all_features()
            
            # Calculate statistics
            stats = {
                'total_cves_extracted': len(features_df),
                'features_extracted': len(features_df.columns) if not features_df.empty else 0,
                'extraction_timestamp': datetime.now().isoformat(),
            }
            
            if not features_df.empty:
                # Add feature statistics
                numeric_features = features_df.select_dtypes(include=[np.number]).columns.tolist()
                stats['numeric_features_count'] = len(numeric_features)
                
                # Calculate basic statistics for key features
                for feature in ['cvss_score', 'epss_probability', 'threat_score']:
                    if feature in features_df.columns:
                        stats[f'{feature}_mean'] = float(features_df[feature].mean())
                        stats[f'{feature}_std'] = float(features_df[feature].std())
                        stats[f'{feature}_min'] = float(features_df[feature].min())
                        stats[f'{feature}_max'] = float(features_df[feature].max())
            
            logger.info(f"Feature extraction complete: {stats['total_cves_extracted']} CVEs extracted")
            return features_df, stats
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return pd.DataFrame(), {'error': str(e)}
    
    def _generate_labels_with_validation(self, features_df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Generate labels with validation and statistics"""
        logger.info("Starting label generation...")
        
        try:
            generator = LabelGenerator()
            
            # Generate labels
            labeled_df = generator.generate_labels(features_df)
            
            # Calculate statistics
            stats = {
                'label_generation_timestamp': datetime.now().isoformat(),
                'total_cves_labeled': len(labeled_df),
            }
            
            if not labeled_df.empty:
                # Add label distribution
                if 'priority_label' in labeled_df.columns:
                    priority_dist = labeled_df['priority_label'].value_counts().to_dict()
                    stats['priority_label_distribution'] = priority_dist
                
                if 'action_label' in labeled_df.columns:
                    action_dist = labeled_df['action_label'].value_counts().to_dict()
                    stats['action_label_distribution'] = action_dist
                
                # Validate labels
                validation = generator.validate_labels(labeled_df)
                stats['validation'] = validation
            
            logger.info(f"Label generation complete: {stats['total_cves_labeled']} CVEs labeled")
            return labeled_df, stats
            
        except Exception as e:
            logger.error(f"Label generation failed: {e}")
            return features_df, {'error': str(e)}
    
    def _create_ml_ready_dataset(self, labeled_df: pd.DataFrame) -> pd.DataFrame:
        """
        Create ML-ready dataset by selecting appropriate features.
        Removes metadata columns and prepares for model training.
        """
        if labeled_df.empty:
            return pd.DataFrame()
        
        # Columns to keep for ML training
        feature_columns = [
            'cvss_score', 'epss_probability', 'exploited_in_wild',
            'ransomware_associated', 'proof_of_concept', 'patch_available',
            'patch_missing', 'detection_confidence', 'mitigation_available',
            'mitigation_confidence', 'os_age_score', 'system_role_score',
            'is_domain_member', 'is_server', 'threat_score',
        ]
        
        # Select only columns that exist
        existing_features = [col for col in feature_columns if col in labeled_df.columns]
        
        # Always include labels
        label_columns = ['priority_label', 'action_label']
        existing_labels = [col for col in label_columns if col in labeled_df.columns]
        
        # Create ML dataset
        ml_columns = existing_features + existing_labels
        
        # Add CVE ID for traceability if it exists
        if 'cve_id' in labeled_df.columns:
            ml_columns.append('cve_id')
        
        ml_dataset = labeled_df[ml_columns].copy()
        
        # Ensure all features are numeric
        for col in existing_features:
            if col in ml_dataset.columns:
                ml_dataset[col] = pd.to_numeric(ml_dataset[col], errors='coerce')
        
        # Fill any NaN values with column means for features only
        for col in existing_features:
            if col in ml_dataset.columns and ml_dataset[col].isna().any():
                col_mean = ml_dataset[col].mean()
                ml_dataset[col] = ml_dataset[col].fillna(col_mean)
        
        logger.info(f"ML dataset created with {len(ml_dataset)} samples and {len(ml_columns)} columns")
        return ml_dataset
    
    def _save_dataset_to_csv(self, ml_dataset: pd.DataFrame, output_path: Path) -> bool:
        """Save dataset to CSV file"""
        try:
            ml_dataset.to_csv(output_path, index=False)
            logger.info(f"Dataset saved to CSV: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save dataset to CSV: {e}")
            return False
    
    def _save_dataset_to_sqlite(self, ml_dataset: pd.DataFrame, output_path: Path) -> bool:
        """Save dataset to SQLite database"""
        try:
            with sqlite3.connect(output_path) as conn:
                # Save main dataset
                ml_dataset.to_sql('ml_dataset', conn, if_exists='replace', index=False)
                
                # Save metadata
                metadata_df = pd.DataFrame([self.metadata])
                metadata_df.to_sql('dataset_metadata', conn, if_exists='replace', index=False)
                
                # Create indices for faster querying
                cursor = conn.cursor()
                if 'cve_id' in ml_dataset.columns:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON ml_dataset(cve_id)")
                if 'priority_label' in ml_dataset.columns:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_priority ON ml_dataset(priority_label)")
                if 'action_label' in ml_dataset.columns:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_action ON ml_dataset(action_label)")
                
                conn.commit()
            
            logger.info(f"Dataset saved to SQLite: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save dataset to SQLite: {e}")
            return False
    
    def build_dataset(self, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Build complete ML-ready dataset.
        
        Args:
            output_dir: Directory to save output files (default: current directory)
            
        Returns:
            Dictionary with build results and statistics
        """
        start_time = datetime.now()
        logger.info(f"Starting dataset build {self.dataset_id}")
        
        # Set output directory
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
        else:
            output_path = Path.cwd()
        
        # Initialize results
        results = {
            'dataset_id': self.dataset_id,
            'build_start_time': start_time.isoformat(),
            'runtime_db': str(self.runtime_db_path),
            'catalogue_db': str(self.catalogue_db_path),
            'success': False,
        }
        
        try:
            # Step 1: Load system context
            system_context = self._load_system_context()
            self.metadata['system_context'] = system_context
            
            # Step 2: Extract features
            features_df, feature_stats = self._extract_features_with_validation()
            self.metadata['feature_extraction'] = feature_stats
            
            if features_df.empty:
                logger.error("No features extracted - cannot build dataset")
                results['error'] = 'No features extracted'
                return results
            
            # Step 3: Generate labels
            labeled_df, label_stats = self._generate_labels_with_validation(features_df)
            self.metadata['label_generation'] = label_stats
            
            if labeled_df.empty:
                logger.error("No labels generated - cannot build dataset")
                results['error'] = 'No labels generated'
                return results
            
            # Step 4: Create ML-ready dataset
            ml_dataset = self._create_ml_ready_dataset(labeled_df)
            
            if ml_dataset.empty:
                logger.error("ML dataset creation failed")
                results['error'] = 'ML dataset creation failed'
                return results
            
            # Step 5: Save datasets
            output_files = {}
            
            # Save CSV
            csv_path = output_path / f"{self.dataset_id}.csv"
            if self._save_dataset_to_csv(ml_dataset, csv_path):
                output_files['csv'] = str(csv_path)
            
            # Save SQLite
            sqlite_path = output_path / f"{self.dataset_id}.sqlite"
            if self._save_dataset_to_sqlite(ml_dataset, sqlite_path):
                output_files['sqlite'] = str(sqlite_path)
            
            # Save metadata JSON
            metadata_path = output_path / f"{self.dataset_id}_metadata.json"
            try:
                with open(metadata_path, 'w') as f:
                    json.dump(self.metadata, f, indent=2, default=str)
                output_files['metadata'] = str(metadata_path)
            except Exception as e:
                logger.error(f"Failed to save metadata: {e}")
            
            # Calculate final statistics
            end_time = datetime.now()
            build_duration = (end_time - start_time).total_seconds()
            
            results.update({
                'success': True,
                'build_end_time': end_time.isoformat(),
                'build_duration_seconds': build_duration,
                'total_cves': len(ml_dataset),
                'total_features': len(ml_dataset.columns) - 2,  # Exclude labels
                'output_files': output_files,
                'dataset_summary': {
                    'rows': len(ml_dataset),
                    'columns': len(ml_dataset.columns),
                    'feature_columns': [col for col in ml_dataset.columns if col not in ['priority_label', 'action_label', 'cve_id']],
                    'label_columns': [col for col in ml_dataset.columns if col in ['priority_label', 'action_label']],
                }
            })
            
            logger.info(f"Dataset build completed successfully in {build_duration:.2f} seconds")
            logger.info(f"Dataset contains {len(ml_dataset)} CVEs with {len(ml_dataset.columns)} columns")
            logger.info(f"Output files: {list(output_files.values())}")
            
            # Log label distribution
            if 'priority_label' in ml_dataset.columns:
                priority_dist = ml_dataset['priority_label'].value_counts()
                logger.info("Final Priority Distribution:")
                for label, count in priority_dist.items():
                    percentage = (count / len(ml_dataset)) * 100
                    logger.info(f"  Label {label}: {count} ({percentage:.1f}%)")
            
            return results
            
        except Exception as e:
            logger.error(f"Dataset build failed: {e}")
            results.update({
                'success': False,
                'error': str(e),
                'build_end_time': datetime.now().isoformat(),
            })
            return results
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable report of dataset build"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("DATASET BUILD REPORT")
        report_lines.append("=" * 80)
        
        if results.get('success'):
            report_lines.append(f"Status: SUCCESS")
            report_lines.append(f"Dataset ID: {results.get('dataset_id')}")
            report_lines.append(f"Build Duration: {results.get('build_duration_seconds', 0):.2f} seconds")
            report_lines.append(f"Total CVEs: {results.get('total_cves', 0)}")
            report_lines.append(f"Total Features: {results.get('total_features', 0)}")
            
            # Output files
            report_lines.append("\nOutput Files:")
            for file_type, file_path in results.get('output_files', {}).items():
                report_lines.append(f"  {file_type}: {file_path}")
            
            # Label distribution
            if 'label_generation' in self.metadata:
                label_stats = self.metadata['label_generation']
                if 'priority_label_distribution' in label_stats:
                    report_lines.append("\nPriority Label Distribution:")
                    for label, count in label_stats['priority_label_distribution'].items():
                        percentage = (count / results.get('total_cves', 1)) * 100
                        report_lines.append(f"  Label {label}: {count} ({percentage:.1f}%)")
                
                if 'action_label_distribution' in label_stats:
                    report_lines.append("\nAction Label Distribution:")
                    for label, count in label_stats['action_label_distribution'].items():
                        percentage = (count / results.get('total_cves', 1)) * 100
                        report_lines.append(f"  Label {label}: {count} ({percentage:.1f}%)")
            
            # System context
            if 'system_context' in self.metadata:
                context = self.metadata['system_context']
                report_lines.append("\nSystem Context:")
                if 'system_info' in context:
                    sys_info = context['system_info']
                    report_lines.append(f"  Hostname: {sys_info.get('hostname', 'Unknown')}")
                    report_lines.append(f"  OS Version: {sys_info.get('os_version', 'Unknown')}")
                    report_lines.append(f"  Build: {sys_info.get('build_number', 'Unknown')}")
                report_lines.append(f"  Missing CVEs: {context.get('missing_cves_count', 0)}")
                
        else:
            report_lines.append(f"Status: FAILED")
            report_lines.append(f"Error: {results.get('error', 'Unknown error')}")
        
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)


# High-level convenience function
def build_ml_dataset(
    runtime_db: str,
    catalogue_db: str,
    output_dir: Optional[str] = None,
    generate_report: bool = True
) -> Dict[str, Any]:
    """
    High-level function to build ML dataset from databases.
    
    Args:
        runtime_db: Path to runtime_scan.sqlite
        catalogue_db: Path to smartpatch_catalogue.sqlite
        output_dir: Directory to save output files
        generate_report: Whether to print a report to console
        
    Returns:
        Dictionary with build results
    """
    logger.info("Starting ML dataset build pipeline")
    
    # Create dataset builder
    builder = DatasetBuilder(runtime_db, catalogue_db)
    
    # Build dataset
    results = builder.build_dataset(output_dir)
    
    # Generate report
    if generate_report:
        report = builder.generate_report(results)
        print(report)
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Build ML dataset for vulnerability prioritization")
    parser.add_argument("--runtime-db", required=True, help="Path to runtime_scan.sqlite")
    parser.add_argument("--catalogue-db", required=True, help="Path to smartpatch_catalogue.sqlite")
    parser.add_argument("--output-dir", default="datasets", help="Output directory (default: datasets)")
    parser.add_argument("--no-report", action="store_true", help="Disable console report")
    
    args = parser.parse_args()
    
    # Build dataset
    results = build_ml_dataset(
        runtime_db=args.runtime_db,
        catalogue_db=args.catalogue_db,
        output_dir=args.output_dir,
        generate_report=not args.no_report
    )
    
    # Exit with appropriate code
    if not results.get('success'):
        exit(1)
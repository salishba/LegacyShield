#run_all.py
"""
Orchestrator for the entire patch intelligence pipeline.
Coordinates DataSeeder, Catalogue Ingester, and Patch Collector.
"""
import sys
import logging
from pathlib import Path
import sqlite3
from datetime import datetime
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import modules (ensure they're in the same directory or PYTHONPATH)
try:
    from dev_db import DataSeeder
    from scoped_catalogue import ingest_directory
    from patch_metadata_collector import ProductionPatchCollector
except ImportError as e:
    logger.error(f"Import error: {e}")
    logger.error("Ensure all modules are in the same directory:")
    logger.error("  - data_seeder.py (your DataSeeder class)")
    logger.error("  - scoped_catalogue.py")
    logger.error("  - patch_metadatacollector.py")
    sys.exit(1)


class PatchIntelligencePipeline:
    """Production-grade orchestration of all patch intelligence components."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self.default_config()
        self.setup_directories()
        
    def default_config(self) -> Dict[str, Any]:
        """Default configuration that can be overridden."""
        return {
            'dev_db': "dev_db.sqlite",
            'runtime_db': "runtime_scan.sqlite",
            'catalogue_db': "patch_catalogue.sqlite",
            'catalogues_dir': "catalogues",
            'msrc_csv': "MSRC_Catalogue.csv",
            'cve_kb_map': "cve_kb_map.json",
            'mitigation_files': [
                "application.json",
                "network.json", 
                "authorization.json",
                "services.json",
                "registry.json"
            ],
            'enable_patch_collection': False,
            'patch_collector_db': "mitigations_catalogue.sqlite"
        }
    
    def setup_directories(self):
        """Ensure all required directories exist."""
        Path(self.config['catalogues_dir']).mkdir(exist_ok=True)
        
    def verify_inputs(self) -> bool:
        """Verify all required input files exist."""
        missing_files = []
        
        # Check CSV file
        if not Path(self.config['msrc_csv']).exists():
            logger.warning(f"MSRC CSV not found: {self.config['msrc_csv']}")
            logger.info("This is acceptable for initial setup, but MSRC data will be missing")
        
        # Check JSON files in catalogues directory
        for json_file in [self.config['cve_kb_map']] + self.config['mitigation_files']:
            json_path = Path(self.config['catalogues_dir']) / json_file
            if not json_path.exists():
                missing_files.append(json_file)
        
        if missing_files:
            logger.warning(f"Missing JSON files in {self.config['catalogues_dir']}:")
            for f in missing_files:
                logger.warning(f"  - {f}")
            logger.info("Some mitigations data will be missing")
        
        return True
    
    def run_data_seeding(self) -> bool:
        """Run the initial data seeding phase."""
        logger.info("=" * 60)
        logger.info("PHASE 1: DATA SEEDING")
        logger.info("=" * 60)
        
        try:
            seeder = DataSeeder(
                dev_db_path=self.config['dev_db'],
                runtime_db_path=self.config['runtime_db']
            )
            
            # Verify database schemas
            seeder.ensure_dev_db_schema()
            seeder.seed_runtime_tables()
            
            # Seed data from files
            if Path(self.config['msrc_csv']).exists():
                seeder.seed_msrc_from_csv(self.config['msrc_csv'])
            else:
                logger.warning(f"Skipping MSRC seeding - file not found: {self.config['msrc_csv']}")
            
            # Seed CVE-KB mappings
            cve_kb_path = Path(self.config['catalogues_dir']) / self.config['cve_kb_map']
            if cve_kb_path.exists():
                seeder.seed_from_json(self.config['cve_kb_map'], "cve_kb_map")
            else:
                logger.warning(f"CVE-KB mapping not found: {cve_kb_path}")
            
            # Seed mitigation controls
            for mitigation_file in self.config['mitigation_files']:
                mitigation_path = Path(self.config['catalogues_dir']) / mitigation_file
                if mitigation_path.exists():
                    logger.info(f"Seeding mitigations from: {mitigation_file}")
                    seeder.seed_from_json(mitigation_file)
                else:
                    logger.warning(f"Mitigation file not found: {mitigation_path}")
            
            # Generate report
            seeder.generate_seeding_report()
            
            logger.info("[✓] Data seeding completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Data seeding failed: {e}", exc_info=True)
            return False
    
    def run_catalogue_ingestion(self) -> bool:
        """Run the catalogue ingestion phase."""
        logger.info("\n" + "=" * 60)
        logger.info("PHASE 2: CATALOGUE INGESTION")
        logger.info("=" * 60)
        
        try:
            json_dir = Path(self.config['catalogues_dir'])
            db_path = Path(self.config['catalogue_db'])
            
            # Ensure catalogue database exists
            if not db_path.exists():
                logger.info(f"Creating catalogue database: {db_path}")
                conn = sqlite3.connect(str(db_path))
                conn.execute("PRAGMA journal_mode=WAL;")
                
                # Create necessary tables for catalogue ingestion
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS mitigation_techniques (
                        technique_id TEXT PRIMARY KEY,
                        cve_id TEXT,
                        technique_type TEXT,
                        title TEXT,
                        description TEXT,
                        implementation TEXT,
                        validation TEXT,
                        effectiveness TEXT,
                        windows_versions TEXT,
                        potential_impact TEXT,
                        source TEXT,
                        source_url TEXT,
                        confidence REAL,
                        verified INTEGER,
                        ingested_at TEXT
                    );
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS registry_mitigations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        technique_id TEXT,
                        cve_id TEXT,
                        description TEXT,
                        registry_path TEXT,
                        value_name TEXT,
                        recommended_value TEXT,
                        risk_level TEXT,
                        source_reference TEXT
                    );
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS system_mitigations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        technique_id TEXT,
                        cve_id TEXT,
                        mitigation_type TEXT,
                        feature_name TEXT,
                        service_name TEXT,
                        action TEXT,
                        powershell_command TEXT,
                        wmi_query TEXT,
                        notes TEXT,
                        verified INTEGER,
                        source_reference TEXT
                    );
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS network_mitigations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        technique_id TEXT,
                        cve_id TEXT,
                        rule_name TEXT,
                        protocol TEXT,
                        port_range TEXT,
                        action TEXT,
                        netsh_command TEXT,
                        verified INTEGER,
                        notes TEXT,
                        source_reference TEXT
                    );
                """)
                
                conn.commit()
                conn.close()
            
            # Import the ingest_directory function
            from scoped_catalogue import ingest_directory
            
            logger.info(f"Ingesting from: {json_dir}")
            logger.info(f"Database: {db_path}")
            
            # Run ingestion
            ingest_directory(json_dir, db_path)
            
            logger.info("[✓] Catalogue ingestion completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Catalogue ingestion failed: {e}", exc_info=True)
            return False
    
    def run_patch_collection(self) -> bool:
        """Run the patch metadata collection phase (optional)."""
        if not self.config.get('enable_patch_collection', False):
            logger.info("\n" + "=" * 60)
            logger.info("PHASE 3: PATCH COLLECTION (SKIPPED)")
            logger.info("Enable with 'enable_patch_collection: True' in config")
            logger.info("=" * 60)
            return True
        
        logger.info("\n" + "=" * 60)
        logger.info("PHASE 3: PATCH COLLECTION")
        logger.info("=" * 60)
        
        try:
            collector = ProductionPatchCollector(
                db_path=self.config['patch_collector_db']
            )
            
            # Example: You would typically provide a list of KB URLs here
            # For production, you'd load these from a configuration file or database
            kb_urls = []
            
            # Load KB URLs from configuration or external file
            kb_urls_file = Path("kb_urls.txt")
            if kb_urls_file.exists():
                with open(kb_urls_file, 'r') as f:
                    kb_urls = [line.strip() for line in f if line.strip()]
            
            if not kb_urls:
                logger.warning("No KB URLs provided for patch collection")
                logger.info("Create a 'kb_urls.txt' file with one URL per line")
                logger.info("Example: https://support.microsoft.com/kb/4012212")
                return True
            
            # Collect patches from each URL
            success_count = 0
            for url in kb_urls[:5]:  # Limit to 5 for demonstration
                logger.info(f"Collecting from: {url}")
                if collector.collect_from_kb_url(url):
                    success_count += 1
                else:
                    logger.warning(f"Failed to collect from: {url}")
            
            logger.info(f"Successfully collected {success_count}/{len(kb_urls)} patches")
            
            # Example query to demonstrate functionality
            sample_host = {
                "os_name": "Windows 7",
                "architecture": "x64",
                "service_pack": "SP1",
                "build_number": "7601"
            }
            
            patches = collector.query_applicability(sample_host)
            logger.info(f"Found {len(patches)} applicable patches for sample host")
            
            logger.info("[✓] Patch collection completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Patch collection failed: {e}", exc_info=True)
            return False
    
    def create_unified_view(self) -> bool:
        """Create views that unify data across databases."""
        logger.info("\n" + "=" * 60)
        logger.info("PHASE 4: CREATE UNIFIED VIEWS")
        logger.info("=" * 60)
        
        try:
            # Create a master database with attached views
            master_db = "patch_intelligence_master.sqlite"
            
            with sqlite3.connect(master_db) as conn:
                # Attach all databases
                conn.execute(f"ATTACH DATABASE '{self.config['dev_db']}' AS dev")
                conn.execute(f"ATTACH DATABASE '{self.config['catalogue_db']}' AS catalogue")
                
                if Path(self.config['patch_collector_db']).exists():
                    conn.execute(f"ATTACH DATABASE '{self.config['patch_collector_db']}' AS patches")
                
                # Create unified view for mitigations
                conn.execute("""
                    CREATE VIEW IF NOT EXISTS unified_mitigations AS
                    SELECT 
                        'dev' as source_db,
                        'registry' as mitigation_type,
                        technique_id,
                        cve_id,
                        description,
                        registry_path as implementation_detail
                    FROM dev.registry_mitigations
                    
                    UNION ALL
                    
                    SELECT 
                        'dev' as source_db,
                        'system' as mitigation_type,
                        technique_id,
                        cve_id,
                        description,
                        notes as implementation_detail
                    FROM dev.system_mitigations
                    
                    UNION ALL
                    
                    SELECT 
                        'dev' as source_db,
                        'network' as mitigation_type,
                        technique_id,
                        cve_id,
                        description,
                        notes as implementation_detail
                    FROM dev.network_mitigations
                    
                    UNION ALL
                    
                    SELECT 
                        'catalogue' as source_db,
                        technique_type as mitigation_type,
                        technique_id,
                        cve_id,
                        description,
                        implementation as implementation_detail
                    FROM catalogue.mitigation_techniques
                    WHERE cve_id IS NOT NULL AND cve_id != ''
                """)
                
                # Create view for patch-CVE relationships
                if Path(self.config['patch_collector_db']).exists():
                    conn.execute("""
                        CREATE VIEW IF NOT EXISTS patch_cve_relationships AS
                        SELECT 
                            'catalogue' as source,
                            cve_id,
                            kb_article as kb_id,
                            'direct_mapping' as relation_type
                        FROM dev.cve_kb_map
                        
                        UNION ALL
                        
                        SELECT 
                            'patches' as source,
                            cve_id,
                            kb_id,
                            'patch_cve_link' as relation_type
                        FROM patches.cve_patch_mapping
                    """)
                
                conn.commit()
            
            logger.info(f"[✓] Unified views created in: {master_db}")
            
            # Print summary
            with sqlite3.connect(master_db) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM unified_mitigations")
                total_mitigations = cursor.fetchone()[0]
                
                logger.info(f"Total unified mitigations: {total_mitigations}")
                
                if Path(self.config['patch_collector_db']).exists():
                    cursor.execute("SELECT COUNT(*) FROM patch_cve_relationships")
                    total_relationships = cursor.fetchone()[0]
                    logger.info(f"Total patch-CVE relationships: {total_relationships}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create unified views: {e}", exc_info=True)
            return False
    
    def run(self) -> bool:
        """Execute the entire pipeline."""
        logger.info("Starting Patch Intelligence Pipeline")
        logger.info(f"Timestamp: {datetime.now().isoformat()}")
        
        # Verify inputs
        if not self.verify_inputs():
            logger.warning("Input verification found missing files")
        
        # Run phases
        phases = [
            ("Data Seeding", self.run_data_seeding),
            ("Catalogue Ingestion", self.run_catalogue_ingestion),
            ("Patch Collection", self.run_patch_collection),
            ("Unified Views", self.create_unified_view)
        ]
        
        results = []
        for phase_name, phase_func in phases:
            logger.info(f"\n{' Starting: ' + phase_name + ' ':=^60}")
            try:
                success = phase_func()
                results.append((phase_name, success))
                if not success:
                    logger.error(f"Phase '{phase_name}' failed")
            except Exception as e:
                logger.error(f"Phase '{phase_name}' crashed: {e}", exc_info=True)
                results.append((phase_name, False))
        
        # Summary report
        logger.info("\n" + "=" * 60)
        logger.info("PIPELINE EXECUTION SUMMARY")
        logger.info("=" * 60)
        
        all_success = True
        for phase_name, success in results:
            status = "✓ SUCCESS" if success else "✗ FAILED"
            logger.info(f"{phase_name:25} {status}")
            if not success:
                all_success = False
        
        logger.info("\nGenerated databases:")
        for db_file in [self.config['dev_db'], 
                       self.config['runtime_db'], 
                       self.config['catalogue_db'],
                       "patch_intelligence_master.sqlite"]:
            if Path(db_file).exists():
                size = Path(db_file).stat().st_size / 1024
                logger.info(f"  - {db_file:30} ({size:.1f} KB)")
        
        return all_success


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Patch Intelligence Pipeline Orchestrator"
    )
    parser.add_argument(
        "--config",
        help="Path to JSON configuration file"
    )
    parser.add_argument(
        "--skip-patch-collection",
        action="store_true",
        help="Skip patch metadata collection phase"
    )
    parser.add_argument(
        "--only-phase",
        choices=["seed", "ingest", "collect", "unify"],
        help="Run only specific phase"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config:
        import json
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Update config based on arguments
    if args.skip_patch_collection:
        config['enable_patch_collection'] = False
    
    # Create and run pipeline
    pipeline = PatchIntelligencePipeline(config)
    
    if args.only_phase:
        # Run only specific phase
        phases = {
            "seed": pipeline.run_data_seeding,
            "ingest": pipeline.run_catalogue_ingestion,
            "collect": pipeline.run_patch_collection,
            "unify": pipeline.create_unified_view
        }
        
        if args.only_phase in phases:
            success = phases[args.only_phase]()
            sys.exit(0 if success else 1)
        else:
            logger.error(f"Unknown phase: {args.only_phase}")
            sys.exit(1)
    else:
        # Run full pipeline
        success = pipeline.run()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
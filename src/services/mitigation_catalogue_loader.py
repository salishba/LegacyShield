"""
MITIGATION CATALOGUE LOADER - Dynamic Control Catalogue Management

SmartPatch Execution Layer Component
Loads and indexes control catalogues for intelligent remediation

Supports: Application, Authentication, Network, Registry, Services controls
"""

import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class MitigationType(str, Enum):
    """Available mitigation control types matching catalogue structure"""
    APPLICATION = "application"      # APP-01 through APP-04
    AUTHENTICATION = "authentication"  # AUTH-01 through AUTH-04
    NETWORK = "network"              # NET-01 through NET-11
    REGISTRY = "registry"            # REG-01 through REG-06
    SERVICES = "services"            # SVC-01 through SVC-06


class ControlSeverity(str, Enum):
    """Severity of control application"""
    CRITICAL = "critical"      # Must apply immediately
    HIGH = "high"             # Apply in 24-48 hours
    MEDIUM = "medium"         # Apply in 1-2 weeks
    LOW = "low"              # Apply in standard change window


class ControlStatus(str, Enum):
    """Status of control application"""
    AVAILABLE = "available"       # Control available, not yet applied
    PENDING = "pending"          # Scheduled for application
    IN_PROGRESS = "in_progress"  # Currently being applied
    APPLIED = "applied"          # Successfully applied
    FAILED = "failed"            # Application failed
    ROLLED_BACK = "rolled_back"  # Rolled back after failure
    TESTED = "tested"            # Passed validation in test mode


@dataclass
class ControlCommand:
    """Individual command within an enforcement method"""
    command: str
    method_type: str  # PowerShell, DISM, Registry, GPO, etc.
    description: Optional[str] = None
    requires_reboot: bool = False
    requires_admin: bool = True
    os_specific: bool = False


@dataclass
class ValidationCheck:
    """Validation step for control application"""
    check_type: str
    command: str
    success_criteria: str
    reference_command: Optional[str] = None


@dataclass
class ControlDefinition:
    """Complete control definition from catalogue"""
    control_id: str
    name: str
    category: MitigationType
    description: str
    rationale: str
    os_applicability: List[Dict[str, Any]]
    enforcement_methods: List[Dict[str, Any]]
    validation_checks: List[Dict[str, Any]]
    failure_modes: List[str]
    privilege_required: str = "Administrator"
    functional_impact: Optional[str] = None
    operational_impact: Optional[str] = None
    references: Optional[List[str]] = None
    severity: ControlSeverity = ControlSeverity.MEDIUM
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CatalogueIndex:
    """In-memory index for fast control lookup"""
    controls_by_id: Dict[str, ControlDefinition] = field(default_factory=dict)
    controls_by_category: Dict[MitigationType, List[ControlDefinition]] = field(default_factory=dict)
    keywords_index: Dict[str, List[ControlDefinition]] = field(default_factory=dict)
    
    def add_control(self, control: ControlDefinition) -> None:
        """Add control to index"""
        self.controls_by_id[control.control_id] = control
        
        if control.category not in self.controls_by_category:
            self.controls_by_category[control.category] = []
        self.controls_by_category[control.category].append(control)
        
        # Index keywords from name and description
        keywords = set()
        keywords.update(control.name.lower().split())
        keywords.update(control.description.lower().split()[:10])
        
        for keyword in keywords:
            if keyword not in self.keywords_index:
                self.keywords_index[keyword] = []
            self.keywords_index[keyword].append(control)
    
    def find_by_id(self, control_id: str) -> Optional[ControlDefinition]:
        """Find control by ID"""
        return self.controls_by_id.get(control_id)
    
    def find_by_category(self, category: MitigationType) -> List[ControlDefinition]:
        """Find all controls in category"""
        return self.controls_by_category.get(category, [])
    
    def find_by_keyword(self, keyword: str) -> List[ControlDefinition]:
        """Find controls by keyword search"""
        keyword_lower = keyword.lower()
        results = set()
        
        # Exact keyword match
        if keyword_lower in self.keywords_index:
            results.update(self.keywords_index[keyword_lower])
        
        # Substring matches in control names and descriptions
        for control in self.controls_by_id.values():
            if keyword_lower in control.name.lower():
                results.add(control)
            if keyword_lower in control.description.lower():
                results.add(control)
        
        return list(results)
    
    def find_by_os(self, os_name: str) -> List[ControlDefinition]:
        """Find applicable controls for OS"""
        results = []
        for control in self.controls_by_id.values():
            for os_applicability in control.os_applicability:
                if os_applicability.get("supported", False):
                    os_names = os_applicability.get("os_name", "").lower()
                    if os_name.lower() in os_names or "all" in os_names:
                        results.append(control)
                        break
        return results


class MitigationCatalogueLoader:
    """
    Loads control catalogues from JSON files
    Indexes controls for fast lookup and recommendation generation
    
    Supports: Application, Authentication, Network, Registry, Services
    
    Usage:
        loader = MitigationCatalogueLoader(catalogue_dir="src/catalogues")
        loader.load_all_catalogues()
        controls = loader.find_controls_for_cve("CVE-2021-1234")
    """
    
    def __init__(self, catalogue_dir: str = "src/catalogues"):
        """Initialize loader with catalogue directory"""
        self.catalogue_dir = Path(catalogue_dir)
        self.index = CatalogueIndex()
        self.loaded_files: Dict[str, bool] = {}
        
        # Catalogue file mapping
        self.catalogue_files = {
            MitigationType.APPLICATION: "application.json",
            MitigationType.AUTHENTICATION: "authentication.json",
            MitigationType.NETWORK: "network.json",
            MitigationType.REGISTRY: "registry.json",
            MitigationType.SERVICES: "services.json",
        }
    
    def load_all_catalogues(self) -> bool:
        """Load all available catalogues"""
        logger.info("Loading mitigation catalogues from %s", self.catalogue_dir)
        
        all_success = True
        for mitigation_type, filename in self.catalogue_files.items():
            success = self.load_catalogue(mitigation_type, filename)
            self.loaded_files[filename] = success
            all_success = all_success and success
        
        logger.info("Loaded %d controls total from %d catalogues",
                   len(self.index.controls_by_id),
                   sum(1 for v in self.loaded_files.values() if v))
        return all_success
    
    def load_catalogue(self, mitigation_type: MitigationType, filename: str) -> bool:
        """Load specific catalogue file"""
        filepath = self.catalogue_dir / filename
        
        if not filepath.exists():
            logger.warning("Catalogue file not found: %s", filepath)
            return False
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "controls" not in data:
                logger.warning("No 'controls' section in %s", filename)
                return False
            
            for control_data in data["controls"]:
                control = self._parse_control(control_data, mitigation_type)
                if control:
                    self.index.add_control(control)
            
            logger.info("Loaded %d controls from %s", 
                       len(data["controls"]), filename)
            return True
            
        except Exception as e:
            logger.error("Error loading catalogue %s: %s", filename, str(e))
            return False
    
    def _parse_control(self, control_data: Dict[str, Any], 
                      mitigation_type: MitigationType) -> Optional[ControlDefinition]:
        """Parse control from JSON data"""
        try:
            control = ControlDefinition(
                control_id=control_data.get("control_id", ""),
                name=control_data.get("name", ""),
                category=mitigation_type,
                description=control_data.get("description", ""),
                rationale=control_data.get("rationale", ""),
                os_applicability=control_data.get("os_applicability", []),
                enforcement_methods=control_data.get("enforcement_methods", []),
                validation_checks=control_data.get("validation_checks", []),
                failure_modes=control_data.get("failure_modes", []),
                privilege_required=control_data.get("privilege_required", "Administrator"),
                functional_impact=control_data.get("functional_impact"),
                operational_impact=control_data.get("operational_impact"),
                references=control_data.get("references", []),
                raw_data=control_data
            )
            return control
        except Exception as e:
            logger.error("Error parsing control: %s", str(e))
            return None
    
    def find_controls_for_vulnerability(self, cve_id: str, 
                                       vulnerability_components: List[str],
                                       affected_os: str = "Windows 10") -> List[ControlDefinition]:
        """Find applicable controls for a specific vulnerability"""
        applicable_controls = []
        
        # Map vulnerability components to control keywords
        component_keywords = {
            "SMB": [MitigationType.NETWORK],
            "RPC": [MitigationType.NETWORK, MitigationType.SERVICES],
            "PowerShell": [MitigationType.APPLICATION],
            "LM": [MitigationType.AUTHENTICATION],
            "NTLM": [MitigationType.AUTHENTICATION],
            "Registry": [MitigationType.REGISTRY],
            "WinRM": [MitigationType.NETWORK, MitigationType.SERVICES],
            "credential": [MitigationType.AUTHENTICATION],
            "privilege": [MitigationType.AUTHENTICATION],
        }
        
        # Find controls by OS applicability
        os_controls = self.index.find_by_os(affected_os)
        
        # Filter to relevant categories based on vulnerability type
        for component in vulnerability_components:
            if component in component_keywords:
                for category in component_keywords[component]:
                    for control in self.index.find_by_category(category):
                        if control in os_controls and control not in applicable_controls:
                            applicable_controls.append(control)
        
        return applicable_controls
    
    def get_control(self, control_id: str) -> Optional[ControlDefinition]:
        """Get specific control by ID"""
        return self.index.find_by_id(control_id)
    
    def get_controls_by_category(self, category: MitigationType) -> List[ControlDefinition]:
        """Get all controls by category"""
        return self.index.find_by_category(category)
    
    def search_controls(self, query: str) -> List[ControlDefinition]:
        """Search controls by keyword"""
        return self.index.find_by_keyword(query)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get catalogue statistics"""
        return {
            "total_controls": len(self.index.controls_by_id),
            "controls_by_category": {
                cat.value: len(controls)
                for cat, controls in self.index.controls_by_category.items()
            },
            "loaded_files": self.loaded_files,
            "catalogue_directory": str(self.catalogue_dir)
        }


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.DEBUG)
    
    # Initialize loader
    loader = MitigationCatalogueLoader(
        catalogue_dir="src/catalogues"
    )
    
    # Load all catalogues
    if loader.load_all_catalogues():
        print("\n✓ Catalogues loaded successfully")
        
        # Show statistics
        stats = loader.get_statistics()
        print(f"\nCatalogue Statistics:")
        print(f"  Total Controls: {stats['total_controls']}")
        print(f"  By Category:")
        for category, count in stats['controls_by_category'].items():
            print(f"    {category.upper()}: {count}")
        
        # Example: Search for SMB controls
        print("\n--- Searching for SMB controls ---")
        smb_controls = loader.search_controls("SMB")
        for control in smb_controls[:3]:
            print(f"  {control.control_id}: {control.name}")
        
        # Example: Get controls for Windows 10
        print("\n--- Controls for Windows 10 ---")
        win10_controls = loader.index.find_by_os("Windows 10")
        print(f"  Total applicable: {len(win10_controls)}")
        if win10_controls:
            print(f"  Sample: {win10_controls[0].control_id} - {win10_controls[0].name}")
        
        # Example: Get specific control
        print("\n--- Specific Control: NET-01 ---")
        net01 = loader.get_control("NET-01")
        if net01:
            print(f"  Name: {net01.name}")
            print(f"  Category: {net01.category.value}")
            print(f"  Description: {net01.description[:100]}...")
            print(f"  Enforcement Methods: {len(net01.enforcement_methods)}")
            print(f"  Validation Checks: {len(net01.validation_checks)}")
    else:
        print("✗ Failed to load catalogues")
        sys.exit(1)

"""
os_fingerprint.py - OS fingerprinting with caching
Writes runtime/os_metadata.json once, all modules read from it
"""

import json
import os
import sys
import platform
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import hashlib

# Import existing runtime_db for path management
try:
    from runtime_db import RuntimePaths
except ImportError:
    # Fallback if runtime_db not available
    class RuntimePaths:
        BASE_DIR = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData")) / "SmartPatch"
        DB_DIR = BASE_DIR / "runtime"
        
        @staticmethod
        def init_dirs():
            for d in [RuntimePaths.BASE_DIR, RuntimePaths.DB_DIR]:
                d.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)


class OSFingerprinter:
    """
    Comprehensive OS fingerprinting with caching.
    Detects OS metadata once per scan and writes to JSON cache.
    """
    
    def __init__(self):
        self.metadata = {}
        self.cache_file = RuntimePaths.DB_DIR / "os_metadata.json"
        self.cache_ttl = 300  # 5 minutes cache TTL in seconds
        
    def _run_powershell(self, command: str) -> Optional[str]:
        """Run PowerShell command and return output"""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.debug(f"PowerShell command failed: {e}")
        return None
    
    def _get_windows_os_info(self) -> Dict[str, Any]:
        """Get Windows-specific OS information"""
        os_info = {
            "platform": "windows",
            "detection_method": "native"
        }
        
        # Try CIM (modern Windows)
        ps_cim = """
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $props = @{
                Caption = $os.Caption
                Version = $os.Version
                BuildNumber = $os.BuildNumber
                OSArchitecture = $os.OSArchitecture
                CSName = $os.CSName
                TotalVisibleMemorySize = $os.TotalVisibleMemorySize
                FreePhysicalMemory = $os.FreePhysicalMemory
                InstallDate = $os.InstallDate
                LastBootUpTime = $os.LastBootUpTime
                LocalDateTime = $os.LocalDateTime
                NumberOfUsers = $os.NumberOfUsers
                Organization = $os.Organization
                RegisteredUser = $os.RegisteredUser
                ServicePackMajorVersion = $os.ServicePackMajorVersion
                ServicePackMinorVersion = $os.ServicePackMinorVersion
                WindowsDirectory = $os.WindowsDirectory
            }
            $props | ConvertTo-Json -Compress
        }
        """
        
        output = self._run_powershell(ps_cim)
        if output:
            try:
                cim_data = json.loads(output)
                os_info.update(cim_data)
                os_info["detection_method"] = "cim"
                return os_info
            except json.JSONDecodeError:
                pass
        
        # Fallback to WMI (legacy Windows)
        ps_wmi = """
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $props = @{
                Caption = $os.Caption
                Version = $os.Version
                BuildNumber = $os.BuildNumber
                OSArchitecture = if ($os.OSArchitecture) { $os.OSArchitecture } else { (Get-WmiObject Win32_Processor).AddressWidth }
                CSName = $os.CSName
                TotalVisibleMemorySize = $os.TotalVisibleMemorySize
                FreePhysicalMemory = $os.FreePhysicalMemory
                InstallDate = $os.ConvertToDateTime($os.InstallDate)
                LastBootUpTime = $os.ConvertToDateTime($os.LastBootUpTime)
                LocalDateTime = $os.ConvertToDateTime($os.LocalDateTime)
                NumberOfUsers = $os.NumberOfUsers
                Organization = $os.Organization
                RegisteredUser = $os.RegisteredUser
                ServicePackMajorVersion = $os.ServicePackMajorVersion
                ServicePackMinorVersion = $os.ServicePackMinorVersion
                WindowsDirectory = $os.WindowsDirectory
            }
            $props | ConvertTo-Json -Compress
        }
        """
        
        output = self._run_powershell(ps_wmi)
        if output:
            try:
                wmi_data = json.loads(output)
                os_info.update(wmi_data)
                os_info["detection_method"] = "wmi"
                return os_info
            except json.JSONDecodeError:
                pass
        
        # Final fallback to environment variables
        os_info.update({
            "Caption": os.environ.get("OS", "Windows"),
            "Version": platform.version(),
            "BuildNumber": "0",
            "OSArchitecture": os.environ.get("PROCESSOR_ARCHITECTURE", "Unknown"),
            "CSName": os.environ.get("COMPUTERNAME", "Unknown"),
            "detection_method": "environment"
        })
        
        return os_info
    
    def _get_hotfix_info(self) -> List[Dict[str, Any]]:
        """Get installed hotfix information"""
        ps_hotfix = """
        Get-HotFix -ErrorAction SilentlyContinue |
        Select-Object HotFixID, Description, InstalledOn, InstalledBy |
        ConvertTo-Json -Compress
        """
        
        output = self._run_powershell(ps_hotfix)
        if output:
            try:
                hotfixes = json.loads(output)
                if isinstance(hotfixes, dict):
                    return [hotfixes]
                return hotfixes
            except json.JSONDecodeError:
                pass
        return []
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get additional system information"""
        system_info = {}
        
        # Computer system info
        ps_computer = """
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) {
            $props = @{
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
                TotalPhysicalMemory = $cs.TotalPhysicalMemory
                Domain = $cs.Domain
                DomainRole = $cs.DomainRole
                PartOfDomain = $cs.PartOfDomain
                Workgroup = $cs.Workgroup
            }
            $props | ConvertTo-Json -Compress
        }
        """
        
        output = self._run_powershell(ps_computer)
        if output:
            try:
                system_info.update(json.loads(output))
            except json.JSONDecodeError:
                pass
        
        # BIOS info
        ps_bios = """
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bios) {
            $props = @{
                BIOSVersion = $bios.Version
                BIOSSerialNumber = $bios.SerialNumber
                BIOSManufacturer = $bios.Manufacturer
            }
            $props | ConvertTo-Json -Compress
        }
        """
        
        output = self._run_powershell(ps_bios)
        if output:
            try:
                system_info.update(json.loads(output))
            except json.JSONDecodeError:
                pass
        
        return system_info
    
    def _detect_capabilities(self, os_info: Dict[str, Any]) -> Dict[str, bool]:
        """Detect OS capabilities based on build number"""
        capabilities = {
            "cim": False,
            "wmi": False,
            "powershell": False,
            "modern_registry": False,
            "credential_guard": False,
            "applocker": False,
            "bitlocker": False,
            "defender": False,
            "windows_firewall": False
        }
        
        try:
            build = int(os_info.get("BuildNumber", "0"))
        except ValueError:
            build = 0
        
        # Basic capability detection
        capabilities["powershell"] = build >= 7600  # Windows 7+
        capabilities["wmi"] = build >= 2600  # Windows XP+
        capabilities["cim"] = build >= 9200  # Windows 8+
        capabilities["modern_registry"] = build >= 9200
        capabilities["credential_guard"] = build >= 10240  # Windows 10 1507+
        capabilities["applocker"] = build >= 9200  # Windows 8+
        capabilities["bitlocker"] = build >= 7600  # Windows 7+
        capabilities["defender"] = build >= 9200  # Windows 8+
        capabilities["windows_firewall"] = build >= 7600  # Windows 7+
        
        return capabilities
    
    def _calculate_fingerprint_hash(self, metadata: Dict[str, Any]) -> str:
        """Calculate hash of OS fingerprint for change detection"""
        fingerprint_data = {
            "os_caption": metadata.get("os_info", {}).get("Caption", ""),
            "os_version": metadata.get("os_info", {}).get("Version", ""),
            "build_number": metadata.get("os_info", {}).get("BuildNumber", ""),
            "architecture": metadata.get("os_info", {}).get("OSArchitecture", ""),
            "hostname": metadata.get("os_info", {}).get("CSName", ""),
            "hotfix_count": len(metadata.get("hotfixes", []))
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    def collect_os_metadata(self) -> Dict[str, Any]:
        """Collect comprehensive OS metadata"""
        logger.info("Collecting OS fingerprint...")
        
        # OS information
        os_info = self._get_windows_os_info()
        
        # Hotfix information
        hotfixes = self._get_hotfix_info()
        
        # System information
        system_info = self._get_system_info()
        
        # Capabilities
        capabilities = self._detect_capabilities(os_info)
        
        # Compile metadata
        metadata = {
            "timestamp": datetime.utcnow().isoformat(),
            "os_info": os_info,
            "hotfixes": hotfixes,
            "system_info": system_info,
            "capabilities": capabilities,
            "collection_method": os_info.get("detection_method", "unknown")
        }
        
        # Add fingerprint hash
        metadata["fingerprint_hash"] = self._calculate_fingerprint_hash(metadata)
        
        logger.info(f"OS fingerprint collected: {os_info.get('Caption', 'Unknown')} "
                   f"{os_info.get('Version', '')} Build {os_info.get('BuildNumber', '')}")
        
        return metadata
    
    def write_cache(self, metadata: Dict[str, Any]) -> bool:
        """Write OS metadata to cache file"""
        try:
            RuntimePaths.init_dirs()
            
            # Add cache metadata
            metadata["cache_timestamp"] = datetime.utcnow().isoformat()
            metadata["cache_file"] = str(self.cache_file)
            
            # Write to file
            with open(self.cache_file, 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            
            logger.info(f"OS metadata cached to: {self.cache_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to write OS metadata cache: {e}")
            return False
    
    def read_cache(self) -> Optional[Dict[str, Any]]:
        """Read OS metadata from cache file"""
        try:
            if not self.cache_file.exists():
                logger.debug("OS metadata cache file does not exist")
                return None
            
            # Check cache age
            cache_age = datetime.utcnow().timestamp() - self.cache_file.stat().st_mtime
            if cache_age > self.cache_ttl:
                logger.debug(f"OS metadata cache expired (age: {cache_age:.0f}s)")
                return None
            
            with open(self.cache_file, 'r') as f:
                metadata = json.load(f)
            
            logger.debug(f"OS metadata loaded from cache: {self.cache_file}")
            return metadata
        except Exception as e:
            logger.debug(f"Failed to read OS metadata cache: {e}")
            return None
    
    def get_os_metadata(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get OS metadata, using cache if available and valid.
        Set force_refresh=True to bypass cache.
        """
        # Try cache first (unless forced refresh)
        if not force_refresh:
            cached = self.read_cache()
            if cached:
                self.metadata = cached
                return self.metadata
        
        # Collect fresh metadata
        self.metadata = self.collect_os_metadata()
        
        # Write to cache
        self.write_cache(self.metadata)
        
        return self.metadata
    
    def get_metadata_value(self, key: str, default: Any = None) -> Any:
        """Get specific value from OS metadata using dot notation"""
        if not self.metadata:
            self.get_os_metadata()
        
        keys = key.split('.')
        value = self.metadata
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value


# Global singleton instance
_os_fingerprinter = None

def get_os_fingerprinter() -> OSFingerprinter:
    """Get singleton OSFingerprinter instance"""
    global _os_fingerprinter
    if _os_fingerprinter is None:
        _os_fingerprinter = OSFingerprinter()
    return _os_fingerprinter

def get_os_metadata(force_refresh: bool = False) -> Dict[str, Any]:
    """Convenience function to get OS metadata"""
    return get_os_fingerprinter().get_os_metadata(force_refresh)

def get_capabilities() -> Dict[str, bool]:
    """Get OS capabilities from cached metadata"""
    metadata = get_os_metadata()
    return metadata.get("capabilities", {})


if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Collect and display OS metadata
    fingerprinter = OSFingerprinter()
    metadata = fingerprinter.get_os_metadata()
    
    print("OS Metadata:")
    print(json.dumps(metadata, indent=2, default=str))
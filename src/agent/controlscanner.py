#statechecker/scanner.py

import hashlib
import json 
import logging
import tempfile
from typing import Dict, List, Any, Optional, Tuple
import os
import re
import subprocess
import datetime
from dataclasses import dataclass, asdict
from enum import Enum
# statechecker/context_reader.py

import json
from pathlib import Path

def load_runtime_context(context_file: Path) -> dict:
    if not context_file.exists():
        raise FileNotFoundError(f"Runtime context not found: {context_file}")
    with open(context_file, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_os_identity(ctx: dict) -> dict:
    """
    Canonical OS identity used by all scanners.
    """
    system = ctx.get("system", {})
    release = system.get("release", "")
    version = system.get("version", "")

    build = version.split(".")[-1] if "." in version else version

    return {
        "product": f"Windows {release}".strip(),
        "build": build,
        "architecture": system.get("machine")
    }

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Conditional imports for Windows-specific modules
try:
    import win32api
    import win32security
    import win32con
    import winreg
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logger.warning("win32api not available - some features will be disabled")

try:
    from ldap3 import Server, Connection, NTLM, ALL, SUBTREE
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False
    logger.warning("ldap3 not available - AD scanning disabled")

try:
    from packaging.version import parse as parse_version
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False
    logger.warning("packaging library not available - version comparison disabled")


# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStatus(Enum):
    """Compliance check status"""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


@dataclass
class ScanMetadata:
    """Metadata for scan execution"""
    scanner_version: str = "2.0.0"
    scan_id: str = ""
    scanned_at: str = ""
    hostname: str = ""
    os_version: str = ""
    os_build: str = ""
    architecture: str = ""
    scan_user: str = ""
    elevated_privileges: bool = False
    
    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = hashlib.md5(f"{self.hostname}{self.scanned_at}".encode()).hexdigest()
        if not self.scanned_at:
            self.scanned_at = datetime.datetime.utcnow().isoformat()


@dataclass
class SecurityFinding:
    """Represents a single security finding"""
    domain: str
    finding_type: str
    status: str
    risk: str
    description: str
    actual_value: Any = None
    expected_value: Any = None
    remediation_hint: Optional[str] = None
    evidence: Optional[Dict] = None


# ============================================================================
# SECURITY CONFIGURATION BASELINES
# ============================================================================

class SecurityBaselines:
    """
    Centralized security baselines.
    Based on CIS Benchmarks, Microsoft Security Baselines, and NIST guidelines.
    """
    
    # Authentication Domain
    AUTHENTICATION_CHECKS = [
        {
            "path": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "LmCompatibilityLevel",
            "expected": 5,  # NTLMv2 only
            "risk": RiskLevel.HIGH.value,
            "description": "NTLM authentication level - should enforce NTLMv2 only"
        },
        {
            "path": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "NoLMHash",
            "expected": 1,
            "risk": RiskLevel.HIGH.value,
            "description": "Prevent storage of LM hashes"
        },
        {
            "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "value": "CachedLogonsCount",
            "expected": 2,  # Minimal cached credentials
            "risk": RiskLevel.MEDIUM.value,
            "description": "Number of cached domain credentials"
        },
        {
            "path": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "LsaCfgFlags",
            "expected": 1,  # Credential Guard enabled (Win10+)
            "risk": RiskLevel.HIGH.value,
            "description": "Credential Guard status (Windows 10+ only)"
        },
    ]
    
    # Network Exposure Domain
    NETWORK_CHECKS = [
        {
            "path": r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "value": "EnableMulticast",
            "expected": 0,  # Disable LLMNR
            "risk": RiskLevel.HIGH.value,
            "description": "LLMNR protocol state (credential relay attack vector)"
        },
        {
            "path": r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
            "value": "NodeType",
            "expected": 2,  # P-node (disable NBT-NS)
            "risk": RiskLevel.HIGH.value,
            "description": "NetBIOS node type"
        },
    ]
    
    # Code Execution Domain
    CODE_EXECUTION_CHECKS = [
        {
            "path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "value": "EnableScriptBlockLogging",
            "expected": 1,
            "risk": RiskLevel.MEDIUM.value,
            "description": "PowerShell script block logging"
        },
        {
            "path": r"SOFTWARE\Microsoft\Windows Script Host\Settings",
            "value": "Enabled",
            "expected": 0,  # Disable WSH if not needed
            "risk": RiskLevel.MEDIUM.value,
            "description": "Windows Script Host status"
        },
    ]
    
    # Privilege & Access Domain
    PRIVILEGE_CHECKS = [
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "EnableLUA",
            "expected": 1,
            "risk": RiskLevel.CRITICAL.value,
            "description": "UAC enabled"
        },
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "ConsentPromptBehaviorAdmin",
            "expected": 2,  # Prompt for consent on secure desktop
            "risk": RiskLevel.HIGH.value,
            "description": "UAC admin consent behavior"
        },
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "EnableVirtualization",
            "expected": 1,
            "risk": RiskLevel.MEDIUM.value,
            "description": "File and registry virtualization for standard users"
        },
    ]
    
    # Update / Installer Abuse Domain
    UPDATE_CHECKS = [
        {
            "path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "value": "NoAutoUpdate",
            "expected": 0,  # Auto-update enabled
            "risk": RiskLevel.HIGH.value,
            "description": "Windows automatic updates"
        },
        {
            "path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            "value": "DoNotConnectToWindowsUpdateInternetLocations",
            "expected": 0,
            "risk": RiskLevel.MEDIUM.value,
            "description": "Allow connection to Windows Update"
        },
    ]
    
    # Logging & Auditing Domain
    LOGGING_CHECKS = [
        {
            "path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
            "value": "EnableModuleLogging",
            "expected": 1,
            "risk": RiskLevel.MEDIUM.value,
            "description": "PowerShell module logging"
        },
    ]
    
    # High-risk services that should typically be disabled
    RISKY_SERVICES = [
        "RemoteRegistry",
        "TlntSvr",  # Telnet
        "SSDPSRV",  # SSDP Discovery (UPnP)
        "upnphost",  # UPnP Device Host
        "WMPNetworkSvc",  # Windows Media Player Network Sharing
        "SharedAccess",  # Internet Connection Sharing
        "FTPSVC",  # FTP Publishing Service
    ]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def run_powershell_json(ps: str, timeout: int = 30) -> Any:
    """
    Executes PowerShell and returns parsed JSON.
    Returns None on failure.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            logger.debug(f"PowerShell command failed: {result.stderr}")
            return None
        
        output = result.stdout.strip()
        if not output:
            return None
            
        return json.loads(output)
    except subprocess.TimeoutExpired:
        logger.error(f"PowerShell command timed out after {timeout}s")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse PowerShell JSON output: {e}")
        return None
    except Exception as e:
        logger.error(f"PowerShell execution error: {e}")
        return None


def run_cmd(command: str, timeout: int = 30) -> str:
    """
    Executes cmd.exe command and returns output.
    Returns empty string on failure.
    """
    try:
        result = subprocess.run(
            ["cmd", "/c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="ignore"
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        return ""
    except Exception as e:
        logger.error(f"Command execution error: {e}")
        return ""


def read_reg(hive: int, path: str, value: str) -> Optional[Any]:
    """
    Read registry value. Returns None if not found or access denied.
    Requires HAS_WIN32 = True.
    """
    if not HAS_WIN32:
        return None
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        data, reg_type = winreg.QueryValueEx(key, value)
        winreg.CloseKey(key)
        return data
    except FileNotFoundError:
        logger.debug(f"Registry key not found: {path}\\{value}")
        return None
    except PermissionError:
        logger.warning(f"Permission denied reading registry: {path}\\{value}")
        return None
    except Exception as e:
        logger.error(f"Registry read error: {e}")
        return None


def is_admin() -> bool:
    """Check if script is running with elevated privileges"""
    if not HAS_WIN32:
        return False
    try:
        return win32security.CheckTokenMembership(
            None, 
            win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
        )
    except Exception:
        return False


def get_hostname() -> str:
    """Get system hostname"""
    try:
        return os.environ.get("COMPUTERNAME", "UNKNOWN")
    except Exception:
        return "UNKNOWN"


def get_username() -> str:
    """Get current username"""
    try:
        return os.environ.get("USERNAME", "UNKNOWN")
    except Exception:
        return "UNKNOWN"


# ============================================================================
# CORE SCANNER CLASSES
# ============================================================================

class WindowsOSScanner:
    """
    Responsibility:
    - Collect OS facts
    - Detect supported features
    - Decide which modules are allowed to run
    """
    
    def __init__(self):
        self.os_info = {}
        self.features = {}
        self.active_modules = {}

    def scan(self) -> Dict:
        """Execute full OS scan"""
        self.os_info = self.get_os_info()
        self.features = self.detect_os_features(self.os_info)
        self.active_modules = self.activate_modules(self.features)
        
        return {
            "os_info": self.os_info,
            "features": self.features,
            "active_modules": self.active_modules
        }

    def get_os_info(self) -> Dict:
        """Collect OS metadata"""
        ps = r"""
        $o = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue |
             Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime
        if ($o) {
            $o | ConvertTo-Json -Compress
        }
        """
        data = run_powershell_json(ps)
        
        if not data:
            # Fallback to environment variables
            data = {
                "Caption": "Unknown Windows",
                "Version": os.environ.get("OS", "Unknown"),
                "BuildNumber": "0",
                "OSArchitecture": "Unknown"
            }
        
        return data if isinstance(data, dict) else {}

    def detect_os_features(self, os_info: Dict) -> Dict[str, bool]:
        """
        Converts raw OS info into capability flags.
        This is the MOST important abstraction layer.
        """
        features = {
            "cim": False,
            "hotfix": False,
            "powershell": False,
            "legacy_wmi": False,
            "modern_registry": False,
            "credential_guard": False,
            "applocker": False,
        }

        build = int(os_info.get("BuildNumber", "0"))

        # PowerShell exists from Win7+ (build 7600)
        features["powershell"] = build >= 7600

        # CIM exists reliably from Win8 / Server 2012 (build 9200)
        if build >= 9200:
            features["cim"] = True
            features["modern_registry"] = True
        else:
            features["legacy_wmi"] = True

        # Get-HotFix exists everywhere except some XP SKUs
        if build >= 2600:
            features["hotfix"] = True
        
        # Credential Guard - Windows 10 1507+ (build 10240)
        if build >= 10240:
            features["credential_guard"] = True
        
        # AppLocker - Windows 7+ but practical from Win8+
        if build >= 9200:
            features["applocker"] = True

        return features

    def activate_modules(self, features: Dict[str, bool]) -> Dict[str, bool]:
        """
        Decides which scanners are allowed to run.
        This prevents crashes on legacy systems.
        """
        modules = {
            "os_metadata": True,
            "kb_scanner": features["hotfix"],
            "file_scanner": HAS_WIN32,
            "network_scanner": True,
            "registry_scanner": HAS_WIN32,
            "policy_scanner": features["powershell"],
            "service_scanner": True,
            "authentication_scanner": HAS_WIN32,
            "privilege_scanner": features["powershell"],
        }
        return modules

    def collect_installed_kbs(self) -> List[Dict]:
        """
        Collect installed KBs for update recency analysis.
        NOT for CVE-by-CVE mapping.
        """
        ps = r"""
        Get-HotFix -ErrorAction SilentlyContinue |
        Select-Object HotFixID, Description, InstalledOn |
        ConvertTo-Json -Compress
        """
        data = run_powershell_json(ps)

        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return []
    
    def analyze_update_recency(self, kbs: List[Dict]) -> Dict:
        """
        Analyze how recent the system's updates are.
        Returns risk assessment based on update age.
        """
        if not kbs:
            return {
                "status": "NO_UPDATES_DETECTED",
                "risk": RiskLevel.HIGH.value,
                "message": "No updates detected - system may never have been patched"
            }
        
        # Find most recent update
        most_recent = None
        for kb in kbs:
            installed_on = kb.get("InstalledOn")
            if installed_on:
                try:
                    date = datetime.datetime.strptime(str(installed_on), "%m/%d/%Y %H:%M:%S")
                    if most_recent is None or date > most_recent:
                        most_recent = date
                except (ValueError, TypeError):
                    continue
        
        if most_recent is None:
            return {
                "status": "UNKNOWN",
                "risk": RiskLevel.MEDIUM.value,
                "message": "Unable to determine update recency"
            }
        
        days_since_update = (datetime.datetime.now() - most_recent).days
        
        if days_since_update > 365:
            risk = RiskLevel.CRITICAL.value
            status = "SEVERELY_OUTDATED"
        elif days_since_update > 180:
            risk = RiskLevel.HIGH.value
            status = "OUTDATED"
        elif days_since_update > 90:
            risk = RiskLevel.MEDIUM.value
            status = "STALE"
        else:
            risk = RiskLevel.LOW.value
            status = "RECENT"
        
        return {
            "status": status,
            "risk": risk,
            "days_since_last_update": days_since_update,
            "last_update_date": most_recent.isoformat(),
            "total_updates": len(kbs)
        }


class WindowsAuthenticationScanner:
    """
    Scans authentication-related security configurations.
    Domain: Authentication
    """
    
    def __init__(self):
        if not HAS_WIN32:
            raise RuntimeError("win32api required for authentication scanning")
    
    def scan(self) -> List[SecurityFinding]:
        """Execute authentication security scan"""
        findings = []
        
        # Registry-based checks
        for check in SecurityBaselines.AUTHENTICATION_CHECKS:
            finding = self._check_registry_value(check)
            findings.append(finding)
        
        # Local account checks
        findings.extend(self._scan_local_accounts())
        
        # Password policy
        findings.extend(self._scan_password_policy())
        
        return findings
    
    def _check_registry_value(self, check: Dict) -> SecurityFinding:
        """Check a single registry value against baseline"""
        actual = read_reg(winreg.HKEY_LOCAL_MACHINE, check["path"], check["value"])
        
        if actual is None:
            status = ComplianceStatus.UNKNOWN.value
        elif actual == check["expected"]:
            status = ComplianceStatus.COMPLIANT.value
        else:
            status = ComplianceStatus.NON_COMPLIANT.value
        
        return SecurityFinding(
            domain="Authentication",
            finding_type="registry_check",
            status=status,
            risk=check["risk"],
            description=check["description"],
            actual_value=actual,
            expected_value=check["expected"],
            evidence={
                "registry_path": f"HKLM\\{check['path']}",
                "value_name": check["value"]
            }
        )
    
    def _scan_local_accounts(self) -> List[SecurityFinding]:
        """Scan local user accounts for security issues"""
        findings = []
        
        ps = r"""
        Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, PasswordLastSet, PasswordExpires, 
                     PasswordRequired, UserMayChangePassword |
        ConvertTo-Json -Compress
        """
        
        data = run_powershell_json(ps)
        if not data:
            return findings
        
        users = data if isinstance(data, list) else [data]
        
        for user in users:
            name = user.get("Name", "Unknown")
            
            # Check for accounts with passwords that never expire
            password_expires = user.get("PasswordExpires")
            if password_expires is None:
                findings.append(SecurityFinding(
                    domain="Authentication",
                    finding_type="password_policy",
                    status=ComplianceStatus.NON_COMPLIANT.value,
                    risk=RiskLevel.MEDIUM.value,
                    description=f"Local account '{name}' has password that never expires",
                    actual_value="Never expires",
                    expected_value="Should expire",
                    evidence={"user": name}
                ))
            
            # Check password age
            password_last_set = user.get("PasswordLastSet")
            if password_last_set:
                try:
                    last_set = datetime.datetime.fromisoformat(password_last_set.replace("Z", "+00:00"))
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - last_set).days
                    
                    if age_days > 365:
                        findings.append(SecurityFinding(
                            domain="Authentication",
                            finding_type="password_age",
                            status=ComplianceStatus.NON_COMPLIANT.value,
                            risk=RiskLevel.HIGH.value,
                            description=f"Local account '{name}' password is {age_days} days old",
                            actual_value=age_days,
                            expected_value="< 365 days",
                            evidence={"user": name, "password_last_set": password_last_set}
                        ))
                except (ValueError, TypeError):
                    pass
        
        return findings
    
    def _scan_password_policy(self) -> List[SecurityFinding]:
        """Scan local password policy settings"""
        findings = []
        
        ps = r"""
        net accounts | ConvertTo-Json -Compress
        """
        
        output = run_cmd("net accounts")
        
        # Parse minimum password length
        for line in output.splitlines():
            if "Minimum password length" in line:
                match = re.search(r'(\d+)', line)
                if match:
                    min_length = int(match.group(1))
                    if min_length < 14:
                        findings.append(SecurityFinding(
                            domain="Authentication",
                            finding_type="password_policy",
                            status=ComplianceStatus.NON_COMPLIANT.value,
                            risk=RiskLevel.MEDIUM.value,
                            description="Minimum password length is below recommended value",
                            actual_value=min_length,
                            expected_value=14,
                            remediation_hint="Set minimum password length to 14 or higher"
                        ))
        
        return findings


class WindowsNetworkScanner:
    """
    Scans network configuration and exposed services.
    Domain: Network Exposure
    """
    
    def scan(self) -> List[SecurityFinding]:
        """Execute network security scan"""
        findings = []
        
        # Registry-based network checks
        for check in SecurityBaselines.NETWORK_CHECKS:
            finding = self._check_registry_value(check)
            findings.append(finding)
        
        # Service-based checks
        findings.extend(self._check_network_protocols())
        
        # Listening ports analysis
        findings.extend(self._analyze_listening_ports())
        
        # Firewall state
        findings.extend(self._check_firewall_state())
        
        # Network shares
        findings.extend(self._check_network_shares())
        
        return findings
    
    def _check_registry_value(self, check: Dict) -> SecurityFinding:
        """Check a single registry value against baseline"""
        actual = read_reg(winreg.HKEY_LOCAL_MACHINE, check["path"], check["value"])
        
        if actual is None:
            status = ComplianceStatus.UNKNOWN.value
        elif actual == check["expected"]:
            status = ComplianceStatus.COMPLIANT.value
        else:
            status = ComplianceStatus.NON_COMPLIANT.value
        
        return SecurityFinding(
            domain="Network_Exposure",
            finding_type="registry_check",
            status=status,
            risk=check["risk"],
            description=check["description"],
            actual_value=actual,
            expected_value=check["expected"],
            evidence={
                "registry_path": f"HKLM\\{check['path']}",
                "value_name": check["value"]
            }
        )
    
    def _check_network_protocols(self) -> List[SecurityFinding]:
        """Check dangerous network protocols"""
        findings = []
        
        # SMBv1 Check
        smb_status = self._check_smbv1()
        if smb_status["status"] in ["ENABLED", "UNKNOWN"]:
            findings.append(SecurityFinding(
                domain="Network_Exposure",
                finding_type="protocol_check",
                status=ComplianceStatus.NON_COMPLIANT.value,
                risk=RiskLevel.CRITICAL.value,
                description="SMBv1 is enabled or present - vulnerable to EternalBlue and other attacks",
                actual_value=smb_status["status"],
                expected_value="REMOVED or DISABLED",
                evidence=smb_status,
                remediation_hint="Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
            ))
        
        # RDP Check
        rdp_enabled = self._check_rdp()
        if rdp_enabled:
            findings.append(SecurityFinding(
                domain="Network_Exposure",
                finding_type="protocol_check",
                status=ComplianceStatus.NON_COMPLIANT.value,
                risk=RiskLevel.HIGH.value,
                description="RDP is enabled - ensure NLA is enforced and access is restricted",
                actual_value="Enabled",
                expected_value="Disabled or properly secured",
                remediation_hint="If RDP needed, enforce Network Level Authentication"
            ))
        
        return findings
    
    def _check_smbv1(self) -> Dict[str, Any]:
        """Check SMBv1 state with multiple detection methods"""
        # Check registry
        reg_val = self._reg_query(
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1"
        )
        
        # Check if driver exists
        driver_path = os.path.join(
            os.environ.get("SystemRoot", "C:\\Windows"),
            "System32", "drivers", "mrxsmb10.sys"
        )
        driver_exists = os.path.exists(driver_path)
        
        # Check service state
        service_output = run_cmd("sc query LanmanServer")
        service_running = "RUNNING" in service_output

        if reg_val == "0" or reg_val == 0:
            status = "DISABLED"
        elif not driver_exists:
            status = "REMOVED"
        elif reg_val is None and driver_exists:
            status = "ENABLED"  # Default on legacy systems
        else:
            status = "UNKNOWN"

        return {
            "status": status,
            "registry_value": reg_val,
            "driver_present": driver_exists,
            "service_running": service_running
        }
    
    def _check_rdp(self) -> bool:
        """Check if RDP is enabled"""
        val = self._reg_query(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections"
        )
        if val is None:
            return False
        # 0 = RDP enabled, 1 = RDP disabled
        return val == 0
    
    def _reg_query(self, path: str, value: str) -> Optional[Any]:
        """Query registry via Python API"""
        return read_reg(winreg.HKEY_LOCAL_MACHINE, path, value) if HAS_WIN32 else None
    
    def _analyze_listening_ports(self) -> List[SecurityFinding]:
        """Analyze listening ports for security risks"""
        findings = []
        
        output = run_cmd("netstat -ano")
        dangerous_ports = {
            21: ("FTP", RiskLevel.HIGH.value),
            23: ("Telnet", RiskLevel.CRITICAL.value),
            25: ("SMTP", RiskLevel.MEDIUM.value),
            135: ("RPC", RiskLevel.HIGH.value),
            139: ("NetBIOS", RiskLevel.HIGH.value),
            445: ("SMB", RiskLevel.HIGH.value),
            3389: ("RDP", RiskLevel.HIGH.value),
            5985: ("WinRM-HTTP", RiskLevel.MEDIUM.value),
        }
        
        for line in output.splitlines():
            if "LISTENING" in line:
                parts = re.split(r"\s+", line.strip())
                if len(parts) >= 5:
                    local = parts[1]
                    try:
                        ip, port_str = local.rsplit(":", 1)
                        port = int(port_str)
                        
                        if port in dangerous_ports:
                            service_name, risk = dangerous_ports[port]
                            findings.append(SecurityFinding(
                                domain="Network_Exposure",
                                finding_type="listening_port",
                                status=ComplianceStatus.NON_COMPLIANT.value,
                                risk=risk,
                                description=f"{service_name} service listening on port {port}",
                                actual_value=f"{ip}:{port}",
                                expected_value="Not listening or firewalled",
                                evidence={"port": port, "ip": ip, "service": service_name}
                            ))
                    except (ValueError, IndexError):
                        continue
        
        return findings
    
    def _check_firewall_state(self) -> List[SecurityFinding]:
        """Check Windows Firewall state for all profiles"""
        findings = []
        
        ps = r"""
        Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled |
        ConvertTo-Json -Compress
        """
        
        data = run_powershell_json(ps)
        if not data:
            return findings
        
        profiles = data if isinstance(data, list) else [data]
        
        for profile in profiles:
            name = profile.get("Name", "Unknown")
            enabled = profile.get("Enabled", False)
            
            if not enabled:
                findings.append(SecurityFinding)(
                    domain="Network_Exposure",
                    finding_type="firewall_state",
                    status=ComplianceStatus.NON_COMPLIANT.value,
                    risk=RiskLevel.CRITICAL.value)

class WindowsPrivilegeEscalationScanner:
    """
    Domain: Privilege & Access
    Focus: Local privilege escalation primitives
    """

    def scan(self) -> List[SecurityFinding]:
        findings = []

        # AlwaysInstallElevated (HKLM + HKCU)
        for hive, hive_name in [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER, "HKCU")
        ]:
            val = read_reg(
                hive,
                r"SOFTWARE\Policies\Microsoft\Windows\Installer",
                "AlwaysInstallElevated"
            )
            if val == 1:
                findings.append(SecurityFinding(
                    domain="Privilege_Access",
                    finding_type="policy_misconfig",
                    status=ComplianceStatus.NON_COMPLIANT.value,
                    risk=RiskLevel.CRITICAL.value,
                    description="AlwaysInstallElevated is enabled",
                    actual_value=1,
                    expected_value=0,
                    remediation_hint="Disable AlwaysInstallElevated in both HKLM and HKCU",
                    evidence={"hive": hive_name}
                ))

        return findings
class WindowsPersistenceScanner:
    """
    Domain: Persistence
    Focus: Common autorun mechanisms
    """

    RUN_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    ]

    def scan(self) -> List[SecurityFinding]:
        findings = []

        for key_path in self.RUN_KEYS:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
            try:
                i = 0
                while True:
                    name, value, _ = winreg.EnumValue(key, i)
                    findings.append(SecurityFinding(
                        domain="Persistence",
                        finding_type="autorun_entry",
                        status=ComplianceStatus.UNKNOWN.value,
                        risk=RiskLevel.MEDIUM.value,
                        description="Autorun entry detected",
                        actual_value=value,
                        evidence={
                            "location": f"HKLM\\{key_path}",
                            "entry": name
                        }
                    ))
                    i += 1
            except OSError:
                pass

        return findings
class WindowsServiceMisconfigurationScanner:
    """
    Domain: Privilege & Access
    Focus: Unquoted paths & writable service binaries
    """

    def scan(self) -> List[SecurityFinding]:
        findings = []
        output = run_cmd("sc query state= all")

        for line in output.splitlines():
            if "SERVICE_NAME" in line:
                service = line.split(":")[1].strip()
                qc = run_cmd(f"sc qc {service}")

                if "BINARY_PATH_NAME" in qc:
                    path = qc.split("BINARY_PATH_NAME")[1]
                    if " " in path and not path.strip().startswith('"'):
                        findings.append(SecurityFinding(
                            domain="Privilege_Access",
                            finding_type="service_misconfig",
                            status=ComplianceStatus.NON_COMPLIANT.value,
                            risk=RiskLevel.CRITICAL.value,
                            description="Unquoted service binary path",
                            actual_value=path.strip(),
                            expected_value="Quoted path",
                            remediation_hint="Quote service binary paths"
                        ))
        return findings
class WindowsAuditPolicyScanner:
    """
    Domain: Logging & Auditing
    """

    def scan(self) -> List[SecurityFinding]:
        findings = []
        output = run_cmd("auditpol /get /category:*")

        if "No Auditing" in output:
            findings.append(SecurityFinding(
                domain="Logging_Auditing",
                finding_type="audit_policy",
                status=ComplianceStatus.NON_COMPLIANT.value,
                risk=RiskLevel.HIGH.value,
                description="Critical audit categories disabled",
                remediation_hint="Enable advanced audit policy categories"
            ))

        return findings
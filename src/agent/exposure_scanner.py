"""
exposure_scanner.py

Focused module: collects open ports and running services on Windows.
Returns simple dicts; no database writes, no OS info duplication.
"""

import subprocess
import re
import socket
import logging
import winreg
import win32com.client
import json
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger('smartpatch.exposure')


@dataclass
class ExposureData:
    """Pure exposure information"""
    open_ports: List[Dict]   # [{'port': 135, 'protocol': 'TCP', 'process': ...}, ...]
    services: List[Dict]      # [{'name': 'Spooler', 'display_name': ..., 'status': ..., 'start_mode': ...}, ...]
    domain_joined: bool
    domain_name: Optional[str]


class ExposureScanner:
    """Scans Windows for open ports and services only."""

    def __init__(self):
        # No DB connection needed – pure collection
        self.target_services: Set[str] = self._load_target_services()

    def _load_target_services(self) -> Set[str]:
        """Load target service names from service_to_check.json (NO HARDCODING)."""
        services = set()
        try:
            # Find service_to_check.json relative to this module
            config_path = Path(__file__).parent.parent / "catalogues" / "service_to_check.json"
            if not config_path.exists():
                logger.warning(f"service_to_check.json not found at {config_path}")
                return services
            
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract all services where target_type == 'service'
            for item in data:
                if item.get('target_type') == 'service':
                    target_name = item.get('target_name')
                    if target_name:
                        # Handle comma-separated or "or" separated service names
                        # e.g., "MpsSvc; BFE" or "WinDefend or vendor agent"
                        # Split by semicolon or " or " and take first part for exact match
                        service_names = [s.strip() for s in target_name.replace(" or ", ";").split(";")]
                        for svc in service_names:
                            if svc and svc != 'vendor agent':  # Skip explanatory text
                                services.add(svc)
            
            logger.info(f"Loaded {len(services)} target services from service_to_check.json: {sorted(services)}")
            return services
        except Exception as e:
            logger.error(f"Error loading target services from JSON: {e}")
            return services

    def scan(self) -> ExposureData:
        """Collect open ports, services, and domain info."""
        open_ports = self._scan_open_ports()
        services = self._scan_services()
        domain_info = self._get_domain_info()
        return ExposureData(
            open_ports=open_ports,
            services=services,
            domain_joined=domain_info['joined'],
            domain_name=domain_info['name']
        )

    def _get_domain_info(self) -> Dict:
        """Determine if system is domain-joined and get domain name."""
        try:
            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
            comp = wmi.ExecQuery("SELECT * FROM Win32_ComputerSystem")[0]
            domain = comp.Domain
            joined = bool(domain and domain != 'WORKGROUP')
            return {'joined': joined, 'name': domain if joined else None}
        except:
            # Fallback: check registry
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
                domain, _ = winreg.QueryValueEx(key, 'Domain')
                winreg.CloseKey(key)
                joined = bool(domain)
                return {'joined': joined, 'name': domain if joined else None}
            except:
                return {'joined': False, 'name': None}

    def _scan_open_ports(self) -> List[Dict]:
        """Get listening ports using netstat."""
        ports = []
        try:
            output = subprocess.check_output(['netstat', '-an'], universal_newlines=True)
            lines = output.splitlines()
            pattern = re.compile(r'^\s*(TCP|UDP)\s+[\d\.]+:(\d+)\s+.*?(LISTENING|\*:\*)', re.IGNORECASE)
            for line in lines:
                match = pattern.search(line)
                if match:
                    proto = match.group(1).upper()
                    port = int(match.group(2))
                    # Try to get process name for TCP ports (admin rights may be needed)
                    process = self._get_process_for_port(port) if proto == 'TCP' else None
                    ports.append({
                        'port': port,
                        'protocol': proto,
                        'process': process
                    })
        except Exception as e:
            logger.error(f"netstat failed: {e}")
        return ports

    def _get_process_for_port(self, port: int) -> Optional[str]:
        """Get process name owning a TCP port (requires netstat -ano + tasklist)."""
        try:
            output = subprocess.check_output(['netstat', '-ano'], universal_newlines=True)
            lines = output.splitlines()
            pattern = re.compile(rf'^\s*TCP\s+[\d\.]+:{port}\s+.*?(\d+)\s*$', re.IGNORECASE)
            for line in lines:
                match = pattern.search(line)
                if match:
                    pid = match.group(1)
                    proc = subprocess.check_output(['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV'],
                                                   universal_newlines=True)
                    import csv
                    reader = csv.reader(proc.splitlines())
                    rows = list(reader)
                    if len(rows) >= 2:
                        return rows[1][0]  # Image Name
            return None
        except:
            return None

    def _scan_services(self) -> List[Dict]:
        """Get services with name, display name, status, start mode (WMI preferred, fallback sc).
        Only scans for services mentioned in service_to_check.json (NO SCAN ALL)."""
        services = []
        
        # If no target services defined, return empty (security-first approach)
        if not self.target_services:
            logger.warning("No target services defined from service_to_check.json")
            return services
        
        # Try WMI first
        try:
            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
            svc_list = wmi.ExecQuery("SELECT Name, DisplayName, State, StartMode FROM Win32_Service")
            for svc in svc_list:
                # Only include services that match target services
                if self._matches_target_service(svc.Name):
                    services.append({
                        'name': svc.Name,
                        'display_name': svc.DisplayName,
                        'status': svc.State,
                        'start_mode': svc.StartMode
                    })
            
            if services:
                logger.info(f"WMI retrieved {len(services)} target services")
                return services
        except Exception as e:
            logger.warning(f"WMI services failed: {e}")
        
        # Fallback: sc query (simplified – no start mode, only target services)
        try:
            output = subprocess.check_output(['sc', 'query', 'state=', 'all'], universal_newlines=True)
            svc_name = None
            disp_name = None
            state = None
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    svc_name = line.split(':', 1)[1].strip()
                elif line.startswith('DISPLAY_NAME:'):
                    disp_name = line.split(':', 1)[1].strip()
                elif line.startswith('STATE'):
                    parts = line.split()
                    if len(parts) >= 3:
                        state = parts[2]
                elif line == '' and svc_name and state:
                    # Only include services that match target services
                    if self._matches_target_service(svc_name):
                        services.append({
                            'name': svc_name,
                            'display_name': disp_name or svc_name,
                            'status': state,
                            'start_mode': 'Unknown'
                        })
                    svc_name = disp_name = state = None
            
            if services:
                logger.info(f"sc query retrieved {len(services)} target services")
            return services
        except Exception as e2:
            logger.error(f"sc query failed: {e2}")
            return []

    def _matches_target_service(self, service_name: str) -> bool:
        """Check if a service name matches any of the target services (case-insensitive)."""
        service_name_lower = service_name.lower()
        for target in self.target_services:
            if service_name_lower == target.lower():
                return True
        return False
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
from typing import List, Dict, Optional
from dataclasses import dataclass

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
        pass

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
        """Get services with name, display name, status, start mode (WMI preferred, fallback sc)."""
        services = []
        # Try WMI first
        try:
            wmi = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
            svc_list = wmi.ExecQuery("SELECT Name, DisplayName, State, StartMode FROM Win32_Service")
            for svc in svc_list:
                services.append({
                    'name': svc.Name,
                    'display_name': svc.DisplayName,
                    'status': svc.State,
                    'start_mode': svc.StartMode
                })
            return services
        except Exception as e:
            logger.warning(f"WMI services failed: {e}")
            # Fallback: sc query (simplified – no start mode)
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
                        services.append({
                            'name': svc_name,
                            'display_name': disp_name or svc_name,
                            'status': state,
                            'start_mode': 'Unknown'
                        })
                        svc_name = disp_name = state = None
                return services
            except Exception as e2:
                logger.error(f"sc query failed: {e2}")
                return []
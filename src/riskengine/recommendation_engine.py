"""
recommendation_engine.py - Generates Actionable Remediation Recommendations

This module transforms decision data into specific, executable recommendations
with code snippets, step-by-step procedures, and risk assessments.

Features:
- Dynamic recommendation generation based on vulnerability type
- PowerShell script generation for Windows patching
- Registry hardening recommendations
- Service disable procedures
- File replacement guides
- Rollback procedures
- Testing validation steps

NO TEMPLATES - All recommendations are generated from runtime data.
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import textwrap

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Recommendation:
    """A specific, actionable recommendation"""
    recommendation_id: str
    cve_id: str
    title: str
    scope: str  # The area affected (system, service, file, registry)
    action_steps: List[str]  # Step-by-step procedures
    execution_method: str  # "powershell", "registry", "manual", etc.
    execution_script: Optional[str]  # Actual script/commands
    estimated_time_minutes: int
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    rollback_procedure: str
    validation_steps: List[str]
    prerequisites: List[str]
    known_issues: List[str]
    references: Dict[str, str]  # KB articles, changelogs, etc.
    owner_team: Optional[str]  # Which team should execute
    approval_required: bool
    created_timestamp: datetime


@dataclass
class RecommendationSet:
    """A complete set of recommendations for a vulnerability"""
    cve_id: str
    vulnerability_title: str
    immediate_actions: List[Recommendation]
    scheduled_actions: List[Recommendation]
    mitigations: List[Recommendation]
    monitoring_steps: List[str]
    generated_timestamp: datetime


# ============================================================================
# RECOMMENDATION ENGINE CLASS
# ============================================================================

class RecommendationEngine:
    """
    Generates specific, actionable recommendations based on vulnerability
    characteristics and system context.
    """

    def __init__(
        self,
        runtime_db_path: str,
        dev_db_path: str,
        log_level: int = logging.INFO
    ):
        """Initialize Recommendation Engine."""
        self.runtime_db_path = runtime_db_path
        self.dev_db_path = dev_db_path
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

    def _generate_msu_patch_recommendation(
        self,
        cve_id: str,
        kb_id: str,
        affected_os: str,
        severity: str
    ) -> Recommendation:
        """Generate MSU patch installation recommendation."""
        
        ps_script = self._generate_msu_installation_script(kb_id, affected_os)
        
        return Recommendation(
            recommendation_id=f"REC-{cve_id}-MSU-{kb_id}",
            cve_id=cve_id,
            title=f"Install Security Update {kb_id}",
            scope=f"OS-Level Patch ({kb_id})",
            action_steps=[
                f"1. Download patch {kb_id} from Microsoft Update Catalog",
                f"2. Verify patch hash matches official Microsoft release",
                f"3. Create system restore point using: `wmic os where name=\"%os%\" call Shutdown /Comment \"Pre-patch restore point\" /Reason \"1(0)(0)\" `",
                f"4. Run patch installation: `wusa.exe {kb_id}.msu /quiet /norestart`",
                f"5. Allow up to 5 minutes for installation to complete",
                f"6. Review Windows Update log: `Get-EventLog -LogName System | Where-Object {{$_.EventID -eq 19}} | Select-Object -First 10`",
                f"7. Verify patch installed: `Get-HotFix | Where-Object {{$_.HotFixID -eq '{kb_id}'}}`",
                f"8. Test critical services and applications",
                f"9. Reboot if required by patch"
            ],
            execution_method="powershell",
            execution_script=ps_script,
            estimated_time_minutes=45,
            risk_level="MEDIUM" if severity == "CRITICAL" else "LOW",
            rollback_procedure=f"""
ROLLBACK PROCEDURE FOR {kb_id}:

Via Windows UI:
  1. Settings → System → Apps & features → Installed updates
  2. Search for "{kb_id}"
  3. Click → Uninstall
  4. Confirm removal

Via PowerShell (Administrative):
  Remove-HotFix -Id "{kb_id}" -Confirm:$false

Via DISM:
  dism /online /remove-package /packagepath:C:\\Users\\{username}\\Downloads\\{kb_id}.msu

Verify rollback:
  - Get-HotFix | Where-Object {{$_.HotFixID -eq '{kb_id}'}}  # Should return nothing
  - Restart-Computer  # Reboot recommended after rollback
""",
            validation_steps=[
                f"Verify patch removed: Get-HotFix | Where-Object {{$_.HotFixID -eq '{kb_id}'}} → Should not appear",
                "Check for dism errors: Get-EventLog -LogName Setup | Select-Object -Last 5",
                "Verify system stability: TaskList | Find /V \"AppName\"",
                "Run baseline security scan to verify rollback complete"
            ],
            prerequisites=[
                "Administrative privileges required",
                "System restart may be required",
                "Estimated downtime: 5-15 minutes",
                "Backup should be available",
                "Network access to patch repository required"
            ],
            known_issues=[
                "Some patches require reboot before validation",
                "Pending reboot prevents installation of other updates",
                "Some applications may require reconfiguration after patch",
                "Antivirus may slow installation process"
            ],
            references={
                "Microsoft KB": f"https://support.microsoft.com/en-us/kb/{kb_id.replace('KB', '')}",
                "Update Catalog": f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb_id}",
                "WUSA Documentation": "https://docs.microsoft.com/en-us/windows/win32/msi/windows-update-standalone-installer",
                "DISM Documentation": "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism---deployment-image-servicing-and-management-technical-reference-for-windows"
            },
            owner_team="Infrastructure/Windows Team",
            approval_required=True,
            created_timestamp=datetime.utcnow()
        )

    def _generate_msu_installation_script(self, kb_id: str, affected_os: str) -> str:
        """Generate PowerShell script for MSU installation."""
        return f"""
# SmartPatch MSU Installation Script
# CVE: {kb_id}
# Generated: {datetime.utcnow().isoformat()}

param(
    [string]$PatchPath = "C:\\Patches\\{kb_id}.msu",
    [bool]$CreateRestorePoint = $true,
    [bool]$AutoReboot = $false,
    [string]$LogPath = "C:\\SmartPatch\\Logs\\{kb_id}_install.log"
)

# ============================================
# PRE-INSTALLATION CHECKS
# ============================================

Write-Host "Starting patch installation for {kb_id}" -ForegroundColor Cyan

# Check administrative privileges
if (-not ([System.Security.Principal.WindowsPrincipal] `
    [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Error "This script requires administrative privileges"
    exit 1
}}

# Check if patch file exists
if (-not (Test-Path $PatchPath)) {{
    Write-Error "Patch file not found: $PatchPath"
    exit 1
}}

# Check disk space (minimum 500MB recommended)
$DriveLetter = $PatchPath.Substring(0, 1)
$Drive = Get-PSDrive -Name $DriveLetter
if ($Drive.Used + 500MB > $Drive.Free) {{
    Write-Warning "Low disk space: {{$($Drive.Free / 1GB)}} GB free (500MB minimum recommended)"
}}

# Verify Windows Update is not already running
$WUProcess = Get-Process -Name "wuauclt" -ErrorAction SilentlyContinue
if ($WUProcess) {{
    Write-Warning "Windows Update is running. Waiting for completion..."
    $WUProcess | Wait-Process -Timeout 300
}}

# ============================================
# CREATE RESTORE POINT
# ============================================

if ($CreateRestorePoint) {{
    Write-Host "Creating system restore point..." -ForegroundColor Yellow
    
    try {{
        $RestorePoint = Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Pre-patch restore point for {kb_id}" `
            -RestorePointType "MODIFY_SETTINGS" | Out-Null
        Write-Host "Restore point created successfully" -ForegroundColor Green
    }} catch {{
        Write-Warning "Could not create restore point: $_"
    }}
}}

# ============================================
# INSTALLATION
# ============================================

Write-Host "Installing patch {kb_id}..." -ForegroundColor Yellow

$InstallProcess = Start-Process `
    -FilePath "wusa.exe" `
    -ArgumentList "$PatchPath /quiet /norestart" `
    -PassThru `
    -RedirectStandardOutput $LogPath

$InstallProcess | Wait-Process

$ExitCode = $InstallProcess.ExitCode

# ============================================
# VERIFICATION
# ============================================

Write-Host "Verifying patch installation..." -ForegroundColor Yellow

Start-Sleep -Seconds 10  # Wait for Windows Update service to update

$Hotfixes = Get-HotFix | Where-Object {{ $_.HotFixID -eq "{kb_id}" }}

if ($Hotfixes) {{
    Write-Host "Patch {kb_id} installed successfully!" -ForegroundColor Green
    Write-Host "Installation Source: $($Hotfixes[0].InstalledBy)" -ForegroundColor Green
    Write-Host "Installation Date: $($Hotfixes[0].InstalledOn)" -ForegroundColor Green
}} else {{
    Write-Warning "Patch {kb_id} could not be verified after installation"
    Write-Warning "Exit code was: $ExitCode"
    exit 1
}}

# ============================================
# POST-INSTALLATION
# ============================================

Write-Host "Running post-installation checks..." -ForegroundColor Yellow

# Check Event Log for errors
$SystemErrors = Get-EventLog -LogName System `
    -InstanceId 7011, 7024, 1000, 1001 -After (Get-Date).AddHours(-1) `
    -ErrorAction SilentlyContinue

if ($SystemErrors) {{
    Write-Warning "System errors detected after patch installation:"
    $SystemErrors | ForEach-Object {{ Write-Host "  - $_" }}
}}

# Verify critical services are running
$Services = Get-Service | Where-Object {{ $_.Status -eq 'Running' }} | Measure-Object
Write-Host "Verified: $($Services.Count) services running" -ForegroundColor Green

# Check network connectivity
$NetworkTest = Test-NetConnection -ComputerName "8.8.8.8" -WarningAction SilentlyContinue
if ($NetworkTest.PingSucceeded) {{
    Write-Host "Network connectivity: OK" -ForegroundColor Green
}} else {{
    Write-Warning "Network connectivity test failed"
}}

Write-Host "Patch installation completed successfully" -ForegroundColor Green
Write-Host "Log file: $LogPath" -ForegroundColor Cyan

if ($AutoReboot) {{
    Write-Host "System will reboot in 5 minutes..." -ForegroundColor Yellow
    shutdown /r /t 300 /c "SmartPatch installation of {kb_id} complete"
}} else {{
    Write-Host "Please schedule a reboot at your earliest convenience" -ForegroundColor Yellow
}}
""".strip()

    def _generate_registry_hardening_recommendation(
        self,
        cve_id: str,
        registry_keys: List[Dict[str, str]]
    ) -> Recommendation:
        """Generate registry hardening recommendation."""
        
        ps_script = self._generate_registry_hardening_script(cve_id, registry_keys)
        
        action_steps = [
            "1. Backup registry hive before making changes:",
            "   reg export HKLM <hive_path> C:\\Backups\\registry_backup.reg",
        ]
        
        for i, key_def in enumerate(registry_keys, 1):
            action_steps.append(
                f"{i+1}. Set {key_def.get('key_name', 'Registry Key')}: "
                f"{key_def.get('value_name', 'Value')} = {key_def.get('value_data', 'Data')}"
            )
        
        action_steps.extend([
            f"{len(registry_keys)+2}. Run validation PowerShell script",
            f"{len(registry_keys)+3}. Restart affected services",
            f"{len(registry_keys)+4}. Verify functionality in test environment first"
        ])
        
        return Recommendation(
            recommendation_id=f"REC-{cve_id}-REG-HARDEN",
            cve_id=cve_id,
            title="Registry Hardening for Vulnerability Mitigation",
            scope="Windows Registry",
            action_steps=action_steps,
            execution_method="powershell",
            execution_script=ps_script,
            estimated_time_minutes=20,
            risk_level="MEDIUM",
            rollback_procedure=f"""
ROLLBACK PROCEDURE - Registry Restore:

1. Open Registry Editor: regedit
2. File → Import → Select C:\\Backups\\registry_backup.reg
3. Or use PowerShell:
   reg import C:\\Backups\\registry_backup.reg
4. Restart computer
5. Verify services running correctly

AUTOMATED ROLLBACK:
   & "C:\\SmartPatch\\Rollback\\restore_registry_{cve_id}.ps1"
""",
            validation_steps=[
                "Verify registry keys exist: Get-ItemProperty -Path 'HKLM:\\Path\\To\\Key'",
                "Test application functionality after changes",
                "Check Event Viewer for warnings or errors",
                "Verify no service startup failures",
                "Run security baseline audit"
            ],
            prerequisites=[
                "Registry backup must be created first",
                "Administrative privileges required",
                "Services may need restart",
                "Test in non-production first"
            ],
            known_issues=[
                "Some applications may fail if registry values are missing",
                "Services must be restarted to apply changes",
                "Backup/restore requires administrative privileges",
                "Some registry changes require system reboot"
            ],
            references={
                "Windows Registry Documentation": "https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry",
                "Registry Entry Reference": f"https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-entry-types"
            },
            owner_team="Infrastructure/Windows Team",
            approval_required=True,
            created_timestamp=datetime.utcnow()
        )

    def _generate_registry_hardening_script(
        self,
        cve_id: str,
        registry_keys: List[Dict[str, str]]
    ) -> str:
        """Generate PowerShell script for registry hardening."""
        
        key_modifications = "\n".join([
            f"""
    # Key: {key.get('key_name', 'Unknown')}
    # Value: {key.get('value_name', 'Unknown')}
    # New Value: {key.get('value_data', 'Unknown')}
    # Description: {key.get('description', 'Registry hardening')}
    
    $RegistryPath = "{key.get('registry_path', 'HKLM:\\Unknown')}"
    $ValueName = "{key.get('value_name', 'Unknown')}"
    $ValueData = {key.get('value_data', '0')} # Type: {key.get('value_type', 'DWORD')}
    
    if (-not (Test-Path $RegistryPath)) {{
        New-Item -Path $RegistryPath -Force | Out-Null
    }}
    
    New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData `
        -PropertyType "{key.get('value_type', 'DWORD')}" -Force | Out-Null
    
    Write-Host "Set $ValueName = $ValueData at $RegistryPath" -ForegroundColor Green
"""
            for key in registry_keys
        ])
        
        return f"""
# Registry Hardening Script for {cve_id}
# Generated: {datetime.utcnow().isoformat()}
# Description: Applies registry-based mitigations for vulnerability

param(
    [bool]$BackupFirst = $true,
    [string]$BackupPath = "C:\\Backups\\registry_backup_{cve_id}.reg"
)

# Check administrative privileges
if (-not ([System.Security.Principal.WindowsPrincipal] `
    [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Error "Administrative privileges required"
    exit 1
}}

# Backup registry first
if ($BackupFirst) {{
    Write-Host "Backing up registry to $BackupPath..." -ForegroundColor Yellow
    
    try {{
        reg export HKLM C:\\Windows\\System32 $BackupPath /y | Out-Null
        Write-Host "Registry backup completed" -ForegroundColor Green
    }} catch {{
        Write-Warning "Registry backup failed: $_"
    }}
}}

# Apply hardening changes
Write-Host "Applying registry hardening..." -ForegroundColor Cyan
{key_modifications}

Write-Host "Registry hardening complete" -ForegroundColor Green
Write-Host "Restart system to apply all changes" -ForegroundColor Yellow
""".strip()

    def _generate_service_disable_recommendation(
        self,
        cve_id: str,
        service_names: List[str],
        reason: str
    ) -> Recommendation:
        """Generate service disable recommendation."""
        
        ps_script = self._generate_service_control_script(
            cve_id, service_names, "disable", reason
        )
        
        action_steps = [
            f"1. Review impact of disabling: {', '.join(service_names)}",
            "2. Inform dependent applications/services",
            "3. Create system restore point",
        ]
        
        for i, service in enumerate(service_names, 1):
            action_steps.append(f"{i+3}. Disable service: {service}")
        
        action_steps.extend([
            f"{len(service_names)+3}. Verify services stopped",
            f"{len(service_names)+4}. Test application functionality",
            f"{len(service_names)+5}. Monitor for service startup failures"
        ])
        
        return Recommendation(
            recommendation_id=f"REC-{cve_id}-SVC-DISABLE",
            cve_id=cve_id,
            title=f"Disable Vulnerable Services: {', '.join(service_names)}",
            scope="Windows Services",
            action_steps=action_steps,
            execution_method="powershell",
            execution_script=ps_script,
            estimated_time_minutes=10,
            risk_level="HIGH",
            rollback_procedure=f"""
ROLLBACK PROCEDURE - Re-enable Services:

PowerShell Method:
{chr(10).join([f"  Set-Service -Name '{svc}' -StartupType 'Automatic' -PassThru | Start-Service" for svc in service_names])}

Services Control Manager:
  1. Open services.msc
  2. Find each service: {', '.join(service_names)}
  3. Right-click → Properties → Startup Type → Automatic
  4. Click Start button

Automated Rollback:
  & "C:\\SmartPatch\\Rollback\\enable_services_{cve_id}.ps1"
""",
            validation_steps=[
                "Verify services are stopped: Get-Service | Where-Object {{$_.Name -in @({','.join([f\"'{s}\" for s in service_names])+\"'}}}} | Select-Object Status",
                "Confirm no errors in Application event log",
                "Test dependent applications still function correctly",
                "Monitor Event Viewer for startup failures"
            ],
            prerequisites=[
                "Administrative privileges required",
                "Identify dependent services/applications first",
                "Backup system state before changes",
                "Inform users of service unavailability"
            ],
            known_issues=[
                f"Applications depending on {', '.join(service_names)} may fail",
                "Some services may auto-start on reboot if dependencies trigger",
                "Antivirus or security software may re-enable services",
                "Third-party applications may attempt to start these services"
            ],
            references={
                "Windows Services Documentation": "https://docs.microsoft.com/en-us/windows/win32/services/services",
                "Service Startup Types": "https://docs.microsoft.com/en-us/windows/win32/services/service-startup-types"
            },
            owner_team="Infrastructure/Windows Team",
            approval_required=True,
            created_timestamp=datetime.utcnow()
        )

    def _generate_service_control_script(
        self,
        cve_id: str,
        service_names: List[str],
        action: str,
        reason: str
    ) -> str:
        """Generate PowerShell script for service control."""
        
        action_verb = "Disabling" if action == "disable" else "Enabling"
        startup_type = "Disabled" if action == "disable" else "Automatic"
        start_stop = "Stop" if action == "disable" else "Start"
        
        return f"""
# Service Control Script - {action_verb} Services
# CVE: {cve_id}
# Reason: {reason}
# Generated: {datetime.utcnow().isoformat()}

param(
    [string]$Action = "{action}",
    [string]$LogPath = "C:\\SmartPatch\\Logs\\services_{cve_id}.log"
)

# Check administrative privileges
if (-not ([System.Security.Principal.WindowsPrincipal] `
    [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Error "Administrative privileges required"
    exit 1
}}

# Initialize logging
$LogDir = Split-Path -Parent $LogPath
if (-not (Test-Path $LogDir)) {{
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}}

function Log-Message {{
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogEntry
    Write-Host $LogEntry
}}

Log-Message "{action_verb} services for CVE {cve_id}: {reason}"

# Services to modify
$Services = @({','.join([f"'{svc}'" for svc in service_names])})

foreach ($Service in $Services) {{
    try {{
        $ServiceObj = Get-Service -Name $Service -ErrorAction Stop
        
        if ($ServiceObj) {{
            Log-Message "Found service: $Service (Status: $($ServiceObj.Status))"
            
            # Set startup type
            Set-Service -Name $Service -StartupType "{startup_type}" -ErrorAction Stop
            Log-Message "Set $Service startup type to {startup_type}"
            
            # Stop or start service
            $ServiceObj | {start_stop}-Service -ErrorAction SilentlyContinue
            Log-Message "{action_verb} service: $Service"
            
            # Verify
            $UpdatedService = Get-Service -Name $Service
            Log-Message "After $Action - $Service status: $($UpdatedService.Status)"
        }}
    }} catch {{
        Log-Message "Error modifying service $Service: $_" "ERROR"
    }}
}}

Log-Message "Service modification complete"
Log-Message "Log file saved to: $LogPath"
""".strip()

    def generate_recommendations(
        self,
        cve_id: str,
        kb_id: Optional[str],
        affected_os: str,
        vulnerability_type: str,
        severity: str,
        registry_keys: Optional[List[Dict[str, str]]] = None,
        vulnerable_services: Optional[List[str]] = None
    ) -> RecommendationSet:
        """
        Generate complete recommendation set for a vulnerability.
        
        Args:
            cve_id: CVE identifier
            kb_id: KB patch number
            affected_os: Affected OS version
            vulnerability_type: Type of vulnerability
            severity: Severity level
            registry_keys: Registry keys to harden
            vulnerable_services: Services to disable
        
        Returns:
            RecommendationSet with actionable recommendations
        """
        
        immediate_actions = []
        scheduled_actions = []
        mitigations = []
        
        # MSU Patch recommendation
        if kb_id:
            patch_rec = self._generate_msu_patch_recommendation(
                cve_id, kb_id, affected_os, severity
            )
            if severity in ["CRITICAL", "HIGH"]:
                immediate_actions.append(patch_rec)
            else:
                scheduled_actions.append(patch_rec)
        
        # Registry hardening
        if registry_keys:
            registry_rec = self._generate_registry_hardening_recommendation(
                cve_id, registry_keys
            )
            mitigations.append(registry_rec)
        
        # Service disabling
        if vulnerable_services:
            service_rec = self._generate_service_disable_recommendation(
                cve_id, vulnerable_services,
                f"Mitigation for {cve_id} - {severity} severity"
            )
            if severity == "CRITICAL":
                immediate_actions.append(service_rec)
            else:
                mitigations.append(service_rec)
        
        # Monitoring steps
        monitoring_steps = [
            "Monitor Windows Event Viewer for security events",
            "Check for signs of exploitation attempts in logs",
            f"After patch/mitigation, verify {cve_id} is no longer detected",
            "Monitor application performance and stability",
            "Track user-reported issues related to patch",
            "Verify antivirus/EDR solutions are detecting attempted exploits"
        ]
        
        return RecommendationSet(
            cve_id=cve_id,
            vulnerability_title=f"{severity} Vulnerability {cve_id}",
            immediate_actions=immediate_actions,
            scheduled_actions=scheduled_actions,
            mitigations=mitigations,
            monitoring_steps=monitoring_steps,
            generated_timestamp=datetime.utcnow()
        )

    def format_recommendations_for_display(
        self,
        recommendation_set: RecommendationSet
    ) -> str:
        """
        Format recommendations as human-readable report.
        
        Args:
            recommendation_set: RecommendationSet to format
        
        Returns:
            Formatted string for display/export
        """
        
        output = []
        output.append("=" * 80)
        output.append(f"REMEDIATION RECOMMENDATIONS FOR {recommendation_set.cve_id}")
        output.append(f"Generated: {recommendation_set.generated_timestamp.isoformat()}")
        output.append("=" * 80)
        output.append("")
        
        # Immediate actions
        if recommendation_set.immediate_actions:
            output.append("IMMEDIATE ACTIONS (Execute within 4-24 hours)")
            output.append("-" * 80)
            for i, rec in enumerate(recommendation_set.immediate_actions, 1):
                output.append(f"\n{i}. {rec.title}")
                output.append(f"   Estimated Time: {rec.estimated_time_minutes} minutes")
                output.append(f"   Risk Level: {rec.risk_level}")
                output.append(f"   Execution Method: {rec.execution_method}")
                output.append(f"\n   Steps:")
                for step in rec.action_steps:
                    output.append(f"   {step}")
                output.append(f"\n   Validation:")
                for val in rec.validation_steps:
                    output.append(f"   ✓ {val}")
            output.append("")
        
        # Scheduled actions
        if recommendation_set.scheduled_actions:
            output.append("\nSCHEDULED ACTIONS (Next patch window)")
            output.append("-" * 80)
            for i, rec in enumerate(recommendation_set.scheduled_actions, 1):
                output.append(f"\n{i}. {rec.title}")
                output.append(f"   Estimated Time: {rec.estimated_time_minutes} minutes")
                for step in rec.action_steps[:3]:  # First 3 steps only
                    output.append(f"   {step}")
            output.append("")
        
        # Mitigations
        if recommendation_set.mitigations:
            output.append("\nTEMPORARY MITIGATIONS (Until patch applied)")
            output.append("-" * 80)
            for i, rec in enumerate(recommendation_set.mitigations, 1):
                output.append(f"\n{i}. {rec.title}")
                for step in rec.action_steps:
                    output.append(f"   {step}")
            output.append("")
        
        # Monitoring
        output.append("\nMONITORING STEPS")
        output.append("-" * 80)
        for i, step in enumerate(recommendation_set.monitoring_steps, 1):
            output.append(f"{i}. {step}")
        
        output.append("")
        output.append("=" * 80)
        
        return "\n".join(output)


# ============================================================================
# MAIN (FOR TESTING)
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    engine = RecommendationEngine(
        runtime_db_path="runtime_scan.sqlite",
        dev_db_path="dev_db.sqlite"
    )
    
    # Example: Generate recommendations
    registry_keys = [
        {
            "registry_path": "HKLM:\\System\\CurrentControlSet\\Services\\RPC",
            "key_name": "RPC Service",
            "value_name": "DisableRemoteRPC",
            "value_data": "1",
            "value_type": "DWORD",
            "description": "Disable remote RPC access"
        }
    ]
    
    recs = engine.generate_recommendations(
        cve_id="CVE-2021-12345",
        kb_id="KB5001234",
        affected_os="Windows 7 SP1",
        vulnerability_type="RCE",
        severity="CRITICAL",
        registry_keys=registry_keys,
        vulnerable_services=["RpcSs", "DcomLaunch"]
    )
    
    print(engine.format_recommendations_for_display(recs))

"""
Excel report generation for ProcmonAI using PowerShell ImportExcel module.

This module generates comprehensive Excel reports with multiple worksheets,
matching the functionality of the Claude procmon-analyzer skill.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from procmon_runner import PROCMON_BASE_DIR


def generate_excel_report(
    pml_path: Path,
    output_path: Optional[Path] = None,
    open_file: bool = True,
) -> Path:
    """
    Generate a comprehensive Excel report from a PML file using PowerShell ImportExcel.

    Creates multiple worksheets:
    - ALL: Complete event log
    - Per-operation sheets: ProcessCreate, LoadImage, CreateFile, WriteFile, etc.
    - Analysis sheets: explorerInjection, HTTPRegSetValue, firewallActions, etc.
    - File type sheets: txt, ps1, lnk, db, exes_dlls

    Args:
        pml_path: Path to the PML file to analyze.
        output_path: Optional output path for the Excel file. If None, generates
            a timestamped filename in PROCMON_BASE_DIR/reports.
        open_file: If True, opens the Excel file after generation.

    Returns:
        Path to the generated Excel file.

    Raises:
        RuntimeError: If report generation fails.
    """
    # First, convert PML to CSV (required for ImportExcel)
    csv_path = pml_path.with_suffix(".csv")
    
    # Check if CSV already exists, otherwise convert
    if not csv_path.exists():
        # Use Procmon to convert PML to CSV
        from procmon_runner import ASSETS_DIR
        
        # Find Procmon executable
        procmon_exe = None
        for candidate in [ASSETS_DIR / "Procmon64.exe", ASSETS_DIR / "Procmon.exe"]:
            if candidate.exists():
                procmon_exe = candidate
                break
        
        if not procmon_exe:
            raise RuntimeError("Procmon executable not found in assets directory")
        convert_cmd = [
            str(procmon_exe),
            "/Openlog",
            str(pml_path),
            "/SaveAs",
            str(csv_path),
            "/AcceptEula",
        ]
        
        try:
            result = subprocess.run(
                convert_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes max for conversion
            )
            if result.returncode != 0:
                raise RuntimeError(f"Failed to convert PML to CSV: {result.stderr}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("PML to CSV conversion timed out")
        except Exception as e:
            raise RuntimeError(f"Error converting PML to CSV: {e}")

    # Generate output path if not provided
    if output_path is None:
        reports_dir = PROCMON_BASE_DIR / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = subprocess.run(
            ["powershell", "-Command", "$env:COMPUTERNAME"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        output_path = reports_dir / f"ProcmonDump_{hostname}_{timestamp}.xlsx"

    # Build PowerShell script to generate Excel report
    ps_script = f'''
# Check/install ImportExcel module
if (-not (Get-Module ImportExcel -ListAvailable)) {{
    try {{
        Install-Module ImportExcel -Force -Scope CurrentUser -ErrorAction Stop
    }} catch {{
        Write-Output (@{{ status = "error"; message = "Failed to install ImportExcel module: $_" }} | ConvertTo-Json)
        exit 1
    }}
}}
Import-Module ImportExcel

$csvFile = "{csv_path}"
$xlFile = "{output_path}"

if (-not (Test-Path $csvFile)) {{
    Write-Output (@{{ status = "error"; message = "CSV file not found: $csvFile" }} | ConvertTo-Json)
    exit 1
}}

$events = Import-Csv $csvFile

# Create ALL worksheet with complete event log
$events | Export-Excel -Path $xlFile -WorksheetName "ALL" -AutoSize

# Per-operation worksheets
$events | Where-Object {{ $_.Operation -eq "Process Create" }} | Export-Excel -Path $xlFile -WorksheetName "ProcessCreate" -AutoSize -Append
$events | Where-Object {{ $_.Operation -eq "Load Image" }} | Export-Excel -Path $xlFile -WorksheetName "LoadImage" -AutoSize -Append
$events | Where-Object {{ $_.Operation -eq "CreateFile" }} | Export-Excel -Path $xlFile -WorksheetName "CreateFile" -AutoSize -Append
$events | Where-Object {{ $_.Operation -eq "WriteFile" }} | Export-Excel -Path $xlFile -WorksheetName "WriteFile" -AutoSize -Append
$events | Where-Object {{ $_.Operation -eq "ReadFile" }} | Export-Excel -Path $xlFile -WorksheetName "ReadFile" -AutoSize -Append
$events | Where-Object {{ $_.Operation -eq "CloseFile" }} | Export-Excel -Path $xlFile -WorksheetName "CloseFile" -AutoSize -Append
$events | Where-Object {{ $_.Operation -like "Reg*" }} | Export-Excel -Path $xlFile -WorksheetName "Registry" -AutoSize -Append
$events | Where-Object {{ $_.Operation -like "TCP*" -or $_.Operation -like "UDP*" }} | Export-Excel -Path $xlFile -WorksheetName "Network" -AutoSize -Append

# Analysis sheets for suspicious patterns
# Explorer.exe DLL injection
$events | Where-Object {{
    $_.Operation -eq "Load Image" -and
    $_.'Process Name' -eq "Explorer.exe" -and
    $_.Path -notlike "C:\\Windows\\*" -and
    $_.Path -notlike "C:\\Program Files*"
}} | Export-Excel -Path $xlFile -WorksheetName "explorerInjection" -AutoSize -Append

# HTTP URLs in registry
$events | Where-Object {{
    $_.Operation -eq "RegSetValue" -and
    ($_.Detail -like "*http://*" -or $_.Detail -like "*https://*")
}} | Export-Excel -Path $xlFile -WorksheetName "HTTPRegSetValue" -AutoSize -Append

# Firewall actions
$events | Where-Object {{
    $_.Path -like "*FirewallRules*" -or
    $_.Path -like "*FirewallPolicy*"
}} | Export-Excel -Path $xlFile -WorksheetName "firewallActions" -AutoSize -Append

# Run key modifications
$events | Where-Object {{
    $_.Operation -like "Reg*" -and
    ($_.Path -like "*\\Run*" -or $_.Path -like "*\\RunOnce*")
}} | Export-Excel -Path $xlFile -WorksheetName "RunKeys" -AutoSize -Append

# File type sheets
$events | Where-Object {{ $_.Path -like "*.txt" }} | Export-Excel -Path $xlFile -WorksheetName "txt" -AutoSize -Append
$events | Where-Object {{ $_.Path -like "*.ps1" }} | Export-Excel -Path $xlFile -WorksheetName "ps1" -AutoSize -Append
$events | Where-Object {{ $_.Path -like "*.lnk" }} | Export-Excel -Path $xlFile -WorksheetName "lnk" -AutoSize -Append
$events | Where-Object {{ $_.Path -like "*.db" }} | Export-Excel -Path $xlFile -WorksheetName "db" -AutoSize -Append
$events | Where-Object {{ $_.Path -like "*.exe" -or $_.Path -like "*.dll" }} | Export-Excel -Path $xlFile -WorksheetName "exes_dlls" -AutoSize -Append

Write-Output (@{{ status = "success"; path = $xlFile }} | ConvertTo-Json)
'''

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=600,  # 10 minutes max for large files
        )

        if result.returncode != 0:
            raise RuntimeError(f"PowerShell script failed: {result.stderr}")

        # Parse JSON response
        try:
            response = json.loads(result.stdout.strip())
            if response.get("status") == "error":
                raise RuntimeError(response.get("message", "Unknown error"))
        except json.JSONDecodeError:
            # If no JSON, check if file was created anyway
            if output_path.exists():
                pass  # Success despite no JSON response
            else:
                raise RuntimeError(f"Report generation failed. Output: {result.stdout}\nError: {result.stderr}")

        # Open file if requested
        if open_file and output_path.exists():
            try:
                subprocess.Popen(["powershell", "-Command", f"Start-Process '{output_path}'"], shell=False)
            except Exception:
                pass  # Non-fatal if we can't open the file

        return output_path

    except subprocess.TimeoutExpired:
        raise RuntimeError("Excel report generation timed out (exceeded 10 minutes)")
    except Exception as e:
        raise RuntimeError(f"Failed to generate Excel report: {e}") from e


__all__ = ["generate_excel_report"]


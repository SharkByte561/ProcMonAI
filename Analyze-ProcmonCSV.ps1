<#
.SYNOPSIS
    Comprehensive Procmon CSV security analysis using DuckDB.

.DESCRIPTION
    Analyzes a Procmon CSV file for security-relevant activity including:
    - File operations (executables created, temp files, system writes)
    - Registry modifications (app settings, uninstall entries)
    - Persistence mechanisms (Run keys, Services, Scheduled Tasks, shell extensions)
    - Process creation and DLL loading
    - Summary statistics

.PARAMETER CsvPath
    Path to the Procmon CSV file to analyze.

.PARAMETER OutputPath
    Optional path for HTML report output. Defaults to <CsvName>_analysis.html

.PARAMETER ShowConsole
    Display results in console in addition to generating report.

.EXAMPLE
    .\Analyze-ProcmonCSV.ps1 -CsvPath "C:\ProgramData\Procmon\capture.csv"

.EXAMPLE
    .\Analyze-ProcmonCSV.ps1 -CsvPath "capture.csv" -ShowConsole

.NOTES
    Requires PSDuckDB module. Install with: Install-Module PSDuckDB
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,

    [string]$OutputPath,

    [switch]$ShowConsole
)

# Import PSDuckDB - try multiple locations
$moduleLocations = @(
    (Join-Path $PSScriptRoot "PSDuckDB\PSDuckDB.psd1"),
    "X:\ProcmonAI\PSDuckDB\PSDuckDB.psd1",
    "C:\ProcmonAI\PSDuckDB\PSDuckDB.psd1"
)

$loaded = $false
foreach ($loc in $moduleLocations) {
    if (Test-Path $loc) {
        Import-Module $loc -Force
        $loaded = $true
        break
    }
}

if (-not $loaded) {
    # Try installed module as fallback
    Import-Module PSDuckDB -ErrorAction Stop
}

# Verify CSV exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    exit 1
}

# Get absolute path with forward slashes for DuckDB
$csvFullPath = (Resolve-Path $CsvPath).Path -replace '\\', '/'

# Default output path
if (-not $OutputPath) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
    $OutputPath = Join-Path (Split-Path $CsvPath -Parent) "${baseName}_analysis.html"
}

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Procmon CSV Security Analysis" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "CSV: $csvFullPath"
Write-Host "Output: $OutputPath"
Write-Host ""

# Initialize report
$report = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    CsvFile = $csvFullPath
    Sections = [ordered]@{}
}

function Run-Query {
    param([string]$Query, [string]$Description)

    Write-Host "  Running: $Description..." -ForegroundColor Gray
    try {
        $result = psduckdb -command $Query
        return $result
    } catch {
        Write-Warning "Query failed: $_"
        return $null
    }
}

function Add-Section {
    param([string]$Name, [string]$Description, $Data, [string]$Query)

    $report.Sections[$Name] = @{
        Description = $Description
        Query = $Query
        Data = $Data
        Count = if ($Data) { @($Data).Count } else { 0 }
    }

    if ($ShowConsole -and $Data) {
        Write-Host "`n--- $Name ($(@($Data).Count) results) ---" -ForegroundColor Yellow
        $Data | Select-Object -First 10 | Format-Table -AutoSize
        if (@($Data).Count -gt 10) {
            Write-Host "  ... and $(@($Data).Count - 10) more" -ForegroundColor Gray
        }
    }
}

# ============================================================
# OVERVIEW
# ============================================================
Write-Host "`n[1/8] Gathering Overview..." -ForegroundColor Green

$overviewQuery = @"
SELECT
    COUNT(*) as total_events,
    COUNT(DISTINCT "Process Name") as unique_processes,
    MIN("Time of Day") as start_time,
    MAX("Time of Day") as end_time
FROM '$csvFullPath'
"@
$overview = Run-Query $overviewQuery "Total event count"
Add-Section "Overview" "Capture summary statistics" $overview $overviewQuery

$opsQuery = @"
SELECT Operation, COUNT(*) as count
FROM '$csvFullPath'
GROUP BY Operation
ORDER BY count DESC
LIMIT 20
"@
$operations = Run-Query $opsQuery "Operations breakdown"
Add-Section "Operations" "Operations by frequency" $operations $opsQuery

$procsQuery = @"
SELECT "Process Name", COUNT(*) as event_count
FROM '$csvFullPath'
GROUP BY "Process Name"
ORDER BY event_count DESC
LIMIT 20
"@
$processes = Run-Query $procsQuery "Top processes"
Add-Section "Top Processes" "Most active processes" $processes $procsQuery

# ============================================================
# FILE OPERATIONS
# ============================================================
Write-Host "`n[2/8] Analyzing File Operations..." -ForegroundColor Green

$filesCreatedQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND Detail LIKE '%OpenResult: Created%'
ORDER BY Path
LIMIT 500
"@
$filesCreated = Run-Query $filesCreatedQuery "Files created"
Add-Section "Files Created" "New files created during capture" $filesCreated $filesCreatedQuery

$exesCreatedQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND Detail LIKE '%OpenResult: Created%'
AND (Path LIKE '%.exe' OR Path LIKE '%.dll' OR Path LIKE '%.sys')
ORDER BY Path
LIMIT 500
"@
$exesCreated = Run-Query $exesCreatedQuery "Executables created"
Add-Section "Executables Created" "EXE/DLL/SYS files created (potential malware indicators)" $exesCreated $exesCreatedQuery

$programFilesQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND Detail LIKE '%OpenResult: Created%'
AND Path LIKE '%Program Files%'
ORDER BY Path
LIMIT 500
"@
$programFiles = Run-Query $programFilesQuery "Program Files writes"
Add-Section "Program Files Writes" "Files created in Program Files (software installation)" $programFiles $programFilesQuery

$tempFilesQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND (Path LIKE '%\Temp\%' OR Path LIKE '%\AppData\Local\Temp\%')
ORDER BY Path
LIMIT 200
"@
$tempFiles = Run-Query $tempFilesQuery "Temp files"
Add-Section "Temp Files" "Temporary files created" $tempFiles $tempFilesQuery

$systemWritesQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND Detail LIKE '%OpenResult: Created%'
AND (Path LIKE '%\Windows\System32\%' OR Path LIKE '%\Windows\SysWOW64\%')
ORDER BY Path
LIMIT 200
"@
$systemWrites = Run-Query $systemWritesQuery "System folder writes"
Add-Section "System Folder Writes" "Files created in Windows system folders (SUSPICIOUS)" $systemWrites $systemWritesQuery

# ============================================================
# REGISTRY OPERATIONS
# ============================================================
Write-Host "`n[3/8] Analyzing Registry Operations..." -ForegroundColor Green

$regModsQuery = @"
SELECT Path, Detail
FROM '$csvFullPath'
WHERE Operation = 'RegSetValue'
AND Result = 'SUCCESS'
ORDER BY Path
LIMIT 500
"@
$regMods = Run-Query $regModsQuery "Registry modifications"
Add-Section "Registry Modifications" "Registry values set" $regMods $regModsQuery

$regKeysCreatedQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'RegCreateKey'
AND Result = 'SUCCESS'
ORDER BY Path
LIMIT 500
"@
$regKeysCreated = Run-Query $regKeysCreatedQuery "Registry keys created"
Add-Section "Registry Keys Created" "New registry keys" $regKeysCreated $regKeysCreatedQuery

# ============================================================
# PERSISTENCE MECHANISMS
# ============================================================
Write-Host "`n[4/8] Checking Persistence Mechanisms..." -ForegroundColor Green

$runKeysQuery = @"
SELECT Path, Detail
FROM '$csvFullPath'
WHERE Operation = 'RegSetValue'
AND (Path LIKE '%\CurrentVersion\Run\%' OR Path LIKE '%\CurrentVersion\RunOnce\%')
ORDER BY Path
"@
$runKeys = Run-Query $runKeysQuery "Run keys"
Add-Section "Run Keys" "Startup Run/RunOnce registry entries (PERSISTENCE)" $runKeys $runKeysQuery

$servicesQuery = @"
SELECT DISTINCT Path, Detail
FROM '$csvFullPath'
WHERE Operation IN ('RegSetValue', 'RegCreateKey')
AND Path LIKE '%\Services\%'
AND Path NOT LIKE '%\Services\bam\%'
AND Path NOT LIKE '%\Services\Tcpip\%'
ORDER BY Path
LIMIT 100
"@
$services = Run-Query $servicesQuery "Services"
Add-Section "Services" "Windows Service registry modifications (PERSISTENCE)" $services $servicesQuery

$scheduledTasksQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND Detail LIKE '%OpenResult: Created%'
AND Path LIKE '%\Windows\System32\Tasks\%'
ORDER BY Path
LIMIT 100
"@
$scheduledTasks = Run-Query $scheduledTasksQuery "Scheduled Tasks"
Add-Section "Scheduled Tasks" "Scheduled Task file operations (PERSISTENCE)" $scheduledTasks $scheduledTasksQuery

$shellExtQuery = @"
SELECT Path, Detail
FROM '$csvFullPath'
WHERE Operation = 'RegSetValue'
AND Path LIKE '%\shell\%'
ORDER BY Path
LIMIT 100
"@
$shellExt = Run-Query $shellExtQuery "Shell extensions"
Add-Section "Shell Extensions" "Shell/context menu registry entries (PERSISTENCE)" $shellExt $shellExtQuery

$appPathsQuery = @"
SELECT Path, Detail
FROM '$csvFullPath'
WHERE Operation = 'RegSetValue'
AND Path LIKE '%\App Paths\%'
ORDER BY Path
"@
$appPaths = Run-Query $appPathsQuery "App Paths"
Add-Section "App Paths" "Application path registry entries" $appPaths $appPathsQuery

$startupFolderQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND (Path LIKE '%\Start Menu\Programs\Startup\%' OR Path LIKE '%\Startup\%')
ORDER BY Path
"@
$startupFolder = Run-Query $startupFolderQuery "Startup folder"
Add-Section "Startup Folder" "Files in Startup folder (PERSISTENCE)" $startupFolder $startupFolderQuery

$startMenuQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'CreateFile'
AND Result = 'SUCCESS'
AND Path LIKE '%\Start Menu\%'
ORDER BY Path
LIMIT 100
"@
$startMenu = Run-Query $startMenuQuery "Start Menu"
Add-Section "Start Menu" "Start Menu shortcuts and entries" $startMenu $startMenuQuery

# ============================================================
# UNINSTALL & APP INFO
# ============================================================
Write-Host "`n[5/8] Checking Uninstall/App Info..." -ForegroundColor Green

$uninstallQuery = @"
SELECT Path, Detail
FROM '$csvFullPath'
WHERE Operation = 'RegSetValue'
AND Path LIKE '%\Uninstall\%'
ORDER BY Path
LIMIT 100
"@
$uninstall = Run-Query $uninstallQuery "Uninstall entries"
Add-Section "Uninstall Entries" "Add/Remove Programs registry entries" $uninstall $uninstallQuery

# ============================================================
# PROCESS & DLL
# ============================================================
Write-Host "`n[6/8] Analyzing Process & DLL Activity..." -ForegroundColor Green

$processCreateQuery = @"
SELECT "Process Name", Path, "Command Line"
FROM '$csvFullPath'
WHERE Operation = 'Process Create'
ORDER BY "Time of Day"
"@
$processCreate = Run-Query $processCreateQuery "Process creation"
Add-Section "Process Creation" "Processes spawned during capture" $processCreate $processCreateQuery

$dllLoadQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'Load Image'
AND Path LIKE '%.dll'
ORDER BY Path
LIMIT 500
"@
$dllLoad = Run-Query $dllLoadQuery "DLLs loaded"
Add-Section "DLLs Loaded" "Dynamic libraries loaded" $dllLoad $dllLoadQuery

$suspiciousDllQuery = @"
SELECT DISTINCT Path
FROM '$csvFullPath'
WHERE Operation = 'Load Image'
AND Path LIKE '%.dll'
AND (Path LIKE '%\Temp\%' OR Path LIKE '%\AppData\%' OR Path LIKE '%\Downloads\%')
ORDER BY Path
"@
$suspiciousDll = Run-Query $suspiciousDllQuery "Suspicious DLL locations"
Add-Section "Suspicious DLL Loads" "DLLs loaded from unusual locations (SUSPICIOUS)" $suspiciousDll $suspiciousDllQuery

# ============================================================
# NETWORK
# ============================================================
Write-Host "`n[7/8] Checking Network Activity..." -ForegroundColor Green

$networkQuery = @"
SELECT "Process Name", Operation, Path, Result
FROM '$csvFullPath'
WHERE Path LIKE '%TCP%' OR Path LIKE '%UDP%'
ORDER BY "Time of Day"
LIMIT 200
"@
$network = Run-Query $networkQuery "Network activity"
Add-Section "Network Activity" "TCP/UDP connections" $network $networkQuery

# ============================================================
# GENERATE HTML REPORT
# ============================================================
Write-Host "`n[8/8] Generating HTML Report..." -ForegroundColor Green

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Procmon Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2980b9; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }
        .section { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .meta { color: #7f8c8d; font-size: 0.9em; margin-bottom: 10px; }
        .count { background: #3498db; color: white; padding: 3px 10px; border-radius: 12px; font-size: 0.85em; }
        .suspicious { border-left: 4px solid #e74c3c; }
        .suspicious h2 { color: #c0392b; }
        .persistence { border-left: 4px solid #f39c12; }
        .persistence h2 { color: #d68910; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9em; }
        th { background: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; word-break: break-all; max-width: 600px; }
        tr:hover { background: #f8f9fa; }
        .query { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.85em; overflow-x: auto; white-space: pre-wrap; margin-top: 10px; }
        .empty { color: #95a5a6; font-style: italic; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card .value { font-size: 2em; font-weight: bold; }
        .stat-card .label { font-size: 0.9em; opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Procmon Security Analysis Report</h1>
        <div class="meta">
            <strong>Generated:</strong> $($report.Timestamp)<br>
            <strong>CSV File:</strong> $($report.CsvFile)
        </div>
"@

# Add summary cards
if ($overview) {
    $html += @"
        <div class="summary">
            <div class="stat-card">
                <div class="value">$($overview.total_events)</div>
                <div class="label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="value">$($overview.unique_processes)</div>
                <div class="label">Unique Processes</div>
            </div>
            <div class="stat-card">
                <div class="value">$(@($filesCreated).Count)</div>
                <div class="label">Files Created</div>
            </div>
            <div class="stat-card">
                <div class="value">$(@($exesCreated).Count)</div>
                <div class="label">Executables Created</div>
            </div>
        </div>
"@
}

# Add each section
foreach ($sectionName in $report.Sections.Keys) {
    $section = $report.Sections[$sectionName]

    # Determine section class
    $sectionClass = "section"
    if ($sectionName -match "SUSPICIOUS|System Folder") { $sectionClass = "section suspicious" }
    elseif ($sectionName -match "PERSISTENCE|Run Keys|Services|Scheduled|Startup|Shell") { $sectionClass = "section persistence" }

    $html += @"
        <div class="$sectionClass">
            <h2>$sectionName <span class="count">$($section.Count) results</span></h2>
            <p class="meta">$($section.Description)</p>
"@

    if ($section.Data -and @($section.Data).Count -gt 0) {
        $html += "<table><tr>"
        $columns = $section.Data[0].PSObject.Properties.Name
        foreach ($col in $columns) {
            $html += "<th>$col</th>"
        }
        $html += "</tr>"

        foreach ($row in $section.Data | Select-Object -First 100) {
            $html += "<tr>"
            foreach ($col in $columns) {
                $val = $row.$col
                if ($val -and $val.Length -gt 150) { $val = $val.Substring(0, 147) + "..." }
                $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($val))</td>"
            }
            $html += "</tr>"
        }
        $html += "</table>"

        if (@($section.Data).Count -gt 100) {
            $html += "<p class='meta'>Showing first 100 of $(@($section.Data).Count) results</p>"
        }
    } else {
        $html += "<p class='empty'>No results found</p>"
    }

    $html += @"
            <details>
                <summary>Show SQL Query</summary>
                <div class="query">$($section.Query)</div>
            </details>
        </div>
"@
}

$html += @"
    </div>
</body>
</html>
"@

# Write HTML report
Add-Type -AssemblyName System.Web
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Analysis Complete!" -ForegroundColor Green
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""
Write-Host "Report saved to: $OutputPath" -ForegroundColor Yellow
Write-Host ""

# Summary
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Total Events:        $($overview.total_events)"
Write-Host "  Files Created:       $(@($filesCreated).Count)"
Write-Host "  Executables Created: $(@($exesCreated).Count)"
Write-Host "  Registry Mods:       $(@($regMods).Count)"
Write-Host "  Run Keys:            $(@($runKeys).Count)" -ForegroundColor $(if (@($runKeys).Count -gt 0) { "Red" } else { "Gray" })
Write-Host "  Services Modified:   $(@($services).Count)" -ForegroundColor $(if (@($services).Count -gt 0) { "Yellow" } else { "Gray" })
Write-Host "  Scheduled Tasks:     $(@($scheduledTasks).Count)" -ForegroundColor $(if (@($scheduledTasks).Count -gt 0) { "Yellow" } else { "Gray" })
Write-Host "  Shell Extensions:    $(@($shellExt).Count)"
Write-Host "  Startup Folder:      $(@($startupFolder).Count)" -ForegroundColor $(if (@($startupFolder).Count -gt 0) { "Red" } else { "Gray" })
Write-Host "  System Folder Writes:$(@($systemWrites).Count)" -ForegroundColor $(if (@($systemWrites).Count -gt 0) { "Red" } else { "Gray" })
Write-Host "  Suspicious DLLs:     $(@($suspiciousDll).Count)" -ForegroundColor $(if (@($suspiciousDll).Count -gt 0) { "Red" } else { "Gray" })
Write-Host ""

# Open report in browser (if running interactively)
if ([Environment]::UserInteractive -and -not [Environment]::GetCommandLineArgs().Contains('-NonInteractive')) {
    $openReport = Read-Host "Open report in browser? (Y/n)"
    if ($openReport -ne 'n') {
        Start-Process $OutputPath
    }
}

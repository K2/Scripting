<#
.SYNOPSIS
    Analyze specific processes for code injection and tampering detection.

.DESCRIPTION
    This example demonstrates how to target specific processes for memory
    validation. This is useful when you suspect certain applications may
    be compromised or want to validate high-value targets.

.PARAMETER TargetHost
    The hostname or IP address of the target system.

.PARAMETER Username
    Administrator username for remote access.

.PARAMETER Password
    Administrator password for remote access.

.PARAMETER ProcessFilter
    Array of process names to scan (e.g., @("chrome.exe", "firefox.exe")).

.EXAMPLE
    .\process-analysis.ps1 -TargetHost "192.168.1.100" -ProcessFilter @("chrome.exe")
    
    Scans only Chrome processes on the target system.

.EXAMPLE
    .\process-analysis.ps1 -ProcessFilter @("powershell.exe", "cmd.exe")
    
    Scans PowerShell and CMD processes (uses environment variables for host/creds).

.NOTES
    Author: PDB2JSON Examples
    License: AGPL-3.0
    
    This script is useful for:
    - Detecting browser-based attacks
    - Finding process injection in system utilities
    - Validating critical business applications
    - Investigating specific suspicious processes
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetHost = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Username = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Password = "",
    
    [Parameter(Mandatory=$false)]
    [string[]]$ProcessFilter = @("chrome.exe", "firefox.exe", "iexplore.exe", "powershell.exe")
)

# ============================================================================
# Configuration
# ============================================================================

# Use environment variables if not provided
if ([string]::IsNullOrEmpty($TargetHost)) {
    $TargetHost = [Environment]::GetEnvironmentVariable("REMOTE_HOST")
}
if ([string]::IsNullOrEmpty($Username)) {
    $Username = [Environment]::GetEnvironmentVariable("USER_NAME")
}
if ([string]::IsNullOrEmpty($Password)) {
    $Password = [Environment]::GetEnvironmentVariable("PASS_WORD")
}

# Validate we have required parameters
if ([string]::IsNullOrEmpty($TargetHost) -or [string]::IsNullOrEmpty($Username)) {
    Write-Error "TargetHost and Username are required (via parameters or environment variables)"
    exit 1
}

# Import the main script
$MainScript = Join-Path $PSScriptRoot ".." "Test-AllVirtualMemory.ps1"
if (-not (Test-Path $MainScript)) {
    Write-Error "Test-AllVirtualMemory.ps1 not found at: $MainScript"
    exit 1
}
. $MainScript

# ============================================================================
# Display Configuration
# ============================================================================

Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Process-Specific Memory Analysis      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Target Host    : $TargetHost" -ForegroundColor White
Write-Host "  Username       : $Username" -ForegroundColor White
Write-Host "  Process Filter : $($ProcessFilter -join ', ')" -ForegroundColor White
Write-Host ""

# ============================================================================
# Process Analysis Functions
# ============================================================================

function Show-ProcessSummary {
    param($Results)
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║       Process Analysis Results         ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    if (-not $Results -or $Results.ResultDictionary.Count -eq 0) {
        Write-Host "⚠️  No matching processes found!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Possible reasons:" -ForegroundColor Yellow
        Write-Host "  - Processes not running on target system" -ForegroundColor White
        Write-Host "  - Process names misspelled in filter" -ForegroundColor White
        Write-Host "  - Insufficient permissions" -ForegroundColor White
        return
    }
    
    # Group results by process name
    $ProcessGroups = $Results.ResultDictionary.Values | Group-Object Name
    
    foreach ($Group in $ProcessGroups) {
        $ProcessName = $Group.Name
        $Instances = $Group.Group
        $TotalInstances = $Instances.Count
        
        Write-Host "📊 Process: $ProcessName" -ForegroundColor Cyan
        Write-Host "   Instances: $TotalInstances" -ForegroundColor White
        Write-Host ""
        
        foreach ($Instance in $Instances) {
            $StatusColor = "Green"
            $StatusIcon = "✅"
            
            if ($Instance.PercentValid -lt 100) {
                $StatusColor = "Yellow"
                $StatusIcon = "⚠️ "
            }
            if ($Instance.PercentValid -lt 90) {
                $StatusColor = "Orange"  # Note: Not all terminals support orange
                $StatusIcon = "🚨"
            }
            if ($Instance.PercentValid -lt 70) {
                $StatusColor = "Red"
                $StatusIcon = "💀"
            }
            
            Write-Host "   $StatusIcon PID $($Instance.Id): $($Instance.PercentValid.ToString('F2'))% validated" -ForegroundColor $StatusColor
            
            # Show suspicious modules if validation is not 100%
            if ($Instance.PercentValid -lt 100 -and $Instance.Modules) {
                $SuspiciousModules = $Instance.Modules | Where-Object { $_.PercentValid -lt 100 }
                if ($SuspiciousModules) {
                    Write-Host "      Suspicious modules:" -ForegroundColor Yellow
                    foreach ($Module in $SuspiciousModules | Select-Object -First 5) {
                        $ModuleName = if ($Module.ModuleName) { 
                            Split-Path -Leaf $Module.ModuleName 
                        } else { 
                            "Anonymous memory region" 
                        }
                        Write-Host "        - $ModuleName ($($Module.PercentValid.ToString('F2'))%)" -ForegroundColor Red
                    }
                }
            }
        }
        Write-Host ""
    }
}

function Export-DetailedReport {
    param($Results, $OutputPath)
    
    $Report = @{
        ScanTime = Get-Date -Format "o"
        TargetHost = $TargetHost
        ProcessFilter = $ProcessFilter
        Summary = @{
            TotalProcesses = $Results.ResultDictionary.Count
            FullyValidated = ($Results.ResultDictionary.Values | Where-Object { $_.PercentValid -eq 100 }).Count
            PartiallyValidated = ($Results.ResultDictionary.Values | Where-Object { $_.PercentValid -lt 100 -and $_.PercentValid -ge 90 }).Count
            Suspicious = ($Results.ResultDictionary.Values | Where-Object { $_.PercentValid -lt 90 }).Count
        }
        Processes = $Results.ResultDictionary.Values | ForEach-Object {
            @{
                Name = $_.Name
                PID = $_.Id
                PercentValid = $_.PercentValid
                ModuleCount = $_.Modules.Count
                SuspiciousModules = ($_.Modules | Where-Object { $_.PercentValid -lt 100 } | ForEach-Object {
                    @{
                        Name = $_.ModuleName
                        PercentValid = $_.PercentValid
                        BaseAddress = $_.BaseAddress
                    }
                })
            }
        }
    }
    
    $Report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
    Write-Host "📄 Detailed report saved to: $OutputPath" -ForegroundColor Cyan
}

# ============================================================================
# Execute Scan
# ============================================================================

Write-Host "🔍 Starting process-specific memory scan..." -ForegroundColor Green
Write-Host "   This may take several minutes depending on the number of processes..." -ForegroundColor Gray
Write-Host ""

try {
    # Execute the memory scan with process filter
    $Results = Test-AllVirtualMemory `
        -TargetHost $TargetHost `
        -aUserName $Username `
        -aPassWord $Password `
        -ProcNameGlob $ProcessFilter `
        -MaxThreads 256 `
        -ElevatePastAdmin `
        -GUIOutput
    
    # Display summary
    Show-ProcessSummary -Results $Results
    
    # Export detailed report
    $ReportPath = "process-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    Export-DetailedReport -Results $Results -OutputPath $ReportPath
    
    # Provide recommendations
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║         Recommendations                ║" -ForegroundColor Magenta
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    
    $SuspiciousCount = ($Results.ResultDictionary.Values | Where-Object { $_.PercentValid -lt 90 }).Count
    
    if ($SuspiciousCount -eq 0) {
        Write-Host "✅ All scanned processes appear to be clean!" -ForegroundColor Green
        Write-Host "   Continue monitoring these processes regularly." -ForegroundColor White
    }
    elseif ($SuspiciousCount -le 2) {
        Write-Host "⚠️  Found $SuspiciousCount potentially compromised process(es)." -ForegroundColor Yellow
        Write-Host "   Next steps:" -ForegroundColor White
        Write-Host "   1. Review the suspicious modules listed above" -ForegroundColor White
        Write-Host "   2. Dump suspicious memory regions for analysis" -ForegroundColor White
        Write-Host "   3. Check process command line arguments" -ForegroundColor White
        Write-Host "   4. Review network connections from these processes" -ForegroundColor White
    }
    else {
        Write-Host "🚨 Found $SuspiciousCount potentially compromised processes!" -ForegroundColor Red
        Write-Host "   CRITICAL: This may indicate a widespread compromise." -ForegroundColor Red
        Write-Host "   Immediate actions recommended:" -ForegroundColor Red
        Write-Host "   1. Isolate the affected system from the network" -ForegroundColor White
        Write-Host "   2. Capture a full memory dump for forensic analysis" -ForegroundColor White
        Write-Host "   3. Begin incident response procedures" -ForegroundColor White
        Write-Host "   4. Check other systems in the environment" -ForegroundColor White
    }
    
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "❌ Error during scan!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Common issues:" -ForegroundColor Yellow
    Write-Host "  - Cannot connect to remote host" -ForegroundColor White
    Write-Host "  - Invalid credentials" -ForegroundColor White
    Write-Host "  - WinRM not enabled on target" -ForegroundColor White
    Write-Host "  - ShowUI module not installed" -ForegroundColor White
    exit 1
}

Write-Host "✅ Process analysis complete!" -ForegroundColor Green
Write-Host ""

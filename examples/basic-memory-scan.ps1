<#
.SYNOPSIS
    Basic example of remote memory scanning using Test-AllVirtualMemory.ps1

.DESCRIPTION
    This script demonstrates a simple use case for scanning remote system memory
    and validating it against the PDB2JSON hash database. This is useful for
    detecting code injection, malware, or unauthorized modifications.

.EXAMPLE
    .\basic-memory-scan.ps1
    
    Runs a basic memory scan on the configured remote host.

.NOTES
    Author: PDB2JSON Examples
    
    Before running:
    1. Update the configuration variables below with your environment details
    2. Ensure ShowUI module is installed: Install-Module ShowUI
    3. Ensure you have admin rights on the target system
    4. Test network connectivity to the target host
#>

# ============================================================================
# CONFIGURATION - Update these values for your environment
# ============================================================================

# Target system to scan
$TargetHost = "192.168.1.100"  # Change to your target IP or hostname

# Credentials for remote access (must have admin rights)
$Username = "Administrator"     # Change to your admin username
$Password = "YourPassword"      # Change to your password (or use Get-Credential)

# Optional: Use Get-Credential for more secure password entry
# $Credential = Get-Credential -UserName $Username -Message "Enter admin credentials"

# Performance tuning - adjust based on your network and system
$MaxThreads = 256              # Number of parallel threads (256 is good default)

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

# Import required script
$scriptPath = Join-Path $PSScriptRoot ".." "Test-AllVirtualMemory.ps1"

# Verify script exists
if (-not (Test-Path $scriptPath)) {
    Write-Error "Test-AllVirtualMemory.ps1 not found. Please ensure you're running from the examples directory."
    exit 1
}

# Import the main script
. $scriptPath

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Basic Memory Scan Example" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Target Host: $TargetHost" -ForegroundColor Yellow
Write-Host "Username: $Username" -ForegroundColor Yellow
Write-Host "Max Threads: $MaxThreads" -ForegroundColor Yellow
Write-Host ""

# Display warning
Write-Host "WARNING: This will scan all process memory on the remote system." -ForegroundColor Red
Write-Host "Press Ctrl+C to cancel, or any other key to continue..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host ""
Write-Host "Starting scan..." -ForegroundColor Green
Write-Host ""

try {
    # Execute the memory scan
    $results = Test-AllVirtualMemory `
        -TargetHost $TargetHost `
        -aUserName $Username `
        -aPassWord $Password `
        -MaxThreads $MaxThreads `
        -GUIOutput `
        -ElevatePastAdmin
    
    # Display summary results
    Write-Host ""
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "Scan Complete!" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($results) {
        Write-Host "Summary Statistics:" -ForegroundColor Cyan
        Write-Host "  Total Processes Scanned: $($results.ResultDictionary.Count)" -ForegroundColor White
        Write-Host "  Total Modules Analyzed: $($results.ResultList.Count)" -ForegroundColor White
        Write-Host ""
        
        # Show processes with lowest validation percentages (most suspicious)
        Write-Host "Top 10 Processes with Lowest Validation:" -ForegroundColor Yellow
        Write-Host "==========================================" -ForegroundColor Yellow
        
        $results.ResultDictionary.Values | 
            Sort-Object PercentValid | 
            Select-Object -First 10 Name, PercentValid, Id | 
            Format-Table -AutoSize
        
        # Show processes with validation issues
        $suspiciousProcesses = $results.ResultDictionary.Values | 
            Where-Object { $_.PercentValid -lt 100 }
        
        if ($suspiciousProcesses) {
            Write-Host ""
            Write-Host "WARNING: Found $($suspiciousProcesses.Count) processes with validation issues!" -ForegroundColor Red
            Write-Host "These processes may have injected code or modifications." -ForegroundColor Red
            Write-Host ""
            Write-Host "Processes to investigate:" -ForegroundColor Yellow
            
            $suspiciousProcesses | 
                Select-Object Name, PercentValid, Id | 
                Format-Table -AutoSize
        }
        else {
            Write-Host ""
            Write-Host "✓ All processes validated successfully!" -ForegroundColor Green
        }
        
        # Save results to file
        $outputFile = "scan-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $outputFile
        Write-Host ""
        Write-Host "Full results saved to: $outputFile" -ForegroundColor Cyan
    }
}
catch {
    Write-Host ""
    Write-Host "ERROR: Scan failed!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Common issues:" -ForegroundColor Yellow
    Write-Host "  - Cannot connect to remote host (check network/firewall)" -ForegroundColor White
    Write-Host "  - Invalid credentials (verify username/password)" -ForegroundColor White
    Write-Host "  - WinRM not enabled on target (run Enable-PSRemoting)" -ForegroundColor White
    Write-Host "  - ShowUI module not installed (run Install-Module ShowUI)" -ForegroundColor White
    exit 1
}

Write-Host ""
Write-Host "Scan complete. Review the GUI window for detailed results." -ForegroundColor Green
Write-Host ""

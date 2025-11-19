# Quick Start Guide

This guide will help you get started with the PDB2JSON scripting examples quickly.

## Table of Contents
- [What is PDB2JSON?](#what-is-pdb2json)
- [Installation](#installation)
- [Quick Examples](#quick-examples)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)

## What is PDB2JSON?

PDB2JSON is an Azure Functions-based application that provides the **largest hash database ever constructed** for verifying the integrity of running Windows memory. It uses SHA256 hashing with JIT (Just-In-Time) methodology to authenticate running memory without requiring pre-computed hash values.

### Key Features
- **No binary data upload** - Only SHA256 hash values are transmitted
- **JIT Hash Verification** - Real-time hash calculation based on your system's virtual address
- **Massive Database** - 5TB of Microsoft software pre-loaded
- **Free & Unlimited Access** - Available for 64-bit and WOW64 systems

## Installation

### Prerequisites

#### For PowerShell Scripts
```powershell
# Check PowerShell version (requires 5.0+)
$PSVersionTable.PSVersion

# Install required modules
Install-Module ShowUI -Scope CurrentUser
```

#### For Python Scripts (Volatility Plugin)
```bash
# Install dependencies
pip install -r requirements.txt

# Verify Volatility installation
python vol.py --version
```

#### For Bash Scripts
```bash
# Verify required tools
which llvm-readobj
which curl
which bc

# On Ubuntu/Debian
sudo apt-get install llvm curl bc
```

## Quick Examples

### 1. Extract Type Information from a Binary (Bash)

The `dt.sh` script allows you to extract JSON symbol information from Windows binaries on Linux/macOS.

```bash
# Extract EPROCESS structure information
./dt.sh -i /path/to/ntoskrnl.exe -t _EPROCESS

# Get all type information
./dt.sh -i /path/to/ntoskrnl.exe -t *

# Look up a symbol by name with wildcards
./dt.sh -i /path/to/kernel32.dll -X "CreateFile*"

# Get symbol at specific address
./dt.sh -i /path/to/user32.dll -A 0x1000

# Get relocation data
./dt.sh -i /path/to/ntdll.dll -r
```

### 2. Remote Memory Integrity Verification (PowerShell)

The `Test-AllVirtualMemory.ps1` script remotely scans all virtual memory in a target system and validates it against the hash database.

```powershell
# Basic scan with GUI output
.\Test-AllVirtualMemory.ps1 `
    -TargetHost "192.168.1.100" `
    -aUserName "Administrator" `
    -aPassWord "YourPassword" `
    -GUIOutput

# Scan specific processes only
.\Test-AllVirtualMemory.ps1 `
    -TargetHost "Server2016" `
    -aUserName "admin" `
    -aPassWord "password123" `
    -ProcNameGlob @("chrome.exe", "iexplore.exe") `
    -MaxThreads 256 `
    -ElevatePastAdmin `
    -GUIOutput

# Use environment variables
$env:REMOTE_HOST = "192.168.1.100"
$env:USER_NAME = "Administrator"
$env:PASS_WORD = "YourPassword"
.\Test-AllVirtualMemory.ps1 -GUIOutput
```

**Accessing Results:**
```powershell
# Run and capture results
$results = .\Test-AllVirtualMemory.ps1 -TargetHost "..." -aUserName "..." -aPassWord "..."

# Browse process list sorted by validation percentage
$results.ResultDictionary.Values | 
    Select-Object Name, PercentValid, Id | 
    Sort-Object PercentValid

# Examine modules for a specific process (PID 4164)
$results.ResultDictionary[4164].Children | 
    Select-Object PercentValid, Name

# Get all module names
$results.ResultList.Struct.ModuleName
```

### 3. Volatility Memory Analysis (Python)

The `inVteroJitHash.py` plugin validates memory dumps against the hash database.

```bash
# Basic usage with Volatility
python vol.py \
    --plugins=/path/to/Scripting \
    -f "/path/to/memory.vmem" \
    --profile=Win10x64_14393 \
    invterojithash

# With extra details
python vol.py \
    --plugins=/path/to/Scripting \
    -f "/path/to/memory.vmem" \
    --profile=Win7SP1x64 \
    invterojithash -x

# Dump failed blocks to folder
python vol.py \
    --plugins=/path/to/Scripting \
    -f "/path/to/memory.vmem" \
    --profile=Win10x64_14393 \
    invterojithash -D /output/folder

# Super verbose mode with all details
python vol.py \
    --plugins=/path/to/Scripting \
    -f "/path/to/memory.vmem" \
    --profile=Win10x64_14393 \
    invterojithash -s -x
```

### 4. Binary Diff Visualization (PowerShell)

Compare memory dumps with golden images:

```powershell
# Fast binary diff (recommended)
Import-Module .\Test-AllVirtualMemory.ps1
Add-Type -AssemblyName PresentationFramework
Get-FastBinDiff C:\temp\mem_ctf.bin C:\windows\system32\msctf.dll 0x12345

# Traditional diff view (slower, more features)
Get-BinDiff C:\temp\mem_ctf.bin C:\windows\system32\msctf.dll
```

## Common Use Cases

### Memory Forensics Investigation

1. **Detect Code Injection:**
   ```powershell
   # Look for processes with low validation percentages
   $results = .\Test-AllVirtualMemory.ps1 -TargetHost "suspect-machine" `
       -aUserName "admin" -aPassWord "pass"
   
   $results.ResultDictionary.Values | 
       Where-Object { $_.PercentValid -lt 50 } | 
       Select-Object Name, PercentValid, Id
   ```

2. **Analyze Memory Dump:**
   ```bash
   # Extract and validate all modules from memory dump
   python vol.py --plugins=. -f suspicious.vmem \
       --profile=Win10x64 invterojithash -x
   ```

3. **Symbol Lookup for Debugging:**
   ```bash
   # Find structure definitions without downloading PDB
   ./dt.sh -i ntoskrnl.exe -t _KTHREAD
   ./dt.sh -i ntoskrnl.exe -t _DRIVER_OBJECT
   ```

### Incident Response

1. **Quick System Scan:**
   ```powershell
   # Scan all running processes
   .\Test-AllVirtualMemory.ps1 `
       -TargetHost "compromised-server" `
       -aUserName "admin" `
       -aPassWord "password" `
       -MaxThreads 512 `
       -GUIOutput
   ```

2. **Focus on Suspicious Processes:**
   ```powershell
   # Only scan browsers and common attack vectors
   .\Test-AllVirtualMemory.ps1 `
       -TargetHost "workstation" `
       -ProcNameGlob @("iexplore.exe", "chrome.exe", "firefox.exe", 
                       "powershell.exe", "cmd.exe", "svchost.exe") `
       -GUIOutput
   ```

## Troubleshooting

### Common Issues

#### PowerShell: ShowUI Module Not Loading
```powershell
# Error: "Import-Module : The specified module 'ShowUI' was not loaded"
# Solution: Install ShowUI
Install-Module ShowUI -Scope CurrentUser

# If still failing, manually import assemblies
Add-Type -AssemblyName PresentationFramework 
Add-Type -AssemblyName PresentationCore
Import-Module ShowUI
```

#### Python: SSL Certificate Verification Errors
```bash
# Error: SSL: CERTIFICATE_VERIFY_FAILED
# Solution: Update certifi package
pip install --upgrade certifi

# Or use system certificates
pip install urllib3[secure]
```

#### Bash: llvm-readobj Not Found
```bash
# Error: "Can not find llvm-readobj"
# Solution: Install LLVM tools
# Ubuntu/Debian:
sudo apt-get install llvm

# macOS:
brew install llvm

# Verify installation
llvm-readobj --version
```

#### Remote Connection Failures
```powershell
# Error: "WinRM cannot process the request"
# Solution: Enable WinRM on target
# On target machine:
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service WinRM

# Test connection
Test-WSMan -ComputerName target-machine
```

#### Memory Access Denied
```powershell
# Error: "Access denied" when scanning memory
# Solution: Run with elevated privileges
# Use -ElevatePastAdmin parameter
.\Test-AllVirtualMemory.ps1 -ElevatePastAdmin -TargetHost "..." ...
```

### Performance Tips

1. **Increase Thread Count** for faster scanning:
   ```powershell
   -MaxThreads 512  # Default is 256
   ```

2. **Use Environment Variables** to avoid repeated credential entry:
   ```bash
   export REMOTE_HOST="192.168.1.100"
   export USER_NAME="admin"
   export PASS_WORD="password"
   ```

3. **Focus on Specific Processes** to reduce scan time:
   ```powershell
   -ProcNameGlob @("specific.exe")
   ```

### Getting Help

- Check the detailed [README.md](README.md) for more information
- Review [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
- Report issues on the GitHub repository
- Review server endpoint documentation at the Azure Functions URL

## Next Steps

- Explore the full [README.md](README.md) for detailed API documentation
- Read about JIT hashing methodology
- Review example outputs and interpretation
- Set up your own local HashServer for custom software validation

## Security Notes

⚠️ **Important Security Considerations:**

- Only SHA256 hash values are transmitted - no binary data leaves your system
- Use secure connections (HTTPS) for all server communications
- Protect credentials when using remote scanning features
- Be cautious with `-ElevatePastAdmin` - it elevates to SYSTEM privileges
- Validate the server certificate when using custom endpoints

## Additional Resources

- [Azure Functions](https://github.com/Azure/Azure-Functions)
- [HashServer (local hosting)](https://github.com/K2/HashServer)
- [inVteroCore](https://github.com/ShaneK2/inVtero.net)
- [Volatility Framework](https://www.volatilityfoundation.org/)

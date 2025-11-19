# Examples

This directory contains example scripts and usage patterns for the PDB2JSON scripting tools.

## Directory Structure

```
examples/
├── README.md                          # This file
├── basic-memory-scan.ps1              # Simple memory scanning example
├── process-analysis.ps1               # Analyze specific processes
├── symbol-lookup.sh                   # Symbol lookup examples
├── custom-hash-validation.py          # Python hash validation example
└── sample-output/                     # Sample output files
    ├── scan-results.txt               # Example scan output
    └── process-report.json            # Example JSON report
```

## Quick Examples

### PowerShell Examples

#### Basic Memory Scan
```powershell
# Run a simple memory scan on a remote host
.\examples\basic-memory-scan.ps1
```

#### Process-Specific Analysis
```powershell
# Analyze browser processes only
.\examples\process-analysis.ps1 -ProcessFilter "chrome.exe","firefox.exe"
```

### Bash Examples

#### Symbol Lookup
```bash
# Look up common Windows structures
./examples/symbol-lookup.sh ntoskrnl.exe
```

### Python Examples

#### Custom Hash Validation
```python
# Validate hashes from a memory dump
python examples/custom-hash-validation.py memory.raw
```

## Sample Data

The `sample-output/` directory contains example outputs from various tools:

- **scan-results.txt**: Example output from Test-AllVirtualMemory.ps1
- **process-report.json**: JSON-formatted scan results

## Usage Tips

1. **Modify for Your Environment**: Update IP addresses, credentials, and file paths
2. **Start Simple**: Begin with basic examples before complex scenarios
3. **Review Comments**: Each example file contains detailed inline comments
4. **Security**: Never commit real credentials or sensitive data

## Contributing Examples

If you have useful examples to share:

1. Create a new file in this directory
2. Add clear comments explaining the use case
3. Include sample output if helpful
4. Update this README with your example
5. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details.

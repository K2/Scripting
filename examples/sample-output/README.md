# Sample Output Files

This directory contains example outputs from various PDB2JSON tools to help you understand what to expect.

## Files

### scan-results-example.txt
Example terminal output from a PowerShell memory scan showing:
- Process enumeration
- Memory validation progress
- Summary statistics
- Suspicious findings

### process-report-example.json
Example JSON report structure from process-specific analysis showing:
- Scan metadata (timestamp, target, filters)
- Summary statistics
- Per-process details
- Suspicious module information

### symbol-lookup-example.json
Example JSON output from dt.sh symbol lookup showing:
- Structure definitions (_EPROCESS, _KTHREAD, etc.)
- Symbol information
- Type metadata

### volatility-output-example.txt
Example terminal output from the Volatility plugin showing:
- Color-coded validation results
- Progress bars
- Per-module statistics
- Summary metrics

## How to Use These Examples

1. **Compare Against Your Output**: Check if your results look similar
2. **Understand Formatting**: Learn how to interpret the data
3. **Identify Issues**: Spot anomalies by comparing to clean examples
4. **Parse Programmatically**: Use JSON examples as parsing templates

## Note

These are **example outputs only** and may not reflect current system configurations. Use them as reference material, not as authoritative baselines for your environment.

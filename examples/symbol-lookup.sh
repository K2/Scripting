#!/bin/bash

#############################################################################
# Symbol Lookup Examples
#
# This script demonstrates various ways to use dt.sh for extracting
# symbol information from Windows PE binaries.
#
# Usage: ./symbol-lookup.sh /path/to/binary.exe
#
# Author: PDB2JSON Examples
# License: AGPL-3.0
#############################################################################

# Check if dt.sh exists
DT_SCRIPT="$(dirname "$0")/../dt.sh"
if [ ! -f "$DT_SCRIPT" ]; then
    echo "❌ Error: dt.sh not found at $DT_SCRIPT"
    exit 1
fi

# Check if binary path provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <pe_binary_file>"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/ntoskrnl.exe"
    echo "  $0 /path/to/kernel32.dll"
    exit 1
fi

BINARY="$1"

# Verify binary exists
if [ ! -f "$BINARY" ]; then
    echo "❌ Error: File not found: $BINARY"
    exit 1
fi

echo "============================================"
echo "🔍 PDB2JSON Symbol Lookup Examples"
echo "============================================"
echo "Binary: $BINARY"
echo "Basename: $(basename "$BINARY")"
echo ""

#############################################################################
# Example 1: Get Common Windows Structures
#############################################################################
echo "📋 Example 1: Common Windows Structures"
echo "----------------------------------------"
echo ""

echo "🔹 Getting _EPROCESS structure..."
$DT_SCRIPT -i "$BINARY" -t "_EPROCESS" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Success!"
else
    echo "⚠️  Structure not found in this binary (this is normal if not ntoskrnl.exe)"
fi
echo ""

echo "🔹 Getting _KTHREAD structure..."
$DT_SCRIPT -i "$BINARY" -t "_KTHREAD" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Success!"
else
    echo "⚠️  Structure not found in this binary"
fi
echo ""

#############################################################################
# Example 2: Symbol Name Lookups with Wildcards
#############################################################################
echo "📝 Example 2: Symbol Name Lookups"
echo "----------------------------------------"
echo ""

echo "🔹 Finding all CreateFile* functions..."
$DT_SCRIPT -i "$BINARY" -X "CreateFile*" 2>/dev/null | head -20
echo ""

echo "🔹 Finding all Nt* system calls..."
$DT_SCRIPT -i "$BINARY" -X "Nt*" 2>/dev/null | head -20
echo ""

#############################################################################
# Example 3: Address Resolution
#############################################################################
echo "📍 Example 3: Address Resolution"
echo "----------------------------------------"
echo ""

echo "🔹 Looking up symbol at RVA 0x1000..."
$DT_SCRIPT -i "$BINARY" -A 0x1000 2>/dev/null
echo ""

echo "🔹 Looking up symbol at RVA 0x10000..."
$DT_SCRIPT -i "$BINARY" -A 0x10000 2>/dev/null
echo ""

#############################################################################
# Example 4: Relocation Data
#############################################################################
echo "🔄 Example 4: Relocation Data Extraction"
echo "----------------------------------------"
echo ""

OUTPUT_DIR="/tmp/pdb2json-examples"
mkdir -p "$OUTPUT_DIR"

RELOC_FILE="$OUTPUT_DIR/$(basename "$BINARY").relocations.json"
echo "🔹 Extracting relocation data to: $RELOC_FILE"
$DT_SCRIPT -i "$BINARY" -r -o "$RELOC_FILE" 2>/dev/null

if [ -f "$RELOC_FILE" ]; then
    FILE_SIZE=$(wc -c < "$RELOC_FILE")
    echo "✅ Success! Extracted $FILE_SIZE bytes of relocation data"
    echo "   Preview:"
    head -10 "$RELOC_FILE" | sed 's/^/   /'
else
    echo "⚠️  No relocation data available for this binary"
fi
echo ""

#############################################################################
# Example 5: Saving Results to Files
#############################################################################
echo "💾 Example 5: Saving Results to Files"
echo "----------------------------------------"
echo ""

STRUCT_FILE="$OUTPUT_DIR/$(basename "$BINARY")_structures.json"
echo "🔹 Saving _POOL_HEADER structure to: $STRUCT_FILE"
$DT_SCRIPT -i "$BINARY" -t "_POOL_HEADER" -o "$STRUCT_FILE" 2>/dev/null

if [ -f "$STRUCT_FILE" ]; then
    FILE_SIZE=$(wc -c < "$STRUCT_FILE")
    echo "✅ Success! Saved structure definition ($FILE_SIZE bytes)"
else
    echo "⚠️  Structure not found in this binary"
fi
echo ""

#############################################################################
# Summary
#############################################################################
echo "============================================"
echo "✅ Examples Complete!"
echo "============================================"
echo ""
echo "💡 Tips:"
echo "   - Use wildcards (*) for pattern matching"
echo "   - Save results with -o flag for later use"
echo "   - Different binaries contain different symbols"
echo "   - System binaries (ntoskrnl.exe, ntdll.dll) have the most structures"
echo ""
echo "📁 Output files saved to: $OUTPUT_DIR"
echo ""
echo "📚 For more information:"
echo "   - See QUICKSTART.md for detailed examples"
echo "   - See ARCHITECTURE.md for system design"
echo "   - Run dt.sh -h for all options"
echo ""

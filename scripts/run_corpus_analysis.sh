#!/bin/bash
# Quick-start script for corpus analysis (no ML, parallel processing enabled)
# Usage: ./run_corpus_analysis.sh /path/to/corpus [output_prefix] [glob_pattern] [--deep]

set -euo pipefail

CORPUS_DIR="${1:-}"
OUTPUT_PREFIX="${2:-corpus_analysis}"
GLOB_PATTERN="${3:-*.pdf}"
DEEP_SCAN=false

# Check for --deep flag in any position
for arg in "$@"; do
    if [ "$arg" = "--deep" ]; then
        DEEP_SCAN=true
    fi
done

if [ -z "$CORPUS_DIR" ]; then
    echo "Usage: $0 /path/to/corpus [output_prefix] [glob_pattern] [--deep]" >&2
    echo "" >&2
    echo "Examples:" >&2
    echo "  # Fast scan (default):" >&2
    echo "  $0 /path/to/corpus corpus_name '*.pdf'" >&2
    echo "" >&2
    echo "  # Deep scan with stream decoding:" >&2
    echo "  $0 /path/to/corpus corpus_name '*.pdf' --deep" >&2
    echo "" >&2
    echo "  # Files without extension (hash-named):" >&2
    echo "  $0 /home/michiel/src/pdf-corpus/2022/malicious malicious_2022 '*' --deep" >&2
    exit 1
fi

if [ ! -d "$CORPUS_DIR" ]; then
    echo "Error: Directory not found: $CORPUS_DIR" >&2
    exit 1
fi

# Get absolute path to this script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SIS_BIN="$PROJECT_ROOT/target/release/sis"

# Check if binary exists
if [ ! -f "$SIS_BIN" ]; then
    echo "Error: sis binary not found at $SIS_BIN" >&2
    echo "Build it first: cd $PROJECT_ROOT && cargo build --release" >&2
    exit 1
fi

# Get CPU count for performance info
CPU_COUNT=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "unknown")

# Output files
JSONL_OUT="${OUTPUT_PREFIX}_scan.jsonl"
ERRORS_OUT="${OUTPUT_PREFIX}_errors.log"
ANALYSIS_OUT="${OUTPUT_PREFIX}_analysis.txt"
PROBLEMS_OUT="${OUTPUT_PREFIX}_problems.txt"

SCAN_MODE="FAST"
if [ "$DEEP_SCAN" = true ]; then
    SCAN_MODE="DEEP"
fi

echo "=========================================="
echo "SIS CORPUS ANALYSIS (No ML, Parallel)"
echo "=========================================="
echo "Corpus:         $CORPUS_DIR"
echo "Output prefix:  $OUTPUT_PREFIX"
echo "Glob pattern:   $GLOB_PATTERN"
echo "Scan mode:      $SCAN_MODE"
echo "Binary:         $SIS_BIN"
echo "CPUs available: $CPU_COUNT"
echo "Parallelism:    ENABLED (default)"
echo ""
echo "Output files:"
echo "  - $JSONL_OUT      (scan results)"
echo "  - $ERRORS_OUT     (stderr logs)"
echo "  - $ANALYSIS_OUT   (coverage report)"
echo "  - $PROBLEMS_OUT   (problem files)"
echo "=========================================="
echo ""

# Count files matching pattern
FILE_COUNT=$(find "$CORPUS_DIR" -maxdepth 1 -name "$GLOB_PATTERN" -type f 2>/dev/null | wc -l)
echo "Found $FILE_COUNT files matching '$GLOB_PATTERN'"
echo ""
if [ "$DEEP_SCAN" = true ]; then
    echo "Performance note: Deep scanning enabled (decodes all streams)."
    echo "With $CPU_COUNT cores, expect ~1-10 files/second throughput."
    echo "Deep scanning may take significantly longer."
else
    echo "Performance note: Fast scanning (no stream decoding)."
    echo "With $CPU_COUNT cores, expect ~$((CPU_COUNT / 2))-$((CPU_COUNT)) files/second throughput."
fi
echo ""

# Confirm
read -p "Start scan? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Starting scan at $(date)..."
echo "This may take several hours for large corpora."
echo "Monitor progress: tail -f $ERRORS_OUT"
echo ""

# Run scan
SCAN_ARGS=(
    scan
    --path "$CORPUS_DIR"
    --glob "$GLOB_PATTERN"
    --jsonl-findings
)

if [ "$DEEP_SCAN" = true ]; then
    SCAN_ARGS+=(--deep)
fi

"$SIS_BIN" "${SCAN_ARGS[@]}" > "$JSONL_OUT" 2> "$ERRORS_OUT"

SCAN_EXIT=$?

echo ""
echo "Scan completed at $(date) with exit code $SCAN_EXIT"
echo ""

# Analyze results
if [ -f "$JSONL_OUT" ] && [ -s "$JSONL_OUT" ]; then
    echo "Analyzing results..."
    "$SCRIPT_DIR/analyze_corpus.py" "$JSONL_OUT" | tee "$ANALYSIS_OUT"
    echo ""
fi

# Extract problem files
if [ -f "$ERRORS_OUT" ] && [ -s "$ERRORS_OUT" ]; then
    echo "Extracting problem files..."
    "$SCRIPT_DIR/extract_problem_files.py" "$ERRORS_OUT" | tee "$PROBLEMS_OUT"
    echo ""
fi

echo "=========================================="
echo "ANALYSIS COMPLETE"
echo "=========================================="
echo "Results:"
echo "  - Scan results:    $JSONL_OUT"
echo "  - Error log:       $ERRORS_OUT"
echo "  - Coverage report: $ANALYSIS_OUT"
echo "  - Problem files:   $PROBLEMS_OUT"
echo ""
echo "Next steps:"
echo "  - Review $ANALYSIS_OUT for finding coverage"
echo "  - Check $PROBLEMS_OUT for files needing fixes"
echo "  - See docs/corpus-analysis.md for deep analysis workflows"
echo "=========================================="

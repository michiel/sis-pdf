#!/bin/bash
# Comprehensive JS Analysis Testing Script
# Tests hostile payloads and identifies gaps in sandbox capabilities

set -e

PAYLOAD_DIR="extracted_js/payloads"
RESULTS_DIR="extracted_js/test_results"
REPORT_FILE="$RESULTS_DIR/hostile_analysis_$(date +%Y%m%d_%H%M%S).json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔍 JavaScript Hostile Payload Analysis"
echo "======================================"
echo

# Create results directory
mkdir -p "$RESULTS_DIR"

# Count payloads
TOTAL_PAYLOADS=$(find "$PAYLOAD_DIR" -name "*.js" | wc -l)
VIRUSSHARE_PAYLOADS=$(find "$PAYLOAD_DIR" -name "VirusShare_*.js" | wc -l)

echo "📊 Payload Statistics:"
echo "   Total payloads: $TOTAL_PAYLOADS"
echo "   VirusShare payloads: $VIRUSSHARE_PAYLOADS"
echo

# Build with JS sandbox features
echo "🔨 Building sis-pdf with JS sandbox..."
cargo build --release --features js-sandbox
echo

# Test mode selection
echo "Select test mode:"
echo "  1) Quick test (10 random VirusShare samples)"
echo "  2) Medium test (100 random samples)"
echo "  3) Full test (all $VIRUSSHARE_PAYLOADS VirusShare payloads)"
echo "  4) All payloads ($TOTAL_PAYLOADS files)"
read -p "Enter choice [1-4]: " CHOICE

case $CHOICE in
    1)
        FILES=$(find "$PAYLOAD_DIR" -name "VirusShare_*.js" | shuf | head -10)
        ;;
    2)
        FILES=$(find "$PAYLOAD_DIR" -name "VirusShare_*.js" | shuf | head -100)
        ;;
    3)
        FILES=$(find "$PAYLOAD_DIR" -name "VirusShare_*.js")
        ;;
    4)
        FILES=$(find "$PAYLOAD_DIR" -name "*.js")
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

FILE_COUNT=$(echo "$FILES" | wc -l)
echo
echo "🧪 Testing $FILE_COUNT JavaScript payloads..."
echo

# Initialize counters
SUCCESSFUL=0
TIMEOUTS=0
SKIPPED=0
ERRORS=0
EXECUTION_ERRORS=0

# Result arrays
declare -a TIMEOUT_FILES
declare -a SKIP_FILES
declare -a ERROR_FILES
declare -a EXEC_ERROR_FILES

# Progress tracking
CURRENT=0

# Test each file
for JS_FILE in $FILES; do
    CURRENT=$((CURRENT + 1))
    FILENAME=$(basename "$JS_FILE")

    # Progress indicator
    printf "\r[%d/%d] Testing: %-60s" $CURRENT $FILE_COUNT "${FILENAME:0:60}"

    # Run analysis
    OUTPUT=$(./target/release/sis-pdf scan --json "$JS_FILE" 2>&1) || true

    # Analyze results
    if echo "$OUTPUT" | grep -q '"outcome".*:.*"executed"'; then
        SUCCESSFUL=$((SUCCESSFUL + 1))

        # Check for execution errors
        if echo "$OUTPUT" | grep -q '"errors".*\[.*\]' && ! echo "$OUTPUT" | grep -q '"errors".*:\s*\[\s*\]'; then
            EXECUTION_ERRORS=$((EXECUTION_ERRORS + 1))
            EXEC_ERROR_FILES+=("$FILENAME")
        fi
    elif echo "$OUTPUT" | grep -q '"outcome".*:.*"timed_out"'; then
        TIMEOUTS=$((TIMEOUTS + 1))
        TIMEOUT_FILES+=("$FILENAME")
    elif echo "$OUTPUT" | grep -q '"outcome".*:.*"skipped"'; then
        SKIPPED=$((SKIPPED + 1))
        SKIP_FILES+=("$FILENAME")
    else
        ERRORS=$((ERRORS + 1))
        ERROR_FILES+=("$FILENAME")
    fi
done

echo
echo
echo "═══════════════════════════════════════════════"
echo "📈 Test Results Summary"
echo "═══════════════════════════════════════════════"
echo
echo -e "${GREEN}✅ Successful executions: $SUCCESSFUL ($((SUCCESSFUL * 100 / FILE_COUNT))%)${NC}"
echo -e "${YELLOW}⚠️  Executions with errors: $EXECUTION_ERRORS ($((EXECUTION_ERRORS * 100 / FILE_COUNT))%)${NC}"
echo -e "${YELLOW}⏱️  Timeouts: $TIMEOUTS ($((TIMEOUTS * 100 / FILE_COUNT))%)${NC}"
echo -e "${YELLOW}⏭️  Skipped (size limits): $SKIPPED ($((SKIPPED * 100 / FILE_COUNT))%)${NC}"
echo -e "${RED}❌ Analysis errors: $ERRORS ($((ERRORS * 100 / FILE_COUNT))%)${NC}"
echo

# Detailed breakdowns
if [ ${#TIMEOUT_FILES[@]} -gt 0 ]; then
    echo "⏱️  Timeout files (infinite loops or very complex code):"
    for f in "${TIMEOUT_FILES[@]}"; do
        echo "   - $f"
    done | head -10
    if [ ${#TIMEOUT_FILES[@]} -gt 10 ]; then
        echo "   ... and $((${#TIMEOUT_FILES[@]} - 10)) more"
    fi
    echo
fi

if [ ${#SKIP_FILES[@]} -gt 0 ]; then
    echo "⏭️  Skipped files (exceeded size limits):"
    for f in "${SKIP_FILES[@]}"; do
        echo "   - $f"
    done | head -10
    if [ ${#SKIP_FILES[@]} -gt 10 ]; then
        echo "   ... and $((${#SKIP_FILES[@]} - 10)) more"
    fi
    echo
fi

if [ ${#ERROR_FILES[@]} -gt 0 ]; then
    echo "❌ Files with analysis errors:"
    for f in "${ERROR_FILES[@]}"; do
        echo "   - $f"
    done | head -10
    if [ ${#ERROR_FILES[@]} -gt 10 ]; then
        echo "   ... and $((${#ERROR_FILES[@]} - 10)) more"
    fi
    echo
fi

echo "═══════════════════════════════════════════════"
echo "🔍 Identifying Capability Gaps"
echo "═══════════════════════════════════════════════"
echo

# Detailed analysis of a few problematic files
echo "Analyzing problematic files for improvement opportunities..."
echo

if [ ${#EXEC_ERROR_FILES[@]} -gt 0 ]; then
    echo "🔬 Sample execution errors (first 3):"
    for f in "${EXEC_ERROR_FILES[@]:0:3}"; do
        echo
        echo "File: $f"
        ./target/release/sis-pdf scan --json "$PAYLOAD_DIR/$f" 2>&1 | \
            jq -r '.dynamic_signals.errors[]?' 2>/dev/null | head -5 || echo "  (Could not extract error details)"
    done
fi

echo
echo "💡 Recommendations:"
echo "   1. Review timeout files - may need loop detection or execution limits"
echo "   2. Check execution errors for missing APIs or unsupported patterns"
echo "   3. Consider increasing limits for skipped files if memory allows"
echo

# Generate detailed JSON report for further analysis
echo "📝 Generating detailed report..."
echo "Saving to: $REPORT_FILE"

cat > "$REPORT_FILE" <<EOF
{
  "test_run": {
    "timestamp": "$(date -Iseconds)",
    "total_tested": $FILE_COUNT,
    "successful": $SUCCESSFUL,
    "execution_errors": $EXECUTION_ERRORS,
    "timeouts": $TIMEOUTS,
    "skipped": $SKIPPED,
    "analysis_errors": $ERRORS
  },
  "problematic_files": {
    "timeouts": $(printf '%s\n' "${TIMEOUT_FILES[@]}" | jq -R . | jq -s .),
    "skipped": $(printf '%s\n' "${SKIP_FILES[@]}" | jq -R . | jq -s .),
    "errors": $(printf '%s\n' "${ERROR_FILES[@]}" | jq -R . | jq -s .),
    "execution_errors": $(printf '%s\n' "${EXEC_ERROR_FILES[@]}" | jq -R . | jq -s .)
  }
}
EOF

echo
echo "✅ Testing complete!"
echo
echo "Next steps:"
echo "  1. Review detailed report: $REPORT_FILE"
echo "  2. Analyze specific failures:"
echo "     ./target/release/sis-pdf scan --json extracted_js/payloads/<filename>"
echo "  3. Run full bulk analysis:"
echo "     python3 extract_js_payloads.py dummy_dir --output extracted_js --create-test-suite"
echo "     cd extracted_js && python3 run_bulk_tests.py payloads/ --workers 8"

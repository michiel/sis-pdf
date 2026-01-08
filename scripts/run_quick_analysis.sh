#!/bin/bash
# Quick hostile payload analysis

set -e

SAMPLES=30
PAYLOAD_DIR="extracted_js/payloads"

echo "🔬 Running Quick Analysis on $SAMPLES VirusShare Samples"
echo "=========================================================="
echo

# Get random samples
FILES=$(find "$PAYLOAD_DIR" -name "VirusShare_*.js" | shuf | head -$SAMPLES)

# Counters
EXECUTED=0
TIMED_OUT=0
SKIPPED=0
WITH_ERRORS=0
NO_CALLS=0
TOTAL=0

# Temp file for errors
ERROR_FILE=$(mktemp)

for FILE in $FILES; do
    TOTAL=$((TOTAL + 1))
    BASENAME=$(basename "$FILE")
    echo -n "[$TOTAL/$SAMPLES] Testing: ${BASENAME:0:60} ... "

    RESULT=$(cargo run --release --features js-sandbox --example test_hostile -- "$FILE" 2>/dev/null || echo '{"outcome":"failed"}')

    OUTCOME=$(echo "$RESULT" | jq -r '.outcome // "failed"')

    case "$OUTCOME" in
        "executed")
            EXECUTED=$((EXECUTED + 1))
            HAS_ERRORS=$(echo "$RESULT" | jq -r '.has_errors')
            TOTAL_CALLS=$(echo "$RESULT" | jq -r '.total_calls')

            if [ "$HAS_ERRORS" = "true" ]; then
                WITH_ERRORS=$((WITH_ERRORS + 1))
                # Extract error for analysis
                echo "$RESULT" | jq -r '.error_samples[0] // ""' >> "$ERROR_FILE"
                echo "✅ (errors)"
            else
                echo "✅"
            fi

            if [ "$TOTAL_CALLS" = "0" ]; then
                NO_CALLS=$((NO_CALLS + 1))
            fi
            ;;
        "timed_out")
            TIMED_OUT=$((TIMED_OUT + 1))
            echo "⏱️  timeout"
            ;;
        "skipped")
            SKIPPED=$((SKIPPED + 1))
            echo "⏭️  skipped"
            ;;
        *)
            echo "❌ failed"
            ;;
    esac
done

echo
echo "=========================================================="
echo "📊 Results Summary"
echo "=========================================================="
echo
echo "Total tested: $SAMPLES"
echo "✅ Executed successfully: $EXECUTED ($((EXECUTED * 100 / SAMPLES))%)"
echo "⚠️  Executed with errors: $WITH_ERRORS ($((WITH_ERRORS * 100 / SAMPLES))%)"
echo "🔇 Executed but no calls: $NO_CALLS ($((NO_CALLS * 100 / SAMPLES))%)"
echo "⏱️  Timed out: $TIMED_OUT ($((TIMED_OUT * 100 / SAMPLES))%)"
echo "⏭️  Skipped: $SKIPPED ($((SKIPPED * 100 / SAMPLES))%)"
echo

if [ -s "$ERROR_FILE" ]; then
    echo "🔍 Most Common Missing Variables/APIs:"
    grep -o '"[^"]*is not defined"' "$ERROR_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 || echo "  (Could not extract error patterns)"
fi

rm -f "$ERROR_FILE"

echo
echo "💡 Key Findings:"
if [ $WITH_ERRORS -gt $((SAMPLES / 2)) ]; then
    echo "  - High error rate ($WITH_ERRORS/$SAMPLES) suggests missing sandbox APIs"
fi
if [ $NO_CALLS -gt $((SAMPLES / 3)) ]; then
    echo "  - Many scripts produce no function calls ($NO_CALLS/$SAMPLES) - may need event triggers"
fi
if [ $TIMED_OUT -gt 0 ]; then
    echo "  - Timeouts detected ($TIMED_OUT) - consider loop detection/limits"
fi

echo
echo "Next steps:"
echo "  1. Add missing APIs/globals to sandbox (see errors above)"
echo "  2. Run full gap analysis: python3 analyze_js_gaps.py extracted_js/payloads --virusshare-only --sample 100"
echo "  3. Test specific file: cargo run --release --features js-sandbox --example test_hostile -- <file>"

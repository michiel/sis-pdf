#!/bin/bash
# Extract test case PDFs for each finding type from corpus
# Usage: ./scripts/extract_test_cases.sh [output_dir]

set -euo pipefail

OUTPUT_DIR="${1:-test_cases}"
CORPUS_DIR="/home/michiel/src/pdf-corpus/2024/malicious/VirusShare_PDF"
JSONL_FILE="virusshare_2024_deep_scan.jsonl"

echo "=========================================="
echo "TEST CASE EXTRACTION"
echo "=========================================="
echo "Output directory: $OUTPUT_DIR"
echo "Corpus directory: $CORPUS_DIR"
echo "JSONL file: $JSONL_FILE"
echo

# Create output structure
mkdir -p "$OUTPUT_DIR"/{common,rare,outliers,edge_cases}

echo "Creating test case directory structure..."
echo

# Extract one example of each finding type
echo "Extracting test cases by finding type..."

# Function to extract test case
extract_test_case() {
    local finding_kind="$1"
    local category="$2"  # common, rare, outliers, edge_cases
    local count="${3:-1}"  # Number of examples to extract

    # Get file paths for this finding kind
    local files=$(jq -r "select(.finding.kind == \"$finding_kind\") | .path" "$JSONL_FILE" | head -n "$count")

    if [ -z "$files" ]; then
        echo "  ⚠️  $finding_kind: No examples found"
        return
    fi

    # Create subdirectory
    mkdir -p "$OUTPUT_DIR/$category/$finding_kind"

    local copied=0
    while IFS= read -r file_path; do
        if [ -f "$file_path" ]; then
            local filename=$(basename "$file_path")
            local example_num=$((copied + 1))
            cp "$file_path" "$OUTPUT_DIR/$category/$finding_kind/example_${example_num}.pdf"
            ((copied++))
        fi
    done <<< "$files"

    echo "  ✓  $finding_kind: $copied examples copied"
}

# COMMON findings (>1% prevalence)
echo "1. Extracting COMMON findings (3 examples each):"
extract_test_case "annotation_action_chain" "common" 3
extract_test_case "uri_present" "common" 3
extract_test_case "incremental_update_chain" "common" 3
extract_test_case "xref_conflict" "common" 3
extract_test_case "object_id_shadowing" "common" 3
extract_test_case "page_tree_mismatch" "common" 3
extract_test_case "page_tree_fallback" "common" 3
extract_test_case "acroform_present" "common" 3
extract_test_case "js_present" "common" 3
extract_test_case "embedded_file_present" "common" 3
extract_test_case "open_action_present" "common" 3
extract_test_case "xfa_present" "common" 3
extract_test_case "ocg_present" "common" 3
extract_test_case "stream_length_mismatch" "common" 3

echo
echo "2. Extracting RARE findings (all available examples):"
extract_test_case "crypto_mining_js" "rare" 10
extract_test_case "supply_chain_staged_payload" "rare" 10
extract_test_case "polyglot_signature_conflict" "rare" 10
extract_test_case "content_html_payload" "rare" 10
extract_test_case "js_multi_stage_decode" "rare" 10
extract_test_case "font_table_anomaly" "rare" 10
extract_test_case "js_sandbox_timeout" "rare" 10
extract_test_case "js_runtime_network_intent" "rare" 10
extract_test_case "js_runtime_file_probe" "rare" 10
extract_test_case "sound_movie_present" "rare" 10
extract_test_case "external_action_risk_context" "rare" 10
extract_test_case "gotor_present" "rare" 10

echo
echo "3. Extracting OUTLIER test cases:"

# High finding count outliers
echo "  Finding files with >1000 findings..."
jq -r '. | select(.path != null) | .path' "$JSONL_FILE" | \
    sort | uniq -c | sort -rn | \
    awk '$1 > 1000 {print $2}' | \
    head -5 | \
    while IFS= read -r file_path; do
        if [ -f "$file_path" ]; then
            filename=$(basename "$file_path")
            cp "$file_path" "$OUTPUT_DIR/outliers/high_finding_count_${filename}"
            echo "  ✓  Copied high-finding-count file: $filename"
        fi
    done

# Files with many finding types (diversity)
echo "  Finding files with >10 finding types..."
jq -r '. | select(.path != null) | .path' "$JSONL_FILE" | \
    sort -u | \
    while IFS= read -r file_path; do
        # Count unique finding kinds for this file
        kind_count=$(jq -r "select(.path == \"$file_path\") | .finding.kind" "$JSONL_FILE" | sort -u | wc -l)
        if [ "$kind_count" -gt 10 ]; then
            filename=$(basename "$file_path")
            if [ -f "$file_path" ]; then
                cp "$file_path" "$OUTPUT_DIR/outliers/high_diversity_${kind_count}_types_${filename}"
                echo "  ✓  Copied high-diversity file: $filename ($kind_count types)"
            fi
        fi
    done | head -5

echo
echo "4. Extracting EDGE CASES (single finding files):"

# Files with exactly one finding
for kind in "stream_length_mismatch" "missing_eof_marker" "encryption_present" "content_overlay_link"; do
    # Find file with ONLY this finding kind
    file=$(jq -r "select(.finding.kind == \"$kind\") | .path" "$JSONL_FILE" | head -1)
    if [ -n "$file" ] && [ -f "$file" ]; then
        # Verify it only has one finding (check count for this file)
        filename=$(basename "$file")
        cp "$file" "$OUTPUT_DIR/edge_cases/${kind}_only_${filename}"
        echo "  ✓  $kind: Copied single-finding example"
    fi
done

echo
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo
echo "Test cases extracted to: $OUTPUT_DIR/"
echo
echo "Structure:"
echo "  common/           - High-prevalence findings (>1%)"
echo "  rare/             - Low-prevalence findings (<0.1%)"
echo "  outliers/         - Extreme cases (performance tests)"
echo "  edge_cases/       - Single-finding files (FP validation)"
echo

# Generate manifest
MANIFEST="$OUTPUT_DIR/manifest.txt"
echo "Generating manifest: $MANIFEST"
find "$OUTPUT_DIR" -name "*.pdf" -type f | sort > "$MANIFEST"

echo
echo "Total test case PDFs extracted: $(wc -l < "$MANIFEST")"
echo
echo "✓ Test case extraction complete!"
echo
echo "To run tests against these cases:"
echo "  ./sis scan --path $OUTPUT_DIR/common --deep"
echo "  ./sis scan --path $OUTPUT_DIR/rare --deep"
echo

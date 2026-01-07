#!/bin/bash
# Quick JavaScript Payload Testing Script
# Usage: ./quick_js_test.sh <pdf_directory> [output_directory]

set -e

PDF_DIR="${1}"
OUTPUT_DIR="${2:-extracted_js_$(date +%Y%m%d_%H%M%S)}"

if [ -z "$PDF_DIR" ]; then
    echo "Usage: $0 <pdf_directory> [output_directory]"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/malicious/pdfs"
    echo "  $0 /path/to/malicious/pdfs my_results"
    echo ""
    exit 1
fi

if [ ! -d "$PDF_DIR" ]; then
    echo "❌ Directory not found: $PDF_DIR"
    exit 1
fi

echo "🔍 Starting JavaScript payload extraction..."
echo "📁 PDF directory: $PDF_DIR"
echo "📁 Output directory: $OUTPUT_DIR"
echo ""

# Check if sis-pdf is built
echo "🔨 Building sis-pdf..."
cargo build -p sis-pdf --release

# Run the extraction
echo "📤 Extracting JavaScript payloads..."
python3 extract_js_payloads.py "$PDF_DIR" --output "$OUTPUT_DIR" --create-test-suite

echo ""
echo "✅ Extraction complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Review extraction summary: $OUTPUT_DIR/extraction_summary.json"
echo "   2. Examine payloads: $OUTPUT_DIR/payloads/"
echo "   3. Run bulk analysis: cd $OUTPUT_DIR && python3 run_bulk_tests.py payloads/"
echo ""
echo "🔬 For individual payload testing:"
echo "   cargo run -p sis-pdf -- scan --json $OUTPUT_DIR/payloads/sample.js"
echo ""
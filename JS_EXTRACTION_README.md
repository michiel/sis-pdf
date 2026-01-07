# JavaScript Payload Extraction & Bulk Testing

This toolkit extracts JavaScript payloads from potentially malicious PDF files and runs comprehensive static and dynamic analysis using the enhanced sis-pdf JavaScript sandbox.

## Quick Start

```bash
# Extract JS from all PDFs in a directory
./quick_js_test.sh /path/to/suspicious/pdfs

# Or use the Python script directly
python3 extract_js_payloads.py /path/to/suspicious/pdfs --output my_results
```

## Tools Overview

### 1. `extract_js_payloads.py` - Main Extraction Tool

**Purpose**: Extracts JavaScript payloads from PDF files and prepares them for bulk analysis.

**Features**:
- Concurrent processing of multiple PDFs
- JSON-formatted extraction with metadata
- Fallback extraction for edge cases
- Comprehensive error handling and reporting
- Automatic deduplication based on content hashes
- Generates detailed summary statistics

**Usage**:
```bash
python3 extract_js_payloads.py <pdf_directory> [options]

Options:
  --output, -o DIR          Output directory (default: extracted_js)
  --pattern PATTERN         File pattern to match (default: *.pdf)
  --workers, -w NUM         Number of worker threads (default: 4)
  --sis-binary CMD          Command to run sis-pdf (default: cargo run --features js-sandbox --)
  --create-test-suite       Create bulk test suite scripts
```

**Example**:
```bash
python3 extract_js_payloads.py /home/user/malicious_pdfs \
  --output analysis_2024 \
  --workers 8 \
  --create-test-suite
```

### 2. `quick_js_test.sh` - Simplified Workflow

**Purpose**: One-command extraction and setup for JavaScript analysis.

**Features**:
- Automatic sis-pdf building
- Extraction with test suite creation
- Clear next-steps guidance

**Usage**:
```bash
./quick_js_test.sh <pdf_directory> [output_directory]
```

### 3. `run_bulk_tests.py` - Bulk Analysis Suite

**Purpose**: Runs comprehensive static and dynamic analysis on extracted payloads.

**Features**:
- Concurrent analysis of JavaScript files
- Enhanced sandbox testing with our new variable promotion system
- Detailed finding classification and reporting
- Performance metrics and error analysis

**Usage** (auto-created by extraction script):
```bash
cd extracted_js/
python3 run_bulk_tests.py payloads/ --workers 4
```

## Output Structure

```
extracted_js/
├── payloads/                    # Extracted JavaScript files
│   ├── malware1_abc12345_0_def67890.js
│   ├── malware2_fed98765_0_bac54321.js
│   └── ...
├── reports/                     # Individual PDF scan reports
├── test_results/                # Bulk analysis results
│   └── bulk_analysis_results.json
├── extraction_summary.json     # Overall extraction statistics
└── run_bulk_tests.py           # Generated test suite
```

## File Naming Convention

JavaScript files are named using the pattern:
```
{pdf_basename}_{pdf_hash}_{index}_{js_hash}.js
```

Where:
- `pdf_basename`: Original PDF filename (without extension)
- `pdf_hash`: 8-character hash of PDF path for uniqueness
- `index`: JavaScript payload index within the PDF (0, 1, 2...)
- `js_hash`: 8-character hash of JavaScript content for deduplication

## Enhanced JavaScript Sandbox Testing

The extracted payloads will be tested using our enhanced JavaScript sandbox that includes:

### Variable Promotion System
- Automatically promotes variables declared in `eval()` contexts to global scope
- Handles obfuscated variable patterns like `M7pzjRpdcM5RVyTMS`
- Prevents "variable is not defined" runtime errors

### Error Recovery
- Continues execution despite undefined variable errors
- Creates fallback variables for common obfuscation patterns
- Comprehensive error logging without terminating analysis

### Enhanced Global Environment
- Complete `String.fromCharCode` implementation with tracking
- `escape`/`unescape` functions for URL encoding/decoding
- `console` object for compatibility
- PDF-specific globals (`app`, `doc`, etc.)

### Advanced Detection Capabilities
- Function call tracking with argument capture
- Property access monitoring
- Network intent detection
- File operation identification
- Obfuscation pattern recognition

## Analysis Results

### Extraction Summary (`extraction_summary.json`)
```json
{
  "extraction_summary": {
    "total_pdfs": 150,
    "pdfs_with_js": 89,
    "total_payloads": 127,
    "total_errors": 5
  },
  "payload_stats": {
    "count": 127,
    "size_min": 45,
    "size_max": 65536,
    "size_avg": 2847.3,
    "unique_hashes": 103
  },
  "error_analysis": {
    "Process timed out": 2,
    "Extract failed": 3
  }
}
```

### Bulk Analysis Results (`bulk_analysis_results.json`)
```json
[
  {
    "filename": "malware_sample_0_abc123.js",
    "dynamic_analysis": {
      "findings": [
        {
          "detector": "js_sandbox",
          "severity": "high",
          "confidence": 0.95,
          "description": "Suspicious JavaScript execution patterns",
          "metadata": {
            "calls": ["eval", "String.fromCharCode", "unescape"],
            "variables_promoted": ["obfuscatedVar1", "hiddenPayload"],
            "execution_time": 15
          }
        }
      ]
    }
  }
]
```

## Performance Considerations

### Recommended Settings

**For large datasets (>1000 PDFs)**:
```bash
python3 extract_js_payloads.py large_dataset/ \
  --workers 16 \
  --output large_analysis
```

**For detailed analysis**:
```bash
# Extract with comprehensive testing
python3 extract_js_payloads.py samples/ --create-test-suite

# Run analysis with detailed logging
cd extracted_js/
python3 run_bulk_tests.py payloads/ --workers 8
```

### Memory and Timeout Handling

- Large PDFs are processed with 120-second timeouts
- JavaScript execution limited to 30 seconds per payload
- Memory usage scales with worker count (recommend 2GB per 4 workers)
- Failed extractions are logged but don't stop the overall process

## Troubleshooting

### Common Issues

**"No JavaScript found"**: 
- PDF may not contain JavaScript
- JavaScript may be heavily obfuscated or encrypted
- Try manual extraction: `cargo run --features js-sandbox -- extract --js sample.pdf`

**"Process timed out"**:
- Large or complex PDF taking too long
- Reduce worker count or increase system resources
- Check for corrupted PDF files

**"Failed to parse JSON"**:
- sis-pdf output format may have changed
- Extraction falls back to raw mode automatically

### Debugging Individual Files

```bash
# Manual extraction for debugging
cargo run --features js-sandbox -- extract --js --json problematic.pdf

# Manual analysis with verbose output
cargo run --features js-sandbox -- scan --json extracted_payload.js
```

## Integration with CI/CD

The extraction and testing tools can be integrated into automated security pipelines:

```bash
#!/bin/bash
# Example CI integration
python3 extract_js_payloads.py /incoming/pdfs/ --output /results/
cd /results/
python3 run_bulk_tests.py payloads/ --workers $(nproc)

# Generate alerts for high-severity findings
jq '.[] | select(.dynamic_analysis.findings[]?.severity == "high")' \
  test_results/bulk_analysis_results.json > alerts.json
```

## Advanced Usage

### Custom Analysis Pipelines

The extracted JavaScript files can be analyzed with external tools:

```bash
# Run with additional static analyzers
for js_file in extracted_js/payloads/*.js; do
    echo "Analyzing: $js_file"
    
    # sis-pdf enhanced sandbox
    cargo run --features js-sandbox -- scan --json "$js_file"
    
    # Additional tools (examples)
    # eslint "$js_file"
    # js-beautify "$js_file"
    # custom_malware_scanner "$js_file"
done
```

### Payload Clustering

Group similar payloads for family analysis:

```bash
# Extract hashes for clustering
jq -r '.extraction_results[].payloads[].hash' extraction_summary.json | sort | uniq -c | sort -nr
```

This toolkit provides a comprehensive foundation for JavaScript malware analysis using the enhanced sis-pdf sandbox with variable promotion and error recovery capabilities.
# JavaScript Payload Extraction & Analysis Toolkit

This toolkit provides comprehensive JavaScript extraction, testing, and analysis capabilities for PDF malware detection using the enhanced sis-pdf JavaScript sandbox.

## Table of Contents
- [Quick Start](#quick-start)
- [Tools Overview](#tools-overview)
- [Enhanced Sandbox Capabilities](#enhanced-sandbox-capabilities)
- [Testing Workflows](#testing-workflows)
- [Output Structure](#output-structure)
- [Analysis Results](#analysis-results)
- [Performance Considerations](#performance-considerations)

## Quick Start

### Extract JS from PDFs and Run Quick Analysis
```bash
# Extract JS from all PDFs in a directory
./scripts/quick_js_test.sh /path/to/suspicious/pdfs

# Run quick analysis on extracted hostile payloads (30 samples)
./scripts/run_quick_analysis.sh

# Deep gap analysis to identify sandbox improvements
python3 scripts/analyze_js_gaps.py --virusshare-only --sample 100
```

### Direct Testing
```bash
# Test a single JavaScript file through the sandbox
cargo run --release --features js-sandbox --example test_hostile -- extracted_js/payloads/<file.js>

# Interactive batch testing with multiple modes
./scripts/test_hostile_payloads.sh
```

## Tools Overview

### 1. `extract_js_payloads.py` - PDF JavaScript Extraction

**Location**: `./scripts/extract_js_payloads.py`

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
python3 scripts/extract_js_payloads.py <pdf_directory> [options]

Options:
  --output, -o DIR          Output directory (default: extracted_js)
  --pattern PATTERN         File pattern to match (default: *.pdf)
  --workers, -w NUM         Number of worker threads (default: 4)
  --sis-binary CMD          Command to run sis-pdf (default: cargo run --features js-sandbox --)
  --create-test-suite       Create bulk test suite scripts
```

**Example**:
```bash
python3 scripts/extract_js_payloads.py /home/user/malicious_pdfs \
  --output analysis_2024 \
  --workers 8 \
  --create-test-suite
```

### 2. `quick_js_test.sh` - Simplified Extraction Workflow

**Location**: `./scripts/quick_js_test.sh`

**Purpose**: One-command extraction and setup for JavaScript analysis.

**Features**:
- Automatic sis-pdf building
- Extraction with test suite creation
- Clear next-steps guidance

**Usage**:
```bash
./scripts/quick_js_test.sh <pdf_directory> [output_directory]
```

### 3. `run_quick_analysis.sh` - Quick Hostile Payload Testing

**Location**: `./scripts/run_quick_analysis.sh`

**Purpose**: Rapidly tests a sample of extracted JavaScript payloads to assess sandbox coverage.

**Features**:
- Tests 30 random VirusShare samples by default (configurable)
- Categorizes results: executed, errors, timeouts, skipped
- Identifies most common missing APIs/globals
- Provides actionable recommendations
- Can be customized for different sample sizes

**Usage**:
```bash
# Test 30 samples (default)
./scripts/run_quick_analysis.sh

# Modify for larger samples
sed -i 's/SAMPLES=30/SAMPLES=100/' scripts/run_quick_analysis.sh
./scripts/run_quick_analysis.sh
```

### 4. `test_hostile_payloads.sh` - Interactive Testing Tool

**Location**: `./scripts/test_hostile_payloads.sh`

**Purpose**: Interactive script for comprehensive testing with multiple modes.

**Features**:
- Multiple test modes: 10/100/all VirusShare, all payloads
- Real-time progress tracking
- Detailed categorization of outcomes
- Generates JSON reports for analysis
- Sample file inspection for problematic payloads

**Usage**:
```bash
./scripts/test_hostile_payloads.sh
# Then select test mode interactively
```

### 5. `analyze_js_gaps.py` - Sandbox Gap Analysis

**Location**: `./scripts/analyze_js_gaps.py`

**Purpose**: Identifies missing sandbox APIs and capabilities by analyzing execution failures.

**Features**:
- Identifies missing/incomplete APIs
- Analyzes error patterns (ReferenceError, TypeError, etc.)
- Detects timeout causes (loops, recursion, eval chains)
- Provides specific implementation recommendations
- Generates detailed JSON reports

**Usage**:
```bash
# Analyze VirusShare samples
python3 scripts/analyze_js_gaps.py --virusshare-only --sample 100

# Analyze all payloads
python3 scripts/analyze_js_gaps.py extracted_js/payloads --sample 200

# Analyze specific pattern
python3 scripts/analyze_js_gaps.py extracted_js/payloads --pattern "VirusShare_*.js"
```

**Options**:
```
--sample N                  Analyze N random samples
--pattern PATTERN           File pattern to match (default: *.js)
--virusshare-only          Only analyze VirusShare files
--output PATH              Output file for detailed report
```

### 6. `test_hostile` - Rust Example for Direct Testing

**Location**: `crates/js-analysis/examples/test_hostile.rs`

**Purpose**: Direct Rust-based testing of JavaScript files through the sandbox.

**Usage**:
```bash
cargo run --release --features js-sandbox --example test_hostile -- <js_file>
```

**Output**: JSON-formatted results including:
- Execution outcome (executed/timed_out/skipped)
- Function calls detected
- Errors encountered
- Behavioral patterns identified
- Execution time

## Enhanced Sandbox Capabilities

The JavaScript sandbox has been significantly enhanced with comprehensive PDF and JavaScript runtime simulation:

### 1. Variable Promotion System
- Automatically promotes variables declared in `eval()` contexts to global scope
- Handles obfuscated variable patterns
- Prevents "variable is not defined" runtime errors
- Tracks variable promotions for behavioral analysis

### 2. Error Recovery
- Continues execution despite undefined variable errors
- Creates fallback variables for common obfuscation patterns
- Comprehensive error logging without terminating analysis
- Error recovery tracking for malware behavior detection

### 3. Complete PDF Environment

**Global Metadata Properties**:
```javascript
creator, producer, title, author, subject, keywords
```

**Event Object Simulation**:
```javascript
event = {
    target: {
        parseInt: [Function],
        eval: [Function],
        getField: [Function],
        print: [Function],
        value: "",
        name: "TextField"
    },
    name: "Open",
    type: "Page",
    value: "",
    willCommit: false,
    rc: true
}
```

**Document Objects**:
- `doc` - Document object with info properties
- `app` - Application object with methods (alert, launchURL, etc.)
- `thisDoc` - Alternative document reference
- `info` - Document metadata object
- `t` - Event alias (commonly used in malware)

**String Encoding Functions**:
- `escape()` - URL encoding
- `unescape()` - URL decoding
- `String.fromCharCode()` - Character code conversion

### 4. Advanced Detection Capabilities
- Function call tracking with argument capture
- Property access monitoring
- Network intent detection
- File operation identification
- Obfuscation pattern recognition
- Behavioral pattern analysis

### 5. Execution Limits & Safety
- Loop iteration limits (100,000 iterations)
- Recursion limits (128 levels)
- Stack size limits (512KB)
- Timeout protection (configurable, default 5s)
- Size limits (configurable, default 64KB)

## Testing Workflows

### Workflow 1: Quick Coverage Assessment
```bash
# 1. Build with sandbox features
cargo build --release --features js-sandbox

# 2. Run quick analysis on extracted payloads
./scripts/run_quick_analysis.sh

# 3. Review results
# - Check execution success rate (aim for >90%)
# - Identify missing APIs in output
# - Note timeout and skipped rates
```

### Workflow 2: Comprehensive Gap Analysis
```bash
# 1. Run gap analysis on larger sample
python3 scripts/analyze_js_gaps.py --virusshare-only --sample 200

# 2. Review detailed report
cat extracted_js/test_results/gap_analysis.json

# 3. Implement missing APIs based on recommendations

# 4. Re-test to verify improvements
./scripts/run_quick_analysis.sh
```

### Workflow 3: Individual File Investigation
```bash
# 1. Identify problematic file from batch results
./scripts/run_quick_analysis.sh | grep "errors"

# 2. Test file directly for detailed output
cargo run --release --features js-sandbox --example test_hostile -- \
    extracted_js/payloads/<problematic_file.js>

# 3. Examine the JavaScript source
cat extracted_js/payloads/<problematic_file.js>

# 4. Add necessary sandbox capabilities

# 5. Retest
cargo run --release --features js-sandbox --example test_hostile -- \
    extracted_js/payloads/<problematic_file.js>
```

### Workflow 4: Full Dataset Analysis
```bash
# 1. Extract all JavaScript from PDF corpus
python3 scripts/extract_js_payloads.py /path/to/pdfs \
    --output full_analysis \
    --workers 16 \
    --create-test-suite

# 2. Run comprehensive testing
cd full_analysis
python3 run_bulk_tests.py payloads/ --workers 8

# 3. Analyze results
python3 ../scripts/analyze_js_gaps.py payloads/ --sample 500

# 4. Generate reports
jq '.[] | select(.dynamic_analysis.findings[]?.severity == "high")' \
    test_results/bulk_analysis_results.json > high_severity.json
```

## Output Structure

```
extracted_js/
├── payloads/                           # Extracted JavaScript files
│   ├── malware1_abc12345_0_def67890.js
│   ├── VirusShare_xxx_0_yyy.js
│   └── ...
├── reports/                            # Individual PDF scan reports
│   └── <pdf_hash>.json
├── test_results/                       # Analysis results
│   ├── bulk_analysis_results.json
│   ├── gap_analysis.json
│   └── hostile_analysis_<timestamp>.json
├── extraction_summary.json             # Overall extraction statistics
└── run_bulk_tests.py                   # Generated test suite (optional)
```

### File Naming Convention

JavaScript files use the pattern:
```
{pdf_basename}_{pdf_hash}_{index}_{js_hash}.js
```

Where:
- `pdf_basename`: Original PDF filename (without extension)
- `pdf_hash`: 8-character hash of PDF path for uniqueness
- `index`: JavaScript payload index within the PDF (0, 1, 2...)
- `js_hash`: 8-character hash of JavaScript content for deduplication

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

### Gap Analysis Report (`gap_analysis.json`)
```json
{
  "summary": {
    "files_analyzed": 100,
    "total_missing_apis": 15,
    "total_timeouts": 5,
    "total_errors": 25
  },
  "missing_apis": {
    "ActiveXObject": 10,
    "WScript.Shell": 8,
    "document.write": 5
  },
  "error_patterns": {
    "ReferenceError": 15,
    "TypeError": 8,
    "SyntaxError": 2
  },
  "timeout_characteristics": [
    {
      "file": "sample.js",
      "has_while_loop": true,
      "has_eval": true
    }
  ]
}
```

### Quick Analysis Output
```
📊 Results Summary
==========================================================

Total tested: 30
✅ Executed successfully: 29 (96%)
⚠️  Executed with errors: 14 (46%)
🔇 Executed but no calls: 21 (70%)
⏱️  Timed out: 0 (0%)
⏭️  Skipped: 1 (3%)

🔍 Most Common Missing Variables/APIs:
      1 "keywords is not defined"

💡 Key Findings:
  - Many scripts produce no function calls (21/30) - may need event triggers
```

## Performance Considerations

### Recommended Settings

**For large datasets (>1000 PDFs)**:
```bash
python3 scripts/extract_js_payloads.py large_dataset/ \
  --workers 16 \
  --output large_analysis
```

**For detailed analysis**:
```bash
# Extract with comprehensive testing
python3 scripts/extract_js_payloads.py samples/ --create-test-suite

# Run analysis with detailed logging
cd extracted_js/
python3 run_bulk_tests.py payloads/ --workers 8
```

### Memory and Timeout Handling

- Large PDFs are processed with 120-second timeouts
- JavaScript execution limited to configurable timeouts (default 5s per payload)
- Memory usage scales with worker count (recommend 2GB per 4 workers)
- Failed extractions are logged but don't stop the overall process

### Performance Tuning

**Sandbox Limits** (configurable in `DynamicOptions`):
```rust
DynamicOptions {
    max_bytes: 64 * 1024,           // Max JS file size
    timeout_ms: 5000,                // Execution timeout
    max_call_args: 100,              // Max tracked call arguments
    max_args_per_call: 10,           // Max args per single call
    max_arg_preview: 200,            // Max preview length
    max_urls: 50,                    // Max URLs to track
    max_domains: 25,                 // Max domains to track
}
```

**Loop Limits** (set in sandbox initialization):
```rust
limits.set_loop_iteration_limit(100_000);    // Prevent infinite loops
limits.set_recursion_limit(128);             // Prevent stack overflow
limits.set_stack_size_limit(512 * 1024);     // Memory safety
```

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

**High error rate in testing**:
- Check gap analysis for missing APIs
- Review error messages for patterns
- Add missing globals/functions to sandbox

**No function calls detected**:
- Scripts may require specific event triggers
- Check if scripts have conditional execution
- Review behavioral patterns in detailed output

### Debugging Individual Files

```bash
# Manual extraction for debugging
cargo run --features js-sandbox -- extract --js --json problematic.pdf

# Manual analysis with verbose output
cargo run --features js-sandbox -- scan --json extracted_payload.js

# Direct sandbox testing with full error output
cargo run --release --features js-sandbox --example test_hostile -- file.js
```

## Integration with CI/CD

The extraction and testing tools can be integrated into automated security pipelines:

```bash
#!/bin/bash
# Example CI integration
python3 scripts/extract_js_payloads.py /incoming/pdfs/ --output /results/
cd /results/
python3 run_bulk_tests.py payloads/ --workers $(nproc)

# Generate alerts for high-severity findings
jq '.[] | select(.dynamic_analysis.findings[]?.severity == "high")' \
  test_results/bulk_analysis_results.json > alerts.json

# Track sandbox coverage over time
python3 scripts/analyze_js_gaps.py payloads/ --sample 100 \
    --output coverage_$(date +%Y%m%d).json
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
jq -r '.extraction_results[].payloads[].hash' extraction_summary.json | \
    sort | uniq -c | sort -nr

# Group by similar patterns
python3 scripts/analyze_js_gaps.py payloads/ --sample 500 | \
    jq '.missing_apis' > api_patterns.json
```

### Continuous Monitoring

```bash
#!/bin/bash
# Monitor sandbox effectiveness over time

DATE=$(date +%Y%m%d)
python3 scripts/analyze_js_gaps.py --virusshare-only --sample 100 \
    --output "metrics/gap_analysis_${DATE}.json"

# Extract key metrics
SUCCESS_RATE=$(jq '.summary.files_analyzed - .summary.total_errors' \
    "metrics/gap_analysis_${DATE}.json")
echo "Success rate: $SUCCESS_RATE"
```

## Contributing

When adding new sandbox capabilities:

1. Test with hostile payloads first: `./scripts/run_quick_analysis.sh`
2. Add missing APIs/globals based on gap analysis
3. Verify improvements: `python3 scripts/analyze_js_gaps.py --sample 100`
4. Update this README with new capabilities
5. Run full test suite: `cargo test --features js-sandbox`

## Key Metrics for Sandbox Quality

- **Execution Success Rate**: >90% is excellent, >80% is good
- **Error Rate**: <10% is excellent, <20% is acceptable
- **Timeout Rate**: <5% is good, <10% is acceptable
- **API Coverage**: Track missing APIs over time, aim for continuous reduction

This toolkit provides a comprehensive foundation for JavaScript malware analysis using the enhanced sis-pdf sandbox with variable promotion, error recovery, and extensive PDF environment simulation.

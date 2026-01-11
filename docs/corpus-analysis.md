# Corpus Analysis Workflow

This document describes how to perform large-scale corpus analysis to evaluate parser health, finding coverage, and identify problem files for tooling improvement.

## Overview

Running SIS on a large corpus (thousands of PDFs) helps:
- Identify parser crashes, errors, and edge cases
- Measure finding coverage across real-world malware
- Detect anomalies and malformed PDFs that need better handling
- Prioritize tooling improvements based on actual failure modes

## Sample Corpus: 21,898 Potentially Malicious PDFs

Location: `/home/michiel/src/pdf-corpus/2022/malicious`
Size: 792MB (avg ~36KB per file)
Source: Mixed corpus (2011 + 2017 samples, hash-named)

This is an **excellent sample size** for:
- Statistical significance across finding types
- Parser stress testing
- Performance profiling at scale

---

## Stage 1: Fast Triage (No ML)

**Goal**: Process all files quickly to identify parser issues and measure basic coverage.

### Build in release mode
```bash
cd /home/michiel/dev/sis-pdf
cargo build --release
```

### Run corpus scan (parallel, JSONL output)
```bash
./target/release/sis scan \
  --path /home/michiel/src/pdf-corpus/2022/malicious \
  --glob "*.pdf" \
  --jsonl-findings \
  > malicious_fast_scan.jsonl 2> scan_errors.log
```

**Options explained**:
- `--path`: Directory to scan recursively
- `--glob "*.pdf"`: Match all PDF files
- `--jsonl-findings`: One JSON object per file with findings
- No `--ml`: Skip ML inference (fast first pass)
- **Parallel processing**: Enabled by default (uses all available CPU cores)
  - To disable: add `--sequential` flag (only for debugging crashes)
  - Configure via `~/.config/sis/config.toml`: `parallel = true` under `[scan]`

**Expected runtime**: 2-6 hours (1-3 files/second depending on hardware)

**Monitor progress** (in another terminal):
```bash
# Watch line count grow
watch -n 5 'wc -l malicious_fast_scan.jsonl scan_errors.log'

# Check recent errors
tail -f scan_errors.log
```

---

## Stage 2: Analyze Results

### Overall coverage and parser health
```bash
./scripts/analyze_corpus.py malicious_fast_scan.jsonl
```

**Output includes**:
- Total files scanned and finding coverage %
- Parser errors and strict deviation counts
- Attack surface breakdown (JS, actions, embedded files)
- Top 30 most common findings
- Rare findings (potential novel techniques or false positives)

### Extract problem files
```bash
./scripts/extract_problem_files.py scan_errors.log
```

**Identifies**:
- Crashes and panics (highest priority)
- Parse errors (malformed PDFs)
- Timeouts (performance edge cases)
- High-warning files (unusual structure)

**Generates file lists**:
```bash
# Created by the script output
crash_files.txt       # Parser crashes - fix these first
error_files.txt       # Parse failures - improve error handling
timeout_files.txt     # Performance issues - optimize
```

---

## Stage 3: Deep Analysis of Problem Files

### Re-scan problem files with strict mode
```bash
# Crashes (if any)
if [ -f crash_files.txt ]; then
  cat crash_files.txt | while read pdf; do
    echo "=== $pdf ===" >> crash_analysis.log
    ./target/release/sis scan "$pdf" --strict --strict-summary \
      >> crash_analysis.log 2>&1 || echo "FAILED: $pdf"
  done
fi

# Parse errors
if [ -f error_files.txt ]; then
  cat error_files.txt | while read pdf; do
    echo "=== $pdf ===" >> error_analysis.log
    ./target/release/sis scan "$pdf" --strict \
      --jsonl >> error_analysis.jsonl 2>> error_analysis.log
  done
fi
```

### Examine individual problem files
```bash
# Pick a specific problematic file
PROBLEM_PDF="/home/michiel/src/pdf-corpus/2022/malicious/0000fc3840119cade9fb2dae9576cafd3be7f923"

# Run with strict mode and full IR
./target/release/sis scan "$PROBLEM_PDF" --strict --ir --deep

# Generate full report
./target/release/sis report "$PROBLEM_PDF" --deep -o problem_report.md

# Extract JavaScript for manual analysis
./target/release/sis extract js "$PROBLEM_PDF" -o problem_js/

# Export structure
./target/release/sis export-org "$PROBLEM_PDF" --format json -o problem_org.json
```

---

## Stage 4: Finding Distribution Analysis

### Extract high-interest subsets

**Files with JavaScript obfuscation**:
```bash
grep '"id".*JS.*OBFUSCATION' malicious_fast_scan.jsonl | \
  jq -r '.path' | sort -u > js_obfuscated_files.txt
wc -l js_obfuscated_files.txt
```

**Files with no findings** (potential false negatives):
```bash
jq -r 'select((.findings | length) == 0) | .path' malicious_fast_scan.jsonl \
  > zero_findings_files.txt
wc -l zero_findings_files.txt
```

**Files with rare findings** (novel techniques):
```bash
# Findings appearing in ≤5 files
jq -r '.findings[].id' malicious_fast_scan.jsonl | \
  sort | uniq -c | sort -n | awk '$1 <= 5 {print $2}' \
  > rare_finding_ids.txt

# Get files with these rare findings
for finding_id in $(cat rare_finding_ids.txt); do
  grep "\"id\":\"$finding_id\"" malicious_fast_scan.jsonl | \
    jq -r '.path' >> rare_technique_files.txt
done
sort -u rare_technique_files.txt -o rare_technique_files.txt
```

**Files with action chains**:
```bash
grep '"id".*ACTION' malicious_fast_scan.jsonl | \
  jq -r '.path' | sort -u > action_chain_files.txt
```

---

## Stage 5: Tooling Improvement Priorities

Based on the analysis, prioritize fixes:

### Priority 1: Crashes
- Files in `crash_files.txt`
- Create minimal reproducers
- Add fuzz corpus entries
- Fix parser panics

### Priority 2: Parse Errors
- Files in `error_files.txt`
- Analyze common malformation patterns
- Improve error recovery
- Add tolerance for common deviations

### Priority 3: Zero Findings
- Files in `zero_findings_files.txt`
- Manual inspection needed
- May be benign (false label) or detection gap
- Extract JS/embedded files to verify

### Priority 4: Performance
- Files in `timeout_files.txt`
- Profile with `--ir` and check object counts
- Identify decompression bombs or recursive structures
- Add circuit breakers if needed

---

## Stage 6: Comparative Analysis (Optional)

### Generate feature vectors for ML training
```bash
./target/release/sis export-features \
  --path /home/michiel/src/pdf-corpus/2022/malicious \
  > malicious_features.jsonl 2> features_errors.log
```

### Compare with benign corpus (if available)
```bash
# Scan benign corpus
./target/release/sis scan \
  --path /path/to/benign/pdfs \
  --jsonl-findings \
  > benign_scan.jsonl 2> benign_errors.log

# Compare finding distributions
./scripts/analyze_corpus.py benign_scan.jsonl > benign_analysis.txt
./scripts/analyze_corpus.py malicious_fast_scan.jsonl > malicious_analysis.txt
diff -u benign_analysis.txt malicious_analysis.txt
```

---

## Expected Outcomes

After completing this workflow, you should have:

1. **Parser Health Report**
   - Crash rate and error rate
   - Common malformation patterns
   - Performance bottlenecks

2. **Finding Coverage Report**
   - Distribution of 72+ finding types
   - Most common malicious indicators
   - Detection gaps (zero-finding files)

3. **Problem File Lists**
   - Crashes for immediate fixing
   - Parse errors for tolerance improvements
   - Rare techniques for detector enhancements

4. **Tooling Improvement Roadmap**
   - Prioritized bug fixes
   - New detectors to add
   - Performance optimizations

---

## Notes

- **Parallel processing**:
  - **Enabled by default** - leverages all available CPU cores
  - Uses Rayon for work-stealing parallelism
  - With 24 cores, expect 12-24 files/second throughput
  - Use `--sequential` **only** when debugging crashes (much slower)
  - Configure in `~/.config/sis/config.toml` under `[scan]`: `parallel = true`
- **Memory usage**: Monitor with `htop`; each worker processes one file at a time
- **Disk space**: JSONL output ~1-5KB per file (22-110MB for 21,898 files)
- **Error logs**: Parse failures go to stderr; successful scans to stdout
- **Incremental runs**: To resume after interruption, use `comm` to diff file lists

## Resume Interrupted Scans

```bash
# Get list of all files
find /home/michiel/src/pdf-corpus/2022/malicious -name "*.pdf" | \
  sort > all_files.txt

# Get list of scanned files
jq -r '.path' malicious_fast_scan.jsonl | sort > scanned_files.txt

# Get remaining files
comm -23 all_files.txt scanned_files.txt > remaining_files.txt

# Resume scan
cat remaining_files.txt | while read pdf; do
  ./target/release/sis scan "$pdf" --jsonl \
    >> malicious_fast_scan.jsonl 2>> scan_errors.log
done
```

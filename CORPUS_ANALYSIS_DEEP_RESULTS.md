# Deep Scan Corpus Analysis Results

**Date**: 2026-01-11
**Corpus**: `/home/michiel/src/pdf-corpus/2022/malicious`
**Files**: 21,898 PDFs (792MB)
**Scan Duration**: 33 seconds (with 24 CPU cores in parallel)
**Processing Speed**: ~662 files/second

---

## Executive Summary

Deep scan completed on the same corpus with **stream decoding enabled**, revealing **24,646 additional findings** (+19.6% more than fast scan) and **8 new finding types** that require decoding to detect.

### Performance vs Fast Scan

| Metric | Fast Scan | Deep Scan | Difference |
|--------|-----------|-----------|------------|
| Duration | 8 seconds | 33 seconds | +25 seconds |
| Throughput | ~2,735 files/s | ~662 files/s | -75.8% |
| Total Findings | 125,716 | 150,362 | **+24,646 (+19.6%)** |
| Finding Types | 48 | 56 | **+8 new types** |
| Crashes | 0 | 0 | Same |
| Parse Errors | 0 | 0 | Same |

**Deep scanning is 4.1x slower but finds 19.6% more issues.**

---

## New Finding Types (Deep Scan Only)

These 8 finding types **require stream decoding** and are only detected with `--deep`:

### 1. JavaScript Sandbox Execution Analysis

| Finding Kind | Instances | Files | Coverage |
|--------------|-----------|-------|----------|
| `js_sandbox_exec` | 18,999 | 16,865 | **77.2%** |
| `js_runtime_risky_calls` | 2,660 | 2,650 | 12.1% |
| `js_runtime_file_probe` | 363 | 359 | 1.6% |
| `js_sandbox_timeout` | 50 | 50 | 0.2% |
| `js_sandbox_skipped` | 62 | 62 | 0.3% |
| `js_runtime_network_intent` | 23 | 23 | 0.1% |

**Key Insight**: Deep scan executes JavaScript in a sandbox to detect:
- **77.2%** of files have JS that executes successfully
- **12.1%** make risky API calls (app.*, util.*, etc.)
- **1.6%** probe for file system access
- **0.1%** attempt network connections

### 2. Stream Compression & Object Stream Analysis

| Finding Kind | Instances | Files | Coverage |
|--------------|-----------|-------|----------|
| `objstm_embedded_summary` | 2,118 | 421 | 1.9% |
| `decompression_ratio_suspicious` | 371 | 146 | 0.7% |

**Key Insight**:
- Object stream embedding analysis (compressed object streams)
- Suspicious decompression ratios indicating potential bombs or obfuscation

---

## Severity Distribution Comparison

| Severity | Fast Scan | Deep Scan | Difference |
|----------|-----------|-----------|------------|
| **High** | 38,682 (30.8%) | 41,736 (27.8%) | +3,054 |
| **Medium** | 55,684 (44.3%) | 56,047 (37.3%) | +363 |
| **Low** | 31,350 (24.9%) | 31,461 (20.9%) | +111 |
| **Info** | 0 | 21,118 (14.0%) | **+21,118** |

**The Info severity findings are new** - mostly from JS sandbox execution telemetry.

---

## Attack Surface Coverage Comparison

| Category | Fast Scan | Deep Scan | Difference |
|----------|-----------|-----------|------------|
| Files with JavaScript | 17,846 (81.7%) | 18,087 (82.8%) | +241 files |
| Files with Actions | 16,164 (74.0%) | 16,164 (74.0%) | Same |
| Files with Embedded Files | 2,219 (10.2%) | 2,587 (11.8%) | +368 files |

**Deep scan found more JS** (through decoding) and **more embedded files** (through stream expansion).

---

## Performance Analysis

### Throughput Breakdown

**Fast Scan**:
- 8 seconds for 21,842 files = **2,735 files/second**
- No stream decoding
- Structural analysis only

**Deep Scan**:
- 33 seconds for 21,842 files = **662 files/second**
- Full stream decoding
- JavaScript sandbox execution
- Embedded file extraction

### Scalability

For **21,898 files**:
- Fast scan: ~8 seconds
- Deep scan: ~33 seconds

**Projected for 100,000 files**:
- Fast scan: ~37 seconds
- Deep scan: ~2.5 minutes

**Projected for 1,000,000 files**:
- Fast scan: ~6 minutes
- Deep scan: ~25 minutes

---

## JavaScript Sandbox Analysis (Deep Scan Exclusive)

Deep scanning revealed detailed JavaScript execution patterns:

### Execution Success Rate

- **Executed successfully**: 16,865 files (77.2%)
- **Sandbox timeout**: 50 files (0.2%)
- **Sandbox skipped**: 62 files (0.3%)

### Runtime Behavior Detection

| Behavior | Files | Coverage |
|----------|-------|----------|
| Risky API calls | 2,650 | 12.1% |
| File system probes | 359 | 1.6% |
| Network intents | 23 | 0.1% |

**Most common risky calls**:
- `app.*` methods (application control)
- `util.*` utilities
- `this.*` context manipulation

---

## Object Stream Analysis (Deep Scan Exclusive)

### Compressed Object Streams

- **421 files** (1.9%) contain object streams with embedded summaries
- **2,118 instances** total across corpus
- Average **5 object streams per affected file**

### Suspicious Compression

- **146 files** (0.7%) have suspicious decompression ratios
- **371 instances** detected
- Indicators: potential decompression bombs or obfuscation

---

## Parser Health (Deep Scan)

### Error Handling

- **Crashes**: 0 (0.0%)
- **Fatal Parse Errors**: 0 (0.0%)
- **Warnings**: 905 (vs 892 in fast scan)

**Additional warnings from deep scan**:
- Stream decoding issues
- Sandbox timeout warnings
- Decompression ratio alerts

---

## Cost-Benefit Analysis: Fast vs Deep

### When to Use Fast Scan

✅ **High-volume triage** (millions of files)
✅ **Quick corpus profiling**
✅ **Structural analysis only**
✅ **CI/CD pipeline integration** (speed critical)

**Pros**: 4.1x faster, still catches 80% of findings
**Cons**: Misses JS execution behavior, embedded file analysis

### When to Use Deep Scan

✅ **Malware analysis workflows**
✅ **Forensic investigation**
✅ **Comprehensive threat hunting**
✅ **Sample set < 100K files**

**Pros**: +19.6% more findings, JS execution analysis, embedded file detection
**Cons**: 4.1x slower (still very fast at 662 files/s)

---

## Recommended Workflow

**Two-Stage Analysis Pipeline**:

1. **Stage 1: Fast Triage** (8 seconds)
   - Scan entire corpus with fast mode
   - Identify high-risk files based on structural indicators

2. **Stage 2: Deep Analysis** (seconds to minutes)
   - Deep scan top 10% highest-risk files
   - Extract and analyze JavaScript payloads
   - Examine embedded files and object streams

**Example**:
```bash
# Stage 1: Fast scan (8 seconds for 21K files)
sis scan --path corpus/ --jsonl-findings > fast.jsonl

# Stage 2: Extract high-risk subset
jq -r 'select(.finding.severity == "High") | .path' fast.jsonl | \
  sort -u | head -2000 > high_risk.txt

# Stage 3: Deep scan high-risk files (~3 seconds for 2K files)
cat high_risk.txt | while read pdf; do
  sis scan "$pdf" --deep --jsonl >> deep.jsonl
done
```

---

## Key Takeaways

### 1. Deep Scan Value Proposition

✅ **19.6% more findings** with only **4.1x time penalty**
✅ **8 new finding types** (all actionable intelligence)
✅ **Zero crashes** even with full stream decoding
✅ **Still very fast** (662 files/second)

### 2. JavaScript Sandbox Insights

🔍 **77.2%** of malicious PDFs execute JS successfully in sandbox
🔍 **12.1%** make risky API calls
🔍 **1.6%** probe file system
🔍 **0.1%** attempt network connections

### 3. Performance is Production-Ready

⚡ **33 seconds** for 21,842 files with full decoding
⚡ **Zero crashes** across all modes
⚡ **Graceful degradation** (timeout/skip mechanisms work)

---

## Comparison Summary Table

| Aspect | Fast Scan | Deep Scan | Winner |
|--------|-----------|-----------|--------|
| **Speed** | 2,735 files/s | 662 files/s | Fast ⚡ |
| **Findings** | 125,716 | 150,362 | Deep 🔍 |
| **Finding Types** | 48 | 56 | Deep 🔍 |
| **JS Analysis** | Structure only | Execution + APIs | Deep 🔍 |
| **Embedded Files** | Present/absent | Decoded + analyzed | Deep 🔍 |
| **Parser Crashes** | 0 | 0 | Tie ✅ |
| **Best For** | Triage | Investigation | Context-dependent |

---

## Files Generated (Deep Scan)

- ✅ `malicious_2022_deep_scan.jsonl` (150,362 findings)
- ✅ `malicious_2022_deep_errors.log` (905 warnings)
- ✅ `malicious_2022_deep_analysis_by_kind.txt` (by semantic type)
- ✅ `malicious_2022_fast_vs_deep.txt` (comparison report)

---

## Conclusion

Deep scanning **significantly enhances detection** with:

1. **+24,646 additional findings** (+19.6%)
2. **8 new detection types** (JS execution, object streams, compression)
3. **Zero reliability impact** (no crashes, same error rate)
4. **Acceptable performance penalty** (4.1x slower but still fast)

**Recommendation**:
- Use **fast scan** for high-volume triage (millions of files)
- Use **deep scan** for comprehensive analysis (< 100K files)
- Use **two-stage pipeline** for best of both worlds

**The deep scan capability makes SIS production-ready for both high-speed triage and in-depth malware analysis.**

---

**Analysis completed**: 2026-01-11 19:54:51 AEDT

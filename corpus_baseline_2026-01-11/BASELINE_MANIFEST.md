# Baseline Corpus Analysis Archive

**Date Archived**: 2026-01-12
**Reason**: Preserve baseline results before re-running with JS sandbox improvements
**Source Report**: `CORPUS_ANALYSIS_FINAL_SUMMARY.md` (2026-01-11)

---

## Archived Commits Baseline

These results were generated with the codebase **before** these improvements:
- `8987db2` - Extend JS sandbox recovery hooks
- `8085456` - Improve JS sandbox error recovery
- `6ebd8f1` - Add JS sandbox stubs for ADBE and page words
- `cfda3a2` - Improve sandbox corpus capture
- `7b00d18` - Improve JS sandbox recovery

---

## Files Archived (33 total, 16GB)

### Malicious Corpus 2022 (21,898 files)
- `malicious_2022_scan.jsonl` (213M) - Fast scan results
- `malicious_2022_deep_scan.jsonl` (538M) - Deep scan results
- `malicious_2022_errors.log` (208K) - Fast scan errors
- `malicious_2022_deep_errors.log` (211K) - Deep scan errors
- `malicious_2022_analysis.txt` - Fast scan analysis
- `malicious_2022_deep_analysis.txt` - Deep scan analysis
- `malicious_2022_analysis_by_kind.txt` (4.8K) - Fast findings by kind
- `malicious_2022_deep_analysis_by_kind.txt` (5.5K) - Deep findings by kind
- `malicious_2022_problems.txt` - Problem files (fast)
- `malicious_2022_deep_problems.txt` - Problem files (deep)
- `malicious_2022_fast_vs_deep.txt` (1.8K) - Mode comparison
- `malicious_2022_comparison.txt` - Additional comparison

### Benign Corpus 2022 (9,107 files)
- `benign_2022_scan.jsonl` (149M) - Fast scan results
- `benign_2022_deep_scan.jsonl` (176M) - Deep scan results
- `benign_2022_errors.log` (229K) - Fast scan errors
- `benign_2022_deep_errors.log` (229K) - Deep scan errors
- `benign_2022_analysis.txt` - Fast scan analysis
- `benign_2022_deep_analysis.txt` - Deep scan analysis
- `benign_2022_analysis_by_kind.txt` (4.1K) - Fast findings by kind
- `benign_2022_deep_analysis_by_kind.txt` (4.3K) - Deep findings by kind
- `benign_2022_problems.txt` - Problem files (fast)
- `benign_2022_deep_problems.txt` - Problem files (deep)
- `benign_2022_fast_vs_deep.txt` (1.4K) - Mode comparison

### Cross-Corpus Comparisons
- `malicious_vs_benign_fast.txt` (3.6K) - Fast mode comparison
- `malicious_vs_benign_deep.txt` (3.9K) - Deep mode comparison

### VirusShare 2024 Corpus (bonus data)
- `virusshare_2024_scan.jsonl` (6.8G) - Fast scan results
- `virusshare_2024_deep_scan.jsonl` (7.6G) - Deep scan results
- `virusshare_2024_errors.log` - Fast scan errors
- `virusshare_2024_deep_errors.log` - Deep scan errors
- `virusshare_2024_analysis_by_kind.txt` - Fast findings by kind
- `virusshare_2024_deep_analysis_by_kind.txt` - Deep findings by kind
- `virusshare_2024_fast_vs_deep.txt` (1.8K) - Mode comparison

### Additional Comparisons
- `2022_vs_2024_malicious_comparison.txt` - Temporal comparison

---

## Key Baseline Metrics (2022 Corpora)

### Performance
- **Malicious Fast**: 21,842 files in 8 sec (2,735 files/s)
- **Malicious Deep**: 21,842 files in 33 sec (662 files/s)
- **Benign Fast**: 8,604 files in 2 sec (4,302 files/s)
- **Benign Deep**: 8,616 files in 3 sec (2,872 files/s)
- **Total**: 60,904 scans in 46 seconds
- **Crashes**: 0 ✅

### JavaScript Sandbox (Areas for Improvement)
- **Timeouts**: 50 instances in malicious corpus
- **Skipped**: 62 instances in malicious corpus
- **Execution Success**: 77.2% malicious, 4.9% benign

### Top Discriminators
- **Malicious**: `js_present` (81.7%), `open_action_present` (71.6%)
- **Benign**: `signature_present` (14.1%), `linearization` (82.9%)

---

## Purpose of Re-Analysis

The new scan will measure improvements in:
1. **JS sandbox stability** - Fewer timeouts and skips
2. **Adobe API compatibility** - Better handling of ADBE namespace
3. **API call detection** - More `js_runtime_*` findings
4. **Overall robustness** - Maintain zero-crash record

---

**Archive Created**: 2026-01-12
**Baseline Report**: See `CORPUS_ANALYSIS_FINAL_SUMMARY.md` in project root

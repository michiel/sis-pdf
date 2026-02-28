# Full Technical Uplift Implementation Plan
**Date**: 2026-02-28
**Based on**: Fresh corpus run (mwb-latest, mwb-2026-02-23), deep code review
**Prior plans superseded**: 20260227-corpus-analysis-uplift.md (P1–P5 items),
20260228-corpus-perf-chain-uplift.md (all items)
**Status**: Not Started

---

## Overview

This plan captures every gap, performance bug, chain architecture failure, and detection deficit
identified across a fresh 40-file corpus run and a full code audit. Items are ordered so each
stage produces a working, testable state. Every stage includes specific file locations, code
changes, test names, and fixture requirements.

---

## Stage 0: Fixture Capture
**Goal**: Commit the 8 corpus PDFs that drive regression targets across all later stages.
**Success criteria**: All fixtures verified by SHA256, registered in manifest.json, and
committed. No test fails due to missing fixtures.

### 0.1 Copy corpus PDFs as named fixtures

Copy these files to `crates/sis-pdf-core/tests/fixtures/corpus_captured/`:

| Fixture name | Source path | SHA256 | Size | Purpose |
|---|---|---|---|---|
| `apt42-polyglot-pdf-zip-pe-6648302d.pdf` | `tmp/corpus/mwb-latest/6648302d…` | `6648302d497ee2364d3b10d0bebd1c30cedf649117a682754aebd35761a5d2ff` | 261 KB | Polyglot chain + PE dropper detection |
| `booking-js-phishing-379b41e3.pdf` | `tmp/corpus/mwb-latest/379b41e3…` | `379b41e3fd94f48d3f1756202fc4e702a98af4f01ca59b1be30cb3e31bc4b3ce` | 38 KB | JS + annotation phishing chain dedup |
| `font-exploit-embedded-js-9ff24c46.pdf` | `tmp/corpus/mwb-latest/9ff24c46…` | `9ff24c464780feb6425d0ab1f30a74401e228b9ad570bb25698e31b4b313a4f4` | 407 KB | Font cluster + JS analysis (already in manifest — update targets) |
| `fog-netlify-phishing-6eb8b598.pdf` | `tmp/corpus/mwb-latest/6eb8b598…` | `6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3` | 344 KB | URI phishing chain (already in manifest — update targets) |
| `romcom-embedded-payload-a99903.pdf` | `tmp/corpus/mwb-latest/a99903…` | `a99903938bf242ea6465865117561ba950bd12a82f41b8eeae108f4f3d74b5d1` | 90 KB | Intent scoring + embedded payload |
| `decompression-bomb-11606ab5.pdf` | `tmp/corpus/mwb-2026-02-23/11606ab5…` | `11606ab5c006a387daacaa4004bbdbae385f6e9e1815d8e33e8046f2555b7e2a` | 261 KB | Decompression bomb (already in manifest — update targets) |
| `perf-hang-717obj-fb87d8a7.pdf` | `tmp/corpus/mwb-2026-02-23/fb87d8a7…` | `fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd` | 6.0 MB | Performance regression: must complete in <10s |
| `font-heavy-objstm-5bb77b57.pdf` | `tmp/corpus/mwb-2026-02-23/5bb77b57…` | `5bb77b5790891f42208d9224a231059ed8e16b7174228caa9dc201329288a741` | 444 KB | Font cluster + objstm performance |
| `encoded-uri-payload-b710ae59.pdf` | `tmp/corpus/mwb-latest/b710ae59…` | `b710ae59bc996a099ca491f6d32fef2d8d5fa25f266d590e4a7a13f81ab2b432` | 132 KB | Encoded C2 URL + phishing chain |

### 0.2 Update manifest.json

Append new entries to `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json`.
Update `"captured_at"` to `2026-02-28`.

New entries:

```json
{
  "path": "apt42-polyglot-pdf-zip-pe-6648302d.pdf",
  "sha256": "6648302d497ee2364d3b10d0bebd1c30cedf649117a682754aebd35761a5d2ff",
  "source_path": "tmp/corpus/mwb-latest/6648302d…",
  "regression_targets": [
    "polyglot_signature_conflict high/strong ZIP signatures",
    "embedded_payload_carved medium/strong zip in stream",
    "nested_container_chain high/probable two PE entries",
    "intent ExploitPrimitive strong after stage 3 fixes",
    "chain polyglot_dropper_chain critical after stage 3 fixes",
    "drift_guard polyglot_pe_count=2"
  ]
},
{
  "path": "booking-js-phishing-379b41e3.pdf",
  "sha256": "379b41e3fd94f48d3f1756202fc4e702a98af4f01ca59b1be30cb3e31bc4b3ce",
  "source_path": "tmp/corpus/mwb-latest/379b41e3…",
  "regression_targets": [
    "js_present medium/strong",
    "annotation_action_chain low/strong netlify URL",
    "js_intent_user_interaction high/strong",
    "network_intents contains bocking.netlify.app",
    "no finding_id appears in more than one chain after stage 2 fixes",
    "chain singleton_rate <=70% after stage 2 fixes"
  ]
},
{
  "path": "romcom-embedded-payload-a99903.pdf",
  "sha256": "a99903938bf242ea6465865117561ba950bd12a82f41b8eeae108f4f3d74b5d1",
  "source_path": "tmp/corpus/mwb-latest/a99903…",
  "regression_targets": [
    "embedded_payload_carved present x2",
    "intent ExploitPrimitive score>=4",
    "intent confidence Probable after stage 3 fixes (was Heuristic)"
  ]
},
{
  "path": "perf-hang-717obj-fb87d8a7.pdf",
  "sha256": "fb87d8a7807626279bae04d56ba01ce1401917f6b0e7a74a335208a940221ddd",
  "source_path": "tmp/corpus/mwb-2026-02-23/fb87d8a7…",
  "regression_targets": [
    "scan completes in <10000 ms after stage 1 fixes",
    "no content_stream_exec_uplift timeout",
    "findings present (not empty)"
  ]
},
{
  "path": "font-heavy-objstm-5bb77b57.pdf",
  "sha256": "5bb77b5790891f42208d9224a231059ed8e16b7174228caa9dc201329288a741",
  "source_path": "tmp/corpus/mwb-2026-02-23/5bb77b57…",
  "regression_targets": [
    "content_first_stage1 completes in <4000 ms",
    "font.ttf_hinting_suspicious present",
    "font_exploitation_cluster present after stage 3 fixes"
  ]
},
{
  "path": "encoded-uri-payload-b710ae59.pdf",
  "sha256": "b710ae59bc996a099ca491f6d32fef2d8d5fa25f266d590e4a7a13f81ab2b432",
  "source_path": "tmp/corpus/mwb-latest/b710ae59…",
  "regression_targets": [
    "network_intents contains evacdir.com",
    "uri.url present in finding meta",
    "intent DataExfiltration or Phishing present"
  ]
}
```

Also update existing entries for `noisy-correlated-highrisk-11606.pdf`, `secondary-invalid-trailer-6eb8.pdf`,
and `modern-gated-supplychain-9ff24c46.pdf` with new regression targets from stages 2 and 3.

### 0.3 Update fixtures/corpus_captured/README.md

Add a section listing all new fixtures with their attack vector classification.

---

## Stage 1: Performance Fixes
**Goal**: Eliminate scan hangs and reduce worst-case scan time from 292 s to < 10 s.
**Success criteria**: `perf-hang-717obj-fb87d8a7.pdf` scans in < 10 s. Batch of 20 files
completes in < 60 s wall time. All existing tests still pass.

### 1.1 Fix `content_stream_exec_uplift` O(n²) sliding window

**File**: `crates/sis-pdf-detectors/src/content_stream_exec_uplift.rs`

**Change**: Replace `detect_resource_cluster_without_markers()`.

Current code (lines ~357–382):
```rust
fn detect_resource_cluster_without_markers(ops: &[ContentOp]) -> Option<MarkedCandidate> {
    if ops.len() < 8 { return None; }
    let mut window = (ops.len() / 10).max(8);
    if window > ops.len() { window = ops.len(); }
    for start in 0..=ops.len().saturating_sub(window) {  // O(N) outer
        let slice = &ops[start..start + window];
        let resource_ops = slice.iter()                  // O(N/10) inner = O(N²/10) total
            .filter(|op| matches!(op.op.as_str(), "Do" | "Tf"))
            .count();
        // ...
    }
    None
}
```

New implementation — single-pass sliding window with O(N) total:

```rust
const MAX_CONTENT_OPS_SCAN: usize = 5_000;
const MIN_OPS_FOR_CLUSTER: usize = 8;
const CLUSTER_FRACTION_THRESHOLD: f64 = 0.80;
const CLUSTER_BUCKET_SIZE: usize = 50;

fn detect_resource_cluster_without_markers(ops: &[ContentOp]) -> Option<MarkedCandidate> {
    // Hard cap: skip large streams to bound worst case
    let ops = if ops.len() > MAX_CONTENT_OPS_SCAN { &ops[..MAX_CONTENT_OPS_SCAN] } else { ops };
    if ops.len() < MIN_OPS_FOR_CLUSTER { return None; }

    // Single-pass approach: walk ops in fixed-size non-overlapping buckets,
    // compute resource/visible ratio per bucket. No sliding window.
    let bucket = CLUSTER_BUCKET_SIZE.min(ops.len());
    let mut max_resource_fraction = 0.0f64;
    let mut best_visible = usize::MAX;

    for chunk in ops.chunks(bucket) {
        if chunk.len() < MIN_OPS_FOR_CLUSTER { break; }
        let resource_ops = chunk.iter()
            .filter(|op| matches!(op.op.as_str(), "Do" | "Tf"))
            .count();
        let visible_ops = chunk.iter()
            .filter(|op| is_visible_render_op(op.op.as_str()))
            .count();
        let fraction = resource_ops as f64 / chunk.len() as f64;
        if fraction > max_resource_fraction {
            max_resource_fraction = fraction;
            best_visible = visible_ops;
        }
    }

    if max_resource_fraction > CLUSTER_FRACTION_THRESHOLD && best_visible == 0 {
        Some(MarkedCandidate {
            tag: "/Cluster".into(),
            resource_fraction: max_resource_fraction,
            visible_op_count: best_visible,
        })
    } else {
        None
    }
}
```

Add a byte-level size guard at the function that calls this (before parsing content ops):
```rust
// In the function that parses content stream ops (around line 255):
const MAX_CONTENT_STREAM_BYTES: usize = 2 * 1024 * 1024; // 2 MB
if stream_bytes.len() > MAX_CONTENT_STREAM_BYTES {
    // Skip expensive analysis; emit a truncation note
    return vec![];
}
```

**Test** — add to `crates/sis-pdf-core/tests/performance_fixtures.rs`:
```rust
#[test]
fn content_stream_exec_uplift_completes_within_budget_on_large_pdf() {
    // fb87d8a7 — 717 objects, was 292 s before fix
    let bytes = include_bytes!(
        "fixtures/corpus_captured/perf-hang-717obj-fb87d8a7.pdf"
    );
    let start = std::time::Instant::now();
    let opts = ScanOptions { deep: false, fast: false, ..default_scan_opts_minimal() };
    let report = run_scan_with_detectors(bytes, opts, &default_detectors())
        .expect("scan must complete");
    let elapsed_ms = start.elapsed().as_millis();
    assert!(elapsed_ms < 10_000, "scan took {} ms, budget is 10 000 ms", elapsed_ms);
    assert!(!report.findings.is_empty(), "scan must produce findings");
}
```

### 1.2 Fix `content_phishing` iteration bounds

**File**: `crates/sis-pdf-detectors/src/content_phishing.rs`

Add these constants at the top of the file:
```rust
const MAX_OBJECTS_STRING_SCAN: usize = 200;
const MAX_OBJECTS_STREAM_DECODE: usize = 50;
const MAX_STREAM_SCAN_BYTES: usize = 512 * 1024; // 512 KB
const MAX_MARKER_MATCHES_PER_STREAM: usize = 10;
```

In `detect_html_payload()`, wrap each loop:
```rust
// First loop — string scan
for (idx, entry) in ctx.graph.objects.iter().enumerate() {
    if idx >= MAX_OBJECTS_STRING_SCAN { break; }  // ADD THIS
    // ... existing code
}

// Second loop — stream decode
let stream_count = AtomicUsize::new(0);
for entry in ctx.graph.objects.iter() {
    if stream_count.fetch_add(1, Ordering::Relaxed) >= MAX_OBJECTS_STREAM_DECODE { break; }
    // In decode: truncate decoded data before calling detect_rendered_script_lure
    let data = ctx.decoded.get_or_decode(/* ... */);
    let scan_data = if data.len() > MAX_STREAM_SCAN_BYTES {
        &data[..MAX_STREAM_SCAN_BYTES]
    } else {
        data.as_slice()
    };
    // pass scan_data instead of data
}
```

In `detect_rendered_script_lure()`, add match counter:
```rust
let mut match_count = 0usize;
while cursor < lower.len() {
    if match_count >= MAX_MARKER_MATCHES_PER_STREAM { break; }  // ADD THIS
    // ... existing code
    match_count += 1;
}
```

Reorder: check for keyword in object strings first (cheap); only decode streams if a keyword
was found in the document:
```rust
let found_keyword_in_strings = /* existing first-pass loop */;
if !found_keyword_in_strings {
    return findings; // skip expensive stream decode entirely
}
```

**Test** — add to `crates/sis-pdf-core/tests/performance_fixtures.rs`:
```rust
#[test]
fn content_phishing_completes_within_budget_on_object_heavy_pdf() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/perf-hang-717obj-fb87d8a7.pdf"
    );
    let start = std::time::Instant::now();
    let opts = ScanOptions { deep: false, fast: false, ..default_scan_opts_minimal() };
    let _ = run_scan_with_detectors(bytes, opts, &default_detectors())
        .expect("scan must complete");
    let elapsed_ms = start.elapsed().as_millis();
    // content_phishing alone should contribute < 500 ms
    // (full scan budget is tested in 1.1)
    assert!(elapsed_ms < 12_000, "scan took {} ms", elapsed_ms);
}
```

### 1.3 Add per-file scan timeout to runner and CLI

**Files**: `crates/sis-pdf-core/src/runner.rs`, `crates/sis-pdf/src/main.rs`

In `ScanOptions`:
```rust
pub struct ScanOptions {
    // ... existing fields ...
    pub timeout_ms: Option<u64>,  // NEW: per-file timeout in milliseconds
}
```

In `runner.rs`, wrap `run_scan_with_detectors` call with a timeout using `std::thread::spawn`
and a channel with `recv_timeout`:

```rust
pub fn run_scan_with_timeout(
    bytes: Vec<u8>,
    opts: ScanOptions,
    detectors: &[Box<dyn Detector>],
) -> Result<Report, ScanError> {
    let timeout_ms = opts.timeout_ms;
    // Clone detectors for the thread (requires Detector: Send)
    // Use a channel with recv_timeout
    let (tx, rx) = std::sync::mpsc::channel();
    let bytes_clone = bytes.clone();
    let opts_clone = opts.clone();
    let detectors_clone: Vec<_> = detectors.iter().map(|d| d.boxed_clone()).collect();

    std::thread::spawn(move || {
        let result = run_scan_with_detectors(&bytes_clone, opts_clone, &detectors_clone);
        let _ = tx.send(result);
    });

    match timeout_ms {
        Some(ms) => {
            match rx.recv_timeout(std::time::Duration::from_millis(ms)) {
                Ok(result) => result,
                Err(_) => {
                    // Timeout — emit a scan_timeout finding
                    Err(ScanError::Timeout { elapsed_ms: ms })
                }
            }
        }
        None => rx.recv().unwrap_or_else(|_| Err(ScanError::ThreadPanic)),
    }
}
```

Note: This requires `Detector: Send + Sync` and a `boxed_clone()` method. If this is
impractical without major refactoring, an alternative is to use `std::process::Command`
to invoke `sis scan` as a subprocess with an OS-level timeout (`timeout` crate).
The simpler approach is a shared `AtomicBool` cancellation flag checked in the hot loops
of slow detectors (see CRIT-3 alternative below).

**Alternative (simpler, no refactor needed)**:
Add a `CancellationToken` shared `Arc<AtomicBool>` to `ScanContext`. In the slow detector
loops, check `ctx.cancelled.load(Ordering::Relaxed)` every N iterations and return early.
The batch runner sets the token after `timeout_ms` using a background thread.

In CLI (`main.rs`):
```
--timeout-per-file <SECONDS>   Abort scan if a file takes longer than this [default: 60]
```

**Test** — add to `crates/sis-pdf-core/tests/performance_fixtures.rs`:
```rust
#[test]
#[cfg(feature = "timeout_tests")]
fn scan_timeout_produces_structured_error_not_hang() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/perf-hang-717obj-fb87d8a7.pdf"
    );
    let opts = ScanOptions {
        timeout_ms: Some(2_000), // 2 second budget — will fire on the slow file
        ..default_scan_opts_minimal()
    };
    let result = run_scan_with_timeout(bytes.to_vec(), opts, &default_detectors());
    // Should NOT hang; should return either Ok (if under budget) or a timeout error
    assert!(result.is_ok() || matches!(result, Err(ScanError::Timeout { .. })));
}
```

---

## Stage 2: Chain Architecture Fixes
**Goal**: Reduce singleton chain rate from 98.8% to ≤ 70%. Add label/severity to chains.
Eliminate finding duplication across chains.
**Success criteria**:
- `booking-js-phishing-379b41e3.pdf` produces ≤ 8 chains (was 24)
- `font-heavy-objstm-5bb77b57.pdf` produces ≤ 15 chains (was 69)
- No finding ID appears in more than one chain
- All chains have non-empty `label` and `severity` fields

### 2.1 Add `label` and `severity` to `ExploitChain`

**File**: `crates/sis-pdf-core/src/chain.rs`

```rust
pub struct ExploitChain {
    pub id: String,
    pub label: String,           // NEW: human-readable chain label
    pub severity: String,        // NEW: "Critical" | "High" | "Medium" | "Low" | "Info"
    // ... rest unchanged ...
}
```

**File**: `crates/sis-pdf-core/src/chain_synth.rs`

After `finalize_chain()`, derive label and severity:

```rust
fn derive_chain_label(chain: &ExploitChain, findings: &[&Finding]) -> String {
    // Priority 1: Use the kind-cluster label if this is a merged cluster chain
    if let Some(cluster_label) = chain.notes.get("cluster.label") {
        return cluster_label.clone();
    }
    // Priority 2: Use action/payload labels from notes
    let action_label = chain.notes.get("action.label").map(|s| s.as_str()).unwrap_or("unknown");
    let payload_label = chain.notes.get("payload.label").map(|s| s.as_str()).unwrap_or("");
    if !payload_label.is_empty() {
        format!("{} → {}", action_label, payload_label)
    } else if chain.trigger.is_some() {
        format!("{}:{}", chain.trigger.as_deref().unwrap_or("?"), action_label)
    } else {
        // Fallback: use the first finding kind
        findings.first().map(|f| f.kind.clone()).unwrap_or_else(|| "unknown".into())
    }
}

fn derive_chain_severity(score: f64, findings: &[&Finding]) -> String {
    // Derive from score threshold, then cap at highest finding severity
    let score_severity = if score >= 0.9 { "Critical" }
        else if score >= 0.75 { "High" }
        else if score >= 0.5 { "Medium" }
        else { "Low" };
    // Could also take max from findings — leave as score-based for now
    score_severity.to_string()
}
```

Call these after `finalize_chain()` in both `build_object_chains` and the singleton loop.

**Tests** — add to `crates/sis-pdf-core/tests/chain_grouping.rs`:
```rust
#[test]
fn chain_has_label_field() {
    let findings = vec![base_finding("f1", "js_present", "4 0 obj")];
    let (chains, _) = synthesise_chains(&findings, true);
    assert!(!chains[0].label.is_empty(), "chain must have a non-empty label");
}

#[test]
fn chain_has_severity_field() {
    let findings = vec![base_finding_with_severity("f1", "js_present", "4 0 obj", Severity::High)];
    let (chains, _) = synthesise_chains(&findings, true);
    assert!(!chains[0].severity.is_empty(), "chain must have a non-empty severity");
}
```

### 2.2 Kind-based chain deduplication (Tier A)

**File**: `crates/sis-pdf-core/src/chain_synth.rs`

After the singleton chain loop (after the `for f in findings` loop), add a merging pass.
This is a new function called before `group_chains_by_signature`:

```rust
/// Merge singleton chains whose findings share the same kind-prefix into cluster chains.
/// Example: 25 chains each with one font.ttf_hinting_suspicious finding → 1 cluster chain.
const CLUSTER_KINDS: &[&str] = &[
    "font",
    "image",
    "object_reference_cycle",
    "label_mismatch_stream_type",
    "declared_filter_invalid",
    "objstm",
    "secondary_parser",
    "parser",
];
const MAX_CLUSTER_MEMBERS: usize = 50;

fn merge_singleton_clusters(
    mut chains: Vec<ExploitChain>,
    findings_by_id: &HashMap<String, &Finding>,
) -> Vec<ExploitChain> {
    // Separate singleton chains from object-grouped chains
    let (singletons, mut multi): (Vec<_>, Vec<_>) = chains
        .drain(..)
        .partition(|c| c.findings.len() == 1);

    // Group singletons by kind prefix
    let mut kind_groups: HashMap<String, Vec<ExploitChain>> = HashMap::new();
    let mut unmatched: Vec<ExploitChain> = Vec::new();

    for chain in singletons {
        let fid = &chain.findings[0];
        let kind = findings_by_id.get(fid.as_str())
            .map(|f| f.kind.as_str())
            .unwrap_or("");
        // Match kind prefix against CLUSTER_KINDS
        let prefix = CLUSTER_KINDS.iter()
            .find(|&&p| kind == p || kind.starts_with(&format!("{}.", p)))
            .copied();
        match prefix {
            Some(p) => kind_groups.entry(p.to_string()).or_default().push(chain),
            None => unmatched.push(chain),
        }
    }

    // Build cluster chains from groups of ≥ 2 singletons
    for (prefix, group) in kind_groups {
        if group.len() < 2 {
            // Small group: keep as-is
            unmatched.extend(group);
            continue;
        }
        // Take up to MAX_CLUSTER_MEMBERS, keep rest as-is
        let (cluster_members, remainder) = if group.len() <= MAX_CLUSTER_MEMBERS {
            (group, vec![])
        } else {
            let mut g = group;
            let remainder = g.split_off(MAX_CLUSTER_MEMBERS);
            (g, remainder)
        };

        // Build one cluster chain
        let finding_ids: Vec<String> = cluster_members.iter()
            .flat_map(|c| c.findings.iter().cloned())
            .collect();
        let count = finding_ids.len();
        let max_score = cluster_members.iter()
            .map(|c| c.score)
            .fold(f64::NEG_INFINITY, f64::max);
        let max_severity = cluster_members.iter()
            .map(|c| c.severity.as_str())
            .max_by_key(|&s| severity_rank(s))
            .unwrap_or("Low")
            .to_string();

        // Derive cluster label from prefix
        let cluster_label = cluster_label_for_prefix(&prefix, count);

        let mut notes = cluster_members[0].notes.clone();
        notes.insert("cluster.kind_prefix".into(), prefix.clone());
        notes.insert("cluster.member_count".into(), count.to_string());
        notes.insert("cluster.label".into(), cluster_label.clone());

        let cluster_chain = ExploitChain {
            id: format!("cluster-{}-{}", prefix, blake3_short(&finding_ids.join(","))),
            label: cluster_label,
            severity: max_severity,
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger: cluster_members[0].trigger.clone(),
            action: cluster_members[0].action.clone(),
            payload: cluster_members[0].payload.clone(),
            findings: finding_ids,
            score: max_score,
            reasons: vec![format!("Cluster of {} {} findings", count, prefix)],
            path: format!("Cluster: {} ({} findings)", prefix, count),
            nodes: cluster_members.iter().flat_map(|c| c.nodes.iter().cloned()).collect(),
            edges: Vec::new(),
            confirmed_stages: Vec::new(),
            inferred_stages: Vec::new(),
            chain_completeness: 0.0,
            reader_risk: HashMap::new(),
            narrative: format!(
                "{} {} signals detected across {} objects. {}",
                count, prefix,
                cluster_members.iter().flat_map(|c| c.nodes.iter()).count(),
                cluster_context_note(&prefix, count),
            ),
            finding_criticality: HashMap::new(),
            active_mitigations: Vec::new(),
            required_conditions: Vec::new(),
            unmet_conditions: Vec::new(),
            finding_roles: HashMap::new(),
            notes,
        };
        multi.push(cluster_chain);
        unmatched.extend(remainder);
    }

    multi.extend(unmatched);
    multi
}

fn cluster_label_for_prefix(prefix: &str, count: usize) -> String {
    match prefix {
        "font" => format!("Font exploitation signals ({} fonts)", count),
        "image" => format!("Image anomaly cluster ({} images)", count),
        "object_reference_cycle" => format!("Reference cycle cluster ({} cycles)", count),
        "label_mismatch_stream_type" => format!("Stream type mismatch cluster ({} streams)", count),
        "declared_filter_invalid" => format!("Invalid filter cluster ({} streams)", count),
        _ => format!("{} cluster ({} findings)", prefix, count),
    }
}

fn cluster_context_note(prefix: &str, count: usize) -> &'static str {
    match prefix {
        "font" if count >= 10 => "Pattern consistent with heap spray or font-based exploit targeting.",
        "font" => "Multiple font anomalies may indicate exploit preparation.",
        "image" => "Multiple image anomalies may indicate steganographic payload or decoder exploit.",
        "object_reference_cycle" => "Cycles in document graph may indicate parser confusion attempts.",
        "declared_filter_invalid" => "Invalid filter chains may indicate obfuscation or malformed payload delivery.",
        _ => "",
    }
}
```

Call `merge_singleton_clusters` in `synthesise_chains`, after the singleton loop and before
`group_chains_by_signature`:
```rust
let chains = merge_singleton_clusters(chains, &findings_by_id);
let chains = if group_chains { group_chains_by_signature(chains, &findings_by_id) } else { ... };
```

**Tests** — add to `crates/sis-pdf-core/tests/chain_grouping.rs`:
```rust
#[test]
fn font_findings_merged_into_cluster_chain() {
    let findings: Vec<Finding> = (0..20)
        .map(|i| base_finding(&format!("f{i}"), "font.ttf_hinting_suspicious", &format!("{i} 0 obj")))
        .collect();
    let (chains, _) = synthesise_chains(&findings, true);
    let font_clusters: Vec<_> = chains.iter()
        .filter(|c| c.notes.get("cluster.kind_prefix").map(|s| s == "font").unwrap_or(false))
        .collect();
    assert_eq!(font_clusters.len(), 1, "all font findings should merge into one cluster");
    assert_eq!(font_clusters[0].findings.len(), 20);
    assert!(!font_clusters[0].label.is_empty());
}

#[test]
fn image_findings_merged_into_cluster_chain() {
    let findings: Vec<Finding> = (0..10)
        .map(|i| base_finding(&format!("f{i}"), "image.decode_skipped", &format!("{i} 0 obj")))
        .collect();
    let (chains, _) = synthesise_chains(&findings, true);
    let image_clusters: Vec<_> = chains.iter()
        .filter(|c| c.label.contains("Image anomaly"))
        .collect();
    assert_eq!(image_clusters.len(), 1);
    assert_eq!(image_clusters[0].findings.len(), 10);
}

#[test]
fn singleton_rate_below_threshold_on_font_heavy_fixture() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/font-heavy-objstm-5bb77b57.pdf"
    );
    let report = run_scan_with_detectors(bytes, default_scan_opts(), &default_detectors())
        .expect("scan succeeds");
    let total = report.chains.len();
    let singletons = report.chains.iter().filter(|c| c.findings.len() == 1).count();
    let rate = if total == 0 { 0.0 } else { singletons as f64 / total as f64 };
    assert!(rate <= 0.70, "singleton rate {:.1}% exceeds 70% threshold", rate * 100.0);
}
```

### 2.3 Finding deduplication across chains

**File**: `crates/sis-pdf-core/src/chain_synth.rs`

Add deduplication pass after `merge_singleton_clusters` and before `group_chains_by_signature`:

```rust
/// Remove chains whose findings are a strict subset of a higher-scoring chain's findings.
/// For partially overlapping chains (>50% shared), merge into the higher-scoring one.
fn deduplicate_chains(mut chains: Vec<ExploitChain>) -> Vec<ExploitChain> {
    // Sort: highest finding count first, then highest score
    chains.sort_by(|a, b| {
        b.findings.len().cmp(&a.findings.len())
            .then(b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
    });

    let mut claimed: HashSet<String> = HashSet::new();
    let mut result: Vec<ExploitChain> = Vec::new();

    for mut chain in chains {
        let chain_findings: HashSet<&str> = chain.findings.iter().map(|s| s.as_str()).collect();

        // Remove already-claimed findings from this chain
        let unclaimed: Vec<String> = chain.findings.iter()
            .filter(|id| !claimed.contains(id.as_str()))
            .cloned()
            .collect();

        if unclaimed.is_empty() {
            // All findings claimed by earlier (higher priority) chains — skip
            continue;
        }

        // If more than half the original findings are already claimed, skip
        let claim_fraction = 1.0 - (unclaimed.len() as f64 / chain.findings.len() as f64);
        if claim_fraction > 0.5 && chain.findings.len() > 1 {
            // Majority already claimed — skip
            continue;
        }

        // Claim the unclaimed findings
        for id in &unclaimed {
            claimed.insert(id.clone());
        }

        // Update chain findings to only include unclaimed (if changed)
        if unclaimed.len() != chain.findings.len() {
            chain.findings = unclaimed;
        }

        result.push(chain);
    }

    result
}
```

Call: `let chains = deduplicate_chains(chains);`

**Test**:
```rust
#[test]
fn no_finding_appears_in_multiple_chains() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/booking-js-phishing-379b41e3.pdf"
    );
    let report = run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors()
    ).expect("scan succeeds");

    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for chain in &report.chains {
        for fid in &chain.findings {
            assert!(
                seen.insert(fid.as_str()),
                "finding {} appears in multiple chains", fid
            );
        }
    }
}

#[test]
fn booking_phishing_chain_count_within_budget() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/booking-js-phishing-379b41e3.pdf"
    );
    let report = run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors()
    ).expect("scan succeeds");
    assert!(
        report.chains.len() <= 8,
        "expected <= 8 chains, got {}",
        report.chains.len()
    );
}
```

### 2.4 Stage-based completeness inference

**File**: `crates/sis-pdf-core/src/chain_synth.rs`

Replace the current completeness calculation. Find `chain_completeness` assignment in
`finalize_chain` and add active inference before computing it:

```rust
/// Infer chain stages from assigned roles and finding kinds.
/// Sets confirmed_stages and inferred_stages, then computes chain_completeness.
fn infer_and_score_stages(chain: &mut ExploitChain, findings: &[&Finding]) {
    // 1. Infer stages from metadata (existing behaviour — keep)
    let existing_confirmed: Vec<String> = findings.iter()
        .filter_map(|f| f.meta.get("chain.stage"))
        .filter(|s| {
            let conf = findings.iter()
                .find(|f| f.meta.get("chain.stage") == Some(s))
                .map(|f| &f.confidence);
            matches!(conf, Some(Confidence::Certain | Confidence::Strong | Confidence::Probable))
        })
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // 2. Active inference from assigned roles
    let mut active_confirmed: std::collections::HashSet<String> = existing_confirmed.into_iter().collect();
    let mut active_inferred: std::collections::HashSet<String> = chain.inferred_stages.iter().cloned().collect();

    if chain.trigger.is_some() {
        active_confirmed.insert("input".into());
    }
    if let Some(action) = &chain.action {
        match action.as_str() {
            "js_present" | "launch_action_present" | "aa_event_present"
            | "uri_javascript_scheme" | "uri_file_scheme" | "uri_command_injection" => {
                active_confirmed.insert("execute".into());
            }
            _ => { active_inferred.insert("execute".into()); }
        }
    }
    if let Some(payload) = &chain.payload {
        match payload.as_str() {
            "stream" | "embedded_file" | "image" => {
                active_confirmed.insert("decode".into());
            }
            "javascript" => {
                active_inferred.insert("decode".into());
                active_confirmed.insert("execute".into());
            }
            _ => {}
        }
    }
    // Infer egress from network_intents presence (if passed via notes)
    if chain.notes.get("chain.has_network_egress").map(|v| v == "true").unwrap_or(false) {
        active_inferred.insert("egress".into());
    }
    // Infer render from image/font/content findings
    let has_render_signal = findings.iter().any(|f| {
        f.kind.starts_with("image.") || f.kind.starts_with("font.") ||
        f.kind.starts_with("content_stream") || f.kind == "content_image_only_page"
    });
    if has_render_signal {
        active_inferred.insert("render".into());
    }

    chain.confirmed_stages = active_confirmed.into_iter().collect();
    chain.inferred_stages = active_inferred.into_iter()
        .filter(|s| !chain.confirmed_stages.contains(s))
        .collect();

    // 3. Compute completeness using blended formula
    const TOTAL_STAGES: f64 = 5.0; // input, decode, render, execute, egress
    let confirmed_score = chain.confirmed_stages.len() as f64 * 1.0;
    let inferred_score = chain.inferred_stages.len() as f64 * 0.4;
    chain.chain_completeness = ((confirmed_score + inferred_score) / TOTAL_STAGES).min(1.0);
}
```

**Test**:
```rust
#[test]
fn chain_completeness_nonzero_when_trigger_and_action_assigned() {
    let mut f1 = base_finding("f1", "open_action_present", "1 0 obj");
    let mut f2 = base_finding("f2", "js_present", "1 0 obj");
    let (chains, _) = synthesise_chains(&[f1, f2], true);
    let chain = chains.iter().find(|c| c.findings.len() == 2).expect("should have a 2-finding chain");
    assert!(
        chain.chain_completeness > 0.0,
        "completeness should be > 0.0 when trigger+action are assigned, got {}",
        chain.chain_completeness
    );
}

#[test]
fn chain_completeness_higher_for_full_chain() {
    let mut f1 = base_finding("f1", "open_action_present", "1 0 obj");
    let mut f2 = base_finding("f2", "js_present", "1 0 obj");
    let mut f3 = base_finding("f3", "embedded_file_present", "1 0 obj");
    let (chains, _) = synthesise_chains(&[f1, f2, f3], true);
    let chain = chains.iter().find(|c| c.findings.len() == 3).expect("3-finding chain");
    assert!(chain.chain_completeness >= 0.4, "full chain should have completeness >=0.4");
}
```

---

## Stage 3: Detection Uplift
**Goal**: Add DenialOfService intent, polyglot dropper chain, font cluster composite,
intent confidence promotion. Fix intent gaps for APT42 and RomCom samples.
**Success criteria**:
- APT42 fixture: `ExploitPrimitive/Probable` or higher
- Decompression bomb: `DenialOfService/Strong` intent fires
- RomCom: intent promotes from Heuristic to Probable
- Font heavy fixture: `font_exploitation_cluster/High` composite present

### 3.1 Add `DenialOfService` intent bucket

**File**: `crates/sis-pdf-core/src/intent.rs`

Add to `IntentBucket` enum:
```rust
pub enum IntentBucket {
    DataExfiltration,
    SandboxEscape,
    Phishing,
    Persistence,
    Obfuscation,
    ExploitPrimitive,
    DenialOfService,  // NEW
}
```

Add to `signals_from_finding()`:
```rust
"decompression_ratio_suspicious" => {
    // Weight by ratio severity
    let ratio: f64 = f.meta.get("decompression.ratio")
        .or_else(|| f.meta.get("ratio"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let weight = if ratio >= 100.0 { 4 } else if ratio >= 20.0 { 2 } else { 1 };
    out.push(signal(IntentBucket::DenialOfService, weight, "Decompression bomb", fid.clone()));
    out.push(signal(IntentBucket::ExploitPrimitive, 2, "Decoder risk", fid.clone())); // keep existing
}
"parser_resource_exhaustion" => {
    out.push(signal(IntentBucket::DenialOfService, 4, "Parser resource exhaustion", fid.clone()));
}
"object_reference_depth_high" | "parser_resource_exhaustion" => {
    out.push(signal(IntentBucket::DenialOfService, 2, "Object graph exhaustion", fid.clone()));
}
```

Add to `bucket_name()`:
```rust
IntentBucket::DenialOfService => "denial_of_service",
```

Add to `score_confidence()` (currently: >=6 Strong, >=3 Probable, else Heuristic):
No change needed — DenialOfService will naturally get Strong when score >= 6 (i.e., decompression
bomb 485:1 gives weight 4 + parser_exhaustion weight 4 = 8 → Strong).

### 3.2 Intent confidence promotion rule

**File**: `crates/sis-pdf-core/src/intent.rs`

After computing per-bucket scores, add a promotion pass:

```rust
fn promote_bucket_confidence(
    bucket_scores: &HashMap<IntentBucket, (u32, Vec<IntentSignal>)>,
    findings: &[&Finding],
) -> HashMap<IntentBucket, Confidence> {
    let mut confidence_overrides: HashMap<IntentBucket, Confidence> = HashMap::new();

    for (bucket, (score, signals)) in bucket_scores {
        // Standard confidence from score
        let base_conf = score_confidence(*score);

        // Check if any finding in this bucket has Strong or Certain confidence
        let has_strong_finding = signals.iter()
            .filter_map(|s| s.finding_id.as_deref())
            .filter_map(|fid| findings.iter().find(|f| f.id == fid))
            .any(|f| matches!(f.confidence, Confidence::Certain | Confidence::Strong));

        let promoted = if has_strong_finding && *score >= 4 {
            // Strong individual signal + meaningful score → promote one tier
            match base_conf {
                Confidence::Heuristic => Confidence::Probable,
                Confidence::Probable => Confidence::Strong,
                other => other,
            }
        } else {
            base_conf
        };

        if promoted != base_conf {
            confidence_overrides.insert(*bucket, promoted);
        }
    }

    confidence_overrides
}
```

Apply the overrides when building `IntentBucketSummary` objects.

Add signals for finding kinds missing from `signals_from_finding()`:
```rust
"polyglot_signature_conflict" => {
    out.push(signal(IntentBucket::ExploitPrimitive, 4, "Polyglot signature conflict", fid.clone()));
}
"nested_container_chain" => {
    // Check if it contains PE/MZ
    let nested_kind = f.meta.get("nested.kind").map(|s| s.as_str()).unwrap_or("");
    if nested_kind == "mz" {
        out.push(signal(IntentBucket::ExploitPrimitive, 4, "Nested PE executable", fid.clone()));
        out.push(signal(IntentBucket::SandboxEscape, 2, "PE dropper in container", fid.clone()));
    } else {
        out.push(signal(IntentBucket::ExploitPrimitive, 2, "Nested container", fid.clone()));
    }
}
"embedded_payload_carved" => {
    let carve_kind = f.meta.get("carve.kind").map(|s| s.as_str()).unwrap_or("");
    let weight = if carve_kind == "zip" || carve_kind == "mz" { 3 } else { 2 };
    out.push(signal(IntentBucket::ExploitPrimitive, weight, "Carved payload", fid.clone()));
}
"font_exploitation_cluster" => {
    out.push(signal(IntentBucket::ExploitPrimitive, 3, "Font exploitation cluster", fid.clone()));
}
```

**Tests** — add to `crates/sis-pdf-core/tests/intent.rs`:
```rust
#[test]
fn intent_dos_bucket_fires_on_decompression_bomb() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/decompression-bomb-11606ab5.pdf"
    );
    let report = run_scan_with_detectors(bytes, base_opts(), &default_detectors())
        .expect("scan succeeds");
    let buckets: Vec<_> = report.intent_summary.as_ref()
        .map(|s| s.buckets.iter().map(|b| format!("{:?}", b.bucket)).collect())
        .unwrap_or_default();
    assert!(
        buckets.iter().any(|b| b == "DenialOfService"),
        "DenialOfService intent should fire on decompression bomb, got: {:?}", buckets
    );
    let dos_bucket = report.intent_summary.as_ref().unwrap().buckets.iter()
        .find(|b| format!("{:?}", b.bucket) == "DenialOfService")
        .expect("DenialOfService bucket");
    assert!(
        matches!(dos_bucket.confidence, Confidence::Strong | Confidence::Probable),
        "DoS confidence should be Strong or Probable, got {:?}", dos_bucket.confidence
    );
}

#[test]
fn intent_exploit_promotes_to_probable_for_apt42_polyglot() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/apt42-polyglot-pdf-zip-pe-6648302d.pdf"
    );
    let report = run_scan_with_detectors(bytes, base_opts(), &default_detectors())
        .expect("scan succeeds");
    let exploit_bucket = report.intent_summary.as_ref().unwrap().buckets.iter()
        .find(|b| format!("{:?}", b.bucket) == "ExploitPrimitive");
    assert!(exploit_bucket.is_some(), "ExploitPrimitive must fire for APT42 sample");
    let conf = exploit_bucket.unwrap().confidence.clone();
    assert!(
        matches!(conf, Confidence::Probable | Confidence::Strong),
        "confidence should promote above Heuristic for APT42, got {:?}", conf
    );
}

#[test]
fn intent_romcom_promotes_above_heuristic() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/romcom-embedded-payload-a99903.pdf"
    );
    let report = run_scan_with_detectors(bytes, base_opts(), &default_detectors())
        .expect("scan succeeds");
    let has_non_heuristic = report.intent_summary.as_ref().unwrap().buckets.iter()
        .any(|b| !matches!(b.confidence, Confidence::Heuristic));
    assert!(
        has_non_heuristic,
        "RomCom sample should have at least one non-Heuristic intent bucket"
    );
}
```

### 3.3 APT42 polyglot dropper composite finding

**File**: `crates/sis-pdf-core/src/correlation.rs`

Add to `correlate_findings_with_event_graph()`:
```rust
composites.extend(correlate_polyglot_dropper(findings));
```

Implement:
```rust
fn correlate_polyglot_dropper(findings: &[Finding]) -> Vec<Finding> {
    let polyglot = findings.iter().find(|f| f.kind == "polyglot_signature_conflict");
    let carved = findings.iter().filter(|f| f.kind == "embedded_payload_carved").collect::<Vec<_>>();
    let nested: Vec<_> = findings.iter()
        .filter(|f| f.kind == "nested_container_chain")
        .collect();

    if polyglot.is_none() || carved.is_empty() || nested.is_empty() {
        return Vec::new();
    }

    let pe_nested: Vec<_> = nested.iter()
        .filter(|f| f.meta.get("nested.kind").map(|k| k == "mz").unwrap_or(false))
        .collect();

    let dropper_kind = if !pe_nested.is_empty() {
        "polyglot_pe_dropper"
    } else {
        "polyglot_dropper_chain"
    };

    let pe_count = pe_nested.len();
    let pe_entries: Vec<String> = pe_nested.iter()
        .filter_map(|f| f.meta.get("container.entry").cloned())
        .collect();
    let zip_signatures = polyglot.unwrap().meta.get("polyglot.signatures")
        .cloned()
        .unwrap_or_default();

    let mut sources: Vec<&Finding> = Vec::new();
    sources.extend(polyglot.iter().copied());
    sources.extend(carved.iter().copied());
    sources.extend(nested.iter().copied());

    vec![build_composite(CompositeConfig {
        kind: dropper_kind,
        title: if !pe_nested.is_empty() {
            "Polyglot PDF+ZIP dropping PE executables"
        } else {
            "Polyglot container dropper chain"
        },
        description: "PDF is simultaneously valid as another container format, \
                      embedding an executable payload that can be extracted and run.",
        surface: AttackSurface::EmbeddedFiles,
        severity: Severity::Critical,
        confidence: if !pe_nested.is_empty() { Confidence::Strong } else { Confidence::Probable },
        sources: &sources,
        extra_meta: vec![
            ("dropper.pe_count", Some(pe_count.to_string())),
            ("dropper.pe_entries", if pe_entries.is_empty() { None } else { Some(pe_entries.join(",")) }),
            ("dropper.zip_signatures", Some(zip_signatures)),
            ("chain.stage", Some("decode".into())),
            ("exploit.outcomes", Some("executable_drop; sandbox_escape".into())),
            ("exploit.preconditions", Some("zip_extraction_tool_available".into())),
        ],
    })]
}
```

**Test** — add to `crates/sis-pdf-core/tests/correlation.rs`:
```rust
#[test]
fn apt42_polyglot_dropper_composite_fires() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/apt42-polyglot-pdf-zip-pe-6648302d.pdf"
    );
    let report = run_scan_with_detectors(bytes, deep_scan_opts(), &default_detectors())
        .expect("scan succeeds");
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(
        kinds.iter().any(|&k| k == "polyglot_pe_dropper" || k == "polyglot_dropper_chain"),
        "polyglot dropper composite must fire on APT42 sample. got: {:?}",
        kinds
    );
    let dropper = report.findings.iter()
        .find(|f| f.kind == "polyglot_pe_dropper" || f.kind == "polyglot_dropper_chain")
        .unwrap();
    assert_eq!(dropper.severity, Severity::Critical);
    assert!(
        matches!(dropper.confidence, Confidence::Strong | Confidence::Probable),
        "dropper should have strong confidence, got {:?}", dropper.confidence
    );
    let pe_count = dropper.meta.get("dropper.pe_count")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    assert_eq!(pe_count, 2, "APT42 has two PE entries");
}
```

### 3.4 Font exploitation cluster composite finding

**File**: `crates/sis-pdf-core/src/correlation.rs`

Add to `correlate_findings_with_event_graph()`:
```rust
composites.extend(correlate_font_exploitation_cluster(findings));
```

Implement:
```rust
const FONT_CLUSTER_THRESHOLD: usize = 5;

fn correlate_font_exploitation_cluster(findings: &[Finding]) -> Vec<Finding> {
    let font_findings: Vec<_> = findings.iter()
        .filter(|f| f.kind.starts_with("font.") &&
                    matches!(f.kind.as_str(),
                        "font.ttf_hinting_suspicious" | "font.ttf_hinting_push_loop" |
                        "font.cmap_range_overlap" | "font.multiple_vuln_signals" |
                        "font.dynamic_parse_failure" | "font.cmap_subtype_inconsistent"))
        .collect();

    if font_findings.len() < FONT_CLUSTER_THRESHOLD {
        return Vec::new();
    }

    // Check for escalating signals
    let has_vuln_signals = font_findings.iter().any(|f| f.kind == "font.multiple_vuln_signals");
    let has_parse_failure = font_findings.iter().any(|f| f.kind == "font.dynamic_parse_failure");
    let hinting_count = font_findings.iter()
        .filter(|f| f.kind == "font.ttf_hinting_suspicious" || f.kind == "font.ttf_hinting_push_loop")
        .count();

    let (severity, confidence, assessment) = if has_vuln_signals || (hinting_count >= 10 && has_parse_failure) {
        (Severity::High, Confidence::Probable, "heap spray or CVE-targeting font exploitation pattern")
    } else if hinting_count >= 5 {
        (Severity::Medium, Confidence::Probable, "suspicious font hinting cluster — possible exploit preparation")
    } else {
        (Severity::Medium, Confidence::Tentative, "elevated font anomaly count")
    };

    let kind_counts: HashMap<&str, usize> = font_findings.iter()
        .fold(HashMap::new(), |mut m, f| { *m.entry(f.kind.as_str()).or_insert(0) += 1; m });
    let kinds_str: Vec<String> = kind_counts.iter()
        .map(|(k, v)| format!("{}×{}", v, k))
        .collect();

    vec![build_composite(CompositeConfig {
        kind: "font_exploitation_cluster",
        title: "Font exploitation cluster",
        description: &format!(
            "{} suspicious font anomalies detected: {}. {}",
            font_findings.len(), kinds_str.join(", "), assessment
        ),
        surface: AttackSurface::Fonts,
        severity,
        confidence,
        sources: &font_findings,
        extra_meta: vec![
            ("font.cluster.count", Some(font_findings.len().to_string())),
            ("font.cluster.kinds", Some(kinds_str.join(","))),
            ("font.cluster.assessment", Some(assessment.into())),
            ("chain.stage", Some("render".into())),
            ("exploit.outcomes", Some("memory_corruption; renderer_compromise".into())),
        ],
    })]
}
```

Downgrade individual `font.ttf_hinting_suspicious` findings when the cluster fires: After
computing correlations, if `font_exploitation_cluster` is in composites, mark individual
`font.ttf_hinting_suspicious` findings with `meta["cluster.suppressed"] = "true"` and
downgrade to Low.

**Test**:
```rust
#[test]
fn font_exploitation_cluster_fires_on_font_heavy_fixture() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/font-heavy-objstm-5bb77b57.pdf"
    );
    let report = run_scan_with_detectors(bytes, deep_scan_opts(), &default_detectors())
        .expect("scan succeeds");
    let has_cluster = report.findings.iter()
        .any(|f| f.kind == "font_exploitation_cluster");
    assert!(has_cluster, "font_exploitation_cluster should fire on file with 25+ font anomalies");
    let cluster = report.findings.iter()
        .find(|f| f.kind == "font_exploitation_cluster").unwrap();
    assert!(
        cluster.meta.get("font.cluster.count")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0) >= 5,
        "cluster count should be >= 5"
    );
}
```

### 3.5 `object_reference_cycle` deduplication and cycle type classification

**File**: `crates/sis-pdf-detectors/src/object_cycles.rs`

After computing all cycles, classify each by type and suppress redundant ones:

```rust
pub const CYCLE_TYPE_PAGE_PARENT: &str = "page_parent";
pub const CYCLE_TYPE_ANNOTATION_PAGE_PARENT: &str = "annotation_page_parent";
pub const CYCLE_TYPE_ACTION_CYCLE: &str = "action_cycle";
pub const CYCLE_TYPE_CATALOG_CYCLE: &str = "catalog_cycle";
pub const CYCLE_TYPE_UNKNOWN: &str = "unknown_cycle";

fn classify_cycle(cycle_nodes: &[ObjectId], graph: &PdfObjectGraph) -> &'static str {
    // Check if all nodes in the cycle are page/pages objects
    let all_pages = cycle_nodes.iter().all(|id| {
        graph.get_type_str(id).map(|t| matches!(t, "Page" | "Pages")).unwrap_or(false)
    });
    if all_pages { return CYCLE_TYPE_PAGE_PARENT; }

    // Check if cycle involves annotation (/Subtype Link|Widget|...) and a Page
    let has_annotation = cycle_nodes.iter().any(|id| {
        let subtype = graph.get_subtype_str(id).unwrap_or("");
        matches!(subtype, "Link" | "Widget" | "FreeText" | "Text" | "Screen" | "FileAttachment")
    });
    let has_page = cycle_nodes.iter().any(|id| {
        graph.get_type_str(id).map(|t| t == "Page").unwrap_or(false)
    });
    if has_annotation && has_page { return CYCLE_TYPE_ANNOTATION_PAGE_PARENT; }

    // Check if cycle involves action-bearing objects
    let has_action = cycle_nodes.iter().any(|id| {
        graph.get_dict(id).map(|d| d.contains_key("S")).unwrap_or(false)
    });
    if has_action { return CYCLE_TYPE_ACTION_CYCLE; }

    // Check if cycle touches the catalog
    let has_catalog = cycle_nodes.iter().any(|id| {
        graph.get_type_str(id).map(|t| t == "Catalog").unwrap_or(false)
    });
    if has_catalog { return CYCLE_TYPE_CATALOG_CYCLE; }

    CYCLE_TYPE_UNKNOWN
}
```

After classifying, group cycles by type and emit findings accordingly:
- `page_parent` and `annotation_page_parent` cycles: suppress all but emit one summary
  `object_reference_cycle/Info` with `meta["cycle.suppressed_count"] = N`.
- `action_cycle` and `catalog_cycle`: emit individual findings at existing severity.
- For `page_parent` cycles, description should clarify "Benign reference cycle (page tree structure)".

Also update `correlate_graph_evasion_with_execute` in `correlation.rs` to exclude
`page_parent` and `annotation_page_parent` cycle types from the evasion count.

**Test**:
```rust
#[test]
fn page_tree_cycles_do_not_inflate_medium_findings() {
    let bytes = include_bytes!(
        "fixtures/corpus_captured/font-heavy-objstm-5bb77b57.pdf"
    );
    let report = run_scan_with_detectors(bytes, default_scan_opts(), &default_detectors())
        .expect("scan succeeds");
    let medium_cycles = report.findings.iter()
        .filter(|f| f.kind == "object_reference_cycle"
                 && matches!(f.severity, Severity::Medium | Severity::High))
        .count();
    assert!(
        medium_cycles <= 3,
        "page tree cycles should not generate >3 Medium/High cycle findings, got {}",
        medium_cycles
    );
}
```

---

## Stage 4: Output and Interface Fixes
**Goal**: Fix verdict field, correlate line limit, JS false positive, and query usability.
**Success criteria**:
- `sis scan --json` output contains `verdict` field
- `sis correlate campaign` processes rich findings without warnings
- JS analysis skips PDF-dict embedded files
- `sis query <pdf> chains` returns chains without separate scan step

### 4.1 Add verdict roll-up to scan report

**File**: `crates/sis-pdf-core/src/report.rs`

Add `VerdictSummary` struct and `verdict` field to `Report`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerdictSummary {
    pub label: String,           // "Malicious" | "Suspicious" | "Anomalous" | "Clean"
    pub confidence: String,      // from Confidence enum
    pub score: f64,              // 0.0 to 1.0
    pub top_chain_id: Option<String>,
    pub top_intent: Option<String>,
    pub rationale: String,       // human-readable explanation
}

pub struct Report {
    // ... existing fields ...
    pub verdict: Option<VerdictSummary>,  // NEW
}
```

**File**: `crates/sis-pdf-core/src/runner.rs`

Compute verdict after chains and intents are assembled:

```rust
fn compute_verdict(
    report: &Report,
) -> VerdictSummary {
    // Pick top chain by score
    let top_chain = report.chains.iter()
        .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
    let top_chain_score = top_chain.map(|c| c.score).unwrap_or(0.0);
    let top_chain_id = top_chain.map(|c| c.id.clone());

    // Pick top intent
    let top_intent = report.intent_summary.as_ref()
        .and_then(|s| s.buckets.iter().max_by_key(|b| b.score))
        .map(|b| format!("{:?}", b.bucket));

    // Determine label
    let has_critical = report.summary.critical > 0;
    let has_high = report.summary.high > 0;
    let has_strong_intent = report.intent_summary.as_ref()
        .map(|s| s.buckets.iter().any(|b| matches!(b.confidence, Confidence::Strong | Confidence::Certain)))
        .unwrap_or(false);

    let (label, confidence) = if has_critical || (top_chain_score >= 0.9 && has_strong_intent) {
        ("Malicious".into(), "Strong")
    } else if has_high || (top_chain_score >= 0.75) || has_strong_intent {
        ("Suspicious".into(), "Probable")
    } else if report.summary.medium > 0 || top_chain_score >= 0.5 {
        ("Anomalous".into(), "Heuristic")
    } else {
        ("Clean".into(), "Heuristic")
    };

    let rationale = format!(
        "{} finding(s) ({} Critical, {} High, {} Medium). \
         Top chain score {:.2}. {}",
        report.summary.total,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        top_chain_score,
        top_intent.as_deref().map(|i| format!("Top intent: {}.", i)).unwrap_or_default(),
    );

    VerdictSummary {
        label,
        confidence: confidence.into(),
        score: top_chain_score,
        top_chain_id,
        top_intent,
        rationale,
    }
}
```

**Test** — add to `crates/sis-pdf-core/tests/report_schema_compat.rs`:
```rust
#[test]
fn report_contains_verdict_field() {
    let bytes = include_bytes!("fixtures/launch_action.pdf");
    let report = run_scan_with_detectors(bytes, default_scan_opts(), &default_detectors())
        .expect("scan succeeds");
    assert!(report.verdict.is_some(), "report must contain verdict field");
    let v = report.verdict.unwrap();
    assert!(!v.label.is_empty(), "verdict label must not be empty");
    assert!(["Malicious","Suspicious","Anomalous","Clean"].contains(&v.label.as_str()),
            "unexpected label: {}", v.label);
}

#[test]
fn launch_action_pdf_verdict_is_suspicious_or_malicious() {
    let bytes = include_bytes!("fixtures/launch_action.pdf");
    let report = run_scan_with_detectors(bytes, default_scan_opts(), &default_detectors())
        .expect("scan succeeds");
    let v = report.verdict.unwrap();
    assert!(
        v.label == "Malicious" || v.label == "Suspicious",
        "launch_action.pdf should be Malicious or Suspicious, got: {}", v.label
    );
}
```

### 4.2 Fix `correlate campaign` JSONL line size limit

**File**: Find the JSONL reader in `crates/sis-pdf/src/cmd/correlate.rs` (or equivalent).

Locate the constant or variable that controls the line size limit (currently `10_240` bytes).
Change to `1_048_576` (1 MB). Add a `--max-line-bytes` flag:

```rust
// In CLI args:
#[arg(long, default_value = "1048576")]
max_line_bytes: usize,
```

Change the per-line warning to a summary-only warning. After processing:
```rust
if skipped_lines > 0 {
    warn!(
        skipped = skipped_lines,
        "some JSONL lines exceeded max-line-bytes and were skipped"
    );
}
```

**Test** — add to `crates/sis-pdf/tests/cli_integration.rs`:
```rust
#[test]
fn correlate_campaign_processes_large_findings_without_warnings() {
    // Use the booking phishing scan output as input
    let pdf = fixture_path("corpus_captured/booking-js-phishing-379b41e3.pdf");
    let scan_output = run_sis(&["scan", pdf.to_str().unwrap(), "--jsonl-findings"]);
    assert!(scan_output.status.success());

    let input_file = write_temp_file("correlate_input.jsonl", &scan_output.stdout);
    let output = run_sis(&["correlate", "campaign", "--input", input_file.to_str().unwrap()]);
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should not warn about line size
    assert!(!stderr.contains("size limit"), "should not hit size limit: {}", stderr);
}
```

### 4.3 JS false positive: skip PDF dict embedded files

**File**: `crates/sis-pdf-detectors/src/js_sandbox.rs` (or wherever embedded files are
forwarded to JS analysis)

Before passing an embedded file's decoded bytes to the JS parser:

```rust
const PDF_DICT_MARKER: &[u8] = b"<<";
const PS_COMMENT_MARKER: &[u8] = b"%!";
const PDF_HEADER_MARKER: &[u8] = b"%PDF";
const MAX_SIGNATURE_PEEK: usize = 16;

fn looks_like_js(data: &[u8]) -> bool {
    let peek = &data[..data.len().min(MAX_SIGNATURE_PEEK)];
    // Quick reject: PDF dict, PostScript, or binary (non-printable first byte with high bit)
    if peek.starts_with(PDF_DICT_MARKER) ||
       peek.starts_with(PS_COMMENT_MARKER) ||
       peek.starts_with(PDF_HEADER_MARKER) {
        return false;
    }
    // Null bytes in first 4 bytes = binary, not JS
    if peek.iter().take(4).any(|&b| b == 0) {
        return false;
    }
    true
}
```

If `!looks_like_js(decoded)`:
- Skip JS sandbox and AST analysis.
- Emit `embedded_file_not_js/Info/Strong` with note "content appears to be PDF dict or PostScript, not JavaScript".
- Set `meta["js.likely_non_js"] = "true"` if the sandbox is still called (shouldn't be).

Also: when `js.runtime.errors` contains `"unexpected token '<<'"` in an already-analyzed file,
set `meta["js.likely_non_js"] = "true"` and downgrade `js_sandbox_exec` confidence from Strong
to Tentative.

**Test**:
```rust
#[test]
fn pdf_dict_embedded_file_is_not_analyzed_as_js() {
    // 9ff24c46 has an IEEE.joboptions file starting with "<<"
    let bytes = include_bytes!(
        "fixtures/corpus_captured/font-exploit-embedded-js-9ff24c46.pdf"
    );
    let report = run_scan_with_detectors(bytes, deep_scan_opts(), &default_detectors())
        .expect("scan succeeds");
    // Should either emit embedded_file_not_js or not have js.runtime.error for "<<"
    let has_dict_error = report.findings.iter().any(|f| {
        f.meta.get("js.runtime.errors")
            .map(|e| e.contains("unexpected token '<<'"))
            .unwrap_or(false)
    });
    // If the error occurred, the sandbox result should be marked non-JS
    if has_dict_error {
        let sandbox_findings = report.findings.iter()
            .filter(|f| f.kind == "js_sandbox_exec")
            .collect::<Vec<_>>();
        for sf in sandbox_findings {
            let is_marked = sf.meta.get("js.likely_non_js").map(|v| v == "true").unwrap_or(false);
            let is_tentative = matches!(sf.confidence, Confidence::Tentative | Confidence::Weak);
            assert!(
                is_marked || is_tentative,
                "js_sandbox_exec should be marked non-JS or downgraded when '<<' token error occurs"
            );
        }
    }
}
```

---

## Stage 5: Corpus Regression Tests
**Goal**: Add a comprehensive regression test module for all new and updated fixtures.
**Success criteria**: `cargo test -p sis-pdf-core --test corpus_captured_regressions` passes.
All new fixtures are covered. Drift guards present for key metadata invariants.

**File**: `crates/sis-pdf-core/tests/corpus_captured_regressions.rs`

Add tests for all new fixtures. Each test follows the existing pattern from that file.

### 5.1 APT42 polyglot regression test

```rust
#[test]
fn apt42_polyglot_pe_dropper_regression() {
    let report = scan_corpus_fixture("apt42-polyglot-pdf-zip-pe-6648302d.pdf");

    // Core detections must be present
    assert_finding_kind(&report, "polyglot_signature_conflict");
    assert_finding_kind(&report, "embedded_payload_carved");
    assert_finding_kind_count(&report, "nested_container_chain", 2);

    // After stage 3: composite must be present
    assert_finding_kind(&report, "polyglot_pe_dropper");

    // Polyglot finding metadata invariants
    let polyglot = finding_by_kind(&report, "polyglot_signature_conflict");
    assert_eq!(polyglot.severity, Severity::High);
    assert_eq!(polyglot.confidence, Confidence::Strong);
    let sigs = polyglot.meta.get("polyglot.signatures").expect("polyglot.signatures");
    assert!(sigs.contains("ZIP"), "should detect ZIP signature: {}", sigs);

    // PE dropper metadata invariants (drift guards)
    let dropper = finding_by_kind(&report, "polyglot_pe_dropper");
    let pe_count: usize = dropper.meta.get("dropper.pe_count")
        .and_then(|v| v.parse().ok())
        .expect("dropper.pe_count must be numeric");
    assert_eq!(pe_count, 2, "drift_guard: apt42 has exactly 2 PE entries");

    let pe_entries = dropper.meta.get("dropper.pe_entries").expect("dropper.pe_entries");
    assert!(pe_entries.contains("msvcp140.dll"), "drift_guard: msvcp140.dll entry expected");

    // Intent check
    assert_intent_bucket(&report, "ExploitPrimitive");
    let exploit = intent_bucket(&report, "ExploitPrimitive");
    assert!(exploit.score >= 8, "drift_guard: ExploitPrimitive score >= 8");
}
```

### 5.2 Booking phishing regression test

```rust
#[test]
fn booking_js_phishing_regression() {
    let report = scan_corpus_fixture("booking-js-phishing-379b41e3.pdf");

    // Core detections
    assert_finding_kind(&report, "js_present");
    assert_finding_kind(&report, "annotation_action_chain");
    assert_finding_kind(&report, "js_intent_user_interaction");

    // Network intents
    let network = &report.network_intents;
    assert!(!network.is_empty(), "booking phishing must have network intents");
    let has_netlify = network.iter().any(|n| n.url.contains("netlify.app"));
    assert!(has_netlify, "drift_guard: netlify.app URL in network intents");

    // Chain quality (after stage 2 fixes)
    let singleton_count = report.chains.iter().filter(|c| c.findings.len() == 1).count();
    let total_chains = report.chains.len();
    assert!(total_chains <= 8, "drift_guard: <= 8 chains, got {}", total_chains);

    // No finding appears in multiple chains
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for chain in &report.chains {
        for fid in &chain.findings {
            assert!(seen.insert(fid.as_str()),
                    "drift_guard: finding {} in multiple chains", fid);
        }
    }

    // Verdict
    let verdict = report.verdict.as_ref().expect("verdict must be present");
    assert!(
        verdict.label == "Suspicious" || verdict.label == "Malicious",
        "drift_guard: booking phishing verdict must be Suspicious or Malicious"
    );
}
```

### 5.3 Decompression bomb regression test

```rust
#[test]
fn decompression_bomb_regression() {
    let start = std::time::Instant::now();
    let report = scan_corpus_fixture("decompression-bomb-11606ab5.pdf");
    let elapsed = start.elapsed().as_millis();

    // Performance: must complete in <8s
    assert!(elapsed < 8_000, "drift_guard: scan time {}ms must be < 8000ms", elapsed);

    // Core detections
    assert_finding_kind_count(&report, "decompression_ratio_suspicious", 2);
    assert_finding_kind(&report, "parser_resource_exhaustion");

    // Severity check
    let decomp = finding_by_kind(&report, "decompression_ratio_suspicious");
    assert_eq!(decomp.severity, Severity::Critical, "decompression bomb must be Critical");

    // Intent: DenialOfService must fire
    assert_intent_bucket(&report, "DenialOfService");
    let dos = intent_bucket(&report, "DenialOfService");
    assert!(
        matches!(dos.confidence, Confidence::Strong | Confidence::Probable),
        "drift_guard: DoS intent should be Strong or Probable"
    );

    // Ratio metadata
    let ratio_finding = report.findings.iter()
        .find(|f| f.kind == "decompression_ratio_suspicious")
        .expect("decompression finding");
    // The ratio should be high (485:1 or 123:1)
    // Exact values may vary; just check it's documented
    assert!(
        ratio_finding.description.contains("ratio") || ratio_finding.meta.contains_key("ratio"),
        "drift_guard: ratio must be present in finding"
    );
}
```

### 5.4 Performance hang regression test

```rust
#[test]
fn perf_hang_717_objects_completes_within_budget() {
    let start = std::time::Instant::now();
    let report = scan_corpus_fixture("perf-hang-717obj-fb87d8a7.pdf");
    let elapsed = start.elapsed().as_millis();

    // Critical: was 292,000 ms before fix, must be < 10,000 ms
    assert!(
        elapsed < 10_000,
        "drift_guard: 717-object PDF must scan in < 10,000 ms, took {} ms", elapsed
    );

    // Scan must produce findings (not silently skipped)
    assert!(!report.findings.is_empty(), "drift_guard: must produce findings");
}
```

### 5.5 Font heavy performance regression test

```rust
#[test]
fn font_heavy_objstm_regression() {
    let start = std::time::Instant::now();
    let report = scan_corpus_fixture("font-heavy-objstm-5bb77b57.pdf");
    let elapsed = start.elapsed().as_millis();

    // Performance: should be fast now (was 13.4s before font clustering)
    assert!(elapsed < 5_000, "drift_guard: font-heavy scan must complete in <5s, took {}ms", elapsed);

    // After stage 3: font cluster must fire
    assert_finding_kind(&report, "font_exploitation_cluster");
    let cluster = finding_by_kind(&report, "font_exploitation_cluster");
    let count: usize = cluster.meta.get("font.cluster.count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(count >= 25, "drift_guard: cluster should have >=25 members, got {}", count);

    // Singleton chain rate check
    let total = report.chains.len();
    let singletons = report.chains.iter().filter(|c| c.findings.len() == 1).count();
    let rate = if total == 0 { 0.0 } else { singletons as f64 / total as f64 };
    assert!(rate <= 0.70, "drift_guard: singleton rate {:.1}% must be <= 70%", rate * 100.0);

    // Stage coverage
    let has_render = report.chains.iter().any(|c| c.confirmed_stages.contains(&"render".into()));
    assert!(has_render, "drift_guard: render stage should be confirmed for font-heavy file");
}
```

### 5.6 RomCom intent regression test

```rust
#[test]
fn romcom_intent_regression() {
    let report = scan_corpus_fixture("romcom-embedded-payload-a99903.pdf");

    // Core detections
    assert_finding_kind_count(&report, "embedded_payload_carved", 2);

    // Network intents
    assert!(!report.network_intents.is_empty(), "RomCom must have network intents");

    // Intent: should promote above Heuristic
    let has_non_heuristic = report.intent_summary.as_ref().map(|s| {
        s.buckets.iter().any(|b| !matches!(b.confidence, Confidence::Heuristic))
    }).unwrap_or(false);
    assert!(
        has_non_heuristic,
        "drift_guard: RomCom should have at least one non-Heuristic intent bucket"
    );
}
```

---

## Stage 6: CLI and Interface Improvements
**Goal**: Fix minor CLI inconsistencies, add `--verdict-only` mode, document changes.

### 6.1 Add `--verdict-only` scan output mode

**File**: `crates/sis-pdf/src/main.rs`

Add flag to scan subcommand:
```
--verdict-only   Print only the verdict label and score (e.g., "Suspicious 0.82")
```

Implementation: run full scan, then print `"{label} {score:.2} {top_intent}"` to stdout.

### 6.2 Fix `sis scan --json` argument conflict hint

The error message when both `--json` and `--jsonl` are specified should be more helpful.
Currently: no explicit conflict declared. Add:
```rust
#[arg(long, conflicts_with_all = &["jsonl", "jsonl_findings", "sarif"])]
json: bool,
```

### 6.3 Document `sis batch` → `sis scan --path` migration note

In `sis doc` output and `docs/cli.md`, add:
```markdown
## Batch scanning

Use `sis scan --path <directory>` to scan all PDFs in a directory.
There is no `sis batch` command. The `--path` flag enables directory scanning.
```

### 6.4 Fix `sis query <pdf> chains` to trigger scan

**File**: `crates/sis-pdf/src/cmd/query.rs`

In the handler for `chains` query type, check if we have a pre-computed report (e.g., from
a cache file); if not, run a standard scan and return its chains.

Note: If this requires significant refactoring of the query handler, defer to a follow-on plan
and add a doc note explaining the limitation.

---

## Stage 7: Test Infrastructure
**Goal**: Ensure all stages have CI-runnable tests and no regressions.

### 7.1 Add `scan_corpus_fixture()` helper to test utilities

**File**: `crates/sis-pdf-core/tests/corpus_captured_regressions.rs`

Extend the existing scan helper:
```rust
fn scan_corpus_fixture(name: &str) -> Report {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/corpus_captured");
    path.push(name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("corpus fixture not found: {}", path.display()));
    run_scan_with_detectors(&bytes, deep_opts(), &default_detectors())
        .expect("scan should succeed")
}

fn assert_intent_bucket(report: &Report, name: &str) {
    let buckets: Vec<_> = report.intent_summary.as_ref()
        .map(|s| s.buckets.iter().map(|b| format!("{:?}", b.bucket)).collect())
        .unwrap_or_default();
    assert!(
        buckets.iter().any(|b| b == name),
        "intent bucket {} not found; got: {:?}", name, buckets
    );
}

fn intent_bucket<'a>(report: &'a Report, name: &str) -> &'a IntentBucketSummary {
    report.intent_summary.as_ref().unwrap().buckets.iter()
        .find(|b| format!("{:?}", b.bucket) == name)
        .unwrap_or_else(|| panic!("intent bucket {} not found", name))
}

fn assert_finding_kind_count(report: &Report, kind: &str, expected: usize) {
    let count = report.findings.iter().filter(|f| f.kind == kind).count();
    assert_eq!(count, expected, "expected {} findings of kind {}, got {}", expected, kind, count);
}
```

### 7.2 Baseline performance test

Add to `crates/sis-pdf-core/tests/performance_fixtures.rs`:
```rust
#[test]
fn batch_of_fixtures_completes_within_global_budget() {
    // Scan all corpus_captured fixtures in sequence.
    // Total budget: 60 seconds for the full suite.
    let fixtures = [
        "corpus_captured/apt42-polyglot-pdf-zip-pe-6648302d.pdf",
        "corpus_captured/booking-js-phishing-379b41e3.pdf",
        "corpus_captured/font-exploit-embedded-js-9ff24c46.pdf",
        "corpus_captured/fog-netlify-phishing-6eb8b598.pdf",
        "corpus_captured/romcom-embedded-payload-a99903.pdf",
        "corpus_captured/decompression-bomb-11606ab5.pdf",
        "corpus_captured/perf-hang-717obj-fb87d8a7.pdf",
        "corpus_captured/font-heavy-objstm-5bb77b57.pdf",
    ];
    let start = std::time::Instant::now();
    for fixture in fixtures {
        scan_fixture(fixture); // existing helper
    }
    let elapsed = start.elapsed().as_millis();
    assert!(elapsed < 60_000, "batch of fixtures must complete in <60s, took {}ms", elapsed);
}
```

---

## Implementation Sequence

| Stage | Items | Estimated Effort | Critical Path |
|---|---|---|---|
| 0 | Fixture capture | 0.5 day | Yes — all later tests depend on it |
| 1.1 | content_stream_exec_uplift fix | 0.5 day | Yes — blocks production use |
| 1.2 | content_phishing size guards | 0.5 day | Yes |
| 1.3 | Per-file timeout | 1 day | Parallel to 1.1/1.2 |
| 2.1 | Chain label/severity fields | 0.5 day | Required for 2.2 |
| 2.2 | Kind-based cluster chains | 1 day | Core chain fix |
| 2.3 | Finding deduplication | 0.5 day | After 2.2 |
| 2.4 | Stage completeness inference | 0.5 day | After 2.2 |
| 3.1 | DenialOfService intent bucket | 0.5 day | |
| 3.2 | Intent confidence promotion | 1 day | |
| 3.3 | APT42 polyglot dropper composite | 1 day | |
| 3.4 | Font exploitation cluster | 1 day | After 2.2 (chains must cluster first) |
| 3.5 | Cycle type classification | 1 day | |
| 4.1 | Verdict roll-up | 1 day | After 3.x |
| 4.2 | Correlate line limit fix | 0.25 day | |
| 4.3 | JS FP: skip PDF dict | 0.5 day | |
| 4.4 | Query chains trigger scan | 1 day | |
| 5 | Corpus regression tests | 1 day | After all above |
| 6 | CLI improvements | 0.5 day | |
| 7 | Test infrastructure | 0.5 day | |

**Total**: ~12 developer-days

**Stage gates**: After each stage, all existing tests must still pass. Run:
```
cargo test -p sis-pdf-core
cargo test -p sis-pdf
```

---

## Metrics and Acceptance Criteria

After Stage 1:
- [ ] `perf-hang-717obj-fb87d8a7.pdf` scans in < 10 s (was 292 s)
- [ ] Batch of 20 files from mwb-latest completes in < 60 s wall time
- [ ] No scan in the batch hangs > 60 s

After Stage 2:
- [ ] Singleton chain rate on `font-heavy-objstm-5bb77b57.pdf`: ≤ 70% (was 100%)
- [ ] `booking-js-phishing-379b41e3.pdf` produces ≤ 8 chains (was 24)
- [ ] All chains have non-empty `label` and `severity` fields
- [ ] No finding ID appears in more than one chain

After Stage 3:
- [ ] APT42: `polyglot_pe_dropper/Critical/Strong` present; `ExploitPrimitive/Probable+`
- [ ] Decompression bomb: `DenialOfService/Strong` intent fires
- [ ] RomCom: at least one intent bucket at Probable or higher (was all Heuristic)
- [ ] Font heavy: `font_exploitation_cluster/High` present; Medium cycle findings ≤ 3

After Stage 4:
- [ ] `sis scan --json` output contains `verdict` field with label and score
- [ ] `sis correlate campaign` on rich findings emits no size-limit warnings
- [ ] JS analysis doesn't emit `<<` syntax errors for PDF-dict embedded files

After Stage 5:
- [ ] `cargo test -p sis-pdf-core --test corpus_captured_regressions` passes fully
- [ ] All 8 new fixtures registered in manifest with regression_targets

---

## Notes

### What the previous plan items this supersedes

From `20260227-corpus-analysis-uplift.md`:
- P1.1 `/Win` dict parsing — **not addressed here**, remains valid
- P1.2 PowerShell URL extraction from `/P` params — **not addressed here**, remains valid
- P2.1 Role mapping expansion — **addressed differently** (stage-based inference in Stage 2.4)
- P2.2 Chain merging — **addressed** as Stage 2.2/2.3
- P2.3 Completeness formula — **addressed** as Stage 2.4
- P3.1–P3.5 False positive reduction — **addressed partially** (P3.4 font noise, P3.5 cycles)
- P4.1 Lure detection — **not addressed**, remains valid
- P4.2 URI enrichment — **partially addressed** (DET-6 in perf plan)
- P4.3 Phishing chain composite — **not addressed**, remains valid
- P4.4 JS URL extraction — **not addressed**, remains valid
- P5, P6 Deep mode, CI — **not addressed in this plan**

Items not addressed here should be collected into a follow-on plan after this plan is complete.

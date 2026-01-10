# Review: Evasive Content Hiding in PDFs

**Date**: 2026-01-08
**Status**: Analysis and Recommendations
**Focus**: PDF-level and JavaScript-level evasion techniques for hiding malicious content

---

## Executive Summary

This document reviews evasion techniques attackers use to hide JavaScript and other malicious content within PDF binary structures, evaluates our current detection and reconstruction capabilities, and provides comprehensive recommendations for improvement.

**Key Findings**:
- Current implementation handles standard extraction well (strings, streams, object streams, filters)
- Significant gaps exist in advanced evasion detection (fragmentation, encoding chains, dictionary key variations, name obfuscation)
- Limited string reconstruction for split/concatenated payloads
- IR capabilities exist but underutilised for payload reconstruction
- No systematic detection of evasive structural patterns

**Impact**: Sophisticated attackers can evade detection through PDF-level obfuscation even with comprehensive JavaScript pattern detection.

**Priority Recommendation**: Implement content reconstruction pipeline before expanding pattern detection further.

---

## Table of Contents

1. [Current Capabilities](#current-capabilities)
2. [PDF-Level Evasion Techniques](#pdf-level-evasion-techniques)
3. [JavaScript-Level Evasion](#javascript-level-evasion)
4. [Gaps and Limitations](#gaps-and-limitations)
5. [Recommendations](#recommendations)
6. [Implementation Roadmap](#implementation-roadmap)

---

## Current Capabilities

### 1. JavaScript Extraction

**Location**: `crates/sis-pdf-detectors/src/lib.rs:516-629`

**Current Implementation**:
```rust
// JavaScriptDetector looks for /JS key in dictionaries
if let Some((k, v)) = dict.get_first(b"/JS") {
    js_obj = Some((k, v));
}

// Resolves payload through resolve_payload()
let res = resolve_payload(ctx, v);
```

**Capabilities**:
- ✅ Detects `/JS` key in dictionaries
- ✅ Resolves direct string payloads
- ✅ Resolves stream objects with filters
- ✅ Follows single-level indirect references
- ✅ Decodes standard filters (FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode, RunLengthDecode)
- ✅ Handles predictor functions (TIFF, PNG)
- ✅ Applies 3-layer deobfuscation (hex escapes, base64, hex strings)

**Detection Coverage** (`crates/js-analysis/src/static_analysis.rs`):
- ✅ 73 detection functions covering 22 malware categories
- ✅ Shellcode, memory corruption, exploit kits, ransomware
- ✅ Resource exhaustion, code injection, anti-analysis
- ✅ ~95% coverage of **known** JavaScript malware patterns

### 2. Stream Decoding

**Location**: `crates/sis-pdf-pdf/src/decode.rs`

**Supported Filters**:
- `/FlateDecode` (zlib/deflate)
- `/ASCIIHexDecode`
- `/ASCII85Decode`
- `/LZWDecode`
- `/RunLengthDecode`
- `/DCTDecode` (JPEG - passes through)
- `/JPXDecode` (JPEG2000 - passes through)
- `/CCITTFaxDecode` (passes through)

**Predictor Support**:
- TIFF predictor (Predictor=2)
- PNG predictors (Predictor=10-15)

**Limitations**:
- ⚠️ Fixed filter support only (no custom/proprietary filters)
- ⚠️ Single decode pass per stream
- ⚠️ No cross-object reconstruction
- ⚠️ Limited error recovery (decode failures stop extraction)

### 3. Object Stream (ObjStm) Expansion

**Location**: `crates/sis-pdf-pdf/src/objstm.rs`

**Capabilities**:
- ✅ Expands object streams when `--deep` flag is used
- ✅ Security boundaries: max 100 ObjStm, configurable byte limits
- ✅ Decodes compressed object collections
- ✅ Parses integer pairs (obj/gen) and reconstructs objects

**Limitations**:
- ⚠️ Only activated with `--deep` flag (not in triage mode)
- ⚠️ No detection of suspicious ObjStm patterns
- ⚠️ No reconstruction of split content across multiple ObjStm

### 4. Object Graph and IR

**Location**: `crates/sis-pdf-pdf/src/graph.rs`, `crates/sis-pdf-pdf/src/ir.rs`

**Object Graph**:
- ✅ Indexes all objects by (obj, gen) ID
- ✅ Resolves indirect references
- ✅ Handles shadowed object IDs (incremental updates)
- ✅ Tracks xref conflicts and deviations

**IR (Intermediate Representation)**:
- ✅ Flattens object structure into key-value lines
- ✅ Path-based navigation (`$.Type`, `$.JS`, etc.)
- ✅ Truncation for large arrays/strings
- ✅ Stream metadata (filters, length)

**Underutilised Capabilities**:
- 💡 IR could enable cross-object string reconstruction
- 💡 Graph traversal could detect payload fragmentation patterns
- 💡 Reference chain analysis could identify obfuscation layers

### 5. Reference Resolution

**Location**: `crates/sis-pdf-detectors/src/lib.rs:1677-1729`

**Capabilities**:
- ✅ Single-level reference resolution
- ✅ Follows `N 0 R` → object `N`
- ✅ Extracts from resolved strings or streams

**Limitations**:
- ⚠️ No multi-hop reference chain reconstruction
- ⚠️ No array flattening for split references
- ⚠️ No detection of circular references (evasion technique)

### 6. Deobfuscation

**Location**: `crates/js-analysis/src/static_analysis.rs:434-529`

**Current Layers**:
1. JavaScript escape sequences (`\xNN`, `\uNNNN`)
2. Hex string decoding (pure hex content)
3. Base64 decoding

**Limitations**:
- ⚠️ Only 3 iterations maximum
- ⚠️ No string concatenation resolution
- ⚠️ No eval/Function reconstruction
- ⚠️ No array-to-string conversion
- ⚠️ No charCode/fromCharCode resolution

---

## PDF-Level Evasion Techniques

### Category 1: Key Name Obfuscation

**Threat Level**: 🔴 CRITICAL
**Current Detection**: ❌ None

#### Technique 1.1: Hex-Encoded Name Keys

**Description**: PDF allows name objects to use hex encoding for characters.

```pdf
% Standard:
<< /JS (app.alert('malicious')) >>

% Evasive:
<< /#4A#53 (app.alert('malicious')) >>
% #4A#53 = "JS" in hex

% More evasive:
<< /#4A#53#63#72#69#70#74 (payload) >>
% #4A#53#63#72#69#70#74 = "JScript" (non-standard but accepted by some readers)
```

**Impact**: Bypasses simple `/JS` string search.

**Current Capability**: ⚠️ Parser may decode hex names, but detector looks for literal `/JS` bytes.

**Recommendation**: Normalise all name objects before pattern matching.

#### Technique 1.2: Whitespace in Names

**Description**: Some readers tolerate whitespace in name objects.

```pdf
<< /J#20S (payload) >>
% #20 = space character
```

**Impact**: Evades exact string matching.

**Current Capability**: ❌ Unknown if parser handles this.

#### Technique 1.3: Alternative Keys

**Description**: Some readers accept non-standard variations.

```pdf
<< /JavaScript (payload) >>  % Instead of /JS
<< /JScript (payload) >>     % Microsoft variant
```

**Impact**: Detection gap if only `/JS` is checked.

**Current Capability**: ⚠️ Only checks `/S /JavaScript` for action dictionaries, not as direct key.

**Recommendation**: Check for `/JavaScript`, `/JScript`, and hex-encoded variants.

### Category 2: Payload Fragmentation

**Threat Level**: 🔴 CRITICAL
**Current Detection**: ❌ None

#### Technique 2.1: Array-Based String Splitting

**Description**: JavaScript payload split across array elements.

```pdf
<< /JS [(app.alert\() (') (malicious) (')) ] >>
% String array concatenated: "app.alert('malicious')"
```

**Impact**: Static analysis sees individual string fragments, not complete payload.

**Current Capability**: ❌ `resolve_payload()` does not handle arrays.

**Reconstruction Need**: HIGH

#### Technique 2.2: Multi-Object Reference Chain

**Description**: Payload split across multiple indirect objects.

```pdf
10 0 obj
<< /JS 11 0 R >>
endobj

11 0 obj
[ 12 0 R 13 0 R 14 0 R ]
endobj

12 0 obj
(app.alert\()
endobj

13 0 obj
('malicious')
endobj

14 0 obj
(\))
endobj
```

**Impact**: Each object appears benign in isolation.

**Current Capability**: ❌ Only single-level reference resolution.

**Reconstruction Need**: CRITICAL

#### Technique 2.3: String Concatenation via Multiple /JS Keys

**Description**: Some readers merge multiple `/JS` entries.

```pdf
<< /JS (part1) /JS (part2) >>
% Some readers concatenate: "part1part2"
```

**Impact**: Detection sees only first `/JS` key.

**Current Capability**: ⚠️ `dict.get_first(b"/JS")` returns only first occurrence.

**Recommendation**: Check for multiple keys with same name.

### Category 3: Encoding and Filter Chains

**Threat Level**: 🟠 HIGH
**Current Detection**: ⚠️ Partial

#### Technique 3.1: Multiple Filter Layers

**Description**: Stack multiple filters to obfuscate content.

```pdf
<< /Filter [/ASCII85Decode /FlateDecode /ASCIIHexDecode] >>
stream
% Triple-encoded payload
endstream
```

**Impact**: Legitimate but can hide malicious content through complexity.

**Current Capability**: ✅ Handles filter arrays, decodes in sequence.

**Detection Gap**: No anomaly detection for excessive filter depth.

**Recommendation**: Add finding for filter chains >2 layers (exists: `FilterChainDepthDetector`).

#### Technique 3.2: Malformed Filter Parameters

**Description**: Use edge cases in predictor parameters.

```pdf
<< /Filter /FlateDecode
   /DecodeParms << /Predictor 12 /Columns 1 /Colors 1 >>
>>
% Forces PNG Up predictor on small columns (unusual)
```

**Impact**: May cause decoder to fail or behave unexpectedly.

**Current Capability**: ✅ Validates parameters, but may skip unusual combinations.

**Recommendation**: Detect anomalous predictor combinations.

#### Technique 3.3: Partial Stream Truncation

**Description**: Stream `/Length` shorter than actual stream data.

```pdf
<< /Length 50 >>
stream
(50 bytes of benign content)(100 bytes of hidden malicious content)
endstream
```

**Impact**: Decoder reads only first 50 bytes; hidden content ignored.

**Current Capability**: ⚠️ Decoder respects `/Length`, hidden content not extracted.

**Recommendation**: Detect stream length mismatches (exists: finding `stream_length_mismatch`).

### Category 4: Object Stream Obfuscation

**Threat Level**: 🟠 HIGH
**Current Detection**: ⚠️ Partial (requires `--deep`)

#### Technique 4.1: Deeply Nested ObjStm

**Description**: Hide JavaScript objects inside compressed object streams.

```pdf
5 0 obj
<< /Type /ObjStm /N 3 /First 12 /Filter /FlateDecode >>
stream
% Compressed content containing:
% 10 0 11 20 12 35
% (object 10 at offset 0, object 11 at offset 20, object 12 at offset 35)
% Object 12 contains: << /JS (malicious) >>
endstream
endobj
```

**Impact**: JavaScript hidden in compressed stream, only visible with deep expansion.

**Current Capability**: ✅ Expands ObjStm with `--deep` flag.
⚠️ Not enabled in default triage mode.

**Recommendation**: Always enable ObjStm expansion (with resource limits).

#### Technique 4.2: Chained ObjStm References

**Description**: Object stream containing references to other object streams.

```pdf
5 0 obj
<< /Type /ObjStm /N 1 /First 5 /Filter /FlateDecode >>
stream
10 0
<< /Type /ObjStm /N 1 /First 5 /Filter /FlateDecode >>
stream
20 0
<< /JS (payload) >>
endstream
endstream
endobj
```

**Impact**: Multi-level extraction required.

**Current Capability**: ⚠️ Unknown if nested ObjStm expansion is supported.

**Recommendation**: Test and ensure recursive ObjStm expansion.

### Category 5: Encoding Obfuscation

**Threat Level**: 🟡 MEDIUM
**Current Detection**: ⚠️ Partial

#### Technique 5.1: PDF String Encoding Variants

**Description**: PDF supports literal strings and hex strings.

```pdf
% Literal string:
<< /JS (app.alert('test')) >>

% Hex string (same content):
<< /JS <6170702E616C657274282774657374272929> >>

% Mixed encoding:
<< /JS (app.)<616C657274>('test') >>
```

**Impact**: Pattern matching may miss hex-encoded strings.

**Current Capability**: ✅ Parser decodes both formats.
⚠️ Static analysis operates on decoded bytes (good).

**Gap**: None identified.

#### Technique 5.2: Octal Escapes in Literal Strings

**Description**: PDF literal strings support `\NNN` octal escapes.

```pdf
<< /JS (app.\141\154\145\162\164\('test'\)) >>
% \141\154\145\162\164 = "alert"
```

**Impact**: String content obfuscated at PDF level.

**Current Capability**: ✅ Parser decodes octal escapes.

**Gap**: None identified.

### Category 6: Structural Evasion

**Threat Level**: 🟡 MEDIUM
**Current Detection**: ⚠️ Partial

#### Technique 6.1: Object ID Shadowing

**Description**: Define same object ID multiple times (incremental updates).

```pdf
% Original (benign):
10 0 obj
<< /Type /Action /S /JavaScript /JS (benign code) >>
endobj

%%EOF

% Incremental update (malicious):
10 0 obj
<< /Type /Action /S /JavaScript /JS (malicious code) >>
endobj

%%EOF
```

**Impact**: Older objects may be indexed; newer objects contain malicious content.

**Current Capability**: ✅ Object graph tracks all versions.
⚠️ `get_object()` returns first entry - **potential evasion if shadowing is reversed**.

**Recommendation**: Review shadowing resolution logic; ensure latest version is used.

#### Technique 6.2: Circular References

**Description**: Create reference loops to cause parser issues.

```pdf
10 0 obj
<< /JS 11 0 R >>
endobj

11 0 obj
<< /Ref 10 0 R >>
endobj
```

**Impact**: Infinite loop in naive reference resolution.

**Current Capability**: ⚠️ Unknown if circular reference protection exists.

**Recommendation**: Add circular reference detection.

#### Technique 6.3: Trailer Manipulation

**Description**: Multiple trailers with conflicting `/Root` or `/Info`.

```pdf
trailer
<< /Root 1 0 R >>  % Points to benign catalog

%%EOF

trailer
<< /Root 2 0 R >>  % Points to malicious catalog
```

**Impact**: Different readers may use different trailers.

**Current Capability**: ✅ Tracks all trailers (`graph.trailers`).
⚠️ Unclear which trailer is used for catalog resolution.

**Recommendation**: Detect conflicting trailers as anomaly.

### Category 7: Content Stream Evasion

**Threat Level**: 🟢 LOW
**Current Detection**: ❌ None

#### Technique 7.1: JavaScript in Content Streams

**Description**: Embed JavaScript-like strings in page content streams (not executable but suspicious).

```pdf
stream
BT
/F1 12 Tf
(app.alert('test')) Tj  % Text object containing JS-like string
ET
endstream
```

**Impact**: Not directly executable, but may confuse analysis or indicate obfuscated intent.

**Current Capability**: ❌ Content streams not analysed for JavaScript patterns.

**Recommendation**: LOW priority - focus on actual executable contexts first.

### Category 8: XFA-Based Evasion

**Threat Level**: 🟠 HIGH
**Current Detection**: ⚠️ Partial

#### Technique 8.1: JavaScript in XFA XML

**Description**: XFA forms embed JavaScript in XML datasets.

```xml
<xfa:datasets>
  <xfa:data>
    <field>
      <script contentType="application/x-javascript">
        app.alert('malicious')
      </script>
    </field>
  </xfa:data>
</xfa:datasets>
```

**Impact**: JavaScript hidden in XML structure, not in `/JS` dictionary keys.

**Current Capability**: ⚠️ XFA presence detected (`XfaDetector`), but content not extracted.

**Recommendation**: Parse XFA XML and extract embedded JavaScript.

---

## JavaScript-Level Evasion

**Note**: This section focuses on **JavaScript obfuscation** rather than PDF-level hiding. Current implementation has strong coverage here.

### Category 9: Dynamic Code Construction

**Threat Level**: 🔴 CRITICAL
**Current Detection**: ⚠️ Partial

#### Technique 9.1: String Concatenation

**Description**: Build malicious strings dynamically.

```javascript
var a = "app";
var b = ".alert";
var c = "('malicious')";
eval(a + b + c);  // Executes: app.alert('malicious')
```

**Impact**: Static analysis sees separate strings, not complete payload.

**Current Capability**: ⚠️ Detects `eval` usage (`js.eval_usage`), but not string reconstruction.

**Recommendation**: Implement constant propagation and string concatenation analysis.

#### Technique 9.2: Array-to-String Conversion

**Description**: Build strings from character codes.

```javascript
var codes = [97, 112, 112, 46, 97, 108, 101, 114, 116];
var func = String.fromCharCode.apply(null, codes);  // "app.alert"
eval(func + "('test')");
```

**Impact**: Payload completely hidden in integer arrays.

**Current Capability**: ⚠️ Detects `fromCharCode` usage (`js.charcode_obfuscation`), but not reconstruction.

**Recommendation**: Implement `fromCharCode` constant folding.

#### Technique 9.3: Computed Property Access

**Description**: Access properties via bracket notation with dynamic strings.

```javascript
var obj = "app";
var prop = "alert";
this[obj][prop]('test');  // Calls app.alert('test')
```

**Impact**: API usage hidden behind dynamic property access.

**Current Capability**: ⚠️ Detects bracket notation (`js.computed_property_access`), but not resolution.

**Recommendation**: Track dynamic property access patterns.

### Category 10: Control Flow Obfuscation

**Threat Level**: 🟠 HIGH
**Current Detection**: ✅ Good

#### Technique 10.1: Control Flow Flattening

**Description**: Convert sequential code into state machine.

```javascript
var state = 0;
while (true) {
  switch (state) {
    case 0: /*...*/ state = 5; break;
    case 5: /*...*/ state = 2; break;
    case 2: /*...*/ return;
  }
}
```

**Current Capability**: ✅ Detected by `js.control_flow_flattening`.

**Gap**: None.

#### Technique 10.2: Opaque Predicates

**Description**: Use always-true or always-false conditions.

```javascript
if (Math.random() < 2) {  // Always true
  maliciousCode();
}
```

**Current Capability**: ✅ Detected by `js.opaque_predicates`.

**Gap**: None.

### Category 11: Encoding and Encryption

**Threat Level**: 🔴 CRITICAL
**Current Detection**: ⚠️ Partial

#### Technique 11.1: Custom Base64 Alphabets

**Description**: Use non-standard base64 encoding.

```javascript
var alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
function customDecode(str) { /* custom base64 logic */ }
var payload = customDecode("...");
eval(payload);
```

**Impact**: Standard base64 decoder won't work.

**Current Capability**: ⚠️ Detects base64 patterns (`js.base64_obfuscation`), but not custom alphabets.

**Recommendation**: Detect custom decoder functions.

#### Technique 11.2: XOR Encryption

**Description**: XOR-encrypt payload with key.

```javascript
var encrypted = [0x1A, 0x2B, 0x3C, ...];
var key = [0xAA, 0xBB];
var decrypted = "";
for (var i = 0; i < encrypted.length; i++) {
  decrypted += String.fromCharCode(encrypted[i] ^ key[i % key.length]);
}
eval(decrypted);
```

**Impact**: Payload completely hidden until runtime.

**Current Capability**: ⚠️ Detects XOR operator usage in loops (basic heuristic), but not decryption.

**Recommendation**: Implement symbolic execution or emulation for decryption loops.

#### Technique 11.3: RC4/AES Encryption

**Description**: Use cryptographic algorithms.

```javascript
function rc4(key, data) { /* RC4 implementation */ }
var payload = rc4(key, encrypted);
eval(payload);
```

**Impact**: Requires crypto library emulation.

**Current Capability**: ⚠️ Detects crypto libraries (`js.cryptomining_library` - wrong category).

**Recommendation**: Add crypto function detection in correct category (obfuscation, not mining).

---

## Gaps and Limitations

### Critical Gaps

1. **No Array Payload Reconstruction**
   - **Impact**: Misses fragmented JavaScript in arrays
   - **Evidence**: `resolve_payload()` only handles strings and streams
   - **Risk**: HIGH

2. **No Multi-Hop Reference Resolution**
   - **Impact**: Misses payloads split across indirect object chains
   - **Evidence**: `resolve_payload()` only follows one reference level
   - **Risk**: CRITICAL

3. **No String Concatenation Analysis**
   - **Impact**: Misses dynamically constructed malicious strings
   - **Evidence**: No constant propagation in static analysis
   - **Risk**: CRITICAL

4. **No fromCharCode Reconstruction**
   - **Impact**: Misses character-code-based payloads
   - **Evidence**: Detection exists but no reconstruction
   - **Risk**: HIGH

5. **Limited Name Normalisation**
   - **Impact**: Hex-encoded key names may evade detection
   - **Evidence**: Detector searches for literal `/JS` bytes
   - **Risk**: HIGH

6. **ObjStm Not Analysed in Triage Mode**
   - **Impact**: Misses JavaScript hidden in object streams
   - **Evidence**: ObjStm expansion only with `--deep` flag
   - **Risk**: MEDIUM (can be mitigated by always using `--deep`)

### Medium Gaps

7. **No XFA JavaScript Extraction**
   - **Impact**: Misses XFA-embedded JavaScript
   - **Evidence**: XFA presence detected but content not parsed
   - **Risk**: MEDIUM

8. **No Circular Reference Protection**
   - **Impact**: Potential infinite loops or crashes
   - **Evidence**: Unknown if graph resolution has cycle detection
   - **Risk**: MEDIUM

9. **No Custom Decoder Detection**
   - **Impact**: Misses custom base64/crypto decoders
   - **Evidence**: Pattern matching only, no semantic analysis
   - **Risk**: MEDIUM

10. **Limited Eval Reconstruction**
    - **Impact**: Eval arguments not reconstructed
    - **Evidence**: Detects eval usage but not content
    - **Risk**: MEDIUM

### Low Priority Gaps

11. **No Content Stream Analysis**
    - **Impact**: Misses JavaScript-like strings in page content
    - **Evidence**: Content streams not analysed
    - **Risk**: LOW (not executable)

12. **No Computed Property Resolution**
    - **Impact**: Misses `obj["method"]()` patterns
    - **Evidence**: Detection exists but no resolution
    - **Risk**: LOW

---

## Recommendations

### Phase 1: Critical Reconstruction (Week 1-2)

**Goal**: Enable payload reconstruction for fragmented content.

#### 1.1: Array Payload Reconstruction

**Priority**: 🔴 CRITICAL
**Effort**: Medium
**Impact**: HIGH

**Implementation**:
- Extend `resolve_payload()` to handle `PdfAtom::Array`
- Recursively resolve each array element
- Concatenate string fragments
- Handle mixed types (strings, refs, nested arrays)

**Code Location**: `crates/sis-pdf-detectors/src/lib.rs`

**Pseudocode**:
```rust
PdfAtom::Array(arr) => {
    let mut fragments = Vec::new();
    for elem in arr {
        match resolve_payload(ctx, elem) {
            PayloadResult { payload: Some(p), .. } => fragments.push(p.bytes),
            _ => continue,
        }
    }
    if !fragments.is_empty() {
        PayloadResult {
            payload: Some(PayloadInfo {
                bytes: fragments.concat(),
                kind: "array".into(),
                ref_chain: format!("array[{}]", fragments.len()),
                // ...
            }),
            error: None,
        }
    }
}
```

**Test Case**:
```pdf
<< /JS [(app.alert\() (') (malicious) (')) ] >>
% Should reconstruct: "app.alert('malicious')"
```

#### 1.2: Multi-Hop Reference Resolution

**Priority**: 🔴 CRITICAL
**Effort**: Medium
**Impact**: CRITICAL

**Implementation**:
- Add recursion depth limit (e.g., 10 hops)
- Track visited references (cycle detection)
- Follow reference chains until terminal value

**Code Location**: `crates/sis-pdf-detectors/src/lib.rs`

**Pseudocode**:
```rust
fn resolve_payload_recursive(
    ctx: &ScanContext,
    obj: &PdfObj,
    depth: usize,
    visited: &mut HashSet<(u32, u16)>,
) -> PayloadResult {
    if depth > 10 {
        return PayloadResult { payload: None, error: Some("max depth".into()) };
    }

    match &obj.atom {
        PdfAtom::Ref { obj, gen } => {
            if !visited.insert((*obj, *gen)) {
                return PayloadResult { payload: None, error: Some("circular ref".into()) };
            }
            let entry = ctx.graph.get_object(*obj, *gen)?;
            resolve_payload_recursive(ctx, &entry.atom, depth + 1, visited)
        }
        PdfAtom::Array(arr) => {
            // Recursive array handling
        }
        // ...
    }
}
```

**Test Case**:
```pdf
10 0 obj << /JS 11 0 R >> endobj
11 0 obj 12 0 R endobj
12 0 obj [ 13 0 R 14 0 R ] endobj
13 0 obj (app.alert\() endobj
14 0 obj ('test'\)) endobj
% Should reconstruct: "app.alert('test')"
```

#### 1.3: Name Object Normalisation

**Priority**: 🔴 CRITICAL
**Effort**: Low
**Impact**: HIGH

**Implementation**:
- Decode hex escapes in name objects before matching
- Check for `/JS`, `/JavaScript`, `/JScript` (case-insensitive)
- Normalise to canonical form for comparison

**Code Location**: `crates/sis-pdf-detectors/src/lib.rs`

**Pseudocode**:
```rust
fn is_javascript_key(name: &PdfName) -> bool {
    let decoded = decode_pdf_name(name);
    matches!(
        decoded.to_lowercase().as_str(),
        "/js" | "/javascript" | "/jscript"
    )
}

// In JavaScriptDetector:
for (k, v) in dict.iter() {
    if let PdfAtom::Name(n) = &k.atom {
        if is_javascript_key(n) {
            // Found JavaScript key
        }
    }
}
```

**Test Cases**:
```pdf
<< /#4A#53 (payload) >>           % Hex-encoded /JS
<< /JavaScript (payload) >>       % Full name
<< /#4A#53#63#72#69#70#74 (p) >> % Hex-encoded /JScript
```

### Phase 2: JavaScript Reconstruction (Week 2-3)

**Goal**: Reconstruct dynamically constructed JavaScript code.

#### 2.1: String Concatenation Analysis

**Priority**: 🔴 CRITICAL
**Effort**: High
**Impact**: CRITICAL

**Implementation**:
- Parse JavaScript to AST (already done)
- Implement constant propagation pass
- Track variable assignments to string literals
- Reconstruct concatenations at `eval()` or `Function()` call sites

**Code Location**: `crates/js-analysis/src/static_analysis.rs`

**Approach**:
- Use existing AST from swc parser
- Walk AST to find variable declarations with string literals
- Track `+` operators on tracked variables
- Reconstruct strings at eval/Function call sites

**Pseudocode**:
```rust
struct StringTracker {
    vars: HashMap<String, String>,  // var name -> constant value
}

impl StringTracker {
    fn track_assignment(&mut self, name: &str, value: &str) {
        self.vars.insert(name.to_string(), value.to_string());
    }

    fn resolve_concatenation(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Lit(Lit::Str(s)) => Some(s.value.to_string()),
            Expr::Ident(id) => self.vars.get(&id.sym.to_string()).cloned(),
            Expr::Bin(BinExpr { op: BinaryOp::Add, left, right, .. }) => {
                let l = self.resolve_concatenation(left)?;
                let r = self.resolve_concatenation(right)?;
                Some(format!("{}{}", l, r))
            }
            _ => None,
        }
    }
}
```

**Test Case**:
```javascript
var a = "app";
var b = ".alert";
var c = "('test')";
eval(a + b + c);
// Should reconstruct: "app.alert('test')"
```

#### 2.2: fromCharCode Reconstruction

**Priority**: 🟠 HIGH
**Effort**: Medium
**Impact**: HIGH

**Implementation**:
- Detect `String.fromCharCode(...)` calls
- Extract numeric arguments (if constants)
- Convert to string
- Track in string analysis

**Code Location**: `crates/js-analysis/src/static_analysis.rs`

**Pseudocode**:
```rust
fn reconstruct_from_charcode(args: &[Expr]) -> Option<String> {
    let mut result = String::new();
    for arg in args {
        if let Expr::Lit(Lit::Num(n)) = arg {
            if let Some(ch) = char::from_u32(n.value as u32) {
                result.push(ch);
            } else {
                return None;
            }
        } else {
            return None;  // Non-constant argument
        }
    }
    Some(result)
}
```

**Test Case**:
```javascript
var func = String.fromCharCode(97, 112, 112, 46, 97, 108, 101, 114, 116);
eval(func + "('test')");
// Should reconstruct: "app.alert('test')"
```

#### 2.3: Array-to-String Reconstruction

**Priority**: 🟠 HIGH
**Effort**: Medium
**Impact**: HIGH

**Implementation**:
- Detect array literals with numeric elements
- Detect `fromCharCode.apply(null, array)` pattern
- Reconstruct string from array

**Test Case**:
```javascript
var codes = [97, 112, 112];  // "app"
var str = String.fromCharCode.apply(null, codes);
```

### Phase 3: Structural Analysis (Week 3-4)

**Goal**: Detect and analyse evasive PDF structures.

#### 3.1: Always-On ObjStm Expansion

**Priority**: 🟠 HIGH
**Effort**: Low
**Impact**: MEDIUM

**Implementation**:
- Enable ObjStm expansion by default (not just with `--deep`)
- Keep resource limits (100 ObjStm, byte limits)
- Make configurable via flag if needed

**Code Location**: `crates/sis-pdf-pdf/src/graph.rs`

**Change**:
```rust
// Current:
if options.deep {
    let expansion = expand_objstm(...);
}

// Proposed:
// Always expand ObjStm (controlled by resource limits)
let expansion = expand_objstm(...);
```

**Rationale**: Object streams are a standard PDF feature; always analysing them shouldn't be "deep mode".

#### 3.2: Circular Reference Detection

**Priority**: 🟡 MEDIUM
**Effort**: Low
**Impact**: MEDIUM

**Implementation**:
- Add cycle detection in `resolve_ref()`
- Track visited references in resolution chain
- Return error on cycle

**Code Location**: `crates/sis-pdf-pdf/src/graph.rs`

**Already Implemented in Recommendation 1.2** (Multi-Hop Resolution).

#### 3.3: Object Shadowing Analysis

**Priority**: 🟡 MEDIUM
**Effort**: Low
**Impact**: MEDIUM

**Implementation**:
- Review `get_object()` logic - ensure it returns **latest** version
- Add finding for shadowed objects (multiple definitions of same ID)
- Analyse both versions if they differ significantly

**Code Location**: `crates/sis-pdf-pdf/src/graph.rs`

**Current Code**:
```rust
pub fn get_object(&self, obj: u32, gen: u16) -> Option<&ObjEntry<'a>> {
    self.index
        .get(&(obj, gen))
        .and_then(|v| v.first().copied())  // ⚠️ Returns FIRST, not LAST
        .and_then(|idx| self.objects.get(idx))
}
```

**Issue**: If `objects` vector contains older objects first, `first()` returns the old version.

**Recommendation**: Review object insertion order or use `last()` instead of `first()`.

#### 3.4: Multiple /JS Keys Detection

**Priority**: 🟡 MEDIUM
**Effort**: Low
**Impact**: LOW

**Implementation**:
- Change from `get_first()` to `get_all()` or iterate all keys
- Detect multiple `/JS` keys in same dictionary
- Emit finding for suspicious duplication
- Analyse all occurrences

**Code Location**: `crates/sis-pdf-detectors/src/lib.rs`

**Pseudocode**:
```rust
let all_js_keys = dict.iter().filter(|(k, _)| is_javascript_key(k));
if all_js_keys.count() > 1 {
    // Emit finding: multiple_js_keys
}
for (k, v) in all_js_keys {
    // Analyse each payload
}
```

### Phase 4: Advanced Extraction (Week 4-5)

**Goal**: Extract JavaScript from non-standard locations.

#### 4.1: XFA JavaScript Extraction

**Priority**: 🟠 HIGH
**Effort**: High
**Impact**: MEDIUM

**Implementation**:
- Add XML parser dependency (e.g., `roxmltree`)
- Extract `/XFA` stream from AcroForm
- Parse XML and find `<script>` tags
- Extract JavaScript content
- Run through existing analysis pipeline

**Code Location**: New module `crates/sis-pdf-detectors/src/xfa_js.rs`

**Pseudocode**:
```rust
fn extract_xfa_javascript(xfa_xml: &str) -> Vec<String> {
    let doc = roxmltree::Document::parse(xfa_xml)?;
    let mut scripts = Vec::new();

    for node in doc.descendants() {
        if node.tag_name().name() == "script" {
            if let Some(text) = node.text() {
                scripts.push(text.to_string());
            }
        }
    }

    scripts
}
```

**Test Case**: XFA form with embedded JavaScript.

#### 4.2: Eval Argument Reconstruction

**Priority**: 🟡 MEDIUM
**Effort**: High
**Impact**: MEDIUM

**Implementation**:
- At `eval()` call sites, reconstruct argument using string analysis
- Track taint flow from sources to eval
- Reconstruct final string value

**Dependency**: Requires Phase 2 string concatenation analysis.

**Test Case**:
```javascript
var payload = "app" + ".alert" + "('test')";
eval(payload);
// Should reconstruct: "app.alert('test')"
```

### Phase 5: Emulation and Symbolic Execution (Week 6-8)

**Goal**: Handle encryption and complex dynamic code.

#### 5.1: Lightweight JavaScript Emulator

**Priority**: 🟡 MEDIUM
**Effort**: Very High
**Impact**: HIGH

**Implementation**:
- Implement simple JavaScript interpreter
- Support basic operators, loops, string operations
- Execute decoder functions with constant inputs
- Extract decrypted payloads

**Challenges**:
- Complexity: Full JavaScript semantics are complex
- Performance: Emulation is slow
- Security: Emulator must be sandboxed (use existing `js-sandbox`)

**Alternative Approach**: Use existing JavaScript sandbox (`boa` or `rquickjs`) with instrumentation.

**Code Location**: Extend `crates/js-analysis/src/dynamic.rs`

**Recommendation**: Start with simple cases (XOR loops, fromCharCode arrays) before full emulation.

#### 5.2: Symbolic Execution for Decoder Detection

**Priority**: 🟢 LOW
**Effort**: Very High
**Impact**: MEDIUM

**Implementation**:
- Track symbolic values through execution
- Identify decoder patterns (loops with XOR, substitution, etc.)
- Invert decoding to extract payload

**Recommendation**: Research-level effort; defer until Phases 1-4 complete.

---

## Implementation Roadmap

### Priority Matrix

| Phase | Priority | Effort | Impact | Weeks |
|-------|----------|--------|--------|-------|
| **Phase 1: Critical Reconstruction** | 🔴 CRITICAL | Medium | HIGH | 1-2 |
| 1.1: Array Payload Reconstruction | 🔴 CRITICAL | Medium | HIGH | 0.5 |
| 1.2: Multi-Hop Reference Resolution | 🔴 CRITICAL | Medium | CRITICAL | 1 |
| 1.3: Name Object Normalisation | 🔴 CRITICAL | Low | HIGH | 0.5 |
| **Phase 2: JavaScript Reconstruction** | 🔴 CRITICAL | High | CRITICAL | 2-3 |
| 2.1: String Concatenation Analysis | 🔴 CRITICAL | High | CRITICAL | 1.5 |
| 2.2: fromCharCode Reconstruction | 🟠 HIGH | Medium | HIGH | 0.5 |
| 2.3: Array-to-String Reconstruction | 🟠 HIGH | Medium | HIGH | 0.5 |
| **Phase 3: Structural Analysis** | 🟠 HIGH | Low | MEDIUM | 1 |
| 3.1: Always-On ObjStm Expansion | 🟠 HIGH | Low | MEDIUM | 0.25 |
| 3.2: Circular Reference Detection | 🟡 MEDIUM | Low | MEDIUM | 0.25 |
| 3.3: Object Shadowing Analysis | 🟡 MEDIUM | Low | MEDIUM | 0.25 |
| 3.4: Multiple /JS Keys Detection | 🟡 MEDIUM | Low | LOW | 0.25 |
| **Phase 4: Advanced Extraction** | 🟠 HIGH | High | MEDIUM | 2-3 |
| 4.1: XFA JavaScript Extraction | 🟠 HIGH | High | MEDIUM | 1.5 |
| 4.2: Eval Argument Reconstruction | 🟡 MEDIUM | High | MEDIUM | 1 |
| **Phase 5: Emulation** | 🟡 MEDIUM | Very High | HIGH | 4-6 |
| 5.1: Lightweight JS Emulator | 🟡 MEDIUM | Very High | HIGH | 3-4 |
| 5.2: Symbolic Execution | 🟢 LOW | Very High | MEDIUM | 2-3 |

### Recommended Sequence

**Immediate (Next Sprint)**:
1. Phase 1.3: Name Object Normalisation (0.5 weeks)
2. Phase 1.1: Array Payload Reconstruction (0.5 weeks)
3. Phase 3.1: Always-On ObjStm Expansion (0.25 weeks)

**Short-Term (1-2 Months)**:
4. Phase 1.2: Multi-Hop Reference Resolution (1 week)
5. Phase 2.2: fromCharCode Reconstruction (0.5 weeks)
6. Phase 2.3: Array-to-String Reconstruction (0.5 weeks)
7. Phase 3.2-3.4: Structural Analysis (1 week)

**Medium-Term (2-4 Months)**:
8. Phase 2.1: String Concatenation Analysis (1.5 weeks)
9. Phase 4.1: XFA JavaScript Extraction (1.5 weeks)
10. Phase 4.2: Eval Argument Reconstruction (1 week)

**Long-Term (4-6 Months)**:
11. Phase 5.1: Lightweight JS Emulator (3-4 weeks)
12. Phase 5.2: Symbolic Execution (research)

---

## Success Metrics

### Coverage Metrics

**Current**:
- ✅ 73 detection functions
- ✅ 72 finding IDs
- ✅ ~95% coverage of **known, non-evasive** JavaScript malware

**Target After Phase 1**:
- 🎯 Reconstruct fragmented payloads (arrays, multi-hop refs)
- 🎯 Detect hex-encoded key names
- 🎯 95% coverage maintained + evasion resistance

**Target After Phase 2**:
- 🎯 Reconstruct dynamically constructed strings
- 🎯 Detect obfuscated API calls (fromCharCode, etc.)
- 🎯 ~85% coverage of **evasive** JavaScript malware

**Target After Phases 3-4**:
- 🎯 Extract JavaScript from XFA, object streams, complex structures
- 🎯 Detect and analyse structural evasion patterns
- 🎯 ~90% coverage of evasive malware

**Target After Phase 5**:
- 🎯 Decrypt simple encoded payloads
- 🎯 ~95% coverage of evasive malware (near-comprehensive)

### Performance Metrics

- **Reconstruction Overhead**: <50ms per file (Phases 1-2)
- **Deep Analysis**: <500ms per file (Phases 3-4)
- **Emulation**: <2s per file (Phase 5)

### False Positive Metrics

- **Target**: <5% false positive rate
- **Approach**: Test against benign corpus (JavaScript-heavy legitimate PDFs)

---

## Testing Strategy

### Phase 1 Testing

**Test Cases**: Create synthetic PDFs with:
1. Array-based string splitting
2. Multi-hop reference chains (2, 3, 5 levels)
3. Hex-encoded `/JS` keys (`/#4A#53`, `/#4A#61#76#61#53#63#72#69#70#74`)
4. Circular references
5. Combined techniques (array of refs to fragmented strings)

**Validation**: Ensure reconstruction produces complete payload matching ground truth.

### Phase 2 Testing

**Test Cases**: JavaScript payloads with:
1. Simple concatenation: `var s = "a" + "b" + "c"`
2. Variable tracking: `var a = "x"; var b = "y"; eval(a + b)`
3. fromCharCode: `String.fromCharCode(97, 98, 99)`
4. Array apply: `String.fromCharCode.apply(null, [97, 98, 99])`
5. Nested concatenation: `var a = "x" + "y"; var b = "z"; eval(a + b)`

**Validation**: Ensure reconstructed strings match expected output.

### Phase 3-4 Testing

**Test Cases**:
1. JavaScript in ObjStm (with/without `--deep`)
2. XFA forms with embedded `<script>` tags
3. Multiple `/JS` keys in same dictionary
4. Object shadowing (incremental updates)

**Validation**: Ensure all JavaScript instances are detected and extracted.

### Phase 5 Testing

**Test Cases**: Encrypted payloads with:
1. Simple XOR: `for (i=0; i<enc.length; i++) dec += chr(enc[i] ^ key)`
2. Custom base64: `decode(str, customAlphabet)`
3. RC4 decryption

**Validation**: Ensure emulator extracts decrypted payload.

### Regression Testing

- **Ensure** all existing 53 tests continue to pass
- **Ensure** hostile payload analysis remains crash-free
- **Ensure** performance does not degrade significantly

---

## Dependency and Integration

### Code Dependencies

**Phase 1**:
- Modify: `crates/sis-pdf-detectors/src/lib.rs` (resolve_payload)
- Modify: `crates/sis-pdf-pdf/src/object.rs` (name normalisation)

**Phase 2**:
- Modify: `crates/js-analysis/src/static_analysis.rs` (add reconstruction pass)
- Dependency: swc AST (already in use)

**Phase 4**:
- Add: `roxmltree` crate for XML parsing
- New module: `crates/sis-pdf-detectors/src/xfa_js.rs`

**Phase 5**:
- Extend: `crates/js-analysis/src/dynamic.rs`
- Consider: Separate emulator crate

### Integration Points

- **Finding IDs**: Add new findings for evasion detection
  - `js.payload_fragmented_array`
  - `js.payload_fragmented_refs`
  - `js.key_name_obfuscated`
  - `js.multiple_js_keys`
  - `js.circular_reference`
  - `js.payload_reconstructed`
  - `js.xfa_embedded`
  - `js.payload_encrypted`

- **Metadata**: Add reconstruction metadata
  - `payload.reconstruction_method`: "array" | "multi_ref" | "concatenation" | "fromCharCode" | "emulated"
  - `payload.reconstruction_depth`: Number of resolution/reconstruction steps
  - `payload.original_form`: Description of obfuscation technique

- **Documentation**: Update `docs/findings.md` with new finding definitions

---

## Security Considerations

### Resource Limits

**Multi-Hop Resolution**:
- **Max Depth**: 10 reference hops
- **Cycle Detection**: Track visited references, abort on cycle
- **Timeout**: 100ms per resolution chain

**String Reconstruction**:
- **Max Concatenations**: 100 operations per chain
- **Max String Length**: 10MB reconstructed payload
- **Timeout**: 500ms per reconstruction

**Emulation** (Phase 5):
- **Max Instructions**: 100,000 ops
- **Max Memory**: 10MB
- **Timeout**: 2 seconds
- **Sandbox**: Use existing `js-sandbox` feature

### Denial of Service Protection

- **Decompression Bombs**: Existing limits on decoded stream size
- **Reconstruction Bombs**: Limit concatenation depth and result size
- **Cyclic Structures**: Detect and abort

### False Positive Mitigation

- **Legitimate Fragmentation**: Some benign PDFs split strings across arrays
- **Approach**: Lower severity for reconstructed payloads unless malicious patterns detected
- **Validation**: Test against benign corpus

---

## Conclusion

The current implementation has **strong JavaScript pattern detection** (~95% of known malware) but **significant gaps in evasion resistance** at the PDF structural level and JavaScript obfuscation level.

**Critical Next Steps**:
1. **Phase 1** (weeks 1-2): Implement PDF-level reconstruction (arrays, multi-hop refs, name normalisation)
2. **Phase 2** (weeks 2-4): Implement JavaScript-level reconstruction (concatenation, fromCharCode)
3. **Phase 3** (week 5): Structural evasion detection (always-on ObjStm, shadowing)
4. **Phase 4** (weeks 6-8): Advanced extraction (XFA, eval arguments)
5. **Phase 5** (weeks 9-14): Emulation for encrypted payloads (optional, high effort)

**Expected Outcome**: Near-comprehensive detection of both direct and evasively-hidden JavaScript malware in PDFs.

**Resource Estimate**:
- Phases 1-2: 2-4 weeks (CRITICAL)
- Phases 3-4: 3-4 weeks (HIGH priority)
- Phase 5: 4-6 weeks (MEDIUM priority, optional)
- **Total**: 9-14 weeks for complete implementation

---

## References

### Internal Documentation
- `crates/sis-pdf-detectors/src/lib.rs` - JavaScript detector
- `crates/sis-pdf-pdf/src/decode.rs` - Stream decoding
- `crates/sis-pdf-pdf/src/graph.rs` - Object graph
- `crates/sis-pdf-pdf/src/objstm.rs` - Object stream expansion
- `crates/js-analysis/src/static_analysis.rs` - JavaScript analysis
- `docs/js-detection-roadmap.md` - Detection capabilities

### External References
- PDF Reference 1.7 (ISO 32000-1:2008) - Name objects, object streams, filters
- PDF Malware Analysis Resources:
  - Didier Stevens' PDF tools and research
  - Malware analysis techniques for PDF JavaScript
  - Object stream obfuscation in APT campaigns

---

**Document Status**: Complete
**Next Action**: Review and prioritise implementation phases
**Owner**: Security Analysis Team

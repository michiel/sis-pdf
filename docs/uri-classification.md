# URI Classification Implementation

## Overview

This document describes the implementation of multi-dimensional URI analysis in sis-pdf. The URI classification system evaluates URIs found in PDFs based on their **content**, **context**, **placement**, and **trigger mechanisms** to distinguish between legitimate hyperlinks and potential security threats.

## Architecture

### Detectors

The URI classification system consists of two primary detectors:

1. **UriContentDetector** - Analyzes URI content, placement, context, and triggers
2. **UriPresenceDetector** - Provides document-level summary of URI usage

### Analysis Dimensions

#### 1. URI Content Analysis

Analyzes the actual URI string to detect:

**Obfuscation Detection**:
- Percent-encoding density (hex characters like `%68%65%6c%6c%6f`)
- Base64 encoding in query parameters
- Unicode escapes (`\u` or `%u`)
- Multiple encoding layers

**Obfuscation Levels**:
- **None**: Normal URLs with minimal encoding
- **Light**: < 10% percent-encoded characters
- **Medium**: > 30% percent-encoded or contains base64 parameters
- **Heavy**: Unicode escapes or heavy percent-encoding with base64

**Suspicious Patterns**:
- Extremely long URLs (> 500 characters) - tracking/fingerprinting
- Many query parameters (> 10) - data collection
- Suspicious parameter names (`data`, `payload`, `info`, `d`, `p`)
- Multiple subdomains - subdomain tricks like `paypal.attacker.com`

**Protocol/Scheme Analysis**:
- `javascript:` URIs - Can execute arbitrary code (HIGH RISK)
- `file://` URIs - Can access local filesystem (MEDIUM-HIGH RISK)
- `http://` (non-HTTPS) - Cleartext transmission
- Standard `https://` - Expected for web links

**Domain Analysis**:
- IP addresses instead of domain names (suspicious for user-facing content)
- Suspicious TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq` (free, often abused)
- New confusing TLDs: `.zip`, `.mov`

**Tracking Detection**:
- Common tracking parameters: `utm_source`, `utm_campaign`, `fbclid`, `gclid`
- Session IDs and fingerprinting parameters
- Informational only (not inherently malicious)

**Data Exfiltration Patterns**:
- Many parameters (> 5) with long values (> 50 chars)
- Suggests form data being transmitted
- Parameter names like `data`, `payload`, `info`

#### 2. URI Context Analysis

Analyzes WHERE the URI appears in the PDF structure:

**Visibility States**:
- **Visible**: Normal annotation with proper rectangle within page bounds
- **HiddenRect**: Zero-size rectangle `[0 0 0 0]` or rectangle outside page boundaries
- **HiddenFlag**: Annotation flags mark as hidden/invisible (bits 1 or 2 set)
- **NoAnnot**: URI in action dictionary but not in visible annotation

**Placement Types**:
- **Annotation**: Normal `/Annot` with `/Subtype /Link` (standard hyperlink)
- **OpenAction**: Document-level `/OpenAction` (triggers on open)
- **PageAction**: Page-level `/AA` (Additional Actions)
- **FieldAction**: Form field action
- **NonStandardAction**: Other action triggers

**Context Risk Scoring**:
- Visible annotation: 0 points (legitimate)
- Hidden rect: +30 points
- Hidden flag: +40 points
- No annotation: +20 points

#### 3. URI Trigger Analysis

Analyzes HOW the URI is activated:

**Trigger Mechanisms**:
- **Click**: User clicks annotation (standard, low risk)
- **OpenAction**: Triggers when document opens (automatic, medium-high risk)
- **PageOpen**: Triggers when user navigates to page (medium risk)
- **PageClose**: Triggers when leaving page
- **FormSubmit**: Form submission action (data exfiltration risk)
- **JavaScript**: JavaScript-initiated navigation (high risk)
- **FieldCalculate/Format/Validate**: Form field events

**Automatic vs Manual**:
- Manual (user-initiated): Low risk baseline
- Automatic (no user action): +20 points

**JavaScript Involvement**:
- Detects if URI is triggered via JavaScript
- Adds +30 points to risk score

**Trigger Risk Scoring**:
- Click: 0 points
- Page open: +20 points
- Document open: +40 points
- JavaScript trigger: +50 points
- Form submit: +60 points

## Composite Risk Scoring

The system calculates a composite risk score by combining signals from all dimensions:

```
Base Score = 0

Context Modifiers:
  + Visible annotation: 0
  + Hidden rect: +30
  + Hidden flag: +40
  + No annotation: +20

Trigger Modifiers:
  + User click: 0
  + Page open: +20
  + Document open: +40
  + JavaScript: +50
  + Form submit: +60
  + Automatic: +20 (if automatic)
  + JS involved: +30 (if JS in chain)

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
  + Suspicious patterns: +20

Final Severity Mapping:
  0-20:   Info
  21-50:  Low
  51-80:  Medium
  81+:    High
```

### Example Scenarios

#### Legitimate Reference Link
```
URL: https://doi.org/10.1000/xyz123
Context: Visible annotation in text
Trigger: User click
Score: 0 + 0 + 0 = 0 → Info
```

#### Tracking Link (Benign but Notable)
```
URL: https://example.com/?utm_source=pdf&utm_campaign=promo
Context: Visible annotation
Trigger: User click
Obfuscation: Light (10%)
Score: 0 + 0 + 10 = 10 → Info
Metadata: Tracking params detected
```

#### Hidden Phishing Link
```
URL: http://paypa1.com/login
Context: Hidden rect [0 0 0 0]
Trigger: Page open
Content: HTTP (not HTTPS), suspicious domain
Score: 30 (hidden) + 20 (page open) + 20 (suspicious) = 70 → Medium
```

#### JavaScript Data Exfiltration
```
URL: http://attacker.com/collect?data=<base64>
Context: No annotation
Trigger: JavaScript trigger, automatic
Content: Data exfil pattern, base64 params
Score: 20 (no annot) + 50 (JS) + 20 (auto) + 30 (JS involved) + 60 (exfil) = 180 → High
```

#### javascript: URI
```
URL: javascript:app.launchURL("http://evil.com")
Context: Hidden annotation
Trigger: Click (but JS URI executes)
Content: JavaScript URI
Score: 40 (hidden) + 0 + 70 (JS URI) = 110 → High
```

## Detector Output

### UriContentDetector

Produces per-URI findings with comprehensive metadata:

```rust
Finding {
    kind: "uri_content_analysis",
    severity: High,  // Based on composite score
    title: "URI with suspicious characteristics",
    description: "URI with: hidden annotation, JavaScript-triggered, heavily obfuscated",

    meta: {
        // Content analysis
        "uri.url": "http://example.com/...",
        "uri.scheme": "http",
        "uri.domain": "example.com",
        "uri.length": "245",
        "uri.obfuscation": "heavy",
        "uri.is_ip": "false",
        "uri.is_javascript": "false",
        "uri.is_file": "false",
        "uri.suspicious_tld": "false",
        "uri.data_exfil_pattern": "true",
        "uri.tracking_params": "utm_source,fbclid",
        "uri.suspicious_patterns": "many_parameters,suspicious_param_names",

        // Context analysis
        "uri.visibility": "hidden_rect",
        "uri.placement": "annotation",

        // Trigger analysis
        "uri.trigger": "javascript",
        "uri.automatic": "true",
        "uri.js_involved": "true",

        // Risk assessment
        "uri.risk_score": "180",
    }
}
```

### UriPresenceDetector

Produces single document-level summary:

```rust
Finding {
    kind: "uri_presence_summary",
    severity: Info,
    title: "Document contains URIs",
    description: "Found 15 URIs pointing to 3 unique domains.",

    meta: {
        "uri.count_total": "15",
        "uri.count_unique_domains": "3",
        "uri.schemes": "https:12, http:2, file:1",
        "uri.domains_sample": "example.com, test.org, suspicious.tk",
    }
}
```

## Implementation Details

### Module Structure

Located in `crates/sis-pdf-detectors/src/uri_classification.rs`:

**Core Types**:
- `UriContentAnalysis` - Content analysis results
- `UriContext` - Context/placement analysis
- `UriTrigger` - Trigger mechanism analysis
- `ObfuscationLevel` - Enum for obfuscation severity
- `UriVisibility` - Enum for visibility states
- `UriPlacement` - Enum for placement types
- `TriggerMechanism` - Enum for trigger types

**Core Functions**:
- `analyze_uri_content()` - Parse and analyze URI string
- `analyze_uri_context()` - Determine visibility and placement
- `analyze_uri_trigger()` - Identify trigger mechanism
- `calculate_uri_risk_score()` - Compute composite score
- `risk_score_to_severity()` - Map score to severity level

**Detectors**:
- `UriContentDetector` - Main content analysis detector
- `UriPresenceDetector` - Document summary detector

### Integration

Both detectors are added to the default detector list in `lib.rs`:

```rust
pub fn default_detectors_with_settings(settings: DetectorSettings) -> Vec<Box<dyn Detector>> {
    let mut detectors: Vec<Box<dyn Detector>> = vec![
        // ... other detectors ...
        Box::new(uri_classification::UriPresenceDetector),
        Box::new(uri_classification::UriContentDetector),
        // ...
    ];
    detectors
}
```

### Performance Characteristics

- **UriPresenceDetector**: Cost::Cheap - Single pass through objects
- **UriContentDetector**: Cost::Moderate - URI parsing and analysis per URI
- **Resource Limits**: Maximum 1000 URIs analyzed per document (DoS prevention)
- **Complexity**: O(n) where n = number of objects with URIs

## Usage Examples

### Command Line

```bash
# Scan PDF with URI analysis
sis-pdf scan document.pdf

# JSON output includes URI findings
sis-pdf scan --format json document.pdf > results.json
```

### Example Output

```
[MEDIUM] uri_content_analysis: URI with suspicious characteristics
  Object: 15 0 obj
  URI: http://192.168.1.100/collect?data=...
  Risk Score: 75
  Issues:
    - IP address instead of domain (+20)
    - Hidden annotation (+30)
    - Data exfiltration pattern detected (+60)
  Recommendation: Review URI destination and trigger mechanism

[INFO] uri_presence_summary: Document contains URIs
  Total URIs: 8
  Unique domains: 2
  Schemes: https:7, http:1
```

## Testing

### Test Coverage

Test cases validate:

1. **Legitimate URIs** - No false positives on normal reference links
2. **Hidden annotations** - Detection of zero-size and out-of-bounds rects
3. **JavaScript URIs** - Proper flagging of `javascript:` scheme
4. **Obfuscation** - Detection of percent-encoding and base64
5. **Data exfiltration** - Identification of form data patterns
6. **Tracking** - Recognition of common tracking parameters (info only)

### Test Files

Located in `crates/sis-pdf-core/tests/fixtures/`:
- `annot_uri.pdf` - Various URI annotation patterns
- Additional test files for edge cases

## Security Considerations

### False Positives

The scoring system is designed to minimize false positives:
- Visible annotations with normal URLs → Info/Low severity
- Tracking parameters alone → Info severity only
- Light obfuscation (normal percent-encoding) → Low risk

### False Negatives

Potential missed threats:
- Novel obfuscation techniques not yet recognized
- Typosquatting domains not in suspicious TLD list
- Sophisticated homoglyph attacks (future enhancement)

### Defense in Depth

URI classification is one layer in sis-pdf's multi-layered analysis:
- JavaScript detector identifies JS code
- External context detector analyzes action chains
- Form detector identifies SubmitForm actions
- Combined, these provide comprehensive coverage

## Future Enhancements

### Planned Improvements

1. **Page Bounds Integration** - Currently stubbed, needs page tree analysis
2. **Advanced Homoglyph Detection** - Punycode and Unicode lookalikes
3. **Machine Learning** - Train classifier on labeled malicious/benign URIs
4. **External Threat Intel** - Optional VirusTotal API integration
5. **Link Following** - Optionally follow redirects to detect final destination
6. **Domain Reputation** - Integration with domain reputation services

### Configuration Options

Future configuration parameters:
- `max_uris_to_analyze` - Resource limit (default: 1000)
- `enable_external_lookups` - Enable VirusTotal/reputation checks
- `suspicious_tld_list` - Customizable TLD blacklist
- `tracking_param_list` - Customizable tracking parameter list

## References

- **PDF Specification**: ISO 32000-1:2008, Section 8.5 (Annotations), 8.6.1 (URI Actions)
- **OWASP**: URL Validation and Phishing Detection
- **Common Obfuscation**: URL encoding, base64, homoglyphs
- **Related Detectors**: `external_context`, `SubmitFormDetector`, `JavaScriptDetector`

## Conclusion

The URI classification system provides nuanced, context-aware analysis of URIs in PDFs. By evaluating content, context, placement, and triggers, it effectively distinguishes between legitimate hyperlinks and potential security threats while minimizing false positives.

The composite scoring approach allows for fine-grained risk assessment, and the comprehensive metadata enables manual review and integration with other security tools.

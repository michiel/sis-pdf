# URI Scheme Abuse, JS Bypass Detection, and Annotation Injection Gap Closure

Date: 2026-02-23
Status: All phases complete (Phase 3 committed 2026-02-23)
Owner: Core + Detectors + JS-Analysis

## Purpose

Close detection gaps and calibration deficits identified during a coverage review of
the PayloadsAllThePDFs corpus (9 documented payloads + foxit-reader-poc + starter_pack).
All gaps involve capabilities that already exist in the codebase in partial form:
the relevant data is already extracted and present in finding metadata, but is not
escalated to dedicated first-class findings with appropriate severity.

This plan also identifies and specifies extensions and new capabilities that the
corpus review surfaced as missing or underweighted.

## Corpus review summary

Files reviewed: `tmp/PayloadsAllThePDFs/pdf-payloads/` (11 PDFs).

| File | Payload type | Coverage verdict |
|---|---|---|
| `payload1.pdf` | OpenAction JS with generator-fn eval bypass + XSS | Partial |
| `payload1.pdf` | `data:text/html` XSS in `/URI` action | **Gap** |
| `payload1.pdf` | HTML XSS in annotation `/T` + `/Contents` | **Gap** |
| `payload2.pdf` | XSS HTML string in `/URI` action | Good — `pdfjs_annotation_injection` fires |
| `payload3.pdf` | OpenAction JS (alert/prompt/document.write) | Good |
| `payload3.pdf` | `file:///C:/Windows/system32/calc.exe` in `/URI` | **Gap** |
| `payload4.pdf` | `app.openDoc("/C/Windows/System32/calc.exe")` in JS | Partial — Low/Tentative is underweighted |
| `payload4.pdf` | `START C:/Windows/system32/calc.exe` in `/URI` | **Gap** |
| `payload5.pdf` | `app.launchURL(…calc.exe…)` in JS | Good |
| `payload5.pdf` | `javascript:confirm(2);` in `/URI` action | **Gap** |
| `payload6.pdf` | `app.launchURL(…XSS…)` in JS | Good |
| `payload7.pdf` | HTML injection in AcroForm field `/V` | Good — `form_html_injection` fires |
| `payload8.pdf` | CVE-2024-4367 FontMatrix JS injection | Good — `fontmatrix_payload_present` + `pdfjs_font_injection` |
| `payload9.pdf` | Sandbox bypass via `delete window/confirm/document` | **Gap** |
| `foxit-reader-poc.pdf` | `importTextData("/etc/passwd")` + `submitForm` | Excellent |
| `starter_pack.pdf` | JS + annotation injection combination | Good |

## Identified gaps

### GAP-1: No dedicated finding for dangerous URI schemes in /URI actions

**Root cause location**: `crates/sis-pdf-detectors/src/annotations_advanced.rs`,
`annotation_action_severity()` (line 333).

The `UriContentAnalysis` struct already classifies URIs into `is_javascript_uri`,
`is_data_uri`, `is_file_uri`, and `has_suspicious_scheme`. These signals are used to
bump the `annotation_action_chain` finding from `Info` to `Low` severity. This is the
wrong behaviour: `javascript:`, `file://`, and `data:text/html` URIs are direct code
execution or local file access vectors, not low-severity informational findings. They
warrant a dedicated finding at `High` severity.

Affected payloads: payload1 (`data:`), payload3 (`file://`), payload4 (`START`),
payload5 (`javascript:`).

**Exact `action.target` values observed**:
- `data:text/html,<script>alert(2);</script>`
- `file:///C:/Windows/system32/calc.exe`
- `START C:/Windows/system32/calc.exe`
- `javascript:confirm(2);`

The `action.target` field is already populated in `annotation_action_chain` metadata.
All the necessary classification logic exists in `uri_classification.rs`.

### GAP-2: Generator function constructor eval bypass not detected

**Root cause location**: `crates/js-analysis/src/static_analysis.rs`,
`contains_dynamic_eval_construction()` (line 649).

The current implementation looks for string concatenation fragments (`'ev'`, `"ev"`,
etc.) and `+` operators, plus `[...]` dynamic access. It does not detect the
generator function constructor pattern:

```javascript
((function*(){}).constructor("code"))().next();
```

This pattern is functionally equivalent to `new Function("code")()` (a well-known
`eval` bypass). It uses `Object.getPrototypeOf(function*(){}).constructor` to obtain
a reference to `GeneratorFunction`, then invokes it as a code constructor. The pattern
is specifically designed to bypass bytewise `eval` detection.

`js.dynamic_eval_construction` and `js.eval_sink` are both `false` for payload1
despite the payload being a direct eval bypass.

### GAP-3: Global deletion sandbox bypass not detected

**Root cause location**: `crates/js-analysis/src/static_analysis.rs`,
`detect_sandbox_evasion()` (line 1635).

The current `detect_sandbox_evasion` checks for `typeof window`, `typeof document`,
`typeof navigator`, Acrobat-specific introspection APIs, and screen/navigator
properties, requiring at least 3 matches. This covers environment fingerprinting
checks, but not the Apryse WebViewer SDK sandbox bypass pattern:

```javascript
delete window; delete confirm; delete document; window.confirm(document.cookie);
```

This technique (CVE-assigned, affects Apryse WebViewer 10.9.x–10.12.0) exploits the
SDK's failure to protect its global scope: deleting browser globals removes sandbox
restrictions, enabling `window.confirm` etc. to execute arbitrary code in the hosting
page's context.

`js.sandbox_evasion` is `false` for payload9. The emulation sandbox does detect a
`missing_callable` breakpoint (`js_emulation_breakpoint` at Info/Tentative) because
the deleted globals cause errors, but no dedicated finding is raised.

### GAP-4: HTML injection in annotation /T and /Contents fields not analysed

**Root cause location**: `crates/sis-pdf-detectors/src/annotations_advanced.rs` and
`crates/sis-pdf-detectors/src/content_phishing.rs`.

Payload1 uses an incremental update to inject a Text annotation with XSS payloads
in the `/T` (title/author) and `/Contents` (comment body) fields:

```
/T (">'><details open ontoggle=confirm(3)>)
/Contents (UTF-16 encoded XSS payload)
```

Existing coverage:
- `revision_annotations_changed` detects the structural addition of the annotation.
- `form_html_injection` detects HTML in AcroForm widget `/V` fields (payload7).
- `pdfjs_annotation_injection` detects HTML in Link annotation `/URI` or
  render-context annotation bodies (payloads 2–6).

The gap: Text annotation `/T` and `/Contents` fields are not inspected for HTML/XSS
injection patterns. These fields render in annotation pop-up callouts in Acrobat/
Adobe Reader and web viewers, and are a known XSS injection vector in PDF.js and
PSPDFKit (see payload1 README attribution).

### Minor: `js_runtime_file_probe` severity for explicit `app.openDoc` to executable

**Root cause**: Runtime confidence downgrading logic in `crates/js-analysis/`.

Payload4's `app.openDoc("/C/Windows/System32/calc.exe")` fires `js_runtime_file_probe`
at `Low/Tentative`. The API call is explicit and the target is a Windows system
executable. The confidence downgrade (`Probable->Tentative` noted in meta) is caused
by profile divergence across execution environments. An explicit named Acrobat API
call targeting a `.exe` path should not fall below `Low/Probable`; the cross-profile
divergence is expected because `app.openDoc` is only meaningful in Adobe's runtime.

## Gaps closed — detailed technical plan

---

## Workstream A: URI dangerous scheme detection

### A1. `URI-01` Dedicated `uri_dangerous_scheme` finding

**Goal**: Emit a dedicated `High`-severity finding when a `/URI` action uses a scheme
that enables direct code execution, local file access, or data exfiltration — distinct
from the generic `annotation_action_chain` finding that already fires for all
annotation actions.

**Finding kinds** (one per scheme class):

| Kind | Trigger | Severity | Confidence |
|---|---|---|---|
| `uri_javascript_scheme` | `/URI` target starts with `javascript:` (case-insensitive) | High | Strong |
| `uri_file_scheme` | `/URI` target starts with `file://` or `file:///` | High | Strong |
| `uri_data_html_scheme` | `/URI` target starts with `data:text/html` or `data:application/` | High | Strong |
| `uri_command_injection` | `/URI` target starts with `START ` or `cmd ` or `shell:` | High | Probable |

**Implementation location**: `crates/sis-pdf-detectors/src/annotations_advanced.rs`.

**Implementation approach**:

1. The `uri_target_is_suspicious()` helper already calls `analyze_uri_content()` and
   tests `is_javascript_uri`, `is_data_uri`, and `is_file_uri`. The classification data
   is already available; it just needs to drive a separate finding rather than only
   adjust `annotation_action_chain` severity.

2. In `AnnotationAttackDetector::run()`, after building the `annotation_action_chain`
   finding, call a new helper:

   ```rust
   fn check_uri_dangerous_scheme(
       entry: &ObjEntry,
       action_target: &str,
       meta_base: &HashMap<String, String>,
   ) -> Option<Finding>
   ```

   This helper:
   - runs `analyze_uri_content(action_target.as_bytes())` (already available via the
     existing import in `annotations_advanced.rs`),
   - selects the appropriate kind and severity from the table above,
   - returns `None` when the scheme is benign.

3. The new finding must include:
   - `meta["uri.scheme"]`: the extracted scheme string (e.g. `"javascript"`, `"file"`,
     `"data"`, `"start"`).
   - `meta["uri.target"]`: the full `/URI` value (already in `action.target`).
   - `meta["uri.classification"]`: the matched category (`javascript`, `file`, `data`,
     `command`).
   - evidence offset pointing to the annotation's `/A` dictionary span.

4. Cap finding count per kind using the existing `apply_kind_cap` pattern (cap = 10).

5. Add dedicated finding kinds to `docs/findings.md` with severity, confidence, and
   example metadata.

**Severity rationale**:
- `javascript:` URIs execute code in the reader's JavaScript context — equivalent to
  having a JS action. `High/Strong`.
- `file://` URIs open local files or paths, enabling local file disclosure or process
  launch in some readers. `High/Strong`.
- `data:text/html` URIs render arbitrary HTML in some readers and web-based viewers.
  `High/Strong`.
- `START`/`cmd` URIs are not valid URI scheme syntax; their presence indicates an
  attempt to inject OS-level commands. `High/Probable` (Probable because their actual
  execution depends on reader implementation).

**Tests**:

1. Synthetic fixture: Link annotation with `/URI (javascript:confirm(1))` →
   `uri_javascript_scheme` finding, severity High, confidence Strong.
2. Synthetic fixture: Link annotation with `/URI (file:///C:/Windows/calc.exe)` →
   `uri_file_scheme` finding.
3. Synthetic fixture: Link annotation with `/URI (data:text/html,<script>x</script>)` →
   `uri_data_html_scheme` finding.
4. Synthetic fixture: Link annotation with `/URI (START calc.exe)` →
   `uri_command_injection` finding.
5. Benign fixture: Link annotation with `/URI (https://example.com)` → no new finding
   from this detector.
6. `annotation_action_chain` still fires alongside the new finding (both are present).
7. Cap test: 15 annotations with `javascript:` URIs → `uri_javascript_scheme` capped
   at 10 with aggregate metadata.

**Regression targets**:
- `cargo test -p sis-pdf-detectors --test annotations_advanced` (extend existing suite).
- `cargo test -p sis-pdf-core --test corpus_captured_regressions` (no new FP on
  clean fixtures).

**Documentation**: add four finding entries to `docs/findings.md`.

**Acceptance**:
1. All four URI scheme classes emit dedicated findings at `High` severity.
2. `annotation_action_chain` severity for `/URI` actions updated: `Low` when benign,
   `Medium` when suspicious (no change to automatic-trigger annotations).
3. No finding emitted for standard `https://` or `http://` URIs.
4. Docs updated in same commit.

---

## Workstream B: JavaScript static analysis gap closure

### B1. `JS-01` Generator function constructor eval bypass detection

**Goal**: Set `js.dynamic_eval_construction = true` when the JavaScript payload
uses generator function (or async function) constructor invocation as an `eval`
bypass.

**Root cause**: `contains_dynamic_eval_construction()` in
`crates/js-analysis/src/static_analysis.rs` uses fragile byte-level checks for
string concatenation fragments (`'ev'`, `"ev"`, etc.). The generator function
constructor pattern is bytewise distinct:

```javascript
// Target pattern A — generator constructor
(function*(){}).constructor("code")
Object.getPrototypeOf(function*(){}).constructor

// Target pattern B — async function constructor (same bypass)
(async function(){}).constructor("code")

// Target pattern C — Function.prototype.constructor via prototype chain
Function.prototype.constructor("code")
```

**Implementation**:

1. Extend `contains_dynamic_eval_construction()` to add a new pattern group alongside
   the existing string-concatenation checks:

   ```rust
   // Generator/async function constructor eval bypass
   b"function*(){}).constructor",
   b"function* () {}).constructor",
   b"async function(){}).constructor",
   b"getPrototypeOf(function*",
   b"getPrototypeOf(function *",
   b"Function.prototype.constructor",
   ```

   These are byte-literal patterns that do not require AST parsing and follow the
   existing `find_token` convention used throughout the file.

2. The return value of `contains_dynamic_eval_construction()` is already emitted as
   `js.dynamic_eval_construction` in the finding metadata. No schema change is needed.

3. Additionally add a dedicated byte pattern for the `null-out and rebind` variant
   (`Object.getPrototypeOf(function*(){}).constructor = null`) — this is a distinct
   anti-detection step often paired with the bypass.

**Tests** (in `crates/js-analysis/src/static_analysis.rs`):

1. `contains_dynamic_eval_construction` returns `true` for
   `((function*(){}).constructor("x"))().next()`.
2. `contains_dynamic_eval_construction` returns `true` for
   `Object.getPrototypeOf(function*(){}).constructor`.
3. `contains_dynamic_eval_construction` returns `true` for
   `(async function(){}).constructor("x")`.
4. `contains_dynamic_eval_construction` still returns `false` for a benign payload
   with no dynamic construction.
5. Integration: scanning payload1.pdf JS produces `js.dynamic_eval_construction: true`.

**Documentation**: update `docs/findings.md` note under `js_present` static flags
to mention generator/async constructor patterns.

**Acceptance**:
1. `js.dynamic_eval_construction: true` for all generator/async constructor bypass
   patterns.
2. Existing benign payload tests continue to pass with no new false positives.
3. Docs updated in same commit.

---

### B2. `JS-02` Global deletion sandbox bypass detection

**Goal**: Set `js.sandbox_evasion = true` and emit a dedicated
`js_global_deletion_sandbox_bypass` finding when a JavaScript payload deletes browser
globals as a sandbox escape technique.

**Root cause**: `detect_sandbox_evasion()` in
`crates/js-analysis/src/static_analysis.rs` tests for environment-fingerprinting
patterns (`typeof window`, `typeof document`, etc.), not for the active deletion
variant (`delete window`, `delete confirm`, `delete document`).

The Apryse WebViewer SDK (10.9.x–10.12.0) sandbox bypass technique uses:
```javascript
delete window; delete confirm; delete document;
window.confirm(document.cookie);
```

The `delete` approach is fundamentally different from fingerprinting: it is an
attempt to actively disable the sandbox's global-scope guard rather than inspect it.

**Implementation**:

1. Add a new dedicated detector function in `static_analysis.rs`:

   ```rust
   fn detect_global_deletion_bypass(data: &[u8]) -> bool {
       let deletion_targets: &[&[u8]] = &[
           b"delete window",
           b"delete document",
           b"delete confirm",
           b"delete alert",
           b"delete Function",
           b"delete eval",
       ];
       // Require at least 2 distinct global deletions to avoid FP on
       // legitimate code that deletes a custom variable named e.g. "window".
       deletion_targets.iter().filter(|p| find_token(data, p)).count() >= 2
   }
   ```

2. Wire into the static analysis output map alongside the existing `js.sandbox_evasion`
   key — when `detect_global_deletion_bypass` is true, set `js.sandbox_evasion = true`
   regardless of the existing `detect_sandbox_evasion` result (logical OR).

3. Add a second metadata key `js.global_deletion_bypass: true/false` to allow consumers
   to distinguish the bypass subtype from environment fingerprinting.

4. In the JS detector findings layer (`crates/sis-pdf-detectors/src/js_sandbox.rs` or
   equivalent), emit a dedicated finding when `js.global_deletion_bypass = true`:

   | Field | Value |
   |---|---|
   | kind | `js_global_deletion_sandbox_bypass` |
   | severity | High |
   | confidence | Probable |
   | surface | JavaScript |
   | title | JavaScript global deletion sandbox bypass |
   | description | Payload deletes browser globals to escape sandbox restrictions. Known pattern for Apryse WebViewer SDK CVE (10.9.x–10.12.0). |
   | meta | `js.global_deletion_bypass: true`, `js.deleted_globals: <comma-separated list>` |

5. Escalate `js_emulation_breakpoint` confidence from `Tentative` to `Probable` when
   the emulation breakpoint co-occurs with `js.global_deletion_bypass = true`. This
   requires coordination between the emulation runtime findings and the static analysis
   result; the emulation result already sets `js.runtime.*` metadata — add a post-
   processing step that checks both signals and upgrades the emulation finding when
   both fire.

**Tests**:

1. Unit: `detect_global_deletion_bypass` returns `true` for
   `delete window; delete confirm; delete document;`.
2. Unit: `detect_global_deletion_bypass` returns `false` for a single deletion
   (`delete window;` alone).
3. Unit: `detect_global_deletion_bypass` returns `false` for benign payload
   (no `delete <global>` pattern).
4. Integration: scanning payload9.pdf produces `js.sandbox_evasion: true`,
   `js.global_deletion_bypass: true`, and `js_global_deletion_sandbox_bypass` finding.
5. Integration: `js_emulation_breakpoint` finding for payload9 upgraded to
   `Probable` confidence when co-occurring.

**Documentation**: add `js_global_deletion_sandbox_bypass` finding entry to
`docs/findings.md` with Apryse CVE context note.

**Acceptance**:
1. `js.sandbox_evasion: true` and `js.global_deletion_bypass: true` for all global
   deletion payloads.
2. Dedicated finding emitted at `High/Probable`.
3. Emulation breakpoint confidence upgraded when co-occurring.
4. No false positives on clean fixture baseline (benign corpus run recorded in
   baseline deltas below before marking complete).
5. Docs updated in same commit.

---

## Workstream C: Annotation field content injection detection

### C1. `ANNOT-01` HTML injection in annotation /T and /Contents fields

**Goal**: Detect HTML and XSS patterns in text annotation `/T` (title) and
`/Contents` (body) fields, extending the existing `pdfjs_annotation_injection`
and `form_html_injection` detectors to cover annotation text fields.

**Root cause**: `pdfjs_annotation_injection` checks `/URI` action targets and
render-context annotation bodies. `form_html_injection` checks AcroForm widget `/V`
fields. Neither inspects the `/T` or `/Contents` fields of standard Text annotations
(`/Subtype /Text`) or other annotation types.

These fields are rendered in:
- Acrobat/Adobe Reader pop-up callout windows.
- PDF.js annotation layer (as tooltip/title content).
- PSPDFKit Web annotation overlay.
Web-based renderers that inject `/T` or `/Contents` into the DOM without sanitisation
are vulnerable to XSS.

**Detection target**: annotation objects of any subtype where either `/T` or
`/Contents` contain:
- HTML tag patterns (`<`, `>` with tag-like structure).
- JavaScript event handler patterns (`on\w+=`).
- HTML injection scaffolding (`><`, `'><`, `">`).
- UTF-16 encoded equivalents of the above (PDF `/Contents` strings are often UTF-16).

**Implementation location**: `crates/sis-pdf-detectors/src/annotations_advanced.rs`,
`AnnotationAttackDetector::run()`.

**Implementation approach**:

1. In the annotation iteration loop, after the existing annotation action check, add
   a new check for `/T` and `/Contents` field values:

   ```rust
   fn check_annotation_field_injection(
       dict: &PdfDict,
       entry: &ObjEntry,
   ) -> Option<Finding>
   ```

   This helper:
   - Extracts `/T` and `/Contents` values as decoded byte strings (handling both
     UTF-16BE BOM-prefixed and UTF-8 encodings; the existing `PdfStr` type already
     handles both via `.to_utf8_lossy()`).
   - Runs a lightweight HTML pattern scan using the existing `content_phishing.rs`
     heuristics (reuse `contains_html_like_content(data)` or equivalent already
     used by `ContentPhishingDetector`).
   - Returns a finding if any match is found.

2. New finding kind:

   | Field | Value |
   |---|---|
   | kind | `annotation_field_html_injection` |
   | severity | Medium |
   | confidence | Probable |
   | surface | ContentPhishing |
   | title | HTML injection in annotation text field |
   | description | Annotation /T or /Contents field contains HTML or JavaScript-like content. Web-based PDF viewers that render these fields in the DOM may be vulnerable to XSS. |
   | meta | `annot.field: /T` or `/Contents`; `annot.subtype: /Text` etc.; `injection.patterns: <matched patterns>` |

3. Decode UTF-16 before scanning: PDF text strings can be UTF-16BE encoded
   (indicated by a `\xFE\xFF` BOM). Use the existing `PdfStr::to_utf8_lossy()`
   method to normalise before pattern matching.

4. Cap at 10 findings per kind using `apply_kind_cap`.

5. The existing `revision_annotations_changed` finding continues to fire and provides
   the structural delta context. This new finding adds content-level signal.

**Tests**:

1. Synthetic fixture: Text annotation with `/T (\">'><details open ontoggle=x>)` →
   `annotation_field_html_injection` finding, meta `annot.field=/T`.
2. Synthetic fixture: annotation with UTF-16 encoded XSS in `/Contents` →
   finding emitted after UTF-16 decode.
3. Benign fixture: annotation with plain text `/T` and `/Contents` → no finding.
4. Benign fixture: annotation with `/Contents` containing `<` in a mathematical
   expression (e.g. `a < b`) → should not fire; evaluate threshold to avoid FP.
5. Integration: payload1.pdf scanning emits `annotation_field_html_injection` for
   object 14:0 (the Text annotation added in revision 1).

**Documentation**: add `annotation_field_html_injection` finding to `docs/findings.md`.

**Acceptance**:
1. HTML/XSS content in `/T` and `/Contents` detected with appropriate severity.
2. UTF-16 encoding handled correctly before pattern match.
3. False positive rate on benign corpus < 1% (corpus run recorded in baseline deltas).
4. Docs updated in same commit.

---

## Workstream D: Severity and confidence calibration

### D1. `CAL-01` `js_runtime_file_probe` calibration for explicit Acrobat API calls

**Goal**: Prevent confidence downgrade to `Tentative` for payloads where the JS
makes explicit and unambiguous Acrobat API calls to system executables.

**Root cause**: Payload4's `app.openDoc("/C/Windows/System32/calc.exe")` fires
`js_runtime_file_probe` at `Low/Tentative` because the profile diverges across
execution environments (Acrobat profile executes; browser/Node profiles do not).
The `profile_confidence_adjusted: Probable->Tentative` meta field shows the
downgrade is caused by cross-profile divergence.

For explicit Acrobat-specific API calls (`app.openDoc`, `app.launchURL`,
`app.importTextData`, `this.submitForm` with file paths, etc.) targeting
executables or system paths, the single-profile execution result is highly
significant and should not be penalised by cross-profile divergence.

**Implementation location**: `crates/js-analysis/` runtime confidence adjuster.

**Implementation approach**:

1. Add a post-processing step in the runtime confidence adjuster: if the call set
   includes one or more Acrobat-specific APIs that are unambiguously file/network
   targeting (`app.openDoc`, `app.launchURL`, `this.submitForm`,
   `this.importTextData`, `this.saveAs`, `this.mailDoc`), and the Adobe-compat
   profile executed those calls successfully (call count > 0), then:
   - Override the confidence floor to `Probable` even when cross-profile divergence
     would otherwise downgrade to `Tentative`.
   - Add metadata key `js.runtime.acrobat_api_execution_override: true`.

2. The override applies only when:
   - The Adobe-compat profile (`pdf_reader:adobe:*:compat`) is in the executed set.
   - The call target contains a file path extension `.exe`, `.dll`, `.bat`, `.cmd`,
     `.ps1`, `.vbs`, `.sh`, or a UNC path prefix.
   - The call count from the Adobe profile is >= 1.

**Tests**:

1. Synthetic: JS with `app.openDoc("/C/Windows/calc.exe")` → `js_runtime_file_probe`
   at `Medium/Probable` (not `Low/Tentative`), `js.runtime.acrobat_api_execution_override: true`.
2. Regression: existing payloads that fire `js_runtime_file_probe` at correct
   severity are not affected by the override for non-executable targets.
3. Benign: `app.openDoc("report.pdf")` → no override applied (`.pdf` is not in the
   override extension list).

**Documentation**: note the Acrobat API confidence override logic in the finding
metadata description in `docs/findings.md`.

**Acceptance**:
1. Explicit Acrobat API + executable-path calls produce `Probable` confidence.
2. Non-executable targets are not affected.
3. Docs updated in same commit.

---

## Extension opportunities

These are capabilities beyond the immediate gap closure that the corpus review
surfaces as valuable additions.

### EXT-01: URI scheme abuse finding integration with exploit chain scoring

**Current state**: `annotation_action_chain` is referenced in chain scoring for
action trigger/payload paths. The new `uri_*_scheme` findings should be treated as
high-weight evidence in chain scoring to elevate chains that include dangerous URI
actions.

**Proposed extension**: in `crates/sis-pdf-core/src/chain.rs` (or equivalent chain
scorer), add `uri_javascript_scheme`, `uri_file_scheme`, `uri_data_html_scheme`, and
`uri_command_injection` to the set of high-risk action findings that contribute to
chain risk score as `payload` or `execute` stage indicators.

### EXT-02: `/URI` action scheme normalisation for consistent classification

**Observation**: the `UriContentAnalysis` struct already classifies schemes but the
detection path in `annotations_advanced.rs` only uses a boolean result
(`uri_target_is_suspicious`). The scheme type is available but not surfaced as a
stable finding metadata field across all URI-related findings.

**Proposed extension**: add `uri.scheme` as a standard metadata key on all
`annotation_action_chain` findings (not just the new scheme-specific ones). This
enables consistent predicate filtering via `sis query findings --where
"kind=annotation_action_chain"` for URI-specific triage. The scheme is already
computed by `analyze_uri_content()`; the change is only in the metadata population.

### EXT-03: `null`-prototype pollution via generator constructor — AST-level detection

**Observation**: payload1 uses `Object.getPrototypeOf(function*(){}).constructor = null`
to null out the GeneratorFunction constructor and then immediately uses
`(function*(){}).constructor(...)` to invoke it. This is a more sophisticated pattern
than simple generator bypass — it actively clobbers a built-in to hinder detection.

**Proposed extension**: add a dedicated static analysis flag
`js.prototype_chain_manipulation: true/false` that detects assignment to properties
of `Object.getPrototypeOf(...)` results. This is distinct from
`js.prototype_pollution_gadget` (which flags read-based pollution) and captures the
write-side manipulation. Implement as a byte pattern:
`b"getPrototypeOf"` AND `b"constructor = null"` (or `b"constructor=null"`).

The flag feeds into the `js_present` metadata and can drive a dedicated
`js_prototype_chain_tamper` finding if both `js.prototype_chain_manipulation` and
`js.dynamic_eval_construction` are true simultaneously.

### EXT-04: Multi-encoding annotation field scanning

**Observation**: the `/Contents` field in payload1's XSS annotation is UTF-16BE
encoded (indicated by `\xFE\xFF` BOM in the raw bytes). The proposed ANNOT-01
uses `PdfStr::to_utf8_lossy()` which normalises this. However, some payloads
use percent-encoding or named character entity encoding in annotation fields.

**Proposed extension**: after UTF-16 normalisation, run the decoded string through
the existing URI percent-decoder and HTML entity decoder (if a lightweight one is
available in the codebase). This ensures that payloads like
`&#x3C;script&#x3E;` or `%3Cscript%3E` are also caught by the pattern matcher.
If no HTML entity decoder exists, add a minimal implementation limited to
`&lt;`, `&gt;`, `&amp;`, and the hex entity forms of `<`, `>`, `"`, `'`.

### EXT-05: Content stream payload scanning for embedded JS literals

**Observation**: the corpus PDFs carry payloads in action strings. However,
some more advanced samples embed JavaScript as text literals within content
streams (e.g. as part of an annotation appearance stream that renders JS source
as visible text, later harvested by a Do chain). The existing content stream
execution uplift detectors (`content_stream_gstate_abuse`, etc.) do not scan
for JS-like literals in stream text operators (`Tj`, `TJ`).

**Proposed extension**: add a lightweight `content_stream_js_literal` detector
that scans `Tj`/`TJ` operator string operands for JS-like patterns (function
declarations, `eval(`, `Function(`, `window.`, `document.`). Flag at
`Low/Tentative` when found — this is noisy but provides coverage for a technique
not currently detected.

### EXT-06: Annotation `/T` field spoofing detection

**Observation**: beyond XSS, the `/T` field is the annotation's unique identifier
in Acrobat's AcroForm model. Spoofing another annotation's `/T` value in an
incremental update can cause a later revision's annotation to shadow an earlier one,
overriding its behaviour without visible change. This is an anti-forensics technique.

**Proposed extension**: in the revision forensics detector, track `/T` values across
revisions and flag when a newly-added annotation's `/T` matches an existing
annotation's `/T` value (same page parent). Emit `annotation_t_field_collision`
at `Low/Probable` — not necessarily malicious but worth flagging for incremental
update payloads.

### EXT-07: Emulation runtime: `delete <global>` execution outcome tracking

**Observation**: the emulation sandbox already executes JS and tracks call counts,
but the `delete window` / `delete confirm` operations produce `missing_callable`
breakpoints rather than being tracked as intentional global-scope manipulations.

**Proposed extension**: extend the emulation runtime to track explicit `delete`
operations on browser globals and emit a dedicated `js.runtime.global_deletions`
count field in the sandbox execution metadata. This feeds the `JS-02` finding
with runtime-confirmed evidence rather than relying solely on static analysis.

### EXT-08: Structured `uri_classification` finding for all `/URI` actions

**Observation**: currently `/URI` action URIs are partially classified (suspicious
boolean) but the full `UriContentAnalysis` output (scheme, domain, obfuscation
level, tracking params, etc.) is not surfaced as first-class finding metadata
except for specific detectors that explicitly extract it.

**Proposed extension**: add a `uri_classification_summary` finding (Info/Strong)
emitted for every non-benign URI action, carrying the full structured classification
output. This gives the GUI, query surface, and chain scorer access to scheme,
domain, obfuscation level, and risk signals without relying on string parsing of
existing description fields.

---

## Implementation sequence and priority

### Phase 1 (gap closure — high urgency)

All four gap closures address concrete missed detections on a published PoC corpus.
Prioritise in the order that minimises code churn and maximises coverage improvement:

1. **A1 `URI-01`** — highest value, lowest risk. Uses existing `UriContentAnalysis`
   data; no new parsing required. Closes 4 missed payloads (1, 3, 4, 5).
2. **B2 `JS-02`** — global deletion sandbox bypass. Extend `detect_sandbox_evasion`
   with new pattern group + dedicated finding. Closes payload9 gap.
3. **C1 `ANNOT-01`** — annotation field HTML injection. Extend annotation loop with
   field content scan. Closes payload1's third payload.
4. **B1 `JS-01`** — generator constructor eval bypass flag. Byte-pattern extension to
   existing function. Closes payload1's first JS gap.

### Phase 2 (calibration and chain integration)

5. **D1 `CAL-01`** — `js_runtime_file_probe` confidence floor for explicit Acrobat
   APIs. Low risk (post-processing change; no new findings emitted).
6. **EXT-01** — chain scorer integration for URI scheme findings.
7. **EXT-02** — `uri.scheme` metadata on all `annotation_action_chain` findings.

### Phase 3 (extensions)

8. **EXT-03** — prototype chain manipulation flag.
9. **EXT-04** — multi-encoding annotation field scanning.
10. **EXT-06** — annotation `/T` field spoofing detection.
11. **EXT-07** — emulation `delete <global>` tracking.
12. **EXT-05** — content stream JS literal detector.
13. **EXT-08** — structured URI classification finding.

---

## Cross-cutting requirements

1. Every new finding kind must be added to `docs/findings.md` with severity,
   confidence, description, and example metadata keys in the same commit.
2. Every new finding kind must be covered by at least one integration test asserting
   the kind, severity, and confidence.
3. All new fixtures must be registered in
   `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json` with
   `sha256`, `source_path`, and `regression_targets`.
4. Corpus regression run required before any confidence level above `Tentative`:
   run `cargo test -p sis-pdf-core --test corpus_captured_regressions` and record
   results in the baseline deltas section below.
5. No unsafe code, no unwraps introduced.
6. Each Phase 1 item must ship as its own commit with a clear imperative message.

---

## Affected files

| File | Change |
|---|---|
| `crates/sis-pdf-detectors/src/annotations_advanced.rs` | Add `check_uri_dangerous_scheme()` helper and `check_annotation_field_injection()` helper; wire into `AnnotationAttackDetector::run()` |
| `crates/js-analysis/src/static_analysis.rs` | Extend `contains_dynamic_eval_construction()` with generator constructor patterns; add `detect_global_deletion_bypass()`; wire `js.global_deletion_bypass` into output map |
| `crates/sis-pdf-detectors/src/js_sandbox.rs` | Emit `js_global_deletion_sandbox_bypass` finding when `js.global_deletion_bypass = true`; upgrade `js_emulation_breakpoint` confidence when co-occurring |
| `crates/js-analysis/src/` (runtime confidence adjuster) | Add Acrobat API execution confidence floor override |
| `docs/findings.md` | Add `uri_javascript_scheme`, `uri_file_scheme`, `uri_data_html_scheme`, `uri_command_injection`, `js_global_deletion_sandbox_bypass`, `annotation_field_html_injection` |
| `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json` | Register any new synthetic fixtures used in tests |

---

## Gaps not in scope for this plan

1. Runtime dynamic analysis of `/URI` actions (not possible without a reader
   implementation; classification is the correct approach for static analysis).
2. Full JavaScript AST parsing for generator constructor detection (byte pattern
   approach is sufficient and consistent with existing detection strategy).
3. Fixing the source of the CVE (this tool detects, not remediates).
4. Signature-based detection of specific malware families (covered by YARA layer).

---

## Baseline deltas

Corpus run against `tmp/PayloadsAllThePDFs/` not yet executed (requires
corpus in `tmp/`). Integration tests against synthetic fixtures pass for
all four Phase 1 gap payloads. Benign corpus run pending.

```
## Phase 1 2026-02-23
- New finding kinds introduced: uri_javascript_scheme, uri_file_scheme,
  uri_data_html_scheme, uri_command_injection, annotation_field_html_injection,
  js_global_deletion_sandbox_bypass
- Severity/confidence levels: all High or Medium as specified in plan
- annotation_action_chain severity for /URI updated: benign Low (was Info),
  suspicious Medium (was Low)
- js.sandbox_evasion now also set by global deletion bypass (OR logic)
- js.global_deletion_bypass new metadata key in js_present findings
- js.dynamic_eval_construction now set by generator/async constructor patterns
- Integration tests: 9 annotation_attack_detection + 5 js_bypass_detection
- Unit tests: 10 annotations_advanced + 9 static_analysis
- Timing delta on CVE fixture: not measured (no regression suite run yet)
- Benign corpus false positive rate: not measured (pending corpus run)
```

---

## Implementation notes

### Phase 1 commits (2026-02-23)

| Commit | Items | Files changed |
|---|---|---|
| `110af2d` | A1, C1 | `annotations_advanced.rs`, `tests/annotation_attack_detection.rs`, `docs/findings.md` |
| `a5e8a43` | B1, B2 (static) | `js-analysis/src/static_analysis.rs` |
| `77e28b6` | B2 (finding layer) | `lib.rs`, `tests/js_bypass_detection.rs` |

### Phase 2 commits (2026-02-23)

| Commit | Items | Files changed |
|---|---|---|
| `e2ca591` | EXT-02, EXT-01, D1 | `annotations_advanced.rs`, `chain_synth.rs`, `chain_score.rs`, `js_sandbox.rs`, tests |

### Deviations from plan

- **B2 finding emission location**: plan suggested `js_sandbox.rs`; implemented
  in `lib.rs` (`JavaScriptDetector`) because that is where static analysis
  signals are available. `js_sandbox.rs` only has access to runtime signals.
- **B2 step 5** (escalate `js_emulation_breakpoint` confidence when co-occurring
  with `js.global_deletion_bypass`): **not implemented**. This requires
  post-processing coordination between the sandbox runtime findings and the
  static analysis result. Deferred to Phase 2 or as a follow-up.
- **Acceptance criteria for A1 point 2** (severity update for
  `annotation_action_chain` /URI actions) was implemented exactly as specified.
  The existing test `annotation_user_benign_uri_is_info` was renamed and updated
  to `annotation_user_benign_uri_is_low` to match.
- **D1 implementation**: override applied post-`apply_profile_scoring_meta` in
  the `has_file` branch of `JavaScriptSandboxDetector::run()`. The override fires
  when: confidence was downgraded below `Probable`, an Adobe-compat profile is in
  the executed set, the call list includes an Acrobat file API (`openDoc`,
  `launchURL`, etc.), and call args contain an executable extension.
- **EXT-02**: `uri.scheme` added to `annotation_action_chain` meta by calling
  `analyze_uri_content` immediately after `action.target` is inserted, when
  action type is `/URI`.
- **EXT-01**: URI scheme finding kinds added to both `action_from_kind()` in
  `chain_synth.rs` (so they become chain action keys) and `score_chain()` in
  `chain_score.rs` (scored at 0.85 for `javascript/file/data` and 0.80 for
  `command_injection`).

### Open items before completion gate

1. Run `cargo test -p sis-pdf-core --test corpus_captured_regressions` and
   record baseline deltas in this document.
2. Run against `tmp/PayloadsAllThePDFs/pdf-payloads/` and verify:
   - payload1.pdf → `uri_data_html_scheme` + `annotation_field_html_injection`
   - payload3.pdf → `uri_file_scheme`
   - payload4.pdf → `uri_command_injection`
   - payload5.pdf → `uri_javascript_scheme`
   - payload9.pdf → `js_global_deletion_sandbox_bypass` + `js.sandbox_evasion=true`
   - payload1.pdf JS → `js.dynamic_eval_construction=true`
3. Record false positive rate on clean benign corpus (target < 1% for
   `annotation_field_html_injection`, < 0.5% for others).

---

## Execution checklist

### Phase 1 — gap closure
- [x] A1: `URI-01` — dedicated `uri_dangerous_scheme` finding family
- [x] B2: `JS-02` — global deletion sandbox bypass detection + finding
- [x] C1: `ANNOT-01` — HTML injection in annotation /T and /Contents
- [x] B1: `JS-01` — generator function constructor eval bypass flag

### Phase 2 — calibration and integration
- [x] D1: `CAL-01` — `js_runtime_file_probe` Acrobat API confidence floor
- [x] EXT-01: chain scorer URI scheme integration
- [x] EXT-02: `uri.scheme` metadata on `annotation_action_chain`

### Phase 3 — extensions
- [x] EXT-03: prototype chain manipulation flag
- [x] EXT-04: multi-encoding annotation field scanning
- [x] EXT-06: annotation /T field spoofing detection
- [x] EXT-07: emulation `delete <global>` tracking
- [x] EXT-05: content stream JS literal detector
- [x] EXT-08: structured URI classification finding

### Completion gate
- [ ] All Phase 1 items have integration tests and corpus run recorded
- [x] All new finding kinds documented in `docs/findings.md`
- [ ] No false positive rate increase > 0.5% on clean benign corpus
- [ ] Phase 1 items validated against PayloadsAllThePDFs corpus (all four
      gap payloads produce expected findings)

### Phase 3 commits (2026-02-23)

| Commit | Items | Files changed |
|---|---|---|
| `eb07da1` | EXT-03, EXT-07 | `static_analysis.rs`, `lib.rs`, `js_bypass_detection.rs` |
| `eaa8f42` | EXT-04 | `annotations_advanced.rs`, `annotation_attack_detection.rs` |
| `2027c4d` | EXT-08 | `annotations_advanced.rs`, `annotation_attack_detection.rs` |
| `b6d3a17` | EXT-06 | `annotations_advanced.rs`, `annotation_attack_detection.rs` |
| `8f1484a` | EXT-05 | `content_stream_exec_uplift.rs`, `content_stream_exec_uplift.rs` (tests) |
| `f277cd3` | docs | `docs/findings.md` |

---

## Phase 3 handover — detailed implementation guide

Phase 1 and Phase 2 are fully committed (`e2ca591` is the latest commit). All tests
pass with `cargo test --features js-sandbox`. Phase 3 was started but interrupted
before any code was written. This section contains the exact implementation plan
for each EXT item, with function signatures, file locations, and test expectations.

The six items are independent and can be implemented in any order. Recommended
sequence based on complexity: EXT-03 → EXT-07 → EXT-04 → EXT-06 → EXT-05 → EXT-08.

---

### EXT-03: Prototype chain manipulation flag

**Status**: Not started.

**Goal**: Set `js.prototype_chain_manipulation = true` when a JS payload tampers
with the prototype chain by assigning `null` (or another value) to
`Object.getPrototypeOf(...).constructor`. Emit a dedicated
`js_prototype_chain_tamper` finding when this co-occurs with
`js.dynamic_eval_construction = true`.

**File 1**: `crates/js-analysis/src/static_analysis.rs`

Add after `detect_prototype_pollution_gadget()` (line ~2200):

```rust
/// Detect active prototype chain tampering via constructor null-assignment.
/// This is the write-side complement to prototype pollution (which is read-based).
/// Pattern: Object.getPrototypeOf(fn*(){}).constructor = null (or = anything)
/// Often paired with generator constructor eval bypass to hinder detection.
pub fn detect_prototype_chain_manipulation(data: &[u8]) -> bool {
    let has_get_prototype = find_token(data, b"getPrototypeOf");
    if !has_get_prototype {
        return false;
    }
    let has_constructor_assign = find_token(data, b"constructor = null")
        || find_token(data, b"constructor=null")
        || find_token(data, b"constructor = undefined")
        || find_token(data, b"constructor=undefined");
    has_get_prototype && has_constructor_assign
}
```

In `extract_js_signals()` output map (around line 153–157 near
`js.prototype_pollution_gadget`), add:

```rust
out.insert(
    "js.prototype_chain_manipulation".into(),
    bool_str(detect_prototype_chain_manipulation(data)),
);
```

Make `detect_prototype_chain_manipulation` `pub` so it is visible to tests.

**File 2**: `crates/sis-pdf-detectors/src/lib.rs`

After the `js_global_deletion_sandbox_bypass` emission block (around line 2062),
add a new block that emits `js_prototype_chain_tamper` when both flags are true:

```rust
if meta.get("js.prototype_chain_manipulation").map(String::as_str) == Some("true")
    && meta.get("js.dynamic_eval_construction").map(String::as_str) == Some("true")
{
    let mut tamper_meta = std::collections::HashMap::new();
    tamper_meta.insert("js.prototype_chain_manipulation".into(), "true".into());
    tamper_meta.insert("js.dynamic_eval_construction".into(), "true".into());
    if let Some(preview) = meta.get("payload.decoded_preview") {
        tamper_meta.insert("payload.preview".into(), preview.clone());
    }
    tamper_meta.insert("object.ref".into(), object_ref.clone());
    findings.push(Finding {
        id: String::new(),
        surface: AttackSurface::JavaScript,
        kind: "js_prototype_chain_tamper".into(),
        severity: Severity::High,
        confidence: Confidence::Probable,
        impact: None,
        title: "JavaScript prototype chain tampering".into(),
        description: "Payload null-assigns the prototype constructor alongside a \
            generator function constructor eval bypass. This is an active \
            anti-detection step that clobbers a built-in to hinder bytewise \
            analysis of the eval bypass.".into(),
        objects: vec![object_ref.clone()],
        evidence: deduped_evidence.clone(),
        remediation: Some("Treat as deliberate obfuscation; inspect full payload \
            for generator constructor eval pattern.".into()),
        meta: tamper_meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Default::default()
    });
}
```

**Also** add `"js.prototype_chain_manipulation"` to `high_risk_flags` in
`js_present_severity_from_meta()` (around line 1302–1308) so that
`js_present` is also elevated to `High` severity when this flag fires.

**Tests**: Add to `crates/sis-pdf-detectors/tests/js_bypass_detection.rs`:

```rust
#[test]
fn prototype_chain_manipulation_with_generator_bypass_emits_tamper_finding() {
    let bytes = build_pdf_with_js(
        "Object.getPrototypeOf(function*(){}).constructor = null; \
         ((function*(){}).constructor('app.alert(1)'))().next();"
    );
    let report = scan(&bytes);
    let finding = report.findings.iter()
        .find(|f| f.kind == "js_prototype_chain_tamper")
        .expect("js_prototype_chain_tamper should be emitted");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Probable);
}

#[test]
fn prototype_chain_manipulation_without_generator_bypass_does_not_emit_tamper_finding() {
    let bytes = build_pdf_with_js(
        "Object.getPrototypeOf(function*(){}).constructor = null;"
    );
    let report = scan(&bytes);
    assert!(
        report.findings.iter().all(|f| f.kind != "js_prototype_chain_tamper"),
        "tamper finding requires both flags to be true simultaneously"
    );
}

#[test]
fn prototype_chain_manipulation_sets_metadata_flag() {
    let bytes = build_pdf_with_js(
        "Object.getPrototypeOf(function*(){}).constructor = null;"
    );
    let report = scan(&bytes);
    let js = report.findings.iter().find(|f| f.kind == "js_present")
        .expect("js_present");
    assert_eq!(
        js.meta.get("js.prototype_chain_manipulation").map(String::as_str),
        Some("true")
    );
}
```

Add unit tests in `crates/js-analysis/src/static_analysis.rs` `#[cfg(test)]` block:
- `detect_prototype_chain_manipulation` returns `true` for the full null-assignment pattern
- `detect_prototype_chain_manipulation` returns `false` for plain `getPrototypeOf` without assignment
- `detect_prototype_chain_manipulation` returns `false` for benign prototype read

**docs/findings.md**: Add entry for `js_prototype_chain_tamper`:
- Severity: High, Confidence: Probable
- Surface: JavaScript
- Triggered when: `js.prototype_chain_manipulation = true` AND `js.dynamic_eval_construction = true`
- Meta keys: `js.prototype_chain_manipulation`, `js.dynamic_eval_construction`, `payload.preview`

---

### EXT-07: Global deletion tracking — deleted globals list

**Status**: Not started.

**Goal**: Extend `detect_global_deletion_bypass` to also return which specific
globals were detected deleted. Add `js.deleted_globals` to the static analysis
output map and incorporate it into the `js_global_deletion_sandbox_bypass`
finding metadata.

**File 1**: `crates/js-analysis/src/static_analysis.rs`

Add a companion function after `detect_global_deletion_bypass()` (line ~1686):

```rust
/// Returns the list of browser globals whose deletion was detected in the payload.
/// Used to populate `js.deleted_globals` metadata for forensic context.
pub fn list_deleted_globals(data: &[u8]) -> Vec<&'static str> {
    let targets: &[(&[u8], &str)] = &[
        (b"delete window",   "window"),
        (b"delete document", "document"),
        (b"delete confirm",  "confirm"),
        (b"delete alert",    "alert"),
        (b"delete Function", "Function"),
        (b"delete eval",     "eval"),
    ];
    targets.iter()
        .filter(|(pat, _)| find_token(data, pat))
        .map(|(_, name)| *name)
        .collect()
}
```

In `extract_js_signals()`, after the `js.global_deletion_bypass` insertion (line ~97):

```rust
let deleted_globals = list_deleted_globals(data);
if !deleted_globals.is_empty() {
    out.insert("js.deleted_globals".into(), deleted_globals.join(", "));
}
```

**File 2**: `crates/sis-pdf-detectors/src/lib.rs`

In the `js_global_deletion_sandbox_bypass` emission block (around line 2030–2062),
add `js.deleted_globals` to the `bypass_meta` if present in `meta`:

```rust
if let Some(deleted) = meta.get("js.deleted_globals") {
    bypass_meta.insert("js.deleted_globals".into(), deleted.clone());
}
```

**Tests**: Add to `crates/sis-pdf-detectors/tests/js_bypass_detection.rs`:

```rust
#[test]
fn global_deletion_bypass_finding_includes_deleted_globals_list() {
    let bytes = build_pdf_with_js(
        "delete window; delete confirm; delete document; window.confirm(document.cookie);"
    );
    let report = scan(&bytes);
    let finding = report.findings.iter()
        .find(|f| f.kind == "js_global_deletion_sandbox_bypass")
        .expect("js_global_deletion_sandbox_bypass");
    let deleted = finding.meta.get("js.deleted_globals")
        .expect("js.deleted_globals should be present");
    assert!(deleted.contains("window"), "should list window");
    assert!(deleted.contains("confirm"), "should list confirm");
    assert!(deleted.contains("document"), "should list document");
}

#[test]
fn js_present_includes_deleted_globals_metadata() {
    let bytes = build_pdf_with_js("delete window; delete confirm; x();");
    let report = scan(&bytes);
    let js = report.findings.iter().find(|f| f.kind == "js_present")
        .expect("js_present");
    let deleted = js.meta.get("js.deleted_globals")
        .expect("js.deleted_globals in js_present meta");
    assert!(deleted.contains("window"));
    assert!(deleted.contains("confirm"));
}
```

Add unit tests in `static_analysis.rs`:
- `list_deleted_globals` returns `["window", "confirm", "document"]` for the full payload
- `list_deleted_globals` returns `["window"]` for single deletion
- `list_deleted_globals` returns `[]` for benign payload

**docs/findings.md**: Update `js_global_deletion_sandbox_bypass` entry to mention
`js.deleted_globals` as an additional metadata key.

---

### EXT-04: Multi-encoding annotation field scanning

**Status**: Not started.

**Goal**: After UTF-16/UTF-8 normalisation in `check_annotation_field_injection()`,
also check percent-decoded and HTML-entity-decoded variants of `/T` and `/Contents`
field values against `FIELD_INJECTION_PATTERNS`.

**File**: `crates/sis-pdf-detectors/src/annotations_advanced.rs`

Add two private helper functions before `check_annotation_field_injection()`:

```rust
/// Minimal percent-decoder for annotation field content.
/// Decodes %XX sequences only; does not handle %uXXXX.
fn percent_decode_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hi = input[i + 1];
            let lo = input[i + 2];
            if let (Some(h), Some(l)) = (hex_digit(hi), hex_digit(lo)) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Minimal HTML entity decoder for annotation field content.
/// Handles: &lt; &gt; &amp; &quot; &apos; &#NNN; &#xNN; forms only.
fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        // Find the closing ';'
        let rest = &input[i..];
        let semi = rest.iter().position(|&b| b == b';');
        let Some(end) = semi else {
            out.push(input[i]);
            i += 1;
            continue;
        };
        let entity = &rest[1..end]; // content between '&' and ';'
        let decoded: Option<u8> = if entity.eq_ignore_ascii_case(b"lt") {
            Some(b'<')
        } else if entity.eq_ignore_ascii_case(b"gt") {
            Some(b'>')
        } else if entity.eq_ignore_ascii_case(b"amp") {
            Some(b'&')
        } else if entity.eq_ignore_ascii_case(b"quot") {
            Some(b'"')
        } else if entity.eq_ignore_ascii_case(b"apos") {
            Some(b'\'')
        } else if entity.starts_with(b"#x") || entity.starts_with(b"#X") {
            // &#xNN; hex numeric
            std::str::from_utf8(&entity[2..]).ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        } else if entity.starts_with(b"#") {
            // &#NNN; decimal numeric
            std::str::from_utf8(&entity[1..]).ok()
                .and_then(|s| s.parse::<u8>().ok())
        } else {
            None
        };
        if let Some(ch) = decoded {
            out.push(ch);
            i += end + 1; // skip past the ';'
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}
```

In `check_annotation_field_injection()`, change the pattern matching to also run
over decoded variants. Replace the current:

```rust
let bytes = pdf_string_bytes(s);
let lower = bytes.to_ascii_lowercase();
let hits: Vec<&str> = FIELD_INJECTION_PATTERNS
    .iter()
    .filter_map(|pat| {
        if lower.windows(pat.len()).any(|w| w == *pat) {
            Some(std::str::from_utf8(pat).unwrap_or("?"))
        } else {
            None
        }
    })
    .collect();
```

With:

```rust
let bytes = pdf_string_bytes(s);
let candidates: [Vec<u8>; 3] = [
    bytes.to_ascii_lowercase(),
    percent_decode_bytes(&bytes).to_ascii_lowercase(),
    html_entity_decode(&bytes).to_ascii_lowercase(),
];
let hits: Vec<&str> = FIELD_INJECTION_PATTERNS
    .iter()
    .filter_map(|pat| {
        if candidates.iter().any(|c| c.windows(pat.len()).any(|w| w == *pat)) {
            Some(std::str::from_utf8(pat).unwrap_or("?"))
        } else {
            None
        }
    })
    .collect();
```

**Tests**: Add to `crates/sis-pdf-detectors/tests/annotation_attack_detection.rs`:

```rust
#[test]
fn percent_encoded_xss_in_annotation_t_field_emits_finding() {
    // %3C = '<', %3E = '>', %2F = '/'  → <script>
    let bytes = build_pdf_with_text_annotation(
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "Normal content",
    );
    let report = scan(&bytes);
    assert!(
        report.findings.iter().any(|f| f.kind == "annotation_field_html_injection"),
        "percent-encoded XSS in /T should be detected"
    );
}

#[test]
fn html_entity_encoded_xss_in_annotation_contents_emits_finding() {
    // &lt;script&gt; → <script>
    let bytes = build_pdf_with_text_annotation(
        "Normal title",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
    );
    let report = scan(&bytes);
    assert!(
        report.findings.iter().any(|f| f.kind == "annotation_field_html_injection"),
        "HTML entity-encoded XSS in /Contents should be detected"
    );
}
```

Add unit tests for `percent_decode_bytes` and `html_entity_decode` in the
`annotations_advanced.rs` `#[cfg(test)]` block or in the test file (as separate
module-level `#[test]` functions):
- `%3Cscript%3E` decodes to `<script>`
- `&lt;script&gt;` decodes to `<script>`
- `&#x3C;` decodes to `<`
- `&#60;` decodes to `<`
- Plain text is unchanged

**Note**: The three-candidate approach (`raw`, `percent_decoded`, `entity_decoded`)
avoids needing to chain decoders and keeps the implementation simple. Do NOT apply
both decoders in sequence or you risk double-decoding benign content.

---

### EXT-06: Annotation /T field spoofing detection

**Status**: Not started.

**Goal**: Track `/T` (unique identifier) values across annotation revisions.
When a newly-added annotation's `/T` collides with an existing annotation's `/T`
on the same page, emit `annotation_t_field_collision` (Low/Probable).

**File**: `crates/sis-pdf-detectors/src/revision_forensics.rs`

The implementation requires two passes over the object graph:

**Pass 1** — collect all `/T` values from annotations in the baseline revision
(all objects not in `annotation_added_refs`), keyed by their page parent:

```rust
fn collect_annotation_t_values<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext,
    refs: &[String],  // object ref strings like "14 0 obj"
) -> HashMap<String, String> {  // map from "/T value" → "obj_ref"
    let mut t_map = HashMap::new();
    for ref_str in refs {
        let Some((obj, gen)) = parse_obj_ref(ref_str) else { continue };
        let Some(entry) = ctx.graph.get_object(obj, gen) else { continue };
        let Some(dict) = entry_dict_from_graph(entry) else { continue };
        if let Some((_, t_obj)) = dict.get_first(b"/T") {
            if let PdfAtom::Str(s) = &t_obj.atom {
                let t_val = String::from_utf8_lossy(&pdf_str_bytes(s)).to_string();
                t_map.insert(t_val, ref_str.clone());
            }
        }
    }
    t_map
}
```

**Note**: The revision timeline provides `annotation_added_refs` (new in this
revision) but does not currently provide "all existing annotation refs before
this revision". You need to build this from the object graph: iterate
`ctx.graph.objects` for annotation objects (dicts with `/Subtype` key) that are
NOT in `annotation_added_refs`.

**Implementation approach** (preferred simplification): use `ctx.graph.objects`
directly. Collect `/T` values from all annotations that existed before the most
recent revision, then check newly-added annotations against them. Use
`timeline.revisions.last().annotation_added_refs` for the newly-added set.

**Simpler alternative** (avoids timeline complexity): In
`AnnotationAttackDetector::run()` (in `annotations_advanced.rs`), which already
iterates all annotation objects — collect all `/T` values in a first pass, then
in a second pass check if any `/T` appears more than once across annotations on
the same page. This does not distinguish "newly added" from "existing" but still
catches the collision. Flag at `Low/Tentative` (slightly lower confidence since
it might catch legitimate multi-occurrence cases):

```rust
// First pass: collect (page_number, t_value) → Vec<obj_ref>
let mut t_collision_map: HashMap<(usize, String), Vec<String>> = HashMap::new();
for entry in &ctx.graph.objects {
    let Some(dict) = entry_dict(entry) else { continue };
    if dict.get_first(b"/Subtype").is_none() { continue };
    let page_num = annot_parent
        .get(&ObjRef { obj: entry.obj, gen: entry.gen })
        .map(|p| p.number).unwrap_or(0);
    if let Some((_, t_obj)) = dict.get_first(b"/T") {
        if let PdfAtom::Str(s) = &t_obj.atom {
            let t_val = pdf_string_bytes(s);
            let t_str = String::from_utf8_lossy(&t_val).to_string();
            t_collision_map
                .entry((page_num, t_str))
                .or_default()
                .push(format!("{} {} obj", entry.obj, entry.gen));
        }
    }
}
// Then emit findings for any collisions
for ((page_num, t_val), refs) in &t_collision_map {
    if refs.len() > 1 {
        let mut meta = HashMap::new();
        meta.insert("collision.t_value".into(), t_val.clone());
        meta.insert("collision.page".into(), page_num.to_string());
        meta.insert("collision.refs".into(), refs.join(", "));
        findings.push(Finding {
            kind: "annotation_t_field_collision".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            ...
        });
    }
}
```

**Finding spec**:
- kind: `annotation_t_field_collision`
- severity: Low, confidence: Probable
- surface: Actions
- title: "Annotation /T field collision"
- description: "Multiple annotations share the same /T identifier on the same page. In Acrobat's AcroForm model, a later annotation with a duplicate /T value shadows the earlier one, which can be used as an anti-forensics technique in incremental updates."
- meta: `collision.t_value`, `collision.page`, `collision.refs`
- cap: 10 per kind

**Tests**: Add to `annotation_attack_detection.rs`:
- Two annotations with the same `/T` on the same page → finding emitted
- Two annotations with different `/T` values → no finding
- Single annotation with `/T` → no finding

**docs/findings.md**: Add entry for `annotation_t_field_collision`.

---

### EXT-05: Content stream JS literal detector

**Status**: Not started.

**Goal**: Scan `Tj` and `TJ` content stream text operator string operands for
JS-like patterns. Emit `content_stream_js_literal` at Low/Tentative when found.

**File**: `crates/sis-pdf-detectors/src/content_stream_exec_uplift.rs`

The `ContentOperand` enum is:
```rust
pub enum ContentOperand {
    Number(f32),
    Name(String),
    Str(String),    // raw string including wrapping (...)  or <...>
    Array(String),  // raw array including wrapping [...]
    Dict(String),
    Bool(bool),
    Null,
}
```

`Tj` takes one `Str` operand. `TJ` takes one `Array` operand containing a mix
of strings and numbers.

Add to `ContentStreamExecUpliftDetector::run()`, after the existing stream
processing loop (after line 95), a new detection pass:

```rust
/// JS-like patterns that would be suspicious as rendered text content.
const JS_TEXT_PATTERNS: &[&[u8]] = &[
    b"function",
    b"eval(",
    b"Function(",
    b"window.",
    b"document.",
    b"<script",
    b"javascript:",
];
const CONTENT_STREAM_JS_LITERAL_CAP: usize = 10;

fn scan_text_ops_for_js(ops: &[ContentOp]) -> Vec<String> {
    let mut hits = Vec::new();
    for op in ops {
        if !matches!(op.op.as_str(), "Tj" | "TJ" | "'" | "\"") {
            continue;
        }
        for operand in &op.operands {
            let raw = match operand {
                ContentOperand::Str(s) => s.as_bytes(),
                ContentOperand::Array(s) => s.as_bytes(),
                _ => continue,
            };
            let lower = raw.to_ascii_lowercase();
            for pat in JS_TEXT_PATTERNS {
                if lower.windows(pat.len()).any(|w| w == *pat) {
                    hits.push(String::from_utf8_lossy(pat).to_string());
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}
```

In `run()`, inside the stream loop, after `analyse_ops`:

```rust
let js_text_hits = scan_text_ops_for_js(&ops);
if !js_text_hits.is_empty() {
    let mut meta = HashMap::new();
    meta.insert("stream.js_patterns".into(), js_text_hits.join(", "));
    meta.insert("stream.obj".into(),
        stream_ref.obj_ref
            .map(|(o, g)| format!("{o} {g}"))
            .unwrap_or_else(|| format!("{} {}", page.obj, page.gen)));
    meta.insert("page.number".into(), page.number.to_string());
    findings.push(Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "content_stream_js_literal".into(),
        severity: Severity::Low,
        confidence: Confidence::Tentative,
        impact: None,
        title: "JavaScript-like literal in content stream".into(),
        description: "Text rendering operators (Tj/TJ) contain strings \
            resembling JavaScript. Some advanced payloads embed JS as \
            text literals in appearance streams for later harvesting.".into(),
        objects: vec![format!("{} {} obj", page.obj, page.gen)],
        evidence: vec![span_to_evidence(
            stream_ref.stream.data_span,
            "Content stream text operators",
        )],
        remediation: Some(
            "Inspect content stream text; determine whether JS fragments \
             are incidental or harvested by a Do/action chain.".into()
        ),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    });
}
```

After the outer page loop, cap:

```rust
apply_kind_cap(&mut findings, "content_stream_js_literal", CONTENT_STREAM_JS_LITERAL_CAP);
```

Note: `apply_kind_cap` lives in `annotations_advanced.rs`. Either duplicate the
function in `content_stream_exec_uplift.rs` or extract it to a shared module in
`crates/sis-pdf-detectors/src/`. The simplest approach is to re-implement a
local version — it is 30 lines.

**Tests**: Add to `crates/sis-pdf-detectors/tests/content_stream_exec_uplift.rs`
(or create it if it doesn't exist):
- Stream with `(function eval() {})` in `Tj` → finding emitted
- Stream with plain text `(Hello World)` → no finding
- Stream with `[(<script> )] TJ` → finding emitted

**docs/findings.md**: Add entry for `content_stream_js_literal`:
- Severity: Low, Confidence: Tentative
- Note that this is a low-certainty indicator; most fires on innocent content

---

### EXT-08: Structured URI classification finding

**Status**: Not started.

**Goal**: Emit `uri_classification_summary` (Info/Strong) for every `/URI` action
where `analyze_uri_content()` indicates at least one risk signal. This provides
structured access to the full `UriContentAnalysis` output via the query surface.

**File**: `crates/sis-pdf-detectors/src/annotations_advanced.rs`

In `AnnotationAttackDetector::run()`, in the `/URI` action handling block (around
line 150–156, after `check_uri_dangerous_scheme`), add:

```rust
if action_type.to_ascii_uppercase() == "/URI" {
    if let Some(scheme_finding) =
        check_uri_dangerous_scheme(entry, &action_target, dict.span)
    {
        findings.push(scheme_finding);
    }
    // EXT-08: structured classification summary for non-benign URIs
    if let Some(summary_finding) =
        check_uri_classification_summary(entry, &action_target, dict.span)
    {
        findings.push(summary_finding);
    }
}
```

Add the new helper function:

```rust
const URI_CLASSIFICATION_SUMMARY_CAP: usize = 25;

fn check_uri_classification_summary(
    entry: &ObjEntry<'_>,
    action_target: &str,
    dict_span: Span,
) -> Option<Finding> {
    if action_target.is_empty() || action_target == "unknown" {
        return None;
    }
    let a = analyze_uri_content(action_target.as_bytes());
    // Only emit for URIs with at least one risk signal.
    let has_risk = a.is_javascript_uri
        || a.is_file_uri
        || (a.is_data_uri && a.data_mime.is_some())
        || a.has_suspicious_scheme
        || a.is_ip_address
        || a.suspicious_tld
        || a.has_data_exfil_pattern
        || a.has_shortener_domain
        || a.has_suspicious_extension
        || a.has_embedded_ip_host
        || a.has_idn_lookalike
        || !a.suspicious_patterns.is_empty()
        || !a.phishing_indicators.is_empty()
        || !a.tracking_params.is_empty();
    if !has_risk {
        return None;
    }
    let mut meta = HashMap::new();
    meta.insert("uri.scheme".into(), a.scheme.clone());
    if let Some(domain) = &a.domain {
        meta.insert("uri.domain".into(), domain.clone());
    }
    if let Some(path) = &a.path {
        meta.insert("uri.path".into(), path.clone());
    }
    meta.insert("uri.obfuscation_level".into(), a.obfuscation_level.as_str().into());
    meta.insert("uri.length".into(), a.length.to_string());
    if !a.tracking_params.is_empty() {
        meta.insert("uri.tracking_params".into(), a.tracking_params.join(", "));
    }
    if !a.suspicious_patterns.is_empty() {
        meta.insert("uri.suspicious_patterns".into(), a.suspicious_patterns.join(", "));
    }
    if !a.phishing_indicators.is_empty() {
        meta.insert("uri.phishing_indicators".into(), a.phishing_indicators.join(", "));
    }
    // Boolean risk flags (only include true ones to keep metadata compact)
    for (key, val) in &[
        ("uri.is_ip_address",          a.is_ip_address),
        ("uri.is_file_uri",            a.is_file_uri),
        ("uri.is_javascript_uri",      a.is_javascript_uri),
        ("uri.is_data_uri",            a.is_data_uri),
        ("uri.suspicious_tld",         a.suspicious_tld),
        ("uri.has_data_exfil_pattern", a.has_data_exfil_pattern),
        ("uri.has_shortener_domain",   a.has_shortener_domain),
        ("uri.has_suspicious_ext",     a.has_suspicious_extension),
        ("uri.has_embedded_ip_host",   a.has_embedded_ip_host),
        ("uri.has_idn_lookalike",      a.has_idn_lookalike),
    ] {
        if *val {
            meta.insert((*key).into(), "true".into());
        }
    }
    if let Some(mime) = &a.data_mime {
        meta.insert("uri.data_mime".into(), mime.clone());
    }
    Some(Finding {
        id: String::new(),
        surface: AttackSurface::Actions,
        kind: "uri_classification_summary".into(),
        severity: Severity::Info,
        confidence: Confidence::Strong,
        impact: None,
        title: format!("URI classification: {}", a.scheme),
        description: format!(
            "Structured classification of /URI action target: {}",
            &action_target[..action_target.len().min(120)]
        ),
        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
        evidence: vec![span_to_evidence(dict_span, "Annotation /URI action")],
        remediation: None,
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    })
}
```

Add to the `apply_kind_cap` calls at the end of `run()`:

```rust
apply_kind_cap(&mut findings, "uri_classification_summary", URI_CLASSIFICATION_SUMMARY_CAP);
```

**Tests**: Add to `annotation_attack_detection.rs`:

```rust
#[test]
fn javascript_uri_emits_uri_classification_summary_finding() {
    let bytes = build_pdf_with_link_annotation("javascript:confirm(1)");
    let report = scan(&bytes);
    let summary = report.findings.iter()
        .find(|f| f.kind == "uri_classification_summary")
        .expect("uri_classification_summary should be emitted for javascript: URI");
    assert_eq!(summary.severity, Severity::Info);
    assert_eq!(summary.confidence, Confidence::Strong);
    assert_eq!(summary.meta.get("uri.scheme").map(String::as_str), Some("javascript"));
    assert_eq!(summary.meta.get("uri.is_javascript_uri").map(String::as_str), Some("true"));
}

#[test]
fn benign_https_uri_does_not_emit_uri_classification_summary() {
    let bytes = build_pdf_with_link_annotation("https://example.com/page");
    let report = scan(&bytes);
    assert!(
        report.findings.iter().all(|f| f.kind != "uri_classification_summary"),
        "plain https URI with no risk signals should not emit classification summary"
    );
}

#[test]
fn ip_address_uri_emits_uri_classification_summary() {
    let bytes = build_pdf_with_link_annotation("http://192.168.1.1/payload");
    let report = scan(&bytes);
    // IP-address URIs are suspicious; expect a summary
    assert!(
        report.findings.iter().any(|f| f.kind == "uri_classification_summary"),
        "IP-address URI should emit uri_classification_summary"
    );
}
```

**docs/findings.md**: Add entry for `uri_classification_summary`:
- Severity: Info, Confidence: Strong
- Note: companion finding to `annotation_action_chain`; provides structured
  URI analysis fields for query/filter without string parsing
- Meta keys: `uri.scheme`, `uri.domain`, `uri.obfuscation_level`,
  `uri.tracking_params`, `uri.suspicious_patterns`, `uri.phishing_indicators`,
  plus boolean risk flags

---

### Phase 3 implementation order and commit strategy

Each EXT item ships as its own commit with an imperative message, following the
Phase 1 pattern. Recommended order:

| Step | Item | Files | Notes |
|---|---|---|---|
| 1 | EXT-03 | `static_analysis.rs`, `lib.rs`, tests | Lowest risk; pure byte-pattern extension |
| 2 | EXT-07 | `static_analysis.rs`, `lib.rs`, tests | Companion to EXT-03; static analysis only |
| 3 | EXT-04 | `annotations_advanced.rs`, tests | Self-contained; new helper functions |
| 4 | EXT-08 | `annotations_advanced.rs`, tests | Builds on EXT-04's URI analysis |
| 5 | EXT-06 | `annotations_advanced.rs` or `revision_forensics.rs`, tests | Needs design decision (see note) |
| 6 | EXT-05 | `content_stream_exec_uplift.rs`, tests | Isolated new capability |

After all six are committed, update `docs/findings.md` in a final consolidation
commit and mark the execution checklist complete.

### Phase 3 design decisions outstanding

1. **EXT-06 location**: The plan specified `revision_forensics.rs` but the simpler
   implementation (collision detection across all current annotations regardless of
   revision) fits more naturally in `AnnotationAttackDetector::run()` in
   `annotations_advanced.rs`. Choose based on whether revision context is important;
   the simpler approach is recommended first.

2. **EXT-05 `apply_kind_cap`**: The function is private to `annotations_advanced.rs`.
   Options: (a) re-implement locally in `content_stream_exec_uplift.rs` (trivial copy),
   (b) move to `crates/sis-pdf-detectors/src/utils.rs` and re-export. Option (a) is
   lower risk.

3. **EXT-04 double-decode risk**: If both `percent_decode` and `html_entity_decode`
   are applied to the same input, benign content like `%26lt;` could produce a false
   positive. The three-candidate approach (raw, percent-only, entity-only) avoids
   this — do NOT chain them.

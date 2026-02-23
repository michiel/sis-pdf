                                                                                                      
  ContentStreamExec represents a PDF page executing its content stream — the stream of drawing operators  
  that renders a page (text placement, images, graphics). Every page has one or more. The source object is
   the page; the execute target is the stream object. From a security perspective this is the primary     
  carrier for obfuscated payloads: encoded shellcode, embedded JavaScript fragments, and heap spray       
  content all live in content streams.                                                                    
                   

  ---
  Detection Coverage — PayloadsAllThePDFs

  Payload matrix

  File: payload1.pdf
  Payload(s): OpenAction JS (generator-fn eval bypass + cookie theft)
  Key findings: js_present, js_sandbox_exec, dom_xss_sink=true, content_html_payload
  Coverage: Partial — eval bypass not detected
  ────────────────────────────────────────
  File: payload1.pdf
  Payload(s): data:text/html,<script>alert(2) in /URI action
  Key findings: annotation_action_chain (meta only)
  Coverage: GAP — no dedicated finding
  ────────────────────────────────────────
  File: payload1.pdf
  Payload(s): HTML XSS in annotation /T + /Contents
  Key findings: revision_annotations_changed only
  Coverage: GAP — field content not analysed
  ────────────────────────────────────────
  File: payload2.pdf
  Payload(s): XSS HTML in /URI action
  Key findings: pdfjs_annotation_injection (Medium/Strong), annotation_action_chain
  Coverage: Good
  ────────────────────────────────────────
  File: payload3.pdf
  Payload(s): OpenAction JS (alert/prompt/document.write)
  Key findings: js_present, js_sandbox_exec, dom_xss_sink=true
  Coverage: Good
  ────────────────────────────────────────
  File: payload3.pdf
  Payload(s): file:///C:/Windows/system32/calc.exe in /URI
  Key findings: annotation_action_chain (meta only)
  Coverage: GAP — no dedicated finding
  ────────────────────────────────────────
  File: payload4.pdf
  Payload(s): app.openDoc("/C/Windows/System32/calc.exe") in JS
  Key findings: js_runtime_file_probe (Low/Tentative), js_intent_user_interaction
  Coverage: Partial — severity underweighted
  ────────────────────────────────────────
  File: payload4.pdf
  Payload(s): START C:/Windows/system32/calc.exe in /URI
  Key findings: annotation_action_chain (meta only)
  Coverage: GAP — no dedicated finding
  ────────────────────────────────────────
  File: payload5.pdf
  Payload(s): app.launchURL("START C:/…/calc.exe") in JS
  Key findings: js_runtime_network_intent (Low/Tentative), supply_chain_staged_payload
  Coverage: Partial
  ────────────────────────────────────────
  File: payload5.pdf
  Payload(s): javascript:confirm(2); in /URI action
  Key findings: annotation_action_chain (meta only)
  Coverage: GAP — no dedicated finding
  ────────────────────────────────────────
  File: payload6.pdf
  Payload(s): app.launchURL(…XSS…) in JS
  Key findings: supply_chain_staged_payload, js_runtime_network_intent
  Coverage: Good
  ────────────────────────────────────────
  File: payload7.pdf
  Payload(s): HTML injection in AcroForm field /V
  Key findings: form_html_injection (Medium/Strong), aa_present, acroform_present
  Coverage: Good
  ────────────────────────────────────────
  File: payload8.pdf
  Payload(s): CVE-2024-4367 FontMatrix JS injection
  Key findings: fontmatrix_payload_present, pdfjs_font_injection, font.type1_dangerous_operator,
    pdfjs_eval_path_risk
  Coverage: Good
  ────────────────────────────────────────
  File: payload9.pdf
  Payload(s): Sandbox bypass via delete window/confirm/document
  Key findings: js_emulation_breakpoint (Info/Tentative), js_intent_user_interaction
  Coverage: GAP — not classified as sandbox evasion
  ────────────────────────────────────────
  File: foxit-reader-poc.pdf
  Payload(s): importTextData("/etc/passwd") + submitForm exfil
  Key findings: js_runtime_credential_harvest (High/Strong ×3), js_runtime_file_probe (High/Strong ×3),
    supply_chain_staged_payload (×3)
  Coverage: Excellent
  ────────────────────────────────────────
  File: starter_pack.pdf
  Payload(s): JS + annotation injection combination
  Key findings: All relevant findings fire
  Coverage: Good

  ---
  What is well detected

  JavaScript static analysis: All JS payloads detected via js_present with correct
  payload.decoded_preview, js.dom_xss_sink, js.behaviour_summary, and intent classification. The sandbox
  executor fires and reveals call traces even when it only partially executes (js.runtime.calls,
  js.runtime.call_args).

  PDF.js-specific attack surface: pdfjs_annotation_injection, pdfjs_font_injection, and
  pdfjs_eval_path_risk all fire correctly for the applicable payloads (2–6, 8). The CVE-2024-4367
  FontMatrix chain is correctly attributed.

  Form injection (payload7): form_html_injection fires cleanly with Medium/Strong on the XSS in the
  AcroForm widget /V field.

  Credential harvesting via Acrobat APIs (foxit-reader-poc): The importTextData("/etc/passwd") +
  submitForm sequence is classified High/Strong with runtime evidence at the URL level
  (http://localhost:1337/post-test in meta). Chain correlation also fires supply_chain_staged_payload.

  Content stream analysis: sis stream analyse terminates early on /JavaScript indicator in payload1.
  Content stream execution events are correctly graphed; no content-stream-embedded payloads are present
  in this set (the payloads here are all in action strings, annotation fields, and font structures — not
  in compressed stream bodies).

  Revision/structural integrity: revision_annotations_changed, revision_anomaly_scoring,
  revision_page_content_changed, and xref_conflict all fire consistently on the payloads that use
  incremental update to inject annotations (payloads 1–6, 9).

  ---
  Gaps

  GAP-1 — No dedicated URI dangerous-scheme finding

  Five payloads use malicious /URI actions:
  - data:text/html,<script>alert(2);</script> (payload1)
  - file:///C:/Windows/system32/calc.exe (payload3)
  - START C:/Windows/system32/calc.exe (payload4, not a valid URI)
  - javascript:confirm(2); (payload5)
  - ">'><details open ontoggle=confirm(2)> (payload2, payload6)

  The action.target value is captured correctly in annotation_action_chain metadata, but that finding is
  only Low–Medium/Probable and does not distinguish a javascript: URI from a benign https: link.
  pdfjs_annotation_injection fires for the XSS-shaped targets (payloads 2, 6) because they match the
  injection pattern, but file://, data:, and javascript: scheme abuses get no dedicated escalation. A
  uri_dangerous_scheme detector should inspect /URI action targets and emit High/Strong for javascript:,
  file://, and data:text/html schemes.

  GAP-2 — Generator function constructor eval bypass not flagged

  Payload1's JS:
  Object.getPrototypeOf(function*(){}).constructor = null;
  ((function*(){}).constructor("document.write(...)"))().next();

  This is functionally new Function("code")() — an eval bypass via the GeneratorFunction constructor. The
  flags js.dynamic_eval_construction, js.eval_sink, and js.contains_eval are all false. The static
  analysis resolves the AST correctly (it does detect dom_xss_sink=true and produces the correct call
  summary via sandbox) but the (function*(){}).constructor(...) pattern itself is not recognised as a
  dynamic code construction technique. Any pattern matching or AST rule for
  <generator|async>.constructor(string) invocations should set js.dynamic_eval_construction: true.

  GAP-3 — Sandbox bypass via global deletion not classified as evasion

  Payload9's JS:
  app.alert(1); console.println(delete window); console.println(delete confirm); console.println(delete
  document); window.confirm(document.cookie);

  This is the Apryse WebViewer SDK sandbox bypass (CVE-assigned, 10.9.x–10.12.0): deleting browser globals
   to escape WebViewer's sandboxed context. The emulation sandbox does detect a missing_callable
  breakpoint (firing js_emulation_breakpoint at Info/Tentative) and the call to
  window.confirm(document.cookie) is noted. However js.sandbox_evasion stays false,
  js.environment_fingerprinting stays false, and there is no dedicated finding for the delete <global>
  pattern. A rule matching delete window, delete document, delete confirm, or delete Function should set
  js.sandbox_evasion: true and escalate js_emulation_breakpoint or produce a dedicated
  js_global_deletion_sandbox_bypass finding.

  GAP-4 — HTML injection in annotation /T and /Contents fields not analysed

  Payload1's third payload is injected via an incremental-update text annotation:
  /T (">'><details open ontoggle=confirm(3)>)
  /Contents (UTF-16 encoded XSS)

  The annotation is detected as added (revision_annotations_changed, Medium/Probable), and the structural
  anomaly is flagged. But the field content — the HTML/XSS string in /T and /Contents — is not inspected
  for injection patterns. form_html_injection covers AcroForm widget /V; pdfjs_annotation_injection covers
   link annotation URIs and select text-annotation patterns. A coverage gap exists for injection via the
  annotation /T (title/author) and /Contents (comment body) fields. Extending either the
  form_html_injection or pdfjs_annotation_injection detectors to also scan these fields would close this.

  Minor: js_runtime_file_probe severity for explicit app.openDoc targeting calc.exe

  Payload4's app.openDoc("/C/Windows/System32/calc.exe") fires js_runtime_file_probe at Low/Tentative. The
   Acrobat API app.openDoc is unambiguous intent, and the target is a system executable. The runtime
  profile does detect the call (profile_consistency_signal: file) but the confidence is downgraded to
  Tentative. This is a calibration issue: explicit openDoc to a .exe path should produce at least
  Medium/Probable.

  ---
  Stream-embedded payload coverage

  None of the PDFs in this set carry payloads inside compressed content stream bodies — the active content
   is exclusively in /JS string actions, /URI action values, form field values, and the FontMatrix array.
  The content stream executor correctly graphs the ContentStreamExec events with no linked findings (clean
   rendering streams), and sis stream analyse triggers an early terminate on the /JavaScript indicator in
  the action action dictionaries rather than in stream bodies. No gap here for this corpus.



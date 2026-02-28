# Booking.com Lure JS Phishing PDF

## Threat Summary

This sample is a JavaScript-driven credential phishing PDF that impersonates Booking.com to deceive
victims into visiting a fraudulent URL. The attacker registered a lookalike Netlify subdomain
(`bocking.netlify.app` — note the transposition of "o" and "b" in "booking") to host the phishing
landing page. The PDF contains embedded JavaScript that activates on user interaction (not
auto-execute), reducing the likelihood of triggering automated sandbox analysis that only observes
passive document open events.

The file is classified Suspicious rather than Malicious because the PDF itself does not contain
executable payloads or exploits. Its function is purely redirection: convincing the victim to click
a link or interact with the document, then navigating the browser to the phishing page. Credential
harvesting occurs on the external Netlify-hosted site.

## File Structure

The PDF contains a small number of objects. Key structural elements:

- **Embedded JavaScript**: A `/JS` action object containing a JavaScript program. The script is
  bound to a user-interaction event (e.g., a button click or field focus) rather than to OpenAction
  or document-open triggers. This means the JS does not execute when the document is opened
  programmatically in a headless PDF parser.

- **Annotation action chain**: One or more page annotations (link annotations or widget annotations)
  reference an action chain. The chain resolves to a `/URI` action pointing to
  `https://bocking.netlify.app/`. The annotation renders as a button or clickable region that
  appears to be a Booking.com login prompt or reservation confirmation link.

- **Branding elements**: The document body contains Booking.com visual branding (logo, colour
  scheme, formatted text) to establish legitimacy with the victim. The content is static and does
  not itself contain malicious structures.

The JS and the annotation action chain provide two independent redirection pathways — a belt-and-
suspenders approach ensuring the victim is redirected even if one mechanism is disabled by the PDF
reader's security policy.

## Detection Chain

Detection proceeds through four signals converging on DataExfiltration and Phishing intent:

1. **js_present (medium/strong)**: The presence of a JavaScript action object is detected during
   object graph traversal. JavaScript in a PDF is not inherently malicious but is uncommon in
   legitimate documents and always warrants closer examination. The medium severity reflects this
   baseline risk.

2. **js_intent_user_interaction (high/strong)**: Static analysis of the JavaScript source identifies
   a `user_interaction` execution profile — the script registers event handlers tied to user input
   (click, focus, or keystroke events). This is a strong indicator of intentional social engineering:
   the attacker wants the victim to take an action, not rely on auto-execution that might be blocked.

3. **annotation_action_chain (low/strong, netlify URL)**: The annotation action chain resolver
   follows the action linked from the page annotation and extracts the final URI. The domain
   `bocking.netlify.app` matches the netlify-abuse heuristic (legitimate CDN/hosting platform used
   as a free phishing host). The low severity reflects that URI actions are common in legitimate
   PDFs; the strong confidence comes from the netlify domain pattern combined with the typosquatted
   subdomain.

4. **network_intents (bocking.netlify.app)**: The network intent extractor records the external
   domain as a DataExfiltration/Phishing indicator. The misspelled "bocking" subdomain is
   characteristic of typosquatting — a simple transposition intended to pass casual inspection.

Intent accumulation: `js_intent_user_interaction` contributes to the Phishing bucket.
`annotation_action_chain` with an external URL contributes to DataExfiltration. Together they
cross the Suspicious threshold. The verdict does not reach Malicious because there are no
executable payloads or exploit primitives.

## Evasion Techniques

**User-interaction trigger (not auto-execute)**: By binding JS to a user event rather than document
open, the sample avoids triggering in automated PDF sandboxes that open documents without simulating
user input. This is a deliberate choice — phishing campaigns need user engagement anyway, so the
attacker sacrifices auto-execution for improved sandbox evasion.

**Netlify platform abuse**: Netlify is a legitimate, widely used static hosting platform. Its domain
(`netlify.app`) appears in many legitimate services, so domain-reputation blocklists are less likely
to flag it wholesale. Using a free Netlify subdomain also means the attacker has no infrastructure
cost and can rotate subdomains rapidly if one is blocked.

**Typosquatting (`bocking`)**: The subdomain `bocking.netlify.app` differs from `booking.netlify.app`
by a single character transposition. Victims reading quickly, especially under urgency (e.g., "your
reservation is expiring"), are likely to miss the typo. Automated string matching against brand names
requires fuzzy matching to detect this.

**Brand impersonation**: Embedding Booking.com visual elements inside the PDF establishes false
legitimacy. Victims who trust the Booking.com brand are less likely to scrutinise the URL they are
being directed to.

## Key Indicators

- **SHA256**: `379b41e3fd94f48d3f1756202fc4e702a98af4f01ca59b1be30cb3e31bc4b3ce`
- **Network indicator**: `bocking.netlify.app` (typosquatted Booking.com lure via Netlify)
- **JS execution profile**: `user_interaction` (not auto-execute)
- **Action chain**: `/URI` annotation action pointing to phishing URL
- **Brand lure**: Booking.com visual impersonation
- **MITRE ATT&CK**: T1566.001 (Spearphishing Attachment), T1056.003 (Web Portal Capture),
  T1204.002 (User Execution: Malicious File)

## Regression Coverage

- **`booking_js_phishing_core_detections_present`**: Verifies that `js_present`,
  `js_intent_user_interaction`, `annotation_action_chain` (with netlify URL), and the
  `network_intents` extraction for `bocking.netlify.app` are all present. Also verifies that the
  DataExfiltration and Phishing intent buckets are activated and the verdict is Suspicious.

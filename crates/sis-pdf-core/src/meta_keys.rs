/// Canonical string keys for [`crate::model::Finding::meta`] and
/// [`crate::chain::ExploitChain::notes`] hash maps.
///
/// Use these constants instead of bare string literals to prevent typos and
/// to make key usage greppable across the codebase.

// ── Trigger / action / payload keys (ExploitChain notes) ────────────────────

/// Chain note key: the trigger finding kind (e.g. `"open_action_present"`).
pub const TRIGGER_KEY: &str = "trigger.key";

/// Chain note key: the action finding kind (e.g. `"launch_action_present"`).
pub const ACTION_KEY: &str = "action.key";

/// Chain note key: the payload finding kind.
pub const PAYLOAD_KEY: &str = "payload.key";

/// Finding meta / chain note: action subtype string (e.g. `"Launch"`, `"URI"`).
pub const ACTION_S: &str = "action.s";

/// Finding meta / chain note: resolved action target (URI, file path, etc.).
pub const ACTION_TARGET: &str = "action.target";

/// Chain note: whether the payload contains risky image format markers.
pub const PAYLOAD_RISKY: &str = "payload.risky";

// ── JavaScript analysis metadata keys ────────────────────────────────────────

/// Finding meta: `"true"` if `eval()` is present in the script.
pub const JS_CONTAINS_EVAL: &str = "js.contains_eval";

/// Finding meta: `"true"` if `unescape()` is present in the script.
pub const JS_CONTAINS_UNESCAPE: &str = "js.contains_unescape";

/// Finding meta: `"true"` if `String.fromCharCode()` is present in the script.
pub const JS_CONTAINS_FROMCHARCODE: &str = "js.contains_fromcharcode";

/// Finding meta: `"true"` if the static analyser suspects obfuscation.
pub const JS_OBFUSCATION_SUSPECTED: &str = "js.obfuscation_suspected";

/// Finding meta: `"true"` if the script calls suspicious Acrobat APIs.
pub const JS_SUSPICIOUS_APIS: &str = "js.suspicious_apis";

/// Finding meta: `"true"` if regex-based packing patterns are detected.
pub const JS_REGEX_PACKING: &str = "js.regex_packing";

/// Finding meta: string-concatenation density (float string, e.g. `"0.045"`).
pub const JS_STRING_CONCAT_DENSITY: &str = "js.string_concat_density";

/// Finding meta: escape-sequence density (float string, e.g. `"0.12"`).
pub const JS_ESCAPE_DENSITY: &str = "js.escape_density";

/// Finding meta: Shannon entropy of the script payload (float string).
pub const JS_ENTROPY: &str = "js.entropy";

/// Finding meta: comma-separated list of domain literals found in the AST.
pub const JS_AST_DOMAINS: &str = "js.ast_domains";

/// Finding meta: comma-separated list of URL literals found in the AST.
pub const JS_AST_URLS: &str = "js.ast_urls";

/// Finding meta: call argument preview strings from the AST.
pub const JS_AST_CALL_ARGS: &str = "js.ast_call_args";

// ── URI / network keys ───────────────────────────────────────────────────────

/// Finding meta / chain note: computed URI risk score (u32 as string).
pub const URI_RISK_SCORE: &str = "uri.risk_score";

// ── Structural analysis keys ─────────────────────────────────────────────────

/// Chain note: count of structural anomaly findings (usize as string).
pub const STRUCTURAL_SUSPICIOUS_COUNT: &str = "structural.suspicious_count";

/// Chain note / finding meta: `"true"` if taint analysis flagged the chain.
pub const TAINT_FLAGGED: &str = "taint.flagged";

// ── Intent classification keys ───────────────────────────────────────────────

/// Finding meta: intent bucket label assigned during intent analysis.
pub const INTENT_BUCKET: &str = "intent.bucket";

/// Finding meta: intent confidence label assigned during intent analysis.
pub const INTENT_CONFIDENCE: &str = "intent.confidence";

// ── Payload preview keys ─────────────────────────────────────────────────────

/// Finding meta: short ASCII preview of the raw payload bytes.
pub const PAYLOAD_PREVIEW: &str = "payload.preview";

/// Finding meta: short ASCII preview of the decoded payload bytes.
pub const PAYLOAD_DECODED_PREVIEW: &str = "payload.decoded_preview";

// ── Image / font object provenance keys ──────────────────────────────────────

/// Finding meta: object provenance label for the image object.
pub const IMAGE_OBJECT_PROVENANCE: &str = "image.object_provenance";

/// Finding meta: number of shadowed revisions for a font object (usize as string).
pub const FONT_OBJECT_SHADOWED_REVISIONS: &str = "font.object_shadowed_revisions";

/// Finding meta: `"true"` if the image object has an xref conflict signal.
pub const IMAGE_XREF_CONFLICT_SIGNAL: &str = "image.xref_conflict_signal";

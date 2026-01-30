// Extended Feature Vector with 388 features
//
// Expands from 76 to 388 features by incorporating all detector findings:
// - Legacy features (76): General, Structural, Behavioral, Content, Graph, Images
// - Attack surface distribution (13)
// - Severity distribution (15)
// - Confidence distribution (9)
// - Finding presence/counts (142: 71 binary + 71 counts)
// - JS signals (30)
// - URI signals (28)
// - Content signals (15)
// - Supply chain signals (10)
// - Structural anomaly signals (20)
// - Crypto signals (10)
// - Embedded content signals (15)
//
// Total: 76 + 312 = 388 features

use crate::features::FeatureVector;
use crate::model::{AttackSurface, Confidence, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Extended feature vector with 388 features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedFeatureVector {
    /// Legacy features (76)
    pub legacy: FeatureVector,

    /// Attack surface distribution (13 features)
    pub attack_surfaces: AttackSurfaceFeatures,

    /// Severity distribution (15 features)
    pub severity_dist: SeverityFeatures,

    /// Confidence distribution (9 features)
    pub confidence_dist: ConfidenceFeatures,

    /// Finding presence (71 binary features)
    pub finding_presence: FindingPresenceFeatures,

    /// Finding counts (71 count features)
    pub finding_counts: FindingCountFeatures,

    /// JavaScript-specific signals (30 features)
    pub js_signals: JsSignalFeatures,

    /// URI-specific signals (28 features)
    pub uri_signals: UriSignalFeatures,

    /// Content analysis signals (15 features)
    pub content_signals: ContentSignalFeatures,

    /// Supply chain signals (10 features)
    pub supply_chain: SupplyChainFeatures,

    /// Structural anomaly signals (20 features)
    pub structural_anomalies: StructuralAnomalyFeatures,

    /// Cryptographic signals (10 features)
    pub crypto_signals: CryptoFeatures,

    /// Embedded content signals (15 features)
    pub embedded_content: EmbeddedContentFeatures,
}

impl ExtendedFeatureVector {
    /// Convert to flat f32 vector (388 features)
    pub fn as_f32_vec(&self) -> Vec<f32> {
        let mut vec = self.legacy.as_f32_vec();
        vec.extend(self.attack_surfaces.as_f32_vec());
        vec.extend(self.severity_dist.as_f32_vec());
        vec.extend(self.confidence_dist.as_f32_vec());
        vec.extend(self.finding_presence.as_f32_vec());
        vec.extend(self.finding_counts.as_f32_vec());
        vec.extend(self.js_signals.as_f32_vec());
        vec.extend(self.uri_signals.as_f32_vec());
        vec.extend(self.content_signals.as_f32_vec());
        vec.extend(self.supply_chain.as_f32_vec());
        vec.extend(self.structural_anomalies.as_f32_vec());
        vec.extend(self.crypto_signals.as_f32_vec());
        vec.extend(self.embedded_content.as_f32_vec());
        vec
    }

    /// Create extended feature vector from legacy feature vector
    /// All extended features will be zero (use extract_extended_features for full extraction)
    pub fn from_legacy(legacy: crate::features::FeatureVector) -> Self {
        Self {
            legacy,
            attack_surfaces: AttackSurfaceFeatures::default(),
            severity_dist: SeverityFeatures::default(),
            confidence_dist: ConfidenceFeatures::default(),
            finding_presence: FindingPresenceFeatures::default(),
            finding_counts: FindingCountFeatures::default(),
            js_signals: JsSignalFeatures::default(),
            uri_signals: UriSignalFeatures::default(),
            content_signals: ContentSignalFeatures::default(),
            supply_chain: SupplyChainFeatures::default(),
            structural_anomalies: StructuralAnomalyFeatures::default(),
            crypto_signals: CryptoFeatures::default(),
            embedded_content: EmbeddedContentFeatures::default(),
        }
    }

    /// Get feature names (388 names)
    pub fn feature_names() -> Vec<String> {
        let mut names = crate::features::feature_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        names.extend(AttackSurfaceFeatures::feature_names());
        names.extend(SeverityFeatures::feature_names());
        names.extend(ConfidenceFeatures::feature_names());
        names.extend(FindingPresenceFeatures::feature_names());
        names.extend(FindingCountFeatures::feature_names());
        names.extend(JsSignalFeatures::feature_names());
        names.extend(UriSignalFeatures::feature_names());
        names.extend(ContentSignalFeatures::feature_names());
        names.extend(SupplyChainFeatures::feature_names());
        names.extend(StructuralAnomalyFeatures::feature_names());
        names.extend(CryptoFeatures::feature_names());
        names.extend(EmbeddedContentFeatures::feature_names());
        names
    }

    /// Convert to named map (feature_name -> value)
    pub fn to_named_map(&self) -> HashMap<String, f32> {
        Self::feature_names()
            .into_iter()
            .zip(self.as_f32_vec())
            .collect()
    }
}

impl Default for ExtendedFeatureVector {
    fn default() -> Self {
        Self {
            legacy: FeatureVector {
                general: Default::default(),
                structural: Default::default(),
                behavioral: Default::default(),
                content: Default::default(),
                graph: Default::default(),
                images: Default::default(),
                xfa: Default::default(),
                encryption: Default::default(),
                filters: Default::default(),
            },
            attack_surfaces: Default::default(),
            severity_dist: Default::default(),
            confidence_dist: Default::default(),
            finding_presence: Default::default(),
            finding_counts: Default::default(),
            js_signals: Default::default(),
            uri_signals: Default::default(),
            content_signals: Default::default(),
            supply_chain: Default::default(),
            structural_anomalies: Default::default(),
            crypto_signals: Default::default(),
            embedded_content: Default::default(),
        }
    }
}

// ============================================================================
// Attack Surface Distribution (12 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackSurfaceFeatures {
    pub file_structure_count: f32,
    pub xref_trailer_count: f32,
    pub object_streams_count: f32,
    pub streams_filters_count: f32,
    pub actions_count: f32,
    pub javascript_count: f32,
    pub forms_count: f32,
    pub embedded_files_count: f32,
    pub richmedia_3d_count: f32,
    pub images_count: f32,
    pub crypto_signatures_count: f32,
    pub metadata_count: f32,
    pub content_phishing_count: f32,
}

impl AttackSurfaceFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.file_structure_count,
            self.xref_trailer_count,
            self.object_streams_count,
            self.streams_filters_count,
            self.actions_count,
            self.javascript_count,
            self.forms_count,
            self.embedded_files_count,
            self.richmedia_3d_count,
            self.images_count,
            self.crypto_signatures_count,
            self.metadata_count,
            self.content_phishing_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "attack_surfaces.file_structure_count",
            "attack_surfaces.xref_trailer_count",
            "attack_surfaces.object_streams_count",
            "attack_surfaces.streams_filters_count",
            "attack_surfaces.actions_count",
            "attack_surfaces.javascript_count",
            "attack_surfaces.forms_count",
            "attack_surfaces.embedded_files_count",
            "attack_surfaces.richmedia_3d_count",
            "attack_surfaces.images_count",
            "attack_surfaces.crypto_signatures_count",
            "attack_surfaces.metadata_count",
            "attack_surfaces.content_phishing_count",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Severity Distribution (15 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeverityFeatures {
    pub total_critical: f32,
    pub total_high: f32,
    pub total_medium: f32,
    pub total_low: f32,
    pub total_info: f32,
    pub max_severity_score: f32,
    pub avg_severity_score: f32,
    pub weighted_severity: f32,
    pub max_severity_actions: f32,
    pub max_severity_javascript: f32,
    pub max_severity_streams: f32,
    pub max_severity_embedded: f32,
    pub max_severity_structural: f32,
    pub max_severity_forms: f32,
    pub max_severity_crypto: f32,
}

impl SeverityFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.total_critical,
            self.total_high,
            self.total_medium,
            self.total_low,
            self.total_info,
            self.max_severity_score,
            self.avg_severity_score,
            self.weighted_severity,
            self.max_severity_actions,
            self.max_severity_javascript,
            self.max_severity_streams,
            self.max_severity_embedded,
            self.max_severity_structural,
            self.max_severity_forms,
            self.max_severity_crypto,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "severity_dist.total_critical",
            "severity_dist.total_high",
            "severity_dist.total_medium",
            "severity_dist.total_low",
            "severity_dist.total_info",
            "severity_dist.max_severity_score",
            "severity_dist.avg_severity_score",
            "severity_dist.weighted_severity",
            "severity_dist.max_severity_actions",
            "severity_dist.max_severity_javascript",
            "severity_dist.max_severity_streams",
            "severity_dist.max_severity_embedded",
            "severity_dist.max_severity_structural",
            "severity_dist.max_severity_forms",
            "severity_dist.max_severity_crypto",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Confidence Distribution (9 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfidenceFeatures {
    pub strong_count: f32,
    pub probable_count: f32,
    pub heuristic_count: f32,
    pub strong_ratio: f32,
    pub avg_confidence_score: f32,
    pub strong_high_severity: f32,
    pub probable_high_severity: f32,
    pub heuristic_high_severity: f32,
    pub weighted_confidence: f32,
}

impl ConfidenceFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.strong_count,
            self.probable_count,
            self.heuristic_count,
            self.strong_ratio,
            self.avg_confidence_score,
            self.strong_high_severity,
            self.probable_high_severity,
            self.heuristic_high_severity,
            self.weighted_confidence,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "confidence_dist.strong_count",
            "confidence_dist.probable_count",
            "confidence_dist.heuristic_count",
            "confidence_dist.strong_ratio",
            "confidence_dist.avg_confidence_score",
            "confidence_dist.strong_high_severity",
            "confidence_dist.probable_high_severity",
            "confidence_dist.heuristic_high_severity",
            "confidence_dist.weighted_confidence",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Finding Presence (71 binary features - one per finding type)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingPresenceFeatures {
    // File structure (10)
    pub xref_conflict: f32,
    pub incremental_update_chain: f32,
    pub object_id_shadowing: f32,
    pub polyglot_signature_conflict: f32,
    pub missing_pdf_header: f32,
    pub missing_eof_marker: f32,
    pub eof_offset_unusual: f32,
    pub header_offset_unusual: f32,
    pub linearization_invalid: f32,
    pub linearization_multiple: f32,

    // Object streams (5)
    pub objstm_density_high: f32,
    pub objstm_embedded_summary: f32,
    pub objstm_action_chain: f32,
    pub orphan_payload_object: f32,
    pub shadow_payload_chain: f32,

    // Streams/filters (6)
    pub decoder_risk_present: f32,
    pub decompression_ratio_suspicious: f32,
    pub filter_chain_depth_high: f32,
    pub huge_image_dimensions: f32,
    pub stream_length_mismatch: f32,
    pub icc_profile_oversized: f32,

    // Actions (8)
    pub open_action_present: f32,
    pub aa_present: f32,
    pub aa_event_present: f32,
    pub launch_action_present: f32,
    pub gotor_present: f32,
    pub uri_present: f32,
    pub submitform_present: f32,
    pub external_action_risk_context: f32,

    // JavaScript (10)
    pub js_present: f32,
    pub js_polymorphic: f32,
    pub js_obfuscation_deep: f32,
    pub js_time_evasion: f32,
    pub js_env_probe: f32,
    pub js_multi_stage_decode: f32,
    pub js_runtime_file_probe: f32,
    pub js_runtime_network_intent: f32,
    pub crypto_mining_js: f32,
    pub js_sandbox_result: f32,

    // URI classification (3)
    pub uri_content_analysis: f32,
    pub uri_presence_summary: f32,
    pub action_payload_path: f32,

    // Forms (2)
    pub acroform_present: f32,
    pub xfa_present: f32,

    // Embedded content (7)
    pub embedded_file_present: f32,
    pub richmedia_present: f32,
    pub three_d_present: f32,
    pub sound_movie_present: f32,
    pub filespec_present: f32,
    pub font_payload_present: f32,
    pub fontmatrix_payload_present: f32,

    // Crypto/signatures (5)
    pub encryption_present: f32,
    pub signature_present: f32,
    pub dss_present: f32,
    pub crypto_weak_algo: f32,
    pub quantum_vulnerable_crypto: f32,

    // Content analysis (6)
    pub content_phishing: f32,
    pub content_html_payload: f32,
    pub content_invisible_text: f32,
    pub content_overlay_link: f32,
    pub content_image_only_page: f32,
    pub annotation_hidden: f32,

    // Annotations (3)
    pub annotation_action_chain: f32,
    pub annotation_attack: f32,
    pub ocg_present: f32,

    // Page tree (3)
    pub page_tree_cycle: f32,
    pub page_tree_mismatch: f32,
    pub page_tree_manipulation: f32,

    // Supply chain (3)
    pub supply_chain_persistence: f32,
    pub supply_chain_staged_payload: f32,
    pub supply_chain_update_vector: f32,
}

impl FindingPresenceFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.xref_conflict,
            self.incremental_update_chain,
            self.object_id_shadowing,
            self.polyglot_signature_conflict,
            self.missing_pdf_header,
            self.missing_eof_marker,
            self.eof_offset_unusual,
            self.header_offset_unusual,
            self.linearization_invalid,
            self.linearization_multiple,
            self.objstm_density_high,
            self.objstm_embedded_summary,
            self.objstm_action_chain,
            self.orphan_payload_object,
            self.shadow_payload_chain,
            self.decoder_risk_present,
            self.decompression_ratio_suspicious,
            self.filter_chain_depth_high,
            self.huge_image_dimensions,
            self.stream_length_mismatch,
            self.icc_profile_oversized,
            self.open_action_present,
            self.aa_present,
            self.aa_event_present,
            self.launch_action_present,
            self.gotor_present,
            self.uri_present,
            self.submitform_present,
            self.external_action_risk_context,
            self.js_present,
            self.js_polymorphic,
            self.js_obfuscation_deep,
            self.js_time_evasion,
            self.js_env_probe,
            self.js_multi_stage_decode,
            self.js_runtime_file_probe,
            self.js_runtime_network_intent,
            self.crypto_mining_js,
            self.js_sandbox_result,
            self.uri_content_analysis,
            self.uri_presence_summary,
            self.action_payload_path,
            self.acroform_present,
            self.xfa_present,
            self.embedded_file_present,
            self.richmedia_present,
            self.three_d_present,
            self.sound_movie_present,
            self.filespec_present,
            self.font_payload_present,
            self.fontmatrix_payload_present,
            self.encryption_present,
            self.signature_present,
            self.dss_present,
            self.crypto_weak_algo,
            self.quantum_vulnerable_crypto,
            self.content_phishing,
            self.content_html_payload,
            self.content_invisible_text,
            self.content_overlay_link,
            self.content_image_only_page,
            self.annotation_hidden,
            self.annotation_action_chain,
            self.annotation_attack,
            self.ocg_present,
            self.page_tree_cycle,
            self.page_tree_mismatch,
            self.page_tree_manipulation,
            self.supply_chain_persistence,
            self.supply_chain_staged_payload,
            self.supply_chain_update_vector,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "finding.xref_conflict",
            "finding.incremental_update_chain",
            "finding.object_id_shadowing",
            "finding.polyglot_signature_conflict",
            "finding.missing_pdf_header",
            "finding.missing_eof_marker",
            "finding.eof_offset_unusual",
            "finding.header_offset_unusual",
            "finding.linearization_invalid",
            "finding.linearization_multiple",
            "finding.objstm_density_high",
            "finding.objstm_embedded_summary",
            "finding.objstm_action_chain",
            "finding.orphan_payload_object",
            "finding.shadow_payload_chain",
            "finding.decoder_risk_present",
            "finding.decompression_ratio_suspicious",
            "finding.filter_chain_depth_high",
            "finding.huge_image_dimensions",
            "finding.stream_length_mismatch",
            "finding.icc_profile_oversized",
            "finding.open_action_present",
            "finding.aa_present",
            "finding.aa_event_present",
            "finding.launch_action_present",
            "finding.gotor_present",
            "finding.uri_present",
            "finding.submitform_present",
            "finding.external_action_risk_context",
            "finding.js_present",
            "finding.js_polymorphic",
            "finding.js_obfuscation_deep",
            "finding.js_time_evasion",
            "finding.js_env_probe",
            "finding.js_multi_stage_decode",
            "finding.js_runtime_file_probe",
            "finding.js_runtime_network_intent",
            "finding.crypto_mining_js",
            "finding.js_sandbox_result",
            "finding.uri_content_analysis",
            "finding.uri_presence_summary",
            "finding.action_payload_path",
            "finding.acroform_present",
            "finding.xfa_present",
            "finding.embedded_file_present",
            "finding.richmedia_present",
            "finding.three_d_present",
            "finding.sound_movie_present",
            "finding.filespec_present",
            "finding.font_payload_present",
            "finding.fontmatrix_payload_present",
            "finding.encryption_present",
            "finding.signature_present",
            "finding.dss_present",
            "finding.crypto_weak_algo",
            "finding.quantum_vulnerable_crypto",
            "finding.content_phishing",
            "finding.content_html_payload",
            "finding.content_invisible_text",
            "finding.content_overlay_link",
            "finding.content_image_only_page",
            "finding.annotation_hidden",
            "finding.annotation_action_chain",
            "finding.annotation_attack",
            "finding.ocg_present",
            "finding.page_tree_cycle",
            "finding.page_tree_mismatch",
            "finding.page_tree_manipulation",
            "finding.supply_chain_persistence",
            "finding.supply_chain_staged_payload",
            "finding.supply_chain_update_vector",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Finding Counts (70 count features - same as presence but counts)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingCountFeatures {
    // Same structure as FindingPresenceFeatures
    // (counts instead of binary flags)
    pub xref_conflict_count: f32,
    pub incremental_update_chain_count: f32,
    pub object_id_shadowing_count: f32,
    pub polyglot_signature_conflict_count: f32,
    pub missing_pdf_header_count: f32,
    pub missing_eof_marker_count: f32,
    pub eof_offset_unusual_count: f32,
    pub header_offset_unusual_count: f32,
    pub linearization_invalid_count: f32,
    pub linearization_multiple_count: f32,
    pub objstm_density_high_count: f32,
    pub objstm_embedded_summary_count: f32,
    pub objstm_action_chain_count: f32,
    pub orphan_payload_object_count: f32,
    pub shadow_payload_chain_count: f32,
    pub decoder_risk_present_count: f32,
    pub decompression_ratio_suspicious_count: f32,
    pub filter_chain_depth_high_count: f32,
    pub huge_image_dimensions_count: f32,
    pub stream_length_mismatch_count: f32,
    pub icc_profile_oversized_count: f32,
    pub open_action_present_count: f32,
    pub aa_present_count: f32,
    pub aa_event_present_count: f32,
    pub launch_action_present_count: f32,
    pub gotor_present_count: f32,
    pub uri_present_count: f32,
    pub submitform_present_count: f32,
    pub external_action_risk_context_count: f32,
    pub js_present_count: f32,
    pub js_polymorphic_count: f32,
    pub js_obfuscation_deep_count: f32,
    pub js_time_evasion_count: f32,
    pub js_env_probe_count: f32,
    pub js_multi_stage_decode_count: f32,
    pub js_runtime_file_probe_count: f32,
    pub js_runtime_network_intent_count: f32,
    pub crypto_mining_js_count: f32,
    pub js_sandbox_result_count: f32,
    pub uri_content_analysis_count: f32,
    pub uri_presence_summary_count: f32,
    pub action_payload_path_count: f32,
    pub acroform_present_count: f32,
    pub xfa_present_count: f32,
    pub embedded_file_present_count: f32,
    pub richmedia_present_count: f32,
    pub three_d_present_count: f32,
    pub sound_movie_present_count: f32,
    pub filespec_present_count: f32,
    pub font_payload_present_count: f32,
    pub fontmatrix_payload_present_count: f32,
    pub encryption_present_count: f32,
    pub signature_present_count: f32,
    pub dss_present_count: f32,
    pub crypto_weak_algo_count: f32,
    pub quantum_vulnerable_crypto_count: f32,
    pub content_phishing_count: f32,
    pub content_html_payload_count: f32,
    pub content_invisible_text_count: f32,
    pub content_overlay_link_count: f32,
    pub content_image_only_page_count: f32,
    pub annotation_hidden_count: f32,
    pub annotation_action_chain_count: f32,
    pub annotation_attack_count: f32,
    pub ocg_present_count: f32,
    pub page_tree_cycle_count: f32,
    pub page_tree_mismatch_count: f32,
    pub page_tree_manipulation_count: f32,
    pub supply_chain_persistence_count: f32,
    pub supply_chain_staged_payload_count: f32,
    pub supply_chain_update_vector_count: f32,
}

impl FindingCountFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.xref_conflict_count,
            self.incremental_update_chain_count,
            self.object_id_shadowing_count,
            self.polyglot_signature_conflict_count,
            self.missing_pdf_header_count,
            self.missing_eof_marker_count,
            self.eof_offset_unusual_count,
            self.header_offset_unusual_count,
            self.linearization_invalid_count,
            self.linearization_multiple_count,
            self.objstm_density_high_count,
            self.objstm_embedded_summary_count,
            self.objstm_action_chain_count,
            self.orphan_payload_object_count,
            self.shadow_payload_chain_count,
            self.decoder_risk_present_count,
            self.decompression_ratio_suspicious_count,
            self.filter_chain_depth_high_count,
            self.huge_image_dimensions_count,
            self.stream_length_mismatch_count,
            self.icc_profile_oversized_count,
            self.open_action_present_count,
            self.aa_present_count,
            self.aa_event_present_count,
            self.launch_action_present_count,
            self.gotor_present_count,
            self.uri_present_count,
            self.submitform_present_count,
            self.external_action_risk_context_count,
            self.js_present_count,
            self.js_polymorphic_count,
            self.js_obfuscation_deep_count,
            self.js_time_evasion_count,
            self.js_env_probe_count,
            self.js_multi_stage_decode_count,
            self.js_runtime_file_probe_count,
            self.js_runtime_network_intent_count,
            self.crypto_mining_js_count,
            self.js_sandbox_result_count,
            self.uri_content_analysis_count,
            self.uri_presence_summary_count,
            self.action_payload_path_count,
            self.acroform_present_count,
            self.xfa_present_count,
            self.embedded_file_present_count,
            self.richmedia_present_count,
            self.three_d_present_count,
            self.sound_movie_present_count,
            self.filespec_present_count,
            self.font_payload_present_count,
            self.fontmatrix_payload_present_count,
            self.encryption_present_count,
            self.signature_present_count,
            self.dss_present_count,
            self.crypto_weak_algo_count,
            self.quantum_vulnerable_crypto_count,
            self.content_phishing_count,
            self.content_html_payload_count,
            self.content_invisible_text_count,
            self.content_overlay_link_count,
            self.content_image_only_page_count,
            self.annotation_hidden_count,
            self.annotation_action_chain_count,
            self.annotation_attack_count,
            self.ocg_present_count,
            self.page_tree_cycle_count,
            self.page_tree_mismatch_count,
            self.page_tree_manipulation_count,
            self.supply_chain_persistence_count,
            self.supply_chain_staged_payload_count,
            self.supply_chain_update_vector_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "finding_count.xref_conflict",
            "finding_count.incremental_update_chain",
            "finding_count.object_id_shadowing",
            "finding_count.polyglot_signature_conflict",
            "finding_count.missing_pdf_header",
            "finding_count.missing_eof_marker",
            "finding_count.eof_offset_unusual",
            "finding_count.header_offset_unusual",
            "finding_count.linearization_invalid",
            "finding_count.linearization_multiple",
            "finding_count.objstm_density_high",
            "finding_count.objstm_embedded_summary",
            "finding_count.objstm_action_chain",
            "finding_count.orphan_payload_object",
            "finding_count.shadow_payload_chain",
            "finding_count.decoder_risk_present",
            "finding_count.decompression_ratio_suspicious",
            "finding_count.filter_chain_depth_high",
            "finding_count.huge_image_dimensions",
            "finding_count.stream_length_mismatch",
            "finding_count.icc_profile_oversized",
            "finding_count.open_action_present",
            "finding_count.aa_present",
            "finding_count.aa_event_present",
            "finding_count.launch_action_present",
            "finding_count.gotor_present",
            "finding_count.uri_present",
            "finding_count.submitform_present",
            "finding_count.external_action_risk_context",
            "finding_count.js_present",
            "finding_count.js_polymorphic",
            "finding_count.js_obfuscation_deep",
            "finding_count.js_time_evasion",
            "finding_count.js_env_probe",
            "finding_count.js_multi_stage_decode",
            "finding_count.js_runtime_file_probe",
            "finding_count.js_runtime_network_intent",
            "finding_count.crypto_mining_js",
            "finding_count.js_sandbox_result",
            "finding_count.uri_content_analysis",
            "finding_count.uri_presence_summary",
            "finding_count.action_payload_path",
            "finding_count.acroform_present",
            "finding_count.xfa_present",
            "finding_count.embedded_file_present",
            "finding_count.richmedia_present",
            "finding_count.three_d_present",
            "finding_count.sound_movie_present",
            "finding_count.filespec_present",
            "finding_count.font_payload_present",
            "finding_count.fontmatrix_payload_present",
            "finding_count.encryption_present",
            "finding_count.signature_present",
            "finding_count.dss_present",
            "finding_count.crypto_weak_algo",
            "finding_count.quantum_vulnerable_crypto",
            "finding_count.content_phishing",
            "finding_count.content_html_payload",
            "finding_count.content_invisible_text",
            "finding_count.content_overlay_link",
            "finding_count.content_image_only_page",
            "finding_count.annotation_hidden",
            "finding_count.annotation_action_chain",
            "finding_count.annotation_attack",
            "finding_count.ocg_present",
            "finding_count.page_tree_cycle",
            "finding_count.page_tree_mismatch",
            "finding_count.page_tree_manipulation",
            "finding_count.supply_chain_persistence",
            "finding_count.supply_chain_staged_payload",
            "finding_count.supply_chain_update_vector",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// JavaScript Signals (30 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JsSignalFeatures {
    pub max_obfuscation_score: f32,
    pub avg_obfuscation_score: f32,
    pub total_eval_count: f32,
    pub max_eval_count: f32,
    pub unique_suspicious_apis: f32,
    pub max_string_concat_layers: f32,
    pub max_unescape_layers: f32,
    pub max_decode_ratio: f32,
    pub avg_entropy: f32,
    pub max_entropy: f32,
    pub time_evasion_present: f32,
    pub env_probe_present: f32,
    pub polymorphic_present: f32,
    pub multi_stage_decode: f32,
    pub sandbox_executed: f32,
    pub sandbox_timeout: f32,
    pub runtime_file_probe: f32,
    pub runtime_network_intent: f32,
    pub crypto_mining_detected: f32,
    pub total_js_objects: f32,
    pub max_js_size: f32,
    pub avg_js_size: f32,
    pub js_in_openaction: f32,
    pub js_in_aa: f32,
    pub js_in_annotation: f32,
    pub js_in_field: f32,
    pub fromcharcode_count: f32,
    pub multiple_keys_present: f32,
    pub ref_chain_depth: f32,
    pub array_fragment_count: f32,
}

impl JsSignalFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.max_obfuscation_score,
            self.avg_obfuscation_score,
            self.total_eval_count,
            self.max_eval_count,
            self.unique_suspicious_apis,
            self.max_string_concat_layers,
            self.max_unescape_layers,
            self.max_decode_ratio,
            self.avg_entropy,
            self.max_entropy,
            self.time_evasion_present,
            self.env_probe_present,
            self.polymorphic_present,
            self.multi_stage_decode,
            self.sandbox_executed,
            self.sandbox_timeout,
            self.runtime_file_probe,
            self.runtime_network_intent,
            self.crypto_mining_detected,
            self.total_js_objects,
            self.max_js_size,
            self.avg_js_size,
            self.js_in_openaction,
            self.js_in_aa,
            self.js_in_annotation,
            self.js_in_field,
            self.fromcharcode_count,
            self.multiple_keys_present,
            self.ref_chain_depth,
            self.array_fragment_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "js_signals.max_obfuscation_score",
            "js_signals.avg_obfuscation_score",
            "js_signals.total_eval_count",
            "js_signals.max_eval_count",
            "js_signals.unique_suspicious_apis",
            "js_signals.max_string_concat_layers",
            "js_signals.max_unescape_layers",
            "js_signals.max_decode_ratio",
            "js_signals.avg_entropy",
            "js_signals.max_entropy",
            "js_signals.time_evasion_present",
            "js_signals.env_probe_present",
            "js_signals.polymorphic_present",
            "js_signals.multi_stage_decode",
            "js_signals.sandbox_executed",
            "js_signals.sandbox_timeout",
            "js_signals.runtime_file_probe",
            "js_signals.runtime_network_intent",
            "js_signals.crypto_mining_detected",
            "js_signals.total_js_objects",
            "js_signals.max_js_size",
            "js_signals.avg_js_size",
            "js_signals.js_in_openaction",
            "js_signals.js_in_aa",
            "js_signals.js_in_annotation",
            "js_signals.js_in_field",
            "js_signals.fromcharcode_count",
            "js_signals.multiple_keys_present",
            "js_signals.ref_chain_depth",
            "js_signals.array_fragment_count",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// URI Signals (28 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UriSignalFeatures {
    pub total_count: f32,
    pub unique_domains: f32,
    pub max_risk_score: f32,
    pub avg_risk_score: f32,
    pub javascript_uri_count: f32,
    pub file_uri_count: f32,
    pub data_uri_count: f32,
    pub http_count: f32,
    pub https_count: f32,
    pub ip_address_count: f32,
    pub suspicious_tld_count: f32,
    pub obfuscated_count: f32,
    pub data_exfil_pattern_count: f32,
    pub data_base64_count: f32,
    pub hidden_annotation_count: f32,
    pub automatic_trigger_count: f32,
    pub js_triggered_count: f32,
    pub tracking_params_count: f32,
    pub max_url_length: f32,
    pub phishing_indicators: f32,
    pub shortener_domain_count: f32,
    pub suspicious_extension_count: f32,
    pub suspicious_scheme_count: f32,
    pub embedded_ip_host_count: f32,
    pub idn_lookalike_count: f32,
    pub non_standard_port_count: f32,
    pub external_dependency_count: f32,
    pub mixed_content_present: f32,
}

impl UriSignalFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.total_count,
            self.unique_domains,
            self.max_risk_score,
            self.avg_risk_score,
            self.javascript_uri_count,
            self.file_uri_count,
            self.data_uri_count,
            self.http_count,
            self.https_count,
            self.ip_address_count,
            self.suspicious_tld_count,
            self.obfuscated_count,
            self.data_exfil_pattern_count,
            self.data_base64_count,
            self.hidden_annotation_count,
            self.automatic_trigger_count,
            self.js_triggered_count,
            self.tracking_params_count,
            self.max_url_length,
            self.phishing_indicators,
            self.shortener_domain_count,
            self.suspicious_extension_count,
            self.suspicious_scheme_count,
            self.embedded_ip_host_count,
            self.idn_lookalike_count,
            self.non_standard_port_count,
            self.external_dependency_count,
            self.mixed_content_present,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "uri_signals.total_count",
            "uri_signals.unique_domains",
            "uri_signals.max_risk_score",
            "uri_signals.avg_risk_score",
            "uri_signals.javascript_uri_count",
            "uri_signals.file_uri_count",
            "uri_signals.data_uri_count",
            "uri_signals.http_count",
            "uri_signals.https_count",
            "uri_signals.ip_address_count",
            "uri_signals.suspicious_tld_count",
            "uri_signals.obfuscated_count",
            "uri_signals.data_exfil_pattern_count",
            "uri_signals.data_base64_count",
            "uri_signals.hidden_annotation_count",
            "uri_signals.automatic_trigger_count",
            "uri_signals.js_triggered_count",
            "uri_signals.tracking_params_count",
            "uri_signals.max_url_length",
            "uri_signals.phishing_indicators",
            "uri_signals.shortener_domain_count",
            "uri_signals.suspicious_extension_count",
            "uri_signals.suspicious_scheme_count",
            "uri_signals.embedded_ip_host_count",
            "uri_signals.idn_lookalike_count",
            "uri_signals.non_standard_port_count",
            "uri_signals.external_dependency_count",
            "uri_signals.mixed_content_present",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Content Signals (15 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentSignalFeatures {
    pub phishing_indicators: f32,
    pub invisible_text_pages: f32,
    pub overlay_link_count: f32,
    pub image_only_pages: f32,
    pub html_payload_present: f32,
    pub hidden_annotation_count: f32,
    pub suspicious_font_count: f32,
    pub text_rendering_anomalies: f32,
    pub color_manipulation_count: f32,
    pub whitespace_abuse_count: f32,
    pub unicode_rtlo_count: f32,
    pub homoglyph_count: f32,
    pub zero_width_char_count: f32,
    pub text_direction_abuse: f32,
    pub layer_manipulation_count: f32,
}

impl ContentSignalFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.phishing_indicators,
            self.invisible_text_pages,
            self.overlay_link_count,
            self.image_only_pages,
            self.html_payload_present,
            self.hidden_annotation_count,
            self.suspicious_font_count,
            self.text_rendering_anomalies,
            self.color_manipulation_count,
            self.whitespace_abuse_count,
            self.unicode_rtlo_count,
            self.homoglyph_count,
            self.zero_width_char_count,
            self.text_direction_abuse,
            self.layer_manipulation_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "content_signals.phishing_indicators",
            "content_signals.invisible_text_pages",
            "content_signals.overlay_link_count",
            "content_signals.image_only_pages",
            "content_signals.html_payload_present",
            "content_signals.hidden_annotation_count",
            "content_signals.suspicious_font_count",
            "content_signals.text_rendering_anomalies",
            "content_signals.color_manipulation_count",
            "content_signals.whitespace_abuse_count",
            "content_signals.unicode_rtlo_count",
            "content_signals.homoglyph_count",
            "content_signals.zero_width_char_count",
            "content_signals.text_direction_abuse",
            "content_signals.layer_manipulation_count",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Supply Chain Signals (10 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SupplyChainFeatures {
    pub persistence_mechanisms: f32,
    pub staged_payload_count: f32,
    pub update_vectors: f32,
    pub multi_stage_chains: f32,
    pub command_control_indicators: f32,
    pub lateral_movement_indicators: f32,
    pub data_staging_indicators: f32,
    pub exfiltration_indicators: f32,
    pub anti_forensics_techniques: f32,
    pub defense_evasion_count: f32,
}

impl SupplyChainFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.persistence_mechanisms,
            self.staged_payload_count,
            self.update_vectors,
            self.multi_stage_chains,
            self.command_control_indicators,
            self.lateral_movement_indicators,
            self.data_staging_indicators,
            self.exfiltration_indicators,
            self.anti_forensics_techniques,
            self.defense_evasion_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "supply_chain.persistence_mechanisms",
            "supply_chain.staged_payload_count",
            "supply_chain.update_vectors",
            "supply_chain.multi_stage_chains",
            "supply_chain.command_control_indicators",
            "supply_chain.lateral_movement_indicators",
            "supply_chain.data_staging_indicators",
            "supply_chain.exfiltration_indicators",
            "supply_chain.anti_forensics_techniques",
            "supply_chain.defense_evasion_count",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Structural Anomaly Signals (20 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuralAnomalyFeatures {
    pub objstm_density: f32,
    pub filter_chain_max_depth: f32,
    pub decompression_max_ratio: f32,
    pub page_tree_anomalies: f32,
    pub linearization_anomalies: f32,
    pub parser_deviations: f32,
    pub xref_table_anomalies: f32,
    pub trailer_anomalies: f32,
    pub catalog_anomalies: f32,
    pub object_stream_anomalies: f32,
    pub cross_ref_stream_anomalies: f32,
    pub incremental_update_count: f32,
    pub conflicting_definitions: f32,
    pub orphaned_objects: f32,
    pub circular_references: f32,
    pub invalid_object_refs: f32,
    pub stream_dictionary_mismatch: f32,
    pub unusual_object_sizes: f32,
    pub object_id_gaps: f32,
    pub generation_number_anomalies: f32,
}

impl StructuralAnomalyFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.objstm_density,
            self.filter_chain_max_depth,
            self.decompression_max_ratio,
            self.page_tree_anomalies,
            self.linearization_anomalies,
            self.parser_deviations,
            self.xref_table_anomalies,
            self.trailer_anomalies,
            self.catalog_anomalies,
            self.object_stream_anomalies,
            self.cross_ref_stream_anomalies,
            self.incremental_update_count,
            self.conflicting_definitions,
            self.orphaned_objects,
            self.circular_references,
            self.invalid_object_refs,
            self.stream_dictionary_mismatch,
            self.unusual_object_sizes,
            self.object_id_gaps,
            self.generation_number_anomalies,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "structural_anomalies.objstm_density",
            "structural_anomalies.filter_chain_max_depth",
            "structural_anomalies.decompression_max_ratio",
            "structural_anomalies.page_tree_anomalies",
            "structural_anomalies.linearization_anomalies",
            "structural_anomalies.parser_deviations",
            "structural_anomalies.xref_table_anomalies",
            "structural_anomalies.trailer_anomalies",
            "structural_anomalies.catalog_anomalies",
            "structural_anomalies.object_stream_anomalies",
            "structural_anomalies.cross_ref_stream_anomalies",
            "structural_anomalies.incremental_update_count",
            "structural_anomalies.conflicting_definitions",
            "structural_anomalies.orphaned_objects",
            "structural_anomalies.circular_references",
            "structural_anomalies.invalid_object_refs",
            "structural_anomalies.stream_dictionary_mismatch",
            "structural_anomalies.unusual_object_sizes",
            "structural_anomalies.object_id_gaps",
            "structural_anomalies.generation_number_anomalies",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Crypto Signals (10 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoFeatures {
    pub encryption_present: f32,
    pub signature_present: f32,
    pub weak_algo_count: f32,
    pub quantum_vulnerable: f32,
    pub cert_anomalies: f32,
    pub signature_validation_failed: f32,
    pub timestamp_anomalies: f32,
    pub revocation_check_failed: f32,
    pub self_signed_cert: f32,
    pub encryption_weakness_score: f32,
}

impl CryptoFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.encryption_present,
            self.signature_present,
            self.weak_algo_count,
            self.quantum_vulnerable,
            self.cert_anomalies,
            self.signature_validation_failed,
            self.timestamp_anomalies,
            self.revocation_check_failed,
            self.self_signed_cert,
            self.encryption_weakness_score,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "crypto_signals.encryption_present",
            "crypto_signals.signature_present",
            "crypto_signals.weak_algo_count",
            "crypto_signals.quantum_vulnerable",
            "crypto_signals.cert_anomalies",
            "crypto_signals.signature_validation_failed",
            "crypto_signals.timestamp_anomalies",
            "crypto_signals.revocation_check_failed",
            "crypto_signals.self_signed_cert",
            "crypto_signals.encryption_weakness_score",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Embedded Content Signals (15 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmbeddedContentFeatures {
    pub file_count: f32,
    pub total_size: f32,
    pub max_decode_ratio: f32,
    pub pe_executable_count: f32,
    pub encrypted_container_count: f32,
    pub double_extension_count: f32,
    pub richmedia_count: f32,
    pub three_d_content_count: f32,
    pub flash_content_count: f32,
    pub suspicious_mime_types: f32,
    pub mismatched_extensions: f32,
    pub archive_count: f32,
    pub nested_archive_depth: f32,
    pub password_protected_count: f32,
    pub macro_enabled_count: f32,
}

impl EmbeddedContentFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.file_count,
            self.total_size,
            self.max_decode_ratio,
            self.pe_executable_count,
            self.encrypted_container_count,
            self.double_extension_count,
            self.richmedia_count,
            self.three_d_content_count,
            self.flash_content_count,
            self.suspicious_mime_types,
            self.mismatched_extensions,
            self.archive_count,
            self.nested_archive_depth,
            self.password_protected_count,
            self.macro_enabled_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "embedded_content.file_count",
            "embedded_content.total_size",
            "embedded_content.max_decode_ratio",
            "embedded_content.pe_executable_count",
            "embedded_content.encrypted_container_count",
            "embedded_content.double_extension_count",
            "embedded_content.richmedia_count",
            "embedded_content.three_d_content_count",
            "embedded_content.flash_content_count",
            "embedded_content.suspicious_mime_types",
            "embedded_content.mismatched_extensions",
            "embedded_content.archive_count",
            "embedded_content.nested_archive_depth",
            "embedded_content.password_protected_count",
            "embedded_content.macro_enabled_count",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }
}

// ============================================================================
// Feature Extraction Functions
// ============================================================================

use crate::scan::ScanContext;

/// Get extended feature names (388 names)
pub fn extended_feature_names() -> Vec<String> {
    let mut names = crate::features::feature_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    names.extend(AttackSurfaceFeatures::feature_names());
    names.extend(SeverityFeatures::feature_names());
    names.extend(ConfidenceFeatures::feature_names());
    names.extend(FindingPresenceFeatures::feature_names());
    names.extend(FindingCountFeatures::feature_names());
    names.extend(JsSignalFeatures::feature_names());
    names.extend(UriSignalFeatures::feature_names());
    names.extend(ContentSignalFeatures::feature_names());
    names.extend(SupplyChainFeatures::feature_names());
    names.extend(StructuralAnomalyFeatures::feature_names());
    names.extend(CryptoFeatures::feature_names());
    names.extend(EmbeddedContentFeatures::feature_names());
    names
}

/// Extract extended features from scan context and findings
pub fn extract_extended_features(ctx: &ScanContext, findings: &[Finding]) -> ExtendedFeatureVector {
    // Extract legacy features (76)
    let legacy = crate::features::FeatureExtractor::extract(ctx);

    // Extract new feature groups from findings
    let attack_surfaces = extract_attack_surface_features(findings);
    let severity_dist = extract_severity_features(findings);
    let confidence_dist = extract_confidence_features(findings);
    let (finding_presence, finding_counts) = extract_finding_features(findings);
    let js_signals = extract_js_features(findings);
    let uri_signals = extract_uri_features(findings);
    let content_signals = extract_content_features(findings);
    let supply_chain = extract_supply_chain_features(findings);
    let structural_anomalies = extract_structural_features(findings);
    let crypto_signals = extract_crypto_features(findings);
    let embedded_content = extract_embedded_features(findings);

    ExtendedFeatureVector {
        legacy,
        attack_surfaces,
        severity_dist,
        confidence_dist,
        finding_presence,
        finding_counts,
        js_signals,
        uri_signals,
        content_signals,
        supply_chain,
        structural_anomalies,
        crypto_signals,
        embedded_content,
    }
}

/// Extract attack surface distribution features
fn extract_attack_surface_features(findings: &[Finding]) -> AttackSurfaceFeatures {
    let mut features = AttackSurfaceFeatures::default();

    for finding in findings {
        let count = match finding.surface {
            AttackSurface::FileStructure => &mut features.file_structure_count,
            AttackSurface::XRefTrailer => &mut features.xref_trailer_count,
            AttackSurface::ObjectStreams => &mut features.object_streams_count,
            AttackSurface::StreamsAndFilters => &mut features.streams_filters_count,
            AttackSurface::Actions => &mut features.actions_count,
            AttackSurface::JavaScript => &mut features.javascript_count,
            AttackSurface::Forms => &mut features.forms_count,
            AttackSurface::EmbeddedFiles => &mut features.embedded_files_count,
            AttackSurface::RichMedia3D => &mut features.richmedia_3d_count,
            AttackSurface::Images => &mut features.images_count,
            AttackSurface::CryptoSignatures => &mut features.crypto_signatures_count,
            AttackSurface::Metadata => &mut features.metadata_count,
            AttackSurface::ContentPhishing => &mut features.content_phishing_count,
        };
        *count += 1.0;
    }

    features
}

/// Extract severity distribution features
fn extract_severity_features(findings: &[Finding]) -> SeverityFeatures {
    let mut features = SeverityFeatures::default();

    if findings.is_empty() {
        return features;
    }

    let mut severity_sum = 0.0;
    let mut severity_confidence_weighted = 0.0;
    let mut per_surface_severity: HashMap<AttackSurface, f32> = HashMap::new();

    for finding in findings {
        // Count by severity
        match finding.severity {
            Severity::Critical => features.total_critical += 1.0,
            Severity::High => features.total_high += 1.0,
            Severity::Medium => features.total_medium += 1.0,
            Severity::Low => features.total_low += 1.0,
            Severity::Info => features.total_info += 1.0,
        }

        // Severity score (0-4)
        let severity_score = match finding.severity {
            Severity::Critical => 4.0,
            Severity::High => 3.0,
            Severity::Medium => 2.0,
            Severity::Low => 1.0,
            Severity::Info => 0.0,
        };
        severity_sum += severity_score;

        // Confidence weight (0-1)
        let confidence_weight = match finding.confidence {
            Confidence::Strong => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Heuristic => 0.4,
        };
        severity_confidence_weighted += severity_score * confidence_weight;

        // Track max severity per surface
        let current_max = per_surface_severity
            .get(&finding.surface)
            .copied()
            .unwrap_or(0.0);
        if severity_score > current_max {
            per_surface_severity.insert(finding.surface, severity_score);
        }
    }

    features.max_severity_score = per_surface_severity.values().copied().fold(0.0, f32::max);
    features.avg_severity_score = severity_sum / findings.len() as f32;
    features.weighted_severity = severity_confidence_weighted / findings.len() as f32;

    // Per-surface max severity
    features.max_severity_actions = per_surface_severity
        .get(&AttackSurface::Actions)
        .copied()
        .unwrap_or(0.0);
    features.max_severity_javascript = per_surface_severity
        .get(&AttackSurface::JavaScript)
        .copied()
        .unwrap_or(0.0);
    features.max_severity_streams = per_surface_severity
        .get(&AttackSurface::StreamsAndFilters)
        .copied()
        .unwrap_or(0.0);
    features.max_severity_embedded = per_surface_severity
        .get(&AttackSurface::EmbeddedFiles)
        .copied()
        .unwrap_or(0.0);
    features.max_severity_structural = per_surface_severity
        .get(&AttackSurface::FileStructure)
        .copied()
        .unwrap_or(0.0);
    features.max_severity_forms = per_surface_severity
        .get(&AttackSurface::Forms)
        .copied()
        .unwrap_or(0.0);
    features.max_severity_crypto = per_surface_severity
        .get(&AttackSurface::CryptoSignatures)
        .copied()
        .unwrap_or(0.0);

    features
}

/// Extract confidence distribution features
fn extract_confidence_features(findings: &[Finding]) -> ConfidenceFeatures {
    let mut features = ConfidenceFeatures::default();

    if findings.is_empty() {
        return features;
    }

    let mut confidence_sum = 0.0;
    let mut confidence_severity_weighted = 0.0;

    for finding in findings {
        // Count by confidence
        match finding.confidence {
            Confidence::Strong => features.strong_count += 1.0,
            Confidence::Probable => features.probable_count += 1.0,
            Confidence::Heuristic => features.heuristic_count += 1.0,
        }

        // Count high-severity by confidence
        if finding.severity == Severity::High || finding.severity == Severity::Critical {
            match finding.confidence {
                Confidence::Strong => features.strong_high_severity += 1.0,
                Confidence::Probable => features.probable_high_severity += 1.0,
                Confidence::Heuristic => features.heuristic_high_severity += 1.0,
            }
        }

        // Confidence score (0-1)
        let confidence_score = match finding.confidence {
            Confidence::Strong => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Heuristic => 0.4,
        };
        confidence_sum += confidence_score;

        // Severity weight
        let severity_weight = match finding.severity {
            Severity::Critical => 4.0,
            Severity::High => 3.0,
            Severity::Medium => 2.0,
            Severity::Low => 1.0,
            Severity::Info => 0.0,
        };
        confidence_severity_weighted += confidence_score * severity_weight;
    }

    features.strong_ratio = features.strong_count / findings.len() as f32;
    features.avg_confidence_score = confidence_sum / findings.len() as f32;
    features.weighted_confidence = confidence_severity_weighted / findings.len() as f32;

    features
}

/// Extract finding presence and count features (140 features total)
fn extract_finding_features(
    findings: &[Finding],
) -> (FindingPresenceFeatures, FindingCountFeatures) {
    let mut presence = FindingPresenceFeatures::default();
    let mut counts = FindingCountFeatures::default();

    // Count occurrences of each finding kind
    let mut finding_counts_map: HashMap<&str, usize> = HashMap::new();
    for finding in findings {
        *finding_counts_map.entry(finding.kind.as_str()).or_insert(0) += 1;
    }

    // Helper macro to set both presence and count
    macro_rules! set_finding {
        ($kind:expr, $presence_field:ident, $count_field:ident) => {
            if let Some(&count) = finding_counts_map.get($kind) {
                presence.$presence_field = 1.0;
                counts.$count_field = count as f32;
            }
        };
    }

    // File structure (10)
    set_finding!("xref_conflict", xref_conflict, xref_conflict_count);
    set_finding!(
        "incremental_update_chain",
        incremental_update_chain,
        incremental_update_chain_count
    );
    set_finding!(
        "object_id_shadowing",
        object_id_shadowing,
        object_id_shadowing_count
    );
    set_finding!(
        "polyglot_signature_conflict",
        polyglot_signature_conflict,
        polyglot_signature_conflict_count
    );
    set_finding!(
        "missing_pdf_header",
        missing_pdf_header,
        missing_pdf_header_count
    );
    set_finding!(
        "missing_eof_marker",
        missing_eof_marker,
        missing_eof_marker_count
    );
    set_finding!(
        "eof_offset_unusual",
        eof_offset_unusual,
        eof_offset_unusual_count
    );
    set_finding!(
        "header_offset_unusual",
        header_offset_unusual,
        header_offset_unusual_count
    );
    set_finding!(
        "linearization_invalid",
        linearization_invalid,
        linearization_invalid_count
    );
    set_finding!(
        "linearization_multiple",
        linearization_multiple,
        linearization_multiple_count
    );

    // Object streams (5)
    set_finding!(
        "objstm_density_high",
        objstm_density_high,
        objstm_density_high_count
    );
    set_finding!(
        "objstm_embedded_summary",
        objstm_embedded_summary,
        objstm_embedded_summary_count
    );
    set_finding!(
        "objstm_action_chain",
        objstm_action_chain,
        objstm_action_chain_count
    );
    set_finding!(
        "orphan_payload_object",
        orphan_payload_object,
        orphan_payload_object_count
    );
    set_finding!(
        "shadow_payload_chain",
        shadow_payload_chain,
        shadow_payload_chain_count
    );

    // Streams/filters (6)
    set_finding!(
        "decoder_risk_present",
        decoder_risk_present,
        decoder_risk_present_count
    );
    set_finding!(
        "decompression_ratio_suspicious",
        decompression_ratio_suspicious,
        decompression_ratio_suspicious_count
    );
    set_finding!(
        "filter_chain_depth_high",
        filter_chain_depth_high,
        filter_chain_depth_high_count
    );
    set_finding!(
        "huge_image_dimensions",
        huge_image_dimensions,
        huge_image_dimensions_count
    );
    set_finding!(
        "stream_length_mismatch",
        stream_length_mismatch,
        stream_length_mismatch_count
    );
    set_finding!(
        "icc_profile_oversized",
        icc_profile_oversized,
        icc_profile_oversized_count
    );

    // Actions (8)
    set_finding!(
        "open_action_present",
        open_action_present,
        open_action_present_count
    );
    set_finding!("aa_present", aa_present, aa_present_count);
    set_finding!("aa_event_present", aa_event_present, aa_event_present_count);
    set_finding!(
        "launch_action_present",
        launch_action_present,
        launch_action_present_count
    );
    set_finding!("gotor_present", gotor_present, gotor_present_count);
    set_finding!("uri_present", uri_present, uri_present_count);
    set_finding!(
        "submitform_present",
        submitform_present,
        submitform_present_count
    );
    set_finding!(
        "external_action_risk_context",
        external_action_risk_context,
        external_action_risk_context_count
    );

    // JavaScript (10)
    set_finding!("js_present", js_present, js_present_count);
    set_finding!("js_polymorphic", js_polymorphic, js_polymorphic_count);
    set_finding!(
        "js_obfuscation_deep",
        js_obfuscation_deep,
        js_obfuscation_deep_count
    );
    set_finding!("js_time_evasion", js_time_evasion, js_time_evasion_count);
    set_finding!("js_env_probe", js_env_probe, js_env_probe_count);
    set_finding!(
        "js_multi_stage_decode",
        js_multi_stage_decode,
        js_multi_stage_decode_count
    );
    set_finding!(
        "js_runtime_file_probe",
        js_runtime_file_probe,
        js_runtime_file_probe_count
    );
    set_finding!(
        "js_runtime_network_intent",
        js_runtime_network_intent,
        js_runtime_network_intent_count
    );
    set_finding!("crypto_mining_js", crypto_mining_js, crypto_mining_js_count);

    // JS sandbox results (combined)
    if finding_counts_map.contains_key("js_sandbox_exec")
        || finding_counts_map.contains_key("js_sandbox_timeout")
        || finding_counts_map.contains_key("js_sandbox_skipped")
    {
        presence.js_sandbox_result = 1.0;
        counts.js_sandbox_result_count = finding_counts_map
            .get("js_sandbox_exec")
            .copied()
            .unwrap_or(0) as f32
            + finding_counts_map
                .get("js_sandbox_timeout")
                .copied()
                .unwrap_or(0) as f32
            + finding_counts_map
                .get("js_sandbox_skipped")
                .copied()
                .unwrap_or(0) as f32;
    }

    // URI classification (3)
    set_finding!(
        "uri_content_analysis",
        uri_content_analysis,
        uri_content_analysis_count
    );
    set_finding!(
        "uri_presence_summary",
        uri_presence_summary,
        uri_presence_summary_count
    );
    set_finding!(
        "action_payload_path",
        action_payload_path,
        action_payload_path_count
    );

    // Forms (2)
    set_finding!("acroform_present", acroform_present, acroform_present_count);
    set_finding!("xfa_present", xfa_present, xfa_present_count);

    // Embedded content (7)
    set_finding!(
        "embedded_file_present",
        embedded_file_present,
        embedded_file_present_count
    );
    set_finding!(
        "richmedia_present",
        richmedia_present,
        richmedia_present_count
    );
    set_finding!("3d_present", three_d_present, three_d_present_count);
    set_finding!(
        "sound_movie_present",
        sound_movie_present,
        sound_movie_present_count
    );
    set_finding!("filespec_present", filespec_present, filespec_present_count);
    set_finding!(
        "font_payload_present",
        font_payload_present,
        font_payload_present_count
    );
    set_finding!(
        "fontmatrix_payload_present",
        fontmatrix_payload_present,
        fontmatrix_payload_present_count
    );

    // Crypto/signatures (5)
    set_finding!(
        "encryption_present",
        encryption_present,
        encryption_present_count
    );
    set_finding!(
        "signature_present",
        signature_present,
        signature_present_count
    );
    set_finding!("dss_present", dss_present, dss_present_count);
    set_finding!("crypto_weak_algo", crypto_weak_algo, crypto_weak_algo_count);
    set_finding!(
        "quantum_vulnerable_crypto",
        quantum_vulnerable_crypto,
        quantum_vulnerable_crypto_count
    );

    // Content analysis (6)
    set_finding!("content_phishing", content_phishing, content_phishing_count);
    set_finding!(
        "content_html_payload",
        content_html_payload,
        content_html_payload_count
    );
    set_finding!(
        "content_invisible_text",
        content_invisible_text,
        content_invisible_text_count
    );
    set_finding!(
        "content_overlay_link",
        content_overlay_link,
        content_overlay_link_count
    );
    set_finding!(
        "content_image_only_page",
        content_image_only_page,
        content_image_only_page_count
    );
    set_finding!(
        "annotation_hidden",
        annotation_hidden,
        annotation_hidden_count
    );

    // Annotations (3)
    set_finding!(
        "annotation_action_chain",
        annotation_action_chain,
        annotation_action_chain_count
    );
    set_finding!(
        "annotation_attack",
        annotation_attack,
        annotation_attack_count
    );
    set_finding!("ocg_present", ocg_present, ocg_present_count);

    // Page tree (3)
    set_finding!("page_tree_cycle", page_tree_cycle, page_tree_cycle_count);
    set_finding!(
        "page_tree_mismatch",
        page_tree_mismatch,
        page_tree_mismatch_count
    );
    set_finding!(
        "page_tree_manipulation",
        page_tree_manipulation,
        page_tree_manipulation_count
    );

    // Supply chain (3)
    set_finding!(
        "supply_chain_persistence",
        supply_chain_persistence,
        supply_chain_persistence_count
    );
    set_finding!(
        "supply_chain_staged_payload",
        supply_chain_staged_payload,
        supply_chain_staged_payload_count
    );
    set_finding!(
        "supply_chain_update_vector",
        supply_chain_update_vector,
        supply_chain_update_vector_count
    );

    (presence, counts)
}

/// Helper to parse f32 from metadata
fn parse_meta_f32(meta: &HashMap<String, String>, key: &str) -> Option<f32> {
    meta.get(key).and_then(|v| v.parse::<f32>().ok())
}

/// Helper to parse usize from metadata
fn parse_meta_usize(meta: &HashMap<String, String>, key: &str) -> Option<usize> {
    meta.get(key).and_then(|v| v.parse::<usize>().ok())
}

/// Helper to check if metadata key exists and equals value
fn meta_equals(meta: &HashMap<String, String>, key: &str, value: &str) -> bool {
    meta.get(key).map(|v| v == value).unwrap_or(false)
}

/// Extract JavaScript-specific features from findings
fn extract_js_features(findings: &[Finding]) -> JsSignalFeatures {
    let mut features = JsSignalFeatures::default();

    let js_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.surface == AttackSurface::JavaScript)
        .collect();

    if js_findings.is_empty() {
        return features;
    }

    let mut obfuscation_scores = Vec::new();
    let mut eval_counts = Vec::new();
    let mut decode_ratios = Vec::new();
    let mut entropies = Vec::new();
    let mut js_sizes = Vec::new();
    let mut concat_layers = Vec::new();
    let mut unescape_layers = Vec::new();
    let mut suspicious_apis = std::collections::HashSet::new();

    for finding in &js_findings {
        let meta = &finding.meta;

        // Obfuscation score
        if let Some(score) = parse_meta_f32(meta, "js.obfuscation_score") {
            obfuscation_scores.push(score);
        }

        // Eval count
        if let Some(count) = parse_meta_usize(meta, "js.eval_count") {
            eval_counts.push(count);
            features.total_eval_count += count as f32;
        }

        // Decode ratio
        if let Some(ratio) = parse_meta_f32(meta, "js.decode_ratio") {
            decode_ratios.push(ratio);
        }

        // Entropy
        if let Some(entropy) = parse_meta_f32(meta, "js.entropy") {
            entropies.push(entropy);
        }

        // JS size
        if let Some(size) = parse_meta_usize(meta, "payload.decoded_len") {
            js_sizes.push(size);
        }

        // String concat layers
        if let Some(layers) = parse_meta_usize(meta, "js.string_concat_layers") {
            concat_layers.push(layers);
        }

        // Unescape layers
        if let Some(layers) = parse_meta_usize(meta, "js.unescape_layers") {
            unescape_layers.push(layers);
        }

        // Suspicious APIs
        if let Some(apis) = meta.get("js.suspicious_apis") {
            for api in apis.split(',') {
                suspicious_apis.insert(api.trim().to_string());
            }
        }

        // Binary flags
        if meta.contains_key("js.time_evasion") || meta_equals(meta, "js.time_evasion", "true") {
            features.time_evasion_present = 1.0;
        }
        if meta.contains_key("js.env_probe") || meta_equals(meta, "js.env_probe", "true") {
            features.env_probe_present = 1.0;
        }
        if finding.kind.contains("polymorphic") {
            features.polymorphic_present = 1.0;
        }
        if finding.kind.contains("multi_stage") {
            features.multi_stage_decode = 1.0;
        }
        if finding.kind.contains("sandbox_exec") {
            features.sandbox_executed = 1.0;
        }
        if finding.kind.contains("sandbox_timeout") {
            features.sandbox_timeout = 1.0;
        }
        if finding.kind.contains("file_probe") {
            features.runtime_file_probe = 1.0;
        }
        if finding.kind.contains("network_intent") {
            features.runtime_network_intent = 1.0;
        }
        if finding.kind.contains("crypto_mining") {
            features.crypto_mining_detected = 1.0;
        }

        // Context flags
        if meta.contains_key("js.in_openaction") {
            features.js_in_openaction = 1.0;
        }
        if meta.contains_key("js.in_aa") {
            features.js_in_aa = 1.0;
        }
        if meta.contains_key("js.in_annotation") {
            features.js_in_annotation = 1.0;
        }
        if meta.contains_key("js.in_field") {
            features.js_in_field = 1.0;
        }

        // fromCharCode count
        if let Some(count) = parse_meta_usize(meta, "payload.fromCharCode_count") {
            features.fromcharcode_count += count as f32;
        }

        // Multiple keys
        if meta.contains_key("js.multiple_keys") {
            features.multiple_keys_present = 1.0;
        }

        // Ref chain depth
        if let Some(chain) = meta.get("payload.ref_chain") {
            let depth = chain.matches("->").count();
            if depth as f32 > features.ref_chain_depth {
                features.ref_chain_depth = depth as f32;
            }
        }

        // Array fragments
        if let Some(frag_str) = meta.get("payload.type") {
            if let Some(array_match) = frag_str.strip_prefix("array[") {
                if let Some(count_str) = array_match.strip_suffix("]") {
                    if let Ok(count) = count_str.parse::<usize>() {
                        if count as f32 > features.array_fragment_count {
                            features.array_fragment_count = count as f32;
                        }
                    }
                }
            }
        }
    }

    // Aggregates
    features.max_obfuscation_score = obfuscation_scores.iter().copied().fold(0.0, f32::max);
    features.avg_obfuscation_score = if !obfuscation_scores.is_empty() {
        obfuscation_scores.iter().sum::<f32>() / obfuscation_scores.len() as f32
    } else {
        0.0
    };

    features.max_eval_count = eval_counts.iter().copied().max().unwrap_or(0) as f32;
    features.unique_suspicious_apis = suspicious_apis.len() as f32;
    features.max_string_concat_layers = concat_layers.iter().copied().max().unwrap_or(0) as f32;
    features.max_unescape_layers = unescape_layers.iter().copied().max().unwrap_or(0) as f32;
    features.max_decode_ratio = decode_ratios.iter().copied().fold(0.0, f32::max);

    features.max_entropy = entropies.iter().copied().fold(0.0, f32::max);
    features.avg_entropy = if !entropies.is_empty() {
        entropies.iter().sum::<f32>() / entropies.len() as f32
    } else {
        0.0
    };

    features.total_js_objects = js_findings.len() as f32;
    features.max_js_size = js_sizes.iter().copied().max().unwrap_or(0) as f32;
    features.avg_js_size = if !js_sizes.is_empty() {
        js_sizes.iter().sum::<usize>() as f32 / js_sizes.len() as f32
    } else {
        0.0
    };

    features
}

/// Extract URI-specific features from findings
fn extract_uri_features(findings: &[Finding]) -> UriSignalFeatures {
    let mut features = UriSignalFeatures::default();

    // Filter to URI-related findings only (not all Actions surface findings)
    let uri_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.kind.contains("uri") || f.kind.contains("url") || f.kind.starts_with("uri_"))
        .collect();

    if uri_findings.is_empty() {
        return features;
    }

    let mut risk_scores = Vec::new();
    let mut domains = std::collections::HashSet::new();
    let mut url_lengths = Vec::new();

    for finding in &uri_findings {
        let meta = &finding.meta;

        // Extract risk score
        if let Some(risk_str) = meta.get("uri.risk_score") {
            if let Ok(risk) = risk_str.parse::<f32>() {
                risk_scores.push(risk);
            }
        }

        // Extract domain
        if let Some(domain) = meta.get("uri.domain") {
            domains.insert(domain.clone());
        }

        // Extract URL length
        if let Some(len_str) = meta.get("uri.length") {
            if let Ok(len) = len_str.parse::<usize>() {
                url_lengths.push(len);
            }
        }

        // Count by scheme
        if let Some(scheme) = meta.get("uri.scheme") {
            match scheme.as_str() {
                "javascript" => features.javascript_uri_count += 1.0,
                "file" => features.file_uri_count += 1.0,
                "data" => features.data_uri_count += 1.0,
                "http" => features.http_count += 1.0,
                "https" => features.https_count += 1.0,
                _ => {}
            }
        }

        // IP address URIs
        if meta.get("uri.is_ip").map(|s| s == "true").unwrap_or(false) {
            features.ip_address_count += 1.0;
        }

        // Suspicious TLD
        if meta
            .get("uri.suspicious_tld")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.suspicious_tld_count += 1.0;
        }

        // Obfuscated URIs (check if obfuscation level is not "none")
        if let Some(obf_level) = meta.get("uri.obfuscation") {
            if obf_level != "none" {
                features.obfuscated_count += 1.0;
            }
        }

        // Data exfiltration patterns
        if meta
            .get("uri.data_exfil_pattern")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.data_exfil_pattern_count += 1.0;
        }

        // Data URI base64 payloads
        if meta
            .get("uri.data_is_base64")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.data_base64_count += 1.0;
        }

        // Hidden annotations
        if meta
            .get("uri.hidden_annotation")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.hidden_annotation_count += 1.0;
        }

        // Automatic triggers
        if meta
            .get("uri.automatic")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.automatic_trigger_count += 1.0;
        }

        // JS-triggered URIs
        if meta
            .get("uri.js_involved")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.js_triggered_count += 1.0;
        }

        // Tracking parameters
        if meta
            .get("uri.tracking_params")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.tracking_params_count += 1.0;
        }

        // Phishing indicators
        if meta
            .get("uri.phishing_indicators")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.phishing_indicators += 1.0;
        }

        if meta
            .get("uri.shortener_domain")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.shortener_domain_count += 1.0;
        }

        if meta
            .get("uri.suspicious_extension")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.suspicious_extension_count += 1.0;
        }

        if meta
            .get("uri.suspicious_scheme")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.suspicious_scheme_count += 1.0;
        }

        if meta
            .get("uri.embedded_ip_host")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.embedded_ip_host_count += 1.0;
        }

        if meta
            .get("uri.idn_lookalike")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.idn_lookalike_count += 1.0;
        }

        if meta
            .get("uri.non_standard_port")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.non_standard_port_count += 1.0;
        }

        // Mixed content
        if meta
            .get("uri.mixed_content")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.mixed_content_present = 1.0;
        }
    }

    // Aggregates
    features.total_count = uri_findings.len() as f32;
    features.unique_domains = domains.len() as f32;
    features.external_dependency_count =
        features.http_count + features.https_count + features.file_uri_count;

    if !risk_scores.is_empty() {
        features.max_risk_score = risk_scores.iter().copied().fold(0.0, f32::max);
        features.avg_risk_score = risk_scores.iter().sum::<f32>() / risk_scores.len() as f32;
    }

    if !url_lengths.is_empty() {
        features.max_url_length = url_lengths.iter().copied().max().unwrap_or(0) as f32;
    }

    features
}

/// Extract content analysis features
fn extract_content_features(findings: &[Finding]) -> ContentSignalFeatures {
    let mut features = ContentSignalFeatures::default();

    for finding in findings {
        let meta = &finding.meta;

        // Phishing indicators
        if finding.kind.contains("phishing") || meta.contains_key("content.phishing_score") {
            features.phishing_indicators += 1.0;
        }

        // Invisible text pages
        if finding.kind == "invisible_text"
            || meta
                .get("content.invisible_text")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.invisible_text_pages += 1.0;
        }

        // Overlay links
        if finding.kind == "overlay_link" || meta.contains_key("content.overlay_link") {
            features.overlay_link_count += 1.0;
        }

        // Image-only pages
        if finding.kind == "image_only_page"
            || meta
                .get("content.image_only")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.image_only_pages += 1.0;
        }

        // HTML payload
        if finding.kind.contains("html_payload") || meta.contains_key("content.html_payload") {
            features.html_payload_present = 1.0;
        }

        // Hidden annotations
        if finding.kind == "hidden_annotation"
            || meta
                .get("annotation.hidden")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.hidden_annotation_count += 1.0;
        }

        // Suspicious fonts
        if finding.kind.contains("suspicious_font") || meta.contains_key("font.suspicious") {
            features.suspicious_font_count += 1.0;
        }

        // Text rendering anomalies
        if finding.kind.contains("text_rendering") || meta.contains_key("content.rendering_anomaly")
        {
            features.text_rendering_anomalies += 1.0;
        }

        // Color manipulation
        if finding.kind.contains("color_manipulation")
            || meta.contains_key("content.color_manipulation")
        {
            features.color_manipulation_count += 1.0;
        }

        // Whitespace abuse
        if finding.kind.contains("whitespace_abuse")
            || meta.contains_key("content.whitespace_abuse")
        {
            features.whitespace_abuse_count += 1.0;
        }

        // Unicode RTLO (Right-to-Left Override)
        if finding.kind.contains("rtlo") || finding.kind.contains("unicode_rtlo") {
            features.unicode_rtlo_count += 1.0;
        }

        // Homoglyph attacks
        if finding.kind.contains("homoglyph") || meta.contains_key("content.homoglyph") {
            features.homoglyph_count += 1.0;
        }

        // Zero-width characters
        if finding.kind.contains("zero_width") || meta.contains_key("content.zero_width_char") {
            features.zero_width_char_count += 1.0;
        }

        // Text direction abuse
        if finding.kind.contains("text_direction") || meta.contains_key("content.direction_abuse") {
            features.text_direction_abuse += 1.0;
        }

        // Layer manipulation (OCG - Optional Content Groups)
        if finding.kind.contains("layer")
            || finding.kind.contains("ocg")
            || meta.contains_key("content.layer_manipulation")
        {
            features.layer_manipulation_count += 1.0;
        }
    }

    features
}

/// Extract supply chain attack features
fn extract_supply_chain_features(findings: &[Finding]) -> SupplyChainFeatures {
    let mut features = SupplyChainFeatures::default();

    for finding in findings {
        let meta = &finding.meta;

        // Persistence mechanisms
        if finding.kind.contains("persistence") || meta.contains_key("supply_chain.persistence") {
            features.persistence_mechanisms += 1.0;
        }

        // Staged payloads
        if finding.kind.contains("staged_payload") || finding.kind.contains("multi_stage") {
            features.staged_payload_count += 1.0;
        }

        // Update vectors
        if finding.kind.contains("update") || meta.contains_key("supply_chain.update_vector") {
            features.update_vectors += 1.0;
        }

        // Multi-stage attack chains (only supply_chain or multi_stage findings)
        if finding.kind.contains("multi_stage") || finding.kind.starts_with("supply_chain") {
            features.multi_stage_chains += 1.0;
        }

        // Command & control indicators
        if finding.kind.contains("c2")
            || finding.kind.contains("command_control")
            || meta.contains_key("supply_chain.c2")
        {
            features.command_control_indicators += 1.0;
        }

        // Lateral movement
        if finding.kind.contains("lateral") || meta.contains_key("supply_chain.lateral_movement") {
            features.lateral_movement_indicators += 1.0;
        }

        // Data staging
        if finding.kind.contains("data_staging") || meta.contains_key("supply_chain.data_staging") {
            features.data_staging_indicators += 1.0;
        }

        // Exfiltration indicators
        if finding.kind.contains("exfiltration") || finding.kind.contains("exfil") {
            features.exfiltration_indicators += 1.0;
        }

        // Anti-forensics techniques
        if finding.kind.contains("anti_forensics")
            || meta.contains_key("supply_chain.anti_forensics")
        {
            features.anti_forensics_techniques += 1.0;
        }

        // Defense evasion
        if finding.kind.contains("evasion") || finding.kind.contains("defense_evasion") {
            features.defense_evasion_count += 1.0;
        }
    }

    features
}

/// Extract structural anomaly features
fn extract_structural_features(findings: &[Finding]) -> StructuralAnomalyFeatures {
    let mut features = StructuralAnomalyFeatures::default();

    let mut decompression_ratios = Vec::new();
    let mut filter_depths = Vec::new();

    for finding in findings {
        let meta = &finding.meta;

        // Object stream density
        if let Some(density_str) = meta.get("objstm.density") {
            if let Ok(density) = density_str.parse::<f32>() {
                if density > features.objstm_density {
                    features.objstm_density = density;
                }
            }
        }

        // Filter chain depth
        if let Some(depth_str) = meta.get("stream.filter_depth") {
            if let Ok(depth) = depth_str.parse::<usize>() {
                filter_depths.push(depth);
            }
        }

        // Decompression ratio
        if let Some(ratio_str) = meta.get("stream.decompression_ratio") {
            if let Ok(ratio) = ratio_str.parse::<f32>() {
                decompression_ratios.push(ratio);
            }
        }

        // Page tree anomalies
        if finding.kind.contains("page_tree") {
            features.page_tree_anomalies += 1.0;
        }

        // Linearization anomalies
        if finding.kind.contains("linearization") {
            features.linearization_anomalies += 1.0;
        }

        // Parser deviations
        if finding.kind.contains("parser") || meta.contains_key("parser.deviation") {
            features.parser_deviations += 1.0;
        }

        // XRef table anomalies
        if finding.kind.contains("xref") {
            features.xref_table_anomalies += 1.0;
        }

        // Trailer anomalies
        if finding.kind.contains("trailer") {
            features.trailer_anomalies += 1.0;
        }

        // Catalog anomalies
        if finding.kind.contains("catalog") {
            features.catalog_anomalies += 1.0;
        }

        // Object stream anomalies
        if finding.kind.contains("objstm") || finding.kind.contains("object_stream") {
            features.object_stream_anomalies += 1.0;
        }

        // Cross-reference stream anomalies
        if finding.kind.contains("xref_stream") {
            features.cross_ref_stream_anomalies += 1.0;
        }

        // Incremental updates
        if finding.kind.contains("incremental_update") {
            features.incremental_update_count += 1.0;
        }

        // Conflicting definitions
        if finding.kind.contains("conflict") || finding.kind.contains("shadowing") {
            features.conflicting_definitions += 1.0;
        }

        // Orphaned objects
        if finding.kind.contains("orphan") {
            features.orphaned_objects += 1.0;
        }

        // Circular references
        if finding.kind.contains("circular") {
            features.circular_references += 1.0;
        }

        // Invalid object references
        if finding.kind.contains("invalid_ref") || meta.contains_key("object.invalid_ref") {
            features.invalid_object_refs += 1.0;
        }

        // Stream dictionary mismatch
        if finding.kind.contains("stream_length_mismatch")
            || finding.kind.contains("dictionary_mismatch")
        {
            features.stream_dictionary_mismatch += 1.0;
        }

        // Unusual object sizes
        if meta
            .get("object.unusual_size")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.unusual_object_sizes += 1.0;
        }

        // Object ID gaps
        if finding.kind.contains("object_id_gap") {
            features.object_id_gaps += 1.0;
        }

        // Generation number anomalies
        if finding.kind.contains("generation") {
            features.generation_number_anomalies += 1.0;
        }
    }

    // Aggregates
    if !filter_depths.is_empty() {
        features.filter_chain_max_depth = filter_depths.iter().copied().max().unwrap_or(0) as f32;
    }

    if !decompression_ratios.is_empty() {
        features.decompression_max_ratio = decompression_ratios.iter().copied().fold(0.0, f32::max);
    }

    features
}

/// Extract cryptographic features
fn extract_crypto_features(findings: &[Finding]) -> CryptoFeatures {
    let mut features = CryptoFeatures::default();

    let mut weakness_scores = Vec::new();

    for finding in findings {
        let meta = &finding.meta;

        // Encryption present
        if finding.kind.contains("encryption") || meta.contains_key("crypto.encryption") {
            features.encryption_present = 1.0;
        }

        // Signature present
        if finding.kind.contains("signature") || meta.contains_key("crypto.signature") {
            features.signature_present = 1.0;
        }

        // Weak algorithms
        if finding.kind.contains("weak_algo")
            || meta
                .get("crypto.weak_algorithm")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.weak_algo_count += 1.0;
        }

        // Quantum vulnerability
        if finding.kind.contains("quantum")
            || meta
                .get("crypto.quantum_vulnerable")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.quantum_vulnerable = 1.0;
        }

        // Certificate anomalies
        if finding.kind.contains("cert") && finding.kind.contains("anomaly") {
            features.cert_anomalies += 1.0;
        }

        // Signature validation failed
        if finding.kind.contains("signature_validation")
            || finding.kind.contains("invalid_signature")
        {
            features.signature_validation_failed += 1.0;
        }

        // Timestamp anomalies
        if finding.kind.contains("timestamp") {
            features.timestamp_anomalies += 1.0;
        }

        // Revocation check failed
        if finding.kind.contains("revocation") {
            features.revocation_check_failed += 1.0;
        }

        // Self-signed certificate
        if finding.kind.contains("self_signed") {
            features.self_signed_cert = 1.0;
        }

        // Encryption weakness score
        if let Some(weakness_str) = meta.get("crypto.weakness_score") {
            if let Ok(score) = weakness_str.parse::<f32>() {
                weakness_scores.push(score);
            }
        }
    }

    // Aggregate weakness score
    if !weakness_scores.is_empty() {
        features.encryption_weakness_score = weakness_scores.iter().copied().fold(0.0, f32::max);
    }

    features
}

/// Extract embedded content features
fn extract_embedded_features(findings: &[Finding]) -> EmbeddedContentFeatures {
    let mut features = EmbeddedContentFeatures::default();

    let mut file_sizes = Vec::new();
    let mut decode_ratios = Vec::new();
    let mut archive_depths = Vec::new();

    for finding in findings {
        let meta = &finding.meta;

        // File count
        if finding.surface == AttackSurface::EmbeddedFiles {
            features.file_count += 1.0;
        }

        // File sizes
        if let Some(size_str) = meta.get("embedded.size") {
            if let Ok(size) = size_str.parse::<usize>() {
                file_sizes.push(size);
            }
        }

        // Decode ratios
        if let Some(ratio_str) = meta.get("embedded.decode_ratio") {
            if let Ok(ratio) = ratio_str.parse::<f32>() {
                decode_ratios.push(ratio);
            }
        }

        // PE executables
        if finding.kind.contains("pe_executable")
            || meta
                .get("embedded.type")
                .map(|s| s == "pe")
                .unwrap_or(false)
        {
            features.pe_executable_count += 1.0;
        }

        // Encrypted containers
        if finding.kind.contains("encrypted")
            || meta
                .get("embedded.encrypted")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.encrypted_container_count += 1.0;
        }

        // Double extensions
        if finding.kind.contains("double_extension") {
            features.double_extension_count += 1.0;
        }

        // RichMedia
        if finding.surface == AttackSurface::RichMedia3D || finding.kind.contains("richmedia") {
            features.richmedia_count += 1.0;
        }

        // 3D content
        if finding.kind.contains("3d")
            || finding.kind.contains("u3d")
            || finding.kind.contains("prc")
        {
            features.three_d_content_count += 1.0;
        }

        // Flash content
        if finding.kind.contains("flash") || finding.kind.contains("swf") {
            features.flash_content_count += 1.0;
        }

        // Suspicious MIME types
        if meta
            .get("embedded.suspicious_mime")
            .map(|s| s == "true")
            .unwrap_or(false)
        {
            features.suspicious_mime_types += 1.0;
        }

        // Mismatched extensions
        if finding.kind.contains("extension_mismatch") {
            features.mismatched_extensions += 1.0;
        }

        // Archives
        if finding.kind.contains("archive")
            || meta
                .get("embedded.is_archive")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.archive_count += 1.0;
        }

        // Nested archive depth
        if let Some(depth_str) = meta.get("embedded.archive_depth") {
            if let Ok(depth) = depth_str.parse::<usize>() {
                archive_depths.push(depth);
            }
        }

        // Password protected
        if finding.kind.contains("password_protected") {
            features.password_protected_count += 1.0;
        }

        // Macro-enabled files
        if finding.kind.contains("macro")
            || meta
                .get("embedded.has_macros")
                .map(|s| s == "true")
                .unwrap_or(false)
        {
            features.macro_enabled_count += 1.0;
        }
    }

    // Aggregates
    if !file_sizes.is_empty() {
        features.total_size = file_sizes.iter().sum::<usize>() as f32;
    }

    if !decode_ratios.is_empty() {
        features.max_decode_ratio = decode_ratios.iter().copied().fold(0.0, f32::max);
    }

    if !archive_depths.is_empty() {
        features.nested_archive_depth = archive_depths.iter().copied().max().unwrap_or(0) as f32;
    }

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_feature_vector_dimensions() {
        let features = ExtendedFeatureVector::default();
        let vec = features.as_f32_vec();

        // 76 (legacy) + 13 (attack surfaces) + 15 (severity) + 9 (confidence) +
        // 71 (presence) + 71 (counts) + 30 (JS) + 20 (URI) + 15 (content) +
        // 10 (supply chain) + 20 (structural) + 10 (crypto) + 15 (embedded)
        // = 76 + 311 = 387
        assert_eq!(vec.len(), 387, "Expected 387 features, got {}", vec.len());
    }

    #[test]
    fn test_feature_names_match_values() {
        let names = ExtendedFeatureVector::feature_names();
        let features = ExtendedFeatureVector::default();
        let values = features.as_f32_vec();

        assert_eq!(
            names.len(),
            values.len(),
            "Feature names ({}) and values ({}) must match",
            names.len(),
            values.len()
        );
        assert_eq!(names.len(), 387, "Expected 387 feature names");
    }

    #[test]
    fn test_to_named_map() {
        let features = ExtendedFeatureVector::default();
        let map = features.to_named_map();

        assert_eq!(map.len(), 387, "Named map should have 387 entries");
        assert!(map.contains_key("general.file_size"));
        assert!(map.contains_key("js_signals.max_obfuscation_score"));
        assert!(map.contains_key("uri_signals.total_count"));
    }

    #[test]
    fn test_js_signals_feature_names() {
        let names = JsSignalFeatures::feature_names();
        assert_eq!(names.len(), 30, "JS signals should have 30 features");
        assert!(names.contains(&"js_signals.max_obfuscation_score".to_string()));
    }

    #[test]
    fn test_uri_signals_feature_names() {
        let names = UriSignalFeatures::feature_names();
        assert_eq!(names.len(), 28, "URI signals should have 28 features");
        assert!(names.contains(&"uri_signals.total_count".to_string()));
    }

    #[test]
    fn test_finding_presence_feature_count() {
        let features = FindingPresenceFeatures::default();
        let vec = features.as_f32_vec();
        assert_eq!(vec.len(), 71, "Finding presence should have 71 features");
    }

    #[test]
    fn test_finding_count_feature_count() {
        let features = FindingCountFeatures::default();
        let vec = features.as_f32_vec();
        assert_eq!(vec.len(), 71, "Finding counts should have 71 features");
    }

    #[test]
    fn test_attack_surface_extraction() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                surface: AttackSurface::JavaScript,
                kind: "js_present".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Strong,
                title: "JavaScript Present".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "2".to_string(),
                surface: AttackSurface::JavaScript,
                kind: "js_obfuscation".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "Obfuscated JS".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "3".to_string(),
                surface: AttackSurface::Actions,
                kind: "open_action".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "OpenAction".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
        ];

        let features = extract_attack_surface_features(&findings);
        assert_eq!(features.javascript_count, 2.0);
        assert_eq!(features.actions_count, 1.0);
        assert_eq!(features.forms_count, 0.0);
    }

    #[test]
    fn test_severity_extraction() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                surface: AttackSurface::JavaScript,
                kind: "test".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Strong,
                title: "Test".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "2".to_string(),
                surface: AttackSurface::Actions,
                kind: "test".to_string(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "Test".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "3".to_string(),
                surface: AttackSurface::Forms,
                kind: "test".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                title: "Test".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
        ];

        let features = extract_severity_features(&findings);
        assert_eq!(features.total_critical, 1.0);
        assert_eq!(features.total_high, 1.0);
        assert_eq!(features.total_medium, 1.0);
        assert_eq!(features.max_severity_score, 4.0); // Critical = 4
        assert!(features.avg_severity_score > 0.0);
    }

    #[test]
    fn test_confidence_extraction() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                surface: AttackSurface::JavaScript,
                kind: "test".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "Test".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "2".to_string(),
                surface: AttackSurface::Actions,
                kind: "test".to_string(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "Test".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
        ];

        let features = extract_confidence_features(&findings);
        assert_eq!(features.strong_count, 1.0);
        assert_eq!(features.probable_count, 1.0);
        assert_eq!(features.strong_high_severity, 1.0);
        assert_eq!(features.probable_high_severity, 1.0);
    }

    #[test]
    fn test_js_feature_extraction_from_metadata() {
        let mut meta = HashMap::new();
        meta.insert("js.obfuscation_score".to_string(), "0.85".to_string());
        meta.insert("js.eval_count".to_string(), "5".to_string());
        meta.insert("js.entropy".to_string(), "7.2".to_string());
        meta.insert("js.decode_ratio".to_string(), "3.5".to_string());
        meta.insert(
            "js.suspicious_apis".to_string(),
            "eval,unescape".to_string(),
        );

        let findings = vec![
            Finding {
                id: "1".to_string(),
                surface: AttackSurface::JavaScript,
                kind: "js_polymorphic".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "Polymorphic JS".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: meta.clone(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "2".to_string(),
                surface: AttackSurface::JavaScript,
                kind: "js_time_evasion".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "Time Evasion".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: {
                    let mut m = HashMap::new();
                    m.insert("js.time_evasion".to_string(), "true".to_string());
                    m
                },
                yara: None,
                position: None,
                positions: Vec::new(),
            },
        ];

        let features = extract_js_features(&findings);
        assert_eq!(features.max_obfuscation_score, 0.85);
        assert_eq!(features.max_eval_count, 5.0);
        assert_eq!(features.max_entropy, 7.2);
        assert_eq!(features.polymorphic_present, 1.0); // Finding kind is "js_polymorphic" which contains "polymorphic"
        assert_eq!(features.time_evasion_present, 1.0); // Metadata key "js.time_evasion" is present
        assert_eq!(features.total_js_objects, 2.0);
    }

    #[test]
    fn test_uri_feature_extraction() {
        let mut meta = HashMap::new();
        meta.insert("uri.scheme".to_string(), "http".to_string());
        meta.insert("uri.is_ip".to_string(), "true".to_string());
        meta.insert("uri.risk_score".to_string(), "0.75".to_string());
        meta.insert("uri.shortener_domain".to_string(), "true".to_string());
        meta.insert("uri.suspicious_extension".to_string(), "true".to_string());
        meta.insert("uri.data_is_base64".to_string(), "true".to_string());

        let findings = vec![Finding {
            id: "1".to_string(),
            surface: AttackSurface::Actions,
            kind: "uri_content_analysis".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Suspicious URI".to_string(),
            description: "Test".to_string(),
            objects: vec![],
            evidence: vec![],
            remediation: None,
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
        }];

        let features = extract_uri_features(&findings);
        assert_eq!(features.http_count, 1.0);
        assert_eq!(features.ip_address_count, 1.0);
        assert_eq!(features.max_risk_score, 0.75);
        assert_eq!(features.total_count, 1.0);
        assert_eq!(features.shortener_domain_count, 1.0);
        assert_eq!(features.suspicious_extension_count, 1.0);
        assert_eq!(features.data_base64_count, 1.0);
    }

    #[test]
    fn test_finding_presence_and_counts() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                surface: AttackSurface::FileStructure,
                kind: "xref_conflict".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Strong,
                title: "XRef Conflict".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "2".to_string(),
                surface: AttackSurface::FileStructure,
                kind: "xref_conflict".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Strong,
                title: "XRef Conflict 2".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "3".to_string(),
                surface: AttackSurface::JavaScript,
                kind: "js_polymorphic".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "Polymorphic JS".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
        ];

        let (presence, counts) = extract_finding_features(&findings);
        assert_eq!(presence.xref_conflict, 1.0); // Binary flag
        assert_eq!(counts.xref_conflict_count, 2.0); // Count
        assert_eq!(presence.js_polymorphic, 1.0);
        assert_eq!(counts.js_polymorphic_count, 1.0);
    }

    #[test]
    fn test_content_feature_extraction() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                surface: AttackSurface::ContentPhishing,
                kind: "phishing_indicator".to_string(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "Phishing".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
            Finding {
                id: "2".to_string(),
                surface: AttackSurface::ContentPhishing,
                kind: "invisible_text".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Invisible Text".to_string(),
                description: "Test".to_string(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: HashMap::new(),
                yara: None,
                position: None,
                positions: Vec::new(),
            },
        ];

        let features = extract_content_features(&findings);
        assert_eq!(features.phishing_indicators, 1.0);
        assert_eq!(features.invisible_text_pages, 1.0);
    }

    #[test]
    fn test_extended_feature_vector_update_count() {
        // This test verifies we have 387 features total
        let features = ExtendedFeatureVector::default();
        let vec = features.as_f32_vec();

        // 76 (legacy) + 13 (attack surfaces - added Images) + 15 (severity) + 9 (confidence) +
        // 71 (presence) + 71 (counts) + 30 (JS) + 28 (URI) + 15 (content) +
        // 10 (supply chain) + 20 (structural) + 10 (crypto) + 15 (embedded)
        // = 76 + 311 = 387
        assert_eq!(
            vec.len(),
            387,
            "Expected 387 features total, got {}",
            vec.len()
        );
    }
}

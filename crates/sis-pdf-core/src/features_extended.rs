// Extended Feature Vector with 320 features
//
// Expands from 35 to 320 features by incorporating all detector findings:
// - Legacy features (35): General, Structural, Behavioral, Content, Graph
// - Attack surface distribution (11)
// - Severity/confidence distributions (24)
// - Finding presence/counts (140: 70 binary + 70 counts)
// - JS signals (30)
// - URI signals (20)
// - Content signals (15)
// - Supply chain signals (10)
// - Structural anomaly signals (20)
// - Crypto signals (10)
// - Embedded content signals (15)

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::features::FeatureVector;
use crate::model::{Finding, Severity, Confidence, AttackSurface};

/// Extended feature vector with 320 features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedFeatureVector {
    /// Legacy features (35)
    pub legacy: FeatureVector,

    /// Attack surface distribution (11 features)
    pub attack_surfaces: AttackSurfaceFeatures,

    /// Severity distribution (15 features)
    pub severity_dist: SeverityFeatures,

    /// Confidence distribution (9 features)
    pub confidence_dist: ConfidenceFeatures,

    /// Finding presence (70 binary features)
    pub finding_presence: FindingPresenceFeatures,

    /// Finding counts (70 count features)
    pub finding_counts: FindingCountFeatures,

    /// JavaScript-specific signals (30 features)
    pub js_signals: JsSignalFeatures,

    /// URI-specific signals (20 features)
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
    /// Convert to flat f32 vector (320 features)
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

    /// Get feature names (320 names)
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
// Attack Surface Distribution (11 features)
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
    pub crypto_signatures_count: f32,
    pub metadata_count: f32,
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
            self.crypto_signatures_count,
            self.metadata_count,
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
            "attack_surfaces.crypto_signatures_count",
            "attack_surfaces.metadata_count",
        ].into_iter().map(|s| s.to_string()).collect()
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
        ].into_iter().map(|s| s.to_string()).collect()
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
        ].into_iter().map(|s| s.to_string()).collect()
    }
}

// ============================================================================
// Finding Presence (70 binary features - one per finding type)
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
            self.xref_conflict, self.incremental_update_chain, self.object_id_shadowing,
            self.polyglot_signature_conflict, self.missing_pdf_header, self.missing_eof_marker,
            self.eof_offset_unusual, self.header_offset_unusual, self.linearization_invalid,
            self.linearization_multiple, self.objstm_density_high, self.objstm_embedded_summary,
            self.objstm_action_chain, self.orphan_payload_object, self.shadow_payload_chain,
            self.decoder_risk_present, self.decompression_ratio_suspicious, self.filter_chain_depth_high,
            self.huge_image_dimensions, self.stream_length_mismatch, self.icc_profile_oversized,
            self.open_action_present, self.aa_present, self.aa_event_present,
            self.launch_action_present, self.gotor_present, self.uri_present,
            self.submitform_present, self.external_action_risk_context, self.js_present,
            self.js_polymorphic, self.js_obfuscation_deep, self.js_time_evasion,
            self.js_env_probe, self.js_multi_stage_decode, self.js_runtime_file_probe,
            self.js_runtime_network_intent, self.crypto_mining_js, self.js_sandbox_result,
            self.uri_content_analysis, self.uri_presence_summary, self.action_payload_path,
            self.acroform_present, self.xfa_present, self.embedded_file_present,
            self.richmedia_present, self.three_d_present, self.sound_movie_present,
            self.filespec_present, self.font_payload_present, self.fontmatrix_payload_present,
            self.encryption_present, self.signature_present, self.dss_present,
            self.crypto_weak_algo, self.quantum_vulnerable_crypto, self.content_phishing,
            self.content_html_payload, self.content_invisible_text, self.content_overlay_link,
            self.content_image_only_page, self.annotation_hidden, self.annotation_action_chain,
            self.annotation_attack, self.ocg_present, self.page_tree_cycle,
            self.page_tree_mismatch, self.page_tree_manipulation, self.supply_chain_persistence,
            self.supply_chain_staged_payload, self.supply_chain_update_vector,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "finding.xref_conflict", "finding.incremental_update_chain", "finding.object_id_shadowing",
            "finding.polyglot_signature_conflict", "finding.missing_pdf_header", "finding.missing_eof_marker",
            "finding.eof_offset_unusual", "finding.header_offset_unusual", "finding.linearization_invalid",
            "finding.linearization_multiple", "finding.objstm_density_high", "finding.objstm_embedded_summary",
            "finding.objstm_action_chain", "finding.orphan_payload_object", "finding.shadow_payload_chain",
            "finding.decoder_risk_present", "finding.decompression_ratio_suspicious", "finding.filter_chain_depth_high",
            "finding.huge_image_dimensions", "finding.stream_length_mismatch", "finding.icc_profile_oversized",
            "finding.open_action_present", "finding.aa_present", "finding.aa_event_present",
            "finding.launch_action_present", "finding.gotor_present", "finding.uri_present",
            "finding.submitform_present", "finding.external_action_risk_context", "finding.js_present",
            "finding.js_polymorphic", "finding.js_obfuscation_deep", "finding.js_time_evasion",
            "finding.js_env_probe", "finding.js_multi_stage_decode", "finding.js_runtime_file_probe",
            "finding.js_runtime_network_intent", "finding.crypto_mining_js", "finding.js_sandbox_result",
            "finding.uri_content_analysis", "finding.uri_presence_summary", "finding.action_payload_path",
            "finding.acroform_present", "finding.xfa_present", "finding.embedded_file_present",
            "finding.richmedia_present", "finding.three_d_present", "finding.sound_movie_present",
            "finding.filespec_present", "finding.font_payload_present", "finding.fontmatrix_payload_present",
            "finding.encryption_present", "finding.signature_present", "finding.dss_present",
            "finding.crypto_weak_algo", "finding.quantum_vulnerable_crypto", "finding.content_phishing",
            "finding.content_html_payload", "finding.content_invisible_text", "finding.content_overlay_link",
            "finding.content_image_only_page", "finding.annotation_hidden", "finding.annotation_action_chain",
            "finding.annotation_attack", "finding.ocg_present", "finding.page_tree_cycle",
            "finding.page_tree_mismatch", "finding.page_tree_manipulation", "finding.supply_chain_persistence",
            "finding.supply_chain_staged_payload", "finding.supply_chain_update_vector",
        ].into_iter().map(|s| s.to_string()).collect()
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
            self.xref_conflict_count, self.incremental_update_chain_count, self.object_id_shadowing_count,
            self.polyglot_signature_conflict_count, self.missing_pdf_header_count, self.missing_eof_marker_count,
            self.eof_offset_unusual_count, self.header_offset_unusual_count, self.linearization_invalid_count,
            self.linearization_multiple_count, self.objstm_density_high_count, self.objstm_embedded_summary_count,
            self.objstm_action_chain_count, self.orphan_payload_object_count, self.shadow_payload_chain_count,
            self.decoder_risk_present_count, self.decompression_ratio_suspicious_count, self.filter_chain_depth_high_count,
            self.huge_image_dimensions_count, self.stream_length_mismatch_count, self.icc_profile_oversized_count,
            self.open_action_present_count, self.aa_present_count, self.aa_event_present_count,
            self.launch_action_present_count, self.gotor_present_count, self.uri_present_count,
            self.submitform_present_count, self.external_action_risk_context_count, self.js_present_count,
            self.js_polymorphic_count, self.js_obfuscation_deep_count, self.js_time_evasion_count,
            self.js_env_probe_count, self.js_multi_stage_decode_count, self.js_runtime_file_probe_count,
            self.js_runtime_network_intent_count, self.crypto_mining_js_count, self.js_sandbox_result_count,
            self.uri_content_analysis_count, self.uri_presence_summary_count, self.action_payload_path_count,
            self.acroform_present_count, self.xfa_present_count, self.embedded_file_present_count,
            self.richmedia_present_count, self.three_d_present_count, self.sound_movie_present_count,
            self.filespec_present_count, self.font_payload_present_count, self.fontmatrix_payload_present_count,
            self.encryption_present_count, self.signature_present_count, self.dss_present_count,
            self.crypto_weak_algo_count, self.quantum_vulnerable_crypto_count, self.content_phishing_count,
            self.content_html_payload_count, self.content_invisible_text_count, self.content_overlay_link_count,
            self.content_image_only_page_count, self.annotation_hidden_count, self.annotation_action_chain_count,
            self.annotation_attack_count, self.ocg_present_count, self.page_tree_cycle_count,
            self.page_tree_mismatch_count, self.page_tree_manipulation_count, self.supply_chain_persistence_count,
            self.supply_chain_staged_payload_count, self.supply_chain_update_vector_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "finding_count.xref_conflict", "finding_count.incremental_update_chain", "finding_count.object_id_shadowing",
            "finding_count.polyglot_signature_conflict", "finding_count.missing_pdf_header", "finding_count.missing_eof_marker",
            "finding_count.eof_offset_unusual", "finding_count.header_offset_unusual", "finding_count.linearization_invalid",
            "finding_count.linearization_multiple", "finding_count.objstm_density_high", "finding_count.objstm_embedded_summary",
            "finding_count.objstm_action_chain", "finding_count.orphan_payload_object", "finding_count.shadow_payload_chain",
            "finding_count.decoder_risk_present", "finding_count.decompression_ratio_suspicious", "finding_count.filter_chain_depth_high",
            "finding_count.huge_image_dimensions", "finding_count.stream_length_mismatch", "finding_count.icc_profile_oversized",
            "finding_count.open_action_present", "finding_count.aa_present", "finding_count.aa_event_present",
            "finding_count.launch_action_present", "finding_count.gotor_present", "finding_count.uri_present",
            "finding_count.submitform_present", "finding_count.external_action_risk_context", "finding_count.js_present",
            "finding_count.js_polymorphic", "finding_count.js_obfuscation_deep", "finding_count.js_time_evasion",
            "finding_count.js_env_probe", "finding_count.js_multi_stage_decode", "finding_count.js_runtime_file_probe",
            "finding_count.js_runtime_network_intent", "finding_count.crypto_mining_js", "finding_count.js_sandbox_result",
            "finding_count.uri_content_analysis", "finding_count.uri_presence_summary", "finding_count.action_payload_path",
            "finding_count.acroform_present", "finding_count.xfa_present", "finding_count.embedded_file_present",
            "finding_count.richmedia_present", "finding_count.three_d_present", "finding_count.sound_movie_present",
            "finding_count.filespec_present", "finding_count.font_payload_present", "finding_count.fontmatrix_payload_present",
            "finding_count.encryption_present", "finding_count.signature_present", "finding_count.dss_present",
            "finding_count.crypto_weak_algo", "finding_count.quantum_vulnerable_crypto", "finding_count.content_phishing",
            "finding_count.content_html_payload", "finding_count.content_invisible_text", "finding_count.content_overlay_link",
            "finding_count.content_image_only_page", "finding_count.annotation_hidden", "finding_count.annotation_action_chain",
            "finding_count.annotation_attack", "finding_count.ocg_present", "finding_count.page_tree_cycle",
            "finding_count.page_tree_mismatch", "finding_count.page_tree_manipulation", "finding_count.supply_chain_persistence",
            "finding_count.supply_chain_staged_payload", "finding_count.supply_chain_update_vector",
        ].into_iter().map(|s| s.to_string()).collect()
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
            self.max_obfuscation_score, self.avg_obfuscation_score, self.total_eval_count,
            self.max_eval_count, self.unique_suspicious_apis, self.max_string_concat_layers,
            self.max_unescape_layers, self.max_decode_ratio, self.avg_entropy,
            self.max_entropy, self.time_evasion_present, self.env_probe_present,
            self.polymorphic_present, self.multi_stage_decode, self.sandbox_executed,
            self.sandbox_timeout, self.runtime_file_probe, self.runtime_network_intent,
            self.crypto_mining_detected, self.total_js_objects, self.max_js_size,
            self.avg_js_size, self.js_in_openaction, self.js_in_aa,
            self.js_in_annotation, self.js_in_field, self.fromcharcode_count,
            self.multiple_keys_present, self.ref_chain_depth, self.array_fragment_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "js_signals.max_obfuscation_score", "js_signals.avg_obfuscation_score", "js_signals.total_eval_count",
            "js_signals.max_eval_count", "js_signals.unique_suspicious_apis", "js_signals.max_string_concat_layers",
            "js_signals.max_unescape_layers", "js_signals.max_decode_ratio", "js_signals.avg_entropy",
            "js_signals.max_entropy", "js_signals.time_evasion_present", "js_signals.env_probe_present",
            "js_signals.polymorphic_present", "js_signals.multi_stage_decode", "js_signals.sandbox_executed",
            "js_signals.sandbox_timeout", "js_signals.runtime_file_probe", "js_signals.runtime_network_intent",
            "js_signals.crypto_mining_detected", "js_signals.total_js_objects", "js_signals.max_js_size",
            "js_signals.avg_js_size", "js_signals.js_in_openaction", "js_signals.js_in_aa",
            "js_signals.js_in_annotation", "js_signals.js_in_field", "js_signals.fromcharcode_count",
            "js_signals.multiple_keys_present", "js_signals.ref_chain_depth", "js_signals.array_fragment_count",
        ].into_iter().map(|s| s.to_string()).collect()
    }
}

// ============================================================================
// URI Signals (20 features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UriSignalFeatures {
    pub total_count: f32,
    pub unique_domains: f32,
    pub max_risk_score: f32,
    pub avg_risk_score: f32,
    pub javascript_uri_count: f32,
    pub file_uri_count: f32,
    pub http_count: f32,
    pub https_count: f32,
    pub ip_address_count: f32,
    pub suspicious_tld_count: f32,
    pub obfuscated_count: f32,
    pub data_exfil_pattern_count: f32,
    pub hidden_annotation_count: f32,
    pub automatic_trigger_count: f32,
    pub js_triggered_count: f32,
    pub tracking_params_count: f32,
    pub max_url_length: f32,
    pub phishing_indicators: f32,
    pub external_dependency_count: f32,
    pub mixed_content_present: f32,
}

impl UriSignalFeatures {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.total_count, self.unique_domains, self.max_risk_score,
            self.avg_risk_score, self.javascript_uri_count, self.file_uri_count,
            self.http_count, self.https_count, self.ip_address_count,
            self.suspicious_tld_count, self.obfuscated_count, self.data_exfil_pattern_count,
            self.hidden_annotation_count, self.automatic_trigger_count, self.js_triggered_count,
            self.tracking_params_count, self.max_url_length, self.phishing_indicators,
            self.external_dependency_count, self.mixed_content_present,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "uri_signals.total_count", "uri_signals.unique_domains", "uri_signals.max_risk_score",
            "uri_signals.avg_risk_score", "uri_signals.javascript_uri_count", "uri_signals.file_uri_count",
            "uri_signals.http_count", "uri_signals.https_count", "uri_signals.ip_address_count",
            "uri_signals.suspicious_tld_count", "uri_signals.obfuscated_count", "uri_signals.data_exfil_pattern_count",
            "uri_signals.hidden_annotation_count", "uri_signals.automatic_trigger_count", "uri_signals.js_triggered_count",
            "uri_signals.tracking_params_count", "uri_signals.max_url_length", "uri_signals.phishing_indicators",
            "uri_signals.external_dependency_count", "uri_signals.mixed_content_present",
        ].into_iter().map(|s| s.to_string()).collect()
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
            self.phishing_indicators, self.invisible_text_pages, self.overlay_link_count,
            self.image_only_pages, self.html_payload_present, self.hidden_annotation_count,
            self.suspicious_font_count, self.text_rendering_anomalies, self.color_manipulation_count,
            self.whitespace_abuse_count, self.unicode_rtlo_count, self.homoglyph_count,
            self.zero_width_char_count, self.text_direction_abuse, self.layer_manipulation_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "content_signals.phishing_indicators", "content_signals.invisible_text_pages", "content_signals.overlay_link_count",
            "content_signals.image_only_pages", "content_signals.html_payload_present", "content_signals.hidden_annotation_count",
            "content_signals.suspicious_font_count", "content_signals.text_rendering_anomalies", "content_signals.color_manipulation_count",
            "content_signals.whitespace_abuse_count", "content_signals.unicode_rtlo_count", "content_signals.homoglyph_count",
            "content_signals.zero_width_char_count", "content_signals.text_direction_abuse", "content_signals.layer_manipulation_count",
        ].into_iter().map(|s| s.to_string()).collect()
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
            self.persistence_mechanisms, self.staged_payload_count, self.update_vectors,
            self.multi_stage_chains, self.command_control_indicators, self.lateral_movement_indicators,
            self.data_staging_indicators, self.exfiltration_indicators, self.anti_forensics_techniques,
            self.defense_evasion_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "supply_chain.persistence_mechanisms", "supply_chain.staged_payload_count", "supply_chain.update_vectors",
            "supply_chain.multi_stage_chains", "supply_chain.command_control_indicators", "supply_chain.lateral_movement_indicators",
            "supply_chain.data_staging_indicators", "supply_chain.exfiltration_indicators", "supply_chain.anti_forensics_techniques",
            "supply_chain.defense_evasion_count",
        ].into_iter().map(|s| s.to_string()).collect()
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
            self.objstm_density, self.filter_chain_max_depth, self.decompression_max_ratio,
            self.page_tree_anomalies, self.linearization_anomalies, self.parser_deviations,
            self.xref_table_anomalies, self.trailer_anomalies, self.catalog_anomalies,
            self.object_stream_anomalies, self.cross_ref_stream_anomalies, self.incremental_update_count,
            self.conflicting_definitions, self.orphaned_objects, self.circular_references,
            self.invalid_object_refs, self.stream_dictionary_mismatch, self.unusual_object_sizes,
            self.object_id_gaps, self.generation_number_anomalies,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "structural_anomalies.objstm_density", "structural_anomalies.filter_chain_max_depth", "structural_anomalies.decompression_max_ratio",
            "structural_anomalies.page_tree_anomalies", "structural_anomalies.linearization_anomalies", "structural_anomalies.parser_deviations",
            "structural_anomalies.xref_table_anomalies", "structural_anomalies.trailer_anomalies", "structural_anomalies.catalog_anomalies",
            "structural_anomalies.object_stream_anomalies", "structural_anomalies.cross_ref_stream_anomalies", "structural_anomalies.incremental_update_count",
            "structural_anomalies.conflicting_definitions", "structural_anomalies.orphaned_objects", "structural_anomalies.circular_references",
            "structural_anomalies.invalid_object_refs", "structural_anomalies.stream_dictionary_mismatch", "structural_anomalies.unusual_object_sizes",
            "structural_anomalies.object_id_gaps", "structural_anomalies.generation_number_anomalies",
        ].into_iter().map(|s| s.to_string()).collect()
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
            self.encryption_present, self.signature_present, self.weak_algo_count,
            self.quantum_vulnerable, self.cert_anomalies, self.signature_validation_failed,
            self.timestamp_anomalies, self.revocation_check_failed, self.self_signed_cert,
            self.encryption_weakness_score,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "crypto_signals.encryption_present", "crypto_signals.signature_present", "crypto_signals.weak_algo_count",
            "crypto_signals.quantum_vulnerable", "crypto_signals.cert_anomalies", "crypto_signals.signature_validation_failed",
            "crypto_signals.timestamp_anomalies", "crypto_signals.revocation_check_failed", "crypto_signals.self_signed_cert",
            "crypto_signals.encryption_weakness_score",
        ].into_iter().map(|s| s.to_string()).collect()
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
            self.file_count, self.total_size, self.max_decode_ratio,
            self.pe_executable_count, self.encrypted_container_count, self.double_extension_count,
            self.richmedia_count, self.three_d_content_count, self.flash_content_count,
            self.suspicious_mime_types, self.mismatched_extensions, self.archive_count,
            self.nested_archive_depth, self.password_protected_count, self.macro_enabled_count,
        ]
    }

    pub fn feature_names() -> Vec<String> {
        vec![
            "embedded_content.file_count", "embedded_content.total_size", "embedded_content.max_decode_ratio",
            "embedded_content.pe_executable_count", "embedded_content.encrypted_container_count", "embedded_content.double_extension_count",
            "embedded_content.richmedia_count", "embedded_content.three_d_content_count", "embedded_content.flash_content_count",
            "embedded_content.suspicious_mime_types", "embedded_content.mismatched_extensions", "embedded_content.archive_count",
            "embedded_content.nested_archive_depth", "embedded_content.password_protected_count", "embedded_content.macro_enabled_count",
        ].into_iter().map(|s| s.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_feature_vector_dimensions() {
        let features = ExtendedFeatureVector::default();
        let vec = features.as_f32_vec();

        // 35 (legacy) + 11 (attack surfaces) + 15 (severity) + 9 (confidence) +
        // 70 (presence) + 70 (counts) + 30 (JS) + 20 (URI) + 15 (content) +
        // 10 (supply chain) + 20 (structural) + 10 (crypto) + 15 (embedded)
        // = 35 + 285 = 320
        assert_eq!(vec.len(), 320, "Expected 320 features, got {}", vec.len());
    }

    #[test]
    fn test_feature_names_match_values() {
        let names = ExtendedFeatureVector::feature_names();
        let features = ExtendedFeatureVector::default();
        let values = features.as_f32_vec();

        assert_eq!(names.len(), values.len(),
            "Feature names ({}) and values ({}) must match",
            names.len(), values.len());
        assert_eq!(names.len(), 320, "Expected 320 feature names");
    }

    #[test]
    fn test_to_named_map() {
        let features = ExtendedFeatureVector::default();
        let map = features.to_named_map();

        assert_eq!(map.len(), 320, "Named map should have 320 entries");
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
        assert_eq!(names.len(), 20, "URI signals should have 20 features");
        assert!(names.contains(&"uri_signals.total_count".to_string()));
    }

    #[test]
    fn test_finding_presence_feature_count() {
        let features = FindingPresenceFeatures::default();
        let vec = features.as_f32_vec();
        assert_eq!(vec.len(), 70, "Finding presence should have 70 features");
    }

    #[test]
    fn test_finding_count_feature_count() {
        let features = FindingCountFeatures::default();
        let vec = features.as_f32_vec();
        assert_eq!(vec.len(), 70, "Finding counts should have 70 features");
    }
}

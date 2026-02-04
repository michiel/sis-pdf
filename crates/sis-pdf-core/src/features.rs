use std::collections::{HashMap, HashSet};

use crate::crypto_analysis::classify_encryption_algorithm;
use crate::page_tree::build_page_tree;
use crate::rich_media::{analyze_swf, detect_media_format, SWF_DECODE_TIMEOUT_MS};
use crate::scan::{ScanContext, ScanOptions};
use crate::timeout::TimeoutChecker;
use image_analysis::ImageDynamicOptions;
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::decode::{decode_stream_with_meta, DecodeLimits};
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr, PdfStream};
use sis_pdf_pdf::path_finder::ActionChain;
use sis_pdf_pdf::typed_graph::EdgeType;
use sis_pdf_pdf::xfa::extract_xfa_script_payloads;
use sis_pdf_pdf::{parse_pdf, ParseOptions};
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GeneralFeatures {
    pub file_size: usize,
    pub file_entropy: f64,
    pub binary_ratio: f64,
    pub object_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct StructuralFeatures {
    pub startxref_count: usize,
    pub trailer_count: usize,
    pub objstm_count: usize,
    pub linearized_present: bool,
    pub max_object_id: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct BehavioralFeatures {
    pub action_count: usize,
    pub js_object_count: usize,
    pub js_entropy_avg: f64,
    pub js_eval_count: usize,
    pub js_suspicious_api_count: usize,
    pub time_api_count: usize,
    pub env_probe_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ContentFeatures {
    pub embedded_file_count: usize,
    pub embedded_executable_count: usize,
    pub embedded_script_count: usize,
    pub embedded_archive_count: usize,
    pub embedded_double_extension_count: usize,
    pub embedded_encrypted_count: usize,
    pub rich_media_count: usize,
    pub rich_media_swf_count: usize,
    pub rich_media_3d_count: usize,
    pub swf_count: usize,
    pub swf_actionscript_count: usize,
    pub media_3d_count: usize,
    pub media_audio_count: usize,
    pub media_video_count: usize,
    pub annotation_count: usize,
    pub page_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ImageFeatures {
    pub image_count: usize,
    pub jbig2_count: usize,
    pub jpx_count: usize,
    pub jpeg_count: usize,
    pub png_count: usize,
    pub ccitt_count: usize,
    pub risky_image_count: usize,
    pub malformed_image_count: usize,
    pub max_image_width: u32,
    pub max_image_height: u32,
    pub max_image_pixels: u64,
    pub total_image_pixels: u64,
    pub avg_image_entropy: f64,
    pub extreme_dimensions_count: usize,
    pub multi_filter_count: usize,
    pub xfa_image_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GraphFeatures {
    pub total_edges: usize,
    pub open_action_edges: usize,
    pub js_payload_edges: usize,
    pub uri_target_edges: usize,
    pub launch_target_edges: usize,
    pub suspicious_edge_count: usize,
    pub action_chain_count: usize,
    pub max_chain_length: usize,
    pub automatic_chain_count: usize,
    pub hidden_trigger_count: usize,
    pub user_trigger_count: usize,
    pub complex_chain_count: usize,
    pub js_chain_count: usize,
    pub external_chain_count: usize,
    pub max_graph_depth: usize,
    pub avg_graph_depth: f64,
    pub catalog_to_js_paths: usize,
    pub multi_stage_indicators: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct XfaFeatures {
    pub present: bool,
    pub payload_count: usize,
    pub script_count: usize,
    pub submit_url_count: usize,
    pub sensitive_field_count: usize,
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct EncryptionFeatures {
    pub encrypted: bool,
    pub encryption_algorithm: String,
    pub encryption_key_length: usize,
    pub high_entropy_stream_count: usize,
    pub avg_stream_entropy: f64,
    pub max_stream_entropy: f64,
    pub encrypted_embedded_file_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct FilterFeatures {
    pub filter_chain_count: usize,
    pub max_filter_chain_depth: usize,
    pub unusual_chain_count: usize,
    pub invalid_order_count: usize,
    pub duplicate_filter_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeatureVector {
    pub general: GeneralFeatures,
    pub structural: StructuralFeatures,
    pub behavioral: BehavioralFeatures,
    pub content: ContentFeatures,
    pub graph: GraphFeatures,
    pub images: ImageFeatures,
    pub xfa: XfaFeatures,
    pub encryption: EncryptionFeatures,
    pub filters: FilterFeatures,
}

impl FeatureVector {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.general.file_size as f32,
            self.general.file_entropy as f32,
            self.general.binary_ratio as f32,
            self.general.object_count as f32,
            self.structural.startxref_count as f32,
            self.structural.trailer_count as f32,
            self.structural.objstm_count as f32,
            bool_to_f32(self.structural.linearized_present),
            self.structural.max_object_id as f32,
            self.behavioral.action_count as f32,
            self.behavioral.js_object_count as f32,
            self.behavioral.js_entropy_avg as f32,
            self.behavioral.js_eval_count as f32,
            self.behavioral.js_suspicious_api_count as f32,
            self.behavioral.time_api_count as f32,
            self.behavioral.env_probe_count as f32,
            self.content.embedded_file_count as f32,
            self.content.rich_media_count as f32,
            self.content.annotation_count as f32,
            self.content.page_count as f32,
            self.graph.total_edges as f32,
            self.graph.open_action_edges as f32,
            self.graph.js_payload_edges as f32,
            self.graph.uri_target_edges as f32,
            self.graph.launch_target_edges as f32,
            self.graph.suspicious_edge_count as f32,
            self.graph.action_chain_count as f32,
            self.graph.max_chain_length as f32,
            self.graph.automatic_chain_count as f32,
            self.graph.hidden_trigger_count as f32,
            self.graph.user_trigger_count as f32,
            self.graph.complex_chain_count as f32,
            self.graph.js_chain_count as f32,
            self.graph.external_chain_count as f32,
            self.graph.max_graph_depth as f32,
            self.graph.avg_graph_depth as f32,
            self.graph.catalog_to_js_paths as f32,
            self.graph.multi_stage_indicators as f32,
            self.images.image_count as f32,
            self.images.jbig2_count as f32,
            self.images.jpx_count as f32,
            self.images.jpeg_count as f32,
            self.images.png_count as f32,
            self.images.ccitt_count as f32,
            self.images.risky_image_count as f32,
            self.images.malformed_image_count as f32,
            self.images.max_image_width as f32,
            self.images.max_image_height as f32,
            self.images.max_image_pixels as f32,
            self.images.total_image_pixels as f32,
            self.images.avg_image_entropy as f32,
            self.images.extreme_dimensions_count as f32,
            self.images.multi_filter_count as f32,
            self.images.xfa_image_count as f32,
            // New features appended for backward compatibility.
            self.content.embedded_executable_count as f32,
            self.content.embedded_script_count as f32,
            self.content.embedded_archive_count as f32,
            self.content.embedded_double_extension_count as f32,
            self.content.embedded_encrypted_count as f32,
            self.content.rich_media_swf_count as f32,
            self.content.rich_media_3d_count as f32,
            self.content.swf_count as f32,
            self.content.swf_actionscript_count as f32,
            self.content.media_3d_count as f32,
            self.content.media_audio_count as f32,
            self.content.media_video_count as f32,
            bool_to_f32(self.xfa.present),
            self.xfa.payload_count as f32,
            self.xfa.script_count as f32,
            self.xfa.submit_url_count as f32,
            self.xfa.sensitive_field_count as f32,
            self.xfa.max_payload_bytes as f32,
            bool_to_f32(self.encryption.encrypted),
            self.encryption.encryption_key_length as f32,
            self.encryption.high_entropy_stream_count as f32,
            self.encryption.avg_stream_entropy as f32,
            self.encryption.max_stream_entropy as f32,
            self.encryption.encrypted_embedded_file_count as f32,
            self.filters.filter_chain_count as f32,
            self.filters.max_filter_chain_depth as f32,
            self.filters.unusual_chain_count as f32,
            self.filters.invalid_order_count as f32,
            self.filters.duplicate_filter_count as f32,
        ]
    }
}

pub fn feature_names() -> Vec<&'static str> {
    vec![
        "general.file_size",
        "general.file_entropy",
        "general.binary_ratio",
        "general.object_count",
        "structural.startxref_count",
        "structural.trailer_count",
        "structural.objstm_count",
        "structural.linearized_present",
        "structural.max_object_id",
        "behavior.action_count",
        "behavior.js_object_count",
        "behavior.js_entropy_avg",
        "behavior.js_eval_count",
        "behavior.js_suspicious_api_count",
        "behavior.time_api_count",
        "behavior.env_probe_count",
        "content.embedded_file_count",
        "content.rich_media_count",
        "content.annotation_count",
        "content.page_count",
        "graph.total_edges",
        "graph.open_action_edges",
        "graph.js_payload_edges",
        "graph.uri_target_edges",
        "graph.launch_target_edges",
        "graph.suspicious_edge_count",
        "graph.action_chain_count",
        "graph.max_chain_length",
        "graph.automatic_chain_count",
        "graph.hidden_trigger_count",
        "graph.user_trigger_count",
        "graph.complex_chain_count",
        "graph.js_chain_count",
        "graph.external_chain_count",
        "graph.max_graph_depth",
        "graph.avg_graph_depth",
        "graph.catalog_to_js_paths",
        "graph.multi_stage_indicators",
        "images.image_count",
        "images.jbig2_count",
        "images.jpx_count",
        "images.jpeg_count",
        "images.png_count",
        "images.ccitt_count",
        "images.risky_image_count",
        "images.malformed_image_count",
        "images.max_image_width",
        "images.max_image_height",
        "images.max_image_pixels",
        "images.total_image_pixels",
        "images.avg_image_entropy",
        "images.extreme_dimensions_count",
        "images.multi_filter_count",
        "images.xfa_image_count",
        "content.embedded_executable_count",
        "content.embedded_script_count",
        "content.embedded_archive_count",
        "content.embedded_double_extension_count",
        "content.embedded_encrypted_count",
        "content.rich_media_swf_count",
        "content.rich_media_3d_count",
        "content.swf_count",
        "content.swf_actionscript_count",
        "content.media_3d_count",
        "content.media_audio_count",
        "content.media_video_count",
        "xfa.present",
        "xfa.payload_count",
        "xfa.script_count",
        "xfa.submit_url_count",
        "xfa.sensitive_field_count",
        "xfa.max_payload_bytes",
        "encryption.encrypted",
        "encryption.encryption_key_length",
        "encryption.high_entropy_stream_count",
        "encryption.avg_stream_entropy",
        "encryption.max_stream_entropy",
        "encryption.encrypted_embedded_file_count",
        "filters.filter_chain_count",
        "filters.max_filter_chain_depth",
        "filters.unusual_chain_count",
        "filters.invalid_order_count",
        "filters.duplicate_filter_count",
    ]
}

pub struct FeatureExtractor;

impl FeatureExtractor {
    pub fn extract(ctx: &ScanContext) -> FeatureVector {
        let graph = &ctx.graph;
        let bytes = ctx.bytes;
        let file_entropy = shannon_entropy(bytes);
        let binary_ratio = binary_ratio(bytes);
        let max_object_id = graph.objects.iter().map(|e| e.obj).max().unwrap_or(0);

        let objstm_count = graph
            .objects
            .iter()
            .filter(|e| {
                entry_dict(e)
                    .map(|d| d.has_name(b"/Type", b"/ObjStm"))
                    .unwrap_or(false)
            })
            .count();

        let linearized_present = graph.objects.iter().any(|e| {
            entry_dict(e)
                .and_then(|d| d.get_first(b"/Linearized"))
                .is_some()
        });

        let mut action_count = 0usize;
        let mut js_object_count = 0usize;
        let mut embedded_file_count = 0usize;
        let mut embedded_executable_count = 0usize;
        let mut embedded_script_count = 0usize;
        let mut embedded_archive_count = 0usize;
        let mut embedded_double_extension_count = 0usize;
        let mut embedded_encrypted_count = 0usize;
        let mut rich_media_count = 0usize;
        let mut rich_media_swf_count = 0usize;
        let mut rich_media_3d_count = 0usize;
        let mut swf_count = 0usize;
        let mut swf_actionscript_count = 0usize;
        let mut media_audio_count = 0usize;
        let mut media_video_count = 0usize;
        let mut annotation_count = 0usize;
        let mut js_payloads = Vec::new();

        for entry in &graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if let Some((_, s)) = dict.get_first(b"/S") {
                    if let Some(name) = name_bytes(s) {
                        if name.eq_ignore_ascii_case(b"/JavaScript")
                            || name.eq_ignore_ascii_case(b"/Launch")
                            || name.eq_ignore_ascii_case(b"/URI")
                            || name.eq_ignore_ascii_case(b"/GoToR")
                            || name.eq_ignore_ascii_case(b"/SubmitForm")
                        {
                            action_count += 1;
                        }
                    }
                }
                if dict.get_first(b"/JS").is_some() || dict.has_name(b"/S", b"/JavaScript") {
                    js_object_count += 1;
                    if let Some((_, obj)) = dict.get_first(b"/JS") {
                        if let Some(bytes) = resolve_obj_bytes(ctx, obj, 512 * 1024) {
                            js_payloads.push(bytes);
                        }
                    }
                }
                let is_embedded = dict.has_name(b"/Type", b"/Filespec")
                    || dict.has_name(b"/Type", b"/EmbeddedFile")
                    || dict.get_first(b"/EF").is_some();
                if is_embedded {
                    embedded_file_count += 1;
                    if let Some(name) = embedded_filename(dict) {
                        if has_double_extension(&name) {
                            embedded_double_extension_count += 1;
                        }
                    }
                    if let Some(bytes) = stream_bytes(ctx, entry, 1024 * 1024) {
                        let analysis = crate::stream_analysis::analyse_stream(
                            &bytes,
                            &crate::stream_analysis::StreamLimits::default(),
                        );
                        match analysis.magic_type.as_str() {
                            "pe" | "elf" | "macho" => embedded_executable_count += 1,
                            "script" => embedded_script_count += 1,
                            "zip" => {
                                embedded_archive_count += 1;
                                if zip_has_encryption_flag(&bytes) {
                                    embedded_encrypted_count += 1;
                                }
                            }
                            _ => {}
                        }
                        if stream_has_crypt_filter(dict) {
                            embedded_encrypted_count += 1;
                        }
                    }
                }

                let is_rich_media = dict.has_name(b"/Subtype", b"/RichMedia")
                    || dict.has_name(b"/Type", b"/RichMedia")
                    || dict.has_name(b"/Subtype", b"/3D")
                    || dict.has_name(b"/Subtype", b"/Sound")
                    || dict.has_name(b"/Subtype", b"/Movie");
                if is_rich_media {
                    rich_media_count += 1;
                    if dict.has_name(b"/Subtype", b"/3D")
                        || dict.has_name(b"/Subtype", b"/U3D")
                        || dict.has_name(b"/Subtype", b"/PRC")
                    {
                        rich_media_3d_count += 1;
                    }
                    if let Some(bytes) = stream_bytes(ctx, entry, 1024 * 1024) {
                        if swf_magic_label(&bytes).is_some() {
                            rich_media_swf_count += 1;
                            swf_count += 1;
                            let mut timeout =
                                TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
                            if let Some(analysis) = analyze_swf(&bytes, &mut timeout) {
                                if !analysis.action_scan.action_tags.is_empty()
                                    || analysis.action_scan.tags_scanned > 0
                                {
                                    swf_actionscript_count += 1;
                                }
                            }
                        }
                    }
                }
                let has_sound_movie = dict.has_name(b"/Subtype", b"/Sound")
                    || dict.has_name(b"/Subtype", b"/Movie")
                    || dict.get_first(b"/Sound").is_some()
                    || dict.get_first(b"/Movie").is_some()
                    || dict.get_first(b"/Rendition").is_some();
                if has_sound_movie {
                    if let Some(bytes) = stream_bytes(ctx, entry, 1024 * 1024) {
                        if let Some(media_format) = detect_media_format(&bytes) {
                            match media_format {
                                "mp3" => media_audio_count += 1,
                                "mp4" => media_video_count += 1,
                                _ => {}
                            }
                        }
                    }
                }
                if dict.get_first(b"/Subtype").is_some() && dict.get_first(b"/Rect").is_some() {
                    annotation_count += 1;
                }
            }
        }

        let (
            js_entropy_avg,
            js_eval_count,
            js_suspicious_api_count,
            time_api_count,
            env_probe_count,
        ) = summarize_js_payloads(&js_payloads);

        let page_count = build_page_tree(graph).pages.len();

        let image_features = extract_image_features(ctx);

        // Extract graph-based features using TypedGraph infrastructure
        let graph_features = extract_graph_features(ctx);
        let xfa_features = extract_xfa_features(ctx);
        let encryption_features = extract_encryption_features(ctx);
        let filter_features = extract_filter_features(ctx);

        FeatureVector {
            general: GeneralFeatures {
                file_size: bytes.len(),
                file_entropy,
                binary_ratio,
                object_count: graph.objects.len(),
            },
            structural: StructuralFeatures {
                startxref_count: graph.startxrefs.len(),
                trailer_count: graph.trailers.len(),
                objstm_count,
                linearized_present,
                max_object_id,
            },
            behavioral: BehavioralFeatures {
                action_count,
                js_object_count,
                js_entropy_avg,
                js_eval_count,
                js_suspicious_api_count,
                time_api_count,
                env_probe_count,
            },
            content: ContentFeatures {
                embedded_file_count,
                embedded_executable_count,
                embedded_script_count,
                embedded_archive_count,
                embedded_double_extension_count,
                embedded_encrypted_count,
                rich_media_count,
                rich_media_swf_count,
                rich_media_3d_count,
                swf_count,
                swf_actionscript_count,
                media_3d_count: rich_media_3d_count,
                media_audio_count,
                media_video_count,
                annotation_count,
                page_count,
            },
            graph: graph_features,
            images: image_features,
            xfa: xfa_features,
            encryption: encryption_features,
            filters: filter_features,
        }
    }

    pub fn extract_from_bytes(bytes: &[u8], opts: &ScanOptions) -> anyhow::Result<FeatureVector> {
        let graph = parse_pdf(
            bytes,
            ParseOptions {
                recover_xref: opts.recover_xref,
                deep: opts.deep,
                strict: opts.strict,
                max_objstm_bytes: opts.max_decode_bytes,
                max_objects: opts.max_objects,
                max_objstm_total_bytes: opts.max_total_decoded_bytes,
                carve_stream_objects: false,
                max_carved_objects: 0,
                max_carved_bytes: 0,
            },
        )?;
        let ctx = ScanContext::new(bytes, graph, opts.clone());
        Ok(Self::extract(&ctx))
    }
}

fn bool_to_f32(v: bool) -> f32 {
    if v {
        1.0
    } else {
        0.0
    }
}

fn entry_dict<'a>(entry: &'a ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn embedded_filename(dict: &PdfDict<'_>) -> Option<String> {
    if let Some((_, obj)) = dict.get_first(b"/F") {
        if let PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    if let Some((_, obj)) = dict.get_first(b"/UF") {
        if let PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    None
}

fn has_double_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let last = parts[parts.len() - 1];
    let prev = parts[parts.len() - 2];
    let suspicious = ["exe", "scr", "js", "vbs", "bat", "cmd", "com", "ps1"];
    let common = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "zip",
    ];
    suspicious.contains(&last) && common.contains(&prev)
}

fn zip_has_encryption_flag(bytes: &[u8]) -> bool {
    if bytes.len() < 8 || !bytes.starts_with(b"PK\x03\x04") {
        return false;
    }
    let flag = u16::from_le_bytes([bytes[6], bytes[7]]);
    (flag & 0x0001) != 0
}

fn stream_has_crypt_filter(dict: &PdfDict<'_>) -> bool {
    use sis_pdf_pdf::object::PdfAtom;

    let filter_obj = dict.get_first(b"/Filter").map(|(_, obj)| obj);
    match filter_obj.map(|obj| &obj.atom) {
        Some(PdfAtom::Name(name)) => name.decoded == b"/Crypt",
        Some(PdfAtom::Array(items)) => items
            .iter()
            .any(|item| matches!(&item.atom, PdfAtom::Name(name) if name.decoded == b"/Crypt")),
        _ => false,
    }
}

fn stream_bytes(ctx: &ScanContext, entry: &ObjEntry<'_>, max_len: usize) -> Option<Vec<u8>> {
    let PdfAtom::Stream(stream) = &entry.atom else {
        return None;
    };
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > ctx.bytes.len() {
        return None;
    }
    let data = &ctx.bytes[start..end];
    let len = data.len().min(max_len);
    Some(data[..len].to_vec())
}

fn swf_magic_label(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"FWS") {
        Some("FWS")
    } else if bytes.starts_with(b"CWS") {
        Some("CWS")
    } else if bytes.starts_with(b"ZWS") {
        Some("ZWS")
    } else {
        None
    }
}

fn name_bytes<'a>(obj: &'a PdfObj<'a>) -> Option<&'a [u8]> {
    match &obj.atom {
        PdfAtom::Name(n) => Some(&n.decoded),
        _ => None,
    }
}

fn resolve_obj_bytes(ctx: &ScanContext, obj: &PdfObj<'_>, max_len: usize) -> Option<Vec<u8>> {
    match &obj.atom {
        PdfAtom::Str(s) => Some(string_bytes(s)),
        PdfAtom::Stream(st) => decoded_stream_bytes(ctx, st, max_len),
        PdfAtom::Ref { .. } => {
            let entry = ctx.graph.resolve_ref(obj)?;
            match &entry.atom {
                PdfAtom::Str(s) => Some(string_bytes(s)),
                PdfAtom::Stream(st) => decoded_stream_bytes(ctx, st, max_len),
                _ => None,
            }
        }
        _ => None,
    }
}

fn decoded_stream_bytes(ctx: &ScanContext, st: &PdfStream<'_>, max_len: usize) -> Option<Vec<u8>> {
    match ctx.decoded.get_or_decode(ctx.bytes, st) {
        Ok(decoded) => Some(decoded.data.into_iter().take(max_len).collect()),
        Err(_) => None,
    }
}

fn string_bytes(s: &PdfStr<'_>) -> Vec<u8> {
    match s {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn summarize_js_payloads(payloads: &[Vec<u8>]) -> (f64, usize, usize, usize, usize) {
    if payloads.is_empty() {
        return (0.0, 0, 0, 0, 0);
    }
    let mut ent_total = 0.0;
    let mut eval_count = 0usize;
    let mut suspicious_api_count = 0usize;
    let mut time_api_count = 0usize;
    let mut env_probe_count = 0usize;

    for data in payloads {
        ent_total += shannon_entropy(data);
        if contains_token(data, b"eval") {
            eval_count += 1;
        }
        if contains_any(
            data,
            &[
                b"app.launchURL",
                b"submitForm",
                b"getURL",
                b"app.execMenuItem",
            ],
        ) {
            suspicious_api_count += 1;
        }
        if contains_any(
            data,
            &[b"setTimeout", b"setInterval", b"Date(", b"performance.now"],
        ) {
            time_api_count += 1;
        }
        if contains_any(
            data,
            &[
                b"app.viewerType",
                b"app.viewerVersion",
                b"app.platform",
                b"navigator.userAgent",
                b"screen.height",
                b"screen.width",
            ],
        ) {
            env_probe_count += 1;
        }
    }

    let avg_entropy = ent_total / payloads.len() as f64;
    (
        avg_entropy,
        eval_count,
        suspicious_api_count,
        time_api_count,
        env_probe_count,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageFormat {
    JBIG2,
    JPX,
    JPEG,
    PNG,
    CCITT,
    TIFF,
    Unknown,
}

fn extract_image_features(ctx: &ScanContext) -> ImageFeatures {
    let mut features = ImageFeatures::default();
    let mut entropy_total = 0.0;
    let mut entropy_count = 0usize;

    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        if !is_image_xobject(dict) {
            continue;
        }
        features.image_count += 1;
        let format = detect_image_format(ctx, entry, dict);
        match format {
            ImageFormat::JBIG2 => {
                features.jbig2_count += 1;
                features.risky_image_count += 1;
            }
            ImageFormat::JPX => {
                features.jpx_count += 1;
                features.risky_image_count += 1;
            }
            ImageFormat::JPEG => features.jpeg_count += 1,
            ImageFormat::PNG => features.png_count += 1,
            ImageFormat::CCITT => {
                features.ccitt_count += 1;
                features.risky_image_count += 1;
            }
            ImageFormat::TIFF => {}
            ImageFormat::Unknown => {}
        }

        if has_multi_filter(dict) {
            features.multi_filter_count += 1;
        }

        if let Some((width, height)) = image_dimensions(dict) {
            features.max_image_width = features.max_image_width.max(width);
            features.max_image_height = features.max_image_height.max(height);
            let pixels = width as u64 * height as u64;
            features.max_image_pixels = features.max_image_pixels.max(pixels);
            features.total_image_pixels += pixels;
            if width == 1 || height == 1 {
                features.extreme_dimensions_count += 1;
            }
        }

        if let Some(data) = image_stream_bytes(ctx, entry, 512 * 1024) {
            entropy_total += shannon_entropy(&data);
            entropy_count += 1;
        }
    }

    if entropy_count > 0 {
        features.avg_image_entropy = entropy_total / entropy_count as f64;
    }

    features.xfa_image_count = count_xfa_images(ctx);
    features.malformed_image_count = count_malformed_images(ctx);

    features
}

fn is_image_xobject(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Subtype", b"/Image")
}

fn image_dimensions(dict: &PdfDict<'_>) -> Option<(u32, u32)> {
    let width = dict_u32(dict, b"/Width")?;
    let height = dict_u32(dict, b"/Height")?;
    Some((width, height))
}

fn dict_u32(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(v) => (*v).try_into().ok(),
        PdfAtom::Real(v) => {
            if *v >= 0.0 {
                (*v as u64).try_into().ok()
            } else {
                None
            }
        }
        PdfAtom::Str(s) => {
            let bytes = string_bytes(s);
            let text = String::from_utf8_lossy(&bytes);
            text.trim().parse::<u32>().ok()
        }
        _ => None,
    }
}

fn has_multi_filter(dict: &PdfDict<'_>) -> bool {
    let Some((_, filter)) = dict.get_first(b"/Filter") else {
        return false;
    };
    match &filter.atom {
        PdfAtom::Array(values) => values.len() > 1,
        _ => false,
    }
}

fn detect_image_format(ctx: &ScanContext, entry: &ObjEntry<'_>, dict: &PdfDict<'_>) -> ImageFormat {
    if let Some(filters) = image_filters(dict) {
        for filter in filters {
            if filter.eq_ignore_ascii_case(b"/JBIG2Decode") {
                return ImageFormat::JBIG2;
            }
            if filter.eq_ignore_ascii_case(b"/JPXDecode") {
                return ImageFormat::JPX;
            }
            if filter.eq_ignore_ascii_case(b"/CCITTFaxDecode") {
                return ImageFormat::CCITT;
            }
            if filter.eq_ignore_ascii_case(b"/DCTDecode") || filter.eq_ignore_ascii_case(b"/DCT") {
                return ImageFormat::JPEG;
            }
        }
    }
    if let Some(data) = image_stream_bytes(ctx, entry, 64) {
        if data.starts_with(b"\xFF\xD8") {
            return ImageFormat::JPEG;
        }
        if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            return ImageFormat::PNG;
        }
        if data.starts_with(b"II*\x00") || data.starts_with(b"MM\x00*") {
            return ImageFormat::TIFF;
        }
    }
    ImageFormat::Unknown
}

fn image_filters(dict: &PdfDict<'_>) -> Option<Vec<Vec<u8>>> {
    let (_, filter) = dict.get_first(b"/Filter")?;
    match &filter.atom {
        PdfAtom::Name(name) => Some(vec![name.decoded.clone()]),
        PdfAtom::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                if let PdfAtom::Name(name) = &item.atom {
                    out.push(name.decoded.clone());
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn image_stream_bytes(ctx: &ScanContext, entry: &ObjEntry<'_>, max_len: usize) -> Option<Vec<u8>> {
    let PdfAtom::Stream(stream) = &entry.atom else {
        return None;
    };
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > ctx.bytes.len() {
        return None;
    }
    let data = &ctx.bytes[start..end];
    if max_len > 0 {
        Some(data[..data.len().min(max_len)].to_vec())
    } else {
        Some(data.to_vec())
    }
}

fn count_xfa_images(ctx: &ScanContext) -> usize {
    let mut count = 0usize;
    let limits = DecodeLimits {
        max_decoded_bytes: ctx.options.image_analysis.max_xfa_decode_bytes,
        max_filter_chain_depth: ctx.options.image_analysis.max_filter_chain_depth,
    };
    for entry in &ctx.graph.objects {
        let dict = match &entry.atom {
            PdfAtom::Dict(dict) => dict,
            PdfAtom::Stream(stream) => &stream.dict,
            _ => continue,
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        for payload in xfa_payloads_from_obj(&ctx.graph, xfa_obj, limits) {
            count += sis_pdf_pdf::xfa::extract_xfa_image_payloads(&payload).len();
        }
    }
    count
}

fn count_malformed_images(ctx: &ScanContext) -> usize {
    if !ctx.options.image_analysis.enabled
        || !ctx.options.deep
        || !ctx.options.image_analysis.dynamic_enabled
    {
        return 0;
    }
    let opts = ImageDynamicOptions {
        max_pixels: ctx.options.image_analysis.max_pixels,
        max_decode_bytes: ctx.options.image_analysis.max_decode_bytes,
        timeout_ms: ctx.options.image_analysis.timeout_ms,
        total_budget_ms: ctx.options.image_analysis.total_budget_ms,
        skip_threshold: ctx.options.image_analysis.skip_threshold,
    };
    let dynamic = image_analysis::dynamic::analyze_dynamic_images(&ctx.graph, &opts);
    dynamic
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind.as_str(),
                "image.decode_failed"
                    | "image.jbig2_malformed"
                    | "image.jpx_malformed"
                    | "image.jpeg_malformed"
                    | "image.ccitt_malformed"
                    | "image.xfa_decode_failed"
            )
        })
        .count()
}

fn extract_xfa_features(ctx: &ScanContext) -> XfaFeatures {
    let mut features = XfaFeatures::default();
    let limits = DecodeLimits {
        max_decoded_bytes: ctx.options.image_analysis.max_xfa_decode_bytes,
        max_filter_chain_depth: ctx.options.image_analysis.max_filter_chain_depth,
    };
    let mut submit_urls = HashSet::new();
    let mut sensitive_fields = HashSet::new();
    for entry in &ctx.graph.objects {
        let dict = match &entry.atom {
            PdfAtom::Dict(dict) => dict,
            PdfAtom::Stream(stream) => &stream.dict,
            _ => continue,
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        features.present = true;
        for payload in xfa_payloads_from_obj(&ctx.graph, xfa_obj, limits) {
            features.payload_count += 1;
            features.max_payload_bytes = features.max_payload_bytes.max(payload.len());
            features.script_count += extract_xfa_script_payloads(&payload).len();
            let lower = String::from_utf8_lossy(&payload).to_ascii_lowercase();
            for url in find_submit_urls(&lower, 10) {
                submit_urls.insert(url);
            }
            for name in find_field_names(&lower, 50) {
                if is_sensitive_field(&name) {
                    sensitive_fields.insert(name);
                }
            }
        }
    }
    features.submit_url_count = submit_urls.len();
    features.sensitive_field_count = sensitive_fields.len();
    features
}

fn xfa_payloads_from_obj(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    obj: &PdfObj<'_>,
    limits: DecodeLimits,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Array(items) => {
            let mut iter = items.iter().peekable();
            while let Some(item) = iter.next() {
                match &item.atom {
                    PdfAtom::Name(_) | PdfAtom::Str(_) => {
                        if let Some(next) = iter.next() {
                            out.extend(resolve_xfa_payload(graph, next, limits));
                        }
                    }
                    _ => {
                        out.extend(resolve_xfa_payload(graph, item, limits));
                    }
                }
            }
        }
        _ => out.extend(resolve_xfa_payload(graph, obj, limits)),
    }
    out
}

fn resolve_xfa_payload(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    obj: &PdfObj<'_>,
    limits: DecodeLimits,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Str(s) => out.push(string_bytes(s)),
        PdfAtom::Stream(stream) => {
            let result = decode_stream_with_meta(graph.bytes, stream, limits);
            if let Some(data) = result.data {
                out.push(data);
            }
        }
        PdfAtom::Ref { .. } => {
            if let Some(entry) = graph.resolve_ref(obj) {
                match &entry.atom {
                    PdfAtom::Stream(stream) => {
                        let result = decode_stream_with_meta(graph.bytes, stream, limits);
                        if let Some(data) = result.data {
                            out.push(data);
                        }
                    }
                    PdfAtom::Str(s) => out.push(string_bytes(s)),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}

fn extract_encryption_features(ctx: &ScanContext) -> EncryptionFeatures {
    let mut features = EncryptionFeatures::default();
    for trailer in &ctx.graph.trailers {
        if let Some((_, encrypt_obj)) = trailer.get_first(b"/Encrypt") {
            if let Some(dict) = resolve_encrypt_dict(&ctx.graph, encrypt_obj) {
                features.encrypted = true;
                let version = dict_int(&dict, b"/V").map(|v| v as u32);
                let length_raw = dict_int(&dict, b"/Length");
                let key_length = length_raw.map(|v| v as usize);
                let key_len_for_algo = length_raw.map(|v| v as u32);
                let algorithm = classify_encryption_algorithm(version, key_len_for_algo);
                if let Some(len) = key_length {
                    features.encryption_key_length = len;
                }
                if let Some(algo) = algorithm {
                    features.encryption_algorithm = algo.to_string();
                }
            }
        }
    }

    let mut entropy_total = 0.0;
    let mut entropy_count = 0usize;
    let mut max_entropy = 0.0;

    for entry in &ctx.graph.objects {
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let data = match ctx.decoded.get_or_decode(ctx.bytes, stream) {
            Ok(decoded) => decoded.data,
            Err(_) => {
                let span = stream.data_span;
                let start = span.start as usize;
                let end = span.end as usize;
                if start >= end || end > ctx.bytes.len() {
                    continue;
                }
                ctx.bytes[start..end].to_vec()
            }
        };
        let analysis = crate::stream_analysis::analyse_stream(
            &data,
            &crate::stream_analysis::StreamLimits::default(),
        );
        entropy_total += analysis.entropy;
        entropy_count += 1;
        if analysis.entropy > max_entropy {
            max_entropy = analysis.entropy;
        }
        if analysis.entropy >= crate::stream_analysis::STREAM_HIGH_ENTROPY_THRESHOLD {
            features.high_entropy_stream_count += 1;
            if stream.dict.has_name(b"/Type", b"/EmbeddedFile") && analysis.magic_type == "unknown"
            {
                features.encrypted_embedded_file_count += 1;
            }
        }
    }

    if entropy_count > 0 {
        features.avg_stream_entropy = entropy_total / entropy_count as f64;
        features.max_stream_entropy = max_entropy;
    }

    if features.encrypted && entropy_count == 0 {
        features.high_entropy_stream_count = 1;
        features.avg_stream_entropy = crate::stream_analysis::STREAM_HIGH_ENTROPY_THRESHOLD;
        features.max_stream_entropy = crate::stream_analysis::STREAM_HIGH_ENTROPY_THRESHOLD;
    }

    features
}

fn extract_filter_features(ctx: &ScanContext) -> FilterFeatures {
    use sis_pdf_pdf::decode::stream_filters;

    let mut features = FilterFeatures::default();
    for entry in &ctx.graph.objects {
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let filters = stream_filters(&stream.dict);
        if filters.is_empty() {
            continue;
        }
        features.filter_chain_count += 1;
        let normalised: Vec<String> = filters
            .iter()
            .map(|f| f.trim_start_matches('/').to_string())
            .collect();
        features.max_filter_chain_depth = features.max_filter_chain_depth.max(normalised.len());
        if is_unusual_chain(&normalised) {
            features.unusual_chain_count += 1;
        }
        if has_invalid_order(&normalised) {
            features.invalid_order_count += 1;
        }
        if has_duplicate_filters(&normalised) {
            features.duplicate_filter_count += 1;
        }
    }
    features
}

fn resolve_encrypt_dict<'a>(
    graph: &'a sis_pdf_pdf::ObjectGraph<'a>,
    obj: &'a PdfObj<'a>,
) -> Option<PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(dict) => Some(dict.clone()),
        PdfAtom::Ref { obj, gen } => {
            graph
                .get_object(*obj, *gen)
                .and_then(|entry| match &entry.atom {
                    PdfAtom::Dict(dict) => Some(dict.clone()),
                    _ => None,
                })
        }
        _ => None,
    }
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<i64> {
    dict.get_first(key).and_then(|(_, obj)| match obj.atom {
        PdfAtom::Int(value) => Some(value),
        _ => None,
    })
}

fn is_unusual_chain(filters: &[String]) -> bool {
    if filters.len() >= 3 {
        return true;
    }
    filters.iter().any(|f| !KNOWN_FILTERS.contains(&f.as_str()))
}

fn has_invalid_order(filters: &[String]) -> bool {
    for (idx, f) in filters.iter().enumerate() {
        if is_ascii_filter(f) && idx != 0 {
            return true;
        }
    }
    false
}

fn has_duplicate_filters(filters: &[String]) -> bool {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in filters {
        *counts.entry(f.as_str()).or_insert(0) += 1;
    }
    counts.values().any(|v| *v > 1)
}

fn is_ascii_filter(filter: &str) -> bool {
    matches!(filter, "ASCIIHexDecode" | "ASCII85Decode")
}

const KNOWN_FILTERS: &[&str] = &[
    "FlateDecode",
    "DCTDecode",
    "JPXDecode",
    "LZWDecode",
    "ASCII85Decode",
    "ASCIIHexDecode",
    "CCITTFaxDecode",
    "RunLengthDecode",
    "Crypt",
];

fn find_submit_urls(input: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for tag in find_tag_blocks(input, "submit", limit) {
        if let Some(url) = extract_attr_value(&tag, "url") {
            out.push(url);
        } else if let Some(url) = extract_attr_value(&tag, "target") {
            out.push(url);
        }
    }
    out
}

fn find_field_names(input: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for tag in find_tag_blocks(input, "field", limit) {
        if let Some(name) = extract_attr_value(&tag, "name") {
            out.push(name);
        }
    }
    out
}

fn find_tag_blocks(input: &str, tag: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("<{}", tag);
    let mut idx = 0usize;
    while let Some(pos) = input[idx..].find(&needle) {
        let start = idx + pos;
        let Some(end) = input[start..].find('>') else {
            break;
        };
        let tag_block = &input[start..start + end + 1];
        out.push(tag_block.to_string());
        idx = start + end + 1;
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn extract_attr_value(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=", attr);
    let pos = tag.find(&needle)?;
    let rest = &tag[pos + needle.len()..];
    let rest = rest.trim_start();
    let quote = rest.chars().next()?;
    let rest = rest.trim_start_matches(quote);
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["password", "passwd", "ssn", "credit", "card", "cvv", "pin"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn contains_any(data: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|n| contains_token(data, n))
}

fn contains_token(data: &[u8], token: &[u8]) -> bool {
    data.windows(token.len()).any(|w| w == token)
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        ent -= p * p.log2();
    }
    ent
}

fn binary_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let binary = data
        .iter()
        .filter(|&&b| !(b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b)))
        .count();
    binary as f64 / data.len() as f64
}

/// Extract graph-based features using TypedGraph and PathFinder infrastructure
fn extract_graph_features(ctx: &ScanContext) -> GraphFeatures {
    // Build typed graph and get classifications
    let typed_graph = ctx.build_typed_graph();
    let classifications = ctx.classifications();

    // Count edges by type
    let total_edges = typed_graph.edges.len();
    let mut open_action_edges = 0;
    let mut js_payload_edges = 0;
    let mut uri_target_edges = 0;
    let mut launch_target_edges = 0;
    let mut suspicious_edge_count = 0;

    for edge in &typed_graph.edges {
        if edge.suspicious {
            suspicious_edge_count += 1;
        }
        match edge.edge_type {
            EdgeType::OpenAction => open_action_edges += 1,
            EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames => js_payload_edges += 1,
            EdgeType::UriTarget => uri_target_edges += 1,
            EdgeType::LaunchTarget => launch_target_edges += 1,
            _ => {}
        }
    }

    // Analyze action chains using PathFinder
    let path_finder = typed_graph.path_finder();
    let chains = path_finder.find_all_action_chains();

    const ACTION_CHAIN_COMPLEX_THRESHOLD: usize = 3;
    let action_chain_count = chains.len();
    let max_chain_length = chains.iter().map(|c| c.length()).max().unwrap_or(0);
    let automatic_chain_count = chains.iter().filter(|c| c.automatic).count();
    let mut hidden_trigger_count = 0usize;
    let mut user_trigger_count = 0usize;
    let mut complex_chain_count = 0usize;
    for chain in &chains {
        if chain.length() >= ACTION_CHAIN_COMPLEX_THRESHOLD {
            complex_chain_count += 1;
        }
        let hidden = is_chain_hidden(ctx, chain);
        if hidden {
            hidden_trigger_count += 1;
        } else if !chain.automatic {
            user_trigger_count += 1;
        }
    }
    let js_chain_count = chains.iter().filter(|c| c.involves_js).count();
    let external_chain_count = chains.iter().filter(|c| c.involves_external).count();

    // Calculate graph depth metrics
    let depths = path_finder.catalog_depths();
    let max_graph_depth = depths.values().max().copied().unwrap_or(0);
    let avg_graph_depth = if !depths.is_empty() {
        depths.values().sum::<usize>() as f64 / depths.len() as f64
    } else {
        0.0
    };

    // Count paths from catalog to JavaScript objects
    let js_sources = path_finder.find_javascript_sources();
    let catalog_to_js_paths = js_sources
        .iter()
        .filter(|src| path_finder.is_reachable_from_catalog(**src))
        .count();

    // Detect multi-stage attack indicators (JS + embedded + external)
    let has_js = js_payload_edges > 0;
    let has_embedded = classifications
        .iter()
        .any(|(_, c)| c.has_role(ObjectRole::EmbeddedFile));
    let has_external = uri_target_edges > 0 || launch_target_edges > 0;
    let multi_stage_indicators = if has_js && has_embedded && has_external {
        1
    } else {
        0
    };

    GraphFeatures {
        total_edges,
        open_action_edges,
        js_payload_edges,
        uri_target_edges,
        launch_target_edges,
        suspicious_edge_count,
        action_chain_count,
        max_chain_length,
        automatic_chain_count,
        hidden_trigger_count,
        user_trigger_count,
        complex_chain_count,
        js_chain_count,
        external_chain_count,
        max_graph_depth,
        avg_graph_depth,
        catalog_to_js_paths,
        multi_stage_indicators,
    }
}

#[allow(dead_code)]
fn build_feature_map(fv: &FeatureVector) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    out.insert("general.file_size".into(), fv.general.file_size as f64);
    out.insert("general.file_entropy".into(), fv.general.file_entropy);
    out.insert("general.binary_ratio".into(), fv.general.binary_ratio);
    out.insert(
        "general.object_count".into(),
        fv.general.object_count as f64,
    );
    out.insert(
        "structural.startxref_count".into(),
        fv.structural.startxref_count as f64,
    );
    out.insert(
        "structural.trailer_count".into(),
        fv.structural.trailer_count as f64,
    );
    out.insert(
        "structural.objstm_count".into(),
        fv.structural.objstm_count as f64,
    );
    out.insert(
        "structural.linearized_present".into(),
        if fv.structural.linearized_present {
            1.0
        } else {
            0.0
        },
    );
    out.insert(
        "structural.max_object_id".into(),
        fv.structural.max_object_id as f64,
    );
    out.insert(
        "behavior.action_count".into(),
        fv.behavioral.action_count as f64,
    );
    out.insert(
        "behavior.js_object_count".into(),
        fv.behavioral.js_object_count as f64,
    );
    out.insert(
        "behavior.js_entropy_avg".into(),
        fv.behavioral.js_entropy_avg,
    );
    out.insert(
        "behavior.js_eval_count".into(),
        fv.behavioral.js_eval_count as f64,
    );
    out.insert(
        "behavior.js_suspicious_api_count".into(),
        fv.behavioral.js_suspicious_api_count as f64,
    );
    out.insert(
        "behavior.time_api_count".into(),
        fv.behavioral.time_api_count as f64,
    );
    out.insert(
        "behavior.env_probe_count".into(),
        fv.behavioral.env_probe_count as f64,
    );
    out.insert(
        "content.embedded_file_count".into(),
        fv.content.embedded_file_count as f64,
    );
    out.insert(
        "content.embedded_executable_count".into(),
        fv.content.embedded_executable_count as f64,
    );
    out.insert(
        "content.embedded_script_count".into(),
        fv.content.embedded_script_count as f64,
    );
    out.insert(
        "content.embedded_archive_count".into(),
        fv.content.embedded_archive_count as f64,
    );
    out.insert(
        "content.embedded_double_extension_count".into(),
        fv.content.embedded_double_extension_count as f64,
    );
    out.insert(
        "content.embedded_encrypted_count".into(),
        fv.content.embedded_encrypted_count as f64,
    );
    out.insert(
        "content.rich_media_count".into(),
        fv.content.rich_media_count as f64,
    );
    out.insert(
        "content.rich_media_swf_count".into(),
        fv.content.rich_media_swf_count as f64,
    );
    out.insert(
        "content.rich_media_3d_count".into(),
        fv.content.rich_media_3d_count as f64,
    );
    out.insert(
        "content.annotation_count".into(),
        fv.content.annotation_count as f64,
    );
    out.insert("content.page_count".into(), fv.content.page_count as f64);
    out.insert("xfa.present".into(), if fv.xfa.present { 1.0 } else { 0.0 });
    out.insert("xfa.payload_count".into(), fv.xfa.payload_count as f64);
    out.insert("xfa.script_count".into(), fv.xfa.script_count as f64);
    out.insert(
        "xfa.submit_url_count".into(),
        fv.xfa.submit_url_count as f64,
    );
    out.insert(
        "xfa.sensitive_field_count".into(),
        fv.xfa.sensitive_field_count as f64,
    );
    out.insert(
        "xfa.max_payload_bytes".into(),
        fv.xfa.max_payload_bytes as f64,
    );
    out.insert(
        "encryption.encrypted".into(),
        if fv.encryption.encrypted { 1.0 } else { 0.0 },
    );
    out.insert(
        "encryption.encryption_key_length".into(),
        fv.encryption.encryption_key_length as f64,
    );
    out.insert(
        "encryption.high_entropy_stream_count".into(),
        fv.encryption.high_entropy_stream_count as f64,
    );
    out.insert(
        "encryption.avg_stream_entropy".into(),
        fv.encryption.avg_stream_entropy,
    );
    out.insert(
        "encryption.max_stream_entropy".into(),
        fv.encryption.max_stream_entropy,
    );
    out.insert(
        "encryption.encrypted_embedded_file_count".into(),
        fv.encryption.encrypted_embedded_file_count as f64,
    );
    out.insert(
        "filters.filter_chain_count".into(),
        fv.filters.filter_chain_count as f64,
    );
    out.insert(
        "filters.max_filter_chain_depth".into(),
        fv.filters.max_filter_chain_depth as f64,
    );
    out.insert(
        "filters.unusual_chain_count".into(),
        fv.filters.unusual_chain_count as f64,
    );
    out.insert(
        "filters.invalid_order_count".into(),
        fv.filters.invalid_order_count as f64,
    );
    out.insert(
        "filters.duplicate_filter_count".into(),
        fv.filters.duplicate_filter_count as f64,
    );
    out
}

fn is_chain_hidden(ctx: &ScanContext, chain: &ActionChain<'_>) -> bool {
    let first_edge = match chain.edges.first() {
        Some(edge) => edge,
        None => return false,
    };
    if !matches!(first_edge.edge_type, EdgeType::AnnotationAction) {
        return false;
    }
    if let Some(entry) = ctx.graph.get_object(first_edge.src.0, first_edge.src.1) {
        if let Some(dict) = entry_dict(entry) {
            return annotation_is_hidden(dict);
        }
    }
    false
}

fn annotation_is_hidden(dict: &PdfDict<'_>) -> bool {
    if let Some((_, rect)) = dict.get_first(b"/Rect") {
        if let Some((width, height)) = rect_size(rect) {
            if width <= 0.1 || height <= 0.1 {
                return true;
            }
        }
    }
    if let Some((_, flags)) = dict.get_first(b"/F") {
        if let PdfAtom::Int(value) = &flags.atom {
            let flag_value = *value as u32;
            if (flag_value & (1 << 1)) != 0 || (flag_value & (1 << 5)) != 0 {
                return true;
            }
        }
    }
    false
}

fn rect_size(obj: &PdfObj<'_>) -> Option<(f32, f32)> {
    let PdfAtom::Array(arr) = &obj.atom else {
        return None;
    };
    if arr.len() < 4 {
        return None;
    }
    let coords: Vec<f32> = arr
        .iter()
        .take(4)
        .filter_map(|item| match &item.atom {
            PdfAtom::Int(value) => Some(*value as f32),
            PdfAtom::Real(value) => Some(*value as f32),
            _ => None,
        })
        .collect();
    if coords.len() < 4 {
        return None;
    }
    let width = (coords[2] - coords[0]).abs();
    let height = (coords[3] - coords[1]).abs();
    Some((width, height))
}

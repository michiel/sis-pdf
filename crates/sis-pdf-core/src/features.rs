use std::collections::HashMap;

use crate::scan::{DecodedCache, ScanContext, ScanOptions};
use crate::page_tree::build_page_tree;
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr, PdfStream};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeneralFeatures {
    pub file_size: usize,
    pub file_entropy: f64,
    pub binary_ratio: f64,
    pub object_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StructuralFeatures {
    pub startxref_count: usize,
    pub trailer_count: usize,
    pub objstm_count: usize,
    pub linearized_present: bool,
    pub max_object_id: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BehavioralFeatures {
    pub action_count: usize,
    pub js_object_count: usize,
    pub js_entropy_avg: f64,
    pub js_eval_count: usize,
    pub js_suspicious_api_count: usize,
    pub time_api_count: usize,
    pub env_probe_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentFeatures {
    pub embedded_file_count: usize,
    pub rich_media_count: usize,
    pub annotation_count: usize,
    pub page_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeatureVector {
    pub general: GeneralFeatures,
    pub structural: StructuralFeatures,
    pub behavioral: BehavioralFeatures,
    pub content: ContentFeatures,
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
            .filter(|e| entry_dict(e).map(|d| d.has_name(b"/Type", b"/ObjStm")).unwrap_or(false))
            .count();

        let linearized_present = graph
            .objects
            .iter()
            .any(|e| entry_dict(e).and_then(|d| d.get_first(b"/Linearized")).is_some());

        let mut action_count = 0usize;
        let mut js_object_count = 0usize;
        let mut embedded_file_count = 0usize;
        let mut rich_media_count = 0usize;
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
                if dict.has_name(b"/Type", b"/Filespec")
                    || dict.has_name(b"/Type", b"/EmbeddedFile")
                    || dict.get_first(b"/EF").is_some()
                {
                    embedded_file_count += 1;
                }
                if dict.has_name(b"/Subtype", b"/RichMedia")
                    || dict.has_name(b"/Subtype", b"/3D")
                    || dict.has_name(b"/Subtype", b"/Sound")
                    || dict.has_name(b"/Subtype", b"/Movie")
                {
                    rich_media_count += 1;
                }
                if dict.get_first(b"/Subtype").is_some() && dict.get_first(b"/Rect").is_some() {
                    annotation_count += 1;
                }
            }
        }

        let (js_entropy_avg, js_eval_count, js_suspicious_api_count, time_api_count, env_probe_count) =
            summarize_js_payloads(&js_payloads);

        let page_count = build_page_tree(graph).pages.len();

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
                rich_media_count,
                annotation_count,
                page_count,
            },
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
            },
        )?;
        let ctx = ScanContext {
            bytes,
            graph,
            decoded: DecodedCache::new(opts.max_decode_bytes, opts.max_total_decoded_bytes),
            options: opts.clone(),
        };
        Ok(Self::extract(&ctx))
    }
}

fn bool_to_f32(v: bool) -> f32 {
    if v { 1.0 } else { 0.0 }
}

fn entry_dict<'a>(entry: &'a ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn name_bytes<'a>(obj: &'a PdfObj<'a>) -> Option<&'a [u8]> {
    match &obj.atom {
        PdfAtom::Name(n) => Some(&n.decoded),
        _ => None,
    }
}

fn resolve_obj_bytes(
    ctx: &ScanContext,
    obj: &PdfObj<'_>,
    max_len: usize,
) -> Option<Vec<u8>> {
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

fn decoded_stream_bytes(
    ctx: &ScanContext,
    st: &PdfStream<'_>,
    max_len: usize,
) -> Option<Vec<u8>> {
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
        if contains_any(data, &[b"app.launchURL", b"submitForm", b"getURL", b"app.execMenuItem"]) {
            suspicious_api_count += 1;
        }
        if contains_any(data, &[b"setTimeout", b"setInterval", b"Date(", b"performance.now"]) {
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
        .filter(|&&b| !(b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b <= 0x7e)))
        .count();
    binary as f64 / data.len() as f64
}

#[allow(dead_code)]
fn build_feature_map(fv: &FeatureVector) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    out.insert("general.file_size".into(), fv.general.file_size as f64);
    out.insert("general.file_entropy".into(), fv.general.file_entropy);
    out.insert("general.binary_ratio".into(), fv.general.binary_ratio);
    out.insert("general.object_count".into(), fv.general.object_count as f64);
    out.insert(
        "structural.startxref_count".into(),
        fv.structural.startxref_count as f64,
    );
    out.insert(
        "structural.trailer_count".into(),
        fv.structural.trailer_count as f64,
    );
    out.insert("structural.objstm_count".into(), fv.structural.objstm_count as f64);
    out.insert(
        "structural.linearized_present".into(),
        if fv.structural.linearized_present { 1.0 } else { 0.0 },
    );
    out.insert("structural.max_object_id".into(), fv.structural.max_object_id as f64);
    out.insert("behavior.action_count".into(), fv.behavioral.action_count as f64);
    out.insert("behavior.js_object_count".into(), fv.behavioral.js_object_count as f64);
    out.insert("behavior.js_entropy_avg".into(), fv.behavioral.js_entropy_avg);
    out.insert("behavior.js_eval_count".into(), fv.behavioral.js_eval_count as f64);
    out.insert(
        "behavior.js_suspicious_api_count".into(),
        fv.behavioral.js_suspicious_api_count as f64,
    );
    out.insert("behavior.time_api_count".into(), fv.behavioral.time_api_count as f64);
    out.insert("behavior.env_probe_count".into(), fv.behavioral.env_probe_count as f64);
    out.insert(
        "content.embedded_file_count".into(),
        fv.content.embedded_file_count as f64,
    );
    out.insert("content.rich_media_count".into(), fv.content.rich_media_count as f64);
    out.insert("content.annotation_count".into(), fv.content.annotation_count as f64);
    out.insert("content.page_count".into(), fv.content.page_count as f64);
    out
}

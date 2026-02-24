//! Content stream panel: structured operator breakdown for a PDF content stream.
//!
//! Displays a collapsible tree of `ContentBlock` values from `content_summary::summarise_stream`,
//! with anomaly highlighting, resolved resource links, hex-viewer navigation, and a
//! "Show in graph" button that switches the graph viewer to ContentStream mode.
use crate::app::SisApp;
use sis_pdf_core::content_correlation::CorrelatedStreamFinding;
use sis_pdf_pdf::content_summary::{ContentBlock, ContentStreamAnomaly, ContentStreamSummary};
use std::collections::HashMap;

#[cfg(feature = "gui")]
use egui::Color32;

/// Persistent state for the content stream floating panel.
#[derive(Default)]
pub struct ContentStreamPanelState {
    /// Currently displayed stream (object reference).
    pub active_stream: Option<(u32, u16)>,
    /// Cached summary for the active stream. `None` if not yet computed or if computation failed.
    pub summary: Option<ContentStreamSummary>,
    /// Expanded state for each top-level block (by index). Default: expanded.
    pub expanded: HashMap<usize, bool>,
    /// Selected block index (drives future graph highlight).
    pub selected_block: Option<usize>,
    /// Show anomalous blocks only.
    pub anomalies_only: bool,
    // --- Stage 4 fields ---
    /// Lazy-loaded Form XObject child summaries. Keyed by stream ref.
    pub xobject_children: HashMap<(u32, u16), ContentStreamSummary>,
    /// Whether Form XObject children are currently expanded in the tree view.
    pub show_xobject_children: bool,
    // --- Stage 5 fields ---
    /// Findings correlated to the active stream. Populated when `active_stream` changes.
    pub correlated_findings: Vec<CorrelatedStreamFinding>,
    /// Show only blocks that match a correlated finding.
    pub findings_only: bool,
}

// ---------------------------------------------------------------------------
// Entry point: open_stream
// ---------------------------------------------------------------------------

/// Open (or switch to) the content stream panel for the given stream object.
///
/// Computes the `ContentStreamSummary` synchronously from `result.bytes` and caches it.
/// Also populates correlated findings from the analysis report (Stage 5).
pub fn open_stream(app: &mut SisApp, obj: u32, gen: u16) {
    let need_recompute = app.content_stream_state.active_stream != Some((obj, gen));
    app.content_stream_state.active_stream = Some((obj, gen));
    app.show_content_stream = true;
    if need_recompute {
        app.content_stream_state.summary = None;
        app.content_stream_state.expanded.clear();
        app.content_stream_state.selected_block = None;
        app.content_stream_state.xobject_children.clear();
        app.content_stream_state.show_xobject_children = false;
        app.content_stream_state.correlated_findings.clear();
        app.content_stream_state.findings_only = false;
        if let Some(bytes) = app.result.as_ref().map(|r| r.bytes.clone()) {
            app.content_stream_state.summary = compute_stream_summary(&bytes, obj, gen);
        }
        // Populate correlated findings from the report.
        if let (Some(ref summary), Some(ref result)) =
            (&app.content_stream_state.summary.clone(), &app.result)
        {
            use sis_pdf_core::content_correlation::correlate_content_stream_findings;
            let approx_len = summary.stats.total_op_count as u64 * 8;
            app.content_stream_state.correlated_findings = correlate_content_stream_findings(
                &result.report.findings,
                (obj, gen),
                summary.page_ref,
                summary.raw_stream_offset,
                approx_len,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Summary computation (temporary borrow of PDF bytes)
// ---------------------------------------------------------------------------

/// Re-parse the PDF bytes, decode stream `(obj, gen)`, resolve resources, and summarise.
///
/// All lifetimed graph objects are dropped before returning the owned summary.
fn compute_stream_summary(
    bytes: &[u8],
    obj: u32,
    gen: u16,
) -> Option<ContentStreamSummary> {
    use sis_pdf_core::page_tree::resolve_page_resources;
    use sis_pdf_pdf::decode::decode_stream;
    use sis_pdf_pdf::graph::{parse_pdf, ParseOptions};
    use sis_pdf_pdf::object::PdfAtom;

    let parse_opts = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 4 * 1024 * 1024,
        max_objects: 250_000,
        max_objstm_total_bytes: 16 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let graph = parse_pdf(bytes, parse_opts).ok()?;
    let entry = graph.get_object(obj, gen)?;
    let stream = match &entry.atom {
        PdfAtom::Stream(st) => st,
        _ => return None,
    };
    let raw_stream_offset = stream.data_span.start;
    let decoded = decode_stream(bytes, stream, 4 * 1024 * 1024).ok()?;

    // Find the page that owns this stream (so we can resolve resources).
    let page_ref = find_page_for_stream(&graph, obj, gen);
    let owned_resources =
        page_ref.and_then(|(po, pg)| resolve_page_resources(&graph, po, pg));

    let summary = sis_pdf_pdf::content_summary::summarise_stream(
        &decoded.data,
        decoded.truncated,
        (obj, gen),
        page_ref,
        raw_stream_offset,
        owned_resources.as_ref(),
        &graph,
    );
    Some(summary)
}

/// Find which page object owns stream `(obj, gen)` by scanning all pages' `/Contents`.
fn find_page_for_stream(
    graph: &sis_pdf_pdf::graph::ObjectGraph<'_>,
    obj: u32,
    gen: u16,
) -> Option<(u32, u16)> {
    use sis_pdf_core::page_tree::build_page_tree;
    let tree = build_page_tree(graph);
    for page in &tree.pages {
        if page_content_stream_refs(graph, page.obj, page.gen).contains(&(obj, gen)) {
            return Some((page.obj, page.gen));
        }
    }
    None
}

/// Collect all stream object refs listed in a page's `/Contents` entry.
fn page_content_stream_refs(
    graph: &sis_pdf_pdf::graph::ObjectGraph<'_>,
    page_obj: u32,
    page_gen: u16,
) -> Vec<(u32, u16)> {
    use sis_pdf_pdf::object::PdfAtom;

    let entry = match graph.get_object(page_obj, page_gen) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let dict = match &entry.atom {
        PdfAtom::Dict(d) => d.clone(),
        PdfAtom::Stream(st) => st.dict.clone(),
        _ => return Vec::new(),
    };
    let Some((_, contents_obj)) = dict.get_first(b"/Contents") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_stream_refs(graph, &contents_obj.atom, &mut out);
    out
}

fn collect_stream_refs(
    graph: &sis_pdf_pdf::graph::ObjectGraph<'_>,
    atom: &sis_pdf_pdf::object::PdfAtom<'_>,
    out: &mut Vec<(u32, u16)>,
) {
    use sis_pdf_pdf::object::PdfAtom;

    match atom {
        PdfAtom::Ref { obj, gen } => {
            if let Some(entry) = graph.get_object(*obj, *gen) {
                match &entry.atom {
                    // Direct stream reference — record the object id.
                    PdfAtom::Stream(_) => out.push((*obj, *gen)),
                    // Indirect ref or array — recurse.
                    other => collect_stream_refs(graph, other, out),
                }
            }
        }
        PdfAtom::Array(arr) => {
            for item in arr {
                collect_stream_refs(graph, &item.atom, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// GUI rendering
// ---------------------------------------------------------------------------

/// Show the content stream panel as a floating window.
#[cfg(feature = "gui")]
pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_content_stream;
    let title = match app.content_stream_state.active_stream {
        Some((obj, gen)) => format!("Content Stream: {} {}", obj, gen),
        None => "Content Stream".to_string(),
    };
    let mut ws = app.window_max.remove(&title).unwrap_or_default();
    let win =
        crate::window_state::dialog_window(ctx, &title, [800.0, 560.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, &title, &mut open, &mut ws);
        show_inner(ui, app);
    });
    app.window_max.insert(title, ws);
    app.show_content_stream = open;
}

#[cfg(feature = "gui")]
fn show_inner(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some((stream_obj, stream_gen)) = app.content_stream_state.active_stream else {
        ui.label("No content stream selected.");
        return;
    };

    let summary = app.content_stream_state.summary.clone();
    let Some(ref summary) = summary else {
        ui.colored_label(Color32::from_rgb(200, 80, 80), "Unable to decode or summarise stream.");
        ui.label(format!("Stream {} {} may not be a content stream.", stream_obj, stream_gen));
        return;
    };

    // Header bar
    ui.horizontal(|ui| {
        if let Some((page_obj, page_gen)) = summary.page_ref {
            ui.label(format!("Page {} {}", page_obj, page_gen));
        }
        if ui.small_button("Go to stream").clicked() {
            app.open_hex_for_stream(stream_obj, stream_gen);
        }
        if ui.small_button("Show in graph").clicked() {
            crate::panels::graph::open_content_stream(
                app,
                stream_obj,
                stream_gen,
            );
        }
    });

    // Stats
    let s = &summary.stats;
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("{} ops", s.total_op_count));
        ui.label("·");
        ui.label(format!("{} text", s.text_op_count));
        ui.label("·");
        ui.label(format!("{} path", s.path_op_count));
        ui.label("·");
        ui.label(format!("{} images", s.image_invoke_count));
        ui.label("·");
        ui.label(format!("{} form XObj", s.form_xobject_invoke_count));
        ui.label("·");
        ui.label(format!("max q-depth {}", s.graphics_state_depth_max));
        if !s.unique_fonts.is_empty() {
            ui.label("·");
            ui.label(format!("fonts: {}", s.unique_fonts.join(", ")));
        }
        // Stage 4: Expand Form XObjects toggle (only visible when there are Form XObjects)
        if summary.stats.form_xobject_invoke_count > 0 {
            ui.separator();
            let lbl = if app.content_stream_state.show_xobject_children {
                "Collapse Form XObjects"
            } else {
                "Expand Form XObjects"
            };
            if ui.small_button(lbl).clicked() {
                let show = !app.content_stream_state.show_xobject_children;
                app.content_stream_state.show_xobject_children = show;
                // Lazy-load child summaries when first expanded.
                if show && app.content_stream_state.xobject_children.is_empty() {
                    if let Some(bytes) = app.result.as_ref().map(|r| r.bytes.clone()) {
                        load_xobject_children(&bytes, &summary, &mut app.content_stream_state.xobject_children);
                    }
                }
            }
        }
    });

    // Stage 5: Correlated findings bar
    let correlated = app.content_stream_state.correlated_findings.clone();
    if !correlated.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("Findings:").strong());
            for f in &correlated {
                let severity_color = severity_colour(f.severity);
                let badge = egui::RichText::new(format!("* {}", f.kind))
                    .color(severity_color);
                ui.label(badge);
                let conf_str = format!("{:?}", f.confidence).to_lowercase();
                ui.weak(format!("[{:?}/{conf_str}]", f.severity));
            }
        });
        ui.horizontal(|ui| {
            ui.toggle_value(
                &mut app.content_stream_state.findings_only,
                "Show findings only",
            );
        });
    }

    // Anomalies bar
    if !summary.anomalies.is_empty() {
        ui.horizontal(|ui| {
            ui.colored_label(
                Color32::from_rgb(220, 140, 30),
                format!("{} anomalies", summary.anomalies.len()),
            );
            ui.toggle_value(
                &mut app.content_stream_state.anomalies_only,
                "Show anomalies only",
            );
        });
        if !app.content_stream_state.anomalies_only {
            // Show anomaly list collapsed
            egui::CollapsingHeader::new("Anomaly details")
                .default_open(false)
                .show(ui, |ui| {
                    for anomaly in &summary.anomalies {
                        ui.label(format_anomaly(anomaly));
                    }
                });
        } else {
            for anomaly in &summary.anomalies {
                ui.label(
                    egui::RichText::new(format_anomaly(anomaly))
                        .color(Color32::from_rgb(220, 140, 30)),
                );
            }
        }
    } else {
        ui.label(egui::RichText::new("No anomalies").color(Color32::from_rgb(100, 180, 100)));
    }

    ui.separator();

    // Block tree
    let blocks = summary.blocks.clone();
    let xobject_children = app.content_stream_state.xobject_children.clone();
    let show_xobj = app.content_stream_state.show_xobject_children;
    let findings_only = app.content_stream_state.findings_only;
    let correlated_clone = app.content_stream_state.correlated_findings.clone();
    egui::ScrollArea::vertical().id_salt("cs_blocks_scroll").show(ui, |ui| {
        if blocks.is_empty() {
            ui.weak("Stream contains no operators.");
        } else {
            let anomalies_only = app.content_stream_state.anomalies_only;
            for (idx, block) in blocks.iter().enumerate() {
                if anomalies_only && !block_has_anomaly(block) {
                    continue;
                }
                show_block_with_findings(
                    ui,
                    app,
                    block,
                    idx,
                    0,
                    &correlated_clone,
                    &xobject_children,
                    show_xobj,
                    findings_only,
                );
            }
        }
    });
}

/// Severity colour for correlated findings badge.
#[cfg(feature = "gui")]
fn severity_colour(severity: sis_pdf_core::model::Severity) -> Color32 {
    use sis_pdf_core::model::Severity;
    match severity {
        Severity::Critical => Color32::from_rgb(220, 60, 60),
        Severity::High => Color32::from_rgb(220, 100, 30),
        Severity::Medium => Color32::from_rgb(200, 160, 30),
        Severity::Low => Color32::from_rgb(100, 160, 220),
        Severity::Info => Color32::from_rgb(160, 160, 160),
    }
}

/// Lazy-load Form XObject child summaries into the given map.
fn load_xobject_children(
    bytes: &[u8],
    summary: &ContentStreamSummary,
    out: &mut HashMap<(u32, u16), ContentStreamSummary>,
) {
    use sis_pdf_pdf::graph::{parse_pdf, ParseOptions};
    use std::collections::HashSet;

    let parse_opts = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 4 * 1024 * 1024,
        max_objects: 250_000,
        max_objstm_total_bytes: 16 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let Ok(graph) = parse_pdf(bytes, parse_opts) else { return; };

    let mut visited: HashSet<(u32, u16)> = HashSet::new();
    visited.insert(summary.stream_ref);

    collect_xobj_children_for_gui(&summary.blocks, &graph, &mut visited, out);
}

/// Collect Form XObject child summaries for GUI display (depth 1 only).
fn collect_xobj_children_for_gui(
    blocks: &[sis_pdf_pdf::content_summary::ContentBlock],
    graph: &sis_pdf_pdf::graph::ObjectGraph<'_>,
    visited: &mut std::collections::HashSet<(u32, u16)>,
    out: &mut HashMap<(u32, u16), ContentStreamSummary>,
) {
    use sis_pdf_pdf::content_summary::{summarise_stream, ContentBlock};
    use sis_pdf_pdf::decode::decode_stream;
    use sis_pdf_pdf::object::{PdfAtom};

    for block in blocks {
        match block {
            ContentBlock::XObjectInvoke {
                subtype: Some(st),
                target_ref: Some(r),
                ..
            } if st == "Form" => {
                let form_ref = *r;
                if visited.contains(&form_ref) {
                    continue;
                }
                visited.insert(form_ref);
                let Some(entry) = graph.get_object(form_ref.0, form_ref.1) else { continue; };
                let stream = match &entry.atom {
                    PdfAtom::Stream(st) => st,
                    _ => continue,
                };
                let raw_stream_offset = stream.data_span.start;
                let form_resources = stream.dict.get_first(b"/Resources").and_then(|(_, res)| {
                    match &res.atom {
                        PdfAtom::Dict(d) => Some(d.clone()),
                        PdfAtom::Ref { .. } => graph.resolve_ref(res).and_then(|e| match &e.atom {
                            PdfAtom::Dict(d) => Some(d.clone()),
                            _ => None,
                        }),
                        _ => None,
                    }
                });
                let Ok(decoded) = decode_stream(graph.bytes, stream, 4 * 1024 * 1024) else { continue; };
                let child = summarise_stream(
                    &decoded.data,
                    decoded.truncated,
                    form_ref,
                    None,
                    raw_stream_offset,
                    form_resources.as_ref(),
                    graph,
                );
                out.insert(form_ref, child);
            }
            ContentBlock::GraphicsState { children, .. } => {
                collect_xobj_children_for_gui(children, graph, visited, out);
            }
            ContentBlock::MarkedContent { children, .. } => {
                collect_xobj_children_for_gui(children, graph, visited, out);
            }
            _ => {}
        }
    }
}

/// Format an anomaly for display.
fn format_anomaly(anomaly: &ContentStreamAnomaly) -> String {
    match anomaly {
        ContentStreamAnomaly::GraphicsStateUnderflow { op, position } => {
            format!("Graphics state underflow: {} at offset {}", op, position)
        }
        ContentStreamAnomaly::TextObjectUnterminatedAtEof => {
            "Unterminated BT (no closing ET) at end of stream".to_string()
        }
        ContentStreamAnomaly::UnknownOperator { op, position } => {
            format!("Unknown operator \"{}\" at offset {}", op, position)
        }
        ContentStreamAnomaly::ExcessiveKernOffset { value, position } => {
            format!("Excessive kern offset {:.1} at offset {}", value, position)
        }
        ContentStreamAnomaly::ZeroScaleText { position } => {
            format!("Zero horizontal scale (Tz 0) at offset {}", position)
        }
        ContentStreamAnomaly::InvisibleRenderingMode { position } => {
            format!("Invisible rendering mode (Tr 3) at offset {}", position)
        }
        ContentStreamAnomaly::HighOpCount { count } => {
            format!("Unusually high operator count: {}", count)
        }
        ContentStreamAnomaly::StreamTruncated => {
            "Stream was truncated during decoding".to_string()
        }
    }
}

/// Returns true if any block in the tree (including recursively) has an anomaly indicator.
fn block_has_anomaly(block: &ContentBlock) -> bool {
    match block {
        ContentBlock::TextObject { .. } => false,
        ContentBlock::GraphicsState { children, .. } => children.iter().any(block_has_anomaly),
        ContentBlock::XObjectInvoke { .. } => false,
        ContentBlock::InlineImage { .. } => false,
        ContentBlock::MarkedContent { children, .. } => children.iter().any(block_has_anomaly),
        ContentBlock::Ops(_) => false,
    }
}

/// Check if any correlated finding's decoded_offset falls within a block's span.
fn block_has_finding(
    span_start: u64,
    span_end: u64,
    correlated: &[CorrelatedStreamFinding],
) -> Option<String> {
    correlated.iter().find_map(|f| {
        f.decoded_offset
            .filter(|&o| o >= span_start && o <= span_end)
            .map(|_| f.kind.clone())
    })
}

/// Render a single `ContentBlock` as a tree row, with findings and XObject child expansion.
#[cfg(feature = "gui")]
#[allow(clippy::too_many_arguments)]
fn show_block_with_findings(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    block: &ContentBlock,
    index: usize,
    depth: usize,
    correlated: &[CorrelatedStreamFinding],
    xobject_children: &HashMap<(u32, u16), ContentStreamSummary>,
    show_xobj: bool,
    findings_only: bool,
) {
    let indent = depth as f32 * 16.0;
    match block {
        ContentBlock::TextObject { fonts, strings, span_start, span_end, .. } => {
            let finding_kind = block_has_finding(*span_start, *span_end, correlated);
            if findings_only && finding_kind.is_none() {
                return;
            }
            ui.horizontal(|ui| {
                ui.add_space(indent);
                let label = format!(
                    "[{}] TextObject BT…ET  span [{}, {}]",
                    index, span_start, span_end
                );
                if finding_kind.is_some() {
                    ui.label(egui::RichText::new(label).background_color(Color32::from_rgb(255, 220, 120)));
                    if let Some(kind) = &finding_kind {
                        ui.weak(format!("[Finding: {}]", kind));
                    }
                } else {
                    ui.label(label);
                }
            });
            if !fonts.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(indent + 16.0);
                    ui.weak("Fonts:");
                    for (name, ref_opt) in fonts {
                        match ref_opt {
                            Some((fo, fg)) => {
                                let lbl = format!("{} → {} {}", name, fo, fg);
                                if ui.link(&lbl).on_hover_text("Open in Object Inspector").clicked()
                                {
                                    app.navigate_to_object(*fo, *fg);
                                    app.show_objects = true;
                                }
                            }
                            None => {
                                ui.label(name);
                            }
                        }
                    }
                });
            }
            if !strings.is_empty() {
                let preview: Vec<&str> =
                    strings.iter().take(3).map(|s| s.as_str()).collect();
                let mut preview_str = preview.join("  ");
                if strings.len() > 3 {
                    preview_str.push_str(&format!(" … (+{})", strings.len() - 3));
                }
                if preview_str.len() > 80 {
                    preview_str.truncate(77);
                    preview_str.push_str("...");
                }
                ui.horizontal(|ui| {
                    ui.add_space(indent + 16.0);
                    ui.weak("Strings:");
                    ui.monospace(&preview_str);
                });
            }
        }
        ContentBlock::GraphicsState { children, ctm_ops, span_start, span_end } => {
            let header = format!(
                "[{}] GraphicsState q…Q  {} children  span [{}, {}]",
                index,
                children.len(),
                span_start,
                span_end
            );
            let has_ctm = !ctm_ops.is_empty();
            let expanded = *app.content_stream_state.expanded.entry(index).or_insert(true);
            let new_expanded = ui.horizontal(|ui| {
                ui.add_space(indent);
                let resp = ui.selectable_label(expanded, &header);
                if has_ctm {
                    ui.weak(format!("{} cm op(s)", ctm_ops.len()));
                }
                resp.clicked()
            });
            if new_expanded.inner {
                *app.content_stream_state.expanded.entry(index).or_insert(true) = !expanded;
            }
            if expanded || new_expanded.inner {
                for (ci, child) in children.iter().enumerate() {
                    show_block_with_findings(
                        ui, app, child, ci, depth + 1, correlated, xobject_children, show_xobj, findings_only,
                    );
                }
            }
        }
        ContentBlock::XObjectInvoke { resource_name, target_ref, subtype, span_start, span_end } => {
            let finding_kind = block_has_finding(*span_start, *span_end, correlated);
            if findings_only && finding_kind.is_none() {
                return;
            }
            ui.horizontal(|ui| {
                ui.add_space(indent);
                let type_label = subtype.as_deref().unwrap_or("?");
                let label = format!(
                    "[{}] XObjectInvoke {}  [{}]  span [{}, {}]",
                    index, resource_name, type_label, span_start, span_end
                );
                if finding_kind.is_some() {
                    ui.label(egui::RichText::new(label).background_color(Color32::from_rgb(255, 220, 120)));
                } else {
                    ui.label(label);
                }
                if let Some((fo, fg)) = target_ref {
                    let btn = format!("Ref {} {}", fo, fg);
                    if ui.small_button(&btn).on_hover_text("Open in Object Inspector").clicked() {
                        app.navigate_to_object(*fo, *fg);
                        app.show_objects = true;
                    }
                }
            });
            // Stage 4: show inline child summary if expanded.
            if show_xobj {
                if let (Some("Form"), Some(form_ref)) = (subtype.as_deref(), target_ref) {
                    if let Some(child_summary) = xobject_children.get(form_ref) {
                        let child_header = format!(
                            "Form XObject {} {} ({} ops)",
                            form_ref.0, form_ref.1, child_summary.stats.total_op_count
                        );
                        egui::CollapsingHeader::new(&child_header)
                            .id_salt(format!("xobj_{}_{}", form_ref.0, form_ref.1))
                            .default_open(true)
                            .show(ui, |ui| {
                                let child_blocks = child_summary.blocks.clone();
                                for (ci, child_block) in child_blocks.iter().enumerate() {
                                    show_block_with_findings(
                                        ui, app, child_block, ci, depth + 2,
                                        correlated, xobject_children, show_xobj, findings_only,
                                    );
                                }
                            });
                    }
                }
            }
        }
        ContentBlock::InlineImage { width, height, color_space, span_start, span_end } => {
            if findings_only {
                return;
            }
            ui.horizontal(|ui| {
                ui.add_space(indent);
                let dims = match (width, height) {
                    (Some(w), Some(h)) => format!("{}×{}", w, h),
                    _ => "?×?".to_string(),
                };
                let cs = color_space.as_deref().unwrap_or("");
                ui.label(format!(
                    "[{}] InlineImage  {}  {}  span [{}, {}]",
                    index, dims, cs, span_start, span_end
                ));
            });
        }
        ContentBlock::MarkedContent { tag, properties, children, span_start, span_end } => {
            if findings_only {
                return;
            }
            let header = format!(
                "[{}] MarkedContent {}  {} children  span [{}, {}]",
                index,
                tag,
                children.len(),
                span_start,
                span_end
            );
            let expanded = *app.content_stream_state.expanded.entry(index + 100_000).or_insert(true);
            let new_expanded = ui.horizontal(|ui| {
                ui.add_space(indent);
                let resp = ui.selectable_label(expanded, &header);
                if let Some(props) = properties {
                    ui.weak(props.as_str());
                }
                resp.clicked()
            });
            if new_expanded.inner {
                let key = index + 100_000;
                *app.content_stream_state.expanded.entry(key).or_insert(true) = !expanded;
            }
            if expanded || new_expanded.inner {
                for (ci, child) in children.iter().enumerate() {
                    show_block_with_findings(
                        ui, app, child, ci, depth + 1, correlated, xobject_children, show_xobj, findings_only,
                    );
                }
            }
        }
        ContentBlock::Ops(ops) => {
            if findings_only {
                return;
            }
            ui.horizontal(|ui| {
                ui.add_space(indent);
                ui.weak(format!("[{}] Ops  {} operators", index, ops.len()));
            });
        }
    }
}

use crate::app::SisApp;
use crate::graph_data::{self, GraphData, GraphError};
use crate::graph_layout::{apply_staged_dag_layout_with_spread, LayoutState};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GraphViewMode {
    #[default]
    Structure,
    Event,
    StagedDag,
    /// Operator/resource graph for a single content stream.
    ContentStream { stream_ref: (u32, u16) },
}

/// Persistent state for the graph viewer panel.
pub struct GraphViewerState {
    /// The current graph data (None until a file is loaded and graph is built).
    pub graph: Option<GraphData>,
    /// Incremental layout state (None when layout is complete).
    pub layout: Option<LayoutState>,
    /// Pan offset in graph coordinates.
    pub pan: [f64; 2],
    /// Zoom level (1.0 = no zoom).
    pub zoom: f64,
    /// Node index under the cursor.
    pub hovered_node: Option<usize>,
    /// Currently selected node index.
    pub selected_node: Option<usize>,
    /// Type filter: only show nodes of these types. Empty = all.
    pub type_filter: Vec<String>,
    /// Graph mode.
    pub mode: GraphViewMode,
    /// Whether to filter to chain-only nodes.
    pub chain_filter: bool,
    /// Whether to overlay the selected chain path.
    pub chain_overlay: bool,
    /// Event-mode node-kind filter (`event`, `outcome`, `object`, `collapse`).
    pub event_node_kind_filter: Option<String>,
    /// Event-mode trigger-class filter (`automatic`, `hidden`, `user`).
    pub event_trigger_filter: Option<String>,
    /// BFS depth limit from selected node. 0 = no limit (show all).
    pub depth_limit: usize,
    /// Minimum ideal edge length used by the layout engine (0 = auto).
    pub min_edge_length: f64,
    /// Whether to show node labels.
    pub show_labels: bool,
    /// Error message if graph could not be built.
    pub error: Option<String>,
    /// Whether the graph has been built for the current result.
    pub built: bool,
    /// Timestamp when layout started (for telemetry).
    pub layout_start_time: f64,
    /// Object requested for focus before the graph is built.
    pub pending_focus: Option<(u32, u16)>,
    /// Maximum hop count for finding-detail event paths.
    pub finding_detail_max_hops: usize,
    /// Whether staged DAG layout requires a rebuild/reposition pass.
    pub dag_layout_dirty: bool,
    /// Highlight only the highest-confidence exploit path.
    pub show_critical_path: bool,
    /// Critical path edges.
    pub critical_path_edges: HashSet<(usize, usize)>,
    /// Critical path nodes.
    pub critical_path_nodes: HashSet<usize>,
    /// Taint overlay toggle.
    pub show_taint_overlay: bool,
    /// Precomputed taint edges mapped to graph indices.
    pub taint_edges: Vec<(usize, usize)>,
    /// Taint source node indices.
    pub taint_source_nodes: HashSet<usize>,
    /// MITRE technique selected for highlight filtering.
    pub mitre_selected_technique: Option<String>,
    /// Graph node indices carrying selected MITRE technique.
    pub mitre_highlight_nodes: HashSet<usize>,
    /// Whether staged DAG should vertically spread nodes inside a lane.
    pub dag_lane_vertical_spread: bool,
    /// Whether staged DAG should horizontally spread nodes inside a lane-level cluster.
    pub dag_lane_horizontal_spread: bool,
    /// Whether the advanced controls sidebar is visible.
    pub show_controls_sidebar: bool,
    /// Request a fit-to-viewport transform on the next graph render.
    pub fit_to_view_pending: bool,
}

const WORLD_CENTRE_X: f64 = 400.0;
const WORLD_CENTRE_Y: f64 = 300.0;
const GRAPH_TOOLTIP_WIDTH: f32 = 400.0;

impl Default for GraphViewerState {
    fn default() -> Self {
        Self {
            graph: None,
            layout: None,
            pan: [0.0, 0.0],
            zoom: 1.0,
            hovered_node: None,
            selected_node: None,
            type_filter: Vec::new(),
            mode: GraphViewMode::Structure,
            chain_filter: false,
            chain_overlay: false,
            event_node_kind_filter: None,
            event_trigger_filter: None,
            depth_limit: 0,
            min_edge_length: 0.0,
            show_labels: true,
            error: None,
            built: false,
            layout_start_time: 0.0,
            pending_focus: None,
            finding_detail_max_hops: 8,
            dag_layout_dirty: false,
            show_critical_path: false,
            critical_path_edges: HashSet::new(),
            critical_path_nodes: HashSet::new(),
            show_taint_overlay: false,
            taint_edges: Vec::new(),
            taint_source_nodes: HashSet::new(),
            mitre_selected_technique: None,
            mitre_highlight_nodes: HashSet::new(),
            dag_lane_vertical_spread: false,
            dag_lane_horizontal_spread: false,
            show_controls_sidebar: false,
            fit_to_view_pending: false,
        }
    }
}

/// Node type colour mapping.
fn node_colour(obj_type: &str) -> egui::Color32 {
    match obj_type.to_lowercase().as_str() {
        "event" => egui::Color32::from_rgb(245, 170, 66),     // amber
        "outcome" => egui::Color32::from_rgb(220, 80, 80),    // red
        "collapse" => egui::Color32::from_rgb(120, 120, 120), // dark grey
        "page" => egui::Color32::from_rgb(70, 130, 230),      // blue
        "action" => egui::Color32::from_rgb(220, 60, 60),     // red
        "stream" => egui::Color32::from_rgb(60, 180, 80),     // green
        "font" => egui::Color32::from_rgb(160, 160, 160),     // grey
        "catalog" | "catalogue" => egui::Color32::from_rgb(160, 80, 200), // purple
        "image" => egui::Color32::from_rgb(230, 160, 40),     // orange
        // Content stream node types
        "content_text" => egui::Color32::from_rgb(70, 130, 230),       // blue
        "content_image" | "content_inline_image" => egui::Color32::from_rgb(60, 180, 80), // green
        "content_form_xobj" => egui::Color32::from_rgb(40, 180, 160),  // teal
        "content_marked" => egui::Color32::from_rgb(150, 150, 150),    // grey
        "content_gstate" | "content_ops" => egui::Color32::from_rgb(190, 190, 190), // light grey
        _ => egui::Color32::from_rgb(140, 140, 140),                   // default grey
    }
}

/// Show the graph viewer as a floating window.
pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_graph;
    egui::Window::new("Graph Viewer")
        .open(&mut open)
        .default_size([800.0, 600.0])
        .max_size(ctx.available_rect().size())
        .resizable(true)
        .show(ctx, |ui| {
            show_inner(ui, ctx, app);
        });
    app.show_graph = open;
}

/// Focus the graph on a specific object reference.
pub fn focus_object(app: &mut SisApp, obj: u32, gen: u16) {
    app.show_graph = true;
    app.graph_state.pending_focus = Some((obj, gen));
    apply_pending_focus(app);
}

/// Switch the graph viewer to ContentStream mode for the given stream object.
///
/// Computes the content graph from the cached `ContentStreamSummary` in the panel state.
/// Opens the graph viewer and requests a fit-to-view.
pub fn open_content_stream(app: &mut SisApp, obj: u32, gen: u16) {
    // Ensure the content stream summary is computed first.
    crate::panels::content_stream::open_stream(app, obj, gen);

    let mode = GraphViewMode::ContentStream { stream_ref: (obj, gen) };
    app.graph_state.mode = mode;
    app.graph_state.built = false;
    app.graph_state.fit_to_view_pending = true;
    app.show_graph = true;
    build_graph(app);
}

fn show_inner(ui: &mut egui::Ui, ctx: &egui::Context, app: &mut SisApp) {
    // Build graph if not yet done
    if !app.graph_state.built {
        build_graph(app);
    }
    apply_pending_focus(app);

    // Show error if graph could not be built
    if let Some(ref err) = app.graph_state.error {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.colored_label(egui::Color32::RED, err);
            ui.add_space(8.0);
            ui.label("Apply type or depth filters to reduce the graph size.");
        });
        show_toolbar(ui, app);
        return;
    }

    // Show toolbar
    show_toolbar(ui, app);
    ui.separator();

    // Run incremental layout if still active
    if app.graph_state.layout.is_some() {
        run_layout_step(app);
        ctx.request_repaint();
    }

    ui.horizontal_top(|ui| {
        if app.graph_state.show_controls_sidebar {
            ui.vertical(|ui| {
                ui.set_min_width(280.0);
                ui.set_max_width(320.0);
                show_controls_sidebar(ui, app);
            });
            ui.separator();
        }
        ui.vertical(|ui| {
            render_graph_canvas(ui, app);
        });
    });
}

fn render_graph_canvas(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref graph) = app.graph_state.graph else {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label("No graph data. Load a PDF to view the object reference graph.");
        });
        return;
    };

    if graph.nodes.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label("Graph is empty (no objects match the current filters).");
        });
        return;
    }

    // Pre-extract data we need for rendering, to avoid borrow issues
    let node_count = graph.nodes.len();
    let node_data: Vec<(f64, f64, String, String, Vec<String>, Option<f32>)> = graph
        .nodes
        .iter()
        .map(|n| {
            (
                n.position[0],
                n.position[1],
                n.obj_type.clone(),
                n.label.clone(),
                n.roles.clone(),
                n.confidence,
            )
        })
        .collect();

    let edge_data: Vec<(usize, usize, bool, Option<String>, Option<String>, Option<String>)> =
        graph
            .edges
            .iter()
            .map(|e| {
                (
                    e.from_idx,
                    e.to_idx,
                    e.suspicious,
                    e.edge_kind.clone(),
                    e.provenance.clone(),
                    e.metadata.clone(),
                )
            })
            .collect();

    let selected_chain = app.selected_chain;
    let chain_overlay = build_chain_overlay(app);
    let visible_nodes = build_visible_node_set(app, graph);
    let critical_path_edges = app.graph_state.critical_path_edges.clone();
    let critical_path_nodes = app.graph_state.critical_path_nodes.clone();
    let taint_edges: HashSet<(usize, usize)> =
        app.graph_state.taint_edges.iter().copied().collect::<HashSet<_>>();
    let taint_source_nodes = app.graph_state.taint_source_nodes.clone();
    let mitre_nodes = app.graph_state.mitre_highlight_nodes.clone();
    let show_critical_path = app.graph_state.show_critical_path;
    let show_taint_overlay = app.graph_state.show_taint_overlay;
    let show_mitre_overlay = app.graph_state.mitre_selected_technique.is_some();

    let pan = app.graph_state.pan;
    let zoom = if app.graph_state.zoom == 0.0 { 1.0 } else { app.graph_state.zoom };
    let selected = app.graph_state.selected_node;
    let show_labels = app.graph_state.show_labels;
    let is_layout_running = app.graph_state.layout.is_some();
    let node_radius = (6.0 * zoom).clamp(3.0, 20.0) as f32;
    let mut placed_label_rects: Vec<egui::Rect> = Vec::new();

    // Allocate painter for custom drawing
    let available = ui.available_size();
    let (response, painter) = ui.allocate_painter(available, egui::Sense::click_and_drag());
    let rect = response.rect;
    if app.graph_state.fit_to_view_pending {
        fit_graph_to_viewport(app, rect);
    }

    // Handle pan via drag
    if response.dragged() {
        let delta = response.drag_delta();
        app.graph_state.pan[0] += delta.x as f64 / zoom;
        app.graph_state.pan[1] += delta.y as f64 / zoom;
    }

    // Handle zoom via scroll
    let scroll_delta = ui.input(|i| i.smooth_scroll_delta.y);
    if scroll_delta != 0.0 && rect.contains(ui.input(|i| i.pointer.hover_pos().unwrap_or_default()))
    {
        let zoom_factor = 1.0 + scroll_delta as f64 * 0.002;
        let new_zoom = (app.graph_state.zoom * zoom_factor).clamp(0.1, 10.0);
        app.graph_state.zoom = new_zoom;
    }

    // Background
    painter.rect_filled(rect, 0.0, egui::Color32::from_rgb(30, 30, 35));

    // Show layout progress if still running
    if is_layout_running {
        painter.text(
            rect.left_top() + egui::vec2(8.0, 8.0),
            egui::Align2::LEFT_TOP,
            "Layout in progress...",
            egui::FontId::proportional(12.0),
            egui::Color32::YELLOW,
        );
    }

    // Transform: graph coords -> screen coords
    let to_screen = |gx: f64, gy: f64| -> egui::Pos2 {
        let sx = rect.center().x as f64 + (gx - WORLD_CENTRE_X + pan[0]) * zoom;
        let sy = rect.center().y as f64 + (gy - WORLD_CENTRE_Y + pan[1]) * zoom;
        egui::pos2(sx as f32, sy as f32)
    };

    // Inverse: screen coords -> graph coords (used by click handlers)
    let _from_screen = |sx: f32, sy: f32| -> (f64, f64) {
        let gx = (sx as f64 - rect.center().x as f64) / zoom + WORLD_CENTRE_X - pan[0];
        let gy = (sy as f64 - rect.center().y as f64) / zoom + WORLD_CENTRE_Y - pan[1];
        (gx, gy)
    };

    if app.graph_state.mode == GraphViewMode::StagedDag {
        draw_staged_lanes(&painter, rect, &to_screen);
    }

    let dim_non_chain = selected_chain.is_some() && app.graph_state.chain_filter;

    let pointer_pos = ui.input(|i| i.pointer.hover_pos());

    // Draw edges
    let mut hovered_edge: Option<(String, Option<String>, Option<String>)> = None;
    for (from_idx, to_idx, suspicious, edge_kind, provenance, edge_metadata) in &edge_data {
        let from_idx = *from_idx;
        let to_idx = *to_idx;
        let suspicious = *suspicious;
        if !visible_nodes.contains(&from_idx) || !visible_nodes.contains(&to_idx) {
            continue;
        }
        let (fx, fy) = (node_data[from_idx].0, node_data[from_idx].1);
        let (tx, ty) = (node_data[to_idx].0, node_data[to_idx].1);
        let p1 = to_screen(fx, fy);
        let p2 = to_screen(tx, ty);

        if !rect.contains(p1) && !rect.contains(p2) {
            continue; // skip off-screen edges
        }

        let mut colour = if suspicious {
            egui::Color32::from_rgba_premultiplied(220, 60, 60, 180)
        } else {
            egui::Color32::from_rgba_premultiplied(100, 100, 100, 120)
        };
        let mut width = if suspicious { 2.0 } else { 1.0 };
        let selected_connection = selected == Some(from_idx) || selected == Some(to_idx);

        if let Some(selected_idx) = selected {
            if from_idx == selected_idx && to_idx == selected_idx {
                colour = egui::Color32::from_rgb(220, 120, 220);
                width = 3.0;
            } else if from_idx == selected_idx {
                colour = egui::Color32::from_rgb(80, 220, 255);
                width = 3.0;
            } else if to_idx == selected_idx {
                colour = egui::Color32::from_rgb(255, 180, 80);
                width = 3.0;
            }
        }

        if app.graph_state.chain_overlay && chain_overlay.path_edges.contains(&(from_idx, to_idx)) {
            colour = egui::Color32::from_rgb(190, 110, 255);
            width = 3.0;
        }
        if show_critical_path && critical_path_edges.contains(&(from_idx, to_idx)) {
            colour = egui::Color32::from_rgb(255, 140, 0);
            width = 3.0;
        }
        if show_taint_overlay && taint_edges.contains(&(from_idx, to_idx)) {
            colour = egui::Color32::from_rgb(200, 60, 60);
            width = 2.5;
        }

        if dim_non_chain {
            let from_in_chain = chain_overlay.node_set.contains(&from_idx);
            let to_in_chain = chain_overlay.node_set.contains(&to_idx);
            if (!from_in_chain || !to_in_chain) && !selected_connection {
                colour = egui::Color32::from_rgba_premultiplied(60, 60, 60, 40);
            }
        }
        if show_critical_path && !critical_path_edges.contains(&(from_idx, to_idx)) {
            colour = egui::Color32::from_rgba_premultiplied(colour.r(), colour.g(), colour.b(), 50);
        }
        if show_mitre_overlay && !(mitre_nodes.contains(&from_idx) && mitre_nodes.contains(&to_idx))
        {
            colour = egui::Color32::from_rgba_premultiplied(colour.r(), colour.g(), colour.b(), 50);
        }
        if show_taint_overlay
            && !taint_edges.contains(&(from_idx, to_idx))
            && !(taint_source_nodes.contains(&from_idx) || taint_source_nodes.contains(&to_idx))
        {
            colour = egui::Color32::from_rgba_premultiplied(colour.r(), colour.g(), colour.b(), 50);
        }

        let stroke = egui::Stroke::new(width, colour);
        if app.graph_state.mode == GraphViewMode::StagedDag
            && node_data[from_idx].0 > node_data[to_idx].0
        {
            draw_back_edge_curve(&painter, p1, p2, stroke);
        } else {
            painter.line_segment([p1, p2], stroke);
            draw_edge_arrowhead(&painter, p1, p2, stroke, node_radius);
        }

        if let Some(pointer) = pointer_pos {
            let dx = p2.x - p1.x;
            let dy = p2.y - p1.y;
            let len2 = dx * dx + dy * dy;
            if len2 > 0.0 {
                let t =
                    (((pointer.x - p1.x) * dx + (pointer.y - p1.y) * dy) / len2).clamp(0.0, 1.0);
                let proj = egui::pos2(p1.x + dx * t, p1.y + dy * t);
                let ex = pointer.x - proj.x;
                let ey = pointer.y - proj.y;
                if ex * ex + ey * ey <= 16.0 {
                    hovered_edge = Some((
                        edge_kind.clone().unwrap_or_else(|| "edge".to_string()),
                        provenance.clone(),
                        edge_metadata.clone(),
                    ));
                }
            }
        }
    }

    // Draw nodes
    let mut hovered = None;

    for (i, (gx, gy, ref obj_type, ref label, ref _roles, confidence)) in
        node_data.iter().enumerate()
    {
        if !visible_nodes.contains(&i) {
            continue;
        }
        let p = to_screen(*gx, *gy);
        if !rect.contains(p) {
            continue;
        }

        let mut colour = node_colour(obj_type);
        if obj_type.eq_ignore_ascii_case("outcome") {
            let intensity = confidence.unwrap_or(0.5).clamp(0.2, 1.0);
            let scale = 0.5 + intensity * 0.5;
            colour = egui::Color32::from_rgb(
                (colour.r() as f32 * scale) as u8,
                (colour.g() as f32 * scale) as u8,
                (colour.b() as f32 * scale) as u8,
            );
        }

        if dim_non_chain && !chain_overlay.node_set.contains(&i) {
            colour = egui::Color32::from_rgba_premultiplied(80, 80, 80, 60);
        }
        if show_critical_path && !critical_path_nodes.contains(&i) {
            colour = egui::Color32::from_rgba_premultiplied(colour.r(), colour.g(), colour.b(), 50);
        }
        if show_mitre_overlay && !mitre_nodes.contains(&i) {
            colour = egui::Color32::from_rgba_premultiplied(colour.r(), colour.g(), colour.b(), 50);
        }
        if show_taint_overlay
            && !taint_source_nodes.contains(&i)
            && !node_has_taint_edge(i, &taint_edges)
        {
            colour = egui::Color32::from_rgba_premultiplied(colour.r(), colour.g(), colour.b(), 50);
        }

        if selected == Some(i) {
            // Draw selection ring
            painter.circle_stroke(
                p,
                node_radius + 3.0,
                egui::Stroke::new(2.0, egui::Color32::WHITE),
            );
        }
        if show_mitre_overlay && mitre_nodes.contains(&i) {
            painter.circle_stroke(
                p,
                node_radius + 2.0,
                egui::Stroke::new(2.0, egui::Color32::from_rgb(180, 80, 220)),
            );
        }
        if show_taint_overlay && taint_source_nodes.contains(&i) {
            painter.circle_stroke(p, node_radius + 3.0, egui::Stroke::new(3.0, egui::Color32::RED));
        }

        painter.circle_filled(p, node_radius, colour);

        // Check hover
        if let Some(pointer) = pointer_pos {
            let dx = pointer.x - p.x;
            let dy = pointer.y - p.y;
            if dx * dx + dy * dy < (node_radius + 4.0) * (node_radius + 4.0) {
                hovered = Some(i);
            }
        }

        // Draw labels if enabled and zoomed in enough
        if show_labels && zoom > 0.5 {
            let font_id = egui::FontId::proportional((10.0 * zoom).clamp(8.0, 14.0) as f32);
            let text_colour = egui::Color32::from_rgb(200, 200, 200);
            let galley = painter.layout_no_wrap(label.clone(), font_id.clone(), text_colour);
            let label_size = galley.size();
            let left_x = -(label_size.x + node_radius + 2.0);
            let centred_x = -label_size.x * 0.5;
            let candidate_offsets = [
                egui::vec2(node_radius + 2.0, -6.0),
                egui::vec2(node_radius + 2.0, 6.0),
                egui::vec2(left_x, -6.0),
                egui::vec2(left_x, 6.0),
                egui::vec2(centred_x, node_radius + 4.0),
                egui::vec2(centred_x, -node_radius - label_size.y - 4.0),
            ];

            let mut best_pos = p + candidate_offsets[0];
            let mut best_rect = egui::Rect::from_min_size(best_pos, label_size);
            for offset in candidate_offsets {
                let candidate_pos = p + offset;
                let candidate_rect = egui::Rect::from_min_size(candidate_pos, label_size);
                if placed_label_rects
                    .iter()
                    .any(|existing| existing.expand(3.0).intersects(candidate_rect))
                {
                    continue;
                }
                best_pos = candidate_pos;
                best_rect = candidate_rect;
                break;
            }

            painter.rect_filled(
                best_rect.expand2(egui::vec2(2.0, 1.0)),
                2.0,
                egui::Color32::from_rgba_premultiplied(20, 20, 24, 180),
            );
            painter.galley(best_pos, galley, text_colour);
            placed_label_rects.push(best_rect);
        }
    }

    app.graph_state.hovered_node = hovered;

    // Show tooltip for hovered node
    if let Some(hi) = hovered {
        let (_, _, ref obj_type, ref label, ref roles, _) = node_data[hi];
        let target_obj = app
            .graph_state
            .graph
            .as_ref()
            .and_then(|graph| graph.nodes.get(hi))
            .and_then(content_stream_target);
        egui::Tooltip::always_open(
            ui.ctx().clone(),
            ui.layer_id(),
            ui.id().with("graph_tooltip"),
            &response,
        )
        .at_pointer()
        .show(|ui| {
            ui.set_min_width(GRAPH_TOOLTIP_WIDTH);
            ui.strong(label);
            ui.label(format!("Type: {}", obj_type));
            let mitre_roles: Vec<&String> =
                roles.iter().filter(|r| r.starts_with("MITRE:")).collect();
            let other_roles: Vec<&String> =
                roles.iter().filter(|r| !r.starts_with("MITRE:")).collect();
            if !mitre_roles.is_empty() {
                ui.label(format!(
                    "MITRE: {}",
                    mitre_roles.iter().map(|r| &r[6..]).collect::<Vec<_>>().join(", ")
                ));
            }
            if !other_roles.is_empty() {
                ui.label(format!(
                    "Roles: {}",
                    other_roles.iter().map(|r| r.as_str()).collect::<Vec<_>>().join(", ")
                ));
            }
            if let Some((target_obj, target_gen)) = target_obj {
                ui.label(format!("Executes: obj {} {}", target_obj, target_gen));
                ui.small("Double-click to navigate to stream");
            }
        });
    }
    if hovered.is_none() {
        if let Some((edge_kind, provenance, edge_metadata)) = hovered_edge {
            egui::Tooltip::always_open(
                ui.ctx().clone(),
                ui.layer_id(),
                ui.id().with("graph_edge_tooltip"),
                &response,
            )
            .at_pointer()
            .show(|ui| {
                ui.set_min_width(GRAPH_TOOLTIP_WIDTH);
                ui.strong(edge_kind);
                if let Some(provenance) = provenance {
                    ui.label(format!("Provenance: {provenance}"));
                }
                if let Some(edge_metadata) = edge_metadata {
                    ui.label(format!("Metadata: {edge_metadata}"));
                }
            });
        }
    }

    // Handle click: select node
    if response.clicked() {
        if let Some(pointer) = pointer_pos {
            let mut closest = None;
            let mut closest_dist = f64::MAX;
            for (i, (gx, gy, _, _, _, _)) in node_data.iter().enumerate() {
                let p = to_screen(*gx, *gy);
                let dx = (pointer.x - p.x) as f64;
                let dy = (pointer.y - p.y) as f64;
                let dist = dx * dx + dy * dy;
                if dist < (node_radius as f64 + 4.0).powi(2) && dist < closest_dist {
                    closest = Some(i);
                    closest_dist = dist;
                }
            }
            app.graph_state.selected_node = closest;
        }
    }

    // Handle double-click: navigate to object in Object Inspector
    if response.double_clicked() {
        if let Some(hi) = hovered {
            if let Some(ref graph) = app.graph_state.graph {
                let node = &graph.nodes[hi];
                if let Some(event_node_id) = resolve_double_click_event_node(node) {
                    app.selected_event = Some(event_node_id);
                    app.show_events = true;
                    return;
                }
                if let Some((obj, gen)) = resolve_double_click_target(node) {
                    app.navigate_to_object(obj, gen);
                    app.show_objects = true;
                }
            }
        }
    }

    // Show node count info
    let info_text = format!("{} nodes, {} edges", node_count, edge_data.len());
    painter.text(
        rect.right_bottom() + egui::vec2(-8.0, -16.0),
        egui::Align2::RIGHT_BOTTOM,
        info_text,
        egui::FontId::proportional(11.0),
        egui::Color32::from_rgb(150, 150, 150),
    );
}

fn content_stream_target(node: &crate::graph_data::GraphNode) -> Option<(u32, u16)> {
    if node.is_content_stream_exec {
        node.target_obj
    } else {
        None
    }
}

fn resolve_double_click_target(node: &crate::graph_data::GraphNode) -> Option<(u32, u16)> {
    content_stream_target(node).or(node.object_ref)
}

fn resolve_double_click_event_node(node: &crate::graph_data::GraphNode) -> Option<String> {
    node.event_node_id.as_ref().filter(|node_id| node_id.starts_with("ev:")).cloned()
}

fn show_toolbar(ui: &mut egui::Ui, app: &mut SisApp) {
    let is_content_stream_mode =
        matches!(app.graph_state.mode, GraphViewMode::ContentStream { .. });
    ui.horizontal(|ui| {
        ui.label("Mode:");
        if ui
            .selectable_label(app.graph_state.mode == GraphViewMode::Structure, "Structure")
            .clicked()
        {
            switch_graph_mode(app, GraphViewMode::Structure);
        }
        if ui.selectable_label(app.graph_state.mode == GraphViewMode::Event, "Event").clicked() {
            switch_graph_mode(app, GraphViewMode::Event);
        }
        if ui
            .selectable_label(app.graph_state.mode == GraphViewMode::StagedDag, "Staged DAG")
            .clicked()
        {
            switch_graph_mode(app, GraphViewMode::StagedDag);
        }
        // Content mode only enabled when a content stream summary is loaded.
        let has_summary = app.content_stream_state.summary.is_some();
        let content_btn = ui.add_enabled(
            has_summary,
            egui::Button::selectable(is_content_stream_mode, "Content"),
        );
        if content_btn.clicked() {
            if let Some((obj, gen)) = app.content_stream_state.active_stream {
                switch_graph_mode(
                    app,
                    GraphViewMode::ContentStream { stream_ref: (obj, gen) },
                );
            }
        }
        if !has_summary {
            content_btn.on_disabled_hover_text("Open a content stream to enable this mode");
        }
        ui.separator();
        let label =
            if app.graph_state.show_controls_sidebar { "Hide Controls" } else { "Show Controls" };
        ui.toggle_value(&mut app.graph_state.show_controls_sidebar, label);
        if ui.button("Fit").clicked() {
            app.graph_state.fit_to_view_pending = true;
        }
    });
}

fn fit_graph_to_viewport(app: &mut SisApp, rect: egui::Rect) {
    app.graph_state.fit_to_view_pending = false;
    let Some(graph) = app.graph_state.graph.as_ref() else {
        return;
    };
    if graph.nodes.is_empty() {
        return;
    }
    let mut min_x = f64::INFINITY;
    let mut max_x = f64::NEG_INFINITY;
    let mut min_y = f64::INFINITY;
    let mut max_y = f64::NEG_INFINITY;
    for node in &graph.nodes {
        min_x = min_x.min(node.position[0]);
        max_x = max_x.max(node.position[0]);
        min_y = min_y.min(node.position[1]);
        max_y = max_y.max(node.position[1]);
    }
    if !min_x.is_finite() || !max_x.is_finite() || !min_y.is_finite() || !max_y.is_finite() {
        return;
    }

    let width = (max_x - min_x).max(1.0);
    let height = (max_y - min_y).max(1.0);
    let margin = 40.0;
    let fit_zoom_x = (rect.width() as f64 - margin) / width;
    let fit_zoom_y = (rect.height() as f64 - margin) / height;
    let fit_zoom = fit_zoom_x.min(fit_zoom_y).clamp(0.1, 10.0);
    let cx = (min_x + max_x) * 0.5;
    let cy = (min_y + max_y) * 0.5;
    app.graph_state.zoom = fit_zoom;
    app.graph_state.pan = [WORLD_CENTRE_X - cx, WORLD_CENTRE_Y - cy];
}

fn show_controls_sidebar(ui: &mut egui::Ui, app: &mut SisApp) {
    ui.heading("Graph Controls");
    ui.separator();

    if matches!(app.graph_state.mode, GraphViewMode::Event | GraphViewMode::StagedDag) {
        ui.label("Node kind:");
        egui::ComboBox::from_id_salt("graph_event_node_kind_filter")
            .selected_text(
                app.graph_state.event_node_kind_filter.clone().unwrap_or_else(|| "all".to_string()),
            )
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(app.graph_state.event_node_kind_filter.is_none(), "all")
                    .clicked()
                {
                    app.graph_state.event_node_kind_filter = None;
                }
                for value in ["event", "outcome", "object", "collapse"] {
                    let selected = app.graph_state.event_node_kind_filter.as_deref() == Some(value);
                    if ui.selectable_label(selected, value).clicked() {
                        app.graph_state.event_node_kind_filter = Some(value.to_string());
                    }
                }
            });

        ui.label("Trigger:");
        egui::ComboBox::from_id_salt("graph_event_trigger_filter")
            .selected_text(
                app.graph_state.event_trigger_filter.clone().unwrap_or_else(|| "all".to_string()),
            )
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(app.graph_state.event_trigger_filter.is_none(), "all")
                    .clicked()
                {
                    app.graph_state.event_trigger_filter = None;
                }
                for value in ["automatic", "hidden", "user"] {
                    let selected = app.graph_state.event_trigger_filter.as_deref() == Some(value);
                    if ui.selectable_label(selected, value).clicked() {
                        app.graph_state.event_trigger_filter = Some(value.to_string());
                    }
                }
            });

        let mut max_hops = app.graph_state.finding_detail_max_hops as i32;
        if ui.add(egui::Slider::new(&mut max_hops, 1..=20).text("Detail hops")).changed() {
            let new_hops = max_hops as usize;
            if new_hops != app.graph_state.finding_detail_max_hops {
                app.graph_state.finding_detail_max_hops = new_hops;
                if let Some(cache) = app.finding_detail_graph_cache.as_mut() {
                    cache.finding_paths.clear();
                }
            }
        }
        ui.separator();
    }

    if app.graph_state.mode == GraphViewMode::StagedDag {
        ui.separator();
        let mut spread = app.graph_state.dag_lane_vertical_spread;
        if ui.toggle_value(&mut spread, "Lane vertical spread").changed() {
            app.graph_state.dag_lane_vertical_spread = spread;
            rebuild_graph(app);
        }
        let mut h_spread = app.graph_state.dag_lane_horizontal_spread;
        if ui.toggle_value(&mut h_spread, "Lane horizontal spread").changed() {
            app.graph_state.dag_lane_horizontal_spread = h_spread;
            rebuild_graph(app);
        }
    }

    ui.label("Type:");
    let current_filter = if app.graph_state.type_filter.is_empty() {
        "All".to_string()
    } else {
        app.graph_state.type_filter.join(", ")
    };
    let type_filter_response = egui::ComboBox::from_id_salt("graph_type_filter")
        .selected_text(&current_filter)
        .show_ui(ui, |ui| {
            if ui.selectable_label(app.graph_state.type_filter.is_empty(), "All").clicked() {
                app.graph_state.type_filter.clear();
                rebuild_graph(app);
            }
            for t in &["page", "action", "stream", "font", "catalog", "image", "other"] {
                let selected = app.graph_state.type_filter.iter().any(|f| f == t);
                if ui.selectable_label(selected, *t).clicked() {
                    if selected {
                        app.graph_state.type_filter.retain(|f| f != t);
                    } else {
                        app.graph_state.type_filter.push(t.to_string());
                    }
                    rebuild_graph(app);
                }
            }
        });
    if app.graph_state.mode == GraphViewMode::Event {
        type_filter_response
            .response
            .on_hover_text("Type filter is only available in structure mode");
    }

    let mut depth = app.graph_state.depth_limit as i32;
    if ui.add(egui::Slider::new(&mut depth, 0..=10).text("Depth hops")).changed() {
        app.graph_state.depth_limit = depth as usize;
        rebuild_graph(app);
    }

    let mut min_edge_len = app.graph_state.min_edge_length;
    if ui.add(egui::Slider::new(&mut min_edge_len, 0.0..=200.0).text("Min edge len")).changed() {
        app.graph_state.min_edge_length = min_edge_len;
        rebuild_graph(app);
    }

    ui.separator();
    ui.toggle_value(&mut app.graph_state.chain_overlay, "Overlay chain");
    ui.toggle_value(&mut app.graph_state.chain_filter, "Dim non-chain");
    ui.toggle_value(&mut app.graph_state.show_critical_path, "Critical path");
    let taint_enabled = app.result.as_ref().is_some_and(|result| {
        sis_pdf_core::taint::taint_from_findings(&result.report.findings).flagged
    });
    ui.add_enabled_ui(taint_enabled, |ui| {
        ui.toggle_value(&mut app.graph_state.show_taint_overlay, "Taint");
    });
    ui.toggle_value(&mut app.graph_state.show_labels, "Labels");

    if app.graph_state.mode != GraphViewMode::Structure {
        ui.separator();
        show_mitre_panel(ui, app);
    }

    ui.separator();
    if ui.button("Reset view").clicked() {
        app.graph_state.pan = [0.0, 0.0];
        app.graph_state.zoom = 1.0;
        rebuild_graph(app);
    }
}

fn current_focus_object(app: &SisApp) -> Option<(u32, u16)> {
    let graph = app.graph_state.graph.as_ref()?;
    let selected = app.graph_state.selected_node?;
    graph.nodes.get(selected)?.object_ref
}

fn switch_graph_mode(app: &mut SisApp, mode: GraphViewMode) {
    if app.graph_state.mode == mode {
        return;
    }
    let focus = current_focus_object(app);
    app.graph_state.mode = mode;
    app.graph_state.dag_layout_dirty = mode == GraphViewMode::StagedDag;
    rebuild_graph(app);
    if let Some((obj, gen)) = focus {
        app.graph_state.pending_focus = Some((obj, gen));
    }
}

fn build_content_stream_graph_for_gui(app: &mut SisApp) -> Result<GraphData, GraphError> {
    let summary = app.content_stream_state.summary.as_ref().ok_or_else(|| {
        GraphError::ParseFailed("No content stream summary available. Open a content stream first.".to_string())
    })?;
    let findings = &app.content_stream_state.correlated_findings;
    let xobject_children = &app.content_stream_state.xobject_children;

    let csg = if app.content_stream_state.show_xobject_children && !xobject_children.is_empty() {
        sis_pdf_pdf::content_summary::build_content_graph_recursive(summary, xobject_children)
    } else {
        sis_pdf_pdf::content_summary::build_content_graph(summary)
    };
    graph_data::from_content_graph(&csg, findings)
}

/// Build the graph from the current analysis result.
fn build_graph(app: &mut SisApp) {
    app.graph_state.built = true;
    app.graph_state.error = None;
    app.graph_state.graph = None;
    app.graph_state.layout = None;

    let Some(ref result) = app.result else {
        return;
    };

    let graph_result = if matches!(app.graph_state.mode, GraphViewMode::ContentStream { .. }) {
        build_content_stream_graph_for_gui(app)
    } else if app.graph_state.mode == GraphViewMode::Event
        || app.graph_state.mode == GraphViewMode::StagedDag
    {
        build_event_graph_for_gui(app)
    } else if !app.graph_state.type_filter.is_empty() {
        let types: Vec<&str> = app.graph_state.type_filter.iter().map(|s| s.as_str()).collect();
        graph_data::from_object_data_filtered(&result.object_data, &types)
    } else if app.graph_state.depth_limit > 0 {
        // Use depth limit from selected node or catalog
        let centre = app
            .graph_state
            .selected_node
            .and_then(|i| app.graph_state.graph.as_ref().and_then(|g| g.nodes[i].object_ref))
            .or_else(|| {
                result
                    .object_data
                    .objects
                    .iter()
                    .find(|o| o.obj_type == "catalog")
                    .map(|o| (o.obj, o.gen))
            })
            .unwrap_or((1, 0));
        graph_data::from_object_data_depth(&result.object_data, centre, app.graph_state.depth_limit)
    } else {
        graph_data::from_object_data(&result.object_data)
    };

    match graph_result {
        Ok(graph) => {
            app.graph_state.graph = Some(graph);
            if app.graph_state.mode == GraphViewMode::StagedDag {
                if let Some(graph_ref) = app.graph_state.graph.as_mut() {
                    apply_staged_dag_layout_with_spread(
                        graph_ref,
                        app.graph_state.dag_lane_vertical_spread,
                        app.graph_state.dag_lane_horizontal_spread,
                    );
                }
                app.graph_state.layout = None;
                app.graph_state.dag_layout_dirty = false;
            } else {
                let node_count = app.graph_state.graph.as_ref().map_or(0, |g| g.nodes.len());
                let layout = LayoutState::new_with_min_edge_length(
                    node_count,
                    app.graph_state.min_edge_length,
                );
                if let Some(graph_ref) = app.graph_state.graph.as_mut() {
                    layout.initialise_positions(graph_ref);
                }
                app.graph_state.layout = Some(layout);
                app.graph_state.layout_start_time = app.elapsed_time;
            }
            recompute_graph_overlays(app);
        }
        Err(GraphError::TooManyNodes { count, limit }) => {
            app.graph_state.error = Some(format!(
                "Graph has {} objects (limit {}). Apply type or depth filters first.",
                count, limit
            ));
        }
        Err(GraphError::ParseFailed(msg)) => {
            app.graph_state.error = Some(msg);
        }
    }
}

fn build_event_graph_for_gui(app: &mut SisApp) -> Result<GraphData, GraphError> {
    let event_graph =
        app.cached_event_graph().map_err(|err| GraphError::ParseFailed(err.to_string()))?;
    graph_data::from_event_graph(event_graph)
}

fn draw_staged_lanes(
    painter: &egui::Painter,
    rect: egui::Rect,
    to_screen: &dyn Fn(f64, f64) -> egui::Pos2,
) {
    let labels = ["INPUT", "DECODE", "RENDER", "EXECUTE", "EGRESS"];
    // Staged DAG layout is anchored to world coordinates in [0, 800]x[0, 600].
    let lane_w = 800.0 / labels.len() as f64;
    for (idx, label) in labels.iter().enumerate() {
        let x = lane_w * idx as f64;
        let line_top = to_screen(x, 0.0);
        let line_bottom = to_screen(x, 600.0);
        painter.line_segment(
            [egui::pos2(line_top.x, rect.top()), egui::pos2(line_bottom.x, rect.bottom())],
            egui::Stroke::new(1.0, egui::Color32::from_rgba_premultiplied(180, 180, 180, 40)),
        );
        let label_pos = to_screen(x + lane_w * 0.5, 0.0);
        painter.text(
            egui::pos2(label_pos.x, rect.top() + 6.0),
            egui::Align2::CENTER_TOP,
            *label,
            egui::FontId::proportional(11.0),
            egui::Color32::from_rgb(170, 170, 170),
        );
    }
}

fn draw_back_edge_curve(
    painter: &egui::Painter,
    from: egui::Pos2,
    to: egui::Pos2,
    stroke: egui::Stroke,
) {
    let control_y = from.y.min(to.y) - 42.0;
    let control = egui::pos2((from.x + to.x) * 0.5, control_y);
    let segments = 16;
    let mut points = Vec::with_capacity(segments + 1);
    for i in 0..=segments {
        let t = i as f32 / segments as f32;
        let inv = 1.0 - t;
        let x = inv * inv * from.x + 2.0 * inv * t * control.x + t * t * to.x;
        let y = inv * inv * from.y + 2.0 * inv * t * control.y + t * t * to.y;
        points.push(egui::pos2(x, y));
    }
    painter.add(egui::Shape::line(points, stroke));
}

fn node_has_taint_edge(node_idx: usize, taint_edges: &HashSet<(usize, usize)>) -> bool {
    taint_edges.iter().any(|(from, to)| *from == node_idx || *to == node_idx)
}

fn show_mitre_panel(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref graph) = app.graph_state.graph else {
        return;
    };
    let mut technique_counts: Vec<(String, usize)> = Vec::new();
    let mut index: HashMap<String, HashSet<usize>> = HashMap::new();
    for (idx, node) in graph.nodes.iter().enumerate() {
        for role in &node.roles {
            let Some(raw) = role.strip_prefix("MITRE:") else {
                continue;
            };
            for technique in raw.split(',').map(str::trim).filter(|value| !value.is_empty()) {
                index.entry(technique.to_string()).or_default().insert(idx);
            }
        }
    }
    for (technique, nodes) in &index {
        technique_counts.push((technique.clone(), nodes.len()));
    }
    if technique_counts.is_empty() {
        return;
    }
    technique_counts.sort_by(|a, b| a.0.cmp(&b.0));
    ui.collapsing("MITRE techniques", |ui| {
        ui.horizontal_wrapped(|ui| {
            if ui
                .selectable_label(app.graph_state.mitre_selected_technique.is_none(), "clear")
                .clicked()
            {
                app.graph_state.mitre_selected_technique = None;
                app.graph_state.mitre_highlight_nodes.clear();
            }
            for (technique, count) in &technique_counts {
                let selected =
                    app.graph_state.mitre_selected_technique.as_deref() == Some(technique);
                if ui.selectable_label(selected, format!("{technique} ({count})")).clicked() {
                    app.graph_state.mitre_selected_technique = Some(technique.clone());
                    app.graph_state.mitre_highlight_nodes =
                        index.get(technique).cloned().unwrap_or_default();
                }
            }
        });
    });
}

fn recompute_graph_overlays(app: &mut SisApp) {
    let Some(ref graph) = app.graph_state.graph else {
        app.graph_state.critical_path_edges.clear();
        app.graph_state.critical_path_nodes.clear();
        app.graph_state.taint_edges.clear();
        app.graph_state.taint_source_nodes.clear();
        app.graph_state.mitre_highlight_nodes.clear();
        return;
    };
    let (critical_edges, critical_nodes) = compute_critical_path(graph);
    app.graph_state.critical_path_edges = critical_edges;
    app.graph_state.critical_path_nodes = critical_nodes;
    let (taint_edges, taint_sources) = map_taint_overlay(app, graph);
    app.graph_state.taint_edges = taint_edges;
    app.graph_state.taint_source_nodes = taint_sources;
    if let Some(selected) = app.graph_state.mitre_selected_technique.clone() {
        app.graph_state.mitre_highlight_nodes = compute_mitre_nodes(graph, &selected);
    } else {
        app.graph_state.mitre_highlight_nodes.clear();
    }
}

fn compute_mitre_nodes(graph: &GraphData, technique: &str) -> HashSet<usize> {
    let mut nodes = HashSet::new();
    for (idx, node) in graph.nodes.iter().enumerate() {
        if node.roles.iter().any(|role| {
            role.strip_prefix("MITRE:")
                .map(|raw| raw.split(',').any(|item| item.trim() == technique))
                .unwrap_or(false)
        }) {
            nodes.insert(idx);
        }
    }
    nodes
}

fn map_taint_overlay(app: &SisApp, graph: &GraphData) -> (Vec<(usize, usize)>, HashSet<usize>) {
    let Some(ref result) = app.result else {
        return (Vec::new(), HashSet::new());
    };
    let taint = sis_pdf_core::taint::taint_from_findings(&result.report.findings);
    if !taint.flagged {
        return (Vec::new(), HashSet::new());
    }
    map_taint_overlay_from_taint(&taint, graph)
}

fn map_taint_overlay_from_taint(
    taint: &sis_pdf_core::taint::Taint,
    graph: &GraphData,
) -> (Vec<(usize, usize)>, HashSet<usize>) {
    let mut nodes_by_ref: HashMap<(u32, u16), Vec<usize>> = HashMap::new();
    for (idx, node) in graph.nodes.iter().enumerate() {
        if let Some(obj_ref) = node.object_ref {
            nodes_by_ref.entry(obj_ref).or_default().push(idx);
        }
    }
    let mut source_nodes = HashSet::new();
    for source in &taint.taint_sources {
        if let Some(indices) = nodes_by_ref.get(source) {
            for idx in indices {
                source_nodes.insert(*idx);
            }
        }
    }
    let edge_set: HashSet<(usize, usize)> =
        graph.edges.iter().map(|edge| (edge.from_idx, edge.to_idx)).collect();
    let mut taint_edges = Vec::new();
    for (from_obj, to_obj) in &taint.taint_propagation {
        let Some(from_indices) = nodes_by_ref.get(from_obj) else {
            continue;
        };
        let Some(to_indices) = nodes_by_ref.get(to_obj) else {
            continue;
        };
        for from_idx in from_indices {
            for to_idx in to_indices {
                if edge_set.contains(&(*from_idx, *to_idx)) {
                    taint_edges.push((*from_idx, *to_idx));
                }
            }
        }
    }
    taint_edges.sort_unstable();
    taint_edges.dedup();
    (taint_edges, source_nodes)
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct QueueEntry {
    cost: f64,
    node: usize,
}

impl Eq for QueueEntry {}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compute_critical_path(graph: &GraphData) -> (HashSet<(usize, usize)>, HashSet<usize>) {
    let trigger_nodes: Vec<usize> = graph
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(idx, node)| {
            if node.obj_type.eq_ignore_ascii_case("event")
                && node.roles.iter().any(|role| role.eq_ignore_ascii_case("automatic"))
            {
                Some(idx)
            } else {
                None
            }
        })
        .collect();
    let outcome_nodes: HashSet<usize> = graph
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(idx, node)| node.obj_type.eq_ignore_ascii_case("outcome").then_some(idx))
        .collect();
    if trigger_nodes.is_empty() || outcome_nodes.is_empty() {
        return (HashSet::new(), HashSet::new());
    }

    let mut distances = vec![f64::INFINITY; graph.nodes.len()];
    let mut previous: HashMap<usize, usize> = HashMap::new();
    let mut heap = BinaryHeap::new();
    for trigger in trigger_nodes {
        distances[trigger] = 0.0;
        heap.push(QueueEntry { cost: 0.0, node: trigger });
    }

    while let Some(QueueEntry { cost, node }) = heap.pop() {
        if cost > distances[node] {
            continue;
        }
        for edge in graph.edges.iter().filter(|edge| edge.from_idx == node) {
            let confidence = graph.nodes[edge.to_idx].confidence.unwrap_or(0.5).clamp(0.01, 1.0);
            let weight = -f64::ln(confidence as f64);
            let next_cost = cost + weight;
            if next_cost < distances[edge.to_idx] {
                distances[edge.to_idx] = next_cost;
                previous.insert(edge.to_idx, node);
                heap.push(QueueEntry { cost: next_cost, node: edge.to_idx });
            }
        }
    }

    let mut best_outcome = None;
    let mut best_cost = f64::INFINITY;
    for outcome in outcome_nodes {
        if distances[outcome].is_finite() && distances[outcome] < best_cost {
            best_cost = distances[outcome];
            best_outcome = Some(outcome);
        }
    }
    let Some(mut cursor) = best_outcome else {
        return (HashSet::new(), HashSet::new());
    };
    let mut nodes = HashSet::new();
    let mut edges = HashSet::new();
    nodes.insert(cursor);
    while let Some(parent) = previous.get(&cursor).copied() {
        edges.insert((parent, cursor));
        nodes.insert(parent);
        cursor = parent;
    }
    (edges, nodes)
}

/// Rebuild the graph (e.g., after filter changes).
fn rebuild_graph(app: &mut SisApp) {
    app.graph_state.built = false;
    app.graph_state.selected_node = None;
    app.graph_state.hovered_node = None;
}

/// Run a few layout iterations per frame.
fn run_layout_step(app: &mut SisApp) {
    let Some(ref mut layout) = app.graph_state.layout else {
        return;
    };
    let Some(ref mut graph) = app.graph_state.graph else {
        app.graph_state.layout = None;
        return;
    };

    let done = layout.step(graph, 8);
    if done {
        let node_count = graph.nodes.len();
        let duration_ms = (app.elapsed_time - app.graph_state.layout_start_time) * 1000.0;
        app.telemetry.record(
            app.elapsed_time,
            crate::telemetry::TelemetryEventKind::GraphLayoutCompleted { node_count, duration_ms },
        );
        app.graph_state.layout = None;
    }
}

fn build_visible_node_set(app: &SisApp, graph: &GraphData) -> std::collections::HashSet<usize> {
    let mut visible = std::collections::HashSet::new();
    for (idx, node) in graph.nodes.iter().enumerate() {
        if matches!(
            app.graph_state.mode,
            GraphViewMode::Structure | GraphViewMode::ContentStream { .. }
        ) {
            visible.insert(idx);
            continue;
        }

        if let Some(kind_filter) = app.graph_state.event_node_kind_filter.as_deref() {
            if !node.obj_type.eq_ignore_ascii_case(kind_filter) {
                continue;
            }
        }

        if let Some(trigger_filter) = app.graph_state.event_trigger_filter.as_deref() {
            if !node.roles.iter().any(|role| role.eq_ignore_ascii_case(trigger_filter)) {
                if node.obj_type.eq_ignore_ascii_case("event") {
                    continue;
                }
            }
        }

        visible.insert(idx);
    }
    visible
}

struct ChainOverlay {
    node_set: std::collections::HashSet<usize>,
    path_edges: std::collections::HashSet<(usize, usize)>,
}

/// Build chain overlay node/edge sets for the currently selected chain.
fn build_chain_overlay(app: &SisApp) -> ChainOverlay {
    let mut node_set = std::collections::HashSet::new();
    let mut ordered_object_nodes = Vec::new();
    let Some(chain_idx) = app.selected_chain else {
        return ChainOverlay { node_set, path_edges: std::collections::HashSet::new() };
    };
    let Some(ref result) = app.result else {
        return ChainOverlay { node_set, path_edges: std::collections::HashSet::new() };
    };
    let Some(ref graph) = app.graph_state.graph else {
        return ChainOverlay { node_set, path_edges: std::collections::HashSet::new() };
    };

    if chain_idx >= result.report.chains.len() {
        return ChainOverlay { node_set, path_edges: std::collections::HashSet::new() };
    }

    let chain = &result.report.chains[chain_idx];

    // Extract object refs from chain trigger/action/payload text
    for text in [&chain.trigger, &chain.action, &chain.payload].iter().filter_map(|t| t.as_ref()) {
        if let Some((obj, gen)) = crate::panels::chains::extract_obj_ref_from_text(text) {
            if let Some(&idx) = graph.node_index.get(&(obj, gen)) {
                if !ordered_object_nodes.contains(&idx) {
                    ordered_object_nodes.push(idx);
                }
            }
            for (idx, node) in graph.nodes.iter().enumerate() {
                if node.object_ref == Some((obj, gen)) {
                    node_set.insert(idx);
                }
            }
        }
    }

    let path_edges = build_chain_path_edges(&ordered_object_nodes, &graph.edges);
    ChainOverlay { node_set, path_edges }
}

fn build_chain_path_edges(
    ordered_object_nodes: &[usize],
    graph_edges: &[crate::graph_data::GraphEdge],
) -> std::collections::HashSet<(usize, usize)> {
    let mut pairs = std::collections::HashSet::new();
    for window in ordered_object_nodes.windows(2) {
        let from = window[0];
        let to = window[1];
        let path = find_directed_path_edges(graph_edges, from, to, 24);
        for edge in path {
            pairs.insert(edge);
        }
    }
    pairs
}

fn find_directed_path_edges(
    graph_edges: &[crate::graph_data::GraphEdge],
    from: usize,
    to: usize,
    max_hops: usize,
) -> Vec<(usize, usize)> {
    if from == to {
        return Vec::new();
    }

    let mut adjacency: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for edge in graph_edges {
        adjacency.entry(edge.from_idx).or_default().push(edge.to_idx);
    }

    let mut queue = std::collections::VecDeque::new();
    let mut visited = std::collections::HashSet::new();
    let mut prev: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut depth: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();

    queue.push_back(from);
    visited.insert(from);
    depth.insert(from, 0);

    while let Some(node) = queue.pop_front() {
        let current_depth = depth.get(&node).copied().unwrap_or(0);
        if current_depth >= max_hops {
            continue;
        }
        let Some(neighbours) = adjacency.get(&node) else {
            continue;
        };
        for next in neighbours {
            if visited.contains(next) {
                continue;
            }
            visited.insert(*next);
            prev.insert(*next, node);
            depth.insert(*next, current_depth + 1);
            if *next == to {
                let mut cursor = to;
                let mut nodes = vec![to];
                while let Some(parent) = prev.get(&cursor).copied() {
                    nodes.push(parent);
                    if parent == from {
                        break;
                    }
                    cursor = parent;
                }
                nodes.reverse();
                return nodes.windows(2).map(|w| (w[0], w[1])).collect();
            }
            queue.push_back(*next);
        }
    }

    Vec::new()
}

fn draw_edge_arrowhead(
    painter: &egui::Painter,
    from: egui::Pos2,
    to: egui::Pos2,
    stroke: egui::Stroke,
    target_node_radius: f32,
) {
    let dx = to.x - from.x;
    let dy = to.y - from.y;
    let len = (dx * dx + dy * dy).sqrt();
    if len <= 0.001 {
        return;
    }

    let dir = egui::vec2(dx / len, dy / len);
    let perp = egui::vec2(-dir.y, dir.x);
    let arrow_len = (6.0 + stroke.width * 2.0).clamp(6.0, 10.0);
    let arrow_half_width = (3.0 + stroke.width).clamp(3.0, 6.0);

    let offset = target_node_radius + 2.0;
    let tip = to - dir * offset;
    let base = tip - dir * arrow_len;
    let left = base + perp * arrow_half_width;
    let right = base - perp * arrow_half_width;

    painter.add(egui::Shape::convex_polygon(
        vec![tip, left, right],
        stroke.color,
        egui::Stroke::NONE,
    ));
}

fn apply_pending_focus(app: &mut SisApp) {
    let Some((obj, gen)) = app.graph_state.pending_focus else {
        return;
    };
    let Some(ref graph) = app.graph_state.graph else {
        return;
    };
    let Some(&idx) = graph.node_index.get(&(obj, gen)) else {
        return;
    };

    let node = &graph.nodes[idx];
    app.graph_state.selected_node = Some(idx);
    app.graph_state.pan = [WORLD_CENTRE_X - node.position[0], WORLD_CENTRE_Y - node.position[1]];
    app.graph_state.pending_focus = None;
}

#[cfg(test)]
mod tests {
    use super::{
        build_chain_path_edges, compute_critical_path, compute_mitre_nodes,
        find_directed_path_edges, map_taint_overlay_from_taint, resolve_double_click_target,
    };
    use crate::graph_data::{GraphData, GraphEdge, GraphNode};
    use sis_pdf_core::taint::Taint;
    use std::collections::HashMap;
    use std::env;
    use std::time::{Duration, Instant};

    fn strict_perf_budget_enabled() -> bool {
        env::var("SIS_GUI_STRICT_PERF_BUDGET").ok().as_deref() == Some("1")
    }

    #[test]
    fn chain_path_overlay_keeps_directed_edges_only() {
        let ordered_object_nodes = vec![10usize, 20usize, 30usize];
        let graph_edges = vec![
            GraphEdge {
                from_idx: 10,
                to_idx: 20,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
            GraphEdge {
                from_idx: 20,
                to_idx: 30,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
            GraphEdge {
                from_idx: 30,
                to_idx: 20,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
        ];
        let overlay_edges = build_chain_path_edges(&ordered_object_nodes, &graph_edges);
        assert!(overlay_edges.contains(&(10, 20)));
        assert!(overlay_edges.contains(&(20, 30)));
        assert!(!overlay_edges.contains(&(30, 20)));
    }

    #[test]
    fn critical_path_prefers_higher_confidence_outcome_path() {
        let nodes = vec![
            GraphNode {
                object_ref: None,
                obj_type: "event".into(),
                label: "Trigger".into(),
                roles: vec!["automatic".into()],
                confidence: Some(1.0),
                position: [0.0, 0.0],
                ..Default::default()
            },
            GraphNode {
                object_ref: None,
                obj_type: "outcome".into(),
                label: "OutcomeLow".into(),
                roles: Vec::new(),
                confidence: Some(0.2),
                position: [0.0, 0.0],
                ..Default::default()
            },
            GraphNode {
                object_ref: None,
                obj_type: "outcome".into(),
                label: "OutcomeHigh".into(),
                roles: Vec::new(),
                confidence: Some(0.9),
                position: [0.0, 0.0],
                ..Default::default()
            },
        ];
        let edges = vec![
            GraphEdge {
                from_idx: 0,
                to_idx: 1,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
            GraphEdge {
                from_idx: 0,
                to_idx: 2,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
        ];
        let graph = GraphData { nodes, edges, node_index: HashMap::new() };
        let (edges, nodes) = compute_critical_path(&graph);
        assert!(edges.contains(&(0, 2)));
        assert!(nodes.contains(&0));
        assert!(nodes.contains(&2));
        assert!(!edges.contains(&(0, 1)));
    }

    #[test]
    fn mitre_nodes_match_selected_technique() {
        let graph = GraphData {
            nodes: vec![
                GraphNode {
                    object_ref: None,
                    obj_type: "event".into(),
                    label: "n0".into(),
                    roles: vec!["MITRE:T1059.007".into()],
                    confidence: None,
                    position: [0.0, 0.0],
                    ..Default::default()
                },
                GraphNode {
                    object_ref: None,
                    obj_type: "event".into(),
                    label: "n1".into(),
                    roles: vec!["MITRE:T1204.002,T1059.007".into()],
                    confidence: None,
                    position: [0.0, 0.0],
                    ..Default::default()
                },
            ],
            edges: Vec::new(),
            node_index: HashMap::new(),
        };
        let nodes = compute_mitre_nodes(&graph, "T1059.007");
        assert!(nodes.contains(&0));
        assert!(nodes.contains(&1));
    }

    #[test]
    fn directed_path_search_finds_multi_hop_route() {
        let graph_edges = vec![
            GraphEdge {
                from_idx: 1,
                to_idx: 2,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
            GraphEdge {
                from_idx: 2,
                to_idx: 5,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
            GraphEdge {
                from_idx: 5,
                to_idx: 9,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
            GraphEdge {
                from_idx: 1,
                to_idx: 3,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
        ];
        let path = find_directed_path_edges(&graph_edges, 1, 9, 8);
        assert_eq!(path, vec![(1, 2), (2, 5), (5, 9)]);
    }

    #[test]
    fn default_finding_detail_max_hops_is_eight() {
        let state = super::GraphViewerState::default();
        assert_eq!(state.finding_detail_max_hops, 8);
    }

    #[test]
    fn critical_path_budget() {
        let node_count = 2_000usize;
        let edge_count = 5_000usize;
        let mut nodes = Vec::with_capacity(node_count);
        for idx in 0..node_count {
            let obj_type = if idx % 40 == 0 { "outcome" } else { "event" };
            let mut roles = Vec::new();
            if idx % 30 == 0 {
                roles.push("automatic".to_string());
            }
            nodes.push(GraphNode {
                object_ref: Some(((idx + 1) as u32, 0)),
                obj_type: obj_type.to_string(),
                label: format!("n{idx}"),
                roles,
                confidence: Some(0.8),
                position: [0.0, 0.0],
                ..Default::default()
            });
        }
        let mut edges = Vec::with_capacity(edge_count);
        for idx in 0..edge_count {
            let from_idx = idx % node_count;
            let mut to_idx = (idx * 17 + 23) % node_count;
            if to_idx == from_idx {
                to_idx = (to_idx + 1) % node_count;
            }
            edges.push(GraphEdge {
                from_idx,
                to_idx,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            });
        }
        let graph = GraphData { nodes, edges, node_index: HashMap::new() };
        let start = Instant::now();
        let (_edges, _nodes) = compute_critical_path(&graph);
        let elapsed = start.elapsed();
        if strict_perf_budget_enabled() {
            assert!(
                elapsed <= Duration::from_millis(80),
                "critical path exceeded strict budget: {:?}",
                elapsed
            );
        } else {
            assert!(
                elapsed <= Duration::from_secs(2),
                "critical path exceeded fallback budget: {:?}",
                elapsed
            );
        }
    }

    #[test]
    fn taint_overlay_mapping_budget() {
        let node_count = 2_000usize;
        let edge_count = 5_000usize;
        let mut nodes = Vec::with_capacity(node_count);
        for idx in 0..node_count {
            nodes.push(GraphNode {
                object_ref: Some(((idx + 1) as u32, 0)),
                obj_type: "object".to_string(),
                label: format!("obj{idx}"),
                roles: Vec::new(),
                confidence: None,
                position: [0.0, 0.0],
                ..Default::default()
            });
        }
        let mut edges = Vec::with_capacity(edge_count);
        let mut taint_propagation = Vec::with_capacity(edge_count);
        for idx in 0..edge_count {
            let from_idx = idx % node_count;
            let mut to_idx = (idx * 29 + 7) % node_count;
            if to_idx == from_idx {
                to_idx = (to_idx + 1) % node_count;
            }
            edges.push(GraphEdge {
                from_idx,
                to_idx,
                suspicious: true,
                edge_kind: Some("taint".into()),
                provenance: None,
                metadata: None,
            });
            taint_propagation.push((((from_idx + 1) as u32, 0), ((to_idx + 1) as u32, 0)));
        }
        let graph = GraphData { nodes, edges, node_index: HashMap::new() };
        let taint = Taint {
            flagged: true,
            reasons: vec!["benchmark".into()],
            taint_sources: (1..=200).map(|obj| (obj, 0)).collect(),
            taint_propagation,
        };
        let start = Instant::now();
        let (mapped_edges, source_nodes) = map_taint_overlay_from_taint(&taint, &graph);
        let elapsed = start.elapsed();
        if strict_perf_budget_enabled() {
            assert!(
                elapsed <= Duration::from_millis(60),
                "taint mapping exceeded strict budget: {:?}",
                elapsed
            );
        } else {
            assert!(
                elapsed <= Duration::from_secs(2),
                "taint mapping exceeded fallback budget: {:?}",
                elapsed
            );
        }
        assert!(!mapped_edges.is_empty());
        assert!(!source_nodes.is_empty());
    }

    #[test]
    fn graph_double_click_prefers_target_only_for_content_stream_exec() {
        let node = GraphNode {
            object_ref: Some((3, 0)),
            target_obj: Some((7, 0)),
            is_content_stream_exec: true,
            ..Default::default()
        };
        assert_eq!(resolve_double_click_target(&node), Some((7, 0)));
    }

    #[test]
    fn graph_double_click_uses_source_for_non_content_stream_exec() {
        let node = GraphNode {
            object_ref: Some((3, 0)),
            target_obj: Some((7, 0)),
            is_content_stream_exec: false,
            ..Default::default()
        };
        assert_eq!(resolve_double_click_target(&node), Some((3, 0)));
    }
}

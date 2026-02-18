use crate::app::SisApp;
use crate::graph_data::{self, GraphData, GraphError};
use crate::graph_layout::LayoutState;
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GraphViewMode {
    #[default]
    Structure,
    Event,
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
        }
    }
}

/// Node type colour mapping.
fn node_colour(obj_type: &str) -> egui::Color32 {
    match obj_type.to_lowercase().as_str() {
        "event" => egui::Color32::from_rgb(245, 170, 66), // amber
        "outcome" => egui::Color32::from_rgb(220, 80, 80), // red
        "collapse" => egui::Color32::from_rgb(120, 120, 120), // dark grey
        "page" => egui::Color32::from_rgb(70, 130, 230),  // blue
        "action" => egui::Color32::from_rgb(220, 60, 60), // red
        "stream" => egui::Color32::from_rgb(60, 180, 80), // green
        "font" => egui::Color32::from_rgb(160, 160, 160), // grey
        "catalog" | "catalogue" => egui::Color32::from_rgb(160, 80, 200), // purple
        "image" => egui::Color32::from_rgb(230, 160, 40), // orange
        _ => egui::Color32::from_rgb(140, 140, 140),      // default grey
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

    // Render graph canvas
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

    let pan = app.graph_state.pan;
    let zoom = if app.graph_state.zoom == 0.0 { 1.0 } else { app.graph_state.zoom };
    let selected = app.graph_state.selected_node;
    let show_labels = app.graph_state.show_labels;
    let is_layout_running = app.graph_state.layout.is_some();
    let node_radius = (6.0 * zoom).clamp(3.0, 20.0) as f32;

    // Allocate painter for custom drawing
    let available = ui.available_size();
    let (response, painter) = ui.allocate_painter(available, egui::Sense::click_and_drag());
    let rect = response.rect;

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

        if dim_non_chain {
            let from_in_chain = chain_overlay.node_set.contains(&from_idx);
            let to_in_chain = chain_overlay.node_set.contains(&to_idx);
            if (!from_in_chain || !to_in_chain) && !selected_connection {
                colour = egui::Color32::from_rgba_premultiplied(60, 60, 60, 40);
            }
        }

        let stroke = egui::Stroke::new(width, colour);
        painter.line_segment([p1, p2], stroke);
        draw_edge_arrowhead(&painter, p1, p2, stroke, node_radius);

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

        if selected == Some(i) {
            // Draw selection ring
            painter.circle_stroke(
                p,
                node_radius + 3.0,
                egui::Stroke::new(2.0, egui::Color32::WHITE),
            );
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
            painter.text(
                p + egui::vec2(node_radius + 2.0, -6.0),
                egui::Align2::LEFT_TOP,
                label,
                egui::FontId::proportional((10.0 * zoom).clamp(8.0, 14.0) as f32),
                egui::Color32::from_rgb(200, 200, 200),
            );
        }
    }

    app.graph_state.hovered_node = hovered;

    // Show tooltip for hovered node
    if let Some(hi) = hovered {
        let (_, _, ref obj_type, ref label, ref roles, _) = node_data[hi];
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
            if !roles.is_empty() {
                ui.label(format!("Roles: {}", roles.join(", ")));
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
                if let Some((obj, gen)) = node.object_ref {
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

fn show_toolbar(ui: &mut egui::Ui, app: &mut SisApp) {
    ui.horizontal(|ui| {
        ui.label("Mode:");
        if ui
            .selectable_label(app.graph_state.mode == GraphViewMode::Structure, "Structure")
            .clicked()
        {
            app.graph_state.mode = GraphViewMode::Structure;
            rebuild_graph(app);
        }
        if ui.selectable_label(app.graph_state.mode == GraphViewMode::Event, "Event").clicked() {
            app.graph_state.mode = GraphViewMode::Event;
            rebuild_graph(app);
        }

        ui.separator();

        if app.graph_state.mode == GraphViewMode::Event {
            ui.label("Node kind:");
            egui::ComboBox::from_id_salt("graph_event_node_kind_filter")
                .selected_text(
                    app.graph_state
                        .event_node_kind_filter
                        .clone()
                        .unwrap_or_else(|| "all".to_string()),
                )
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(app.graph_state.event_node_kind_filter.is_none(), "all")
                        .clicked()
                    {
                        app.graph_state.event_node_kind_filter = None;
                    }
                    for value in ["event", "outcome", "object", "collapse"] {
                        let selected =
                            app.graph_state.event_node_kind_filter.as_deref() == Some(value);
                        if ui.selectable_label(selected, value).clicked() {
                            app.graph_state.event_node_kind_filter = Some(value.to_string());
                        }
                    }
                });

            ui.label("Trigger:");
            egui::ComboBox::from_id_salt("graph_event_trigger_filter")
                .selected_text(
                    app.graph_state
                        .event_trigger_filter
                        .clone()
                        .unwrap_or_else(|| "all".to_string()),
                )
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(app.graph_state.event_trigger_filter.is_none(), "all")
                        .clicked()
                    {
                        app.graph_state.event_trigger_filter = None;
                    }
                    for value in ["automatic", "hidden", "user"] {
                        let selected =
                            app.graph_state.event_trigger_filter.as_deref() == Some(value);
                        if ui.selectable_label(selected, value).clicked() {
                            app.graph_state.event_trigger_filter = Some(value.to_string());
                        }
                    }
                });
            ui.separator();
        }

        // Type filter combo
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

        ui.separator();

        // Depth slider
        ui.label("Depth:");
        let mut depth = app.graph_state.depth_limit as i32;
        if ui.add(egui::Slider::new(&mut depth, 0..=10).text("hops")).changed() {
            app.graph_state.depth_limit = depth as usize;
            rebuild_graph(app);
        }

        ui.separator();

        ui.label("Min edge len:");
        let mut min_edge_len = app.graph_state.min_edge_length;
        if ui.add(egui::Slider::new(&mut min_edge_len, 0.0..=200.0).text("px")).changed() {
            app.graph_state.min_edge_length = min_edge_len;
            rebuild_graph(app);
        }

        ui.separator();

        // Chain overlay controls
        ui.toggle_value(&mut app.graph_state.chain_overlay, "Overlay chain");
        ui.toggle_value(&mut app.graph_state.chain_filter, "Dim non-chain");

        // Labels toggle
        ui.toggle_value(&mut app.graph_state.show_labels, "Labels");

        ui.separator();

        // Reset layout button
        if ui.button("Reset").clicked() {
            app.graph_state.pan = [0.0, 0.0];
            app.graph_state.zoom = 1.0;
            rebuild_graph(app);
        }
    });
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

    let graph_result = if app.graph_state.mode == GraphViewMode::Event {
        build_event_graph_for_gui(result)
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
        Ok(mut graph) => {
            let node_count = graph.nodes.len();
            let layout =
                LayoutState::new_with_min_edge_length(node_count, app.graph_state.min_edge_length);
            layout.initialise_positions(&mut graph);
            app.graph_state.graph = Some(graph);
            app.graph_state.layout = Some(layout);
            app.graph_state.layout_start_time = app.elapsed_time;
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

fn build_event_graph_for_gui(
    result: &crate::analysis::AnalysisResult,
) -> Result<GraphData, GraphError> {
    let parse_options = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 64 * 1024 * 1024,
        max_objects: 250_000,
        max_objstm_total_bytes: 256 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let graph = parse_pdf(&result.bytes, parse_options)
        .map_err(|err| GraphError::ParseFailed(err.to_string()))?;
    let classifications = graph.classify_objects();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&graph, &classifications);
    let event_graph = sis_pdf_core::event_graph::build_event_graph(
        &typed_graph,
        &result.report.findings,
        sis_pdf_core::event_graph::EventGraphOptions::default(),
    );
    graph_data::from_event_graph(&event_graph)
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
        if app.graph_state.mode != GraphViewMode::Event {
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
    use super::{build_chain_path_edges, find_directed_path_edges};
    use crate::graph_data::GraphEdge;

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
}

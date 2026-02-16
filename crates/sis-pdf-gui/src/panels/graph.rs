use crate::app::SisApp;
use crate::graph_data::{self, GraphData, GraphError, MAX_GRAPH_NODES};
use crate::graph_layout::LayoutState;

/// Persistent state for the graph viewer panel.
#[derive(Default)]
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
    /// Whether to filter to chain-only nodes.
    pub chain_filter: bool,
    /// BFS depth limit from selected node. 0 = no limit (show all).
    pub depth_limit: usize,
    /// Whether to show node labels.
    pub show_labels: bool,
    /// Error message if graph could not be built.
    pub error: Option<String>,
    /// Whether the graph has been built for the current result.
    pub built: bool,
    /// Timestamp when layout started (for telemetry).
    pub layout_start_time: f64,
}

/// Node type colour mapping.
fn node_colour(obj_type: &str) -> egui::Color32 {
    match obj_type.to_lowercase().as_str() {
        "page" => egui::Color32::from_rgb(70, 130, 230),   // blue
        "action" => egui::Color32::from_rgb(220, 60, 60),   // red
        "stream" => egui::Color32::from_rgb(60, 180, 80),   // green
        "font" => egui::Color32::from_rgb(160, 160, 160),   // grey
        "catalog" | "catalogue" => egui::Color32::from_rgb(160, 80, 200), // purple
        "image" => egui::Color32::from_rgb(230, 160, 40),   // orange
        _ => egui::Color32::from_rgb(140, 140, 140),        // default grey
    }
}

/// Show the graph viewer as a floating window.
pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_graph;
    egui::Window::new("Graph Viewer")
        .open(&mut open)
        .default_size([800.0, 600.0])
        .resizable(true)
        .show(ctx, |ui| {
            show_inner(ui, ctx, app);
        });
    app.show_graph = open;
}

fn show_inner(ui: &mut egui::Ui, ctx: &egui::Context, app: &mut SisApp) {
    // Build graph if not yet done
    if !app.graph_state.built {
        build_graph(app);
    }

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
    let node_data: Vec<(f64, f64, String, String, Vec<String>)> = graph
        .nodes
        .iter()
        .map(|n| {
            (
                n.position[0],
                n.position[1],
                n.obj_type.clone(),
                format!("{} {}", n.obj, n.gen),
                n.roles.clone(),
            )
        })
        .collect();

    let edge_data: Vec<(usize, usize, bool)> = graph
        .edges
        .iter()
        .map(|e| (e.from_idx, e.to_idx, e.suspicious))
        .collect();

    let selected_chain = app.selected_chain;
    let chain_node_set = build_chain_node_set(app);

    let pan = app.graph_state.pan;
    let zoom = if app.graph_state.zoom == 0.0 { 1.0 } else { app.graph_state.zoom };
    let selected = app.graph_state.selected_node;
    let show_labels = app.graph_state.show_labels;
    let is_layout_running = app.graph_state.layout.is_some();

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
    if scroll_delta != 0.0 && rect.contains(ui.input(|i| i.pointer.hover_pos().unwrap_or_default())) {
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
        let sx = rect.center().x as f64 + (gx - 400.0 + pan[0]) * zoom;
        let sy = rect.center().y as f64 + (gy - 300.0 + pan[1]) * zoom;
        egui::pos2(sx as f32, sy as f32)
    };

    // Inverse: screen coords -> graph coords
    let from_screen = |sx: f32, sy: f32| -> (f64, f64) {
        let gx = (sx as f64 - rect.center().x as f64) / zoom + 400.0 - pan[0];
        let gy = (sy as f64 - rect.center().y as f64) / zoom + 300.0 - pan[1];
        (gx, gy)
    };

    let dim_non_chain = selected_chain.is_some() && app.graph_state.chain_filter;

    // Draw edges
    for &(from_idx, to_idx, suspicious) in &edge_data {
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

        if dim_non_chain {
            let from_in_chain = chain_node_set.contains(&from_idx);
            let to_in_chain = chain_node_set.contains(&to_idx);
            if !from_in_chain || !to_in_chain {
                colour = egui::Color32::from_rgba_premultiplied(60, 60, 60, 40);
            }
        }

        let width = if suspicious { 2.0 } else { 1.0 };
        painter.line_segment([p1, p2], egui::Stroke::new(width, colour));
    }

    // Draw nodes
    let node_radius = (6.0 * zoom).clamp(3.0, 20.0) as f32;
    let mut hovered = None;

    let pointer_pos = ui.input(|i| i.pointer.hover_pos());

    for (i, (gx, gy, ref obj_type, ref label, ref _roles)) in node_data.iter().enumerate() {
        let p = to_screen(*gx, *gy);
        if !rect.contains(p) {
            continue;
        }

        let mut colour = node_colour(obj_type);

        if dim_non_chain && !chain_node_set.contains(&i) {
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
        let (_, _, ref obj_type, ref label, ref roles) = node_data[hi];
        egui::show_tooltip_at_pointer(ui.ctx(), ui.id().with("graph_tooltip"), |ui| {
            ui.strong(label);
            ui.label(format!("Type: {}", obj_type));
            if !roles.is_empty() {
                ui.label(format!("Roles: {}", roles.join(", ")));
            }
        });
    }

    // Handle click: select node
    if response.clicked() {
        if let Some(pointer) = pointer_pos {
            let mut closest = None;
            let mut closest_dist = f64::MAX;
            for (i, (gx, gy, _, _, _)) in node_data.iter().enumerate() {
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
                app.navigate_to_object(node.obj, node.gen);
                app.show_objects = true;
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
        // Type filter combo
        ui.label("Type:");
        let current_filter = if app.graph_state.type_filter.is_empty() {
            "All".to_string()
        } else {
            app.graph_state.type_filter.join(", ")
        };
        egui::ComboBox::from_id_salt("graph_type_filter")
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

        ui.separator();

        // Depth slider
        ui.label("Depth:");
        let mut depth = app.graph_state.depth_limit as i32;
        if ui.add(egui::Slider::new(&mut depth, 0..=10).text("hops")).changed() {
            app.graph_state.depth_limit = depth as usize;
            rebuild_graph(app);
        }

        ui.separator();

        // Chain-only toggle
        ui.toggle_value(&mut app.graph_state.chain_filter, "Chain only");

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

    let graph_result = if !app.graph_state.type_filter.is_empty() {
        let types: Vec<&str> = app.graph_state.type_filter.iter().map(|s| s.as_str()).collect();
        graph_data::from_object_data_filtered(&result.object_data, &types)
    } else if app.graph_state.depth_limit > 0 {
        // Use depth limit from selected node or catalog
        let centre = app.graph_state.selected_node
            .and_then(|i| app.graph_state.graph.as_ref().map(|g| (g.nodes[i].obj, g.nodes[i].gen)))
            .or_else(|| {
                result.object_data.objects.iter()
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
            let mut layout = LayoutState::new(node_count);
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
    }
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
            crate::telemetry::TelemetryEventKind::GraphLayoutCompleted {
                node_count,
                duration_ms,
            },
        );
        app.graph_state.layout = None;
    }
}

/// Build a set of node indices that belong to the currently selected chain.
fn build_chain_node_set(app: &SisApp) -> std::collections::HashSet<usize> {
    let mut set = std::collections::HashSet::new();
    let Some(chain_idx) = app.selected_chain else {
        return set;
    };
    let Some(ref result) = app.result else {
        return set;
    };
    let Some(ref graph) = app.graph_state.graph else {
        return set;
    };

    if chain_idx >= result.report.chains.len() {
        return set;
    }

    let chain = &result.report.chains[chain_idx];

    // Extract object refs from chain trigger/action/payload text
    for text in [&chain.trigger, &chain.action, &chain.payload].iter().filter_map(|t| t.as_ref()) {
        if let Some((obj, gen)) = crate::panels::chains::extract_obj_ref_from_text(text) {
            if let Some(&idx) = graph.node_index.get(&(obj, gen)) {
                set.insert(idx);
            }
        }
    }

    set
}

use crate::app::SisApp;
use crate::hex_format;
use crate::object_data::ObjectValue;
use egui_extras::{Column, TableBuilder};
use sis_pdf_core::model::Severity;
use sis_pdf_core::object_context::{
    get_object_context, ObjectChainRole, ObjectSecurityContext, TaintReasonEntry,
};

pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_objects;
    let mut ws = app.window_max.remove("Object Inspector").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Object Inspector", [700.0, 500.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Object Inspector", &mut open, &mut ws);
        show_inner(ui, app);
    });
    app.window_max.insert("Object Inspector".to_string(), ws);
    app.show_objects = open;
}

fn show_inner(ui: &mut egui::Ui, app: &mut SisApp) {
    // Collect all owned data we need before any mutable usage
    let (object_count, type_list, filtered, related_findings) = {
        let Some(ref result) = app.result else {
            return;
        };
        let od = &result.object_data;

        let mut types: Vec<String> = od.objects.iter().map(|o| o.obj_type.clone()).collect();
        types.sort();
        types.dedup();

        let filtered: Vec<usize> = od
            .objects
            .iter()
            .enumerate()
            .filter(|(_, o)| app.object_type_filter.as_ref().map_or(true, |f| o.obj_type == *f))
            .map(|(i, _)| i)
            .collect();

        let related = if let Some((obj_num, gen_num)) = app.selected_object {
            let obj_id_str = format!("{} {} R", obj_num, gen_num);
            result
                .report
                .findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.objects.iter().any(|o| *o == obj_id_str))
                .map(|(i, f)| (i, f.title.clone()))
                .collect()
        } else {
            Vec::new()
        };

        (od.objects.len(), types, filtered, related)
    };

    // Navigation bar: back/forward, search, stream hex toggle
    show_nav_bar(ui, app, object_count);
    ui.separator();

    // Type filter dropdown
    ui.horizontal(|ui| {
        ui.label("Filter by type:");
        egui::ComboBox::from_id_salt("obj_type_filter")
            .selected_text(app.object_type_filter.as_deref().unwrap_or("All"))
            .show_ui(ui, |ui| {
                if ui.selectable_label(app.object_type_filter.is_none(), "All").clicked() {
                    app.object_type_filter = None;
                }
                for t in &type_list {
                    let is_selected = app.object_type_filter.as_deref() == Some(t.as_str());
                    if ui.selectable_label(is_selected, t).clicked() {
                        app.object_type_filter = Some(t.clone());
                    }
                }
            });

        ui.separator();
        ui.label(format!("{} objects", object_count));
    });
    ui.separator();

    let available = ui.available_size();
    let list_width = (available.x * 0.35).max(150.0).min(250.0);

    ui.horizontal(|ui| {
        ui.set_min_height(available.y);

        // Left pane: object list
        ui.vertical(|ui| {
            ui.set_width(list_width);
            show_object_list(ui, app, &filtered);
        });

        ui.separator();

        // Right pane: selected object detail
        ui.vertical(|ui| {
            show_object_detail(ui, app, &related_findings);
        });
    });
}

fn show_nav_bar(ui: &mut egui::Ui, app: &mut SisApp, _object_count: usize) {
    ui.horizontal(|ui| {
        // Back button
        let can_back = app.object_nav_pos > 1;
        if ui.add_enabled(can_back, egui::Button::new("<")).clicked() {
            app.object_nav_back();
        }

        // Forward button
        let can_forward = app.object_nav_pos < app.object_nav_stack.len();
        if ui.add_enabled(can_forward, egui::Button::new(">")).clicked() {
            app.object_nav_forward();
        }

        ui.separator();

        // Search field
        ui.label("Search:");
        let response =
            ui.add(egui::TextEdit::singleline(&mut app.object_search).desired_width(80.0));
        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            // On Enter, try to navigate to exact match
            if let Some(obj_num) = app.object_search.trim().parse::<u32>().ok() {
                app.navigate_to_object(obj_num, 0);
            }
        }

        ui.separator();

        // Stream hex toggle
        ui.toggle_value(&mut app.show_stream_hex, "Hex");
    });
}

fn show_object_list(ui: &mut egui::Ui, app: &mut SisApp, filtered: &[usize]) {
    let Some(ref result) = app.result else {
        return;
    };
    let object_data = &result.object_data;
    let severity_index = result.object_severity_index.clone();

    // Apply search filter on top of type filter
    let search = app.object_search.trim().to_lowercase();
    let rows: Vec<(u32, u16, String)> = filtered
        .iter()
        .filter_map(|&idx| {
            let obj = &object_data.objects[idx];
            if !search.is_empty() {
                let id_str = format!("{} {}", obj.obj, obj.gen);
                if !id_str.contains(&search) && !obj.obj.to_string().contains(&search) {
                    return None;
                }
            }
            Some((obj.obj, obj.gen, obj.obj_type.clone()))
        })
        .collect();

    let selected = app.selected_object;
    let available = ui.available_size();

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(60.0).at_least(40.0))
        .column(Column::remainder())
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y - 10.0)
        .header(18.0, |mut header| {
            header.col(|ui| {
                ui.label("Obj ID");
            });
            header.col(|ui| {
                ui.label("Type");
            });
        })
        .body(|body| {
            body.rows(18.0, rows.len(), |mut row| {
                let (obj_num, gen_num, ref obj_type) = rows[row.index()];
                let is_selected = selected == Some((obj_num, gen_num));

                row.col(|ui| {
                    ui.horizontal(|ui| {
                        if let Some((severity, finding_count)) =
                            severity_index.get(&(obj_num, gen_num))
                        {
                            let colour = severity_dot_colour(*severity);
                            ui.colored_label(colour, "●");
                            ui.small(format!("({finding_count})"));
                        }
                        let label = format!("{} {}", obj_num, gen_num);
                        if ui.selectable_label(is_selected, label).clicked() {
                            app.navigate_to_object(obj_num, gen_num);
                        }
                    });
                });
                row.col(|ui| {
                    ui.label(obj_type);
                });
            });
        });
}

fn severity_dot_colour(severity: Severity) -> egui::Color32 {
    match severity {
        Severity::Critical | Severity::High => egui::Color32::from_rgb(200, 40, 40),
        Severity::Medium => egui::Color32::from_rgb(210, 125, 40),
        Severity::Low | Severity::Info => egui::Color32::from_rgb(140, 140, 140),
    }
}

fn show_object_detail(ui: &mut egui::Ui, app: &mut SisApp, related_findings: &[(usize, String)]) {
    let Some((obj_num, gen_num)) = app.selected_object else {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label("Select an object to view details");
        });
        return;
    };

    // Extract all display data from the object before entering mutable closures
    let detail = {
        let Some(ref result) = app.result else {
            return;
        };
        let Some(&idx) = result.object_data.index.get(&(obj_num, gen_num)) else {
            ui.label(format!("Object {} {} not found", obj_num, gen_num));
            return;
        };
        let obj = &result.object_data.objects[idx];
        let stream_source_raw = stream_source_bytes(&result.bytes, obj.stream_data_span);
        ObjectDetail {
            obj: obj.obj,
            gen: obj.gen,
            obj_type: obj.obj_type.clone(),
            roles: obj.roles.clone(),
            has_stream: obj.has_stream,
            stream_filters: obj.stream_filters.clone(),
            stream_length: obj.stream_length,
            stream_text: obj.stream_text.clone(),
            stream_raw: obj.stream_raw.clone(),
            stream_source_raw,
            stream_content_type: obj.stream_content_type.clone(),
            image_width: obj.image_width,
            image_height: obj.image_height,
            image_bits: obj.image_bits,
            image_color_space: obj.image_color_space.clone(),
            image_preview: obj.image_preview.clone(),
            dict_entries: obj.dict_entries.clone(),
            dict_entries_tree: obj.dict_entries_tree.clone(),
            references_from: obj.references_from.clone(),
            references_to: obj.references_to.clone(),
            security_context: get_object_context(&result.object_context_index, obj.obj, obj.gen),
        }
    };

    let show_hex = app.show_stream_hex;

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading(format!("Object {} {}", detail.obj, detail.gen));
            if ui.small_button("Copy as JSON").clicked() {
                let dict: std::collections::BTreeMap<&str, &str> =
                    detail.dict_entries.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                let json = serde_json::json!({
                    "obj": detail.obj,
                    "gen": detail.gen,
                    "type": &detail.obj_type,
                    "dict": dict,
                });
                if let Ok(text) = serde_json::to_string_pretty(&json) {
                    ui.ctx().copy_text(text);
                }
            }
        });
        ui.separator();

        show_object_meta(ui, app, &detail);
        show_security_context(ui, app, &detail.security_context);
        show_dict_entries(ui, app, &detail.dict_entries, &detail.dict_entries_tree);
        show_stream_content(ui, &detail, show_hex);
        show_references(ui, app, &detail.references_from, &detail.references_to);
        show_related_findings(ui, app, related_findings);
    });
}

struct ObjectDetail {
    obj: u32,
    gen: u16,
    obj_type: String,
    roles: Vec<String>,
    has_stream: bool,
    stream_filters: Vec<String>,
    stream_length: Option<usize>,
    stream_text: Option<String>,
    stream_raw: Option<Vec<u8>>,
    stream_source_raw: Option<Vec<u8>>,
    stream_content_type: Option<String>,
    image_width: Option<u32>,
    image_height: Option<u32>,
    image_bits: Option<u32>,
    image_color_space: Option<String>,
    image_preview: Option<(u32, u32, Vec<u8>)>,
    dict_entries: Vec<(String, String)>,
    dict_entries_tree: Vec<(String, ObjectValue)>,
    references_from: Vec<(u32, u16)>,
    references_to: Vec<(u32, u16)>,
    security_context: ObjectSecurityContext,
}

fn show_object_meta(ui: &mut egui::Ui, app: &mut SisApp, detail: &ObjectDetail) {
    egui::Grid::new("obj_detail_meta").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label("Type:");
        ui.label(&detail.obj_type);
        ui.end_row();

        if !detail.roles.is_empty() {
            ui.label("Roles:");
            ui.label(detail.roles.join(", "));
            ui.end_row();
        }

        if detail.has_stream {
            ui.label("Stream:");
            let mut info = String::new();
            if !detail.stream_filters.is_empty() {
                info.push_str(&detail.stream_filters.join(" > "));
            }
            if let Some(len) = detail.stream_length {
                if !info.is_empty() {
                    info.push_str(", ");
                }
                info.push_str(&format!("{} bytes", len));
            }
            ui.end_row();
            ui.label("");
            ui.horizontal(|ui| {
                ui.label(if info.is_empty() { "yes".to_string() } else { info });
                if detail.stream_source_raw.is_some() {
                    if ui.small_button("View raw").clicked() {
                        app.open_hex_for_stream(detail.obj, detail.gen);
                    }
                }
                if let Some(raw) = &detail.stream_source_raw {
                    if ui.small_button("Download raw").clicked() {
                        let file_name = format!("obj-{}-{}-raw.bin", detail.obj, detail.gen);
                        app.download_bytes(&file_name, raw);
                    }
                }
                if ui.small_button("Download decoded").clicked() {
                    if let Some(decoded) = decoded_stream_bytes(app, detail) {
                        let file_name = format!("obj-{}-{}-decoded.bin", detail.obj, detail.gen);
                        app.download_bytes(&file_name, &decoded);
                    } else {
                        app.error = Some(crate::analysis::AnalysisError::ParseFailed(
                            "Unable to decode stream for selected object".to_string(),
                        ));
                    }
                }
            });
            ui.end_row();
        }

        // Show in graph button
        ui.label("");
        if ui.small_button("Show in graph").clicked() {
            crate::panels::graph::focus_object(app, detail.obj, detail.gen);
        }
        ui.end_row();
    });
}

fn show_dict_entries(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    entries: &[(String, String)],
    entries_tree: &[(String, ObjectValue)],
) {
    if entries.is_empty() {
        return;
    }

    ui.separator();
    egui::CollapsingHeader::new(format!("Dictionary ({} entries)", entries.len()))
        .default_open(true)
        .show(ui, |ui| {
            if entries_tree.is_empty() {
                egui::Grid::new("obj_dict_grid")
                    .num_columns(2)
                    .spacing([8.0, 2.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for (key, val) in entries {
                            ui.monospace(key);
                            if let Some(ref_id) = parse_obj_ref(val) {
                                if ui.link(val).clicked() {
                                    app.navigate_to_object(ref_id.0, ref_id.1);
                                }
                            } else {
                                ui.label(val);
                            }
                            ui.end_row();
                        }
                    });
                return;
            }
            render_dict_entries_tree(ui, app, entries_tree, "obj_dict_root");
        });
}

fn render_dict_entries_tree(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    entries: &[(String, ObjectValue)],
    path: &str,
) {
    for (idx, (key, value)) in entries.iter().enumerate() {
        ui.horizontal_wrapped(|ui| {
            ui.monospace(key);
            ui.label("=");
            let child_path = format!("{path}.dict.{idx}");
            render_object_value_tree(ui, app, value, &child_path);
        });
    }
}

fn render_object_value_tree(ui: &mut egui::Ui, app: &mut SisApp, value: &ObjectValue, path: &str) {
    match value {
        ObjectValue::Null => {
            ui.label("null");
        }
        ObjectValue::Bool(value) => {
            ui.label(value.to_string());
        }
        ObjectValue::Int(value) => {
            ui.label(value.to_string());
        }
        ObjectValue::Real(value) => {
            ui.label(value.to_string());
        }
        ObjectValue::Name(value) | ObjectValue::Str(value) | ObjectValue::Summary(value) => {
            if let Some(ref_id) = parse_obj_ref(value) {
                if ui.link(value).clicked() {
                    app.navigate_to_object(ref_id.0, ref_id.1);
                }
            } else {
                ui.label(value);
            }
        }
        ObjectValue::Ref { obj, gen } => {
            let label = format!("{obj} {gen} R");
            if ui.link(&label).clicked() {
                app.navigate_to_object(*obj, *gen);
            }
        }
        ObjectValue::Array(items) => {
            egui::CollapsingHeader::new(format!("[{} items]", items.len())).id_salt(path).show(
                ui,
                |ui| {
                    for (idx, item) in items.iter().enumerate() {
                        ui.horizontal_wrapped(|ui| {
                            ui.monospace(format!("[{idx}]"));
                            ui.label("=");
                            let child_path = format!("{path}.arr.{idx}");
                            render_object_value_tree(ui, app, item, &child_path);
                        });
                    }
                },
            );
        }
        ObjectValue::Dict(entries) => {
            egui::CollapsingHeader::new(format!("<< {} entries >>", entries.len()))
                .id_salt(path)
                .show(ui, |ui| {
                    ui.indent(path, |ui| {
                        render_dict_entries_tree(ui, app, entries, path);
                    });
                });
        }
        ObjectValue::Stream { dict } => {
            egui::CollapsingHeader::new(format!("stream << {} entries >>", dict.len()))
                .id_salt(path)
                .show(ui, |ui| {
                    ui.indent(path, |ui| {
                        render_dict_entries_tree(ui, app, dict, path);
                    });
                });
        }
    }
}

fn show_security_context(ui: &mut egui::Ui, app: &mut SisApp, context: &ObjectSecurityContext) {
    ui.separator();
    egui::CollapsingHeader::new("Security context").default_open(true).show(ui, |ui| {
        let taint_label = if context.taint_source {
            "source"
        } else if context.tainted {
            "propagated"
        } else {
            "not tainted"
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Taint: {taint_label}"));
            ui.separator();
            ui.label(format!("Chains: {}", context.chains.len()));
            ui.separator();
            let severity = context
                .max_severity
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "None".to_string());
            ui.label(format!("Severity: {severity}"));
            ui.separator();
            let confidence = context
                .max_confidence
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "None".to_string());
            ui.label(format!("Confidence: {confidence}"));
        });

        if context.tainted {
            if !context.taint_reasons.is_empty() {
                ui.separator();
                ui.label("Taint reasons:");
                for reason in &context.taint_reasons {
                    show_taint_reason(ui, app, reason);
                }
            }
            if !context.taint_incoming.is_empty() {
                ui.separator();
                ui.label("Incoming taint:");
                ui.horizontal_wrapped(|ui| {
                    for (obj, generation) in &context.taint_incoming {
                        let label = format!("{obj} {generation} R");
                        if ui.link(label).clicked() {
                            app.navigate_to_object(*obj, *generation);
                        }
                    }
                });
            }
            if !context.taint_outgoing.is_empty() {
                ui.separator();
                ui.label("Outgoing taint:");
                ui.horizontal_wrapped(|ui| {
                    for (obj, generation) in &context.taint_outgoing {
                        let label = format!("{obj} {generation} R");
                        if ui.link(label).clicked() {
                            app.navigate_to_object(*obj, *generation);
                        }
                    }
                });
            }
        } else {
            ui.small("Not tainted.");
        }

        if context.chains.is_empty() {
            ui.separator();
            ui.small("No chain membership.");
            return;
        }

        ui.separator();
        ui.label("Chain membership:");
        for membership in &context.chains {
            ui.horizontal_wrapped(|ui| {
                let role = format_chain_role(membership.role);
                let label = format!(
                    "Chain #{} [{}] score {:.2}",
                    membership.chain_index + 1,
                    role,
                    membership.score
                );
                if ui.link(label).clicked() {
                    app.selected_chain = Some(membership.chain_index);
                    app.show_chains = true;
                }
                ui.small(format!("id={}", membership.chain_id));
            });
            ui.small(&membership.path);
        }
    });
}

fn show_taint_reason(ui: &mut egui::Ui, app: &mut SisApp, reason: &TaintReasonEntry) {
    ui.horizontal_wrapped(|ui| {
        ui.label(&reason.reason);
        if let Some(finding_id) = &reason.finding_id {
            let label = format!("({finding_id})");
            if ui.link(label).clicked() {
                if let Some(result) = &app.result {
                    if let Some(idx) =
                        result.report.findings.iter().position(|finding| finding.id == *finding_id)
                    {
                        app.selected_finding = Some(idx);
                    }
                }
            }
        }
    });
}

fn format_chain_role(role: ObjectChainRole) -> &'static str {
    match role {
        ObjectChainRole::Trigger => "Trigger",
        ObjectChainRole::Action => "Action",
        ObjectChainRole::Payload => "Payload",
        ObjectChainRole::Participant => "Participant",
        ObjectChainRole::PathNode => "PathNode",
    }
}

fn show_stream_content(ui: &mut egui::Ui, detail: &ObjectDetail, show_hex: bool) {
    if !detail.has_stream {
        return;
    }

    // Stream metadata section
    let has_metadata = detail.stream_content_type.is_some()
        || detail.image_width.is_some()
        || detail.stream_raw.is_some();
    if has_metadata {
        ui.separator();
        ui.collapsing("Stream metadata", |ui| {
            egui::Grid::new("stream_meta_grid").num_columns(2).spacing([8.0, 2.0]).show(ui, |ui| {
                if let Some(ref ct) = detail.stream_content_type {
                    ui.label("Content type:");
                    ui.label(ct);
                    ui.end_row();
                }
                if let (Some(w), Some(h)) = (detail.image_width, detail.image_height) {
                    ui.label("Dimensions:");
                    ui.label(format!("{} x {}", w, h));
                    ui.end_row();
                }
                if let Some(ref cs) = detail.image_color_space {
                    ui.label("Colour space:");
                    ui.label(cs);
                    ui.end_row();
                }
                if let Some(bits) = detail.image_bits {
                    ui.label("Bits/component:");
                    ui.label(format!("{}", bits));
                    ui.end_row();
                }
                if let Some(ref raw) = detail.stream_raw {
                    ui.label("Decoded size:");
                    ui.label(format_byte_size(raw.len()));
                    ui.end_row();
                    if let Some(raw_len) = detail.stream_length {
                        if raw_len != raw.len() {
                            ui.label("Raw size:");
                            ui.label(format_byte_size(raw_len));
                            ui.end_row();
                        }
                    }
                }
            });
        });
    }

    // JPEG image preview
    if let Some((tw, th, ref pixels)) = detail.image_preview {
        ui.separator();
        ui.collapsing("Image preview", |ui| {
            let tex_id = format!("img_preview_{}_{}", detail.obj, detail.gen);
            let texture = ui.ctx().load_texture(
                &tex_id,
                egui::ColorImage::from_rgba_unmultiplied([tw as usize, th as usize], pixels),
                egui::TextureOptions::LINEAR,
            );
            ui.image(&texture);
        });
    }

    if show_hex {
        // Show hex view of stream raw bytes
        if let Some(ref raw) = detail.stream_raw {
            ui.separator();
            ui.collapsing(format!("Stream hex ({} bytes)", raw.len()), |ui| {
                let lines = hex_format::format_hex_block(raw, 0);
                egui::ScrollArea::vertical().max_height(300.0).id_salt("stream_hex_scroll").show(
                    ui,
                    |ui| {
                        for line in &lines {
                            ui.monospace(line);
                        }
                    },
                );
            });
        } else {
            ui.separator();
            ui.label("Stream could not be decoded");
        }
    } else if let Some(ref text) = detail.stream_text {
        ui.separator();
        ui.collapsing("Stream content", |ui| {
            egui::ScrollArea::vertical().max_height(300.0).id_salt("stream_text_scroll").show(
                ui,
                |ui| {
                    ui.monospace(text);
                },
            );
        });
    } else if detail.stream_raw.is_some() {
        ui.separator();
        ui.label("Stream contains binary data (toggle Hex to view)");
    }
}

fn format_byte_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} bytes", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn show_references(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    references_from: &[(u32, u16)],
    references_to: &[(u32, u16)],
) {
    if !references_from.is_empty() {
        ui.separator();
        egui::CollapsingHeader::new(format!("References from ({} objects)", references_from.len()))
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (r_obj, r_gen) in references_from {
                        let label = format!("{} {} R", r_obj, r_gen);
                        if ui.link(&label).clicked() {
                            app.navigate_to_object(*r_obj, *r_gen);
                        }
                    }
                });
            });
    }

    if !references_to.is_empty() {
        ui.separator();
        egui::CollapsingHeader::new(format!("Referenced by ({} objects)", references_to.len()))
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (r_obj, r_gen) in references_to {
                        let label = format!("{} {} R", r_obj, r_gen);
                        if ui.link(&label).clicked() {
                            app.navigate_to_object(*r_obj, *r_gen);
                        }
                    }
                });
            });
    }
}

fn show_related_findings(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    related_findings: &[(usize, String)],
) {
    if related_findings.is_empty() {
        return;
    }

    ui.separator();
    ui.collapsing(format!("Related findings ({})", related_findings.len()), |ui| {
        for (finding_idx, title) in related_findings {
            if ui.link(title).clicked() {
                app.selected_finding = Some(*finding_idx);
            }
        }
    });
}

fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    // Object Inspector dict values are always "N M R" format
    let s = s.trim();
    if !s.ends_with('R') {
        return None;
    }
    crate::util::parse_obj_ref(s)
}

fn stream_source_bytes(bytes: &[u8], span: Option<(usize, usize)>) -> Option<Vec<u8>> {
    let (start, end) = span?;
    if start < end && end <= bytes.len() {
        Some(bytes[start..end].to_vec())
    } else {
        None
    }
}

fn decoded_stream_bytes(app: &SisApp, detail: &ObjectDetail) -> Option<Vec<u8>> {
    if let Some(decoded) = &detail.stream_raw {
        return Some(decoded.clone());
    }
    let result = app.result.as_ref()?;
    crate::object_data::decode_stream_for_object(&result.bytes, detail.obj, detail.gen, 64 * 1024)
}

#[cfg(test)]
mod tests {
    use super::stream_source_bytes;

    #[test]
    fn stream_source_bytes_returns_slice_for_valid_span() {
        let bytes = b"abcdef";
        let raw = stream_source_bytes(bytes, Some((1, 4))).expect("valid span");
        assert_eq!(raw, b"bcd");
    }

    #[test]
    fn stream_source_bytes_rejects_invalid_or_empty_spans() {
        let bytes = b"abcdef";
        assert!(stream_source_bytes(bytes, None).is_none());
        assert!(stream_source_bytes(bytes, Some((3, 3))).is_none());
        assert!(stream_source_bytes(bytes, Some((5, 3))).is_none());
        assert!(stream_source_bytes(bytes, Some((0, 10))).is_none());
    }
}

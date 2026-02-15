use crate::app::SisApp;
use egui_extras::{Column, TableBuilder};

pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_objects;
    egui::Window::new("Object Inspector")
        .open(&mut open)
        .default_size([700.0, 500.0])
        .resizable(true)
        .show(ctx, |ui| {
            show_inner(ui, app);
        });
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

fn show_object_list(ui: &mut egui::Ui, app: &mut SisApp, filtered: &[usize]) {
    let Some(ref result) = app.result else {
        return;
    };
    let object_data = &result.object_data;

    // Pre-extract display data for all filtered objects
    let rows: Vec<(u32, u16, String)> = filtered
        .iter()
        .map(|&idx| {
            let obj = &object_data.objects[idx];
            (obj.obj, obj.gen, obj.obj_type.clone())
        })
        .collect();

    // Drop the borrow on app.result before entering the mutable table body
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
                    let label = format!("{} {}", obj_num, gen_num);
                    if ui.selectable_label(is_selected, label).clicked() {
                        app.selected_object = Some((obj_num, gen_num));
                    }
                });
                row.col(|ui| {
                    ui.label(obj_type);
                });
            });
        });
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
        ObjectDetail {
            obj: obj.obj,
            gen: obj.gen,
            obj_type: obj.obj_type.clone(),
            roles: obj.roles.clone(),
            has_stream: obj.has_stream,
            stream_filters: obj.stream_filters.clone(),
            stream_length: obj.stream_length,
            stream_text: obj.stream_text.clone(),
            dict_entries: obj.dict_entries.clone(),
            references_from: obj.references_from.clone(),
            references_to: obj.references_to.clone(),
        }
    };

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading(format!("Object {} {}", detail.obj, detail.gen));
        ui.separator();

        show_object_meta(ui, &detail);
        show_dict_entries(ui, app, &detail.dict_entries);
        show_stream_content(ui, &detail);
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
    dict_entries: Vec<(String, String)>,
    references_from: Vec<(u32, u16)>,
    references_to: Vec<(u32, u16)>,
}

fn show_object_meta(ui: &mut egui::Ui, detail: &ObjectDetail) {
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
            ui.label(if info.is_empty() { "yes".to_string() } else { info });
            ui.end_row();
        }
    });
}

fn show_dict_entries(ui: &mut egui::Ui, app: &mut SisApp, entries: &[(String, String)]) {
    if entries.is_empty() {
        return;
    }

    ui.separator();
    ui.collapsing(format!("Dictionary ({} entries)", entries.len()), |ui| {
        egui::Grid::new("obj_dict_grid").num_columns(2).spacing([8.0, 2.0]).striped(true).show(
            ui,
            |ui| {
                for (key, val) in entries {
                    ui.monospace(key);
                    if let Some(ref_id) = parse_obj_ref(val) {
                        if ui.link(val).clicked() {
                            app.selected_object = Some(ref_id);
                        }
                    } else {
                        ui.label(val);
                    }
                    ui.end_row();
                }
            },
        );
    });
}

fn show_stream_content(ui: &mut egui::Ui, detail: &ObjectDetail) {
    if let Some(ref text) = detail.stream_text {
        ui.separator();
        ui.collapsing("Stream content", |ui| {
            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                ui.monospace(text);
            });
        });
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
        ui.collapsing(format!("References from ({} objects)", references_from.len()), |ui| {
            ui.horizontal_wrapped(|ui| {
                for (r_obj, r_gen) in references_from {
                    let label = format!("{} {} R", r_obj, r_gen);
                    if ui.link(&label).clicked() {
                        app.selected_object = Some((*r_obj, *r_gen));
                    }
                }
            });
        });
    }

    if !references_to.is_empty() {
        ui.separator();
        ui.collapsing(format!("Referenced by ({} objects)", references_to.len()), |ui| {
            ui.horizontal_wrapped(|ui| {
                for (r_obj, r_gen) in references_to {
                    let label = format!("{} {} R", r_obj, r_gen);
                    if ui.link(&label).clicked() {
                        app.selected_object = Some((*r_obj, *r_gen));
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
                app.show_chains = false;
            }
        }
    });
}

/// Parse an object reference string like "5 0 R" into (obj, gen).
fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    let s = s.trim();
    if !s.ends_with('R') {
        return None;
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 3 && parts[2] == "R" {
        let obj = parts[0].parse::<u32>().ok()?;
        let gen = parts[1].parse::<u16>().ok()?;
        Some((obj, gen))
    } else {
        None
    }
}

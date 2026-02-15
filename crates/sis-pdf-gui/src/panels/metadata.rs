use crate::app::SisApp;
use crate::object_data::ObjectData;

pub fn show(ui: &mut egui::Ui, app: &SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("Document Metadata");
        ui.separator();

        show_document_info(ui, &result.object_data);
        show_structure(ui, result);
        show_xref_summary(ui, &result.object_data);
        show_deviations(ui, &result.object_data);
    });
}

fn show_document_info(ui: &mut egui::Ui, object_data: &ObjectData) {
    // Find the Catalog object and its /Info reference
    let info_obj_id = find_info_dict_id(object_data);

    ui.collapsing("Document Info", |ui| {
        if let Some(id) = info_obj_id {
            if let Some(&idx) = object_data.index.get(&id) {
                let obj = &object_data.objects[idx];
                let info_keys = [
                    ("/Title", "Title"),
                    ("/Author", "Author"),
                    ("/Subject", "Subject"),
                    ("/Creator", "Creator"),
                    ("/Producer", "Producer"),
                    ("/CreationDate", "Created"),
                    ("/ModDate", "Modified"),
                    ("/Keywords", "Keywords"),
                ];
                egui::Grid::new("doc_info_grid").num_columns(2).spacing([8.0, 4.0]).show(
                    ui,
                    |ui| {
                        for (key, label) in info_keys {
                            if let Some(val) = find_dict_value(&obj.dict_entries, key) {
                                ui.label(format!("{}:", label));
                                ui.label(val);
                                ui.end_row();
                            }
                        }
                    },
                );
                if obj.dict_entries.iter().all(|(k, _)| !info_keys.iter().any(|(ik, _)| k == ik)) {
                    ui.label("No standard info fields found");
                }
            } else {
                ui.label("Info dictionary object not found");
            }
        } else {
            ui.label("No document info dictionary");
        }
    });
}

fn show_structure(ui: &mut egui::Ui, result: &crate::analysis::AnalysisResult) {
    ui.collapsing("Structure", |ui| {
        egui::Grid::new("structure_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
            ui.label("Objects:");
            ui.label(format!("{}", result.object_data.objects.len()));
            ui.end_row();

            if let Some(ref structural) = result.report.structural_summary {
                ui.label("Startxref count:");
                ui.label(format!("{}", structural.startxref_count));
                ui.end_row();

                ui.label("Trailer count:");
                ui.label(format!("{}", structural.trailer_count));
                ui.end_row();

                ui.label("ObjStm count:");
                ui.label(format!("{}", structural.objstm_count));
                ui.end_row();

                if structural.polyglot_risk {
                    ui.label("Polyglot risk:");
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 140, 0),
                        structural.polyglot_signatures.join(", "),
                    );
                    ui.end_row();
                }
            }
        });
    });
}

fn show_xref_summary(ui: &mut egui::Ui, object_data: &ObjectData) {
    if object_data.xref_sections.is_empty() {
        return;
    }

    ui.collapsing(format!("XRef Sections ({})", object_data.xref_sections.len()), |ui| {
        for (i, sec) in object_data.xref_sections.iter().enumerate() {
            ui.group(|ui| {
                ui.label(format!("Section {}: {} at offset {}", i + 1, sec.kind, sec.offset));
                if let Some(size) = sec.trailer_size {
                    ui.label(format!("  Trailer size: {}", size));
                }
                if let Some(ref root) = sec.trailer_root {
                    ui.label(format!("  Root: {}", root));
                }
                if let Some(prev) = sec.prev {
                    ui.label(format!("  Prev: {}", prev));
                }
            });
        }
    });
}

fn show_deviations(ui: &mut egui::Ui, object_data: &ObjectData) {
    if object_data.deviations.is_empty() {
        return;
    }

    ui.collapsing(format!("Deviations ({})", object_data.deviations.len()), |ui| {
        for dev in &object_data.deviations {
            ui.group(|ui| {
                ui.label(format!("{} at offset {}", dev.kind, dev.offset));
                if let Some(ref note) = dev.note {
                    ui.label(note);
                }
            });
        }
    });
}

/// Find the Info dict object ID by looking for a Catalog with /Info reference.
fn find_info_dict_id(object_data: &ObjectData) -> Option<(u32, u16)> {
    for obj in &object_data.objects {
        if obj.obj_type == "catalog" {
            if let Some(val) = find_dict_value(&obj.dict_entries, "/Info") {
                return parse_obj_ref(&val);
            }
        }
    }
    None
}

/// Look up a dict entry value by key.
fn find_dict_value(entries: &[(String, String)], key: &str) -> Option<String> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// Parse an object reference string like "5 0 R" into (obj, gen).
fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        let obj = parts[0].parse::<u32>().ok()?;
        let gen = parts[1].parse::<u16>().ok()?;
        Some((obj, gen))
    } else {
        None
    }
}

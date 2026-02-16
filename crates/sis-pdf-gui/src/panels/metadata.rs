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
        show_encryption(ui, &result.object_data);
        show_temporal_signals(ui, result);
        show_revision_timeline(ui, result);
        show_xref_summary(ui, &result.object_data);
        show_deviations(ui, &result.object_data);
    });
}

fn show_document_info(ui: &mut egui::Ui, object_data: &ObjectData) {
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

            if result.page_count > 0 {
                ui.label("Pages:");
                ui.label(format!("{}", result.page_count));
                ui.end_row();
            }

            if let Some(ref ver) = result.pdf_version {
                ui.label("PDF version:");
                ui.label(ver);
                ui.end_row();
            }

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

fn show_encryption(ui: &mut egui::Ui, object_data: &ObjectData) {
    // Look for /Encrypt in catalog or trailer entries
    let encrypt_info = find_encrypt_info(object_data);
    if encrypt_info.is_empty() {
        return;
    }

    ui.collapsing("Encryption", |ui| {
        egui::Grid::new("encrypt_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
            for (key, val) in &encrypt_info {
                ui.label(format!("{}:", key));
                ui.label(val);
                ui.end_row();
            }
        });
    });
}

fn show_temporal_signals(ui: &mut egui::Ui, result: &crate::analysis::AnalysisResult) {
    let Some(ref signals) = result.report.temporal_signals else {
        return;
    };

    ui.collapsing("Temporal Signals", |ui| {
        egui::Grid::new("temporal_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
            ui.label("Revisions:");
            ui.label(format!("{}", signals.revisions));
            ui.end_row();

            ui.label("New high-severity:");
            ui.label(format!("{}", signals.new_high_severity));
            ui.end_row();

            if !signals.new_attack_surfaces.is_empty() {
                ui.label("New attack surfaces:");
                ui.label(signals.new_attack_surfaces.join(", "));
                ui.end_row();
            }

            if !signals.new_findings.is_empty() {
                ui.label("New findings:");
                ui.label(signals.new_findings.join(", "));
                ui.end_row();
            }

            if !signals.removed_findings.is_empty() {
                ui.label("Removed findings:");
                ui.label(signals.removed_findings.join(", "));
                ui.end_row();
            }

            if !signals.structural_deltas.is_empty() {
                ui.label("Structural deltas:");
                ui.label(signals.structural_deltas.join(", "));
                ui.end_row();
            }
        });
    });
}

fn show_revision_timeline(ui: &mut egui::Ui, result: &crate::analysis::AnalysisResult) {
    let Some(ref snapshots) = result.report.temporal_snapshots else {
        return;
    };
    if snapshots.is_empty() {
        return;
    }

    ui.collapsing(format!("Revision Timeline ({} versions)", snapshots.len()), |ui| {
        egui::Grid::new("timeline_grid")
            .num_columns(4)
            .spacing([8.0, 4.0])
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Version");
                ui.strong("Score");
                ui.strong("High Sev");
                ui.strong("Findings");
                ui.end_row();

                for snap in snapshots {
                    ui.label(&snap.version_label);
                    ui.label(format!("{:.2}", snap.score));
                    ui.label(format!("{}", snap.high_severity_count));
                    ui.label(format!("{}", snap.finding_count));
                    ui.end_row();
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

/// Find encryption info from the catalog or trailer objects.
fn find_encrypt_info(object_data: &ObjectData) -> Vec<(String, String)> {
    // Look for /Encrypt reference in catalog, then read the encrypt dict
    for obj in &object_data.objects {
        if obj.obj_type == "catalog" {
            if let Some(val) = find_dict_value(&obj.dict_entries, "/Encrypt") {
                if let Some(encrypt_id) = parse_obj_ref(&val) {
                    if let Some(&idx) = object_data.index.get(&encrypt_id) {
                        let encrypt_obj = &object_data.objects[idx];
                        let mut info = Vec::new();
                        for (k, v) in &encrypt_obj.dict_entries {
                            let label = k.trim_start_matches('/');
                            info.push((label.to_string(), v.clone()));
                        }
                        return info;
                    }
                }
                // If we found an /Encrypt reference but can't resolve it
                return vec![("Reference".to_string(), val)];
            }
        }
    }
    Vec::new()
}

/// Look up a dict entry value by key.
fn find_dict_value(entries: &[(String, String)], key: &str) -> Option<String> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    crate::util::parse_obj_ref(s)
}

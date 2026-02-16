use crate::app::SisApp;

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };
    let Some(idx) = app.selected_finding else {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label("Select a finding to view details");
        });
        return;
    };

    let findings = &result.report.findings;
    if idx >= findings.len() {
        return;
    }
    let f = &findings[idx];

    // Pre-extract object references for clickable links
    let object_refs: Vec<(String, Option<(u32, u16)>)> = f
        .objects
        .iter()
        .map(|s| {
            let parsed = parse_obj_ref(s);
            (s.clone(), parsed)
        })
        .collect();

    // Pre-extract all data we need from the finding to avoid borrow conflicts
    let title = f.title.clone();
    let id = f.id.clone();
    let kind = f.kind.clone();
    let severity = format!("{:?}", f.severity);
    let confidence = format!("{:?}", f.confidence);
    let impact = f.impact.as_ref().map(|i| format!("{:?}", i));
    let surface = format!("{:?}", f.surface);
    let action_type = f.action_type.clone();
    let action_target = f.action_target.clone();
    let description = f.description.clone();
    let remediation = f.remediation.clone();
    let evidence: Vec<_> = f
        .evidence
        .iter()
        .map(|ev| EvidenceDisplay {
            info: format!("offset: {}, length: {}, source: {:?}", ev.offset, ev.length, ev.source),
            note: ev.note.clone(),
            offset: ev.offset,
            length: ev.length,
            is_file_source: matches!(ev.source, sis_pdf_core::model::EvidenceSource::File),
        })
        .collect();
    let reader_impacts: Vec<String> = f
        .reader_impacts
        .iter()
        .map(|ri| {
            format!(
                "  {:?} - {:?} ({:?}): {}",
                ri.profile,
                ri.severity,
                ri.impact,
                ri.note.as_deref().unwrap_or("")
            )
        })
        .collect();
    let meta: Vec<(String, String)> = f.meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading(&title);
        ui.separator();

        egui::Grid::new("finding_meta").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
            ui.label("ID:");
            ui.label(&id);
            ui.end_row();

            ui.label("Kind:");
            ui.label(&kind);
            ui.end_row();

            ui.label("Severity:");
            ui.label(&severity);
            ui.end_row();

            ui.label("Confidence:");
            ui.label(&confidence);
            ui.end_row();

            if let Some(ref imp) = impact {
                ui.label("Impact:");
                ui.label(imp);
                ui.end_row();
            }

            ui.label("Surface:");
            ui.label(&surface);
            ui.end_row();

            if let Some(ref at) = action_type {
                ui.label("Action type:");
                ui.label(at);
                ui.end_row();
            }

            if let Some(ref at) = action_target {
                ui.label("Action target:");
                ui.label(at);
                ui.end_row();
            }
        });

        ui.separator();
        ui.label("Description:");
        ui.label(&description);

        if let Some(ref rem) = remediation {
            ui.separator();
            ui.label("Remediation:");
            ui.label(rem);
        }

        if !evidence.is_empty() {
            ui.separator();
            ui.label(format!("Evidence ({}):", evidence.len()));
            for ev in &evidence {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(&ev.info);
                        if ev.is_file_source && ev.length > 0 {
                            if ui.small_button("View hex").clicked() {
                                let label = ev
                                    .note
                                    .as_deref()
                                    .unwrap_or("evidence")
                                    .chars()
                                    .take(40)
                                    .collect::<String>();
                                app.open_hex_at_evidence(ev.offset, ev.length, label);
                            }
                        }
                    });
                    if let Some(ref n) = ev.note {
                        ui.monospace(n);
                    }
                });
            }
        }

        // Objects section with clickable references
        if !object_refs.is_empty() {
            ui.separator();
            ui.label("Objects:");
            ui.horizontal_wrapped(|ui| {
                for (obj_str, parsed) in &object_refs {
                    if let Some((obj_num, gen_num)) = parsed {
                        if ui.link(obj_str).clicked() {
                            app.navigate_to_object(*obj_num, *gen_num);
                            app.show_objects = true;
                        }
                    } else {
                        ui.label(obj_str);
                    }
                }
            });
        }

        if !reader_impacts.is_empty() {
            ui.separator();
            ui.label("Reader impacts:");
            for ri in &reader_impacts {
                ui.label(ri);
            }
        }

        if !meta.is_empty() {
            ui.separator();
            ui.collapsing("Metadata", |ui| {
                for (k, v) in &meta {
                    ui.horizontal(|ui| {
                        ui.monospace(k);
                        ui.label("=");
                        ui.monospace(v);
                    });
                }
            });
        }
    });
}

struct EvidenceDisplay {
    info: String,
    note: Option<String>,
    offset: u64,
    length: u32,
    is_file_source: bool,
}

/// Parse an object reference string like "5 0 R" into (obj, gen).
fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    let s = s.trim();
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        let obj = parts[0].parse::<u32>().ok()?;
        let gen = parts[1].parse::<u16>().ok()?;
        Some((obj, gen))
    } else {
        None
    }
}

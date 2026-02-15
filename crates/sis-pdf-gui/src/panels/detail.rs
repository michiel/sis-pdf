use crate::app::SisApp;

pub fn show(ui: &mut egui::Ui, app: &SisApp) {
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

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading(&f.title);
        ui.separator();

        egui::Grid::new("finding_meta").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
            ui.label("ID:");
            ui.label(&f.id);
            ui.end_row();

            ui.label("Kind:");
            ui.label(&f.kind);
            ui.end_row();

            ui.label("Severity:");
            ui.label(format!("{:?}", f.severity));
            ui.end_row();

            ui.label("Confidence:");
            ui.label(format!("{:?}", f.confidence));
            ui.end_row();

            if let Some(ref impact) = f.impact {
                ui.label("Impact:");
                ui.label(format!("{:?}", impact));
                ui.end_row();
            }

            ui.label("Surface:");
            ui.label(format!("{:?}", f.surface));
            ui.end_row();

            if let Some(ref action_type) = f.action_type {
                ui.label("Action type:");
                ui.label(action_type);
                ui.end_row();
            }

            if let Some(ref action_target) = f.action_target {
                ui.label("Action target:");
                ui.label(action_target);
                ui.end_row();
            }
        });

        ui.separator();
        ui.label("Description:");
        ui.label(&f.description);

        if let Some(ref rem) = f.remediation {
            ui.separator();
            ui.label("Remediation:");
            ui.label(rem);
        }

        if !f.evidence.is_empty() {
            ui.separator();
            ui.label(format!("Evidence ({}):", f.evidence.len()));
            for ev in &f.evidence {
                ui.group(|ui| {
                    ui.label(format!(
                        "offset: {}, length: {}, source: {:?}",
                        ev.offset, ev.length, ev.source
                    ));
                    if let Some(ref note) = ev.note {
                        ui.monospace(note);
                    }
                });
            }
        }

        if !f.objects.is_empty() {
            ui.separator();
            ui.label(format!("Objects: {}", f.objects.join(", ")));
        }

        if !f.reader_impacts.is_empty() {
            ui.separator();
            ui.label("Reader impacts:");
            for ri in &f.reader_impacts {
                ui.label(format!(
                    "  {:?} - {:?} ({:?}): {}",
                    ri.profile,
                    ri.severity,
                    ri.impact,
                    ri.note.as_deref().unwrap_or("")
                ));
            }
        }

        if !f.meta.is_empty() {
            ui.separator();
            ui.collapsing("Metadata", |ui| {
                for (k, v) in &f.meta {
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

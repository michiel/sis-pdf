use crate::app::SisApp;
use std::collections::{BTreeMap, BTreeSet};

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_revision;
    let mut ws = app.window_max.remove("Revision Timeline").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Revision Timeline", [640.0, 360.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Revision Timeline", &mut open, &mut ws);
        show(ui, app);
    });
    app.window_max.insert("Revision Timeline".to_string(), ws);
    app.show_revision = open;
}

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(result) = app.result.as_ref() else {
        return;
    };
    let mut revisions: BTreeMap<i32, RevisionSummary> = BTreeMap::new();
    let relevant_kinds = [
        "incremental_update_chain",
        "revision_forensics_present",
        "shadow_hide_attack",
        "shadow_replace_attack",
        "object_id_shadowing",
    ];

    for finding in &result.report.findings {
        if !relevant_kinds.contains(&finding.kind.as_str()) {
            continue;
        }
        let revision =
            finding.meta.get("revision.index").and_then(|raw| raw.parse::<i32>().ok()).unwrap_or(0);
        let entry = revisions.entry(revision).or_default();
        for object in &finding.objects {
            entry.objects.insert(object.clone());
        }
        if finding.meta.get("revision.post_cert").map(|v| v == "true").unwrap_or(false) {
            entry.post_cert = true;
        }
        if finding.kind.contains("shadow") {
            entry.shadow_objects.extend(finding.objects.iter().cloned());
        }
    }

    if revisions.is_empty() {
        ui.label("No incremental revisions detected.");
        return;
    }

    egui::ScrollArea::horizontal().show(ui, |ui| {
        ui.horizontal(|ui| {
            for (revision, summary) in revisions {
                ui.group(|ui| {
                    ui.set_width(220.0);
                    if revision <= 0 {
                        ui.strong("Rev baseline");
                    } else {
                        ui.strong(format!("Rev {}", revision));
                    }
                    if summary.post_cert {
                        ui.colored_label(egui::Color32::from_rgb(220, 70, 70), "post-cert");
                    }
                    ui.label(format!("{} objects", summary.objects.len()));
                    if !summary.shadow_objects.is_empty() {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 70, 70),
                            format!("{} shadow objects", summary.shadow_objects.len()),
                        );
                    }
                    ui.separator();
                    for object in summary.objects.iter().take(10) {
                        let colour = if summary.shadow_objects.contains(object) {
                            egui::Color32::from_rgb(220, 70, 70)
                        } else {
                            egui::Color32::from_rgb(180, 180, 180)
                        };
                        ui.colored_label(colour, object);
                    }
                    if summary.objects.len() > 10 {
                        ui.label(format!("... +{} more", summary.objects.len() - 10));
                    }
                });
            }
        });
    });
}

#[derive(Default)]
struct RevisionSummary {
    objects: BTreeSet<String>,
    shadow_objects: BTreeSet<String>,
    post_cert: bool,
}

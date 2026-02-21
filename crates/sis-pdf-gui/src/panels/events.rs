use crate::app::SisApp;
use sis_pdf_core::model::{Confidence, Finding, Severity};

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_events;
    let mut ws = app.window_max.remove("Events").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Events", [780.0, 500.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Events", &mut open, &mut ws);
        show(ui, app);
    });
    app.window_max.insert("Events".to_string(), ws);
    app.show_events = open;
}

fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let events = {
        let Some(result) = app.result.as_ref() else {
            return;
        };
        collect_events(&result.report.findings)
    };

    if events.is_empty() {
        app.selected_event = None;
        ui.label("No event signals detected.");
        return;
    }

    if app.selected_event.map(|idx| idx >= events.len()).unwrap_or(true) {
        app.selected_event = Some(0);
    }

    ui.label(format!("{} event signal(s)", events.len()));
    ui.separator();

    let available = ui.available_size();
    let list_width = (available.x * 0.42).max(260.0).min(380.0);

    ui.horizontal(|ui| {
        ui.set_min_height(available.y);

        ui.vertical(|ui| {
            ui.set_width(list_width);
            show_event_list(ui, app, &events);
        });

        ui.separator();

        ui.vertical(|ui| {
            show_event_details(ui, app, &events);
        });
    });
}

fn show_event_list(ui: &mut egui::Ui, app: &mut SisApp, events: &[EventEntry]) {
    egui::ScrollArea::vertical().id_salt("events_list").show(ui, |ui| {
        for (idx, event) in events.iter().enumerate() {
            let selected = app.selected_event == Some(idx);
            let label = format!(
                "{} [{}] {} ({})",
                event.event_label,
                event.initiation,
                event.kind,
                severity_label(event.severity)
            );
            if ui.selectable_label(selected, label).clicked() {
                app.selected_event = Some(idx);
            }
        }
    });
}

fn show_event_details(ui: &mut egui::Ui, app: &mut SisApp, events: &[EventEntry]) {
    let Some(selected) = app.selected_event.and_then(|idx| events.get(idx)) else {
        ui.label("Select an event to inspect details.");
        return;
    };

    ui.heading(&selected.event_label);
    ui.label(format!("Finding ID: {}", selected.finding_id));
    ui.label(format!("Kind: {}", selected.kind));
    ui.label(format!("Severity: {}", severity_label(selected.severity)));
    ui.label(format!("Confidence: {}", confidence_label(selected.confidence)));
    ui.label(format!("Initiation: {}", selected.initiation));
    if let Some(value) = selected.trigger_event_normalised.as_deref() {
        ui.label(format!("Trigger event (normalised): {value}"));
    }
    if let Some(value) = selected.trigger_event.as_deref() {
        ui.label(format!("Trigger event (raw): {value}"));
    }
    if let Some(value) = selected.trigger_context.as_deref() {
        ui.label(format!("Trigger context: {value}"));
    }
    if let Some(value) = selected.trigger_surface.as_deref() {
        ui.label(format!("Trigger surface: {value}"));
    }
    if let Some(value) = selected.action_type.as_deref() {
        ui.label(format!("Action type: {value}"));
    }
    if let Some(value) = selected.action_target.as_deref() {
        ui.label(format!("Action target: {value}"));
    }
    if !selected.objects.is_empty() {
        ui.label(format!("Objects: {}", selected.objects.join(", ")));
    }

    ui.separator();
    ui.label("Description");
    ui.label(&selected.description);

    ui.separator();
    ui.label("Metadata");
    egui::ScrollArea::vertical().id_salt("events_metadata").show(ui, |ui| {
        for (key, value) in &selected.metadata {
            ui.horizontal_wrapped(|ui| {
                ui.monospace(format!("{key}:"));
                ui.label(value);
            });
        }
    });
}

#[derive(Clone)]
struct EventEntry {
    finding_id: String,
    kind: String,
    severity: Severity,
    confidence: Confidence,
    initiation: String,
    event_label: String,
    trigger_event: Option<String>,
    trigger_event_normalised: Option<String>,
    trigger_context: Option<String>,
    trigger_surface: Option<String>,
    action_type: Option<String>,
    action_target: Option<String>,
    objects: Vec<String>,
    description: String,
    metadata: Vec<(String, String)>,
}

fn collect_events(findings: &[Finding]) -> Vec<EventEntry> {
    let mut events = Vec::new();
    for finding in findings {
        if !finding_has_event_signal(finding) {
            continue;
        }
        let trigger_event_normalised = finding.meta.get("action.trigger_event_normalised").cloned();
        let trigger_event = finding.meta.get("action.trigger_event").cloned();
        let event_key = finding.meta.get("action.event_key").cloned();
        let action_type_meta = finding.meta.get("action.s").cloned();
        let action_type = finding.action_type.clone().or(action_type_meta);
        let action_target = finding
            .action_target
            .clone()
            .or_else(|| finding.meta.get("action.target").cloned())
            .or_else(|| finding.meta.get("uri").cloned());
        let trigger_context = finding
            .meta
            .get("action.trigger_context")
            .cloned()
            .or_else(|| finding.meta.get("annot.trigger_context").cloned());
        let trigger_surface = finding.meta.get("action.trigger_surface").cloned();
        let initiation = finding
            .meta
            .get("action.initiation")
            .cloned()
            .or_else(|| finding.meta.get("action.trigger_type").cloned())
            .or_else(|| finding.action_initiation.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let event_label = trigger_event_normalised
            .clone()
            .or(trigger_event.clone())
            .or(event_key)
            .or(action_type.clone())
            .unwrap_or_else(|| finding.kind.clone());
        let mut metadata =
            finding.meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        metadata.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

        events.push(EventEntry {
            finding_id: finding.id.clone(),
            kind: finding.kind.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            initiation,
            event_label,
            trigger_event,
            trigger_event_normalised,
            trigger_context,
            trigger_surface,
            action_type,
            action_target,
            objects: finding.objects.clone(),
            description: finding.description.clone(),
            metadata,
        });
    }
    events
}

fn finding_has_event_signal(finding: &Finding) -> bool {
    finding.meta.contains_key("action.trigger_event_normalised")
        || finding.meta.contains_key("action.trigger_event")
        || finding.meta.contains_key("action.event_key")
        || finding.meta.contains_key("action.trigger_type")
        || finding.meta.contains_key("action.trigger_context")
        || finding.meta.contains_key("action.trigger_surface")
        || finding.meta.contains_key("action.initiation")
        || finding.meta.contains_key("annot.trigger_context")
        || finding.action_initiation.is_some()
        || finding.action_type.is_some()
        || finding.action_target.is_some()
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    confidence.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_core::model::{AttackSurface, Finding};
    use std::collections::HashMap;

    #[test]
    fn collect_events_extracts_trigger_metadata() {
        let mut meta = HashMap::new();
        meta.insert("action.trigger_event_normalised".to_string(), "/open".to_string());
        meta.insert("action.trigger_event".to_string(), "OpenAction".to_string());
        meta.insert("action.trigger_type".to_string(), "automatic".to_string());
        meta.insert("action.trigger_context".to_string(), "document".to_string());
        meta.insert("action.initiation".to_string(), "automatic".to_string());
        let finding = Finding {
            id: "f-1".to_string(),
            surface: AttackSurface::Actions,
            kind: "action_automatic_trigger".to_string(),
            severity: Severity::High,
            confidence: Confidence::Strong,
            title: "Automatic trigger".to_string(),
            description: "Triggered on open".to_string(),
            objects: vec!["1 0 R".to_string()],
            meta,
            ..Finding::default()
        };

        let events = collect_events(&[finding]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_label, "/open");
        assert_eq!(events[0].initiation, "automatic");
        assert_eq!(events[0].trigger_context.as_deref(), Some("document"));
    }

    #[test]
    fn collect_events_ignores_findings_without_event_signals() {
        let finding = Finding {
            id: "f-2".to_string(),
            surface: AttackSurface::Metadata,
            kind: "metadata_mismatch".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            title: "Metadata".to_string(),
            description: "No action signals".to_string(),
            ..Finding::default()
        };

        let events = collect_events(&[finding]);
        assert!(events.is_empty());
    }
}

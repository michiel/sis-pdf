use crate::app::SisApp;
use crate::event_view::{
    collect_unmapped_finding_event_signals, extract_event_view_models, EventViewModel,
};

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_events;
    let mut ws = app.window_max.remove("Events").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Events", [820.0, 520.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Events", &mut open, &mut ws);
        show(ui, app);
    });
    app.window_max.insert("Events".to_string(), ws);
    app.show_events = open;
}

fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let findings =
        app.result.as_ref().map(|result| result.report.findings.clone()).unwrap_or_default();
    if findings.is_empty() && app.result.is_none() {
        return;
    }
    let event_graph = match app.cached_event_graph() {
        Ok(graph) => graph,
        Err(err) => {
            ui.colored_label(egui::Color32::RED, format!("Unable to build event graph: {err}"));
            return;
        }
    };
    let events = extract_event_view_models(event_graph);
    let unmapped = collect_unmapped_finding_event_signals(&findings, &events);

    if events.is_empty() {
        app.selected_event = None;
        ui.label("No event graph nodes detected.");
        if !unmapped.is_empty() {
            show_unmapped_signals(ui, &unmapped);
        }
        return;
    }

    if app
        .selected_event
        .as_ref()
        .map(|node_id| events.iter().any(|event| &event.node_id == node_id))
        .unwrap_or(false)
    {
        // current selection still valid
    } else {
        app.selected_event = Some(events[0].node_id.clone());
    }

    ui.label(format!("{} event node(s)", events.len()));
    ui.separator();

    let available = ui.available_size();
    let list_width = (available.x * 0.44).max(300.0).min(420.0);

    ui.horizontal(|ui| {
        ui.set_min_height(available.y);

        ui.vertical(|ui| {
            ui.set_width(list_width);
            show_event_list(ui, app, &events);
            if !unmapped.is_empty() {
                ui.separator();
                show_unmapped_signals(ui, &unmapped);
            }
        });

        ui.separator();

        ui.vertical(|ui| {
            show_event_details(ui, app, &events);
        });
    });
}

fn show_event_list(ui: &mut egui::Ui, app: &mut SisApp, events: &[EventViewModel]) {
    egui::ScrollArea::vertical().id_salt("events_list").show(ui, |ui| {
        for event in events {
            let selected = app.selected_event.as_deref() == Some(event.node_id.as_str());
            let source = event
                .source_object
                .map(|(obj, generation)| format!("{obj} {generation}"))
                .unwrap_or_else(|| "-".to_string());
            let label = format!(
                "{} [{}] {} ({source})",
                event.event_type, event.trigger_class, event.node_id
            );
            if ui.selectable_label(selected, label).clicked() {
                app.selected_event = Some(event.node_id.clone());
            }
        }
    });
}

fn show_event_details(ui: &mut egui::Ui, app: &mut SisApp, events: &[EventViewModel]) {
    let Some(node_id) = app.selected_event.as_ref() else {
        ui.label("Select an event node to inspect details.");
        return;
    };
    let Some(selected) = events.iter().find(|event| &event.node_id == node_id) else {
        ui.label("Select an event node to inspect details.");
        return;
    };

    ui.heading(&selected.event_type);
    ui.label(format!("Node ID: {}", selected.node_id));
    ui.label(format!("Trigger class: {}", selected.trigger_class));
    match selected.source_object {
        Some((obj, generation)) => {
            ui.label(format!("Source object: {obj} {generation}"));
        }
        None => {
            ui.label("Source object: -");
        }
    }

    if let Some(event_key) = selected.event_key.as_deref() {
        ui.label(format!("Event key: {event_key}"));
    }
    if let Some(initiation) = selected.initiation.as_deref() {
        ui.label(format!("Initiation: {initiation}"));
    }
    if let Some(branch_index) = selected.branch_index {
        ui.label(format!("Branch index: {branch_index}"));
    }

    ui.separator();
    ui.label(format!("Executes: {}", render_list(&selected.execute_targets)));
    ui.label(format!("Outcomes: {}", render_list(&selected.outcome_targets)));
    ui.label(format!("Linked findings: {}", render_list(&selected.linked_finding_ids)));
}

fn show_unmapped_signals(
    ui: &mut egui::Ui,
    unmapped: &[crate::event_view::UnmappedFindingEventSignal],
) {
    ui.strong(format!("Unmapped finding event signals ({})", unmapped.len()));
    egui::ScrollArea::vertical().id_salt("events_unmapped").max_height(120.0).show(ui, |ui| {
        for row in unmapped {
            ui.label(format!("{} | {} | {}", row.finding_id, row.kind, row.title));
        }
    });
}

fn render_list(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_view::EventViewModel;

    #[test]
    fn render_list_handles_empty_and_non_empty() {
        assert_eq!(render_list(&[]), "-");
        assert_eq!(render_list(&["a".to_string(), "b".to_string()]), "a, b");
    }

    #[test]
    fn node_id_selection_matches_row() {
        let event = EventViewModel {
            node_id: "ev:1".to_string(),
            event_type: "DocumentOpen".to_string(),
            trigger_class: "automatic".to_string(),
            source_object: Some((1, 0)),
            execute_targets: Vec::new(),
            outcome_targets: Vec::new(),
            linked_finding_ids: Vec::new(),
            event_key: None,
            initiation: None,
            branch_index: None,
        };
        assert_eq!(event.node_id, "ev:1");
    }
}

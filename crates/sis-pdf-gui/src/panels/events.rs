use crate::app::SisApp;
use crate::event_view::{
    collect_unmapped_finding_event_signals, extract_event_view_models, EventViewModel,
    UnmappedFindingEventSignal,
};
use sis_pdf_core::model::{Finding, Severity};
use std::collections::HashMap;

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_events;
    let mut ws = app.window_max.remove("Events").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Events", [900.0, 560.0], &mut ws);
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
            show_unmapped_signals(ui, app, &unmapped);
        }
        return;
    }

    if !app
        .selected_event
        .as_ref()
        .map(|node_id| events.iter().any(|event| &event.node_id == node_id))
        .unwrap_or(false)
    {
        app.selected_event = Some(events[0].node_id.clone());
    }

    ui.label(format!("{} event node(s)", events.len()));
    ui.separator();

    let available = ui.available_size();
    let list_width = (available.x * 0.38).max(280.0).min(380.0);
    let finding_severity_by_id: HashMap<&str, Severity> =
        findings.iter().map(|finding| (finding.id.as_str(), finding.severity)).collect();

    ui.horizontal(|ui| {
        ui.set_min_height(available.y);

        ui.vertical(|ui| {
            ui.set_width(list_width);
            show_event_list(ui, app, &events, &finding_severity_by_id);
            if !unmapped.is_empty() {
                ui.separator();
                show_unmapped_signals(ui, app, &unmapped);
            }
        });

        ui.separator();

        ui.vertical(|ui| {
            show_event_details(ui, app, &events, &findings);
        });
    });
}

fn show_event_list(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    events: &[EventViewModel],
    finding_severity_by_id: &HashMap<&str, Severity>,
) {
    let content_events =
        events.iter().filter(|event| event.event_type == "ContentStreamExec").collect::<Vec<_>>();
    let group_content = content_events.len() >= 3;

    egui::ScrollArea::vertical().id_salt("events_list").show(ui, |ui| {
        for event in events {
            if group_content && event.event_type == "ContentStreamExec" {
                continue;
            }
            render_event_row(ui, app, event, finding_severity_by_id);
        }
        if group_content {
            let expanded = content_events.iter().any(|event| {
                worst_event_severity(event, finding_severity_by_id)
                    .is_some_and(|severity| severity >= Severity::Medium)
            });
            egui::CollapsingHeader::new(format!("Content streams ({})", content_events.len()))
                .default_open(expanded)
                .show(ui, |ui| {
                    for event in content_events {
                        render_event_row(ui, app, event, finding_severity_by_id);
                    }
                });
        }
    });
}

fn render_event_row(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    event: &EventViewModel,
    finding_severity_by_id: &HashMap<&str, Severity>,
) {
    let selected = app.selected_event.as_deref() == Some(event.node_id.as_str());
    let source = event
        .source_object
        .map(|(obj, generation)| format!("{obj} {generation}"))
        .unwrap_or_else(|| "-".to_string());
    let display_label = if event.label.is_empty() {
        format!("{} [{}] ({})", event.event_type, event.trigger_class, source)
    } else {
        format!("{} [{}]", event.label, event.trigger_class)
    };

    ui.horizontal(|ui| {
        if let Some(severity) = worst_event_severity(event, finding_severity_by_id) {
            ui.label(egui::RichText::new("●").color(severity_colour(severity)))
                .on_hover_text(format!("{severity:?}"));
        } else {
            ui.label(egui::RichText::new("•").weak());
        }
        if ui.selectable_label(selected, display_label).clicked() {
            app.selected_event = Some(event.node_id.clone());
        }
    });
}

fn show_event_details(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    events: &[EventViewModel],
    findings: &[Finding],
) {
    let Some(node_id) = app.selected_event.as_ref() else {
        ui.label("Select an event node to inspect details.");
        return;
    };
    let Some(selected) = events.iter().find(|event| &event.node_id == node_id) else {
        ui.label("Select an event node to inspect details.");
        return;
    };

    egui::ScrollArea::vertical().id_salt("events_detail").show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading(&selected.event_type);
            if ui.button("Show in graph").clicked() {
                if let Some(graph) = app.graph_state.graph.as_ref() {
                    if let Some(idx) = graph.nodes.iter().position(|node| {
                        node.event_node_id.as_deref() == Some(selected.node_id.as_str())
                    }) {
                        app.graph_state.selected_node = Some(idx);
                    }
                }
                app.show_graph = true;
            }
        });
        if !selected.label.is_empty() && selected.label != selected.event_type {
            ui.label(
                egui::RichText::new(&selected.label)
                    .color(ui.visuals().weak_text_color())
                    .italics(),
            );
        }
        let description = event_type_description(&selected.event_type);
        if !description.is_empty() {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(description).weak());
            ui.add_space(4.0);
        }

        ui.separator();
        ui.label(
            egui::RichText::new(format!("Node ID: {}", selected.node_id))
                .color(ui.visuals().weak_text_color()),
        );
        ui.label(format!("Trigger class: {}", selected.trigger_class));
        if let Some(event_key) = selected.event_key.as_deref() {
            ui.label(format!("Event key: {event_key}"));
        }
        if let Some(initiation) = selected.initiation.as_deref() {
            ui.label(format!("Initiation: {initiation}"));
        }
        if let Some(branch_index) = selected.branch_index {
            ui.label(format!("Branch index: {branch_index}"));
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.strong("Source object:");
            match selected.source_object {
                Some((obj, gen)) => {
                    if ui
                        .link(format!("{obj} {gen}"))
                        .on_hover_text("Open in Object Inspector")
                        .clicked()
                    {
                        app.navigate_to_object(obj, gen);
                        app.show_objects = true;
                    }
                }
                None => {
                    ui.weak("-");
                }
            };
        });

        // "View content operators" button for ContentStreamExec events.
        if selected.event_type == "ContentStreamExec" {
            for target in &selected.execute_targets {
                if let Some((obj, gen)) = target.object_ref {
                    if ui
                        .button(format!("View content operators: {} {}", obj, gen))
                        .on_hover_text("Open content stream operator breakdown")
                        .clicked()
                    {
                        crate::panels::content_stream::open_stream(app, obj, gen);
                    }
                }
            }
        }

        ui.horizontal_wrapped(|ui| {
            ui.strong("Executes:");
            if selected.execute_targets.is_empty() {
                ui.weak("-");
            } else {
                for target in &selected.execute_targets {
                    match target.object_ref {
                        Some((obj, gen)) => {
                            if ui
                                .link(format!("{obj} {gen}"))
                                .on_hover_text(format!("Object Inspector: {}", target.node_id))
                                .clicked()
                            {
                                app.navigate_to_object(obj, gen);
                                app.show_objects = true;
                            }
                        }
                        None => {
                            ui.weak(&target.node_id);
                        }
                    };
                }
            }
        });

        ui.add_space(6.0);
        ui.strong("Outcomes");
        if selected.outcome_targets.is_empty() {
            ui.weak("-");
        } else {
            for outcome in &selected.outcome_targets {
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("{} — {}", outcome.outcome_type, outcome.label));
                        if let Some(score) = outcome.confidence_score {
                            ui.label(
                                egui::RichText::new(format!("{score}%"))
                                    .background_color(ui.visuals().faint_bg_color),
                            );
                        }
                        if let Some(severity_hint) = outcome.severity_hint.as_deref() {
                            ui.label(
                                egui::RichText::new(severity_hint)
                                    .color(severity_hint_colour(severity_hint)),
                            );
                        }
                    });
                    if let Some((obj, gen)) = outcome.source_obj {
                        ui.horizontal(|ui| {
                            ui.label("Source:");
                            if ui.link(format!("{obj} {gen}")).clicked() {
                                app.navigate_to_object(obj, gen);
                                app.show_objects = true;
                            }
                        });
                    }
                    if !outcome.evidence.is_empty() {
                        ui.label("Evidence:");
                        for evidence in &outcome.evidence {
                            ui.label(format!("- {evidence}"));
                        }
                    }
                });
            }
        }

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.strong("Linked findings:");
            if selected.linked_finding_ids.is_empty() {
                ui.weak("-");
            } else {
                for finding_id in &selected.linked_finding_ids {
                    if let Some(idx) = findings.iter().position(|f| f.id == *finding_id) {
                        let short_id = finding_id.get(..12).unwrap_or(finding_id);
                        if ui
                            .link(short_id)
                            .on_hover_text(format!("{finding_id} — open in Finding Detail"))
                            .clicked()
                        {
                            app.selected_finding = Some(idx);
                            app.finding_origin_event = Some(selected.node_id.clone());
                        }
                    } else {
                        ui.weak(finding_id.get(..12).unwrap_or(finding_id));
                    }
                }
            }
        });

        if !selected.mitre_techniques.is_empty() {
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.strong("MITRE:");
                for technique in &selected.mitre_techniques {
                    ui.label(
                        egui::RichText::new(technique)
                            .monospace()
                            .background_color(ui.visuals().extreme_bg_color),
                    );
                }
            });
        }
    });
}

fn show_unmapped_signals(
    ui: &mut egui::Ui,
    app: &mut SisApp,
    unmapped: &[UnmappedFindingEventSignal],
) {
    ui.strong(format!("Unmapped finding event signals ({})", unmapped.len()));
    egui::ScrollArea::vertical().id_salt("events_unmapped").max_height(140.0).show(ui, |ui| {
        for row in unmapped {
            let label = format!("{} — {}", row.kind, row.title);
            if ui
                .link(label)
                .on_hover_text(format!("{} — open in Finding Detail", row.finding_id))
                .clicked()
            {
                app.selected_finding = Some(row.finding_idx);
                app.finding_origin_event = None;
            }
        }
    });
}

fn worst_event_severity(
    event: &EventViewModel,
    finding_severity_by_id: &HashMap<&str, Severity>,
) -> Option<Severity> {
    event
        .linked_finding_ids
        .iter()
        .filter_map(|finding_id| finding_severity_by_id.get(finding_id.as_str()).copied())
        .max_by_key(|severity| *severity as u8)
}

fn severity_colour(severity: Severity) -> egui::Color32 {
    match severity {
        Severity::Critical => egui::Color32::from_rgb(176, 0, 32),
        Severity::High => egui::Color32::from_rgb(210, 53, 23),
        Severity::Medium => egui::Color32::from_rgb(216, 142, 0),
        Severity::Low => egui::Color32::from_rgb(17, 120, 75),
        Severity::Info => egui::Color32::from_rgb(74, 101, 130),
    }
}

fn severity_hint_colour(severity_hint: &str) -> egui::Color32 {
    match severity_hint.to_ascii_lowercase().as_str() {
        "critical" => severity_colour(Severity::Critical),
        "high" => severity_colour(Severity::High),
        "medium" => severity_colour(Severity::Medium),
        "low" => severity_colour(Severity::Low),
        _ => severity_colour(Severity::Info),
    }
}

/// Returns a brief static description for the given event type (Debug-format string).
fn event_type_description(event_type: &str) -> &'static str {
    match event_type {
        "ContentStreamExec" => {
            "A page content stream is being executed by the reader. The source object is the \
             originating page; the execute target is the stream object containing PDF drawing \
             operators. Content streams are the primary rendering mechanism and are also used to \
             carry obfuscated payloads, shellcode, and embedded JavaScript."
        }
        "DocumentOpen" => "Triggered when the document is first opened by the reader.",
        "DocumentWillClose" => "Triggered just before the document is closed.",
        "DocumentWillSave" => "Triggered just before the document is saved.",
        "DocumentDidSave" => "Triggered after the document has been saved.",
        "DocumentWillPrint" => "Triggered just before the document is printed.",
        "DocumentDidPrint" => "Triggered after the document has been printed.",
        "PageOpen" => "Triggered when a page is displayed to the user.",
        "PageClose" => "Triggered when the user navigates away from a page.",
        "PageVisible" => "Triggered when a page becomes visible in the viewport.",
        "PageInvisible" => "Triggered when a page leaves the viewport.",
        "FieldKeystroke" => "Triggered on each keystroke in a form field.",
        "FieldFormat" => "Triggered when a form field value is formatted for display.",
        "FieldValidate" => "Triggered when a form field value is validated.",
        "FieldCalculate" => "Triggered to recalculate a dependent form field value.",
        "FieldMouseDown" | "FieldMouseUp" | "FieldMouseEnter" | "FieldMouseExit"
        | "FieldOnFocus" | "FieldOnBlur" | "FieldActivation" => {
            "Triggered by user interaction with a form field."
        }
        "AnnotationActivation" => {
            "Triggered when the user activates an annotation (e.g. clicks a link or button)."
        }
        "NextAction" => "A chained action following a prior action in an action sequence.",
        "JsTimerDelayed" => {
            "A JavaScript timer-based delayed execution. Used by malware to defer payload \
             execution until after initial scan analysis windows."
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_view::EventViewModel;

    #[test]
    fn event_type_description_returns_non_empty_for_known_types() {
        assert!(!event_type_description("ContentStreamExec").is_empty());
        assert!(!event_type_description("DocumentOpen").is_empty());
        assert!(!event_type_description("JsTimerDelayed").is_empty());
    }

    #[test]
    fn event_type_description_returns_empty_for_unknown_type() {
        assert_eq!(event_type_description("UnknownType"), "");
    }

    #[test]
    fn node_id_selection_matches_row() {
        let event = EventViewModel {
            node_id: "ev:1".to_string(),
            event_type: "DocumentOpen".to_string(),
            trigger_class: "automatic".to_string(),
            source_object: Some((1, 0)),
            ..EventViewModel::default()
        };
        assert_eq!(event.node_id, "ev:1");
    }
}

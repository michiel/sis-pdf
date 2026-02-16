use crate::app::SisApp;

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    let chains = &result.report.chains;

    if chains.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label("No exploit chains detected");
        });
        return;
    }

    // Pre-build a lookup from finding ID to index for clickable links
    let finding_index: Vec<(String, usize)> =
        result.report.findings.iter().enumerate().map(|(i, f)| (f.id.clone(), i)).collect();

    // Pre-extract chain display data to avoid borrowing result inside mutable closure
    let chain_data: Vec<ChainDisplay> = chains
        .iter()
        .enumerate()
        .map(|(i, chain)| {
            let finding_links: Vec<(String, Option<usize>)> = chain
                .findings
                .iter()
                .map(|fid| {
                    let idx = finding_index.iter().find(|(id, _)| id == fid).map(|(_, i)| *i);
                    (fid.clone(), idx)
                })
                .collect();

            // Extract flow nodes from trigger/action/payload
            let mut flow_nodes = Vec::new();
            if let Some(ref trigger) = chain.trigger {
                flow_nodes.push(FlowNode {
                    stage: "Trigger".to_string(),
                    description: trigger.clone(),
                    object_ref: extract_obj_ref_from_text(trigger),
                });
            }
            if let Some(ref action) = chain.action {
                flow_nodes.push(FlowNode {
                    stage: "Action".to_string(),
                    description: action.clone(),
                    object_ref: extract_obj_ref_from_text(action),
                });
            }
            if let Some(ref payload) = chain.payload {
                flow_nodes.push(FlowNode {
                    stage: "Payload".to_string(),
                    description: payload.clone(),
                    object_ref: extract_obj_ref_from_text(payload),
                });
            }

            ChainDisplay {
                index: i,
                score: chain.score,
                path: chain.path.clone(),
                trigger: chain.trigger.clone(),
                action: chain.action.clone(),
                payload: chain.payload.clone(),
                reasons: chain.reasons.clone(),
                finding_links,
                flow_nodes,
            }
        })
        .collect();

    ui.heading(format!("{} Exploit Chains", chain_data.len()));
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        for chain in &chain_data {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    let is_selected = app.selected_chain == Some(chain.index);
                    if ui.selectable_label(is_selected, format!("Chain #{}", chain.index + 1)).clicked() {
                        app.selected_chain = if is_selected { None } else { Some(chain.index) };
                    }
                    ui.separator();
                    ui.label(format!("Score: {:.2}", chain.score));
                    ui.separator();
                    ui.label(&chain.path);
                });

                ui.add_space(4.0);
                if let Some(ref trigger) = chain.trigger {
                    ui.horizontal(|ui| {
                        ui.monospace("[trigger]");
                        ui.label(trigger);
                    });
                }
                if let Some(ref action) = chain.action {
                    ui.horizontal(|ui| {
                        ui.monospace("[action] ");
                        ui.label(action);
                    });
                }
                if let Some(ref payload) = chain.payload {
                    ui.horizontal(|ui| {
                        ui.monospace("[payload]");
                        ui.label(payload);
                    });
                }

                // Flow diagram
                if chain.flow_nodes.len() >= 2 {
                    ui.add_space(4.0);
                    show_flow_diagram(ui, app, &chain.flow_nodes);
                }

                if !chain.reasons.is_empty() {
                    ui.add_space(4.0);
                    ui.label("Reasons:");
                    for reason in &chain.reasons {
                        ui.label(format!("  - {}", reason));
                    }
                }

                if !chain.finding_links.is_empty() {
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("Findings ({}):", chain.finding_links.len()));
                        for (finding_id, maybe_idx) in &chain.finding_links {
                            if let Some(idx) = maybe_idx {
                                if ui.link(finding_id).clicked() {
                                    app.selected_finding = Some(*idx);
                                    app.show_chains = false;
                                }
                            } else {
                                ui.label(finding_id);
                            }
                        }
                    });
                }
            });
            ui.add_space(4.0);
        }
    });
}

/// Render a horizontal flow diagram: [Stage: desc] --> [Stage: desc] --> ...
fn show_flow_diagram(ui: &mut egui::Ui, app: &mut SisApp, nodes: &[FlowNode]) {
    ui.horizontal_wrapped(|ui| {
        for (i, node) in nodes.iter().enumerate() {
            if i > 0 {
                ui.label(egui::RichText::new(" --> ").color(egui::Color32::GRAY).monospace());
            }

            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.strong(&node.stage);
                    ui.label(&node.description);
                    if let Some((obj, gen)) = node.object_ref {
                        if ui.link(format!("obj {} {}", obj, gen)).clicked() {
                            app.navigate_to_object(obj, gen);
                            app.show_objects = true;
                        }
                    }
                });
            });
        }
    });
}

/// Try to extract an object reference like "obj 5 0" or "5 0 R" from descriptive text.
pub fn extract_obj_ref_from_text(text: &str) -> Option<(u32, u16)> {
    // Try "N M R" pattern
    for word_group in text.split(|c: char| c == ',' || c == ';' || c == '(' || c == ')') {
        let trimmed = word_group.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 3 && parts.last() == Some(&"R") {
            if let (Ok(obj), Ok(gen)) =
                (parts[parts.len() - 3].parse::<u32>(), parts[parts.len() - 2].parse::<u16>())
            {
                return Some((obj, gen));
            }
        }
    }
    // Try "obj N" pattern (gen defaults to 0)
    if let Some(pos) = text.to_lowercase().find("obj ") {
        let rest = &text[pos + 4..];
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(obj) = num_str.parse::<u32>() {
            return Some((obj, 0));
        }
    }
    None
}

struct ChainDisplay {
    index: usize,
    score: f64,
    path: String,
    trigger: Option<String>,
    action: Option<String>,
    payload: Option<String>,
    reasons: Vec<String>,
    finding_links: Vec<(String, Option<usize>)>,
    flow_nodes: Vec<FlowNode>,
}

struct FlowNode {
    stage: String,
    description: String,
    object_ref: Option<(u32, u16)>,
}

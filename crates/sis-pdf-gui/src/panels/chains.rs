use crate::app::{ChainSortColumn, SisApp};

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_chains;
    let mut ws = app.window_max.remove("Chains").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Chains", [600.0, 400.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Chains", &mut open, &mut ws);
        show(ui, app);
    });
    app.window_max.insert("Chains".to_string(), ws);
    app.show_chains = open;
}

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    let chains: Vec<(usize, &sis_pdf_core::chain::ExploitChain)> = result
        .report
        .chains
        .iter()
        .enumerate()
        .filter(|(_, chain)| app.include_singleton_chains || chain.findings.len() > 1)
        .collect();

    if chains.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label("No exploit chains match the current filter");
        });
        return;
    }

    // Pre-build a lookup from finding ID to index for clickable links
    let finding_index: Vec<(String, usize)> =
        result.report.findings.iter().enumerate().map(|(i, f)| (f.id.clone(), i)).collect();

    // Pre-extract chain display data to avoid borrowing result inside mutable closure
    let chain_data: Vec<ChainDisplay> = chains
        .iter()
        .map(|(original_index, chain)| {
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
                index: *original_index,
                score: chain.score,
                path: chain.path.clone(),
                trigger: chain.trigger.clone(),
                action: chain.action.clone(),
                payload: chain.payload.clone(),
                reasons: chain.reasons.clone(),
                confirmed_stages: chain.confirmed_stages.clone(),
                inferred_stages: chain.inferred_stages.clone(),
                chain_completeness: chain.chain_completeness,
                reader_risk: chain.reader_risk.clone(),
                narrative: chain.narrative.clone(),
                all_false_positive: chain.findings.iter().all(|fid| {
                    app.annotations
                        .get(fid)
                        .map(|annotation| {
                            annotation.triage_state
                                == crate::annotations::TriageState::FalsePositive
                        })
                        .unwrap_or(false)
                }),
                all_mitigated: chain.findings.iter().all(|fid| {
                    app.annotations
                        .get(fid)
                        .map(|annotation| {
                            annotation.triage_state == crate::annotations::TriageState::Mitigated
                        })
                        .unwrap_or(false)
                }),
                finding_links,
                flow_nodes,
            }
        })
        .collect();

    ui.heading(format!("{} Exploit Chains", chain_data.len()));
    ui.horizontal(|ui| {
        ui.checkbox(&mut app.include_singleton_chains, "Include single-item chains");
    });

    // Sort controls
    ui.horizontal(|ui| {
        ui.label("Sort by:");
        if ui.selectable_label(app.chain_sort_column == ChainSortColumn::Score, "Score").clicked() {
            toggle_chain_sort(app, ChainSortColumn::Score);
        }
        if ui.selectable_label(app.chain_sort_column == ChainSortColumn::Path, "Path").clicked() {
            toggle_chain_sort(app, ChainSortColumn::Path);
        }
        if ui
            .selectable_label(app.chain_sort_column == ChainSortColumn::Findings, "Findings")
            .clicked()
        {
            toggle_chain_sort(app, ChainSortColumn::Findings);
        }
        let arrow = if app.chain_sort_ascending { "^" } else { "v" };
        ui.label(arrow);
    });
    ui.separator();

    // Sort the chain data
    let mut sorted_indices: Vec<usize> = (0..chain_data.len()).collect();
    sorted_indices.sort_by(|&a, &b| {
        let ca = &chain_data[a];
        let cb = &chain_data[b];
        let ord = match app.chain_sort_column {
            ChainSortColumn::Score => {
                ca.score.partial_cmp(&cb.score).unwrap_or(std::cmp::Ordering::Equal)
            }
            ChainSortColumn::Path => ca.path.cmp(&cb.path),
            ChainSortColumn::Findings => ca.finding_links.len().cmp(&cb.finding_links.len()),
        };
        if app.chain_sort_ascending {
            ord
        } else {
            ord.reverse()
        }
    });

    egui::ScrollArea::vertical().show(ui, |ui| {
        for &ci in &sorted_indices {
            let chain = &chain_data[ci];
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    let is_selected = app.selected_chain == Some(chain.index);
                    if ui
                        .selectable_label(is_selected, format!("Chain #{}", chain.index + 1))
                        .clicked()
                    {
                        app.selected_chain = if is_selected { None } else { Some(chain.index) };
                    }
                    ui.separator();
                    ui.label(format!("Score: {:.2}", chain.score));
                    ui.separator();
                    if chain.all_false_positive {
                        ui.colored_label(egui::Color32::RED, "[FP]");
                        ui.separator();
                    } else if chain.all_mitigated {
                        ui.colored_label(egui::Color32::from_rgb(80, 150, 230), "[OK]");
                        ui.separator();
                    }
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
                show_completeness_bar(
                    ui,
                    &chain.confirmed_stages,
                    &chain.inferred_stages,
                    chain.chain_completeness,
                );
                show_reader_risk_chips(ui, &chain.reader_risk);
                if !chain.narrative.trim().is_empty() {
                    ui.add_space(4.0);
                    ui.label(&chain.narrative);
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

fn toggle_chain_sort(app: &mut SisApp, column: ChainSortColumn) {
    if app.chain_sort_column == column {
        app.chain_sort_ascending = !app.chain_sort_ascending;
    } else {
        app.chain_sort_column = column;
        app.chain_sort_ascending = false;
    }
}

struct ChainDisplay {
    index: usize,
    score: f64,
    path: String,
    trigger: Option<String>,
    action: Option<String>,
    payload: Option<String>,
    reasons: Vec<String>,
    confirmed_stages: Vec<String>,
    inferred_stages: Vec<String>,
    chain_completeness: f64,
    reader_risk: std::collections::HashMap<String, String>,
    narrative: String,
    all_false_positive: bool,
    all_mitigated: bool,
    finding_links: Vec<(String, Option<usize>)>,
    flow_nodes: Vec<FlowNode>,
}

struct FlowNode {
    stage: String,
    description: String,
    object_ref: Option<(u32, u16)>,
}

fn show_completeness_bar(
    ui: &mut egui::Ui,
    confirmed: &[String],
    inferred: &[String],
    completeness: f64,
) {
    ui.horizontal(|ui| {
        for stage in ["INPUT", "DECODE", "RENDER", "EXECUTE", "EGRESS"] {
            let lower = stage.to_lowercase();
            let colour = if confirmed.iter().any(|value| value == &lower) {
                egui::Color32::GREEN
            } else if inferred.iter().any(|value| value == &lower) {
                egui::Color32::YELLOW
            } else {
                egui::Color32::DARK_GRAY
            };
            ui.colored_label(colour, stage);
            ui.add_space(4.0);
        }
        ui.label(format!("{:.0}% complete", completeness * 100.0));
    });
}

fn show_reader_risk_chips(
    ui: &mut egui::Ui,
    reader_risk: &std::collections::HashMap<String, String>,
) {
    if reader_risk.is_empty() {
        return;
    }
    ui.horizontal(|ui| {
        for profile in ["acrobat", "pdfium", "preview"] {
            if let Some(severity) = reader_risk.get(profile) {
                ui.colored_label(severity_colour(severity), format!("{}: {}", profile, severity));
                ui.add_space(4.0);
            }
        }
    });
}

fn severity_colour(value: &str) -> egui::Color32 {
    match value {
        "Critical" => egui::Color32::from_rgb(180, 40, 40),
        "High" => egui::Color32::from_rgb(210, 80, 40),
        "Medium" => egui::Color32::from_rgb(210, 140, 50),
        "Low" => egui::Color32::from_rgb(120, 120, 120),
        _ => egui::Color32::from_rgb(100, 100, 100),
    }
}

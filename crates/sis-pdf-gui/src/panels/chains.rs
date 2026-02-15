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
            ChainDisplay {
                index: i,
                score: chain.score,
                path: chain.path.clone(),
                trigger: chain.trigger.clone(),
                action: chain.action.clone(),
                payload: chain.payload.clone(),
                reasons: chain.reasons.clone(),
                finding_links,
            }
        })
        .collect();

    ui.heading(format!("{} Exploit Chains", chain_data.len()));
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        for chain in &chain_data {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!("Chain #{}", chain.index + 1));
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

struct ChainDisplay {
    index: usize,
    score: f64,
    path: String,
    trigger: Option<String>,
    action: Option<String>,
    payload: Option<String>,
    reasons: Vec<String>,
    finding_links: Vec<(String, Option<usize>)>,
}

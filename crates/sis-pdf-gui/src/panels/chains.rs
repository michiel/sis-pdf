use crate::app::SisApp;

pub fn show(ui: &mut egui::Ui, app: &SisApp) {
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

    ui.heading(format!("{} Exploit Chains", chains.len()));
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        for (i, chain) in chains.iter().enumerate() {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!("Chain #{}", i + 1));
                    ui.separator();
                    ui.label(format!("Score: {:.2}", chain.score));
                    ui.separator();
                    ui.label(&chain.path);
                });

                // Show trigger -> action -> payload
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

                if !chain.findings.is_empty() {
                    ui.add_space(4.0);
                    ui.label(format!("Findings: {}", chain.findings.join(", ")));
                }
            });
            ui.add_space(4.0);
        }
    });
}

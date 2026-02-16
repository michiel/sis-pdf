use crate::app::SisApp;

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.selected_finding.is_some();
    let state = app.window_max.entry("Finding Detail".to_string()).or_default();
    let is_max = state.is_maximised;
    let mut win = egui::Window::new("Finding Detail").open(&mut open).resizable(true);
    if is_max {
        let area = ctx.available_rect();
        win = win.fixed_pos(area.left_top()).fixed_size(area.size());
    } else {
        win = win.default_size([400.0, 500.0]);
    }
    win.show(ctx, |ui| {
        ui.horizontal(|ui| {
            let ws = app.window_max.entry("Finding Detail".to_string()).or_default();
            crate::window_state::maximise_button(ui, ws);
        });
        show(ui, app);
    });
    if !open {
        app.selected_finding = None;
    }
}

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
    let reader_impacts: Vec<ReaderImpactDisplay> = f
        .reader_impacts
        .iter()
        .map(|ri| ReaderImpactDisplay {
            profile: format!("{:?}", ri.profile),
            severity: format!("{:?}", ri.severity),
            impact: format!("{:?}", ri.impact),
            note: ri.note.clone().unwrap_or_default(),
        })
        .collect();
    let meta: Vec<(String, String)> = f.meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    // CVE references from metadata
    let cve_refs: Vec<(String, String)> = meta
        .iter()
        .filter(|(k, _)| k.contains("cve"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // YARA annotation
    let yara = f.yara.as_ref().map(|y| YaraDisplay {
        rule_name: y.rule_name.clone(),
        tags: y.tags.clone(),
        strings: y.strings.clone(),
    });

    // Chain membership: find chains containing this finding's ID
    let finding_id = id.clone();
    let chain_membership: Vec<(usize, String)> = result
        .report
        .chains
        .iter()
        .enumerate()
        .filter(|(_, chain)| chain.findings.contains(&finding_id))
        .map(|(i, chain)| (i, chain.path.clone()))
        .collect();

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

        // Description (collapsible, default open)
        let desc_id = ui.make_persistent_id("detail_description");
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), desc_id, true)
            .show_header(ui, |ui| {
                ui.strong("Description");
            })
            .body(|ui| {
                ui.label(&description);
                if let Some(ref rem) = remediation {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Remediation:").strong());
                    ui.label(rem);
                }
            });

        // Evidence (collapsible, default open)
        if !evidence.is_empty() {
            let ev_id = ui.make_persistent_id("detail_evidence");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                ev_id,
                true,
            )
            .show_header(ui, |ui| {
                ui.strong(format!("Evidence ({})", evidence.len()));
            })
            .body(|ui| {
                for ev in &evidence {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(&ev.info);
                            if ev.is_file_source
                                && ev.length > 0
                                && ui.small_button("View hex").clicked()
                            {
                                let label = ev
                                    .note
                                    .as_deref()
                                    .unwrap_or("evidence")
                                    .chars()
                                    .take(40)
                                    .collect::<String>();
                                app.open_hex_at_evidence(ev.offset, ev.length, label);
                            }
                        });
                        if let Some(ref n) = ev.note {
                            ui.monospace(n);
                        }
                    });
                }
            });
        }

        // Objects (collapsible, default open)
        if !object_refs.is_empty() {
            let obj_id = ui.make_persistent_id("detail_objects");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                obj_id,
                true,
            )
            .show_header(ui, |ui| {
                ui.strong(format!("Objects ({})", object_refs.len()));
            })
            .body(|ui| {
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
            });
        }

        // Chain membership (collapsible, default open)
        if !chain_membership.is_empty() {
            let cm_id = ui.make_persistent_id("detail_chains");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                cm_id,
                true,
            )
            .show_header(ui, |ui| {
                ui.strong(format!("Chain Membership ({})", chain_membership.len()));
            })
            .body(|ui| {
                for (chain_idx, path) in &chain_membership {
                    let label = format!("Chain #{}: {}", chain_idx + 1, path);
                    if ui.link(&label).clicked() {
                        app.show_chains = true;
                        app.selected_chain = Some(*chain_idx);
                    }
                }
            });
        }

        // CVE references (collapsible, default open when present)
        if !cve_refs.is_empty() {
            let cve_id = ui.make_persistent_id("detail_cve");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                cve_id,
                true,
            )
            .show_header(ui, |ui| {
                ui.strong(format!("CVE References ({})", cve_refs.len()));
            })
            .body(|ui| {
                for (key, value) in &cve_refs {
                    ui.horizontal(|ui| {
                        ui.monospace(key);
                        ui.label(value);
                    });
                }
            });
        }

        // YARA matches
        if let Some(ref yara) = yara {
            let yara_id = ui.make_persistent_id("detail_yara");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                yara_id,
                true,
            )
            .show_header(ui, |ui| {
                ui.strong("YARA Match");
            })
            .body(|ui| {
                ui.label(format!("Rule: {}", yara.rule_name));
                if !yara.tags.is_empty() {
                    ui.label(format!("Tags: {}", yara.tags.join(", ")));
                }
                if !yara.strings.is_empty() {
                    ui.label(format!("Strings: {}", yara.strings.join(", ")));
                }
            });
        }

        // Reader impacts (collapsible, default collapsed)
        if !reader_impacts.is_empty() {
            let ri_id = ui.make_persistent_id("detail_reader_impacts");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                ri_id,
                false,
            )
            .show_header(ui, |ui| {
                ui.strong(format!("Reader Impacts ({})", reader_impacts.len()));
            })
            .body(|ui| {
                egui::Grid::new("reader_impacts_grid")
                    .num_columns(4)
                    .spacing([8.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Reader");
                        ui.strong("Severity");
                        ui.strong("Impact");
                        ui.strong("Notes");
                        ui.end_row();
                        for ri in &reader_impacts {
                            ui.label(&ri.profile);
                            ui.label(&ri.severity);
                            ui.label(&ri.impact);
                            ui.label(&ri.note);
                            ui.end_row();
                        }
                    });
            });
        }

        // Metadata (collapsible, default collapsed)
        if !meta.is_empty() {
            let meta_id = ui.make_persistent_id("detail_metadata");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                meta_id,
                false,
            )
            .show_header(ui, |ui| {
                ui.strong(format!("Metadata ({})", meta.len()));
            })
            .body(|ui| {
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

struct ReaderImpactDisplay {
    profile: String,
    severity: String,
    impact: String,
    note: String,
}

struct YaraDisplay {
    rule_name: String,
    tags: Vec<String>,
    strings: Vec<String>,
}

fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    crate::util::parse_obj_ref(s)
}

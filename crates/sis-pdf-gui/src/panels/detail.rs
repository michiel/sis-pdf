use crate::app::SisApp;
use sis_pdf_core::event_graph::{EventGraph, EventNodeKind};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.selected_finding.is_some();
    let mut ws = app.window_max.remove("Finding Detail").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Finding Detail", [400.0, 500.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Finding Detail", &mut open, &mut ws);
        show(ui, app);
    });
    app.window_max.insert("Finding Detail".to_string(), ws);
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
    let finding_objects = object_refs.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>();
    let chain_membership: Vec<(usize, String)> = result
        .report
        .chains
        .iter()
        .enumerate()
        .filter(|(_, chain)| chain.findings.contains(&finding_id))
        .map(|(i, chain)| (i, chain.path.clone()))
        .collect();
    let event_graph_paths = event_graph_paths_for_finding(app, &finding_id, &finding_objects);

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
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), ev_id, true)
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
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), cm_id, true)
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

        // Event graph paths (collapsible, default open)
        if !event_graph_paths.is_empty() {
            let egp_id = ui.make_persistent_id("detail_event_graph_paths");
            egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                egp_id,
                true,
            )
            .show_header(ui, |ui| {
                ui.strong(format!("Event Graph Paths ({})", event_graph_paths.len()));
            })
            .body(|ui| {
                for path in &event_graph_paths {
                    ui.label(path);
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

fn event_graph_paths_for_finding(
    app: &mut SisApp,
    finding_id: &str,
    finding_objects: &[String],
) -> Vec<String> {
    let Some(result) = app.result.as_ref() else {
        return Vec::new();
    };
    let findings_hash = compute_findings_hash(&result.report.findings);
    if app
        .finding_detail_graph_cache
        .as_ref()
        .map(|cache| {
            cache.file_name != result.file_name
                || cache.file_size != result.file_size
                || cache.findings_hash != findings_hash
        })
        .unwrap_or(true)
    {
        app.finding_detail_graph_cache = build_finding_detail_graph_cache(result);
    }
    let Some(cache) = app.finding_detail_graph_cache.as_mut() else {
        return Vec::new();
    };
    if let Some(cached) = cache.finding_paths.get(finding_id) {
        return cached.clone();
    }

    let mut output = Vec::new();
    for object in finding_objects {
        let Some((obj, generation)) = parse_obj_ref(object) else {
            continue;
        };
        let start_id = format!("obj:{obj}:{generation}");
        if !cache.event_graph.node_index.contains_key(&start_id) {
            continue;
        }
        let max_hops = app.graph_state.finding_detail_max_hops;
        if let Some(path) = shortest_path_to_event(&cache.event_graph, &start_id, max_hops) {
            output.push(format!("Trigger path: {}", render_event_path(&cache.event_graph, &path)));
        }
        if let Some(path) = shortest_path_to_outcome(&cache.event_graph, &start_id, max_hops) {
            output.push(format!("Outcome path: {}", render_event_path(&cache.event_graph, &path)));
        }
    }
    output.sort();
    output.dedup();
    cache.finding_paths.insert(finding_id.to_string(), output.clone());
    output
}

fn build_finding_detail_graph_cache(
    result: &crate::analysis::AnalysisResult,
) -> Option<crate::app::FindingDetailGraphCache> {
    let parse_options = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 64 * 1024 * 1024,
        max_objects: 250_000,
        max_objstm_total_bytes: 256 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let Ok(graph) = parse_pdf(&result.bytes, parse_options) else {
        return None;
    };
    let classifications = graph.classify_objects();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&graph, &classifications);
    let event_graph = sis_pdf_core::event_graph::build_event_graph(
        &typed_graph,
        &result.report.findings,
        sis_pdf_core::event_graph::EventGraphOptions::default(),
    );
    Some(crate::app::FindingDetailGraphCache {
        file_name: result.file_name.clone(),
        file_size: result.file_size,
        findings_hash: compute_findings_hash(&result.report.findings),
        event_graph,
        finding_paths: std::collections::HashMap::new(),
    })
}

fn compute_findings_hash(findings: &[sis_pdf_core::model::Finding]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for finding in findings {
        finding.id.hash(&mut hasher);
    }
    findings.len().hash(&mut hasher);
    hasher.finish()
}

fn shortest_path_to_event(graph: &EventGraph, start: &str, max_hops: usize) -> Option<Vec<String>> {
    shortest_path(graph, start, max_hops, true)
}

fn shortest_path_to_outcome(
    graph: &EventGraph,
    start: &str,
    max_hops: usize,
) -> Option<Vec<String>> {
    shortest_path(graph, start, max_hops, false)
}

fn shortest_path(
    graph: &EventGraph,
    start: &str,
    max_hops: usize,
    reverse: bool,
) -> Option<Vec<String>> {
    let mut queue = std::collections::VecDeque::<String>::new();
    let mut visited = std::collections::HashSet::<String>::new();
    let mut parent = std::collections::HashMap::<String, String>::new();
    let mut depth = std::collections::HashMap::<String, usize>::new();

    queue.push_back(start.to_string());
    visited.insert(start.to_string());
    depth.insert(start.to_string(), 0);

    while let Some(node_id) = queue.pop_front() {
        let d = depth.get(&node_id).copied().unwrap_or(0);
        if d >= max_hops {
            continue;
        }
        let edge_indices = if reverse {
            graph.reverse_index.get(&node_id)
        } else {
            graph.forward_index.get(&node_id)
        };
        let Some(indices) = edge_indices else {
            continue;
        };
        for edge_idx in indices {
            let Some(edge) = graph.edges.get(*edge_idx) else {
                continue;
            };
            let next = if reverse { edge.from.clone() } else { edge.to.clone() };
            if !visited.insert(next.clone()) {
                continue;
            }
            parent.insert(next.clone(), node_id.clone());
            depth.insert(next.clone(), d + 1);

            let Some(node_index) = graph.node_index.get(&next) else {
                continue;
            };
            let Some(node) = graph.nodes.get(*node_index) else {
                continue;
            };
            if (reverse && matches!(node.kind, EventNodeKind::Event { .. }))
                || (!reverse && matches!(node.kind, EventNodeKind::Outcome { .. }))
            {
                return Some(reconstruct_path(start, &next, &parent));
            }
            queue.push_back(next);
        }
    }
    None
}

fn reconstruct_path(
    start: &str,
    end: &str,
    parent: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut current = end.to_string();
    let mut path = vec![current.clone()];
    while current != start {
        let Some(prev) = parent.get(&current) else {
            break;
        };
        path.push(prev.clone());
        current = prev.clone();
    }
    path.reverse();
    path
}

fn render_event_path(graph: &EventGraph, path: &[String]) -> String {
    path.iter()
        .map(|node_id| {
            graph
                .node_index
                .get(node_id)
                .and_then(|idx| graph.nodes.get(*idx))
                .map(node_label)
                .unwrap_or_else(|| node_id.clone())
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn node_label(node: &sis_pdf_core::event_graph::EventNode) -> String {
    match &node.kind {
        EventNodeKind::Object { obj, gen, .. } => format!("obj {} {}", obj, gen),
        EventNodeKind::Event { label, .. } => format!("event {}", label),
        EventNodeKind::Outcome { label, target, .. } => {
            if let Some(target) = target {
                format!("outcome {} ({})", label, target)
            } else {
                format!("outcome {}", label)
            }
        }
        EventNodeKind::Collapse { label, .. } => format!("collapse {}", label),
    }
}

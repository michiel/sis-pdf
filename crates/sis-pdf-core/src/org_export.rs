use crate::explainability::GraphPathExplanation;
use crate::org::OrgGraph;
use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge, TypedGraph};
use std::collections::HashSet;

pub fn export_org_json(org: &OrgGraph) -> serde_json::Value {
    // If enhanced data is available, export it
    if let (Some(enhanced_nodes), Some(enhanced_edges)) = (&org.enhanced_nodes, &org.enhanced_edges)
    {
        let nodes: Vec<serde_json::Value> = enhanced_nodes
            .iter()
            .map(|n| {
                serde_json::json!({
                    "id": format!("{} {}", n.obj_ref.obj, n.obj_ref.gen),
                    "obj": n.obj_ref.obj,
                    "gen": n.obj_ref.gen,
                    "type": n.obj_type,
                    "roles": n.roles,
                })
            })
            .collect();

        let edges: Vec<serde_json::Value> = enhanced_edges
            .iter()
            .map(|e| {
                serde_json::json!({
                    "from": format!("{} {}", e.from.obj, e.from.gen),
                    "to": format!("{} {}", e.to.obj, e.to.gen),
                    "type": e.edge_type,
                    "suspicious": e.suspicious,
                })
            })
            .collect();

        return serde_json::json!({
            "nodes": nodes,
            "edges": edges,
            "enhanced": true,
        });
    }

    // Fallback to basic export
    let nodes: Vec<String> = org.nodes.iter().map(|n| format!("{} {}", n.obj, n.gen)).collect();
    let mut edges = Vec::new();
    for (src, targets) in &org.adjacency {
        for t in targets {
            edges.push(serde_json::json!({
                "from": format!("{} {}", src.obj, src.gen),
                "to": format!("{} {}", t.obj, t.gen),
            }));
        }
    }
    serde_json::json!({
        "nodes": nodes,
        "edges": edges,
        "enhanced": false,
    })
}

pub fn export_org_dot(org: &OrgGraph) -> String {
    let mut out = String::new();
    out.push_str("digraph pdf_org {\n");

    // If enhanced data is available, use it
    if let (Some(enhanced_nodes), Some(enhanced_edges)) = (&org.enhanced_nodes, &org.enhanced_edges)
    {
        // Export nodes with type information
        for node in enhanced_nodes {
            let mut label = format!("{} {}", node.obj_ref.obj, node.obj_ref.gen);
            if let Some(obj_type) = &node.obj_type {
                label.push_str(&format!("\\n{}", obj_type));
            }
            if !node.roles.is_empty() {
                label.push_str(&format!("\\n[{}]", node.roles.join(", ")));
            }
            out.push_str(&format!(
                "  \"{} {}\" [label=\"{}\"];\n",
                node.obj_ref.obj, node.obj_ref.gen, label
            ));
        }

        // Export edges with type information
        for edge in enhanced_edges {
            let edge_label = edge.edge_type.as_deref().unwrap_or("ref");
            let style = if edge.suspicious { "color=red, style=bold" } else { "" };
            out.push_str(&format!(
                "  \"{} {}\" -> \"{} {}\" [label=\"{}\" {}];\n",
                edge.from.obj, edge.from.gen, edge.to.obj, edge.to.gen, edge_label, style
            ));
        }
    } else {
        // Fallback to basic export
        for node in &org.nodes {
            out.push_str(&format!("  \"{} {}\";\n", node.obj, node.gen));
        }
        for (src, targets) in &org.adjacency {
            for t in targets {
                out.push_str(&format!(
                    "  \"{} {}\" -> \"{} {}\";\n",
                    src.obj, src.gen, t.obj, t.gen
                ));
            }
        }
    }

    out.push_str("}\n");
    out
}

// ============================================================================
// Enhanced ORG Export with Graph Paths
// ============================================================================

/// ORG export combined with suspicious path analysis
#[derive(Debug, Clone)]
pub struct OrgExportWithPaths {
    /// The object reference graph
    pub org: OrgGraph,
    /// Optional graph path analysis (included when enhanced=true)
    pub paths: Option<GraphPathExplanation>,
}

impl OrgExportWithPaths {
    /// Create a basic export without path analysis
    pub fn basic(org: OrgGraph) -> Self {
        Self { org, paths: None }
    }

    /// Create an enhanced export with path analysis
    pub fn enhanced(org: OrgGraph, paths: GraphPathExplanation) -> Self {
        Self { org, paths: Some(paths) }
    }
}

/// Export ORG with paths to JSON
pub fn export_org_with_paths_json(export: &OrgExportWithPaths) -> serde_json::Value {
    let org_json = export_org_json(&export.org);

    if let Some(paths) = &export.paths {
        let paths_json = serde_json::to_value(paths).unwrap_or(serde_json::json!(null));

        serde_json::json!({
            "org": org_json,
            "suspicious_paths": paths_json,
        })
    } else {
        serde_json::json!({
            "org": org_json,
            "suspicious_paths": null,
        })
    }
}

/// Export ORG with paths to pretty-printed JSON
pub fn export_org_with_paths_json_pretty(export: &OrgExportWithPaths) -> String {
    let value = export_org_with_paths_json(export);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

pub fn export_action_graph_json(typed_graph: &TypedGraph<'_>) -> serde_json::Value {
    let edges = collect_action_edges(typed_graph);
    let mut node_set = HashSet::new();

    let edge_values: Vec<_> = edges
        .iter()
        .map(|info| {
            let from = format!("{} {}", info.edge.src.0, info.edge.src.1);
            let to = format!("{} {}", info.edge.dst.0, info.edge.dst.1);
            node_set.insert(from.clone());
            node_set.insert(to.clone());
            serde_json::json!({
                "from": from,
                "to": to,
                "event": info.label,
                "trigger_type": info.class.as_str(),
                "color": trigger_color(&info.class),
            })
        })
        .collect();

    serde_json::json!({
        "type": "action_graph",
        "nodes": node_set.into_iter().collect::<Vec<_>>(),
        "edges": edge_values,
    })
}

pub fn export_action_graph_dot(typed_graph: &TypedGraph<'_>) -> String {
    let edges = collect_action_edges(typed_graph);
    let mut out = String::new();
    out.push_str("digraph action_graph {\n");

    for info in &edges {
        let from = format!("\"{} {}\"", info.edge.src.0, info.edge.src.1);
        let to = format!("\"{} {}\"", info.edge.dst.0, info.edge.dst.1);
        let label = info.label.replace('"', "\\\"");
        out.push_str(&format!(
            "  {} -> {} [label=\"{}\", color={}, style=bold];\n",
            from,
            to,
            label,
            trigger_color(&info.class)
        ));
    }

    out.push_str("}\n");
    out
}

struct ActionEdgeInfo<'a> {
    edge: &'a TypedEdge,
    label: String,
    class: TriggerClass,
}

fn collect_action_edges<'a>(typed_graph: &'a TypedGraph<'a>) -> Vec<ActionEdgeInfo<'a>> {
    typed_graph.edges.iter().filter_map(classify_action_edge).collect()
}

fn classify_action_edge<'a>(edge: &'a TypedEdge) -> Option<ActionEdgeInfo<'a>> {
    match &edge.edge_type {
        EdgeType::OpenAction => Some(ActionEdgeInfo {
            edge,
            label: "/OpenAction".into(),
            class: TriggerClass::Automatic,
        }),
        EdgeType::PageAction { event } => Some(ActionEdgeInfo {
            edge,
            label: format!("/PageAction {}", event),
            class: if is_automatic_action_event(event) {
                TriggerClass::Automatic
            } else {
                TriggerClass::User
            },
        }),
        EdgeType::AnnotationAction => Some(ActionEdgeInfo {
            edge,
            label: "/AnnotationAction".into(),
            class: TriggerClass::Hidden,
        }),
        EdgeType::AdditionalAction { event } => Some(ActionEdgeInfo {
            edge,
            label: format!("/AA {}", event),
            class: if is_automatic_action_event(event) {
                TriggerClass::Automatic
            } else {
                TriggerClass::User
            },
        }),
        _ => None,
    }
}

fn is_automatic_action_event(event: &str) -> bool {
    matches!(event, "/O" | "/C" | "/PV" | "/PI" | "/V" | "/PO")
}

enum TriggerClass {
    Automatic,
    Hidden,
    User,
}

impl TriggerClass {
    fn as_str(&self) -> &'static str {
        match self {
            TriggerClass::Automatic => "automatic",
            TriggerClass::Hidden => "hidden",
            TriggerClass::User => "user",
        }
    }
}

fn trigger_color(class: &TriggerClass) -> &'static str {
    match class {
        TriggerClass::Automatic => "red",
        TriggerClass::Hidden => "orange",
        TriggerClass::User => "yellow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explainability::{PathNode, SuspiciousPath};
    use sis_pdf_pdf::graph::ObjectGraph;
    use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge, TypedGraph};
    use std::collections::HashMap;

    fn create_empty_org() -> OrgGraph {
        OrgGraph {
            nodes: vec![],
            adjacency: std::collections::HashMap::new(),
            enhanced_nodes: None,
            enhanced_edges: None,
        }
    }

    #[test]
    fn test_org_export_with_paths_basic() {
        let org = create_empty_org();
        let export = OrgExportWithPaths::basic(org);

        assert!(export.paths.is_none());
    }

    #[test]
    fn test_org_export_with_paths_enhanced() {
        let org = create_empty_org();
        let paths = GraphPathExplanation {
            suspicious_paths: vec![SuspiciousPath {
                path: vec![PathNode {
                    obj_ref: (1, 0),
                    node_type: "Catalog".to_string(),
                    edge_to_next: None,
                    findings: vec![],
                }],
                risk_score: 0.5,
                explanation: "Test path".to_string(),
                attack_pattern: None,
            }],
            max_path_risk: 0.5,
            avg_path_risk: 0.5,
        };

        let export = OrgExportWithPaths::enhanced(org, paths);

        let paths = match export.paths.as_ref() {
            Some(value) => value,
            None => panic!("expected enhanced paths"),
        };
        assert_eq!(paths.suspicious_paths.len(), 1);
        assert_eq!(paths.max_path_risk, 0.5);
    }

    #[test]
    fn test_export_org_with_paths_json() {
        let org = create_empty_org();
        let export = OrgExportWithPaths::basic(org);

        let json = export_org_with_paths_json(&export);

        assert!(json.is_object());
        assert!(json.get("org").is_some());
        let suspicious_paths = match json.get("suspicious_paths") {
            Some(value) => value,
            None => panic!("suspicious_paths missing"),
        };
        assert!(suspicious_paths.is_null());
    }

    #[test]
    fn test_export_org_with_paths_json_with_paths() {
        let org = create_empty_org();
        let paths = GraphPathExplanation {
            suspicious_paths: vec![],
            max_path_risk: 0.0,
            avg_path_risk: 0.0,
        };
        let export = OrgExportWithPaths::enhanced(org, paths);

        let json = export_org_with_paths_json(&export);

        assert!(json.is_object());
        assert!(json.get("org").is_some());
        let suspicious_paths = match json.get("suspicious_paths") {
            Some(value) => value,
            None => panic!("suspicious_paths missing"),
        };
        assert!(!suspicious_paths.is_null());
    }

    #[test]
    fn test_export_org_with_paths_json_pretty() {
        let org = create_empty_org();
        let export = OrgExportWithPaths::basic(org);

        let json_str = export_org_with_paths_json_pretty(&export);

        assert!(json_str.contains("org"));
        assert!(json_str.contains("suspicious_paths"));
    }

    #[test]
    fn action_graph_json_exports_edges() {
        let graph = test_object_graph();
        let typed_graph = test_typed_graph(&graph);
        let exported = export_action_graph_json(&typed_graph);
        let edges = exported["edges"].as_array().expect("edges array");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["trigger_type"], "automatic");
        assert_eq!(edges[0]["event"], "/OpenAction");
    }

    #[test]
    fn action_graph_dot_contains_colored_edge() {
        let graph = test_object_graph();
        let typed_graph = test_typed_graph(&graph);
        let dot = export_action_graph_dot(&typed_graph);
        assert!(dot.contains("color=red"));
        assert!(dot.contains("/OpenAction"));
    }

    fn test_object_graph<'a>() -> ObjectGraph<'a> {
        ObjectGraph {
            bytes: &[],
            objects: Vec::new(),
            index: HashMap::new(),
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            deviations: Vec::new(),
        }
    }

    fn test_typed_graph<'a>(graph: &'a ObjectGraph<'a>) -> TypedGraph<'a> {
        let edge = TypedEdge::new_suspicious((1, 0), (2, 0), EdgeType::OpenAction);
        let mut forward_index = HashMap::new();
        forward_index.insert((1, 0), vec![0]);
        let mut reverse_index = HashMap::new();
        reverse_index.insert((2, 0), vec![0]);
        TypedGraph { graph, edges: vec![edge], forward_index, reverse_index }
    }
}

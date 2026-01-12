use std::collections::{BTreeSet, HashMap};

use sis_pdf_pdf::classification::ClassificationMap;
use sis_pdf_pdf::typed_graph::TypedGraph;
use sis_pdf_pdf::ObjectGraph;

use crate::graph_walk::{build_adjacency, ObjRef};

/// Enhanced edge with semantic type information
#[derive(Debug, Clone)]
pub struct OrgEdge {
    pub from: ObjRef,
    pub to: ObjRef,
    pub edge_type: Option<String>,
    pub suspicious: bool,
}

/// Enhanced node with classification information
#[derive(Debug, Clone)]
pub struct OrgNode {
    pub obj_ref: ObjRef,
    pub obj_type: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OrgGraph {
    pub nodes: Vec<ObjRef>,
    pub adjacency: HashMap<ObjRef, Vec<ObjRef>>,
    // Enhanced data (optional for backwards compatibility)
    pub enhanced_nodes: Option<Vec<OrgNode>>,
    pub enhanced_edges: Option<Vec<OrgEdge>>,
}

impl OrgGraph {
    pub fn from_object_graph(graph: &ObjectGraph<'_>) -> Self {
        let mut adjacency = build_adjacency(&graph.objects);
        let mut nodes_set: BTreeSet<ObjRef> = BTreeSet::new();
        for entry in &graph.objects {
            nodes_set.insert(ObjRef {
                obj: entry.obj,
                gen: entry.gen,
            });
        }
        let mut missing = Vec::new();
        for (_src, targets) in adjacency.iter() {
            for t in targets {
                if !nodes_set.contains(t) {
                    missing.push(*t);
                }
            }
        }
        for m in missing {
            nodes_set.insert(m);
            adjacency.entry(m).or_default();
        }
        let nodes: Vec<ObjRef> = nodes_set.into_iter().collect();
        Self {
            nodes,
            adjacency,
            enhanced_nodes: None,
            enhanced_edges: None,
        }
    }

    /// Create enhanced ORG with classifications and typed edges
    pub fn from_object_graph_enhanced(
        graph: &ObjectGraph<'_>,
        classifications: &ClassificationMap,
        typed_graph: &TypedGraph<'_>,
    ) -> Self {
        // Build basic structure
        let mut base = Self::from_object_graph(graph);

        // Build enhanced nodes with classification data
        let mut enhanced_nodes = Vec::new();
        for node in &base.nodes {
            let key = (node.obj, node.gen);
            let (obj_type, roles) = if let Some(classified) = classifications.get(&key) {
                let obj_type_str = format!("{:?}", classified.obj_type);
                let role_strs: Vec<String> = classified
                    .roles
                    .iter()
                    .map(|r| format!("{:?}", r))
                    .collect();
                (Some(obj_type_str), role_strs)
            } else {
                (None, Vec::new())
            };

            enhanced_nodes.push(OrgNode {
                obj_ref: *node,
                obj_type,
                roles,
            });
        }

        // Build enhanced edges with type information
        let mut enhanced_edges = Vec::new();
        for edge in &typed_graph.edges {
            enhanced_edges.push(OrgEdge {
                from: ObjRef {
                    obj: edge.src.0,
                    gen: edge.src.1,
                },
                to: ObjRef {
                    obj: edge.dst.0,
                    gen: edge.dst.1,
                },
                edge_type: Some(edge.edge_type.as_str().to_string()),
                suspicious: edge.suspicious,
            });
        }

        base.enhanced_nodes = Some(enhanced_nodes);
        base.enhanced_edges = Some(enhanced_edges);
        base
    }

    pub fn edge_index(&self) -> Vec<(usize, usize)> {
        let mut index_map: HashMap<ObjRef, usize> = HashMap::new();
        for (i, n) in self.nodes.iter().enumerate() {
            index_map.insert(*n, i);
        }
        let mut edges = Vec::new();
        for (src, targets) in &self.adjacency {
            let Some(&src_idx) = index_map.get(src) else {
                continue;
            };
            for t in targets {
                if let Some(&t_idx) = index_map.get(t) {
                    edges.push((src_idx, t_idx));
                }
            }
        }
        edges
    }
}

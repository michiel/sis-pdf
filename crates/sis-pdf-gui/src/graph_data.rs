use std::collections::HashMap;

use crate::object_data::ObjectData;

/// Maximum nodes the graph will render. Beyond this, return an error
/// prompting the user to filter first.
pub const MAX_GRAPH_NODES: usize = 2000;

/// A directed graph of PDF objects and their references.
#[derive(Debug, Default)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Map from (obj, gen) to node index for fast lookup.
    pub node_index: HashMap<(u32, u16), usize>,
}

/// A node in the object reference graph.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub obj: u32,
    pub gen: u16,
    pub obj_type: String,
    pub roles: Vec<String>,
    pub position: [f64; 2],
}

/// An edge in the object reference graph.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from_idx: usize,
    pub to_idx: usize,
    /// Whether this edge is suspicious (action->stream, roles containing
    /// JsContainer or UriTarget).
    pub suspicious: bool,
}

/// Error returned when the graph cannot be built.
#[derive(Debug, PartialEq)]
pub enum GraphError {
    TooManyNodes { count: usize, limit: usize },
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyNodes { count, limit } => {
                write!(
                    f,
                    "Graph has {} nodes (limit {}). Apply type or depth filters to reduce.",
                    count, limit
                )
            }
        }
    }
}

/// Build a complete graph from all objects in the data set.
pub fn from_object_data(data: &ObjectData) -> Result<GraphData, GraphError> {
    if data.objects.len() > MAX_GRAPH_NODES {
        return Err(GraphError::TooManyNodes {
            count: data.objects.len(),
            limit: MAX_GRAPH_NODES,
        });
    }
    build_graph(data, |_| true)
}

/// Build a graph including only objects matching one of the given types.
pub fn from_object_data_filtered(
    data: &ObjectData,
    types: &[&str],
) -> Result<GraphData, GraphError> {
    build_graph(data, |obj| {
        types.iter().any(|t| obj.obj_type.eq_ignore_ascii_case(t))
    })
}

/// Build a graph via BFS from a centre node up to `max_depth` hops.
pub fn from_object_data_depth(
    data: &ObjectData,
    centre: (u32, u16),
    max_depth: usize,
) -> Result<GraphData, GraphError> {
    // BFS to find reachable nodes within depth
    let mut visited: HashMap<(u32, u16), usize> = HashMap::new(); // key -> depth
    let mut queue = std::collections::VecDeque::new();

    if data.index.contains_key(&centre) {
        visited.insert(centre, 0);
        queue.push_back((centre, 0));
    }

    while let Some((key, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(&idx) = data.index.get(&key) {
            let obj = &data.objects[idx];
            // Follow outgoing references
            for &target in &obj.references_from {
                if !visited.contains_key(&target) && data.index.contains_key(&target) {
                    if visited.len() >= MAX_GRAPH_NODES {
                        return Err(GraphError::TooManyNodes {
                            count: visited.len() + 1,
                            limit: MAX_GRAPH_NODES,
                        });
                    }
                    visited.insert(target, depth + 1);
                    queue.push_back((target, depth + 1));
                }
            }
            // Follow incoming references
            for &source in &obj.references_to {
                if !visited.contains_key(&source) && data.index.contains_key(&source) {
                    if visited.len() >= MAX_GRAPH_NODES {
                        return Err(GraphError::TooManyNodes {
                            count: visited.len() + 1,
                            limit: MAX_GRAPH_NODES,
                        });
                    }
                    visited.insert(source, depth + 1);
                    queue.push_back((source, depth + 1));
                }
            }
        }
    }

    let reachable: std::collections::HashSet<(u32, u16)> = visited.keys().copied().collect();
    build_graph(data, |obj| reachable.contains(&(obj.obj, obj.gen)))
}

/// Internal builder that creates a graph from objects matching a predicate.
fn build_graph(
    data: &ObjectData,
    include: impl Fn(&crate::object_data::ObjectSummary) -> bool,
) -> Result<GraphData, GraphError> {
    let mut nodes = Vec::new();
    let mut node_index = HashMap::new();

    for obj in &data.objects {
        if !include(obj) {
            continue;
        }
        let idx = nodes.len();
        node_index.insert((obj.obj, obj.gen), idx);
        nodes.push(GraphNode {
            obj: obj.obj,
            gen: obj.gen,
            obj_type: obj.obj_type.clone(),
            roles: obj.roles.clone(),
            position: [0.0, 0.0],
        });
    }

    if nodes.len() > MAX_GRAPH_NODES {
        return Err(GraphError::TooManyNodes { count: nodes.len(), limit: MAX_GRAPH_NODES });
    }

    // Build edges from references_from, only between included nodes
    let mut edges = Vec::new();
    for obj in &data.objects {
        let Some(&from_idx) = node_index.get(&(obj.obj, obj.gen)) else {
            continue;
        };
        for &(target_obj, target_gen) in &obj.references_from {
            if let Some(&to_idx) = node_index.get(&(target_obj, target_gen)) {
                let suspicious = is_suspicious_edge(obj, &data.objects[data.index[&(target_obj, target_gen)]]);
                edges.push(GraphEdge { from_idx, to_idx, suspicious });
            }
        }
    }

    Ok(GraphData { nodes, edges, node_index })
}

/// Heuristic: an edge is suspicious if it goes from an action to a stream,
/// or if the source has JsContainer/UriTarget roles.
fn is_suspicious_edge(
    from: &crate::object_data::ObjectSummary,
    to: &crate::object_data::ObjectSummary,
) -> bool {
    let from_is_action = from.obj_type.eq_ignore_ascii_case("action");
    let to_is_stream = to.has_stream;

    if from_is_action && to_is_stream {
        return true;
    }

    let suspicious_roles = ["JsContainer", "UriTarget"];
    for role in &from.roles {
        if suspicious_roles.iter().any(|r| role.contains(r)) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_data::{ObjectData, ObjectSummary};

    fn make_object(obj: u32, gen: u16, obj_type: &str, refs: Vec<(u32, u16)>) -> ObjectSummary {
        ObjectSummary {
            obj,
            gen,
            obj_type: obj_type.to_string(),
            roles: Vec::new(),
            dict_entries: Vec::new(),
            has_stream: false,
            stream_text: None,
            stream_raw: None,
            stream_filters: Vec::new(),
            stream_length: None,
            stream_data_span: None,
            stream_content_type: None,
            image_width: None,
            image_height: None,
            image_bits: None,
            image_color_space: None,
            image_preview: None,
            references_from: refs,
            references_to: Vec::new(),
        }
    }

    fn small_object_data() -> ObjectData {
        let mut objects = vec![
            make_object(1, 0, "catalog", vec![(2, 0), (3, 0)]),
            make_object(2, 0, "page", vec![(4, 0)]),
            make_object(3, 0, "action", vec![(4, 0)]),
            make_object(4, 0, "stream", vec![]),
        ];
        // Build reverse references
        objects[1].references_to = vec![(1, 0)];
        objects[2].references_to = vec![(1, 0)];
        objects[3].references_to = vec![(2, 0), (3, 0)];

        let mut index = HashMap::new();
        for (i, obj) in objects.iter().enumerate() {
            index.insert((obj.obj, obj.gen), i);
        }

        ObjectData { objects, index, xref_sections: Vec::new(), deviations: Vec::new() }
    }

    #[test]
    fn build_from_small_data() {
        let data = small_object_data();
        let graph = from_object_data(&data).expect("should build");
        assert_eq!(graph.nodes.len(), 4);
        // Catalog refs 2 objects, page refs 1, action refs 1
        assert_eq!(graph.edges.len(), 4);
    }

    #[test]
    fn cap_enforcement() {
        let mut objects = Vec::new();
        let mut index = HashMap::new();
        for i in 0..(MAX_GRAPH_NODES + 1) as u32 {
            let obj = make_object(i, 0, "other", vec![]);
            index.insert((i, 0u16), objects.len());
            objects.push(obj);
        }
        let data = ObjectData { objects, index, xref_sections: Vec::new(), deviations: Vec::new() };
        let result = from_object_data(&data);
        assert!(result.is_err());
        match result {
            Err(GraphError::TooManyNodes { count, limit }) => {
                assert_eq!(count, MAX_GRAPH_NODES + 1);
                assert_eq!(limit, MAX_GRAPH_NODES);
            }
            _ => panic!("Expected TooManyNodes"),
        }
    }

    #[test]
    fn filter_by_type() {
        let data = small_object_data();
        let graph = from_object_data_filtered(&data, &["page", "catalog"]).expect("should build");
        assert_eq!(graph.nodes.len(), 2);
        // Only catalog->page edge should be present (both endpoints included)
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn depth_limited_bfs() {
        let data = small_object_data();
        // From catalog (obj 1), depth=1 should include catalog + direct refs (2, 3)
        let graph = from_object_data_depth(&data, (1, 0), 1).expect("should build");
        assert_eq!(graph.nodes.len(), 3);
    }

    #[test]
    fn suspicious_edge_detection() {
        let mut data = small_object_data();
        // Make object 4 (stream) actually have has_stream=true
        data.objects[3].has_stream = true;
        let graph = from_object_data(&data).expect("should build");
        // Edge from action (obj 3) to stream (obj 4) should be suspicious
        let suspicious: Vec<_> = graph.edges.iter().filter(|e| e.suspicious).collect();
        assert!(!suspicious.is_empty(), "Expected at least one suspicious edge");
        // Find the specific edge 3->4
        let action_to_stream = graph.edges.iter().find(|e| {
            graph.nodes[e.from_idx].obj == 3 && graph.nodes[e.to_idx].obj == 4
        });
        assert!(action_to_stream.is_some(), "action->stream edge should exist");
        assert!(action_to_stream.expect("checked").suspicious);
    }

    #[test]
    fn empty_data_builds_empty_graph() {
        let data = ObjectData::default();
        let graph = from_object_data(&data).expect("should build");
        assert_eq!(graph.nodes.len(), 0);
        assert_eq!(graph.edges.len(), 0);
    }
}

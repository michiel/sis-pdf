use crate::graph_data::GraphData;
use std::collections::HashMap;

/// Incremental Fruchterman-Reingold force-directed layout.
pub struct LayoutState {
    /// Layout area width.
    area_w: f64,
    /// Layout area height.
    area_h: f64,
    /// Current temperature (controls step size; decreases over iterations).
    temperature: f64,
    /// Initial temperature.
    initial_temperature: f64,
    /// Maximum number of iterations before the layout is considered done.
    max_iterations: usize,
    /// Iterations completed so far.
    iterations_done: usize,
    /// Ideal edge length (derived from area and node count).
    k: f64,
}

impl LayoutState {
    /// Create a new layout state for a graph with `node_count` nodes.
    pub fn new(node_count: usize) -> Self {
        Self::new_with_min_edge_length(node_count, 0.0)
    }

    /// Create a new layout state with an optional minimum ideal edge length.
    pub fn new_with_min_edge_length(node_count: usize, min_edge_length: f64) -> Self {
        let area_w = 800.0;
        let area_h = 600.0;
        let area = area_w * area_h;
        let k = if node_count > 0 { (area / node_count as f64).sqrt() } else { 1.0 }
            .max(min_edge_length.max(0.0));
        let temperature = area_w / 4.0;
        let max_iterations = 200;

        Self {
            area_w,
            area_h,
            temperature,
            initial_temperature: temperature,
            max_iterations,
            iterations_done: 0,
            k,
        }
    }

    /// Run `iterations` steps of the layout algorithm.
    /// Returns `true` when the layout is finished (all iterations done or
    /// temperature has cooled below threshold).
    pub fn step(&mut self, graph: &mut GraphData, iterations: usize) -> bool {
        let n = graph.nodes.len();
        if n == 0 {
            return true;
        }

        for _ in 0..iterations {
            if self.is_complete() {
                return true;
            }
            self.one_iteration(graph);
        }

        self.is_complete()
    }

    /// Whether the layout is complete.
    pub fn is_complete(&self) -> bool {
        self.iterations_done >= self.max_iterations || self.temperature < 0.5
    }

    /// Number of iterations completed so far.
    pub fn iterations_done(&self) -> usize {
        self.iterations_done
    }

    /// Assign deterministic initial positions (spiral layout).
    pub fn initialise_positions(&self, graph: &mut GraphData) {
        let n = graph.nodes.len();
        if n == 0 {
            return;
        }

        let cx = self.area_w / 2.0;
        let cy = self.area_h / 2.0;

        if n == 1 {
            graph.nodes[0].position = [cx, cy];
            return;
        }

        // Spiral layout: evenly-spaced angular steps with increasing radius
        let max_radius = self.area_w.min(self.area_h) * 0.4;
        for (i, node) in graph.nodes.iter_mut().enumerate() {
            let t = i as f64 / n as f64;
            let angle = t * 6.0 * std::f64::consts::PI; // ~3 full turns
            let radius = max_radius * t;
            node.position = [cx + radius * angle.cos(), cy + radius * angle.sin()];
        }
    }

    /// Run a single iteration of the Fruchterman-Reingold algorithm.
    fn one_iteration(&mut self, graph: &mut GraphData) {
        let n = graph.nodes.len();
        let k = self.k;
        let k_sq = k * k;

        // Displacement accumulator
        let mut disp = vec![[0.0f64; 2]; n];

        // Repulsive forces: O(n^2)
        for i in 0..n {
            for j in (i + 1)..n {
                let dx = graph.nodes[i].position[0] - graph.nodes[j].position[0];
                let dy = graph.nodes[i].position[1] - graph.nodes[j].position[1];
                let dist_sq = dx * dx + dy * dy;
                let dist = dist_sq.sqrt().max(0.01);
                let force = k_sq / dist;
                let fx = (dx / dist) * force;
                let fy = (dy / dist) * force;
                disp[i][0] += fx;
                disp[i][1] += fy;
                disp[j][0] -= fx;
                disp[j][1] -= fy;
            }
        }

        // Attractive forces along edges
        for edge in &graph.edges {
            let dx = graph.nodes[edge.from_idx].position[0] - graph.nodes[edge.to_idx].position[0];
            let dy = graph.nodes[edge.from_idx].position[1] - graph.nodes[edge.to_idx].position[1];
            let dist = (dx * dx + dy * dy).sqrt().max(0.01);
            let force = dist * dist / k;
            let fx = (dx / dist) * force;
            let fy = (dy / dist) * force;
            disp[edge.from_idx][0] -= fx;
            disp[edge.from_idx][1] -= fy;
            disp[edge.to_idx][0] += fx;
            disp[edge.to_idx][1] += fy;
        }

        // Apply displacements, limited by temperature
        for (i, node) in graph.nodes.iter_mut().enumerate() {
            let dx = disp[i][0];
            let dy = disp[i][1];
            let dist = (dx * dx + dy * dy).sqrt().max(0.01);
            let scale = self.temperature.min(dist) / dist;
            node.position[0] += dx * scale;
            node.position[1] += dy * scale;
        }

        // Cool down
        self.iterations_done += 1;
        let progress = self.iterations_done as f64 / self.max_iterations as f64;
        self.temperature = self.initial_temperature * (1.0 - progress);
    }
}

/// Assign nodes to stage columns for staged DAG rendering.
pub fn stage_column(node: &crate::graph_data::GraphNode) -> usize {
    for role in &node.roles {
        match role.as_str() {
            "input" => return 0,
            "decode" => return 1,
            "render" => return 2,
            "execute" => return 3,
            "egress" => return 4,
            _ => {}
        }
    }
    let label_lower = node.label.to_lowercase();
    if label_lower.contains("network") || label_lower.contains("egress") {
        return 4;
    }
    if label_lower.contains("execute") || label_lower.contains("code") {
        return 3;
    }
    if node.obj_type.eq_ignore_ascii_case("event")
        && node.roles.iter().any(|role| matches!(role.as_str(), "automatic" | "hidden"))
    {
        return 0;
    }
    if node.obj_type.eq_ignore_ascii_case("outcome") {
        return 4;
    }
    2
}

/// Apply staged DAG layout positions directly.
pub fn apply_staged_dag_layout(graph: &mut GraphData) {
    let area_w = 800.0f64;
    let area_h = 600.0f64;
    let cols = 5.0f64;
    let col_w = area_w / cols;
    let mut by_column: HashMap<usize, Vec<usize>> = HashMap::new();
    for (idx, node) in graph.nodes.iter().enumerate() {
        by_column.entry(stage_column(node)).or_default().push(idx);
    }
    for column in 0..5 {
        let Some(indices) = by_column.get(&column) else {
            continue;
        };
        let count = indices.len();
        for (row, idx) in indices.iter().enumerate() {
            let x = (column as f64 + 0.5) * col_w;
            let y = if count <= 1 {
                area_h / 2.0
            } else {
                ((row + 1) as f64 / (count + 1) as f64) * area_h
            };
            graph.nodes[*idx].position = [x, y];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_data::{GraphData, GraphEdge, GraphNode};
    use std::collections::HashMap;

    fn simple_graph() -> GraphData {
        let nodes = vec![
            GraphNode {
                object_ref: Some((1, 0)),
                obj_type: "catalog".to_string(),
                label: "1 0".to_string(),
                roles: vec![],
                confidence: None,
                position: [0.0, 0.0],
            },
            GraphNode {
                object_ref: Some((2, 0)),
                obj_type: "page".to_string(),
                label: "2 0".to_string(),
                roles: vec![],
                confidence: None,
                position: [0.0, 0.0],
            },
            GraphNode {
                object_ref: Some((3, 0)),
                obj_type: "action".to_string(),
                label: "3 0".to_string(),
                roles: vec![],
                confidence: None,
                position: [0.0, 0.0],
            },
        ];
        let edges = vec![
            GraphEdge {
                from_idx: 0,
                to_idx: 1,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
            GraphEdge {
                from_idx: 0,
                to_idx: 2,
                suspicious: false,
                edge_kind: None,
                provenance: None,
                metadata: None,
            },
        ];
        let mut node_index = HashMap::new();
        for (i, n) in nodes.iter().enumerate() {
            if let Some((obj, gen)) = n.object_ref {
                node_index.insert((obj, gen), i);
            }
        }
        GraphData { nodes, edges, node_index }
    }

    #[test]
    fn layout_converges() {
        let mut graph = simple_graph();
        let mut layout = LayoutState::new(graph.nodes.len());
        layout.initialise_positions(&mut graph);

        // Run all iterations
        let done = layout.step(&mut graph, 300);
        assert!(done);
        assert!(layout.is_complete());
    }

    #[test]
    fn positions_are_finite_after_layout() {
        let mut graph = simple_graph();
        let mut layout = LayoutState::new(graph.nodes.len());
        layout.initialise_positions(&mut graph);
        layout.step(&mut graph, 200);

        for node in &graph.nodes {
            assert!(node.position[0].is_finite(), "x not finite for node {}", node.label);
            assert!(node.position[1].is_finite(), "y not finite for node {}", node.label);
        }
    }

    #[test]
    fn initial_positions_are_spread() {
        let mut graph = simple_graph();
        let layout = LayoutState::new(graph.nodes.len());
        layout.initialise_positions(&mut graph);

        // All positions should be different
        let positions: Vec<[f64; 2]> = graph.nodes.iter().map(|n| n.position).collect();
        for i in 0..positions.len() {
            for j in (i + 1)..positions.len() {
                let dx = positions[i][0] - positions[j][0];
                let dy = positions[i][1] - positions[j][1];
                let dist = (dx * dx + dy * dy).sqrt();
                assert!(dist > 1.0, "nodes {} and {} too close: {}", i, j, dist);
            }
        }
    }

    #[test]
    fn empty_graph_completes_immediately() {
        let mut graph = GraphData::default();
        let mut layout = LayoutState::new(0);
        layout.initialise_positions(&mut graph);
        assert!(layout.step(&mut graph, 1));
    }

    #[test]
    fn single_node_centred() {
        let nodes = vec![GraphNode {
            object_ref: Some((1, 0)),
            obj_type: "catalog".to_string(),
            label: "1 0".to_string(),
            roles: vec![],
            confidence: None,
            position: [0.0, 0.0],
        }];
        let mut node_index = HashMap::new();
        node_index.insert((1, 0), 0);
        let mut graph = GraphData { nodes, edges: vec![], node_index };
        let layout = LayoutState::new(1);
        layout.initialise_positions(&mut graph);
        assert!((graph.nodes[0].position[0] - 400.0).abs() < 0.01);
        assert!((graph.nodes[0].position[1] - 300.0).abs() < 0.01);
    }

    #[test]
    fn incremental_step_progresses() {
        let mut graph = simple_graph();
        let mut layout = LayoutState::new(graph.nodes.len());
        layout.initialise_positions(&mut graph);

        // Run 5 iterations
        let done = layout.step(&mut graph, 5);
        assert!(!done);
        assert_eq!(layout.iterations_done(), 5);

        // Run 5 more
        layout.step(&mut graph, 5);
        assert_eq!(layout.iterations_done(), 10);
    }

    #[test]
    fn step_does_not_force_positions_into_fixed_rectangle() {
        let nodes = vec![GraphNode {
            object_ref: Some((42, 0)),
            obj_type: "other".to_string(),
            label: "42 0".to_string(),
            roles: vec![],
            confidence: None,
            position: [5_000.0, -200.0],
        }];
        let mut node_index = HashMap::new();
        node_index.insert((42, 0), 0);
        let mut graph = GraphData { nodes, edges: vec![], node_index };

        let mut layout = LayoutState::new(graph.nodes.len());
        layout.step(&mut graph, 1);

        assert_eq!(graph.nodes[0].position[0], 5_000.0);
        assert_eq!(graph.nodes[0].position[1], -200.0);
    }

    #[test]
    fn minimum_edge_length_overrides_small_ideal_length() {
        let layout = LayoutState::new_with_min_edge_length(2_000, 120.0);
        assert!(layout.k >= 120.0);
    }

    #[test]
    fn staged_layout_places_automatic_events_left_and_outcomes_right() {
        let mut graph = simple_graph();
        graph.nodes[0].obj_type = "event".into();
        graph.nodes[0].roles = vec!["automatic".into()];
        graph.nodes[2].obj_type = "outcome".into();
        graph.nodes[2].label = "Network egress".into();
        apply_staged_dag_layout(&mut graph);
        assert!(graph.nodes[0].position[0] < graph.nodes[1].position[0]);
        assert!(graph.nodes[2].position[0] > graph.nodes[1].position[0]);
    }
}

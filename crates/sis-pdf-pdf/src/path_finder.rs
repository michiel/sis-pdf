/// Path finding and chain analysis for PDF reference graphs
///
/// This module provides utilities for finding paths, detecting action chains,
/// and propagating risk scores through the PDF object graph.
use crate::typed_graph::{EdgeType, TypedEdge, TypedGraph};
use std::collections::{HashMap, HashSet, VecDeque};

/// Trigger type for action chains
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerType {
    /// Document /OpenAction
    OpenAction,
    /// Page open event
    PageOpen,
    /// Page close event
    PageClose,
    /// Annotation click
    Annotation,
    /// Form field event
    FormField,
    /// Other trigger
    Other,
}

impl TriggerType {
    /// Returns true if this trigger is automatic (no user action required)
    pub fn is_automatic(&self) -> bool {
        matches!(
            self,
            TriggerType::OpenAction | TriggerType::PageOpen | TriggerType::PageClose
        )
    }

    /// Returns string representation
    pub fn as_str(&self) -> &str {
        match self {
            TriggerType::OpenAction => "open_action",
            TriggerType::PageOpen => "page_open",
            TriggerType::PageClose => "page_close",
            TriggerType::Annotation => "annotation",
            TriggerType::FormField => "form_field",
            TriggerType::Other => "other",
        }
    }
}

/// An action chain in the PDF
#[derive(Debug, Clone)]
pub struct ActionChain<'a> {
    /// Trigger type that initiates the chain
    pub trigger: TriggerType,
    /// Edges in the chain
    pub edges: Vec<&'a TypedEdge>,
    /// Final payload object (if any)
    pub payload: Option<(u32, u16)>,
    /// Is this trigger automatic?
    pub automatic: bool,
    /// Does this chain involve JavaScript?
    pub involves_js: bool,
    /// Does this chain involve external actions (URI, Launch, etc.)?
    pub involves_external: bool,
}

impl<'a> ActionChain<'a> {
    /// Returns the chain length (number of edges)
    pub fn length(&self) -> usize {
        self.edges.len()
    }

    /// Returns true if this is a multi-stage chain (length > 2)
    pub fn is_multi_stage(&self) -> bool {
        self.edges.len() > 2
    }

    /// Calculates a risk score for this chain
    pub fn risk_score(&self) -> f32 {
        let mut score = 0.0;

        // Automatic triggers are riskier
        if self.automatic {
            score += 0.3;
        }

        // JavaScript involvement
        if self.involves_js {
            score += 0.4;
        }

        // External actions
        if self.involves_external {
            score += 0.3;
        }

        // Multi-stage chains are more suspicious
        if self.is_multi_stage() {
            score += 0.2;
        }

        // Suspicious edges
        let suspicious_count = self.edges.iter().filter(|e| e.suspicious).count();
        score += (suspicious_count as f32 / self.edges.len() as f32) * 0.5;

        score.min(1.0)
    }
}

/// Path finder for PDF object graphs
pub struct PathFinder<'a> {
    graph: &'a TypedGraph<'a>,
}

impl<'a> PathFinder<'a> {
    /// Creates a new path finder
    pub fn new(graph: &'a TypedGraph<'a>) -> Self {
        Self { graph }
    }

    /// Finds all paths from source to destination (up to max_depth)
    pub fn find_paths(
        &self,
        from: (u32, u16),
        to: (u32, u16),
        max_depth: usize,
    ) -> Vec<Vec<&'a TypedEdge>> {
        let mut paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited = HashSet::new();

        self.dfs_paths(
            from,
            to,
            max_depth,
            &mut current_path,
            &mut visited,
            &mut paths,
        );

        paths
    }

    /// DFS helper for path finding
    fn dfs_paths(
        &self,
        current: (u32, u16),
        target: (u32, u16),
        depth_remaining: usize,
        current_path: &mut Vec<&'a TypedEdge>,
        visited: &mut HashSet<(u32, u16)>,
        paths: &mut Vec<Vec<&'a TypedEdge>>,
    ) {
        if depth_remaining == 0 {
            return;
        }

        if current == target && !current_path.is_empty() {
            paths.push(current_path.clone());
            return;
        }

        visited.insert(current);

        for edge in self.graph.outgoing_edges(current.0, current.1) {
            if !visited.contains(&edge.dst) {
                current_path.push(edge);
                self.dfs_paths(
                    edge.dst,
                    target,
                    depth_remaining - 1,
                    current_path,
                    visited,
                    paths,
                );
                current_path.pop();
            }
        }

        visited.remove(&current);
    }

    /// Finds all objects reachable from a source via specific edge types
    pub fn find_reachable_with_types(
        &self,
        from: (u32, u16),
        edge_types: &[EdgeType],
        max_depth: usize,
    ) -> HashSet<(u32, u16)> {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back((from, 0));
        visited.insert(from);

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in self.graph.outgoing_edges(current.0, current.1) {
                if edge_types.iter().any(|et| et == &edge.edge_type)
                    && !visited.contains(&edge.dst) {
                        visited.insert(edge.dst);
                        reachable.insert(edge.dst);
                        queue.push_back((edge.dst, depth + 1));
                    }
            }
        }

        reachable
    }

    /// Finds all JavaScript source objects (objects that can trigger JS)
    pub fn find_javascript_sources(&self) -> Vec<(u32, u16)> {
        let mut sources = Vec::new();

        // Find all edges that lead to JavaScript
        for edge in &self.graph.edges {
            if matches!(
                edge.edge_type,
                EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames
            ) {
                sources.push(edge.src);
            }
        }

        // Deduplicate
        sources.sort();
        sources.dedup();

        sources
    }

    /// Finds all action chains in the document
    pub fn find_all_action_chains(&self) -> Vec<ActionChain<'a>> {
        let mut chains = Vec::new();

        // Find OpenAction chains
        for edge in &self.graph.edges {
            if edge.edge_type == EdgeType::OpenAction {
                if let Some(chain) = self.build_action_chain(edge, TriggerType::OpenAction) {
                    chains.push(chain);
                }
            }
        }

        // Find PageAction chains
        for edge in &self.graph.edges {
            if matches!(edge.edge_type, EdgeType::PageAction { .. }) {
                let trigger = if let EdgeType::PageAction { event } = &edge.edge_type {
                    if event == "/O" {
                        TriggerType::PageOpen
                    } else if event == "/C" {
                        TriggerType::PageClose
                    } else {
                        TriggerType::Other
                    }
                } else {
                    TriggerType::Other
                };

                if let Some(chain) = self.build_action_chain(edge, trigger) {
                    chains.push(chain);
                }
            }
        }

        // Find AnnotationAction chains
        for edge in &self.graph.edges {
            if edge.edge_type == EdgeType::AnnotationAction {
                if let Some(chain) = self.build_action_chain(edge, TriggerType::Annotation) {
                    chains.push(chain);
                }
            }
        }

        chains
    }

    /// Builds an action chain starting from a trigger edge
    fn build_action_chain(
        &self,
        trigger_edge: &'a TypedEdge,
        trigger_type: TriggerType,
    ) -> Option<ActionChain<'a>> {
        let mut edges = vec![trigger_edge];
        let mut current = trigger_edge.dst;
        let mut visited = HashSet::new();
        visited.insert(trigger_edge.src);
        visited.insert(trigger_edge.dst);

        // Follow the chain
        const MAX_CHAIN_LENGTH: usize = 10;
        while edges.len() < MAX_CHAIN_LENGTH {
            let outgoing = self.graph.outgoing_edges(current.0, current.1);

            // Find next action edge
            let next_edge = outgoing.iter().find(|e| {
                !visited.contains(&e.dst)
                    && (e.edge_type.is_executable()
                        || matches!(
                            e.edge_type,
                            EdgeType::JavaScriptPayload
                                | EdgeType::UriTarget
                                | EdgeType::LaunchTarget
                        ))
            });

            if let Some(edge) = next_edge {
                edges.push(*edge);
                visited.insert(edge.dst);
                current = edge.dst;
            } else {
                break;
            }
        }

        // Analyze chain characteristics
        let automatic = trigger_type.is_automatic();
        let involves_js = edges.iter().any(|e| {
            matches!(
                e.edge_type,
                EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames
            )
        });
        let involves_external = edges.iter().any(|e| {
            matches!(
                e.edge_type,
                EdgeType::UriTarget
                    | EdgeType::LaunchTarget
                    | EdgeType::SubmitFormTarget
                    | EdgeType::GoToRTarget
            )
        });

        let payload = Some(current);

        Some(ActionChain {
            trigger: trigger_type,
            edges,
            payload,
            automatic,
            involves_js,
            involves_external,
        })
    }

    /// Checks if an object is reachable from the catalog
    pub fn is_reachable_from_catalog(&self, target: (u32, u16)) -> bool {
        // Find catalog object (usually 1 0)
        let catalog = (1, 0); // Common case
        self.is_reachable_bfs(catalog, target, 20)
    }

    /// BFS reachability check
    fn is_reachable_bfs(&self, from: (u32, u16), to: (u32, u16), max_depth: usize) -> bool {
        if from == to {
            return true;
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back((from, 0));
        visited.insert(from);

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in self.graph.outgoing_edges(current.0, current.1) {
                if edge.dst == to {
                    return true;
                }

                if !visited.contains(&edge.dst) {
                    visited.insert(edge.dst);
                    queue.push_back((edge.dst, depth + 1));
                }
            }
        }

        false
    }

    /// Calculates depth from catalog for all reachable objects
    pub fn catalog_depths(&self) -> HashMap<(u32, u16), usize> {
        let catalog = (1, 0);
        let mut depths = HashMap::new();
        let mut queue = VecDeque::new();

        queue.push_back((catalog, 0));
        depths.insert(catalog, 0);

        while let Some((current, depth)) = queue.pop_front() {
            for edge in self.graph.outgoing_edges(current.0, current.1) {
                if let std::collections::hash_map::Entry::Vacant(e) = depths.entry(edge.dst) {
                    e.insert(depth + 1);
                    queue.push_back((edge.dst, depth + 1));
                }
            }
        }

        depths
    }

    /// Propagates suspiciousness scores through the graph
    pub fn propagate_suspiciousness(&self) -> HashMap<(u32, u16), f32> {
        let mut scores = HashMap::new();

        // Initialize with suspicious edges
        for edge in &self.graph.edges {
            if edge.suspicious {
                *scores.entry(edge.src).or_insert(0.0) += 0.3;
                *scores.entry(edge.dst).or_insert(0.0) += 0.5;
            }
        }

        // Propagate through edges (multiple iterations)
        for _ in 0..3 {
            let mut new_scores = scores.clone();

            for edge in &self.graph.edges {
                if let Some(&src_score) = scores.get(&edge.src) {
                    if src_score > 0.1 {
                        let propagated = src_score * 0.7;
                        let dst_score = new_scores.entry(edge.dst).or_insert(0.0);
                        *dst_score = f32::max(*dst_score, propagated);
                    }
                }
            }

            scores = new_scores;
        }

        // Normalize to 0-1 range
        if let Some(&max_score) = scores
            .values()
            .filter(|score| score.is_finite())
            .max_by(|a, b| a.total_cmp(b))
        {
            if max_score > 1.0 {
                for score in scores.values_mut() {
                    *score /= max_score;
                }
            }
        }

        scores
    }

    /// Finds all objects with incoming suspicious edges
    pub fn find_suspicious_targets(&self) -> Vec<(u32, u16)> {
        let mut targets = HashSet::new();

        for edge in self.graph.suspicious_edges() {
            targets.insert(edge.dst);
        }

        targets.into_iter().collect()
    }

    /// Finds all cycles in the graph (potential infinite loops)
    pub fn find_cycles(&self, max_cycle_length: usize) -> Vec<Vec<&'a TypedEdge>> {
        let mut cycles = Vec::new();
        let mut visited_global = HashSet::new();

        for edge in &self.graph.edges {
            if !visited_global.contains(&edge.src) {
                let mut path = Vec::new();
                let mut visited_path = HashSet::new();
                self.find_cycles_dfs(
                    edge.src,
                    &mut path,
                    &mut visited_path,
                    &mut visited_global,
                    &mut cycles,
                    max_cycle_length,
                );
            }
        }

        cycles
    }

    fn find_cycles_dfs(
        &self,
        current: (u32, u16),
        path: &mut Vec<&'a TypedEdge>,
        visited_path: &mut HashSet<(u32, u16)>,
        visited_global: &mut HashSet<(u32, u16)>,
        cycles: &mut Vec<Vec<&'a TypedEdge>>,
        max_length: usize,
    ) {
        if path.len() >= max_length {
            return;
        }

        visited_path.insert(current);
        visited_global.insert(current);

        for edge in self.graph.outgoing_edges(current.0, current.1) {
            if visited_path.contains(&edge.dst) {
                // Found a cycle
                if let Some(cycle_start) = path.iter().position(|e| e.dst == edge.dst) {
                    let mut cycle = path[cycle_start..].to_vec();
                    cycle.push(edge);
                    cycles.push(cycle);
                }
            } else {
                path.push(edge);
                self.find_cycles_dfs(
                    edge.dst,
                    path,
                    visited_path,
                    visited_global,
                    cycles,
                    max_length,
                );
                path.pop();
            }
        }

        visited_path.remove(&current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trigger_type() {
        assert!(TriggerType::OpenAction.is_automatic());
        assert!(TriggerType::PageOpen.is_automatic());
        assert!(!TriggerType::Annotation.is_automatic());

        assert_eq!(TriggerType::OpenAction.as_str(), "open_action");
    }

    #[test]
    fn test_action_chain_risk_score() {
        // Mock chain (we'll create a simple one for testing)
        let chain = ActionChain {
            trigger: TriggerType::OpenAction,
            edges: Vec::new(),
            payload: Some((5, 0)),
            automatic: true,
            involves_js: true,
            involves_external: false,
        };

        let score = chain.risk_score();
        assert!(score > 0.5); // Automatic + JS should be high risk
    }
}

use crate::analysis::AnalysisResult;
use crate::annotations::AnnotationStore;
use crate::app::{
    ChainSortColumn, HexViewState, ImagePreviewDialogState, SeverityFilters, SortState,
};
use crate::panels::graph::GraphViewerState;
use crate::query::QueryOutput;
use std::path::PathBuf;

/// Maximum number of open tabs: 5 on native, 3 on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub const MAX_TABS: usize = 5;
#[cfg(target_arch = "wasm32")]
pub const MAX_TABS: usize = 3;

/// Per-tab workspace state, stored when the tab is not active.
pub struct WorkspaceContext {
    pub result: AnalysisResult,
    pub selected_finding: Option<usize>,
    pub show_findings: bool,
    pub show_chains: bool,
    pub show_metadata: bool,
    pub show_revision: bool,
    pub show_objects: bool,
    pub show_events: bool,
    pub show_image_preview: bool,
    pub show_hex: bool,
    pub selected_object: Option<(u32, u16)>,
    pub selected_event: Option<usize>,
    pub image_preview_state: ImagePreviewDialogState,
    pub object_type_filter: Option<String>,
    pub object_nav_stack: Vec<(u32, u16)>,
    pub object_nav_pos: usize,
    pub object_search: String,
    pub show_stream_hex: bool,
    pub hex_view: HexViewState,
    pub severity_filters: SeverityFilters,
    pub sort: SortState,
    pub findings_search: String,
    pub surface_filter: Option<String>,
    pub min_confidence: u8,
    pub has_cve_filter: bool,
    pub auto_triggered_filter: bool,
    pub chain_sort_column: ChainSortColumn,
    pub chain_sort_ascending: bool,
    pub command_history_pos: Option<usize>,
    pub show_command_bar: bool,
    pub command_input: String,
    pub command_history: Vec<String>,
    pub command_results: Vec<QueryOutput>,
    pub tab_name: String,
    pub show_graph: bool,
    pub graph_state: GraphViewerState,
    pub selected_chain: Option<usize>,
    pub include_singleton_chains: bool,
    pub active_file_path: Option<PathBuf>,
    pub annotations: AnnotationStore,
    pub annotation_edit_finding: Option<String>,
}

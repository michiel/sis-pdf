use crate::analysis::AnalysisResult;
use crate::app::{HexViewState, SeverityFilters, SortState};
use crate::query::QueryOutput;

/// Maximum number of open tabs.
pub const MAX_TABS: usize = 3;

/// Per-tab workspace state, stored when the tab is not active.
pub struct WorkspaceContext {
    pub result: AnalysisResult,
    pub selected_finding: Option<usize>,
    pub show_chains: bool,
    pub show_metadata: bool,
    pub show_objects: bool,
    pub show_hex: bool,
    pub selected_object: Option<(u32, u16)>,
    pub object_type_filter: Option<String>,
    pub object_nav_stack: Vec<(u32, u16)>,
    pub object_nav_pos: usize,
    pub object_search: String,
    pub show_stream_hex: bool,
    pub hex_view: HexViewState,
    pub severity_filters: SeverityFilters,
    pub sort: SortState,
    pub show_command_bar: bool,
    pub command_input: String,
    pub command_history: Vec<String>,
    pub command_results: Vec<QueryOutput>,
    pub tab_name: String,
}

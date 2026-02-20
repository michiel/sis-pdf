use std::collections::HashMap;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExploitChain {
    pub id: String,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub group_count: usize,
    #[serde(default)]
    pub group_members: Vec<String>,
    pub trigger: Option<String>,
    pub action: Option<String>,
    pub payload: Option<String>,
    pub findings: Vec<String>,
    pub score: f64,
    pub reasons: Vec<String>,
    pub path: String,
    #[serde(default)]
    pub nodes: Vec<String>,
    #[serde(default)]
    pub edges: Vec<String>,
    #[serde(default)]
    pub confirmed_stages: Vec<String>,
    #[serde(default)]
    pub inferred_stages: Vec<String>,
    #[serde(default)]
    pub chain_completeness: f64,
    #[serde(default)]
    pub reader_risk: HashMap<String, String>,
    #[serde(default)]
    pub narrative: String,
    #[serde(default)]
    pub finding_criticality: HashMap<String, f64>,
    #[serde(default)]
    pub active_mitigations: Vec<String>,
    #[serde(default)]
    pub required_conditions: Vec<String>,
    #[serde(default)]
    pub unmet_conditions: Vec<String>,
    pub notes: HashMap<String, String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainTemplate {
    pub id: String,
    pub trigger: Option<String>,
    pub action: Option<String>,
    pub payload: Option<String>,
    pub instances: Vec<String>,
}

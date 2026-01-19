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

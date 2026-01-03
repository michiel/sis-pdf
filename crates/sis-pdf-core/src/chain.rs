use std::collections::HashMap;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExploitChain {
    pub id: String,
    pub trigger: Option<String>,
    pub action: Option<String>,
    pub payload: Option<String>,
    pub findings: Vec<String>,
    pub score: f64,
    pub reasons: Vec<String>,
    pub path: String,
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

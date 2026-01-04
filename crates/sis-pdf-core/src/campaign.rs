use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkIntent {
    pub url: String,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PDFAnalysis {
    pub id: String,
    pub path: Option<String>,
    pub network_intents: Vec<NetworkIntent>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Campaign {
    pub id: String,
    pub domains: Vec<String>,
    pub pdfs: Vec<String>,
}

pub struct MultiStageCorrelator;

impl MultiStageCorrelator {
    pub fn correlate_campaign(&self, pdfs: &[PDFAnalysis]) -> Vec<Campaign> {
        let mut by_domain: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for pdf in pdfs {
            let pid = pdf.path.clone().unwrap_or_else(|| pdf.id.clone());
            for intent in &pdf.network_intents {
                if let Some(domain) = &intent.domain {
                    by_domain.entry(domain.clone()).or_default().insert(pid.clone());
                }
            }
        }
        let mut campaigns = Vec::new();
        for (domain, pdfs) in by_domain {
            if pdfs.len() < 2 {
                continue;
            }
            campaigns.push(Campaign {
                id: format!("campaign:{}", domain),
                domains: vec![domain],
                pdfs: pdfs.into_iter().collect(),
            });
        }
        campaigns
    }

    pub fn detect_c2_infrastructure(&self, intents: &[NetworkIntent]) -> Vec<String> {
        let mut out = Vec::new();
        for intent in intents {
            if let Some(domain) = &intent.domain {
                if domain.contains(".onion") || domain.contains("pastebin") {
                    out.push(domain.clone());
                }
            }
        }
        out
    }
}

pub fn extract_domain(url: &str) -> Option<String> {
    let url = url.trim();
    let url = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://")).unwrap_or(url);
    let mut end = url.len();
    for (idx, ch) in url.char_indices() {
        if ch == '/' || ch == ':' {
            end = idx;
            break;
        }
    }
    if end == 0 {
        return None;
    }
    Some(url[..end].to_string())
}

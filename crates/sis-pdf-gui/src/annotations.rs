use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TriageState {
    Pending,
    Confirmed,
    FalsePositive,
    Mitigated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub finding_id: String,
    pub note: String,
    pub triage_state: TriageState,
    pub timestamp_unix: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnnotationStore {
    pub document_sha256: String,
    pub annotations: HashMap<String, Annotation>,
}

impl AnnotationStore {
    pub fn sidecar_path(pdf_path: &Path) -> PathBuf {
        let base = pdf_path.to_string_lossy();
        PathBuf::from(format!("{base}.sis-notes.json"))
    }

    pub fn load(pdf_path: &Path) -> Self {
        let sidecar = Self::sidecar_path(pdf_path);
        let Ok(data) = std::fs::read_to_string(&sidecar) else {
            return Self::default();
        };
        serde_json::from_str(&data).unwrap_or_default()
    }

    pub fn save(&self, pdf_path: &Path) -> std::io::Result<()> {
        let sidecar = Self::sidecar_path(pdf_path);
        let json = serde_json::to_vec_pretty(self)
            .map_err(|err| std::io::Error::other(format!("serialise annotations: {err}")))?;
        std::fs::write(sidecar, json)
    }

    pub fn upsert(&mut self, annotation: Annotation) {
        self.annotations.insert(annotation.finding_id.clone(), annotation);
    }

    pub fn remove(&mut self, finding_id: &str) {
        self.annotations.remove(finding_id);
    }

    pub fn get(&self, finding_id: &str) -> Option<&Annotation> {
        self.annotations.get(finding_id)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{digest:x}")
}

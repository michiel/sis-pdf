use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{warn, Level};

use crate::report::Report;
use crate::features::FeatureVector;
use crate::security_log::{SecurityDomain, SecurityEvent};

const CACHE_VERSION: u32 = 1;
const MAX_CACHE_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct CacheEntry<'a> {
    version: u32,
    file_hash: String,
    report: &'a Report,
}

#[derive(Debug, Deserialize)]
struct CacheEntryOwned {
    version: u32,
    file_hash: String,
    report: Report,
}

#[derive(Debug, Serialize)]
struct FeatureEntry<'a> {
    version: u32,
    file_hash: String,
    features: &'a FeatureVector,
}

#[derive(Debug, Deserialize)]
struct FeatureEntryOwned {
    version: u32,
    file_hash: String,
    features: FeatureVector,
}

pub trait AnalysisCache {
    fn load_report(&self, hash: &str) -> Option<Report>;
    fn store_report(&self, hash: &str, report: &Report) -> Result<()>;
    fn load_features(&self, hash: &str) -> Option<FeatureVector>;
    fn store_features(&self, hash: &str, features: &FeatureVector) -> Result<()>;
}

#[derive(Debug)]
pub struct ScanCache {
    dir: PathBuf,
}

impl ScanCache {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn load(&self, hash: &str) -> Option<Report> {
        let safe_hash = sanitize_hash(hash)?;
        let path = self.path_for(&safe_hash);
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() > MAX_CACHE_BYTES {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Cache,
                    severity: crate::model::Severity::Low,
                    kind: "cache_entry_too_large",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Cache entry too large",
                }
                .emit();
                warn!(bytes = meta.len(), "Cache entry too large");
                return None;
            }
        }
        let data = fs::read(path).ok()?;
        let entry: CacheEntryOwned = serde_json::from_slice(&data).ok()?;
        if entry.version != CACHE_VERSION {
            return None;
        }
        if entry.file_hash != safe_hash {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Cache,
                severity: crate::model::Severity::Low,
                kind: "cache_hash_mismatch",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Cache hash mismatch",
            }
            .emit();
            warn!(
                requested = %safe_hash,
                cached = %entry.file_hash,
                "Cache hash mismatch"
            );
            return None;
        }
        Some(entry.report)
    }

    pub fn store(&self, hash: &str, report: &Report) -> Result<()> {
        let safe_hash = sanitize_hash(hash)
            .ok_or_else(|| anyhow::anyhow!("invalid cache hash"))?;
        let path = self.path_for(&safe_hash);
        let entry = CacheEntry {
            version: CACHE_VERSION,
            file_hash: safe_hash,
            report,
        };
        let data = serde_json::to_vec(&entry)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn load_features(&self, hash: &str) -> Option<FeatureVector> {
        let safe_hash = sanitize_hash(hash)?;
        let path = self.feature_path_for(&safe_hash);
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() > MAX_CACHE_BYTES {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Cache,
                    severity: crate::model::Severity::Low,
                    kind: "cache_feature_entry_too_large",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Cache feature entry too large",
                }
                .emit();
                warn!(bytes = meta.len(), "Cache feature entry too large");
                return None;
            }
        }
        let data = fs::read(path).ok()?;
        let entry: FeatureEntryOwned = serde_json::from_slice(&data).ok()?;
        if entry.version != CACHE_VERSION {
            return None;
        }
        if entry.file_hash != safe_hash {
            SecurityEvent {
                level: Level::WARN,
                domain: SecurityDomain::Cache,
                severity: crate::model::Severity::Low,
                kind: "cache_feature_hash_mismatch",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Cache feature hash mismatch",
            }
            .emit();
            warn!(
                requested = %safe_hash,
                cached = %entry.file_hash,
                "Cache feature hash mismatch"
            );
            return None;
        }
        Some(entry.features)
    }

    pub fn store_features(&self, hash: &str, features: &FeatureVector) -> Result<()> {
        let safe_hash = sanitize_hash(hash)
            .ok_or_else(|| anyhow::anyhow!("invalid cache hash"))?;
        let path = self.feature_path_for(&safe_hash);
        let entry = FeatureEntry {
            version: CACHE_VERSION,
            file_hash: safe_hash,
            features,
        };
        let data = serde_json::to_vec(&entry)?;
        fs::write(path, data)?;
        Ok(())
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        self.dir.join(format!("{}.json", hash))
    }

    fn feature_path_for(&self, hash: &str) -> PathBuf {
        self.dir.join(format!("{}_features.json", hash))
    }
}

impl AnalysisCache for ScanCache {
    fn load_report(&self, hash: &str) -> Option<Report> {
        self.load(hash)
    }

    fn store_report(&self, hash: &str, report: &Report) -> Result<()> {
        self.store(hash, report)
    }

    fn load_features(&self, hash: &str) -> Option<FeatureVector> {
        self.load_features(hash)
    }

    fn store_features(&self, hash: &str, features: &FeatureVector) -> Result<()> {
        self.store_features(hash, features)
    }
}

pub fn cache_dir_from_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn sanitize_hash(hash: &str) -> Option<String> {
    if hash.len() != 64 {
        SecurityEvent {
            level: Level::WARN,
            domain: SecurityDomain::Cache,
            severity: crate::model::Severity::Low,
            kind: "cache_hash_invalid_len",
            policy: None,
            object_id: None,
            object_type: None,
            vector: None,
            technique: None,
            confidence: None,
            message: "Cache hash rejected due to length",
        }
        .emit();
        warn!(len = hash.len(), "Cache hash rejected due to length");
        return None;
    }
    if !hash.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        SecurityEvent {
            level: Level::WARN,
            domain: SecurityDomain::Cache,
            severity: crate::model::Severity::Low,
            kind: "cache_hash_invalid_chars",
            policy: None,
            object_id: None,
            object_type: None,
            vector: None,
            technique: None,
            confidence: None,
            message: "Cache hash rejected due to non-hex characters",
        }
        .emit();
        warn!("Cache hash rejected due to non-hex characters");
        return None;
    }
    Some(hash.to_string())
}

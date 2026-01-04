use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::report::Report;
use crate::features::FeatureVector;

const CACHE_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
struct CacheEntry<'a> {
    version: u32,
    report: &'a Report,
}

#[derive(Debug, Deserialize)]
struct CacheEntryOwned {
    version: u32,
    report: Report,
}

#[derive(Debug, Serialize)]
struct FeatureEntry<'a> {
    version: u32,
    features: &'a FeatureVector,
}

#[derive(Debug, Deserialize)]
struct FeatureEntryOwned {
    version: u32,
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
        let path = self.path_for(hash);
        let data = fs::read(path).ok()?;
        let entry: CacheEntryOwned = serde_json::from_slice(&data).ok()?;
        if entry.version != CACHE_VERSION {
            return None;
        }
        Some(entry.report)
    }

    pub fn store(&self, hash: &str, report: &Report) -> Result<()> {
        let path = self.path_for(hash);
        let entry = CacheEntry {
            version: CACHE_VERSION,
            report,
        };
        let data = serde_json::to_vec(&entry)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn load_features(&self, hash: &str) -> Option<FeatureVector> {
        let path = self.feature_path_for(hash);
        let data = fs::read(path).ok()?;
        let entry: FeatureEntryOwned = serde_json::from_slice(&data).ok()?;
        if entry.version != CACHE_VERSION {
            return None;
        }
        Some(entry.features)
    }

    pub fn store_features(&self, hash: &str, features: &FeatureVector) -> Result<()> {
        let path = self.feature_path_for(hash);
        let entry = FeatureEntry {
            version: CACHE_VERSION,
            features,
        };
        let data = serde_json::to_vec(&entry)?;
        fs::write(path, data)?;
        Ok(())
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        let safe = hash.replace('/', "_");
        self.dir.join(format!("{}.json", safe))
    }

    fn feature_path_for(&self, hash: &str) -> PathBuf {
        let safe = hash.replace('/', "_");
        self.dir.join(format!("{}_features.json", safe))
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

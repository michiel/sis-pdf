use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::report::Report;

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

    fn path_for(&self, hash: &str) -> PathBuf {
        let safe = hash.replace('/', "_");
        self.dir.join(format!("{}.json", safe))
    }
}

pub fn cache_dir_from_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

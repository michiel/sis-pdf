#[cfg(feature = "filesystem")]
use std::fs;
#[cfg(feature = "filesystem")]
use std::path::{Path, PathBuf};

#[cfg(feature = "filesystem")]
use anyhow::{anyhow, Result};
#[cfg(feature = "filesystem")]
use serde::Deserialize;

#[cfg(feature = "filesystem")]
use crate::ml::{LinearModel, StackingClassifier};

#[cfg(feature = "filesystem")]
#[derive(Debug, Deserialize)]
struct StackingModelFile {
    base: Vec<LinearModel>,
    meta: LinearModel,
}

#[cfg(feature = "filesystem")]
pub fn load_stacking(path: impl AsRef<Path>) -> Result<StackingClassifier> {
    let path = path.as_ref();
    let model_path = resolve_model_path(path)?;
    let data = fs::read(&model_path)?;
    let model: StackingModelFile = serde_json::from_slice(&data)?;
    if model.base.is_empty() {
        return Err(anyhow!("stacking model has no base models"));
    }
    let base = model.base.into_iter().map(|m| Box::new(m) as _).collect();
    let meta = Box::new(model.meta);
    Ok(StackingClassifier { base, meta })
}

#[cfg(feature = "filesystem")]
fn resolve_model_path(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    if path.is_dir() {
        let candidates = ["stacking.json", "model.json", "ml.json"];
        for name in candidates {
            let candidate = path.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        return Err(anyhow!("no model file found in {}", path.display()));
    }
    Err(anyhow!("model path not found: {}", path.display()))
}

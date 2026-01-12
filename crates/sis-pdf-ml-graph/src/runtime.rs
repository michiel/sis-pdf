use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use ort::ep;
use ort::ep::{ExecutionProvider, ExecutionProviderDispatch};
use tracing::warn;

use crate::config::RuntimeConfig;

#[derive(Debug, Clone, Default)]
pub struct RuntimeSettings {
    pub provider: Option<String>,
    pub provider_order: Option<Vec<String>>,
    pub ort_dylib_path: Option<PathBuf>,
    pub prefer_quantized: bool,
    pub max_embedding_batch_size: Option<usize>,
    pub print_provider: bool,
}

#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub requested: Vec<String>,
    pub available: Vec<String>,
    pub selected: Option<String>,
}

static ORT_INIT: OnceLock<()> = OnceLock::new();

pub fn merge_runtime_settings(
    model_runtime: Option<&RuntimeConfig>,
    overrides: &RuntimeSettings,
) -> RuntimeSettings {
    let mut settings = RuntimeSettings::default();
    if let Some(runtime) = model_runtime {
        settings.provider = runtime.device_preference.clone();
        settings.provider_order = runtime.execution_providers.clone();
        settings.ort_dylib_path = runtime.ort_dylib_path.as_ref().map(PathBuf::from);
        settings.prefer_quantized = runtime.prefer_quantized.unwrap_or(false);
        settings.max_embedding_batch_size = runtime.max_embedding_batch_size;
    }
    if overrides.provider.is_some() {
        settings.provider = overrides.provider.clone();
    }
    if overrides.provider_order.is_some() {
        settings.provider_order = overrides.provider_order.clone();
    }
    if overrides.ort_dylib_path.is_some() {
        settings.ort_dylib_path = overrides.ort_dylib_path.clone();
    }
    if overrides.prefer_quantized {
        settings.prefer_quantized = true;
    }
    if overrides.max_embedding_batch_size.is_some() {
        settings.max_embedding_batch_size = overrides.max_embedding_batch_size;
    }
    settings.print_provider = overrides.print_provider;
    settings
}

pub fn ensure_ort_initialised(settings: &RuntimeSettings) -> Result<()> {
    if ORT_INIT.get().is_some() {
        return Ok(());
    }
    let init = || -> Result<()> {
        let path = resolve_dylib_path(settings)?;
        if let Some(path) = path {
            let builder = ort::init_from(&path)
                .map_err(|e| anyhow!("failed to load ORT dylib {}: {}", path.display(), e))?;
            let committed = builder.commit();
            if !committed {
                warn!(
                    "ORT environment already initialised; dynamic library selection may not apply"
                );
            }
        } else {
            let committed = ort::init().commit();
            if !committed {
                warn!("ORT environment already initialised; environment settings may not apply");
            }
        }
        Ok(())
    };
    init()?;
    let _ = ORT_INIT.set(());
    Ok(())
}

pub fn execution_providers(settings: &RuntimeSettings) -> Vec<ExecutionProviderDispatch> {
    let order = provider_order(settings);
    let mut out = Vec::new();
    for name in order {
        if let Some(ep) = provider_from_name(&name) {
            out.push(ep);
        }
    }
    if !out.iter().any(|ep| ep.downcast_ref::<ep::CPU>().is_some()) {
        out.push(ep::CPU::default().build());
    }
    out
}

pub fn provider_info(settings: &RuntimeSettings) -> Result<ProviderInfo> {
    ensure_ort_initialised(settings)?;
    let requested = provider_order(settings);
    let mut available = Vec::new();
    for name in &requested {
        if is_provider_available(name)? {
            available.push(name.clone());
        }
    }
    let selected = available.first().cloned();
    Ok(ProviderInfo {
        requested,
        available,
        selected,
    })
}

fn resolve_dylib_path(settings: &RuntimeSettings) -> Result<Option<PathBuf>> {
    if let Some(path) = &settings.ort_dylib_path {
        return Ok(Some(path.clone()));
    }
    if let Ok(path) = std::env::var("SIS_ORT_DYLIB_PATH") {
        if !path.is_empty() {
            return Ok(Some(PathBuf::from(path)));
        }
    }
    Ok(None)
}

fn provider_order(settings: &RuntimeSettings) -> Vec<String> {
    if let Some(list) = &settings.provider_order {
        return ensure_cpu(sanitise_provider_list(list));
    }
    if let Some(pref) = settings.provider.as_deref() {
        return ensure_cpu(sanitise_provider_list(&[
            pref.to_string(),
            "cpu".to_string(),
        ]));
    }
    let mut out = Vec::new();
    if cfg!(target_os = "windows") {
        out.push("directml".to_string());
        out.push("cuda".to_string());
    } else if cfg!(target_os = "macos") {
        out.push("coreml".to_string());
    } else {
        out.push("cuda".to_string());
        out.push("rocm".to_string());
    }
    out.push("cpu".to_string());
    ensure_cpu(sanitise_provider_list(&out))
}

fn sanitise_provider_list(list: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in list {
        let name = raw.trim().to_lowercase();
        if name.is_empty() {
            continue;
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn ensure_cpu(mut list: Vec<String>) -> Vec<String> {
    if !list.iter().any(|p| p == "cpu") {
        list.push("cpu".to_string());
    }
    list
}

fn provider_from_name(name: &str) -> Option<ExecutionProviderDispatch> {
    match name {
        "cpu" => Some(ep::CPU::default().build()),
        "cuda" => Some(ep::CUDA::default().build()),
        "rocm" => Some(ep::ROCm::default().build()),
        "migraphx" => Some(ep::MIGraphX::default().build()),
        "directml" => Some(ep::DirectML::default().build()),
        "coreml" => Some(ep::CoreML::default().build()),
        "onednn" => Some(ep::OneDNN::default().build()),
        "openvino" => Some(ep::OpenVINO::default().build()),
        _ => {
            warn!(provider = name, "Unknown execution provider requested");
            None
        }
    }
}

fn is_provider_available(name: &str) -> Result<bool> {
    match name {
        "cpu" => ep::CPU::default()
            .is_available()
            .map_err(anyhow::Error::from),
        "cuda" => ep::CUDA::default()
            .is_available()
            .map_err(anyhow::Error::from),
        "rocm" => ep::ROCm::default()
            .is_available()
            .map_err(anyhow::Error::from),
        "migraphx" => ep::MIGraphX::default()
            .is_available()
            .map_err(anyhow::Error::from),
        "directml" => ep::DirectML::default()
            .is_available()
            .map_err(anyhow::Error::from),
        "coreml" => ep::CoreML::default()
            .is_available()
            .map_err(anyhow::Error::from),
        "onednn" => ep::OneDNN::default()
            .is_available()
            .map_err(anyhow::Error::from),
        "openvino" => ep::OpenVINO::default()
            .is_available()
            .map_err(anyhow::Error::from),
        _ => Ok(false),
    }
}

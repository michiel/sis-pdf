#[cfg(feature = "filesystem")]
use std::fs;
#[cfg(feature = "filesystem")]
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterAllowlistEntry {
    pub filters: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterAllowlistConfig {
    pub allowed_chains: Vec<FilterAllowlistEntry>,
}

impl FilterAllowlistConfig {
    pub fn to_chain_list(&self) -> Vec<Vec<String>> {
        self.allowed_chains
            .iter()
            .map(|entry| entry.filters.iter().map(|f| normalise_filter_name(f)).collect())
            .collect()
    }
}

pub fn default_filter_allowlist_config() -> FilterAllowlistConfig {
    FilterAllowlistConfig {
        allowed_chains: vec![
            entry(&["ASCIIHexDecode", "FlateDecode"], "Hex-encoded compressed stream"),
            entry(&["ASCII85Decode", "FlateDecode"], "Base85-encoded compressed stream"),
            entry(&["FlateDecode", "DCTDecode"], "Compressed JPEG image (unusual but valid)"),
            entry(&["DCTDecode"], "JPEG image (uncompressed stream)"),
            entry(&["CCITTFaxDecode"], "Fax-encoded image"),
            entry(&["JBIG2Decode"], "JBIG2-encoded image"),
            entry(&["JPXDecode"], "JPEG2000-encoded image"),
            entry(&["LZWDecode"], "LZW compression (legacy)"),
            entry(&["RunLengthDecode"], "Run-length encoding"),
            entry(&["ASCIIHexDecode"], "Hex encoding only"),
            entry(&["ASCII85Decode"], "Base85 encoding only"),
            entry(&["FlateDecode"], "Flate compression"),
            entry(&["Crypt"], "Crypt filter"),
        ],
    }
}

pub fn default_filter_allowlist() -> Vec<Vec<String>> {
    default_filter_allowlist_config().to_chain_list()
}

#[cfg(feature = "filesystem")]
pub fn load_filter_allowlist(path: &Path) -> anyhow::Result<Vec<Vec<String>>> {
    let data = fs::read_to_string(path)?;
    let cfg: FilterAllowlistConfig = toml::from_str(&data)?;
    Ok(cfg.to_chain_list())
}

pub fn load_filter_allowlist_from_str(data: &str) -> anyhow::Result<Vec<Vec<String>>> {
    let cfg: FilterAllowlistConfig = toml::from_str(data)?;
    Ok(cfg.to_chain_list())
}

pub fn default_filter_allowlist_toml() -> anyhow::Result<String> {
    toml::to_string_pretty(&default_filter_allowlist_config())
        .map_err(|err| anyhow::anyhow!("failed to serialise filter allowlist: {err}"))
}

fn entry(filters: &[&str], description: &str) -> FilterAllowlistEntry {
    FilterAllowlistEntry {
        filters: filters.iter().map(|f| (*f).to_string()).collect(),
        description: Some(description.to_string()),
    }
}

fn normalise_filter_name(value: &str) -> String {
    value.trim().trim_start_matches('/').trim().to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::default_filter_allowlist;

    #[cfg(feature = "filesystem")]
    #[test]
    fn load_filter_allowlist_parses_chains() {
        use super::load_filter_allowlist;
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(file, "[[allowed_chains]]\nfilters = [\"/FlateDecode\"]\n")
            .expect("write allowlist");
        let allowlist = load_filter_allowlist(file.path()).expect("load allowlist");
        assert_eq!(allowlist.len(), 1);
        assert_eq!(allowlist[0], vec!["FLATEDECODE".to_string()]);
        let defaults = default_filter_allowlist();
        assert!(!defaults.is_empty());
    }

    #[test]
    fn default_filter_allowlist_is_non_empty() {
        let defaults = default_filter_allowlist();
        assert!(!defaults.is_empty());
    }
}

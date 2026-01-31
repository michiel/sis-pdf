use sis_pdf_pdf::object::PdfDict;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WeakCrypto {
    pub issue: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertAnomaly {
    pub issue: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CryptoMiner {
    pub indicator: String,
}

#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub filter: Option<String>,
    pub subfilter: Option<String>,
}

pub struct CryptoAnalyzer;

impl CryptoAnalyzer {
    pub fn detect_weak_crypto(&self, encrypt: &PdfDict<'_>) -> Vec<WeakCrypto> {
        let mut out = Vec::new();
        let v = dict_int(encrypt, b"/V");
        let r = dict_int(encrypt, b"/R");
        let length = dict_int(encrypt, b"/Length");
        if matches!(v, Some(v) if v <= 2) {
            out.push(WeakCrypto {
                issue: "Encryption version <= 2".into(),
            });
        }
        if matches!(r, Some(r) if r <= 3) {
            out.push(WeakCrypto {
                issue: "Encryption revision <= 3".into(),
            });
        }
        if matches!(length, Some(l) if l < 128) {
            out.push(WeakCrypto {
                issue: "Encryption key length below 128 bits".into(),
            });
        }
        out
    }

    pub fn analyze_cert_chains(&self, sigs: &[SignatureInfo]) -> Vec<CertAnomaly> {
        let mut out = Vec::new();
        for sig in sigs {
            if let Some(sub) = &sig.subfilter {
                if sub.contains("adbe.pkcs7") {
                    out.push(CertAnomaly {
                        issue: format!("Legacy subfilter {}", sub),
                    });
                }
            }
            if sig.filter.as_deref() == Some("Adobe.PPKLite") {
                out.push(CertAnomaly {
                    issue: "Legacy filter Adobe.PPKLite".into(),
                });
            }
        }
        out
    }

    pub fn detect_crypto_mining(&self, js: &[u8]) -> Option<CryptoMiner> {
        for needle in [
            b"CryptoJS".as_slice(),
            b"cryptonight".as_slice(),
            b"hashcash".as_slice(),
            b"sha256".as_slice(),
            b"mining".as_slice(),
            b"coinhive".as_slice(),
        ] {
            if js
                .windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle))
            {
                return Some(CryptoMiner {
                    indicator: String::from_utf8_lossy(needle).to_string(),
                });
            }
        }
        None
    }
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match obj.atom {
        sis_pdf_pdf::object::PdfAtom::Int(v) => Some(v as u32),
        _ => None,
    }
}

pub fn classify_encryption_algorithm(
    version: Option<u32>,
    key_len: Option<u32>,
) -> Option<&'static str> {
    match version {
        Some(1 | 2) => {
            if let Some(len) = key_len {
                if len <= 40 {
                    Some("RC4-40")
                } else {
                    Some("RC4-128")
                }
            } else {
                Some("RC4")
            }
        }
        Some(4 | 5) => {
            if let Some(len) = key_len {
                if len >= 256 {
                    Some("AES-256")
                } else {
                    Some("AES-128")
                }
            } else {
                Some("AES")
            }
        }
        _ => None,
    }
}

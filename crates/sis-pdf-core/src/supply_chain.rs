use sis_pdf_pdf::ObjectGraph;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StagedPayload {
    pub indicator: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateVector {
    pub indicator: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Persistence {
    pub indicator: String,
}

pub struct SupplyChainDetector;

impl SupplyChainDetector {
    pub fn detect_staged_payload(&self, bytes: &[u8]) -> Vec<StagedPayload> {
        let mut out = Vec::new();
        for needle in [
            b"app.launchURL".as_slice(),
            b"getURL".as_slice(),
            b"submitForm".as_slice(),
            b"Launch".as_slice(),
            b"OpenURL".as_slice(),
        ] {
            if bytes.windows(needle.len()).any(|w| w == needle) {
                out.push(StagedPayload { indicator: String::from_utf8_lossy(needle).to_string() });
            }
        }
        out
    }

    pub fn analyze_update_mechanisms(&self, bytes: &[u8]) -> Vec<UpdateVector> {
        let mut out = Vec::new();
        for needle in [
            b"update".as_slice(),
            b"download".as_slice(),
            b"installer".as_slice(),
            b"version".as_slice(),
            b"patch".as_slice(),
        ] {
            if bytes.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle)) {
                out.push(UpdateVector { indicator: String::from_utf8_lossy(needle).to_string() });
            }
        }
        out
    }

    pub fn check_persistence_methods(&self, bytes: &[u8]) -> Vec<Persistence> {
        let mut out = Vec::new();
        for needle in [
            b"app.execMenuItem".as_slice(),
            b"app.addToolButton".as_slice(),
            b"setTimeOut".as_slice(),
            b"setInterval".as_slice(),
        ] {
            if bytes.windows(needle.len()).any(|w| w == needle) {
                out.push(Persistence { indicator: String::from_utf8_lossy(needle).to_string() });
            }
        }
        out
    }
}

pub fn extract_js_blobs(graph: &ObjectGraph<'_>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in &graph.objects {
        if let sis_pdf_pdf::object::PdfAtom::Str(s) = &entry.atom {
            out.push(match s {
                sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
                sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
            });
        }
    }
    out
}

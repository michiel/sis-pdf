use sis_pdf_pdf::graph::ObjectGraph;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfStr};

use crate::util::dict_u32;

/// Maximum recursion depth when resolving nested colour spaces (e.g. Indexed base).
const MAX_RESOLVE_DEPTH: u8 = 2;

/// Resolved colour space for a PDF image XObject.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedColourSpace {
    DeviceGray,
    DeviceRGB,
    DeviceCMYK,
    /// Indexed colour space with base space and palette bytes.
    /// `hival` is the maximum valid index (0..=hival).
    Indexed {
        base: Box<ResolvedColourSpace>,
        hival: u8,
        palette: Vec<u8>,
    },
    /// ICCBased with fallback channel count from `/N` in the ICC stream dict.
    ICCBased { n: u8 },
    /// CalGray (1), CalRGB (3), or Lab (3).
    Calibrated { channels: u8 },
    /// Unrecognised colour space name (for diagnostic metadata).
    Unknown(String),
}

impl ResolvedColourSpace {
    /// Number of colour component samples per pixel, if known.
    pub fn channels(&self) -> Option<u8> {
        match self {
            Self::DeviceGray => Some(1),
            Self::DeviceRGB => Some(3),
            Self::DeviceCMYK => Some(4),
            Self::Indexed { .. } => Some(1), // sample is a single palette index
            Self::ICCBased { n } => Some(*n),
            Self::Calibrated { channels } => Some(*channels),
            Self::Unknown(_) => None,
        }
    }

    /// Whether this colour space can be converted to RGBA for preview.
    pub fn supports_preview(&self) -> bool {
        match self {
            Self::DeviceGray | Self::DeviceRGB | Self::DeviceCMYK => true,
            Self::Indexed { base, .. } => base.supports_preview(),
            Self::ICCBased { n } => matches!(n, 1 | 3 | 4),
            Self::Calibrated { channels } => matches!(channels, 1 | 3),
            Self::Unknown(_) => false,
        }
    }
}

/// Resolve the `/ColorSpace` entry from an image XObject dictionary.
///
/// Returns `None` if no `/ColorSpace` entry exists.
pub fn resolve_colour_space(
    dict: &PdfDict<'_>,
    graph: &ObjectGraph<'_>,
) -> Option<ResolvedColourSpace> {
    let (_, cs_obj) = dict.get_first(b"/ColorSpace")?;
    Some(resolve_cs_value(&cs_obj.atom, graph, 0))
}

fn resolve_cs_value(
    atom: &PdfAtom<'_>,
    graph: &ObjectGraph<'_>,
    depth: u8,
) -> ResolvedColourSpace {
    if depth > MAX_RESOLVE_DEPTH {
        return ResolvedColourSpace::Unknown("depth_exceeded".to_string());
    }

    match atom {
        PdfAtom::Name(name) => resolve_cs_name(&name.decoded),
        PdfAtom::Array(arr) => resolve_cs_array(arr, graph, depth),
        PdfAtom::Ref { obj, gen } => {
            // Dereference indirect object
            match graph.get_object(*obj, *gen) {
                Some(entry) => resolve_cs_value(&entry.atom, graph, depth),
                None => ResolvedColourSpace::Unknown(format!("{} {} R (unresolved)", obj, gen)),
            }
        }
        _ => ResolvedColourSpace::Unknown("unexpected_type".to_string()),
    }
}

fn resolve_cs_name(name: &[u8]) -> ResolvedColourSpace {
    // Names may or may not have a leading slash
    let normalised = if name.starts_with(b"/") { &name[1..] } else { name };
    match normalised {
        b"DeviceGray" | b"G" => ResolvedColourSpace::DeviceGray,
        b"DeviceRGB" | b"RGB" => ResolvedColourSpace::DeviceRGB,
        b"DeviceCMYK" | b"CMYK" => ResolvedColourSpace::DeviceCMYK,
        b"CalGray" => ResolvedColourSpace::Calibrated { channels: 1 },
        b"CalRGB" => ResolvedColourSpace::Calibrated { channels: 3 },
        b"Lab" => ResolvedColourSpace::Calibrated { channels: 3 },
        _ => {
            let s = String::from_utf8_lossy(name).to_string();
            ResolvedColourSpace::Unknown(s)
        }
    }
}

fn resolve_cs_array(
    arr: &[sis_pdf_pdf::object::PdfObj<'_>],
    graph: &ObjectGraph<'_>,
    depth: u8,
) -> ResolvedColourSpace {
    if arr.is_empty() {
        return ResolvedColourSpace::Unknown("empty_array".to_string());
    }

    // First element should be the colour space family name
    let family = match &arr[0].atom {
        PdfAtom::Name(name) => &name.decoded,
        _ => return ResolvedColourSpace::Unknown("array_no_name".to_string()),
    };

    let normalised = if family.starts_with(b"/") { &family[1..] } else { &family[..] };

    match normalised {
        b"ICCBased" => resolve_icc_based(arr, graph),
        b"Indexed" | b"I" => resolve_indexed(arr, graph, depth),
        b"CalGray" => ResolvedColourSpace::Calibrated { channels: 1 },
        b"CalRGB" => ResolvedColourSpace::Calibrated { channels: 3 },
        b"Lab" => ResolvedColourSpace::Calibrated { channels: 3 },
        b"DeviceGray" | b"G" => ResolvedColourSpace::DeviceGray,
        b"DeviceRGB" | b"RGB" => ResolvedColourSpace::DeviceRGB,
        b"DeviceCMYK" | b"CMYK" => ResolvedColourSpace::DeviceCMYK,
        _ => {
            let s = String::from_utf8_lossy(family).to_string();
            ResolvedColourSpace::Unknown(s)
        }
    }
}

/// Resolve `[/ICCBased <stream-ref>]`.
fn resolve_icc_based(
    arr: &[sis_pdf_pdf::object::PdfObj<'_>],
    graph: &ObjectGraph<'_>,
) -> ResolvedColourSpace {
    if arr.len() < 2 {
        return ResolvedColourSpace::Unknown("ICCBased_missing_stream".to_string());
    }

    // Second element should be an indirect reference to an ICC profile stream
    let icc_dict = match &arr[1].atom {
        PdfAtom::Ref { obj, gen } => match graph.get_object(*obj, *gen) {
            Some(entry) => match &entry.atom {
                PdfAtom::Stream(stream) => Some(&stream.dict),
                _ => None,
            },
            None => None,
        },
        PdfAtom::Stream(stream) => Some(&stream.dict),
        _ => None,
    };

    let Some(dict) = icc_dict else {
        return ResolvedColourSpace::Unknown("ICCBased_no_dict".to_string());
    };

    // Read /N (number of colour components) from the ICC stream dictionary
    let Some(n) = dict_u32(dict, b"/N") else {
        return ResolvedColourSpace::Unknown("ICCBased_missing_N".to_string());
    };

    if n < 1 || n > 4 {
        return ResolvedColourSpace::Unknown(format!("ICCBased_invalid_N_{}", n));
    }

    ResolvedColourSpace::ICCBased { n: n as u8 }
}

/// Resolve `[/Indexed <base> <hival> <palette>]`.
fn resolve_indexed(
    arr: &[sis_pdf_pdf::object::PdfObj<'_>],
    graph: &ObjectGraph<'_>,
    depth: u8,
) -> ResolvedColourSpace {
    if arr.len() < 4 {
        return ResolvedColourSpace::Unknown("Indexed_missing_elements".to_string());
    }

    // Element 1: base colour space
    let base = resolve_cs_value(&arr[1].atom, graph, depth + 1);

    // Element 2: hival (maximum valid index)
    let hival = match &arr[2].atom {
        PdfAtom::Int(v) => {
            if *v < 0 || *v > 255 {
                return ResolvedColourSpace::Unknown(format!("Indexed_invalid_hival_{}", v));
            }
            *v as u8
        }
        _ => return ResolvedColourSpace::Unknown("Indexed_hival_not_int".to_string()),
    };

    // Element 3: palette (string or stream)
    let palette = extract_palette_bytes(&arr[3].atom, graph);

    ResolvedColourSpace::Indexed {
        base: Box::new(base),
        hival,
        palette,
    }
}

/// Extract palette bytes from a string literal, hex string, or stream.
fn extract_palette_bytes(atom: &PdfAtom<'_>, graph: &ObjectGraph<'_>) -> Vec<u8> {
    match atom {
        PdfAtom::Str(s) => match s {
            PdfStr::Literal { decoded, .. } => decoded.clone(),
            PdfStr::Hex { decoded, .. } => decoded.clone(),
        },
        PdfAtom::Stream(stream) => {
            // Try to decode inline stream for palette data
            let start = stream.data_span.start as usize;
            let end = stream.data_span.end as usize;
            if start < end && end <= graph.bytes.len() {
                match sis_pdf_pdf::decode::decode_stream(
                    graph.bytes,
                    stream,
                    4096, // palettes are at most 256 * 4 = 1024 bytes
                ) {
                    Ok(decoded) => decoded.data,
                    Err(_) => Vec::new(),
                }
            } else {
                Vec::new()
            }
        }
        PdfAtom::Ref { obj, gen } => {
            // Dereference and try again
            match graph.get_object(*obj, *gen) {
                Some(entry) => extract_palette_bytes(&entry.atom, graph),
                None => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::HashMap;

    use sis_pdf_pdf::graph::{ObjEntry, ObjProvenance};
    use sis_pdf_pdf::object::{PdfName, PdfObj};
    use sis_pdf_pdf::span::Span;

    fn zero_span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn pdf_name(name: &'static str) -> PdfName<'static> {
        PdfName {
            span: zero_span(),
            raw: Cow::Owned(name.as_bytes().to_vec()),
            decoded: name.as_bytes().to_vec(),
        }
    }

    fn pdf_obj_name(name: &'static str) -> PdfObj<'static> {
        PdfObj { span: zero_span(), atom: PdfAtom::Name(pdf_name(name)) }
    }

    fn pdf_obj_int(value: i64) -> PdfObj<'static> {
        PdfObj { span: zero_span(), atom: PdfAtom::Int(value) }
    }

    fn empty_graph() -> ObjectGraph<'static> {
        ObjectGraph {
            bytes: &[],
            objects: Vec::new(),
            index: HashMap::new(),
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        }
    }

    fn make_dict(entries: Vec<(PdfName<'static>, PdfObj<'static>)>) -> PdfDict<'static> {
        PdfDict { span: zero_span(), entries }
    }

    #[test]
    fn device_gray_from_name() {
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray"))]);
        let graph = empty_graph();
        let cs = resolve_colour_space(&dict, &graph);
        assert_eq!(cs, Some(ResolvedColourSpace::DeviceGray));
        assert_eq!(cs.as_ref().and_then(|c| c.channels()), Some(1));
    }

    #[test]
    fn device_rgb_from_name() {
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), pdf_obj_name("/DeviceRGB"))]);
        let graph = empty_graph();
        let cs = resolve_colour_space(&dict, &graph);
        assert_eq!(cs, Some(ResolvedColourSpace::DeviceRGB));
        assert_eq!(cs.as_ref().and_then(|c| c.channels()), Some(3));
    }

    #[test]
    fn device_cmyk_from_name() {
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), pdf_obj_name("/DeviceCMYK"))]);
        let graph = empty_graph();
        let cs = resolve_colour_space(&dict, &graph);
        assert_eq!(cs, Some(ResolvedColourSpace::DeviceCMYK));
        assert_eq!(cs.as_ref().and_then(|c| c.channels()), Some(4));
    }

    #[test]
    fn icc_based_from_array() {
        // Build an ICC stream object with /N 3
        let icc_dict = make_dict(vec![(pdf_name("/N"), pdf_obj_int(3))]);
        let icc_stream = sis_pdf_pdf::object::PdfStream {
            dict: icc_dict,
            data_span: zero_span(),
        };
        let icc_entry = ObjEntry {
            obj: 5,
            gen: 0,
            atom: PdfAtom::Stream(icc_stream),
            header_span: zero_span(),
            body_span: zero_span(),
            full_span: zero_span(),
            provenance: ObjProvenance::Indirect,
        };

        let mut index = HashMap::new();
        index.insert((5u32, 0u16), vec![0usize]);

        let graph = ObjectGraph {
            bytes: &[],
            objects: vec![icc_entry],
            index,
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        };

        // Build the image dict with [/ICCBased 5 0 R]
        let cs_array = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/ICCBased"),
                PdfObj { span: zero_span(), atom: PdfAtom::Ref { obj: 5, gen: 0 } },
            ]),
        };
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), cs_array)]);

        let cs = resolve_colour_space(&dict, &graph);
        assert_eq!(cs, Some(ResolvedColourSpace::ICCBased { n: 3 }));
        assert_eq!(cs.as_ref().and_then(|c| c.channels()), Some(3));
        assert!(cs.as_ref().map(|c| c.supports_preview()).unwrap_or(false));
    }

    #[test]
    fn indexed_with_device_rgb_base() {
        let graph = empty_graph();

        // Palette: 2 entries (hival=1), 3 bytes each for RGB base
        let palette_bytes = vec![255, 0, 0, 0, 255, 0]; // red, green
        let palette_str = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Str(PdfStr::Literal {
                span: zero_span(),
                raw: Cow::Owned(palette_bytes.clone()),
                decoded: palette_bytes.clone(),
            }),
        };

        let cs_array = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/Indexed"),
                pdf_obj_name("/DeviceRGB"),
                pdf_obj_int(1),
                palette_str,
            ]),
        };
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), cs_array)]);

        let cs = resolve_colour_space(&dict, &graph);
        assert_eq!(
            cs,
            Some(ResolvedColourSpace::Indexed {
                base: Box::new(ResolvedColourSpace::DeviceRGB),
                hival: 1,
                palette: palette_bytes,
            })
        );
        // Indexed always has 1 channel (the index itself)
        assert_eq!(cs.as_ref().and_then(|c| c.channels()), Some(1));
        assert!(cs.as_ref().map(|c| c.supports_preview()).unwrap_or(false));
    }

    #[test]
    fn unknown_colour_space_returned() {
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), pdf_obj_name("/Separation"))]);
        let graph = empty_graph();
        let cs = resolve_colour_space(&dict, &graph);
        assert!(matches!(cs, Some(ResolvedColourSpace::Unknown(_))));
        assert!(!cs.as_ref().map(|c| c.supports_preview()).unwrap_or(true));
    }

    #[test]
    fn recursive_depth_limited() {
        let graph = empty_graph();

        // [/Indexed [/Indexed [/Indexed /DeviceRGB 0 ""] 0 ""] 0 ""]
        // The innermost /Indexed should hit depth limit
        let empty_str = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Str(PdfStr::Literal {
                span: zero_span(),
                raw: Cow::Owned(Vec::new()),
                decoded: Vec::new(),
            }),
        };

        let inner_cs = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/Indexed"),
                pdf_obj_name("/DeviceRGB"),
                pdf_obj_int(0),
                empty_str.clone(),
            ]),
        };
        let middle_cs = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/Indexed"),
                inner_cs,
                pdf_obj_int(0),
                empty_str.clone(),
            ]),
        };
        let outer_cs = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/Indexed"),
                middle_cs,
                pdf_obj_int(0),
                empty_str,
            ]),
        };
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), outer_cs)]);

        let cs = resolve_colour_space(&dict, &graph);
        // The deepest base should be Unknown("depth_exceeded")
        match cs {
            Some(ResolvedColourSpace::Indexed { base, .. }) => match *base {
                ResolvedColourSpace::Indexed { base: mid_base, .. } => match *mid_base {
                    ResolvedColourSpace::Indexed { base: inner_base, .. } => {
                        assert!(matches!(*inner_base, ResolvedColourSpace::Unknown(ref s) if s == "depth_exceeded"));
                    }
                    _ => panic!("expected innermost Indexed"),
                },
                _ => panic!("expected middle Indexed"),
            },
            _ => panic!("expected outer Indexed"),
        }
    }

    #[test]
    fn no_colour_space_returns_none() {
        let dict = make_dict(vec![]);
        let graph = empty_graph();
        assert_eq!(resolve_colour_space(&dict, &graph), None);
    }

    #[test]
    fn calibrated_spaces() {
        let graph = empty_graph();

        let dict = make_dict(vec![(pdf_name("/ColorSpace"), pdf_obj_name("/CalGray"))]);
        assert_eq!(
            resolve_colour_space(&dict, &graph),
            Some(ResolvedColourSpace::Calibrated { channels: 1 })
        );

        let dict = make_dict(vec![(pdf_name("/ColorSpace"), pdf_obj_name("/CalRGB"))]);
        assert_eq!(
            resolve_colour_space(&dict, &graph),
            Some(ResolvedColourSpace::Calibrated { channels: 3 })
        );
    }

    #[test]
    fn icc_based_invalid_n_rejected() {
        // ICCBased with /N = 0
        let icc_dict = make_dict(vec![(pdf_name("/N"), pdf_obj_int(0))]);
        let icc_stream = sis_pdf_pdf::object::PdfStream {
            dict: icc_dict,
            data_span: zero_span(),
        };
        let icc_entry = ObjEntry {
            obj: 5,
            gen: 0,
            atom: PdfAtom::Stream(icc_stream),
            header_span: zero_span(),
            body_span: zero_span(),
            full_span: zero_span(),
            provenance: ObjProvenance::Indirect,
        };

        let mut index = HashMap::new();
        index.insert((5u32, 0u16), vec![0usize]);

        let graph = ObjectGraph {
            bytes: &[],
            objects: vec![icc_entry],
            index,
            trailers: Vec::new(),
            startxrefs: Vec::new(),
            xref_sections: Vec::new(),
            deviations: Vec::new(),
            telemetry_events: Vec::new(),
        };

        let cs_array = PdfObj {
            span: zero_span(),
            atom: PdfAtom::Array(vec![
                pdf_obj_name("/ICCBased"),
                PdfObj { span: zero_span(), atom: PdfAtom::Ref { obj: 5, gen: 0 } },
            ]),
        };
        let dict = make_dict(vec![(pdf_name("/ColorSpace"), cs_array)]);

        let cs = resolve_colour_space(&dict, &graph);
        assert!(matches!(cs, Some(ResolvedColourSpace::Unknown(ref s)) if s.contains("invalid_N")));
    }
}

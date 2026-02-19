use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfStr};

pub(crate) fn dict_u32(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(value) => u32::try_from(*value).ok(),
        PdfAtom::Real(value) => {
            if *value < 0.0 {
                None
            } else {
                Some(*value as u32)
            }
        }
        _ => None,
    }
}

pub(crate) fn string_bytes(value: &PdfStr<'_>) -> Vec<u8> {
    match value {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

/// Extract a `/Decode` array as pairs of f64 values from a dict entry.
/// Returns `None` if the key is absent.
/// Returns `Some(Err(_))` for invalid non-array/non-numeric forms.
pub(crate) fn dict_f64_array(dict: &PdfDict<'_>, key: &[u8]) -> Option<Result<Vec<f64>, String>> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for (index, item) in arr.iter().enumerate() {
                match &item.atom {
                    PdfAtom::Int(v) => out.push(*v as f64),
                    PdfAtom::Real(v) => out.push(*v as f64),
                    _ => {
                        return Some(Err(format!("non_numeric_entry_at_index_{}", index)));
                    }
                }
            }
            Some(Ok(out))
        }
        _ => Some(Err("decode_not_array".to_string())),
    }
}

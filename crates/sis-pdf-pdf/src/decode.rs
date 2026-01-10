use std::io::Read;

use anyhow::{anyhow, Result};
use tracing::warn;

use crate::object::{PdfAtom, PdfDict, PdfName, PdfStream};

#[derive(Debug, Clone)]
pub struct DecodedStream {
    pub data: Vec<u8>,
    pub truncated: bool,
    pub filters: Vec<String>,
    pub input_len: usize,
}

#[derive(Debug, Clone, Copy)]
struct DecodeParms {
    predictor: u32,
    colors: u32,
    bits_per_component: u32,
    columns: u32,
}

const MAX_DECODE_PARMS: u32 = 100_000;

pub fn decode_stream(bytes: &[u8], stream: &PdfStream<'_>, max_out: usize) -> Result<DecodedStream> {
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > bytes.len() {
        return Err(anyhow!("invalid stream span"));
    }
    let mut data = bytes[start..end].to_vec();
    let mut truncated = false;
    let filters = stream_filters(&stream.dict);
    let parms = stream_decode_parms(&stream.dict, &filters);
    for (idx, filter) in filters.iter().enumerate() {
        let decoded = decode_filter(&data, filter, max_out)?;
        data = decoded.0;
        if let Some(p) = parms.get(idx).copied().flatten() {
            if is_flate_filter(filter) && p.predictor > 1 {
                data = apply_predictor(&data, p)?;
            }
        }
        if decoded.1 {
            truncated = true;
            break;
        }
    }
    if data.len() > max_out {
        data.truncate(max_out);
        truncated = true;
    }
    Ok(DecodedStream {
        data,
        truncated,
        filters,
        input_len: end - start,
    })
}

pub fn stream_filters(dict: &PdfDict<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let (_, obj) = match dict.get_first(b"/Filter") {
        Some(v) => v,
        None => return out,
    };
    match &obj.atom {
        PdfAtom::Name(n) => out.push(name_to_string(n)),
        PdfAtom::Array(arr) => {
            for o in arr {
                if let PdfAtom::Name(n) = &o.atom {
                    out.push(name_to_string(n));
                }
            }
        }
        _ => {}
    }
    out
}

fn stream_decode_parms(dict: &PdfDict<'_>, filters: &[String]) -> Vec<Option<DecodeParms>> {
    let mut out = vec![None; filters.len().max(1)];
    let (_, obj) = match dict.get_first(b"/DecodeParms") {
        Some(v) => v,
        None => return out,
    };
    match &obj.atom {
        PdfAtom::Dict(d) => {
            if let Some(p) = decode_parms_from_dict(d) {
                out[0] = Some(p);
            }
        }
        PdfAtom::Array(arr) => {
            for (idx, o) in arr.iter().enumerate() {
                if idx >= out.len() {
                    break;
                }
                if let PdfAtom::Dict(d) = &o.atom {
                    out[idx] = decode_parms_from_dict(d);
                }
            }
        }
        _ => {}
    }
    out
}

fn decode_parms_from_dict(dict: &PdfDict<'_>) -> Option<DecodeParms> {
    let predictor = dict_int(dict, b"/Predictor").unwrap_or(1);
    let colors = dict_int(dict, b"/Colors").unwrap_or(1);
    let bits = dict_int(dict, b"/BitsPerComponent").unwrap_or(8);
    let columns = dict_int(dict, b"/Columns").unwrap_or(1);
    Some(DecodeParms {
        predictor,
        colors,
        bits_per_component: bits,
        columns,
    })
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u32),
        _ => None,
    }
}

fn is_flate_filter(filter: &str) -> bool {
    matches!(filter, "/FlateDecode" | "/Fl")
}

fn apply_predictor(data: &[u8], parms: DecodeParms) -> Result<Vec<u8>> {
    validate_decode_parms(parms)?;
    if parms.bits_per_component != 8 || parms.columns == 0 {
        return Ok(data.to_vec());
    }
    if parms.predictor == 2 {
        return Ok(apply_tiff_predictor(data, parms)?);
    }
    if (10..=15).contains(&parms.predictor) {
        return Ok(apply_png_predictor(data, parms)?);
    }
    Ok(data.to_vec())
}

fn apply_tiff_predictor(data: &[u8], parms: DecodeParms) -> Result<Vec<u8>> {
    let bpp = checked_bpp(parms)?;
    let row_len = checked_row_len(parms, bpp)?;
    if row_len == 0 {
        return Ok(data.to_vec());
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(row_len) {
        let mut row = chunk.to_vec();
        for i in bpp..row.len() {
            row[i] = row[i].wrapping_add(row[i - bpp]);
        }
        out.extend_from_slice(&row);
    }
    Ok(out)
}

fn apply_png_predictor(data: &[u8], parms: DecodeParms) -> Result<Vec<u8>> {
    let bpp = checked_bpp(parms)?;
    let row_len = checked_row_len(parms, bpp)?;
    if row_len == 0 {
        return Ok(data.to_vec());
    }
    let mut out = Vec::new();
    let mut prev = vec![0u8; row_len];
    let mut i = 0usize;
    while i < data.len() {
        if i + 1 > data.len() {
            break;
        }
        let filter = data[i];
        i += 1;
        if i + row_len > data.len() {
            break;
        }
        let mut row = data[i..i + row_len].to_vec();
        i += row_len;
        match filter {
            0 => {} // None
            1 => {
                for j in 0..row_len {
                    let left = if j >= bpp { row[j - bpp] } else { 0 };
                    row[j] = row[j].wrapping_add(left);
                }
            }
            2 => {
                for j in 0..row_len {
                    row[j] = row[j].wrapping_add(prev[j]);
                }
            }
            3 => {
                for j in 0..row_len {
                    let left = if j >= bpp { row[j - bpp] } else { 0 };
                    let up = prev[j];
                    let avg = ((left as u16 + up as u16) / 2) as u8;
                    row[j] = row[j].wrapping_add(avg);
                }
            }
            4 => {
                for j in 0..row_len {
                    let left = if j >= bpp { row[j - bpp] } else { 0 };
                    let up = prev[j];
                    let up_left = if j >= bpp { prev[j - bpp] } else { 0 };
                    row[j] = row[j].wrapping_add(paeth(left, up, up_left));
                }
            }
            _ => {}
        }
        prev = row.clone();
        out.extend_from_slice(&row);
    }
    Ok(out)
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let a = a as i32;
    let b = b as i32;
    let c = c as i32;
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

fn name_to_string(n: &PdfName<'_>) -> String {
    String::from_utf8_lossy(&n.decoded).to_string()
}

fn validate_decode_parms(parms: DecodeParms) -> Result<()> {
    if parms.colors > MAX_DECODE_PARMS
        || parms.bits_per_component > MAX_DECODE_PARMS
        || parms.columns > MAX_DECODE_PARMS
    {
        warn!(
            security = true,
            domain = "pdf.decode",
            kind = "decode_parms_out_of_range",
            colors = parms.colors,
            bits = parms.bits_per_component,
            columns = parms.columns,
            "Decode parameters out of range"
        );
        return Err(anyhow!("decode parms exceed safe limits"));
    }
    Ok(())
}

fn checked_bpp(parms: DecodeParms) -> Result<usize> {
    let bpp_bits = (parms.colors as u64)
        .checked_mul(parms.bits_per_component as u64)
        .ok_or_else(|| anyhow!("decode parms overflow"))?;
    let bpp = bpp_bits
        .checked_add(7)
        .ok_or_else(|| anyhow!("decode parms overflow"))?
        / 8;
    usize::try_from(bpp).map_err(|_| anyhow!("decode parms overflow"))
}

fn checked_row_len(parms: DecodeParms, bpp: usize) -> Result<usize> {
    let row_len = (parms.columns as u64)
        .checked_mul(bpp as u64)
        .ok_or_else(|| anyhow!("decode parms overflow"))?;
    usize::try_from(row_len).map_err(|_| anyhow!("decode parms overflow"))
}

fn decode_filter(data: &[u8], filter: &str, max_out: usize) -> Result<(Vec<u8>, bool)> {
    match filter {
        "/FlateDecode" | "/Fl" => decode_flate(data, max_out),
        "/ASCIIHexDecode" | "/AHx" => Ok((decode_ascii_hex(data), false)),
        "/ASCII85Decode" | "/A85" => decode_ascii85(data),
        "/RunLengthDecode" | "/RL" => Ok((decode_run_length(data), false)),
        "/LZWDecode" | "/LZW" => decode_lzw(data, max_out),
        other => Err(anyhow!("unsupported filter {}", other)),
    }
}

fn decode_flate(data: &[u8], max_out: usize) -> Result<(Vec<u8>, bool)> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_out {
            let remaining = max_out.saturating_sub(out.len());
            out.extend_from_slice(&buf[..remaining]);
            truncated = true;
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok((out, truncated))
}

fn decode_lzw(data: &[u8], max_out: usize) -> Result<(Vec<u8>, bool)> {
    let mut decoder = weezl::decode::Decoder::new(weezl::BitOrder::Msb, 8);
    let mut out = Vec::new();
    let mut input = data;
    let mut truncated = false;
    loop {
        let res = decoder.decode_bytes(input, &mut out);
        let consumed = res.consumed_in;
        input = &input[consumed..];
        if res.status.is_ok() {
            break;
        }
        if out.len() > max_out {
            out.truncate(max_out);
            truncated = true;
            break;
        }
        if input.is_empty() {
            break;
        }
    }
    if out.len() > max_out {
        out.truncate(max_out);
        truncated = true;
    }
    Ok((out, truncated))
}

pub fn decode_ascii_hex(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    for &b in data {
        if b == b'>' {
            break;
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        buf.push(b);
    }
    let mut i = 0;
    while i < buf.len() {
        let hi = hex_val(buf[i]);
        let lo = if i + 1 < buf.len() { hex_val(buf[i + 1]) } else { Some(0) };
        if let (Some(h), Some(l)) = (hi, lo) {
            out.push((h << 4) | l);
        }
        i += 2;
    }
    out
}

fn decode_ascii85(data: &[u8]) -> Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut tuple = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if b == b'~' && i + 1 < data.len() && data[i + 1] == b'>' {
            break;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'z' && tuple.is_empty() {
            out.extend_from_slice(&[0, 0, 0, 0]);
            i += 1;
            continue;
        }
        if b < b'!' || b > b'u' {
            i += 1;
            continue;
        }
        tuple.push(b);
        if tuple.len() == 5 {
            let mut value: u32 = 0;
            for &c in &tuple {
                value = value * 85 + (c - 33) as u32;
            }
            out.extend_from_slice(&value.to_be_bytes());
            tuple.clear();
        }
        i += 1;
    }
    if !tuple.is_empty() {
        let mut value: u32 = 0;
        let padding = 5 - tuple.len();
        for &c in &tuple {
            value = value * 85 + (c - 33) as u32;
        }
        for _ in 0..padding {
            value = value * 85 + 84;
        }
        let bytes = value.to_be_bytes();
        out.extend_from_slice(&bytes[..4 - padding]);
    }
    Ok((out, false))
}

fn decode_run_length(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let n = data[i];
        i += 1;
        if n == 128 {
            break;
        } else if n <= 127 {
            let count = (n as usize) + 1;
            if i + count > data.len() {
                break;
            }
            out.extend_from_slice(&data[i..i + count]);
            i += count;
        } else {
            let count = 257 - (n as usize);
            if i >= data.len() {
                break;
            }
            let b = data[i];
            out.extend(std::iter::repeat(b).take(count));
            i += 1;
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

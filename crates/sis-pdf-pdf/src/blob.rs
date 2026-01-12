use anyhow::{anyhow, Result};

use crate::decode::{decode_stream_with_meta, DecodeLimits, DecodeMeta};
use crate::object::PdfStream;

#[derive(Debug, Clone)]
pub enum BlobOrigin {
    Stream { obj: u32, gen: u16 },
    EmbeddedFile { obj: u32, gen: u16 },
    EmbeddedFileNameTree { obj: u32, gen: u16 },
    XfaPackage { obj: u32, gen: u16 },
    String { obj: u32, gen: u16, key: Vec<u8> },
    XrefSpan { start: u64, end: u64 },
    Recovered { heuristic: String },
}

#[derive(Debug, Clone)]
pub enum BlobPathStep {
    Obj { obj: u32, gen: u16 },
    Key(String),
    Index(usize),
    Ref { obj: u32, gen: u16 },
    Stream,
}

#[derive(Debug, Clone)]
pub struct Blob<'a> {
    pub origin: BlobOrigin,
    pub pdf_path: Vec<BlobPathStep>,
    pub raw: &'a [u8],
    pub decoded: Option<Vec<u8>>,
    pub decode_meta: Option<DecodeMeta>,
}

impl<'a> Blob<'a> {
    pub fn from_stream(
        bytes: &'a [u8],
        obj: u32,
        gen: u16,
        stream: &PdfStream<'a>,
        limits: DecodeLimits,
    ) -> Result<Self> {
        let span = stream.data_span;
        let start = span.start as usize;
        let end = span.end as usize;
        if start >= end || end > bytes.len() {
            return Err(anyhow!("invalid stream span"));
        }

        let raw = &bytes[start..end];
        let result = decode_stream_with_meta(bytes, stream, limits);

        Ok(Self {
            origin: BlobOrigin::Stream { obj, gen },
            pdf_path: vec![BlobPathStep::Obj { obj, gen }, BlobPathStep::Stream],
            raw,
            decoded: result.data,
            decode_meta: Some(result.meta),
        })
    }

    pub fn from_embedded_file(
        bytes: &'a [u8],
        file_spec: (u32, u16),
        stream_ref: (u32, u16),
        stream: &PdfStream<'a>,
        limits: DecodeLimits,
        origin: BlobOrigin,
    ) -> Result<Self> {
        let span = stream.data_span;
        let start = span.start as usize;
        let end = span.end as usize;
        if start >= end || end > bytes.len() {
            return Err(anyhow!("invalid stream span"));
        }

        let raw = &bytes[start..end];
        let result = decode_stream_with_meta(bytes, stream, limits);

        Ok(Self {
            origin,
            pdf_path: vec![
                BlobPathStep::Obj {
                    obj: file_spec.0,
                    gen: file_spec.1,
                },
                BlobPathStep::Key("EF".to_string()),
                BlobPathStep::Ref {
                    obj: stream_ref.0,
                    gen: stream_ref.1,
                },
                BlobPathStep::Stream,
            ],
            raw,
            decoded: result.data,
            decode_meta: Some(result.meta),
        })
    }

    pub fn from_xfa_package(
        bytes: &'a [u8],
        container: (u32, u16),
        stream_ref: (u32, u16),
        stream: &PdfStream<'a>,
        limits: DecodeLimits,
    ) -> Result<Self> {
        let span = stream.data_span;
        let start = span.start as usize;
        let end = span.end as usize;
        if start >= end || end > bytes.len() {
            return Err(anyhow!("invalid stream span"));
        }

        let raw = &bytes[start..end];
        let result = decode_stream_with_meta(bytes, stream, limits);

        Ok(Self {
            origin: BlobOrigin::XfaPackage {
                obj: stream_ref.0,
                gen: stream_ref.1,
            },
            pdf_path: vec![
                BlobPathStep::Obj {
                    obj: container.0,
                    gen: container.1,
                },
                BlobPathStep::Key("XFA".to_string()),
                BlobPathStep::Ref {
                    obj: stream_ref.0,
                    gen: stream_ref.1,
                },
                BlobPathStep::Stream,
            ],
            raw,
            decoded: result.data,
            decode_meta: Some(result.meta),
        })
    }
}

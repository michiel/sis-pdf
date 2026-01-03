use crate::span::Span;

#[derive(Debug, Clone)]
pub enum PdfStr<'a> {
    Literal { span: Span, raw: &'a [u8], decoded: Vec<u8> },
    Hex { span: Span, raw: &'a [u8], decoded: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct PdfName<'a> {
    pub span: Span,
    pub raw: &'a [u8],
    pub decoded: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PdfDict<'a> {
    pub span: Span,
    pub entries: Vec<(PdfName<'a>, PdfObj<'a>)>,
}

#[derive(Debug, Clone)]
pub struct PdfStream<'a> {
    pub dict: PdfDict<'a>,
    pub data_span: Span,
}

#[derive(Debug, Clone)]
pub enum PdfAtom<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Name(PdfName<'a>),
    Str(PdfStr<'a>),
    Array(Vec<PdfObj<'a>>),
    Dict(PdfDict<'a>),
    Stream(PdfStream<'a>),
    Ref { obj: u32, gen: u16 },
}

#[derive(Debug, Clone)]
pub struct PdfObj<'a> {
    pub span: Span,
    pub atom: PdfAtom<'a>,
}

impl<'a> PdfDict<'a> {
    pub fn get_first(&self, name: &[u8]) -> Option<(&PdfName<'a>, &PdfObj<'a>)> {
        self.entries
            .iter()
            .find(|(k, _)| k.decoded.eq_ignore_ascii_case(name))
            .map(|(k, v)| (k, v))
    }

    pub fn get_all(&self, name: &[u8]) -> Vec<(&PdfName<'a>, &PdfObj<'a>)> {
        self.entries
            .iter()
            .filter(|(k, _)| k.decoded.eq_ignore_ascii_case(name))
            .map(|(k, v)| (k, v))
            .collect()
    }

    pub fn has_name(&self, key: &[u8], value: &[u8]) -> bool {
        self.entries.iter().any(|(k, v)| {
            k.decoded.eq_ignore_ascii_case(key)
                && match &v.atom {
                    PdfAtom::Name(n) => n.decoded.eq_ignore_ascii_case(value),
                    _ => false,
                }
        })
    }
}

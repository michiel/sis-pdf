#![forbid(unsafe_code)]

pub mod blob;
pub mod blob_classify;
pub mod classification;
pub mod content;
pub mod decode;
pub mod graph;
pub mod ir;
pub mod lexer;
pub mod object;
pub mod objstm;
pub mod parser;
pub mod path_finder;
pub mod span;
pub mod swf;
pub mod typed_graph;
pub mod xfa;
pub mod xref;

pub use crate::graph::{parse_pdf, ObjectGraph, ParseOptions};

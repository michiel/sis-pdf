//! Query command implementation and output formatting helpers.

use anyhow::{anyhow, Result};
use globset::Glob;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{self, json};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use sis_pdf_core::model::Severity;
use sis_pdf_core::scan::ScanContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Csv,
    Dot,
}

impl OutputFormat {
    pub fn parse(input: &str) -> Result<Self> {
        match input {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "jsonl" => Ok(OutputFormat::Jsonl),
            "csv" => Ok(OutputFormat::Csv),
            "dot" => Ok(OutputFormat::Dot),
            _ => Err(anyhow!("invalid format: {input}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    Decode,
    Raw,
    Hexdump,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PredicateExpr {
    And(Box<PredicateExpr>, Box<PredicateExpr>),
    Or(Box<PredicateExpr>, Box<PredicateExpr>),
    Not(Box<PredicateExpr>),
    Compare {
        field: PredicateField,
        op: PredicateOp,
        value: PredicateValue,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateField {
    Length,
    Filter,
    Type,
    Subtype,
    Entropy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateOp {
    Eq,
    NotEq,
    Gt,
    Lt,
    Gte,
    Lte,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PredicateValue {
    Number(f64),
    String(String),
}

#[derive(Debug, Clone)]
struct PredicateContext {
    length: usize,
    filter: Option<String>,
    type_name: String,
    subtype: Option<String>,
    entropy: f64,
}

/// Query types supported by the interface
#[derive(Debug, Clone)]
pub enum Query {
    // Metadata queries
    Pages,
    Objects,
    ObjectsCount,
    Creator,
    Producer,
    Title,
    Created,
    Modified,
    Version,
    Encrypted,
    Filesize,

    // Structure queries
    Trailer,
    Catalog,

    // Content queries
    JavaScript,
    JavaScriptCount,
    Urls,
    UrlsCount,
    Embedded,
    EmbeddedCount,

    // Finding queries
    Findings,
    FindingsCount,
    FindingsBySeverity(Severity),
    FindingsByKind(String),

    // Event trigger queries
    Events,
    EventsCount,
    EventsDocument,
    EventsPage,
    EventsField,

    // Object queries
    ShowObject(u32, u16),
    ObjectsList,
    ObjectsWithType(String),

    // Advanced queries
    Chains,
    ChainsJs,
    Cycles,
    CyclesPage,

    // Export queries
    ExportOrgDot,
    ExportOrgJson,
    ExportIrText,
    ExportIrJson,
    ExportFeatures,
    ExportFeaturesJson,

    // Reference queries
    References(u32, u16),
}

/// Query result that can be serialized to JSON or formatted as text
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum QueryResult {
    Scalar(ScalarValue),
    List(Vec<String>),
    Structure(serde_json::Value),
    Error(QueryError),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ScalarValue {
    String(String),
    Number(i64),
    Boolean(bool),
}

#[derive(Debug, Serialize)]
pub struct QueryError {
    pub status: &'static str,
    pub error_code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Parse a query string into a Query enum
pub fn parse_query(input: &str) -> Result<Query> {
    let input = input.trim();

    match input {
        // Metadata
        "pages" => Ok(Query::Pages),
        "objects" => Ok(Query::ObjectsCount),
        "objects.count" => Ok(Query::ObjectsCount),
        "objects.list" => Ok(Query::ObjectsList),
        "creator" => Ok(Query::Creator),
        "producer" => Ok(Query::Producer),
        "title" => Ok(Query::Title),
        "created" => Ok(Query::Created),
        "modified" => Ok(Query::Modified),
        "version" => Ok(Query::Version),
        "encrypted" => Ok(Query::Encrypted),
        "filesize" => Ok(Query::Filesize),

        // Structure
        "trailer" => Ok(Query::Trailer),
        "catalog" => Ok(Query::Catalog),

        // Content
        "js" | "javascript" => Ok(Query::JavaScript),
        "js.count" => Ok(Query::JavaScriptCount),
        "urls" | "uris" => Ok(Query::Urls),
        "urls.count" => Ok(Query::UrlsCount),
        "embedded" => Ok(Query::Embedded),
        "embedded.count" => Ok(Query::EmbeddedCount),

        // Findings
        "findings" => Ok(Query::Findings),
        "findings.count" => Ok(Query::FindingsCount),
        "findings.high" => Ok(Query::FindingsBySeverity(Severity::High)),
        "findings.medium" => Ok(Query::FindingsBySeverity(Severity::Medium)),
        "findings.low" => Ok(Query::FindingsBySeverity(Severity::Low)),
        "findings.info" => Ok(Query::FindingsBySeverity(Severity::Info)),
        "findings.critical" => Ok(Query::FindingsBySeverity(Severity::Critical)),

        // Events
        "events" => Ok(Query::Events),
        "events.count" => Ok(Query::EventsCount),
        "events.document" => Ok(Query::EventsDocument),
        "events.page" => Ok(Query::EventsPage),
        "events.field" => Ok(Query::EventsField),

        // Advanced
        "chains" => Ok(Query::Chains),
        "chains.js" => Ok(Query::ChainsJs),
        "cycles" => Ok(Query::Cycles),
        "cycles.page" => Ok(Query::CyclesPage),

        // Export queries
        "graph.org" => Ok(Query::ExportOrgDot),
        "graph.org.dot" => Ok(Query::ExportOrgDot),
        "graph.org.json" => Ok(Query::ExportOrgJson),
        "graph.ir" => Ok(Query::ExportIrText),
        "graph.ir.text" => Ok(Query::ExportIrText),
        "graph.ir.json" => Ok(Query::ExportIrJson),
        "features" => Ok(Query::ExportFeatures),
        "features.csv" => Ok(Query::ExportFeatures),
        "features.json" => Ok(Query::ExportFeaturesJson),

        _ => {
            // Try to parse ref/references query
            if let Some(rest) = input.strip_prefix("ref ").or(input.strip_prefix("references ")) {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 1 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    return Ok(Query::References(obj, 0));
                } else if parts.len() == 2 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts[1]
                        .parse::<u16>()
                        .map_err(|_| anyhow!("Invalid generation number: {}", parts[1]))?;
                    return Ok(Query::References(obj, gen));
                }
                return Err(anyhow!("Invalid ref query format"));
            }

            // Try to parse object queries
            if let Some(rest) = input.strip_prefix("object ").or(input.strip_prefix("obj ")) {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 1 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    return Ok(Query::ShowObject(obj, 0));
                } else if parts.len() == 2 {
                    let obj = parts[0]
                        .parse::<u32>()
                        .map_err(|_| anyhow!("Invalid object number: {}", parts[0]))?;
                    let gen = parts[1]
                        .parse::<u16>()
                        .map_err(|_| anyhow!("Invalid generation number: {}", parts[1]))?;
                    return Ok(Query::ShowObject(obj, gen));
                }
            }

            // Try to parse findings.kind query
            if let Some(kind) = input.strip_prefix("findings.kind ") {
                return Ok(Query::FindingsByKind(kind.to_string()));
            }

            // Try to parse objects.with query
            if let Some(obj_type) = input.strip_prefix("objects.with ") {
                return Ok(Query::ObjectsWithType(obj_type.to_string()));
            }

            Err(anyhow!("Unknown query: {}", input))
        }
    }
}

pub fn parse_predicate(input: &str) -> Result<PredicateExpr> {
    let mut parser = PredicateParser::new(input);
    let expr = parser.parse_expr()?;
    parser.expect_end()?;
    Ok(expr)
}

struct PredicateParser<'a> {
    lexer: PredicateLexer<'a>,
    lookahead: Option<PredicateToken>,
}

impl<'a> PredicateParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            lexer: PredicateLexer::new(input),
            lookahead: None,
        }
    }

    fn parse_expr(&mut self) -> Result<PredicateExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<PredicateExpr> {
        let mut expr = self.parse_and()?;
        while self.peek_is_keyword("OR") {
            self.next_token();
            let rhs = self.parse_and()?;
            expr = PredicateExpr::Or(Box::new(expr), Box::new(rhs));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<PredicateExpr> {
        let mut expr = self.parse_not()?;
        while self.peek_is_keyword("AND") {
            self.next_token();
            let rhs = self.parse_not()?;
            expr = PredicateExpr::And(Box::new(expr), Box::new(rhs));
        }
        Ok(expr)
    }

    fn parse_not(&mut self) -> Result<PredicateExpr> {
        if self.peek_is_keyword("NOT") {
            self.next_token();
            let expr = self.parse_not()?;
            Ok(PredicateExpr::Not(Box::new(expr)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<PredicateExpr> {
        if self.peek_is_token(&PredicateToken::LParen) {
            self.next_token();
            let expr = self.parse_expr()?;
            self.expect_token(&PredicateToken::RParen)?;
            Ok(expr)
        } else {
            self.parse_comparison()
        }
    }

    fn parse_comparison(&mut self) -> Result<PredicateExpr> {
        let field_name = self.expect_ident()?;
        let field = parse_predicate_field(&field_name)?;
        let op = self.expect_op()?;
        let value = self.expect_value()?;
        Ok(PredicateExpr::Compare { field, op, value })
    }

    fn expect_value(&mut self) -> Result<PredicateValue> {
        match self.next_token().ok_or_else(|| anyhow!("Expected value"))? {
            PredicateToken::Number(value) => Ok(PredicateValue::Number(value)),
            PredicateToken::String(value) => Ok(PredicateValue::String(value)),
            token => Err(anyhow!("Unexpected token in value: {:?}", token)),
        }
    }

    fn expect_op(&mut self) -> Result<PredicateOp> {
        match self.next_token().ok_or_else(|| anyhow!("Expected operator"))? {
            PredicateToken::Op(op) => Ok(op),
            token => Err(anyhow!("Unexpected token in operator: {:?}", token)),
        }
    }

    fn expect_ident(&mut self) -> Result<String> {
        match self.next_token().ok_or_else(|| anyhow!("Expected identifier"))? {
            PredicateToken::Ident(value) => Ok(value),
            token => Err(anyhow!("Unexpected token in identifier: {:?}", token)),
        }
    }

    fn expect_token(&mut self, expected: &PredicateToken) -> Result<()> {
        let token = self.next_token().ok_or_else(|| anyhow!("Expected token"))?;
        if &token == expected {
            Ok(())
        } else {
            Err(anyhow!("Expected {:?}, got {:?}", expected, token))
        }
    }

    fn peek_is_keyword(&mut self, keyword: &str) -> bool {
        matches!(self.peek_token(), Some(PredicateToken::Keyword(k)) if k == keyword)
    }

    fn peek_is_token(&mut self, token: &PredicateToken) -> bool {
        matches!(self.peek_token(), Some(current) if current == *token)
    }

    fn peek_token(&mut self) -> Option<PredicateToken> {
        if self.lookahead.is_none() {
            self.lookahead = self.lexer.next_token();
        }
        self.lookahead.clone()
    }

    fn next_token(&mut self) -> Option<PredicateToken> {
        if let Some(token) = self.lookahead.take() {
            Some(token)
        } else {
            self.lexer.next_token()
        }
    }

    fn expect_end(&mut self) -> Result<()> {
        if self.next_token().is_some() {
            Err(anyhow!("Unexpected trailing input in predicate"))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum PredicateToken {
    Ident(String),
    String(String),
    Number(f64),
    Op(PredicateOp),
    Keyword(String),
    LParen,
    RParen,
}

struct PredicateLexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    index: usize,
}

impl<'a> PredicateLexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            index: 0,
        }
    }

    fn next_token(&mut self) -> Option<PredicateToken> {
        self.skip_whitespace();
        if self.index >= self.bytes.len() {
            return None;
        }

        let ch = self.bytes[self.index];
        match ch {
            b'(' => {
                self.index += 1;
                Some(PredicateToken::LParen)
            }
            b')' => {
                self.index += 1;
                Some(PredicateToken::RParen)
            }
            b'\'' | b'"' => self.lex_string(ch),
            b'>' | b'<' | b'=' | b'!' => self.lex_operator(),
            b'0'..=b'9' => self.lex_number(),
            _ => {
                if is_ident_start(ch) {
                    self.lex_identifier()
                } else {
                    self.index += 1;
                    self.next_token()
                }
            }
        }
    }

    fn skip_whitespace(&mut self) {
        while self.index < self.bytes.len() && self.bytes[self.index].is_ascii_whitespace() {
            self.index += 1;
        }
    }

    fn lex_string(&mut self, quote: u8) -> Option<PredicateToken> {
        self.index += 1;
        let mut out = String::new();
        while self.index < self.bytes.len() {
            let ch = self.bytes[self.index];
            self.index += 1;
            if ch == quote {
                break;
            }
            if ch == b'\\' && self.index < self.bytes.len() {
                let escaped = self.bytes[self.index];
                self.index += 1;
                out.push(escaped as char);
            } else {
                out.push(ch as char);
            }
        }
        Some(PredicateToken::String(out))
    }

    fn lex_operator(&mut self) -> Option<PredicateToken> {
        let start = self.index;
        let end = usize::min(self.index + 2, self.bytes.len());
        let slice = &self.bytes[start..end];
        let op = if slice.starts_with(b">=") {
            self.index += 2;
            Some(PredicateOp::Gte)
        } else if slice.starts_with(b"<=") {
            self.index += 2;
            Some(PredicateOp::Lte)
        } else if slice.starts_with(b"==") {
            self.index += 2;
            Some(PredicateOp::Eq)
        } else if slice.starts_with(b"!=") {
            self.index += 2;
            Some(PredicateOp::NotEq)
        } else {
            let ch = self.bytes[self.index];
            self.index += 1;
            match ch {
                b'>' => Some(PredicateOp::Gt),
                b'<' => Some(PredicateOp::Lt),
                _ => None,
            }
        };

        op.map(PredicateToken::Op)
    }

    fn lex_number(&mut self) -> Option<PredicateToken> {
        let start = self.index;
        let mut seen_dot = false;
        while self.index < self.bytes.len() {
            let ch = self.bytes[self.index];
            if ch == b'.' && !seen_dot {
                seen_dot = true;
                self.index += 1;
                continue;
            }
            if !ch.is_ascii_digit() {
                break;
            }
            self.index += 1;
        }

        let value = self.input[start..self.index].parse::<f64>().ok()?;
        Some(PredicateToken::Number(value))
    }

    fn lex_identifier(&mut self) -> Option<PredicateToken> {
        let start = self.index;
        self.index += 1;
        while self.index < self.bytes.len() {
            let ch = self.bytes[self.index];
            if is_ident_continue(ch) {
                self.index += 1;
            } else {
                break;
            }
        }
        let ident = &self.input[start..self.index];
        let upper = ident.to_ascii_uppercase();
        match upper.as_str() {
            "AND" | "OR" | "NOT" => Some(PredicateToken::Keyword(upper)),
            _ => Some(PredicateToken::Ident(ident.to_string())),
        }
    }
}

fn is_ident_start(ch: u8) -> bool {
    ch.is_ascii_alphabetic() || ch == b'_'
}

fn is_ident_continue(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'.'
}

fn parse_predicate_field(name: &str) -> Result<PredicateField> {
    let lower = name.to_ascii_lowercase();
    let field = if lower.ends_with(".length") || lower == "length" {
        PredicateField::Length
    } else if lower.ends_with(".filter") || lower == "filter" {
        PredicateField::Filter
    } else if lower.ends_with(".type") || lower == "type" {
        PredicateField::Type
    } else if lower.ends_with(".subtype") || lower == "subtype" {
        PredicateField::Subtype
    } else if lower.ends_with(".entropy") || lower == "entropy" {
        PredicateField::Entropy
    } else {
        return Err(anyhow!("Unknown predicate field: {}", name));
    };
    Ok(field)
}

impl PredicateExpr {
    fn evaluate(&self, ctx: &PredicateContext) -> bool {
        match self {
            PredicateExpr::And(lhs, rhs) => lhs.evaluate(ctx) && rhs.evaluate(ctx),
            PredicateExpr::Or(lhs, rhs) => lhs.evaluate(ctx) || rhs.evaluate(ctx),
            PredicateExpr::Not(expr) => !expr.evaluate(ctx),
            PredicateExpr::Compare { field, op, value } => match field {
                PredicateField::Length => compare_number(ctx.length as f64, *op, value),
                PredicateField::Entropy => compare_number(ctx.entropy, *op, value),
                PredicateField::Filter => compare_string(ctx.filter.as_deref(), *op, value),
                PredicateField::Type => compare_string(Some(ctx.type_name.as_str()), *op, value),
                PredicateField::Subtype => compare_string(ctx.subtype.as_deref(), *op, value),
            },
        }
    }
}

fn compare_number(lhs: f64, op: PredicateOp, value: &PredicateValue) -> bool {
    let rhs = match value {
        PredicateValue::Number(value) => *value,
        PredicateValue::String(_) => return false,
    };
    match op {
        PredicateOp::Eq => lhs == rhs,
        PredicateOp::NotEq => lhs != rhs,
        PredicateOp::Gt => lhs > rhs,
        PredicateOp::Lt => lhs < rhs,
        PredicateOp::Gte => lhs >= rhs,
        PredicateOp::Lte => lhs <= rhs,
    }
}

fn compare_string(lhs: Option<&str>, op: PredicateOp, value: &PredicateValue) -> bool {
    let rhs = match value {
        PredicateValue::String(value) => value.as_str(),
        PredicateValue::Number(_) => return false,
    };
    let lhs = match lhs {
        Some(value) => value,
        None => return false,
    };
    match op {
        PredicateOp::Eq => lhs == rhs,
        PredicateOp::NotEq => lhs != rhs,
        _ => false,
    }
}

pub fn apply_output_format(query: Query, format: OutputFormat) -> Result<Query> {
    let resolved = match format {
        OutputFormat::Json | OutputFormat::Jsonl => match query {
            Query::ExportOrgDot => Query::ExportOrgJson,
            Query::ExportIrText => Query::ExportIrJson,
            Query::ExportFeatures => Query::ExportFeaturesJson,
            other => other,
        },
        OutputFormat::Dot => match query {
            Query::ExportOrgJson | Query::ExportOrgDot => Query::ExportOrgDot,
            _ => {
                return Err(anyhow!(
                    "--format dot is only supported for graph.org queries"
                ))
            }
        },
        OutputFormat::Csv => match query {
            Query::ExportFeatures | Query::ExportFeaturesJson => Query::ExportFeatures,
            _ => {
                return Err(anyhow!(
                    "--format csv is only supported for features queries"
                ))
            }
        },
        OutputFormat::Text => match query {
            Query::ExportOrgJson => Query::ExportOrgDot,
            Query::ExportIrJson => Query::ExportIrText,
            Query::ExportFeaturesJson => Query::ExportFeatures,
            other => other,
        },
    };

    Ok(resolved)
}

/// Build a scan context (public version for REPL caching)
pub fn build_scan_context_public<'a>(
    bytes: &'a [u8],
    options: &ScanOptions,
) -> Result<sis_pdf_core::scan::ScanContext<'a>> {
    build_scan_context(bytes, options)
}

/// Execute a query using a pre-built context (for REPL mode)
pub fn execute_query_with_context(
    query: &Query,
    ctx: &ScanContext,
    extract_to: Option<&Path>,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<QueryResult> {
    let result = (|| {
        if predicate.is_some()
            && !matches!(
                query,
                Query::JavaScript
                    | Query::JavaScriptCount
                    | Query::Embedded
                    | Query::EmbeddedCount
                    | Query::Urls
                    | Query::UrlsCount
                    | Query::Events
                    | Query::EventsCount
                    | Query::EventsDocument
                    | Query::EventsPage
                    | Query::EventsField
                    | Query::Findings
                    | Query::FindingsCount
                    | Query::FindingsBySeverity(_)
                    | Query::FindingsByKind(_)
                    | Query::ObjectsCount
                    | Query::ObjectsList
                    | Query::ObjectsWithType(_)
            )
        {
            ensure_predicate_supported(query)?;
        }

        match query {
            Query::Pages => {
                let count = count_pages(ctx)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::ObjectsCount => {
                let count = count_objects(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::Creator => {
                let creator = get_metadata_field(ctx, "Creator")?;
                Ok(QueryResult::Scalar(ScalarValue::String(creator)))
            }
            Query::Producer => {
                let producer = get_metadata_field(ctx, "Producer")?;
                Ok(QueryResult::Scalar(ScalarValue::String(producer)))
            }
            Query::Title => {
                let title = get_metadata_field(ctx, "Title")?;
                Ok(QueryResult::Scalar(ScalarValue::String(title)))
            }
            Query::Version => {
                let version = get_pdf_version(ctx.bytes)?;
                Ok(QueryResult::Scalar(ScalarValue::String(version)))
            }
            Query::Encrypted => {
                let encrypted = is_encrypted(ctx)?;
                Ok(QueryResult::Scalar(ScalarValue::Boolean(encrypted)))
            }
            Query::Filesize => Ok(QueryResult::Scalar(ScalarValue::Number(
                ctx.bytes.len() as i64
            ))),
            Query::FindingsCount => {
                let findings = run_detectors(ctx)?;
                let filtered = filter_findings(findings, predicate);
                Ok(QueryResult::Scalar(ScalarValue::Number(
                    filtered.len() as i64
                )))
            }
            Query::FindingsBySeverity(severity) => {
                let findings = run_detectors(ctx)?;
                let filtered: Vec<sis_pdf_core::model::Finding> = findings
                    .into_iter()
                    .filter(|f| &f.severity == severity)
                    .collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::FindingsByKind(kind) => {
                let findings = run_detectors(ctx)?;
                let filtered: Vec<sis_pdf_core::model::Finding> = findings
                    .into_iter()
                    .filter(|f| f.kind == *kind)
                    .collect();
                let filtered = filter_findings(filtered, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::Findings => {
                let findings = run_detectors(ctx)?;
                let filtered = filter_findings(findings, predicate);
                Ok(QueryResult::Structure(json!(filtered)))
            }
            Query::JavaScript => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    // Extract to disk
                    let written = write_js_files(
                        ctx,
                        extract_path,
                        max_extract_bytes,
                        decode_mode,
                        predicate,
                    )?;
                    Ok(QueryResult::List(written))
                } else {
                    // Return preview list
                    let js_code = extract_javascript(ctx, decode_mode, predicate)?;
                    Ok(QueryResult::List(js_code))
                }
            }
            Query::JavaScriptCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let js_code = extract_javascript(ctx, decode_mode, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(
                    js_code.len() as i64
                )))
            }
            Query::Urls => {
                let urls = extract_urls(ctx, predicate)?;
                Ok(QueryResult::List(urls))
            }
            Query::UrlsCount => {
                let urls = extract_urls(ctx, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(urls.len() as i64)))
            }
            Query::Embedded => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                if let Some(extract_path) = extract_to {
                    // Extract to disk
                    let written = write_embedded_files(
                        ctx,
                        extract_path,
                        max_extract_bytes,
                        decode_mode,
                        predicate,
                    )?;
                    Ok(QueryResult::List(written))
                } else {
                    // Return preview list
                    let embedded = extract_embedded_files(ctx, decode_mode, predicate)?;
                    Ok(QueryResult::List(embedded))
                }
            }
            Query::EmbeddedCount => {
                if predicate.is_some() {
                    ensure_predicate_supported(query)?;
                }
                let embedded = extract_embedded_files(ctx, decode_mode, predicate)?;
                Ok(QueryResult::Scalar(ScalarValue::Number(
                    embedded.len() as i64
                )))
            }
            Query::Created => {
                let created = get_metadata_field(ctx, "CreationDate")?;
                Ok(QueryResult::Scalar(ScalarValue::String(created)))
            }
            Query::Modified => {
                let modified = get_metadata_field(ctx, "ModDate")?;
                Ok(QueryResult::Scalar(ScalarValue::String(modified)))
            }
            Query::ShowObject(obj, gen) => {
                let obj_str = show_object(ctx, *obj, *gen)?;
                Ok(QueryResult::Scalar(ScalarValue::String(obj_str)))
            }
            Query::ObjectsList => {
                let objects = list_objects(ctx, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::List(objects))
            }
            Query::ObjectsWithType(obj_type) => {
                let objects =
                    list_objects_with_type(ctx, obj_type, decode_mode, max_extract_bytes, predicate)?;
                Ok(QueryResult::List(objects))
            }
            Query::Trailer => {
                let trailer_str = show_trailer(ctx)?;
                Ok(QueryResult::Scalar(ScalarValue::String(trailer_str)))
            }
            Query::Catalog => {
                let catalog_str = show_catalog(ctx)?;
                Ok(QueryResult::Scalar(ScalarValue::String(catalog_str)))
            }
            Query::Chains => {
                let chains = list_action_chains(ctx)?;
                Ok(QueryResult::Structure(chains))
            }
            Query::ChainsJs => {
                let chains = list_js_chains(ctx)?;
                Ok(QueryResult::Structure(chains))
            }
            Query::Cycles => {
                let cycles = list_cycles(ctx)?;
                Ok(QueryResult::Structure(cycles))
            }
            Query::CyclesPage => {
                let cycles = list_page_cycles(ctx)?;
                Ok(QueryResult::Structure(cycles))
            }
            Query::References(obj, gen) => {
                let references = list_references(ctx, *obj, *gen)?;
                Ok(QueryResult::Structure(references))
            }
            Query::Events => {
                let events = extract_event_triggers(ctx, None, predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::EventsCount => {
                let events_json = extract_event_triggers(ctx, None, predicate)?;
                let count = events_json.as_array().map(|arr| arr.len()).unwrap_or(0);
                Ok(QueryResult::Scalar(ScalarValue::Number(count as i64)))
            }
            Query::EventsDocument => {
                let events = extract_event_triggers(ctx, Some("document"), predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::EventsPage => {
                let events = extract_event_triggers(ctx, Some("page"), predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::EventsField => {
                let events = extract_event_triggers(ctx, Some("field"), predicate)?;
                Ok(QueryResult::Structure(events))
            }
            Query::ExportOrgDot => {
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph(&ctx.graph);
                let dot_output = sis_pdf_core::org_export::export_org_dot(&org_graph);
                Ok(QueryResult::Scalar(ScalarValue::String(dot_output)))
            }
            Query::ExportOrgJson => {
                let org_graph = sis_pdf_core::org::OrgGraph::from_object_graph(&ctx.graph);
                let json_output = sis_pdf_core::org_export::export_org_json(&org_graph);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportIrText => {
                let ir_opts = sis_pdf_pdf::ir::IrOptions {
                    max_lines_per_object: 256,
                    max_string_len: 120,
                    max_array_elems: 128,
                };
                let ir_artifacts = sis_pdf_core::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
                let text_output = sis_pdf_core::ir_export::export_ir_text(&ir_artifacts.ir_objects);
                Ok(QueryResult::Scalar(ScalarValue::String(text_output)))
            }
            Query::ExportIrJson => {
                let ir_opts = sis_pdf_pdf::ir::IrOptions {
                    max_lines_per_object: 256,
                    max_string_len: 120,
                    max_array_elems: 128,
                };
                let ir_artifacts = sis_pdf_core::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
                let json_output = sis_pdf_core::ir_export::export_ir_json(&ir_artifacts.ir_objects);
                Ok(QueryResult::Structure(json_output))
            }
            Query::ExportFeatures => {
                let features = sis_pdf_core::features::FeatureExtractor::extract(ctx);
                let feature_names = sis_pdf_core::features::feature_names();
                let feature_values = features.as_f32_vec();

                // Create CSV output
                let mut csv_output = String::new();
                csv_output.push_str("feature,value\n");
                for (name, value) in feature_names.iter().zip(feature_values.iter()) {
                    csv_output.push_str(&format!("{},{}\n", name, value));
                }

                Ok(QueryResult::Scalar(ScalarValue::String(csv_output)))
            }
            Query::ExportFeaturesJson => {
                let features = sis_pdf_core::features::FeatureExtractor::extract(ctx);
                let feature_names = sis_pdf_core::features::feature_names();
                let feature_values = features.as_f32_vec();
                let mut values = serde_json::Map::new();

                for (name, value) in feature_names.iter().zip(feature_values.iter()) {
                    values.insert(name.to_string(), json!(value));
                }

                Ok(QueryResult::Structure(serde_json::Value::Object(values)))
            }
            _ => Err(anyhow!("Query not yet implemented: {:?}", query)),
        }
    })();

    result.or_else(|err| Ok(QueryResult::Error(build_query_error(err))))
}

/// Execute a query against a PDF file
pub fn execute_query(
    query: &Query,
    pdf_path: &Path,
    scan_options: &ScanOptions,
    extract_to: Option<&Path>,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<QueryResult> {
    // Read PDF file
    let bytes = fs::read(pdf_path)?;

    // Parse PDF and build context
    let ctx = build_scan_context(&bytes, scan_options)?;

    // Delegate to execute_query_with_context
    execute_query_with_context(
        query,
        &ctx,
        extract_to,
        max_extract_bytes,
        decode_mode,
        predicate,
    )
}

/// Scan options for query execution
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub max_total_decoded_bytes: usize,
    pub no_recover: bool,
    pub max_objects: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            no_recover: false,
            max_objects: 500_000,
        }
    }
}

// Helper functions (stubs for now, will be implemented)

fn build_scan_context<'a>(
    bytes: &'a [u8],
    options: &ScanOptions,
) -> Result<sis_pdf_core::scan::ScanContext<'a>> {
    let scan_options = sis_pdf_core::scan::ScanOptions {
        recover_xref: !options.no_recover,
        deep: options.deep,
        max_decode_bytes: options.max_decode_bytes,
        max_total_decoded_bytes: options.max_total_decoded_bytes,
        strict: false,
        strict_summary: false,
        diff_parser: false,
        fast: false,
        focus_trigger: None,
        yara_scope: None,
        focus_depth: 5,
        ir: false,
        max_objects: options.max_objects,
        max_recursion_depth: 64,
        parallel: false,
        batch_parallel: false,
        ml_config: None,
        font_analysis: sis_pdf_core::scan::FontAnalysisOptions::default(),
        profile: false,
        profile_format: sis_pdf_core::scan::ProfileFormat::Text,
    };

    // Parse PDF
    let graph = sis_pdf_pdf::parse_pdf(
        bytes,
        sis_pdf_pdf::ParseOptions {
            recover_xref: scan_options.recover_xref,
            deep: scan_options.deep,
            strict: scan_options.strict,
            max_objstm_bytes: scan_options.max_decode_bytes,
            max_objects: scan_options.max_objects,
            max_objstm_total_bytes: scan_options.max_total_decoded_bytes,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )?;

    Ok(sis_pdf_core::scan::ScanContext::new(
        bytes,
        graph,
        scan_options,
    ))
}

fn count_pages(ctx: &ScanContext) -> Result<usize> {
    // Fallback: count Page objects
    let mut page_count = 0;
    for obj in &ctx.graph.objects {
        if let sis_pdf_pdf::object::PdfAtom::Dict(dict) = &obj.atom {
            for (key, value) in &dict.entries {
                let key_bytes = &key.decoded;
                if key_bytes.as_slice() == b"/Type" || key_bytes.as_slice() == b"Type" {
                    if let sis_pdf_pdf::object::PdfAtom::Name(name) = &value.atom {
                        let name_bytes = &name.decoded;
                        if name_bytes.as_slice() == b"/Page" || name_bytes.as_slice() == b"Page" {
                            page_count += 1;
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(page_count)
}

fn get_metadata_field(ctx: &ScanContext, field: &str) -> Result<String> {
    // Look for /Info dictionary in the trailer
    if let Some(trailer) = ctx.graph.trailers.first() {
        // Find /Info entry
        for (key, value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes.as_slice() == b"/Info" || key_bytes.as_slice() == b"Info" {
                // Resolve the reference
                if let sis_pdf_pdf::object::PdfAtom::Ref { obj, gen } = &value.atom {
                    if let Some(info_obj) = ctx.graph.get_object(*obj, *gen) {
                        if let sis_pdf_pdf::object::PdfAtom::Dict(dict) = &info_obj.atom {
                            let field_bytes = format!("/{}", field).into_bytes();
                            let field_bytes_alt = field.as_bytes().to_vec();

                            for (k, v) in &dict.entries {
                                let k_bytes = &k.decoded;
                                if k_bytes.as_slice() == field_bytes.as_slice()
                                    || k_bytes.as_slice() == field_bytes_alt.as_slice()
                                {
                                    if let sis_pdf_pdf::object::PdfAtom::Str(s) = &v.atom {
                                        let decoded = match s {
                                            sis_pdf_pdf::object::PdfStr::Literal {
                                                decoded,
                                                ..
                                            } => decoded,
                                            sis_pdf_pdf::object::PdfStr::Hex {
                                                decoded, ..
                                            } => decoded,
                                        };
                                        return Ok(decode_pdf_text_string(decoded));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(String::new())
}

/// Decode a PDF text string, handling UTF-16BE with BOM or PDFDocEncoding
fn decode_pdf_text_string(bytes: &[u8]) -> String {
    // Check for UTF-16BE BOM (0xFE 0xFF)
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        // UTF-16BE encoding
        let utf16_bytes = &bytes[2..];
        if utf16_bytes.len() % 2 != 0 {
            // Invalid UTF-16 (odd number of bytes after BOM)
            return String::from_utf8_lossy(bytes).to_string();
        }

        // Convert byte pairs to u16 values (big-endian)
        let utf16_chars: Vec<u16> = utf16_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();

        // Decode UTF-16 to String
        String::from_utf16(&utf16_chars)
            .unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string())
    } else {
        // PDFDocEncoding or plain ASCII/Latin-1
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn get_pdf_version(bytes: &[u8]) -> Result<String> {
    // Look for %PDF-X.Y header
    if bytes.len() < 8 {
        return Ok("unknown".to_string());
    }

    if &bytes[0..5] == b"%PDF-" {
        if let Ok(header) = std::str::from_utf8(&bytes[0..8]) {
            return Ok(header[5..].to_string());
        }
    }

    Ok("unknown".to_string())
}

fn is_encrypted(ctx: &ScanContext) -> Result<bool> {
    // Look for /Encrypt entry in trailer
    if let Some(trailer) = ctx.graph.trailers.first() {
        for (key, _value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes.as_slice() == b"/Encrypt" || key_bytes.as_slice() == b"Encrypt" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn run_detectors(ctx: &ScanContext) -> Result<Vec<sis_pdf_core::model::Finding>> {
    let detectors = sis_pdf_detectors::default_detectors();
    let mut findings = Vec::new();

    for detector in detectors {
        match detector.run(ctx) {
            Ok(mut det_findings) => findings.append(&mut det_findings),
            Err(e) => {
                // Log error but continue with other detectors
                eprintln!("Detector {} failed: {}", detector.id(), e);
            }
        }
    }

    Ok(findings)
}

fn impact_from_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "None",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

/// Format query result as human-readable text
pub fn format_result(result: &QueryResult, compact: bool) -> String {
    match result {
        QueryResult::Scalar(ScalarValue::String(s)) => s.clone(),
        QueryResult::Scalar(ScalarValue::Number(n)) => n.to_string(),
        QueryResult::Scalar(ScalarValue::Boolean(b)) => {
            if compact {
                if *b { "true" } else { "false" }.to_string()
            } else {
                if *b { "yes" } else { "no" }.to_string()
            }
        }
        QueryResult::List(items) => {
            if compact {
                items.len().to_string()
            } else {
                items.join("\n")
            }
        }
        QueryResult::Structure(v) => {
            serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string())
        }
        QueryResult::Error(err) => err.message.clone(),
    }
}

/// Format query result as JSON
pub fn format_json(query: &str, file: &str, result: &QueryResult) -> Result<String> {
    let output = serde_json::json!({
        "query": query,
        "file": file,
        "result": result,
    });

    Ok(serde_json::to_string_pretty(&output)?)
}

/// Format query result as JSON Lines (single line per result)
pub fn format_jsonl(query: &str, file: &str, result: &QueryResult) -> Result<String> {
    let output = serde_json::json!({
        "query": query,
        "file": file,
        "result": result,
    });

    Ok(serde_json::to_string(&output)?)
}

/// Extract JavaScript code from PDF
fn extract_javascript(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let mut js_code = Vec::new();

    for entry in &ctx.graph.objects {
        // Check for /JS entry in dictionary or stream
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some((bytes, meta)) = extract_obj_with_metadata(
                    &ctx.graph,
                    ctx.bytes,
                    obj,
                    32 * 1024 * 1024,
                    decode_mode,
                ) {
                    if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                        if let Some(code) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                            js_code.push(format!(
                                "Object {}_{}: {}",
                                entry.obj,
                                entry.gen,
                                preview_text(&code, 200)
                            ));
                        } else if decode_mode == DecodeMode::Raw {
                            js_code.push(format!(
                                "Object {}_{}: {} bytes (raw)",
                                entry.obj,
                                entry.gen,
                                bytes.len()
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(js_code)
}

/// Extract URLs from PDF
fn extract_urls(ctx: &ScanContext, predicate: Option<&PredicateExpr>) -> Result<Vec<String>> {
    let mut urls = Vec::new();

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Check for /URI entry (Action dictionaries)
            if let Some((_, obj)) = dict.get_first(b"/URI") {
                if let Some(uri) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                    urls.push(uri);
                }
            }

            // Check for /URL entry (some PDFs use this)
            if let Some((_, obj)) = dict.get_first(b"/URL") {
                if let Some(url) = extract_obj_text(&ctx.graph, ctx.bytes, obj) {
                    urls.push(url);
                }
            }
        }
    }

    // Deduplicate
    urls.sort();
    urls.dedup();

    if let Some(pred) = predicate {
        let filtered = urls
            .into_iter()
            .filter(|url| pred.evaluate(&predicate_context_for_url(url)))
            .collect();
        Ok(filtered)
    } else {
        Ok(urls)
    }
}

/// Extract embedded files information from PDF
fn extract_embedded_files(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut embedded = Vec::new();

    for entry in &ctx.graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                let data = stream_bytes_for_mode(ctx.bytes, st, 32 * 1024 * 1024, decode_mode)?;
                let meta = PredicateContext {
                    length: data.len(),
                    filter: filter_name(&st.dict),
                    type_name: "Stream".to_string(),
                    subtype: subtype_name(&st.dict),
                    entropy: entropy_score(&data),
                };
                if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                    let name = embedded_filename(&st.dict)
                        .unwrap_or_else(|| format!("embedded_{}_{}.bin", entry.obj, entry.gen));
                    embedded.push(format!(
                        "{} ({}_{}, {} bytes)",
                        name,
                        entry.obj,
                        entry.gen,
                        data.len()
                    ));
                }
            }
        }
    }

    Ok(embedded)
}

fn ensure_predicate_supported(query: &Query) -> Result<()> {
    match query {
        Query::JavaScript
        | Query::JavaScriptCount
        | Query::Embedded
        | Query::EmbeddedCount
        | Query::Urls
        | Query::UrlsCount
        | Query::Events
        | Query::EventsCount
        | Query::EventsDocument
        | Query::EventsPage
        | Query::EventsField
        | Query::Findings
        | Query::FindingsCount
        | Query::FindingsBySeverity(_)
        | Query::FindingsByKind(_)
        | Query::ObjectsCount
        | Query::ObjectsList
        | Query::ObjectsWithType(_) => Ok(()),
        _ => Err(anyhow!(
            "Predicate filtering is only supported for js, embedded, urls, events, findings, and objects queries"
        )),
    }
}

/// Extract event triggers from PDF
fn extract_event_triggers(
    ctx: &ScanContext,
    filter_level: Option<&str>,
    predicate: Option<&PredicateExpr>,
) -> Result<serde_json::Value> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut events = Vec::new();

    // 1. Document-level events (from Catalog and document actions)
    // Find catalog from trailer /Root entry
    if let Some(trailer) = ctx.graph.trailers.first() {
        for (key, value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes == b"/Root" {
                if let PdfAtom::Ref { obj, gen } = &value.atom {
                    if let Some(catalog_entry) = ctx.graph.get_object(*obj, *gen) {
                        if let Some(dict) = entry_dict(catalog_entry) {
                            // OpenAction (automatic execution on document open)
                            if let Some((_, action_obj)) = dict.get_first(b"/OpenAction") {
                                if filter_level.is_none() || filter_level == Some("document") {
                                    let action_details = extract_action_details(&ctx.graph, ctx.bytes, action_obj);
                                    events.push(json!({
                                        "level": "document",
                                        "event_type": "OpenAction",
                                        "location": format!("obj {}:{} (Catalog)", obj, gen),
                                        "trigger_config": "Triggered on document open",
                                        "action_details": action_details
                                    }));
                                }
                            }

                            // Additional actions (AA dictionary)
                            if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                                if filter_level.is_none() || filter_level == Some("document") {
                                    extract_aa_events(&ctx.graph, ctx.bytes, aa_obj, "document", &format!("obj {}:{} (Catalog)", obj, gen), &mut events);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Page-level events
    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Check if this is a Page object
            if dict.has_name(b"/Type", b"/Page") {
                if filter_level.is_none() || filter_level == Some("page") {
                    // Check for Page AA (Additional Actions)
                    if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                        extract_aa_events(&ctx.graph, ctx.bytes, aa_obj, "page", &format!("obj {}:{}", entry.obj, entry.gen), &mut events);
                    }
                }
            }
        }
    }

    // 3. Field-level events (form fields / annotations)
    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            // Check for widget annotations (form fields)
            if dict.has_name(b"/Subtype", b"/Widget") || dict.get_first(b"/FT").is_some() {
                if filter_level.is_none() || filter_level == Some("field") {
                    let field_name = dict.get_first(b"/T")
                        .and_then(|(_, obj)| extract_obj_text(&ctx.graph, ctx.bytes, obj))
                        .unwrap_or_else(|| "unnamed".to_string());

                    // Check for field actions
                    if let Some((_, action_obj)) = dict.get_first(b"/A") {
                        let action_details = extract_action_details(&ctx.graph, ctx.bytes, action_obj);
                        events.push(json!({
                            "level": "field",
                            "event_type": "Action",
                            "location": format!("obj {}:{} (field: {})", entry.obj, entry.gen, field_name),
                            "trigger_config": "Triggered on field activation",
                            "action_details": action_details
                        }));
                    }

                    // Check for Additional Actions (AA)
                    if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                        extract_aa_events(&ctx.graph, ctx.bytes, aa_obj, "field", &format!("obj {}:{} (field: {})", entry.obj, entry.gen, field_name), &mut events);
                    }
                }
            }
        }
    }

    if let Some(pred) = predicate {
        let filtered: Vec<_> = events
            .into_iter()
            .filter(|event| predicate_context_for_event(event).map_or(false, |ctx| pred.evaluate(&ctx)))
            .collect();
        Ok(json!(filtered))
    } else {
        Ok(json!(events))
    }
}

/// Extract additional actions from an AA dictionary
fn extract_aa_events(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    aa_obj: &sis_pdf_pdf::object::PdfObj<'_>,
    level: &str,
    location: &str,
    events: &mut Vec<serde_json::Value>,
) {
    use sis_pdf_pdf::object::PdfAtom;

    if let PdfAtom::Dict(ref aa_dict) = aa_obj.atom {
        let event_types = vec![
            (b"/O" as &[u8], if level == "page" { "Page/Open" } else { "OnFocus" }),
            (b"/C", if level == "page" { "Page/Close" } else { "OnBlur" }),
            (b"/WC", "Doc/WillClose"),
            (b"/WS", "Doc/WillSave"),
            (b"/DS", "Doc/DidSave"),
            (b"/WP", "Doc/WillPrint"),
            (b"/DP", "Doc/DidPrint"),
            (b"/K", "Keystroke"),
            (b"/F", "Format"),
            (b"/V", "Validate"),
            (b"/C", "Calculate"),
            (b"/D", "MouseDown"),
            (b"/U", "MouseUp"),
            (b"/E", "MouseEnter"),
            (b"/X", "MouseExit"),
            (b"/Fo", "OnFocus"),
            (b"/Bl", "OnBlur"),
        ];

        for (key, event_name) in event_types {
            if let Some((_, action_obj)) = aa_dict.get_first(key) {
                let action_details = extract_action_details(graph, bytes, action_obj);
                let trigger_desc = match event_name {
                    "Page/Open" => "Triggered when page is opened/viewed",
                    "Page/Close" => "Triggered when page is closed",
                    "Doc/WillClose" => "Triggered before document close",
                    "Doc/WillSave" => "Triggered before document save",
                    "Doc/DidSave" => "Triggered after document save",
                    "Doc/WillPrint" => "Triggered before printing",
                    "Doc/DidPrint" => "Triggered after printing",
                    "Keystroke" => "Triggered on each keystroke in field",
                    "Format" => "Triggered when field is formatted",
                    "Validate" => "Triggered on field validation",
                    "Calculate" => "Triggered when field value is calculated",
                    "MouseDown" => "Triggered on mouse button press",
                    "MouseUp" => "Triggered on mouse button release",
                    "MouseEnter" => "Triggered when mouse enters field",
                    "MouseExit" => "Triggered when mouse exits field",
                    "OnFocus" => "Triggered when field receives focus",
                    "OnBlur" => "Triggered when field loses focus",
                    _ => "Triggered by event",
                };

                events.push(json!({
                    "level": level,
                    "event_type": event_name,
                    "location": location,
                    "trigger_config": trigger_desc,
                    "action_details": action_details
                }));
            }
        }
    }
}

/// Extract action details from an action object
fn extract_action_details(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    action_obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> String {
    use sis_pdf_pdf::object::PdfAtom;

    if let Some(dict) = match &action_obj.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    } {
        // Check action type
        if let Some((_, s_obj)) = dict.get_first(b"/S") {
            if let Some(action_type) = extract_obj_text(graph, bytes, s_obj) {
                match action_type.as_str() {
                    "/JavaScript" => {
                        if let Some((_, js_obj)) = dict.get_first(b"/JS") {
                            if let Some(js_code) = extract_obj_text(graph, bytes, js_obj) {
                                return format!("JavaScript: {}", preview_text(&js_code, 100));
                            }
                        }
                        return "JavaScript: <code unavailable>".to_string();
                    }
                    "/URI" => {
                        if let Some((_, uri_obj)) = dict.get_first(b"/URI") {
                            if let Some(uri) = extract_obj_text(graph, bytes, uri_obj) {
                                return format!("URI: {}", uri);
                            }
                        }
                        return "URI: <unavailable>".to_string();
                    }
                    "/SubmitForm" => {
                        if let Some((_, f_obj)) = dict.get_first(b"/F") {
                            if let Some(url) = extract_obj_text(graph, bytes, f_obj) {
                                return format!("Submit form to: {}", url);
                            }
                        }
                        return "Submit form".to_string();
                    }
                    "/Launch" => {
                        return "Launch external application".to_string();
                    }
                    "/GoTo" => {
                        return "Navigate to destination".to_string();
                    }
                    "/GoToR" => {
                        return "Navigate to remote destination".to_string();
                    }
                    "/Named" => {
                        if let Some((_, n_obj)) = dict.get_first(b"/N") {
                            if let Some(name) = extract_obj_text(graph, bytes, n_obj) {
                                return format!("Named action: {}", name);
                            }
                        }
                        return "Named action".to_string();
                    }
                    _ => return format!("Action type: {}", action_type),
                }
            }
        }
    }

    "Action details unavailable".to_string()
}

// Helper functions

fn entry_dict<'a>(
    entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>,
) -> Option<&'a sis_pdf_pdf::object::PdfDict<'a>> {
    use sis_pdf_pdf::object::PdfAtom;
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn extract_obj_text(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    match &obj.atom {
        PdfAtom::Str(s) => {
            let text_bytes = string_bytes(s);
            Some(decode_pdf_text_string(&text_bytes))
        }
        PdfAtom::Stream(st) => sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
            .ok()
            .map(|d| String::from_utf8_lossy(&d.data).to_string()),
        PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                PdfAtom::Str(s) => {
                    let text_bytes = string_bytes(s);
                    Some(decode_pdf_text_string(&text_bytes))
                }
                PdfAtom::Stream(st) => {
                    sis_pdf_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                        .ok()
                        .map(|d| String::from_utf8_lossy(&d.data).to_string())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn string_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    use sis_pdf_pdf::object::PdfStr;
    match s {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn string_raw_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    use sis_pdf_pdf::object::PdfStr;
    match s {
        PdfStr::Literal { raw, .. } => raw.to_vec(),
        PdfStr::Hex { raw, .. } => raw.to_vec(),
    }
}

fn entropy_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts.iter().filter(|&&c| c > 0) {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn filter_name(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    let filter_obj = dict.get_first(b"/Filter").map(|(_, obj)| obj)?;
    match &filter_obj.atom {
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        PdfAtom::Array(items) => items.first().and_then(|item| {
            if let PdfAtom::Name(name) = &item.atom {
                Some(String::from_utf8_lossy(&name.decoded).to_string())
            } else {
                None
            }
        }),
        _ => None,
    }
}

fn subtype_name(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    let subtype_obj = dict.get_first(b"/Subtype").map(|(_, obj)| obj)?;
    if let PdfAtom::Name(name) = &subtype_obj.atom {
        Some(String::from_utf8_lossy(&name.decoded).to_string())
    } else {
        None
    }
}

fn atom_type_name(atom: &sis_pdf_pdf::object::PdfAtom<'_>) -> String {
    use sis_pdf_pdf::object::PdfAtom;
    match atom {
        PdfAtom::Null => "Null",
        PdfAtom::Bool(_) => "Bool",
        PdfAtom::Int(_) => "Int",
        PdfAtom::Real(_) => "Real",
        PdfAtom::Name(_) => "Name",
        PdfAtom::Str(_) => "String",
        PdfAtom::Array(_) => "Array",
        PdfAtom::Dict(_) => "Dict",
        PdfAtom::Stream(_) => "Stream",
        PdfAtom::Ref { .. } => "Ref",
    }
    .to_string()
}

fn predicate_context_for_entry(
    entry: &sis_pdf_pdf::graph::ObjEntry<'_>,
    bytes: &[u8],
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
) -> PredicateContext {
    use sis_pdf_pdf::object::PdfAtom;

    match &entry.atom {
        PdfAtom::Str(s) => {
            let data = match decode_mode {
                DecodeMode::Raw => string_raw_bytes(s),
                DecodeMode::Decode | DecodeMode::Hexdump => string_bytes(s),
            };
            PredicateContext {
                length: data.len(),
                filter: None,
                type_name: "String".to_string(),
                subtype: None,
                entropy: entropy_score(&data),
            }
        }
        PdfAtom::Stream(stream) => {
            let (data_len, entropy) =
                match stream_bytes_for_mode(bytes, stream, max_extract_bytes, decode_mode) {
                    Ok(data) => (data.len(), entropy_score(&data)),
                    Err(_) => {
                        let length = stream
                            .dict
                            .get_first(b"/Length")
                            .and_then(|(_, obj)| {
                                if let PdfAtom::Int(n) = &obj.atom {
                                    Some(*n as usize)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        (length, 0.0)
                    }
                };
            PredicateContext {
                length: data_len,
                filter: filter_name(&stream.dict),
                type_name: "Stream".to_string(),
                subtype: subtype_name(&stream.dict),
                entropy,
            }
        }
        PdfAtom::Dict(dict) => PredicateContext {
            length: 0,
            filter: None,
            type_name: "Dict".to_string(),
            subtype: subtype_name(dict),
            entropy: 0.0,
        },
        PdfAtom::Array(_) => PredicateContext {
            length: 0,
            filter: None,
            type_name: "Array".to_string(),
            subtype: None,
            entropy: 0.0,
        },
        atom => PredicateContext {
            length: 0,
            filter: None,
            type_name: atom_type_name(atom),
            subtype: None,
            entropy: 0.0,
        },
    }
}

fn predicate_context_for_url(url: &str) -> PredicateContext {
    let bytes = url.as_bytes();
    PredicateContext {
        length: bytes.len(),
        filter: None,
        type_name: "Url".to_string(),
        subtype: None,
        entropy: entropy_score(bytes),
    }
}

fn predicate_context_for_event(event: &serde_json::Value) -> Option<PredicateContext> {
    let level = event.get("level")?.as_str()?;
    let event_type = event.get("event_type")?.as_str()?;
    let details = event
        .get("action_details")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let bytes = details.as_bytes();
    Some(PredicateContext {
        length: bytes.len(),
        filter: Some(level.to_string()),
        type_name: "Event".to_string(),
        subtype: Some(event_type.to_string()),
        entropy: entropy_score(bytes),
    })
}

fn predicate_context_for_finding(finding: &sis_pdf_core::model::Finding) -> PredicateContext {
    let bytes = finding.description.as_bytes();
    PredicateContext {
        length: bytes.len(),
        filter: Some(severity_to_string(&finding.severity)),
        type_name: "Finding".to_string(),
        subtype: Some(finding.kind.clone()),
        entropy: entropy_score(bytes),
    }
}

fn severity_to_string(severity: &sis_pdf_core::model::Severity) -> String {
    match severity {
        sis_pdf_core::model::Severity::Info => "info",
        sis_pdf_core::model::Severity::Low => "low",
        sis_pdf_core::model::Severity::Medium => "medium",
        sis_pdf_core::model::Severity::High => "high",
        sis_pdf_core::model::Severity::Critical => "critical",
    }
    .to_string()
}

fn build_query_error(err: anyhow::Error) -> QueryError {
    QueryError {
        status: "error",
        error_code: "QUERY_ERROR",
        message: err.to_string(),
        context: None,
    }
}

fn filter_findings(
    findings: Vec<sis_pdf_core::model::Finding>,
    predicate: Option<&PredicateExpr>,
) -> Vec<sis_pdf_core::model::Finding> {
    if let Some(pred) = predicate {
        findings
            .into_iter()
            .filter(|finding| pred.evaluate(&predicate_context_for_finding(finding)))
            .collect()
    } else {
        findings
    }
}

fn embedded_filename(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    use sis_pdf_pdf::object::PdfAtom;

    // Try /F (file name)
    if let Some((_, obj)) = dict.get_first(b"/F") {
        if let PdfAtom::Str(s) = &obj.atom {
            let text_bytes = string_bytes(s);
            return Some(decode_pdf_text_string(&text_bytes));
        }
    }

    // Try /UF (unicode file name)
    if let Some((_, obj)) = dict.get_first(b"/UF") {
        if let PdfAtom::Str(s) = &obj.atom {
            let text_bytes = string_bytes(s);
            return Some(decode_pdf_text_string(&text_bytes));
        }
    }

    None
}

/// Extract raw bytes from a PDF object (for file extraction)
fn extract_obj_bytes(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    max_bytes: usize,
    decode_mode: DecodeMode,
) -> Option<Vec<u8>> {
    use sis_pdf_pdf::object::PdfAtom;

    match &obj.atom {
        PdfAtom::Str(s) => match decode_mode {
            DecodeMode::Raw => Some(string_raw_bytes(s)),
            DecodeMode::Decode | DecodeMode::Hexdump => Some(string_bytes(s)),
        },
        PdfAtom::Stream(st) => stream_bytes_for_mode(bytes, st, max_bytes, decode_mode).ok(),
        PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                PdfAtom::Str(s) => match decode_mode {
                    DecodeMode::Raw => Some(string_raw_bytes(s)),
                    DecodeMode::Decode | DecodeMode::Hexdump => Some(string_bytes(s)),
                },
                PdfAtom::Stream(st) => {
                    stream_bytes_for_mode(bytes, st, max_bytes, decode_mode).ok()
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn extract_obj_with_metadata(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    max_bytes: usize,
    decode_mode: DecodeMode,
) -> Option<(Vec<u8>, PredicateContext)> {
    use sis_pdf_pdf::object::PdfAtom;

    match &obj.atom {
        PdfAtom::Str(s) => {
            let data = match decode_mode {
                DecodeMode::Raw => string_raw_bytes(s),
                DecodeMode::Decode | DecodeMode::Hexdump => string_bytes(s),
            };
            let ctx = PredicateContext {
                length: data.len(),
                filter: None,
                type_name: "String".to_string(),
                subtype: None,
                entropy: entropy_score(&data),
            };
            Some((data, ctx))
        }
        PdfAtom::Stream(stream) => {
            let data = stream_bytes_for_mode(bytes, stream, max_bytes, decode_mode).ok()?;
            let ctx = PredicateContext {
                length: data.len(),
                filter: filter_name(&stream.dict),
                type_name: "Stream".to_string(),
                subtype: subtype_name(&stream.dict),
                entropy: entropy_score(&data),
            };
            Some((data, ctx))
        }
        PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                PdfAtom::Str(s) => {
                    let data = match decode_mode {
                        DecodeMode::Raw => string_raw_bytes(s),
                        DecodeMode::Decode | DecodeMode::Hexdump => string_bytes(s),
                    };
                    let ctx = PredicateContext {
                        length: data.len(),
                        filter: None,
                        type_name: "String".to_string(),
                        subtype: None,
                        entropy: entropy_score(&data),
                    };
                    Some((data, ctx))
                }
                PdfAtom::Stream(stream) => {
                    let data =
                        stream_bytes_for_mode(bytes, stream, max_bytes, decode_mode).ok()?;
                    let ctx = PredicateContext {
                        length: data.len(),
                        filter: filter_name(&stream.dict),
                        type_name: "Stream".to_string(),
                        subtype: subtype_name(&stream.dict),
                        entropy: entropy_score(&data),
                    };
                    Some((data, ctx))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn stream_bytes_for_mode(
    bytes: &[u8],
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
    max_bytes: usize,
    decode_mode: DecodeMode,
) -> Result<Vec<u8>> {
    match decode_mode {
        DecodeMode::Decode | DecodeMode::Hexdump => {
            let decoded = sis_pdf_pdf::decode::decode_stream(bytes, stream, max_bytes)?;
            Ok(decoded.data)
        }
        DecodeMode::Raw => raw_stream_bytes(bytes, stream, max_bytes),
    }
}

fn raw_stream_bytes(
    bytes: &[u8],
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > bytes.len() {
        return Err(anyhow!("invalid stream span"));
    }
    let data = &bytes[start..end];
    if max_bytes > 0 && data.len() > max_bytes {
        return Err(anyhow!("stream exceeds extract byte limit"));
    }
    Ok(data.to_vec())
}

/// Sanitize filename to prevent path traversal attacks
fn sanitize_embedded_filename(name: &str) -> String {
    use std::path::Path;

    // Extract just the filename, removing any path components
    let leaf = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("embedded.bin");

    // Filter to safe characters only
    let mut out = String::new();
    for ch in leaf.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }

    if out.is_empty() {
        "embedded.bin".into()
    } else {
        out
    }
}

/// Detect file type from magic bytes
fn magic_type(data: &[u8]) -> &'static str {
    if data.starts_with(b"MZ") {
        "pe"
    } else if data.starts_with(b"%PDF") {
        "pdf"
    } else if data.starts_with(b"PK\x03\x04") {
        "zip"
    } else if data.starts_with(b"\x7fELF") {
        "elf"
    } else if data.starts_with(b"#!") {
        "script"
    } else if data.starts_with(b"\x89PNG") {
        "png"
    } else if data.starts_with(b"\xff\xd8\xff") {
        "jpeg"
    } else if data.starts_with(b"GIF8") {
        "gif"
    } else {
        "unknown"
    }
}

/// Calculate SHA256 hash as hex string
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Write JavaScript files to disk and return list of written files
fn write_js_files(
    ctx: &ScanContext,
    extract_to: &Path,
    max_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use std::fs;

    // Create output directory
    fs::create_dir_all(extract_to)?;

    let mut written_files = Vec::new();
    let mut count = 0usize;

    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some((data, meta)) = extract_obj_with_metadata(
                    &ctx.graph,
                    ctx.bytes,
                    obj,
                    max_bytes,
                    decode_mode,
                ) {
                    if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                        let base_name = format!("js_{}_{}", entry.obj, entry.gen);
                        let (filename, output_bytes, mode_label) = match decode_mode {
                            DecodeMode::Decode => (
                                format!("{base_name}.js"),
                                data.clone(),
                                "decode",
                            ),
                            DecodeMode::Raw => (format!("{base_name}.raw"), data.clone(), "raw"),
                            DecodeMode::Hexdump => (
                                format!("{base_name}.hex"),
                                format_hexdump(&data).into_bytes(),
                                "hexdump",
                            ),
                        };
                        let filepath = extract_to.join(&filename);
                        let hash = sha256_hex(&data);

                        fs::write(&filepath, &output_bytes)?;

                        let mut info = format!(
                            "{}: {} bytes, sha256={}, object={}_{}",
                            filename,
                            data.len(),
                            hash,
                            entry.obj,
                            entry.gen
                        );
                        info.push_str(&format!(", mode={}", mode_label));
                        if decode_mode == DecodeMode::Hexdump {
                            info.push_str(&format!(", hexdump_bytes={}", output_bytes.len()));
                        }
                        written_files.push(info);
                        count += 1;
                    }
                }
            }
        }
    }

    eprintln!("Extracted {} JavaScript file(s) to {}", count, extract_to.display());
    Ok(written_files)
}

/// Write embedded files to disk and return list of written files
fn write_embedded_files(
    ctx: &ScanContext,
    extract_to: &Path,
    max_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;
    use std::fs;

    // Create output directory
    fs::create_dir_all(extract_to)?;

    let mut written_files = Vec::new();
    let mut count = 0usize;
    let mut total_bytes = 0usize;

    for entry in &ctx.graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            // Check if this is an embedded file
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                if let Ok(data) = stream_bytes_for_mode(ctx.bytes, st, max_bytes, decode_mode) {
                    // Check size limit
                    if max_bytes > 0 && total_bytes.saturating_add(data.len()) > max_bytes {
                        eprintln!(
                            "Embedded extraction budget exceeded ({} bytes), stopping",
                            max_bytes
                        );
                        break;
                    }

                    let meta = PredicateContext {
                        length: data.len(),
                        filter: filter_name(&st.dict),
                        type_name: "Stream".to_string(),
                        subtype: subtype_name(&st.dict),
                        entropy: entropy_score(&data),
                    };
                    if predicate.map(|pred| pred.evaluate(&meta)).unwrap_or(true) {
                    // Get filename
                    let name = embedded_filename(&st.dict).unwrap_or_else(|| {
                        format!("embedded_{}_{}.bin", entry.obj, entry.gen)
                    });
                    let safe_name = sanitize_embedded_filename(&name);
                    let (filename, output_bytes, mode_label) = match decode_mode {
                        DecodeMode::Decode => (safe_name, data.clone(), "decode"),
                        DecodeMode::Raw => (format!("{safe_name}.raw"), data.clone(), "raw"),
                        DecodeMode::Hexdump => (
                            format!("{safe_name}.hex"),
                            format_hexdump(&data).into_bytes(),
                            "hexdump",
                        ),
                    };
                    let filepath = extract_to.join(&filename);

                    // Detect file type and calculate hash
                    let hash = sha256_hex(&data);
                    let file_type = magic_type(&data);
                    let data_len = data.len();

                    // Write file
                    fs::write(&filepath, &output_bytes)?;

                    let mut info = format!(
                        "{}: {} bytes, type={}, sha256={}, object={}_{}",
                        filename,
                        data_len,
                        file_type,
                        hash,
                        entry.obj,
                        entry.gen
                    );
                    info.push_str(&format!(", mode={}", mode_label));
                    if decode_mode == DecodeMode::Hexdump {
                        info.push_str(&format!(", hexdump_bytes={}", output_bytes.len()));
                    }
                    written_files.push(info);

                    total_bytes = total_bytes.saturating_add(data_len);
                    count += 1;
                    }
                }
            }
        }
    }

    eprintln!(
        "Extracted {} embedded file(s) ({} bytes total) to {}",
        count,
        total_bytes,
        extract_to.display()
    );
    Ok(written_files)
}

fn preview_text(text: &str, max_len: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max_len])
    }
}

fn format_hexdump(data: &[u8]) -> String {
    let mut output = String::new();
    for (line_idx, chunk) in data.chunks(16).enumerate() {
        let offset = line_idx * 16;
        output.push_str(&format!("{offset:08x}  "));
        for i in 0..16 {
            if i < chunk.len() {
                output.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                output.push_str("   ");
            }
            if i == 7 {
                output.push(' ');
            }
        }
        output.push_str(" |");
        for &byte in chunk {
            let ch = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            output.push(ch);
        }
        output.push_str("|\n");
    }
    output
}

/// Show a specific PDF object
fn show_object(ctx: &ScanContext, obj: u32, gen: u16) -> Result<String> {
    // Find the object in the graph
    if let Some(entry) = ctx.graph.get_object(obj, gen) {
        let mut output = String::new();
        output.push_str(&format!("Object {} {} obj\n", obj, gen));
        output.push_str(&format_pdf_atom(&entry.atom, 0));
        output.push_str("\nendobj");
        Ok(output)
    } else {
        Err(anyhow!("Object {} {} not found", obj, gen))
    }
}

/// Format a PDF atom for display
fn format_pdf_atom(atom: &sis_pdf_pdf::object::PdfAtom, indent: usize) -> String {
    use sis_pdf_pdf::object::PdfAtom;

    let indent_str = "  ".repeat(indent);

    match atom {
        PdfAtom::Null => format!("{}null", indent_str),
        PdfAtom::Bool(b) => format!("{}{}", indent_str, b),
        PdfAtom::Int(n) => format!("{}{}", indent_str, n),
        PdfAtom::Real(f) => format!("{}{}", indent_str, f),
        PdfAtom::Name(name) => {
            format!("{}/{}", indent_str, String::from_utf8_lossy(&name.decoded))
        }
        PdfAtom::Str(s) => {
            let bytes = match s {
                sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded,
                sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded,
            };
            format!("{}({})", indent_str, String::from_utf8_lossy(bytes))
        }
        PdfAtom::Array(arr) => {
            let mut output = format!("{}[\n", indent_str);
            for item in arr.iter() {
                output.push_str(&format_pdf_atom(&item.atom, indent + 1));
                output.push('\n');
            }
            output.push_str(&format!("{}]", indent_str));
            output
        }
        PdfAtom::Dict(dict) => {
            let mut output = format!("{}<<\n", indent_str);
            for (key, value) in &dict.entries {
                let key_str = String::from_utf8_lossy(&key.decoded);
                output.push_str(&format!("{}  {}", indent_str, key_str));
                output.push_str(" ");
                output.push_str(&format_pdf_atom(&value.atom, 0).trim());
                output.push('\n');
            }
            output.push_str(&format!("{}", indent_str));
            output.push_str(">>");
            output
        }
        PdfAtom::Stream(stream) => {
            let mut output = format_pdf_atom(&PdfAtom::Dict(stream.dict.clone()), indent);
            output.push_str("\nstream\n");
            output.push_str("<stream data>");
            output.push_str("\nendstream");
            output
        }
        PdfAtom::Ref { obj, gen } => format!("{}{} {} R", indent_str, obj, gen),
    }
}

/// List all object IDs
fn list_objects(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    let objects: Vec<String> = ctx
        .graph
        .objects
        .iter()
        .filter(|entry| {
            if let Some(pred) = predicate {
                let context =
                    predicate_context_for_entry(entry, ctx.bytes, decode_mode, max_extract_bytes);
                pred.evaluate(&context)
            } else {
                true
            }
        })
        .map(|entry| format!("{} {}", entry.obj, entry.gen))
        .collect();
    Ok(objects)
}

/// List objects with a specific type
fn list_objects_with_type(
    ctx: &ScanContext,
    obj_type: &str,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<Vec<String>> {
    use sis_pdf_pdf::object::PdfAtom;

    let mut objects = Vec::new();
    let search_type = if obj_type.starts_with('/') {
        obj_type.to_string()
    } else {
        format!("/{}", obj_type)
    };

    for entry in &ctx.graph.objects {
        if let Some(pred) = predicate {
            let context =
                predicate_context_for_entry(entry, ctx.bytes, decode_mode, max_extract_bytes);
            if !pred.evaluate(&context) {
                continue;
            }
        }
        if let Some(dict) = entry_dict(entry) {
            // Look for /Type entry
            if let Some((_, type_obj)) = dict.get_first(b"/Type") {
                if let PdfAtom::Name(name) = &type_obj.atom {
                    let type_name = String::from_utf8_lossy(&name.decoded);
                    if type_name == search_type || type_name == &search_type[1..] {
                        objects.push(format!("{} {} ({})", entry.obj, entry.gen, type_name));
                    }
                }
            }
        }
    }

    Ok(objects)
}

fn count_objects(
    ctx: &ScanContext,
    decode_mode: DecodeMode,
    max_extract_bytes: usize,
    predicate: Option<&PredicateExpr>,
) -> Result<usize> {
    let mut count = 0usize;
    for entry in &ctx.graph.objects {
        if let Some(pred) = predicate {
            let context =
                predicate_context_for_entry(entry, ctx.bytes, decode_mode, max_extract_bytes);
            if !pred.evaluate(&context) {
                continue;
            }
        }
        count += 1;
    }
    Ok(count)
}

/// Show the PDF trailer
fn show_trailer(ctx: &ScanContext) -> Result<String> {
    if let Some(trailer) = ctx.graph.trailers.first() {
        let mut output = String::from("<<\n");
        for (key, value) in &trailer.entries {
            let key_str = String::from_utf8_lossy(&key.decoded);
            output.push_str(&format!("  {} ", key_str));
            output.push_str(&format_pdf_atom(&value.atom, 0).trim());
            output.push('\n');
        }
        output.push_str(">>");
        Ok(output)
    } else {
        Err(anyhow!("No trailer found"))
    }
}

/// Show the PDF catalog
fn show_catalog(ctx: &ScanContext) -> Result<String> {
    use sis_pdf_pdf::object::PdfAtom;

    // Find catalog from trailer /Root entry
    if let Some(trailer) = ctx.graph.trailers.first() {
        for (key, value) in &trailer.entries {
            let key_bytes = &key.decoded;
            if key_bytes.as_slice() == b"/Root" || key_bytes.as_slice() == b"Root" {
                if let PdfAtom::Ref { obj, gen } = &value.atom {
                    if let Some(catalog_entry) = ctx.graph.get_object(*obj, *gen) {
                        let mut output = format!("Catalog (Object {} {})\n", obj, gen);
                        output.push_str(&format_pdf_atom(&catalog_entry.atom, 0));
                        return Ok(output);
                    }
                }
            }
        }
    }

    Err(anyhow!("Catalog not found"))
}

/// List all action chains
fn list_action_chains(ctx: &ScanContext) -> Result<serde_json::Value> {
    let classifications = ctx.classifications();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(&typed_graph);

    let chains = path_finder.find_all_action_chains();
    Ok(build_chain_query_result(
        "chains",
        chains.iter().enumerate(),
    ))
}

/// List JavaScript-containing action chains
fn list_js_chains(ctx: &ScanContext) -> Result<serde_json::Value> {
    let classifications = ctx.classifications();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&ctx.graph, classifications);
    let path_finder = sis_pdf_pdf::path_finder::PathFinder::new(&typed_graph);

    let chains = path_finder.find_all_action_chains();
    let js_chains = chains
        .iter()
        .enumerate()
        .filter(|(_, chain)| chain.involves_js);

    Ok(build_chain_query_result("chains.js", js_chains))
}

/// List all reference cycles
fn list_cycles(ctx: &ScanContext) -> Result<serde_json::Value> {
    use std::collections::HashSet;

    let mut cycles = Vec::new();
    let mut visited = HashSet::new();
    let mut path = Vec::new();
    let mut path_set = HashSet::new();

    for entry in &ctx.graph.objects {
        if !visited.contains(&(entry.obj, entry.gen)) {
            find_cycles_dfs(
                &ctx.graph,
                entry.obj,
                entry.gen,
                &mut visited,
                &mut path,
                &mut path_set,
                &mut cycles,
            );
        }
    }

    Ok(build_cycles_result("cycles", &cycles))
}

/// List page tree cycles (only /Kids and /Parent edges)
fn list_page_cycles(ctx: &ScanContext) -> Result<serde_json::Value> {
    use sis_pdf_pdf::object::PdfAtom;
    use sis_pdf_pdf::typed_graph::TypedGraph;
    use std::collections::HashSet;

    let classifications = ctx.classifications();
    let typed_graph = TypedGraph::build(&ctx.graph, classifications);

    let page_nodes: Vec<(u32, u16)> = ctx
        .graph
        .objects
        .iter()
        .filter_map(|entry| {
            if let Some(dict) = entry_dict(entry) {
                if let Some((_, type_obj)) = dict.get_first(b"/Type") {
                    if let PdfAtom::Name(name) = &type_obj.atom {
                        let type_name = String::from_utf8_lossy(&name.decoded);
                        if type_name == "/Page"
                            || type_name == "Page"
                            || type_name == "/Pages"
                            || type_name == "Pages"
                        {
                            return Some((entry.obj, entry.gen));
                        }
                    }
                }
            }
            None
        })
        .collect();

    let mut cycles = Vec::new();
    let mut seen = HashSet::new();
    let mut path = Vec::new();
    let mut path_set = HashSet::new();

    for node in page_nodes {
        dfs_page_cycles(
            node,
            &typed_graph,
            &mut path,
            &mut path_set,
            &mut cycles,
            &mut seen,
        );
        path.clear();
        path_set.clear();
    }

    Ok(build_cycles_result("cycles.page", &cycles))
}

fn list_references(ctx: &ScanContext, obj: u32, gen: u16) -> Result<serde_json::Value> {
    use sis_pdf_pdf::typed_graph::TypedGraph;

    if ctx.graph.get_object(obj, gen).is_none() {
        return Err(anyhow!("Object {} {} not found", obj, gen));
    }

    let classifications = ctx.classifications();
    let typed_graph = TypedGraph::build(&ctx.graph, classifications);
    let incoming = typed_graph.incoming_edges(obj, gen);

    let references: Vec<_> = incoming
        .iter()
        .map(|edge| {
            let detail = edge_detail(&edge.edge_type)
                .map(|value| json!(value))
                .unwrap_or(serde_json::Value::Null);
            json!({
                "src": { "obj": edge.src.0, "gen": edge.src.1 },
                "relationship": edge.edge_type.as_str(),
                "detail": detail,
                "suspicious": edge.suspicious,
            })
        })
        .collect();

    Ok(json!({
        "type": "references",
        "target": { "obj": obj, "gen": gen },
        "count": references.len(),
        "references": references,
    }))
}

fn edge_detail(edge_type: &sis_pdf_pdf::typed_graph::EdgeType) -> Option<String> {
    use sis_pdf_pdf::typed_graph::EdgeType;

    match edge_type {
        EdgeType::DictReference { key } => Some(key.clone()),
        EdgeType::ArrayElement { index } => Some(format!("[{}]", index)),
        EdgeType::PageAction { event } => Some(event.clone()),
        EdgeType::AdditionalAction { event } => Some(event.clone()),
        EdgeType::FormFieldAction { event } => Some(event.clone()),
        _ => None,
    }
}

fn dfs_page_cycles(
    current: (u32, u16),
    graph: &sis_pdf_pdf::typed_graph::TypedGraph<'_>,
    path: &mut Vec<(u32, u16)>,
    path_set: &mut std::collections::HashSet<(u32, u16)>,
    cycles: &mut Vec<Vec<(u32, u16)>>,
    seen_cycles: &mut std::collections::HashSet<String>,
) {
    use sis_pdf_pdf::typed_graph::EdgeType;

    path.push(current);
    path_set.insert(current);

    for edge in graph.outgoing_edges(current.0, current.1) {
        if !matches!(edge.edge_type, EdgeType::PagesKids | EdgeType::PageParent) {
            continue;
        }

        let next = edge.dst;
        if let Some(pos) = path.iter().position(|&node| node == next) {
            record_page_cycle(cycles, seen_cycles, path[pos..].to_vec());
        } else {
            dfs_page_cycles(next, graph, path, path_set, cycles, seen_cycles);
        }
    }

    path_set.remove(&current);
    path.pop();
}

fn record_page_cycle(
    cycles: &mut Vec<Vec<(u32, u16)>>,
    seen_cycles: &mut std::collections::HashSet<String>,
    cycle: Vec<(u32, u16)>,
) {
    if cycle.is_empty() {
        return;
    }

    let normalized = normalize_cycle(&cycle);
    let key = cycle_key(&normalized);
    if seen_cycles.insert(key) {
        cycles.push(normalized);
    }
}

fn normalize_cycle(cycle: &[(u32, u16)]) -> Vec<(u32, u16)> {
    if cycle.is_empty() {
        return Vec::new();
    }

    fn rotation(cycle: &[(u32, u16)], start: usize) -> Vec<(u32, u16)> {
        let mut rotated = Vec::with_capacity(cycle.len());
        rotated.extend_from_slice(&cycle[start..]);
        rotated.extend_from_slice(&cycle[..start]);
        rotated
    }

    let mut best = rotation(cycle, 0);
    for start in 1..cycle.len() {
        let candidate = rotation(cycle, start);
        if candidate < best {
            best = candidate;
        }
    }

    let reversed_cycle: Vec<_> = cycle.iter().rev().copied().collect();
    for start in 0..reversed_cycle.len() {
        let candidate = rotation(&reversed_cycle, start);
        if candidate < best {
            best = candidate;
        }
    }

    best
}

fn cycle_key(cycle: &[(u32, u16)]) -> String {
    cycle
        .iter()
        .map(|(obj, gen)| format!("{obj}:{gen}"))
        .collect::<Vec<_>>()
        .join("->")
}

/// Helper function for DFS cycle detection
fn find_cycles_dfs(
    graph: &sis_pdf_pdf::ObjectGraph,
    obj: u32,
    gen: u16,
    visited: &mut std::collections::HashSet<(u32, u16)>,
    path: &mut Vec<(u32, u16)>,
    path_set: &mut std::collections::HashSet<(u32, u16)>,
    cycles: &mut Vec<Vec<(u32, u16)>>,
) {
    let current = (obj, gen);

    if path_set.contains(&current) {
        // Found a cycle - extract it
        if let Some(cycle_start) = path.iter().position(|&x| x == current) {
            let cycle = path[cycle_start..].to_vec();
            cycles.push(cycle);
        }
        return;
    }

    if visited.contains(&current) {
        return;
    }

    visited.insert(current);
    path.push(current);
    path_set.insert(current);

    // Find references in this object
    if let Some(entry) = graph.get_object(obj, gen) {
        collect_refs(&entry.atom, graph, visited, path, path_set, cycles);
    }

    path.pop();
    path_set.remove(&current);
}

/// Collect references from a PDF atom
fn collect_refs(
    atom: &sis_pdf_pdf::object::PdfAtom,
    graph: &sis_pdf_pdf::ObjectGraph,
    visited: &mut std::collections::HashSet<(u32, u16)>,
    path: &mut Vec<(u32, u16)>,
    path_set: &mut std::collections::HashSet<(u32, u16)>,
    cycles: &mut Vec<Vec<(u32, u16)>>,
) {
    use sis_pdf_pdf::object::PdfAtom;

    match atom {
        PdfAtom::Ref { obj, gen } => {
            find_cycles_dfs(graph, *obj, *gen, visited, path, path_set, cycles);
        }
        PdfAtom::Array(arr) => {
            for item in arr.iter() {
                collect_refs(&item.atom, graph, visited, path, path_set, cycles);
            }
        }
        PdfAtom::Dict(dict) => {
            for (_, value) in &dict.entries {
                collect_refs(&value.atom, graph, visited, path, path_set, cycles);
            }
        }
        PdfAtom::Stream(stream) => {
            for (_, value) in &stream.dict.entries {
                collect_refs(&value.atom, graph, visited, path, path_set, cycles);
            }
        }
        _ => {}
    }
}

fn build_chain_query_result<'a, I>(label: &str, chains: I) -> serde_json::Value
where
    I: Iterator<Item = (usize, &'a sis_pdf_pdf::path_finder::ActionChain<'a>)>,
{
    let chain_values: Vec<_> = chains
        .map(|(idx, chain)| chain_to_json(idx, chain))
        .collect();

    json!({
        "type": label,
        "count": chain_values.len(),
        "chains": chain_values,
    })
}

fn chain_to_json(
    idx: usize,
    chain: &sis_pdf_pdf::path_finder::ActionChain<'_>,
) -> serde_json::Value {
    let edges: Vec<_> = chain.edges.iter().map(|edge| edge_to_json(*edge)).collect();
    let payload = chain.payload.map(|(obj, gen)| ref_to_json((obj, gen)));

    json!({
        "id": idx,
        "trigger": chain.trigger.as_str(),
        "length": chain.length(),
        "automatic": chain.automatic,
        "involves_js": chain.involves_js,
        "involves_external": chain.involves_external,
        "risk_score": chain.risk_score(),
        "payload": payload,
        "edges": edges,
    })
}

fn edge_to_json(edge: &sis_pdf_pdf::typed_graph::TypedEdge) -> serde_json::Value {
    json!({
        "src": ref_to_json(edge.src),
        "dst": ref_to_json(edge.dst),
        "type": edge.edge_type.as_str(),
        "suspicious": edge.suspicious,
        "weight": edge.weight,
    })
}

fn ref_to_json(obj: (u32, u16)) -> serde_json::Value {
    json!({
        "obj": obj.0,
        "gen": obj.1,
    })
}

fn build_cycles_result(label: &str, cycles: &[Vec<(u32, u16)>]) -> serde_json::Value {
    let cycle_values: Vec<_> = cycles
        .iter()
        .enumerate()
        .map(|(idx, cycle)| cycle_to_json(idx, cycle))
        .collect();

    json!({
        "type": label,
        "count": cycle_values.len(),
        "cycles": cycle_values,
    })
}

fn cycle_to_json(idx: usize, cycle: &[(u32, u16)]) -> serde_json::Value {
    let path: Vec<_> = cycle
        .iter()
        .map(|&(obj, gen)| ref_to_json((obj, gen)))
        .collect();
    json!({
        "id": idx,
        "length": cycle.len(),
        "path": path,
    })
}

/// Batch mode: Execute query across multiple PDF files in a directory
///
/// # Arguments
/// * `query` - The query to execute
/// * `path` - Directory to scan
/// * `glob` - Glob pattern for file matching
/// * `scan_options` - Scan configuration
/// * `extract_to` - Optional extraction directory
/// * `max_extract_bytes` - Maximum bytes to extract per file
/// * `decode_mode` - Stream decode behaviour for extraction
/// * `predicate` - Optional predicate filter for supported queries
/// * `output_format` - Output format override
/// * `max_batch_files` - Maximum number of files to process
/// * `max_batch_bytes` - Maximum total bytes to process
/// * `max_walk_depth` - Maximum directory depth
pub fn run_query_batch(
    query: &Query,
    path: &Path,
    glob: &str,
    scan_options: &ScanOptions,
    extract_to: Option<&Path>,
    max_extract_bytes: usize,
    decode_mode: DecodeMode,
    predicate: Option<&PredicateExpr>,
    output_format: OutputFormat,
    max_batch_files: usize,
    max_batch_bytes: u64,
    max_walk_depth: usize,
) -> Result<()> {
    use sis_pdf_core::security_log::{SecurityDomain, SecurityEvent};
    use sis_pdf_core::model::Severity as SecuritySeverity;
    use tracing::{error, Level};
    use memmap2::Mmap;

    // Compile glob matcher
    let matcher = Glob::new(glob)?.compile_matcher();

    // Walk directory and collect matching files
    let iter = if path.is_file() {
        WalkDir::new(path.parent().unwrap_or(path))
            .follow_links(false)
            .max_depth(max_walk_depth)
    } else {
        WalkDir::new(path)
            .follow_links(false)
            .max_depth(max_walk_depth)
    };

    let mut total_bytes = 0u64;
    let mut file_count = 0usize;
    let mut paths = Vec::new();

    for entry in iter.into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let entry_path = entry.path();
        if !matcher.is_match(entry_path) {
            continue;
        }

        file_count += 1;
        if file_count > max_batch_files {
            SecurityEvent {
                level: Level::ERROR,
                domain: SecurityDomain::Detection,
                severity: SecuritySeverity::Medium,
                kind: "batch_file_limit_exceeded",
                policy: None,
                object_id: None,
                object_type: None,
                vector: None,
                technique: None,
                confidence: None,
                message: "Batch query file count exceeded",
            }
            .emit();
            error!(
                max_files = max_batch_files,
                "Batch query file count exceeded"
            );
            return Err(anyhow!("batch file count exceeds limit"));
        }

        if let Ok(meta) = entry.metadata() {
            total_bytes = total_bytes.saturating_add(meta.len());
            if total_bytes > max_batch_bytes {
                SecurityEvent {
                    level: Level::ERROR,
                    domain: SecurityDomain::Detection,
                    severity: SecuritySeverity::Medium,
                    kind: "batch_size_limit_exceeded",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Batch query byte limit exceeded",
                }
                .emit();
                error!(
                    total_bytes = total_bytes,
                    max_bytes = max_batch_bytes,
                    "Batch query byte limit exceeded"
                );
                return Err(anyhow!("batch size exceeds limit"));
            }
        }
        paths.push(entry_path.to_path_buf());
    }

    if paths.is_empty() {
        return Err(anyhow!("no files matched {} in {}", glob, path.display()));
    }

    // Helper to mmap a file
    fn mmap_file(path: &Path) -> Result<Mmap> {
        let file = fs::File::open(path)?;
        unsafe { memmap2::Mmap::map(&file).map_err(|e| anyhow!("mmap failed: {}", e)) }
    }

    // Process files in parallel using rayon
    let thread_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let use_parallel = thread_count > 1 && paths.len() > 1;

    let indexed_paths: Vec<(usize, PathBuf)> = paths.into_iter().enumerate().collect();

    // Batch result structure
    #[derive(Serialize)]
    struct BatchResult {
        path: String,
        result: QueryResult,
    }

    let process_path = |path_buf: &PathBuf| -> Result<Option<BatchResult>> {
        let path_str = path_buf.display().to_string();
        let mmap = mmap_file(path_buf)?;

        // Build scan context
        let ctx = build_scan_context(&mmap, scan_options)?;

        // Execute query
        let result = execute_query_with_context(
            query,
            &ctx,
            extract_to,
            max_extract_bytes,
            decode_mode,
            predicate,
        )?;

        // Filter out empty results
        let is_empty = match &result {
            QueryResult::Scalar(ScalarValue::Number(n)) => *n == 0,
            QueryResult::Scalar(ScalarValue::String(s)) => s.is_empty(),
            QueryResult::Scalar(ScalarValue::Boolean(_)) => false,
            QueryResult::List(l) => l.is_empty(),
        QueryResult::Structure(_) => false,  // Always include structure results
        QueryResult::Error(_) => false,
    };

        if is_empty {
            Ok(None)
        } else {
            Ok(Some(BatchResult {
                path: path_str,
                result,
            }))
        }
    };

    let results: Vec<(usize, Option<BatchResult>)> = if use_parallel {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build();
        match pool {
            Ok(pool) => pool.install(|| {
                indexed_paths
                    .par_iter()
                    .map(|(idx, path_buf)| {
                        process_path(path_buf).map(|res| (*idx, res))
                    })
                    .collect::<Result<Vec<_>>>()
            })?,
            Err(_) => {
                // Fall back to sequential processing
                indexed_paths
                    .iter()
                    .map(|(idx, path_buf)| {
                        process_path(path_buf).map(|res| (*idx, res))
                    })
                    .collect::<Result<Vec<_>>>()?
            }
        }
    } else {
        indexed_paths
            .iter()
            .map(|(idx, path_buf)| {
                process_path(path_buf).map(|res| (*idx, res))
            })
            .collect::<Result<Vec<_>>>()?
    };

    // Sort by original index to preserve order
    let mut sorted_results: Vec<_> = results.into_iter()
        .filter_map(|(idx, res)| res.map(|r| (idx, r)))
        .collect();
    sorted_results.sort_by_key(|(idx, _)| *idx);

    // Output results
    match output_format {
        OutputFormat::Json => {
            let results_only: Vec<_> = sorted_results.into_iter().map(|(_, r)| r).collect();
            println!("{}", serde_json::to_string_pretty(&results_only)?);
        }
        OutputFormat::Jsonl => {
            for (_, batch_result) in sorted_results {
                println!("{}", serde_json::to_string(&batch_result)?);
            }
        }
        OutputFormat::Text | OutputFormat::Csv | OutputFormat::Dot => {
            for (_, batch_result) in sorted_results {
                match batch_result.result {
                    QueryResult::Scalar(ScalarValue::Number(n)) => {
                        println!("{}: {}", batch_result.path, n)
                    }
                    QueryResult::Scalar(ScalarValue::String(s)) => {
                        println!("{}: {}", batch_result.path, s)
                    }
                    QueryResult::Scalar(ScalarValue::Boolean(b)) => {
                        println!("{}: {}", batch_result.path, b)
                    }
                    QueryResult::List(l) => {
                        for item in l {
                            println!("{}: {}", batch_result.path, item);
                        }
                    }
                QueryResult::Structure(j) => {
                    println!("{}: {}", batch_result.path, serde_json::to_string_pretty(&j)?);
                }
                QueryResult::Error(err) => {
                    println!("{}: {}", batch_result.path, err.message);
                }
            }
        }
    }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sis_pdf_pdf::path_finder::TriggerType;
    use sis_pdf_pdf::typed_graph::{EdgeType, TypedEdge};

    fn with_fixture_context<F>(fixture: &str, test: F)
    where
        F: FnOnce(&ScanContext),
    {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root is two levels above crate manifest");
        let fixture_path = workspace_root
            .join("crates/sis-pdf-core/tests/fixtures")
            .join(fixture);
        let bytes = std::fs::read(&fixture_path).expect("fixture read");
        let options = ScanOptions::default();
        let ctx = build_scan_context(&bytes, &options).expect("build context");
        test(&ctx);
    }

    #[test]
    fn advanced_query_json_outputs_are_structured() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let chains = list_action_chains(ctx).expect("chains");
            assert_eq!(chains["type"], json!("chains"));
            assert!(chains["chains"].is_array());

            let js_chains = list_js_chains(ctx).expect("js chains");
            assert_eq!(js_chains["type"], json!("chains.js"));

            let cycles = list_cycles(ctx).expect("cycles");
            assert_eq!(cycles["type"], json!("cycles"));

            let page_cycles = list_page_cycles(ctx).expect("page cycles");
            assert_eq!(page_cycles["type"], json!("cycles.page"));
        });
    }

    #[test]
    fn chain_to_json_includes_payload_and_edges() {
        let edges = vec![
            TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction),
            TypedEdge::new((2, 0), (3, 0), EdgeType::JavaScriptPayload),
        ];

        let chain = sis_pdf_pdf::path_finder::ActionChain {
            trigger: TriggerType::OpenAction,
            edges: vec![&edges[0], &edges[1]],
            payload: Some((3, 0)),
            automatic: true,
            involves_js: true,
            involves_external: false,
        };

        let json_value = chain_to_json(5, &chain);
        assert_eq!(json_value["id"], json!(5));
        assert_eq!(json_value["trigger"], json!("open_action"));
        assert!(json_value["payload"].is_object());
        assert_eq!(json_value["payload"]["obj"], json!(3));

        let edge_array = json_value["edges"].as_array().unwrap();
        assert_eq!(edge_array.len(), 2);
        assert_eq!(edge_array[1]["type"], json!("javascript_payload"));
        assert_eq!(edge_array[1]["suspicious"], json!(true));
    }

    #[test]
    fn cycle_to_json_builds_path_details() {
        let cycle = vec![(1, 0), (2, 0), (3, 0), (1, 0)];
        let json_value = cycle_to_json(2, &cycle);
        assert_eq!(json_value["id"], json!(2));
        assert_eq!(json_value["length"], json!(4));

        let path = json_value["path"].as_array().unwrap();
        assert_eq!(path.len(), 4);
        assert_eq!(path[0]["obj"], json!(1));
    }

    #[test]
    fn output_format_parsing_accepts_expected_values() {
        assert_eq!(OutputFormat::parse("text").unwrap(), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("jsonl").unwrap(), OutputFormat::Jsonl);
        assert_eq!(OutputFormat::parse("csv").unwrap(), OutputFormat::Csv);
        assert_eq!(OutputFormat::parse("dot").unwrap(), OutputFormat::Dot);
    }

    #[test]
    fn apply_output_format_overrides_export_variants() {
        let query = apply_output_format(Query::ExportOrgDot, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportOrgJson));

        let query = apply_output_format(Query::ExportIrText, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportIrJson));

        let query = apply_output_format(Query::ExportFeatures, OutputFormat::Json).unwrap();
        assert!(matches!(query, Query::ExportFeaturesJson));

        let query = apply_output_format(Query::ExportOrgJson, OutputFormat::Dot).unwrap();
        assert!(matches!(query, Query::ExportOrgDot));

        let error = apply_output_format(Query::Urls, OutputFormat::Csv);
        assert!(error.is_err());
    }

    #[test]
    fn format_jsonl_emits_single_line_json() {
        let result = QueryResult::Scalar(ScalarValue::Number(12));
        let output = format_jsonl("js.count", "sample.pdf", &result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["query"], json!("js.count"));
        assert_eq!(value["file"], json!("sample.pdf"));
        assert_eq!(value["result"], json!(12));
    }

    #[test]
    fn format_hexdump_renders_offsets_and_ascii() {
        let data = b"ABC";
        let output = format_hexdump(data);
        assert!(output.starts_with("00000000"));
        assert!(output.contains("41 42 43"));
        assert!(output.contains("|ABC|"));
    }

    #[test]
    fn list_references_reports_target_and_count() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let entry = ctx.graph.objects.first().expect("object entry");
            let refs = list_references(ctx, entry.obj, entry.gen).expect("references");
            assert_eq!(refs["type"], json!("references"));
            assert_eq!(refs["target"]["obj"], json!(entry.obj));
            assert_eq!(refs["target"]["gen"], json!(entry.gen));
            let count = refs["count"].as_u64().expect("count");
            let list = refs["references"].as_array().expect("references list");
            assert_eq!(count as usize, list.len());
        });
    }

    #[test]
    fn parse_predicate_supports_boolean_logic() {
        let expr = parse_predicate("length > 10 AND entropy >= 5.0").expect("predicate");
        let ctx = PredicateContext {
            length: 20,
            filter: None,
            type_name: "Stream".to_string(),
            subtype: None,
            entropy: 6.5,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn predicate_not_operator_inverts_result() {
        let expr = parse_predicate("NOT type == 'Stream'").expect("predicate");
        let ctx = PredicateContext {
            length: 10,
            filter: None,
            type_name: "Stream".to_string(),
            subtype: None,
            entropy: 0.0,
        };
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn list_objects_respects_predicate_filter() {
        with_fixture_context("content_first_phase1.pdf", |ctx| {
            let all = list_objects(ctx, DecodeMode::Decode, 1024, None).expect("all objects");
            let predicate = parse_predicate("length < 0").expect("predicate");
            let filtered = list_objects(
                ctx,
                DecodeMode::Decode,
                1024,
                Some(&predicate),
            )
            .expect("filtered objects");
            assert!(filtered.is_empty());
            assert!(all.len() >= filtered.len());
        });
    }

    #[test]
    fn predicate_context_for_url_tracks_length() {
        let predicate = parse_predicate("length == 4 AND type == 'Url'").expect("predicate");
        let ctx = predicate_context_for_url("http");
        assert!(predicate.evaluate(&ctx));
    }

    #[test]
    fn predicate_context_for_event_maps_level_and_type() {
        let event = json!({
            "level": "document",
            "event_type": "OpenAction",
            "action_details": "JavaScript: app.alert(1)"
        });
        let predicate = parse_predicate("filter == 'document' AND subtype == 'OpenAction'")
            .expect("predicate");
        let ctx = predicate_context_for_event(&event).expect("context");
        assert!(predicate.evaluate(&ctx));
    }
}

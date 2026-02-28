//! Predicate expression types, parser, and evaluator for `--where` filtering.
//!
//! This module is extracted from the parent `query` module to reduce file size.
//! All symbols are re-exported into the parent via `use self::predicates::*;`.

use anyhow::{anyhow, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum PredicateExpr {
    And(Box<PredicateExpr>, Box<PredicateExpr>),
    Or(Box<PredicateExpr>, Box<PredicateExpr>),
    Not(Box<PredicateExpr>),
    Compare { field: PredicateField, op: PredicateOp, value: PredicateValue },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateField {
    Length,
    Filter,
    Type,
    Subtype,
    Entropy,
    ScriptCount,
    Width,
    Height,
    Pixels,
    Risky,
    Severity,
    Confidence,
    Impact,
    Surface,
    Kind,
    ActionType,
    ActionTarget,
    ActionInitiation,
    Objects,
    Evidence,
    Name,
    Magic,
    Hash,
    Meta(String),
    Url,
    Field,
    HasDoctype,
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
pub(super) struct PredicateContext {
    pub(super) length: usize,
    pub(super) filter: Option<String>,
    pub(super) type_name: String,
    pub(super) subtype: Option<String>,
    pub(super) entropy: f64,
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) pixels: u64,
    pub(super) risky: bool,
    pub(super) severity: Option<String>,
    pub(super) confidence: Option<String>,
    pub(super) surface: Option<String>,
    pub(super) kind: Option<String>,
    pub(super) object_count: usize,
    pub(super) evidence_count: usize,
    pub(super) name: Option<String>,
    pub(super) magic: Option<String>,
    pub(super) hash: Option<String>,
    pub(super) impact: Option<String>,
    pub(super) action_type: Option<String>,
    pub(super) action_target: Option<String>,
    pub(super) action_initiation: Option<String>,
    pub(super) meta: HashMap<String, String>,
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
        Self { lexer: PredicateLexer::new(input), lookahead: None }
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
        Self { input, bytes: input.as_bytes(), index: 0 }
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
    let field = if lower.ends_with(".length")
        || lower == "length"
        || lower == "size"
        || lower.ends_with(".size")
    {
        PredicateField::Length
    } else if lower.ends_with(".filter") || lower == "filter" {
        PredicateField::Filter
    } else if lower.ends_with(".type") || lower == "type" {
        PredicateField::Type
    } else if lower.ends_with(".subtype")
        || lower == "subtype"
        || lower.ends_with(".format")
        || lower == "format"
    {
        PredicateField::Subtype
    } else if lower.ends_with(".entropy") || lower == "entropy" {
        PredicateField::Entropy
    } else if lower.ends_with(".width") || lower == "width" {
        PredicateField::Width
    } else if lower.ends_with(".height") || lower == "height" {
        PredicateField::Height
    } else if lower.ends_with(".pixels") || lower == "pixels" {
        PredicateField::Pixels
    } else if lower.ends_with(".risky") || lower == "risky" {
        PredicateField::Risky
    } else if lower.ends_with(".severity") || lower == "severity" {
        PredicateField::Severity
    } else if lower.ends_with(".confidence") || lower == "confidence" {
        PredicateField::Confidence
    } else if lower.ends_with(".impact") || lower == "impact" {
        PredicateField::Impact
    } else if lower.ends_with(".surface") || lower == "surface" {
        PredicateField::Surface
    } else if lower.ends_with(".kind") || lower == "kind" {
        PredicateField::Kind
    } else if lower == "action_type" || lower.ends_with(".action_type") {
        PredicateField::ActionType
    } else if lower == "action_target" || lower.ends_with(".action_target") {
        PredicateField::ActionTarget
    } else if lower == "action_initiation" || lower.ends_with(".action_initiation") {
        PredicateField::ActionInitiation
    } else if lower.ends_with(".objects")
        || lower == "objects"
        || lower.ends_with(".object_count")
        || lower == "object_count"
    {
        PredicateField::Objects
    } else if lower.ends_with(".evidence")
        || lower == "evidence"
        || lower.ends_with(".evidence_count")
        || lower == "evidence_count"
    {
        PredicateField::Evidence
    } else if lower.ends_with(".name")
        || lower == "name"
        || lower.ends_with(".filename")
        || lower == "filename"
    {
        PredicateField::Name
    } else if lower.ends_with(".magic") || lower == "magic" {
        PredicateField::Magic
    } else if lower.ends_with(".hash") || lower == "hash" {
        PredicateField::Hash
    } else if lower == "script_count" || lower.ends_with(".script_count") {
        PredicateField::ScriptCount
    } else if lower == "url" || lower.ends_with(".url") {
        PredicateField::Url
    } else if lower == "field"
        || lower.ends_with(".field")
        || lower.ends_with(".field_name")
        || lower == "field_name"
    {
        PredicateField::Field
    } else if lower == "has_doctype" || lower.ends_with(".has_doctype") {
        PredicateField::HasDoctype
    } else {
        PredicateField::Meta(lower.clone())
    };
    Ok(field)
}

impl PredicateExpr {
    pub(super) fn evaluate(&self, ctx: &PredicateContext) -> bool {
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
                PredicateField::Width => compare_number(ctx.width as f64, *op, value),
                PredicateField::Height => compare_number(ctx.height as f64, *op, value),
                PredicateField::Pixels => compare_number(ctx.pixels as f64, *op, value),
                PredicateField::Risky => compare_bool(ctx.risky, *op, value),
                PredicateField::Severity => compare_string(ctx.severity.as_deref(), *op, value),
                PredicateField::Confidence => compare_string(ctx.confidence.as_deref(), *op, value),
                PredicateField::Surface => compare_string(ctx.surface.as_deref(), *op, value),
                PredicateField::Kind => compare_string(ctx.kind.as_deref(), *op, value),
                PredicateField::Impact => compare_string(ctx.impact.as_deref(), *op, value),
                PredicateField::ActionType => {
                    compare_string(ctx.action_type.as_deref(), *op, value)
                }
                PredicateField::ActionTarget => {
                    compare_string(ctx.action_target.as_deref(), *op, value)
                }
                PredicateField::ActionInitiation => {
                    compare_string(ctx.action_initiation.as_deref(), *op, value)
                }
                PredicateField::Objects => compare_number(ctx.object_count as f64, *op, value),
                PredicateField::Evidence => compare_number(ctx.evidence_count as f64, *op, value),
                PredicateField::Name => compare_string(ctx.name.as_deref(), *op, value),
                PredicateField::Magic => compare_string(ctx.magic.as_deref(), *op, value),
                PredicateField::Hash => compare_string(ctx.hash.as_deref(), *op, value),
                PredicateField::ScriptCount => {
                    let lhs = ctx
                        .meta
                        .get("script_count")
                        .and_then(|v| v.parse::<f64>().ok())
                        .unwrap_or(0.0);
                    compare_number(lhs, *op, value)
                }
                PredicateField::Url => {
                    let candidate = ctx.meta.get("url").or_else(|| ctx.meta.get("xfa.submit.url"));
                    compare_string(candidate.map(|s| s.as_str()), *op, value)
                }
                PredicateField::Field => {
                    let candidate =
                        ctx.meta.get("field").or_else(|| ctx.meta.get("xfa.field.name"));
                    compare_string(candidate.map(|s| s.as_str()), *op, value)
                }
                PredicateField::HasDoctype => {
                    let actual = ctx.meta.get("has_doctype").map(|v| v == "true").unwrap_or(false);
                    compare_bool(actual, *op, value)
                }
                PredicateField::Meta(key) => compare_meta(ctx.meta.get(key), *op, value),
            },
        }
    }
}

fn compare_bool(lhs: bool, op: PredicateOp, value: &PredicateValue) -> bool {
    let rhs = match value {
        PredicateValue::String(value) => match value.to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => return false,
        },
        PredicateValue::Number(value) => *value != 0.0,
    };
    match op {
        PredicateOp::Eq => lhs == rhs,
        PredicateOp::NotEq => lhs != rhs,
        _ => false,
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
    let lhs_norm = lhs.to_ascii_lowercase();
    let rhs_norm = rhs.to_ascii_lowercase();
    match op {
        PredicateOp::Eq => lhs_norm == rhs_norm,
        PredicateOp::NotEq => lhs_norm != rhs_norm,
        _ => false,
    }
}

fn compare_meta(value: Option<&String>, op: PredicateOp, predicate: &PredicateValue) -> bool {
    if let Some(actual) = value {
        match predicate {
            PredicateValue::Number(_) => {
                if let Ok(lhs) = actual.parse::<f64>() {
                    compare_number(lhs, op, predicate)
                } else {
                    false
                }
            }
            PredicateValue::String(_) => compare_string(Some(actual.as_str()), op, predicate),
        }
    } else {
        false
    }
}

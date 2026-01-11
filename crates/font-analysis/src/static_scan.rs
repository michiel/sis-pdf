use std::collections::{HashMap, HashSet};

use crate::model::{Confidence, FontFinding, Severity, StaticAnalysisOutcome};

const SFNT_HEADER_LEN: usize = 12;
const TABLE_RECORD_LEN: usize = 16;
const MAX_TABLE_COUNT: u16 = 512;
const MAX_TABLE_LENGTH: usize = 8 * 1024 * 1024;
const MAX_FONT_LENGTH: usize = 32 * 1024 * 1024;
const MAX_HINT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TableRecord {
    tag: [u8; 4],
    offset: u32,
    length: u32,
}

pub fn analyse_static(data: &[u8]) -> StaticAnalysisOutcome {
    let mut outcome = StaticAnalysisOutcome::default();
    let mut meta = HashMap::new();
    meta.insert("font.length".into(), data.len().to_string());

    if data.len() > MAX_FONT_LENGTH {
        outcome.findings.push(FontFinding {
            kind: "font.anomalous_table_size".into(),
            severity: Severity::Medium,
            confidence: Confidence::Heuristic,
            title: "Oversized font payload".into(),
            description: "Font length exceeds expected bounds.".into(),
            meta: meta.clone(),
        });
        outcome.risk_score += 1;
    }

    if data.len() < SFNT_HEADER_LEN {
        outcome.findings.push(FontFinding {
            kind: "font.invalid_structure".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Invalid font structure".into(),
            description: "Font data is too short to contain a valid header.".into(),
            meta,
        });
        outcome.risk_score += 3;
        return outcome;
    }

    if !looks_like_sfnt(data) {
        return outcome;
    }

    let num_tables = u16::from_be_bytes([data[4], data[5]]);
    if num_tables == 0 {
        outcome.findings.push(FontFinding {
            kind: "font.invalid_structure".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Invalid font structure".into(),
            description: "Font table directory is empty.".into(),
            meta: meta.clone(),
        });
        outcome.risk_score += 3;
        return outcome;
    }

    if num_tables > MAX_TABLE_COUNT {
        let mut meta = meta.clone();
        meta.insert("font.table_count".into(), num_tables.to_string());
        outcome.findings.push(FontFinding {
            kind: "font.anomalous_table_size".into(),
            severity: Severity::Medium,
            confidence: Confidence::Heuristic,
            title: "Excessive font table count".into(),
            description: "Font declares an unusually high number of tables.".into(),
            meta,
        });
        outcome.risk_score += 1;
    }

    let dir_len = SFNT_HEADER_LEN + (num_tables as usize * TABLE_RECORD_LEN);
    if dir_len > data.len() {
        outcome.findings.push(FontFinding {
            kind: "font.invalid_structure".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Invalid font structure".into(),
            description: "Font table directory extends beyond file length.".into(),
            meta: meta.clone(),
        });
        outcome.risk_score += 3;
        return outcome;
    }

    let mut seen_tags = HashSet::new();
    let mut records = Vec::with_capacity(num_tables as usize);
    let mut invalid_tables = Vec::new();
    let mut oversized_tables = Vec::new();
    let mut hinting_tables = Vec::new();
    let mut duplicates = Vec::new();

    for i in 0..num_tables as usize {
        let start = SFNT_HEADER_LEN + i * TABLE_RECORD_LEN;
        let tag = [data[start], data[start + 1], data[start + 2], data[start + 3]];
        let offset = u32::from_be_bytes([
            data[start + 8],
            data[start + 9],
            data[start + 10],
            data[start + 11],
        ]);
        let length = u32::from_be_bytes([
            data[start + 12],
            data[start + 13],
            data[start + 14],
            data[start + 15],
        ]);

        if !seen_tags.insert(tag) {
            duplicates.push(tag_to_string(tag));
        }

        let end = offset as u64 + length as u64;
        if end as usize > data.len() {
            invalid_tables.push(format!(
                "{}:{}-{}",
                tag_to_string(tag),
                offset,
                end
            ));
        }
        if length as usize > MAX_TABLE_LENGTH {
            oversized_tables.push(format!(
                "{}:{}",
                tag_to_string(tag),
                length
            ));
        }
        if is_hinting_table(tag) && length as usize > MAX_HINT_BYTES {
            hinting_tables.push(format!(
                "{}:{}",
                tag_to_string(tag),
                length
            ));
        }

        records.push(TableRecord { tag, offset, length });
    }

    if !invalid_tables.is_empty() {
        let mut meta = meta.clone();
        meta.insert("font.invalid_tables".into(), invalid_tables.join(","));
        outcome.findings.push(FontFinding {
            kind: "font.invalid_structure".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Invalid font structure".into(),
            description: "One or more font tables reference offsets outside the file.".into(),
            meta,
        });
        outcome.risk_score += 3;
    }

    if !duplicates.is_empty() {
        let mut meta = meta.clone();
        meta.insert("font.duplicate_tables".into(), duplicates.join(","));
        outcome.findings.push(FontFinding {
            kind: "font.inconsistent_table_layout".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Inconsistent font table layout".into(),
            description: "Font table directory contains duplicate tags.".into(),
            meta,
        });
        outcome.risk_score += 2;
    }

    if !oversized_tables.is_empty() {
        let mut meta = meta.clone();
        meta.insert("font.oversized_tables".into(), oversized_tables.join(","));
        outcome.findings.push(FontFinding {
            kind: "font.anomalous_table_size".into(),
            severity: Severity::Medium,
            confidence: Confidence::Heuristic,
            title: "Anomalous font table sizes".into(),
            description: "Font tables exceed expected size limits.".into(),
            meta,
        });
        outcome.risk_score += 1;
    }

    if !hinting_tables.is_empty() {
        let mut meta = meta.clone();
        meta.insert("font.hinting_tables".into(), hinting_tables.join(","));
        outcome.findings.push(FontFinding {
            kind: "font.suspicious_hinting".into(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            title: "Suspicious hinting programs".into(),
            description: "Hinting programs are unusually large.".into(),
            meta,
        });
        outcome.risk_score += 1;
    }

    records.sort_by_key(|r| r.offset);
    let mut overlaps = Vec::new();
    let mut prev_end = 0u64;
    for record in &records {
        let start = record.offset as u64;
        let end = record.offset as u64 + record.length as u64;
        if start < prev_end {
            overlaps.push(tag_to_string(record.tag));
        }
        prev_end = prev_end.max(end);
    }

    if !overlaps.is_empty() {
        let mut meta = meta.clone();
        meta.insert("font.overlapping_tables".into(), overlaps.join(","));
        outcome.findings.push(FontFinding {
            kind: "font.inconsistent_table_layout".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "Inconsistent font table layout".into(),
            description: "Font tables overlap in the file.".into(),
            meta,
        });
        outcome.risk_score += 2;
    }

    outcome
}

fn looks_like_sfnt(data: &[u8]) -> bool {
    matches!(
        &data[0..4],
        b"\x00\x01\x00\x00" | b"OTTO" | b"true" | b"typ1"
    )
}

fn tag_to_string(tag: [u8; 4]) -> String {
    tag.iter()
        .map(|b| if b.is_ascii_graphic() { *b as char } else { '?' })
        .collect()
}

fn is_hinting_table(tag: [u8; 4]) -> bool {
    matches!(&tag, b"fpgm" | b"prep" | b"cvt ")
}

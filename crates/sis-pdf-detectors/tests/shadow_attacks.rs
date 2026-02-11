mod common;

use common::default_scan_opts;
use sis_pdf_core::model::{Confidence, Severity};
use sis_pdf_detectors::default_detectors;

#[derive(Clone, Copy)]
enum ShadowMode {
    Hide,
    Replace,
    HideReplace,
}

fn build_signed_incremental_pdf(mode: ShadowMode) -> Vec<u8> {
    let mut rev1 = Vec::new();
    rev1.extend_from_slice(b"%PDF-1.4\n");
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>\nendobj\n"
            .to_string(),
        "4 0 obj\n<< /Length 33 >>\nstream\nBT /F1 12 Tf 10 10 Td (Signed) Tj ET\nendstream\nendobj\n"
            .to_string(),
        "5 0 obj\n<< /Type /Sig /ByteRange [0 0000000000 0000000000 0] /Contents <00112233> >>\nendobj\n"
            .to_string(),
    ];
    let mut offsets = [0usize; 6];
    for object in &objects {
        let header = object.as_bytes()[0];
        let obj_id = if header == b'1' {
            1
        } else if header == b'2' {
            2
        } else if header == b'3' {
            3
        } else if header == b'4' {
            4
        } else {
            5
        };
        offsets[obj_id] = rev1.len();
        rev1.extend_from_slice(object.as_bytes());
    }
    let startxref_rev1 = rev1.len();
    rev1.extend_from_slice(b"xref\n0 6\n");
    rev1.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        let line = format!("{offset:010} 00000 n \n");
        rev1.extend_from_slice(line.as_bytes());
    }
    rev1.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
    rev1.extend_from_slice(startxref_rev1.to_string().as_bytes());
    rev1.extend_from_slice(b"\n%%EOF\n");

    let rev1_len = rev1.len();
    let padded = format!("{rev1_len:010}");
    let first_placeholder = b"0000000000";
    let mut replaced = 0usize;
    let mut idx = 0usize;
    while idx + first_placeholder.len() <= rev1.len() && replaced < 2 {
        if &rev1[idx..idx + first_placeholder.len()] == first_placeholder {
            rev1[idx..idx + first_placeholder.len()].copy_from_slice(padded.as_bytes());
            replaced += 1;
            idx += first_placeholder.len();
            continue;
        }
        idx += 1;
    }

    let mut out = rev1;
    out.extend_from_slice(b"\n");
    let mut updated_offsets = Vec::new();
    match mode {
        ShadowMode::Hide => {
            let off6 = out.len();
            out.extend_from_slice(
                b"6 0 obj\n<< /Subtype /Widget /Rect [0 0 300 300] /AP << /N 4 0 R >> >>\nendobj\n",
            );
            updated_offsets.push((6u32, off6));
        }
        ShadowMode::Replace => {
            let off4 = out.len();
            out.extend_from_slice(
                b"4 0 obj\n<< /Length 35 >>\nstream\nBT /F1 12 Tf 10 10 Td (Tampered) Tj ET\nendstream\nendobj\n",
            );
            updated_offsets.push((4u32, off4));
        }
        ShadowMode::HideReplace => {
            let off4 = out.len();
            out.extend_from_slice(
                b"4 0 obj\n<< /Length 35 >>\nstream\nBT /F1 12 Tf 10 10 Td (Tampered) Tj ET\nendstream\nendobj\n",
            );
            updated_offsets.push((4u32, off4));
            let off6 = out.len();
            out.extend_from_slice(
                b"6 0 obj\n<< /Subtype /Widget /Rect [0 0 300 300] /AP << /N 4 0 R >> >>\nendobj\n",
            );
            updated_offsets.push((6u32, off6));
        }
    }

    let startxref_rev2 = out.len();
    out.extend_from_slice(b"xref\n");
    updated_offsets.sort_by_key(|(obj, _)| *obj);
    let mut run_start = 0u32;
    let mut run = Vec::new();
    for (idx, (obj, offset)) in updated_offsets.iter().enumerate() {
        if idx == 0 {
            run_start = *obj;
            run.push((*obj, *offset));
            continue;
        }
        let prev = updated_offsets[idx - 1].0;
        if *obj == prev + 1 {
            run.push((*obj, *offset));
        } else {
            out.extend_from_slice(format!("{run_start} {}\n", run.len()).as_bytes());
            for (_, off) in &run {
                out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
            }
            run_start = *obj;
            run.clear();
            run.push((*obj, *offset));
        }
    }
    if !run.is_empty() {
        out.extend_from_slice(format!("{run_start} {}\n", run.len()).as_bytes());
        for (_, off) in &run {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
    }

    out.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R /Prev ");
    out.extend_from_slice(startxref_rev1.to_string().as_bytes());
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(startxref_rev2.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
    out
}

fn build_certified_incremental_pdf(
    permission_level: i64,
    add_annotation_overlay: bool,
    add_signature_overlay: bool,
) -> Vec<u8> {
    let mut rev1 = Vec::new();
    rev1.extend_from_slice(b"%PDF-1.7\n");
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>\nendobj\n"
            .to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 400] /Contents 4 0 R >>\nendobj\n"
            .to_string(),
        "4 0 obj\n<< /Length 32 >>\nstream\nBT /F1 12 Tf 10 10 Td (Base) Tj ET\nendstream\nendobj\n"
            .to_string(),
        format!(
            "5 0 obj\n<< /Type /Sig /ByteRange [0 0000000000 0000000000 0] /Reference [6 0 R] /Contents <0011223344> >>\nendobj\n"
        ),
        format!(
            "6 0 obj\n<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P {} /V /1.2 >> >>\nendobj\n",
            permission_level
        ),
    ];
    let mut offsets = [0usize; 7];
    for object in &objects {
        let id = object
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if id < offsets.len() {
            offsets[id] = rev1.len();
        }
        rev1.extend_from_slice(object.as_bytes());
    }
    let startxref_rev1 = rev1.len();
    rev1.extend_from_slice(b"xref\n0 7\n");
    rev1.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        let line = format!("{offset:010} 00000 n \n");
        rev1.extend_from_slice(line.as_bytes());
    }
    rev1.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n");
    rev1.extend_from_slice(startxref_rev1.to_string().as_bytes());
    rev1.extend_from_slice(b"\n%%EOF\n");

    let rev1_len = rev1.len();
    let padded = format!("{rev1_len:010}");
    let placeholder = b"0000000000";
    let mut replaced = 0usize;
    let mut idx = 0usize;
    while idx + placeholder.len() <= rev1.len() && replaced < 2 {
        if &rev1[idx..idx + placeholder.len()] == placeholder {
            rev1[idx..idx + placeholder.len()].copy_from_slice(padded.as_bytes());
            replaced += 1;
            idx += placeholder.len();
            continue;
        }
        idx += 1;
    }

    let mut out = rev1;
    out.extend_from_slice(b"\n");
    let mut updated_offsets = Vec::new();
    if add_annotation_overlay {
        let off = out.len();
        out.extend_from_slice(
            b"7 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 360 360] /AP << /N 4 0 R >> >>\nendobj\n",
        );
        updated_offsets.push((7u32, off));
    }
    if add_signature_overlay {
        let object_number = if add_annotation_overlay { 8u32 } else { 7u32 };
        let off = out.len();
        let payload = format!(
            "{} 0 obj\n<< /Subtype /Widget /FT /Sig /Rect [0 0 360 360] /AP << /N 4 0 R >> >>\nendobj\n",
            object_number
        );
        out.extend_from_slice(payload.as_bytes());
        updated_offsets.push((object_number, off));
    }

    let startxref_rev2 = out.len();
    out.extend_from_slice(b"xref\n");
    updated_offsets.sort_by_key(|(obj, _)| *obj);
    let first_obj = updated_offsets.first().map(|(obj, _)| *obj).unwrap_or(7);
    out.extend_from_slice(format!("{first_obj} {}\n", updated_offsets.len()).as_bytes());
    for (_, offset) in &updated_offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(b"trailer\n<< /Size 9 /Root 1 0 R /Prev ");
    out.extend_from_slice(startxref_rev1.to_string().as_bytes());
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(startxref_rev2.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
    out
}

#[test]
fn detects_shadow_hide_attack() {
    let bytes = build_signed_incremental_pdf(ShadowMode::Hide);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let shadow_finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "shadow_hide_attack")
        .expect("shadow hide finding");
    assert_eq!(
        shadow_finding.meta.get("shadow.diff.objects_added").map(|value| value.as_str()),
        Some("1")
    );
    assert!(!report.findings.iter().any(|finding| finding.kind == "shadow_replace_attack"));
}

#[test]
fn detects_shadow_replace_attack() {
    let bytes = build_signed_incremental_pdf(ShadowMode::Replace);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    assert!(report.findings.iter().any(|finding| finding.kind == "shadow_replace_attack"));
    assert!(!report.findings.iter().any(|finding| finding.kind == "shadow_hide_attack"));
}

#[test]
fn detects_shadow_hide_replace_attack() {
    let bytes = build_signed_incremental_pdf(ShadowMode::HideReplace);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    assert!(report.findings.iter().any(|finding| finding.kind == "shadow_hide_attack"));
    assert!(report.findings.iter().any(|finding| finding.kind == "shadow_replace_attack"));
    assert!(report.findings.iter().any(|finding| finding.kind == "shadow_hide_replace_attack"));
}

#[test]
fn detects_certified_doc_manipulation_for_disallowed_p1_changes() {
    let bytes = build_certified_incremental_pdf(1, true, true);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|candidate| candidate.kind == "certified_doc_manipulation")
        .expect("certified doc finding");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Strong);
    assert_eq!(
        finding.meta.get("certified.permission_violation").map(|value| value.as_str()),
        Some("true")
    );
    assert_eq!(
        finding.meta.get("certified.disallowed_changes").map(|value| value.as_str()),
        Some("annotations,signature_fields")
    );
}

#[test]
fn detects_certified_doc_manipulation_for_p3_allowed_changes_with_lower_confidence() {
    let bytes = build_certified_incremental_pdf(3, true, true);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|candidate| candidate.kind == "certified_doc_manipulation")
        .expect("certified doc finding");
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::Tentative);
    assert_eq!(
        finding.meta.get("certified.permission_violation").map(|value| value.as_str()),
        Some("false")
    );
}

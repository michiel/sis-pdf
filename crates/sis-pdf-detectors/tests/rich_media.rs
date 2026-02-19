mod common;
use common::default_scan_opts;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

fn build_pdf_with_objects(objects: &[&str]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; objects.len() + 1];
    for object in objects {
        let obj_num = object
            .split_whitespace()
            .next()
            .and_then(|token| token.parse::<usize>().ok())
            .expect("object number");
        if obj_num < offsets.len() {
            offsets[obj_num] = pdf.len();
        }
        pdf.extend_from_slice(object.as_bytes());
    }
    let start_xref = pdf.len();
    let size = offsets.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    pdf.extend_from_slice(start_xref.to_string().as_bytes());
    pdf.extend_from_slice(b"\n%%EOF\n");
    pdf
}

fn build_pdf_with_raw_objects(objects: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");

    let max_obj = objects.iter().map(|(obj, _)| *obj).max().unwrap_or(0);
    let mut offsets = vec![0usize; max_obj + 1];
    for (obj_num, object_bytes) in objects {
        offsets[*obj_num] = pdf.len();
        pdf.extend_from_slice(object_bytes);
        if !object_bytes.ends_with(b"\n") {
            pdf.push(b'\n');
        }
    }

    let start_xref = pdf.len();
    let size = offsets.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    pdf.extend_from_slice(start_xref.to_string().as_bytes());
    pdf.extend_from_slice(b"\n%%EOF\n");
    pdf
}

#[test]
fn detects_swf_action_tags() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/media/swf_cve_2011_0611.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let swf_filtered: Vec<&_> =
        report.findings.iter().filter(|f| f.kind == "swf_actionscript_detected").collect();
    assert!(!swf_filtered.is_empty(), "expected ActionScript finding");
    let meta = &swf_filtered[0].meta;
    assert_eq!(meta.get("swf.action_tag_count").map(String::as_str), Some("1"));
    assert!(
        meta.get("swf.action_tags").map(|value| value.contains("DoABC")).unwrap_or(false),
        "expected DoABC name"
    );
}

#[test]
fn detects_3d_structure_anomaly_for_malformed_u3d_payload() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
        "3 0 obj\n<< /Type /3D /Length 12 >>\nstream\n\x00\x00\x00$\x00\x00\x01\x00AAAA\nendstream\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "richmedia_3d_structure_anomaly")
        .expect("richmedia_3d_structure_anomaly");
    assert_eq!(finding.meta.get("media_type").map(std::string::String::as_str), Some("u3d"));
    assert!(finding
        .meta
        .get("richmedia.3d.structure_anomalies")
        .map(|value| value.contains("u3d_declared_block_len_out_of_bounds"))
        .unwrap_or(false));
}

#[test]
fn correlates_3d_anomaly_with_decoder_risk_factors() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
        "3 0 obj\n<< /Type /3D /Filter [/FlateDecode /ASCII85Decode /RunLengthDecode] /Length 12 >>\nstream\n\x00\x00\x00$\x00\x00\x01\x00AAAA\nendstream\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let risk = report
        .findings
        .iter()
        .find(|finding| finding.kind == "richmedia_3d_decoder_risk")
        .expect("richmedia_3d_decoder_risk");
    assert!(risk
        .meta
        .get("richmedia.3d.decoder_correlation")
        .map(|value| value.contains("filter_depth=3"))
        .unwrap_or(false));
}

#[test]
fn detects_u3d_block_table_bounds_anomaly() {
    let stream = vec![
        0x00, 0x00, 0x00, 0x24, // U3D marker
        0x00, 0x00, 0x00, 0x04, // block data length
        0x00, 0x00, 0x00, 0x20, // metadata length (out of bounds)
        b'A', b'B', b'C', b'D',
    ];
    let mut object_three = Vec::new();
    object_three.extend_from_slice(b"3 0 obj\n<< /Type /3D /Length 16 >>\nstream\n");
    object_three.extend_from_slice(&stream);
    object_three.extend_from_slice(b"\nendstream\nendobj\n");
    let objects = vec![
        (1usize, b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_vec()),
        (2usize, b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_vec()),
        (3usize, object_three),
    ];
    let bytes = build_pdf_with_raw_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "richmedia_3d_structure_anomaly")
        .expect("richmedia_3d_structure_anomaly");
    assert!(finding
        .meta
        .get("richmedia.3d.structure_anomalies")
        .map(|value| value.contains("u3d_block_table_out_of_bounds"))
        .unwrap_or(false));
    assert_eq!(
        finding.meta.get("richmedia.3d.block_count_estimate").map(String::as_str),
        Some("0")
    );
}

#[test]
fn flags_decode_expansion_ratio_for_3d_streams() {
    let mut decoded = Vec::new();
    decoded.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x24, // U3D marker
        0x00, 0x00, 0x00, 0x08, // first block length
        0x00, 0x00, 0x00, 0x00, // metadata length
    ]);
    decoded.extend_from_slice(b"ABCDEFGH");
    decoded.extend(std::iter::repeat(b'A').take(8192));

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&decoded).expect("compress");
    let compressed = encoder.finish().expect("finish");

    let mut object_three = Vec::new();
    object_three.extend_from_slice(
        format!(
            "3 0 obj\n<< /Type /3D /Filter /FlateDecode /Length {} >>\nstream\n",
            compressed.len()
        )
        .as_bytes(),
    );
    object_three.extend_from_slice(&compressed);
    object_three.extend_from_slice(b"\nendstream\nendobj\n");

    let objects = vec![
        (1usize, b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_vec()),
        (2usize, b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_vec()),
        (3usize, object_three),
    ];
    let bytes = build_pdf_with_raw_objects(&objects);
    let detectors = sis_pdf_detectors::default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "richmedia_3d_structure_anomaly")
        .expect("richmedia_3d_structure_anomaly");
    assert!(finding
        .meta
        .get("richmedia.3d.structure_anomalies")
        .map(|value| value.contains("richmedia_decode_expansion_ratio_high"))
        .unwrap_or(false));
    assert!(finding
        .meta
        .get("richmedia.3d.decoded_expansion_ratio")
        .map(|value| value.parse::<f64>().ok().is_some_and(|ratio| ratio > 40.0))
        .unwrap_or(false));
}

#[test]
fn richmedia_presence_uses_conservative_viewer_dependent_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n",
        "4 0 obj\n<< /Subtype /RichMedia /RichMedia << /Assets 5 0 R >> >>\nendobj\n",
        "5 0 obj\n<< /Names [] >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &sis_pdf_detectors::default_detectors(),
    )
    .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|entry| entry.kind == "richmedia_present")
        .expect("richmedia_present finding");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(finding.impact, Some(sis_pdf_core::model::Impact::Low));
    assert_eq!(finding.meta.get("viewer.feature").map(String::as_str), Some("richmedia"));
    assert_eq!(
        finding.meta.get("renderer.precondition").map(String::as_str),
        Some("richmedia_runtime_enabled")
    );
    assert_eq!(finding.meta.get("chain.stage").map(String::as_str), Some("render"));
}

#[test]
fn rendition_external_target_adds_egress_context_metadata() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /AA << /O 4 0 R >> >>\nendobj\n",
        "4 0 obj\n<< /S /Rendition /Rendition << /S /MR /C << /S /URI /URI (https://media.example/payload.mp4) >> >> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &sis_pdf_detectors::default_detectors(),
    )
    .expect("scan");
    let finding = report
        .findings
        .iter()
        .find(|entry| entry.kind == "sound_movie_present")
        .expect("sound_movie_present finding");
    assert_eq!(finding.severity, sis_pdf_core::model::Severity::Low);
    assert_eq!(finding.meta.get("media.rendition_present").map(String::as_str), Some("true"));
    assert_eq!(
        finding.meta.get("media.external_target").map(String::as_str),
        Some("https://media.example/payload.mp4")
    );
    assert_eq!(finding.meta.get("egress.channel").map(String::as_str), Some("media_rendition"));
}

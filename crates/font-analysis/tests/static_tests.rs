use font_analysis::static_scan::analyse_static;

fn build_sfnt(records: &[(<&[u8; 4], u32, u32>)], length: usize) -> Vec<u8> {
    let num_tables = records.len() as u16;
    let mut data = vec![0u8; length.max(12 + 16 * records.len())];
    data[0..4].copy_from_slice(b"\x00\x01\x00\x00");
    data[4..6].copy_from_slice(&num_tables.to_be_bytes());
    for (idx, (tag, offset, len)) in records.iter().enumerate() {
        let start = 12 + idx * 16;
        data[start..start + 4].copy_from_slice(tag.as_slice());
        data[start + 8..start + 12].copy_from_slice(&offset.to_be_bytes());
        data[start + 12..start + 16].copy_from_slice(&len.to_be_bytes());
    }
    data
}

#[test]
fn flags_short_font() {
    let outcome = analyse_static(&[0u8; 4]);
    assert!(outcome.findings.iter().any(|f| f.kind == "font.invalid_structure"));
}

#[test]
fn flags_overlapping_tables() {
    let data = build_sfnt(
        &[
            (&*b"head", 40, 12),
            (&*b"glyf", 45, 12),
        ],
        80,
    );
    let outcome = analyse_static(&data);
    assert!(outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.inconsistent_table_layout"));
}

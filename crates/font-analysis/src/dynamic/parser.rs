/// Dynamic font parser using ttf-parser for comprehensive analysis

#[cfg(feature = "dynamic")]
use ttf_parser::Face;

/// Font context extracted from parsing
#[cfg(feature = "dynamic")]
#[derive(Debug, Clone)]
pub struct FontContext {
    pub glyph_count_maxp: Option<u16>,
    pub glyph_count_cff: Option<usize>,
    pub num_h_metrics: Option<u16>,
    pub hmtx_length: Option<usize>,
    pub has_gvar: bool,
    pub has_cff2: bool,
    pub has_ebsc: bool,
    pub tables: Vec<TableInfo>,
}

#[cfg(not(feature = "dynamic"))]
#[derive(Debug, Clone)]
pub struct FontContext {}

#[cfg(feature = "dynamic")]
#[derive(Debug, Clone)]
pub struct TableInfo {
    pub tag: String,
    pub offset: usize,
    pub length: usize,
}

#[cfg(not(feature = "dynamic"))]
#[derive(Debug, Clone)]
pub struct TableInfo {}

#[cfg(feature = "dynamic")]
pub fn parse_font(data: &[u8]) -> Result<FontContext, String> {
    let face = Face::parse(data, 0).map_err(|e| format!("Failed to parse font: {:?}", e))?;

    let mut context = FontContext {
        glyph_count_maxp: None,
        glyph_count_cff: None,
        num_h_metrics: None,
        hmtx_length: None,
        has_gvar: false,
        has_cff2: false,
        has_ebsc: false,
        tables: Vec::new(),
    };

    // Extract glyph count from maxp
    context.glyph_count_maxp = Some(face.number_of_glyphs());

    // Extract horizontal metrics info from hhea
    // ttf-parser stores number_of_h_metrics as a public field
    let hhea_table = face.tables().hhea;
    context.num_h_metrics = Some(hhea_table.number_of_metrics);

    // Check for variable font tables
    context.has_gvar = face.tables().gvar.is_some();

    // Check for CFF2 (OpenType with CFF2 outline)
    // Note: ttf-parser doesn't expose CFF2 directly, so we check table presence
    context.has_cff2 = has_table(data, b"CFF2");
    context.has_ebsc = has_table(data, b"EBSC");

    // Extract table information for analysis
    extract_tables(data, &mut context)?;

    Ok(context)
}

#[cfg(feature = "dynamic")]
fn has_table(data: &[u8], tag: &[u8; 4]) -> bool {
    if data.len() < 12 {
        return false;
    }

    // Read number of tables
    let num_tables = u16::from_be_bytes([data[4], data[5]]);
    let table_dir_offset = 12;

    for i in 0..num_tables as usize {
        let offset = table_dir_offset + i * 16;
        if offset + 16 > data.len() {
            break;
        }

        let table_tag = &data[offset..offset + 4];
        if table_tag == tag {
            return true;
        }
    }

    false
}

#[cfg(feature = "dynamic")]
fn extract_tables(data: &[u8], context: &mut FontContext) -> Result<(), String> {
    if data.len() < 12 {
        return Err("Font data too short".to_string());
    }

    let num_tables = u16::from_be_bytes([data[4], data[5]]);
    let table_dir_offset = 12;

    for i in 0..num_tables as usize {
        let offset = table_dir_offset + i * 16;
        if offset + 16 > data.len() {
            break;
        }

        let tag_bytes = &data[offset..offset + 4];
        let tag = String::from_utf8_lossy(tag_bytes).to_string();

        let table_offset = u32::from_be_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]) as usize;

        let table_length = u32::from_be_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]) as usize;

        // Special handling for hmtx to get exact length
        if tag == "hmtx" {
            context.hmtx_length = Some(table_length);
        }

        context.tables.push(TableInfo {
            tag,
            offset: table_offset,
            length: table_length,
        });
    }

    Ok(())
}

#[cfg(not(feature = "dynamic"))]
pub fn parse_font(_data: &[u8]) -> Result<FontContext, String> {
    Err("dynamic analysis not compiled".to_string())
}

#[cfg(test)]
#[cfg(feature = "dynamic")]
mod tests {
    use super::*;

    #[test]
    fn test_has_table() {
        // Create minimal TrueType header with one table
        let mut data = vec![0u8; 12 + 16];
        data[0..4].copy_from_slice(b"\x00\x01\x00\x00"); // TrueType signature
        data[4..6].copy_from_slice(&1u16.to_be_bytes()); // 1 table
        data[12..16].copy_from_slice(b"head"); // table tag

        assert!(has_table(&data, b"head"));
        assert!(!has_table(&data, b"glyf"));
    }
}

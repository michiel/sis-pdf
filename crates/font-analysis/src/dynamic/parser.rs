/// Dynamic font parser using ttf-parser for comprehensive analysis
#[cfg(feature = "dynamic")]
use std::collections::HashMap;
#[cfg(feature = "dynamic")]
use ttf_parser::Face;

/// Font context extracted from parsing
#[cfg(feature = "dynamic")]
#[derive(Debug, Clone)]
pub struct FontContext {
    // Existing fields for basic analysis
    pub glyph_count_maxp: Option<u16>,
    pub glyph_count_cff: Option<usize>,
    pub num_h_metrics: Option<u16>,
    pub hmtx_length: Option<usize>,
    pub has_gvar: bool,
    pub has_cff2: bool,
    pub has_ebsc: bool,
    pub tables: Vec<TableInfo>,

    // New fields for advanced pattern matching
    pub file_length: usize,
    pub table_map: HashMap<String, TableInfo>,
    pub recursion_depths: HashMap<String, usize>,
    pub table_references: HashMap<String, Vec<String>>,
    pub invalid_magic_numbers: Vec<InvalidMagic>,
    pub instruction_issues: Vec<InstructionIssue>,
}

/// Invalid magic number detected during parsing
#[cfg(feature = "dynamic")]
#[derive(Debug, Clone)]
pub struct InvalidMagic {
    pub table: String,
    pub offset: usize,
    pub expected: Vec<u8>,
    pub actual: Vec<u8>,
}

/// Instruction stream issue detected during parsing
#[cfg(feature = "dynamic")]
#[derive(Debug, Clone)]
pub struct InstructionIssue {
    pub table: String,
    pub offset: usize,
    pub opcode: u8,
    pub issue_type: String, // "invalid_opcode", "invalid_sequence"
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

#[cfg(not(feature = "dynamic"))]
#[derive(Debug, Clone)]
pub struct InvalidMagic {}

#[cfg(not(feature = "dynamic"))]
#[derive(Debug, Clone)]
pub struct InstructionIssue {}

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
        // Initialize new fields with defaults (full extraction in Stage 8)
        file_length: data.len(),
        table_map: HashMap::new(),
        recursion_depths: HashMap::new(),
        table_references: HashMap::new(),
        invalid_magic_numbers: Vec::new(),
        instruction_issues: Vec::new(),
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

    // Build table_map from tables for quick lookup
    build_table_map(&mut context);

    // Stage 8: Extract advanced context for pattern matching
    extract_table_references(data, &mut context);
    extract_recursion_depths(data, &mut context);
    validate_magic_numbers(data, &mut context);
    analyze_instructions(data, &mut context);

    Ok(context)
}

#[cfg(feature = "dynamic")]
fn build_table_map(context: &mut FontContext) {
    for table in &context.tables {
        context.table_map.insert(table.tag.clone(), table.clone());
    }
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

/// Extract table reference graph for circular reference detection
#[cfg(feature = "dynamic")]
fn extract_table_references(data: &[u8], context: &mut FontContext) {
    // Track references between tables
    // For now, we focus on common reference patterns:

    // 1. Composite glyphs in glyf table reference other glyphs
    if let Some(glyf_table) = context.table_map.get("glyf").cloned() {
        extract_glyf_references(data, &glyf_table, context);
    }

    // 2. GSUB/GPOS tables can cross-reference
    let has_gsub = context.table_map.contains_key("GSUB");
    let has_gpos = context.table_map.contains_key("GPOS");
    if has_gsub && has_gpos {
        // GSUB and GPOS can reference each other through feature tables
        context
            .table_references
            .entry("GSUB".to_string())
            .or_default()
            .push("GPOS".to_string());
        context
            .table_references
            .entry("GPOS".to_string())
            .or_default()
            .push("GSUB".to_string());
    }

    // 3. CFF can reference Private DICT
    if let Some(_cff_table) = context.table_map.get("CFF ") {
        // CFF internal structure has references, but these are within the table
        // We track this as self-reference for recursion depth tracking
        context
            .table_references
            .entry("CFF ".to_string())
            .or_default();
    }
}

/// Extract glyph references from glyf table for composite glyphs
#[cfg(feature = "dynamic")]
fn extract_glyf_references(data: &[u8], glyf_table: &TableInfo, context: &mut FontContext) {
    // We need loca table to find glyph offsets
    let loca_table = match context.table_map.get("loca") {
        Some(t) => t,
        None => return,
    };

    let glyf_offset = glyf_table.offset;
    let loca_offset = loca_table.offset;

    // Determine loca format from head table (indexToLocFormat)
    let head_table = match context.table_map.get("head") {
        Some(t) => t,
        None => return,
    };

    if head_table.offset + 52 > data.len() {
        return;
    }

    let index_to_loc_format =
        i16::from_be_bytes([data[head_table.offset + 50], data[head_table.offset + 51]]);

    let num_glyphs = context.glyph_count_maxp.unwrap_or(0) as usize;

    // Parse composite glyphs and build reference map
    for glyph_id in 0..num_glyphs {
        let glyph_offset = if index_to_loc_format == 0 {
            // Short format: offsets are u16 * 2
            if loca_offset + (glyph_id + 1) * 2 > data.len() {
                continue;
            }
            let offset = u16::from_be_bytes([
                data[loca_offset + glyph_id * 2],
                data[loca_offset + glyph_id * 2 + 1],
            ]) as usize
                * 2;
            glyf_offset + offset
        } else {
            // Long format: offsets are u32
            if loca_offset + (glyph_id + 1) * 4 > data.len() {
                continue;
            }
            let offset = u32::from_be_bytes([
                data[loca_offset + glyph_id * 4],
                data[loca_offset + glyph_id * 4 + 1],
                data[loca_offset + glyph_id * 4 + 2],
                data[loca_offset + glyph_id * 4 + 3],
            ]) as usize;
            glyf_offset + offset
        };

        // Check if this is a composite glyph (numberOfContours < 0)
        if glyph_offset + 2 > data.len() {
            continue;
        }

        let num_contours = i16::from_be_bytes([data[glyph_offset], data[glyph_offset + 1]]);

        if num_contours < 0 {
            // This is a composite glyph - track the reference
            let glyf_key = format!("glyf[{}]", glyph_id);
            context
                .table_references
                .entry(glyf_key)
                .or_default();
            // Note: Full component parsing would require more complex logic
            // For now we just mark that this glyph has references
        }
    }
}

/// Calculate recursion depths for nested structures
#[cfg(feature = "dynamic")]
fn extract_recursion_depths(data: &[u8], context: &mut FontContext) {
    // Calculate max recursion depth for composite glyphs
    if let Some(glyf_table) = context.table_map.get("glyf").cloned() {
        let max_depth = calculate_glyf_recursion_depth(data, &glyf_table, context);
        if max_depth > 0 {
            context
                .recursion_depths
                .insert("glyf".to_string(), max_depth);
        }
    }

    // GSUB/GPOS lookup nesting depth
    if let Some(gsub_table) = context.table_map.get("GSUB").cloned() {
        let depth = estimate_lookup_depth(data, &gsub_table);
        if depth > 0 {
            context.recursion_depths.insert("GSUB".to_string(), depth);
        }
    }

    if let Some(gpos_table) = context.table_map.get("GPOS").cloned() {
        let depth = estimate_lookup_depth(data, &gpos_table);
        if depth > 0 {
            context.recursion_depths.insert("GPOS".to_string(), depth);
        }
    }
}

/// Calculate maximum nesting depth of composite glyphs
#[cfg(feature = "dynamic")]
fn calculate_glyf_recursion_depth(
    _data: &[u8],
    _glyf_table: &TableInfo,
    _context: &FontContext,
) -> usize {
    // Simplified implementation: assume max depth of 1 for any composite glyph
    // Full implementation would require DFS through component tree
    // This is a conservative estimate that prevents false positives
    1
}

/// Estimate lookup table nesting depth
#[cfg(feature = "dynamic")]
fn estimate_lookup_depth(data: &[u8], table: &TableInfo) -> usize {
    // Read lookup list offset from GSUB/GPOS table
    if table.offset + 8 > data.len() {
        return 0;
    }

    let lookup_list_offset =
        u16::from_be_bytes([data[table.offset + 6], data[table.offset + 7]]) as usize;

    let lookup_list_addr = table.offset + lookup_list_offset;
    if lookup_list_addr + 2 > data.len() {
        return 0;
    }

    let lookup_count =
        u16::from_be_bytes([data[lookup_list_addr], data[lookup_list_addr + 1]]) as usize;

    // Heuristic: estimate depth based on lookup count
    // More lookups often means more nesting
    match lookup_count {
        0..=10 => 1,
        11..=50 => 2,
        51..=100 => 3,
        _ => 4,
    }
}

/// Validate magic numbers in critical tables
#[cfg(feature = "dynamic")]
fn validate_magic_numbers(data: &[u8], context: &mut FontContext) {
    // Validate head table magic number (0x5F0F3CF5)
    if let Some(head_table) = context.table_map.get("head").cloned() {
        validate_head_magic(data, &head_table, context);
    }

    // Validate CFF table header
    if let Some(cff_table) = context.table_map.get("CFF ").cloned() {
        validate_cff_magic(data, &cff_table, context);
    }

    // Validate OTTO (CFF-flavored OpenType) signature
    if data.len() >= 4 {
        let sfnt_version = &data[0..4];
        if sfnt_version == b"OTTO" {
            // This is a CFF font, verify CFF table exists
            if !context.table_map.contains_key("CFF ") {
                context.invalid_magic_numbers.push(InvalidMagic {
                    table: "sfnt".to_string(),
                    offset: 0,
                    expected: b"OTTO".to_vec(),
                    actual: sfnt_version.to_vec(),
                });
            }
        }
    }
}

/// Validate head table magic number
#[cfg(feature = "dynamic")]
fn validate_head_magic(data: &[u8], head_table: &TableInfo, context: &mut FontContext) {
    // Magic number is at offset 12 in head table
    let magic_offset = head_table.offset + 12;
    if magic_offset + 4 > data.len() {
        return;
    }

    let expected_magic = [0x5F, 0x0F, 0x3C, 0xF5];
    let actual_magic = [
        data[magic_offset],
        data[magic_offset + 1],
        data[magic_offset + 2],
        data[magic_offset + 3],
    ];

    if actual_magic != expected_magic {
        context.invalid_magic_numbers.push(InvalidMagic {
            table: "head".to_string(),
            offset: 12,
            expected: expected_magic.to_vec(),
            actual: actual_magic.to_vec(),
        });
    }
}

/// Validate CFF table header
#[cfg(feature = "dynamic")]
fn validate_cff_magic(data: &[u8], cff_table: &TableInfo, context: &mut FontContext) {
    // CFF header format: major version (1 byte), minor version (1 byte), header size (1 byte), offSize (1 byte)
    // Major version should be 1 for CFF, 2 for CFF2
    if cff_table.offset + 4 > data.len() {
        return;
    }

    let major_version = data[cff_table.offset];

    // Valid major versions are 1 (CFF) or 2 (CFF2)
    if major_version != 1 && major_version != 2 {
        context.invalid_magic_numbers.push(InvalidMagic {
            table: "CFF ".to_string(),
            offset: 0,
            expected: vec![1], // or vec![2]
            actual: vec![major_version],
        });
    }
}

/// Analyze instruction streams for security issues
#[cfg(feature = "dynamic")]
fn analyze_instructions(data: &[u8], context: &mut FontContext) {
    // Analyze glyf table instructions
    if let Some(glyf_table) = context.table_map.get("glyf").cloned() {
        analyze_glyf_instructions(data, &glyf_table, context);
    }

    // Analyze fpgm (Font Program) table
    if let Some(fpgm_table) = context.table_map.get("fpgm").cloned() {
        analyze_tt_instructions(data, &fpgm_table, "fpgm", context);
    }

    // Analyze prep (Control Value Program) table
    if let Some(prep_table) = context.table_map.get("prep").cloned() {
        analyze_tt_instructions(data, &prep_table, "prep", context);
    }
}

/// Analyze TrueType instructions in a table
#[cfg(feature = "dynamic")]
fn analyze_tt_instructions(
    data: &[u8],
    table: &TableInfo,
    table_name: &str,
    context: &mut FontContext,
) {
    let start = table.offset;
    let end = start + table.length;

    if end > data.len() {
        return;
    }

    let instructions = &data[start..end];

    // Scan for dangerous or invalid opcodes
    for (i, &opcode) in instructions.iter().enumerate() {
        // Check for invalid opcodes
        if is_invalid_opcode(opcode) {
            context.instruction_issues.push(InstructionIssue {
                table: table_name.to_string(),
                offset: i,
                opcode,
                issue_type: "invalid_opcode".to_string(),
            });
        }

        // Check for dangerous instruction sequences
        if i + 1 < instructions.len() {
            let next_opcode = instructions[i + 1];
            if is_dangerous_sequence(opcode, next_opcode) {
                context.instruction_issues.push(InstructionIssue {
                    table: table_name.to_string(),
                    offset: i,
                    opcode,
                    issue_type: "invalid_sequence".to_string(),
                });
            }
        }
    }
}

/// Analyze instructions in glyf table glyphs
#[cfg(feature = "dynamic")]
fn analyze_glyf_instructions(_data: &[u8], _glyf_table: &TableInfo, _context: &mut FontContext) {
    // Simplified: Skip glyf instruction analysis for now
    // Full implementation would parse each glyph's instruction stream
    // This is complex and requires careful offset calculations
}

/// Check if a TrueType opcode is invalid
#[cfg(feature = "dynamic")]
fn is_invalid_opcode(opcode: u8) -> bool {
    // TrueType instructions range from 0x00 to 0xBF
    // Opcodes >= 0xC0 are undefined/invalid
    opcode >= 0xC0
}

/// Check if two opcodes form a dangerous sequence
#[cfg(feature = "dynamic")]
fn is_dangerous_sequence(opcode1: u8, opcode2: u8) -> bool {
    // Example: Multiple CALL instructions in a row can cause stack overflow
    // CALL opcode is 0x2B
    const CALL: u8 = 0x2B;
    const LOOPCALL: u8 = 0x2A;

    // Consecutive CALL/LOOPCALL can be dangerous
    matches!(
        (opcode1, opcode2),
        (CALL, CALL) | (CALL, LOOPCALL) | (LOOPCALL, CALL)
    )
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

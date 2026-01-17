#!/usr/bin/env python3
"""
Generate synthetic CVE test fixtures for font analysis testing.
All fonts are minimal valid structures with specific vulnerabilities.
"""

import struct
import os

def write_u8(f, val):
    f.extend(struct.pack('>B', val))

def write_i8(f, val):
    """Write signed 8-bit integer"""
    f.extend(struct.pack('>b', val))

def write_u16(f, val):
    f.extend(struct.pack('>H', val))

def write_i16(f, val):
    """Write signed 16-bit integer"""
    f.extend(struct.pack('>h', val))

def write_u32(f, val):
    f.extend(struct.pack('>I', val))

def write_fixed(f, val):
    """Write 16.16 fixed-point number"""
    f.extend(struct.pack('>i', int(val * 65536)))

def calc_table_checksum(data):
    """Calculate TrueType table checksum"""
    checksum = 0
    nLongs = (len(data) + 3) // 4
    for i in range(nLongs):
        if i * 4 + 3 < len(data):
            val = struct.unpack('>I', data[i*4:i*4+4])[0]
        else:
            # Pad with zeros
            remaining = data[i*4:]
            padded = remaining + b'\x00' * (4 - len(remaining))
            val = struct.unpack('>I', padded)[0]
        checksum = (checksum + val) & 0xFFFFFFFF
    return checksum

def pad_to_4_bytes(data):
    """Pad data to 4-byte boundary"""
    remainder = len(data) % 4
    if remainder != 0:
        data += b'\x00' * (4 - remainder)
    return data

def create_cve_2025_27163_hmtx_hhea_mismatch():
    """
    CVE-2025-27163: hmtx table length < 4 * hhea.numberOfHMetrics
    Creates a TrueType font where hmtx is too short for the declared metrics count.
    """
    tables = {}

    # head table
    head_data = bytearray()
    write_u16(head_data, 1)  # majorVersion
    write_u16(head_data, 0)  # minorVersion
    write_fixed(head_data, 1.0)  # fontRevision
    write_u32(head_data, 0)  # checksumAdjustment (placeholder)
    write_u32(head_data, 0x5F0F3CF5)  # magicNumber
    write_u16(head_data, 0)  # flags
    write_u16(head_data, 1000)  # unitsPerEm
    write_u32(head_data, 0)  # created (high)
    write_u32(head_data, 0)  # created (low)
    write_u32(head_data, 0)  # modified (high)
    write_u32(head_data, 0)  # modified (low)
    write_u16(head_data, 0)  # xMin
    write_i16(head_data, 0)  # yMin
    write_i16(head_data, 1000)  # xMax
    write_i16(head_data, 1000)  # yMax
    write_u16(head_data, 0)  # macStyle
    write_u16(head_data, 8)  # lowestRecPPEM
    write_u16(head_data, 2)  # fontDirectionHint
    write_u16(head_data, 0)  # indexToLocFormat (short)
    write_u16(head_data, 0)  # glyphDataFormat
    tables[b'head'] = bytes(head_data)

    # maxp table
    maxp_data = bytearray()
    write_u32(maxp_data, 0x00005000)  # version 0.5 (TrueType)
    write_u16(maxp_data, 2)  # numGlyphs
    tables[b'maxp'] = bytes(maxp_data)

    # hhea table - declares 10 metrics
    hhea_data = bytearray()
    write_u32(hhea_data, 0x00010000)  # version
    write_i16(hhea_data, 750)  # Ascender
    write_i16(hhea_data, -250)  # Descender
    write_i16(hhea_data, 0)  # LineGap
    write_u16(hhea_data, 1000)  # advanceWidthMax
    write_i16(hhea_data, 0)  # minLeftSideBearing
    write_i16(hhea_data, 0)  # minRightSideBearing
    write_i16(hhea_data, 1000)  # xMaxExtent
    write_u16(hhea_data, 1)  # caretSlopeRise
    write_u16(hhea_data, 0)  # caretSlopeRun
    write_u16(hhea_data, 0)  # caretOffset
    write_u16(hhea_data, 0)  # reserved
    write_u16(hhea_data, 0)  # reserved
    write_u16(hhea_data, 0)  # reserved
    write_u16(hhea_data, 0)  # reserved
    write_u16(hhea_data, 0)  # metricDataFormat
    write_u16(hhea_data, 10)  # numberOfHMetrics - DECLARES 10 METRICS
    tables[b'hhea'] = bytes(hhea_data)

    # hmtx table - but only provide 2 metrics (should be 10 * 4 = 40 bytes, but only 8 bytes)
    # This creates the CVE condition: hmtx.length < 4 * hhea.numberOfHMetrics
    hmtx_data = bytearray()
    write_u16(hmtx_data, 500)  # advanceWidth for glyph 0
    write_u16(hmtx_data, 0)    # lsb for glyph 0
    write_u16(hmtx_data, 500)  # advanceWidth for glyph 1
    write_u16(hmtx_data, 0)    # lsb for glyph 1
    # Missing 8 more metrics!
    tables[b'hmtx'] = bytes(hmtx_data)

    # Minimal glyf and loca tables
    loca_data = bytearray()
    write_u16(loca_data, 0)  # glyph 0 offset
    write_u16(loca_data, 0)  # glyph 1 offset
    write_u16(loca_data, 0)  # end offset
    tables[b'loca'] = bytes(loca_data)

    glyf_data = b''  # Empty glyf
    tables[b'glyf'] = glyf_data

    return build_truetype_font(tables, 'cve/cve-2025-27163-hmtx-hhea-mismatch.ttf')

def create_cve_2023_26369_ebsc_oob():
    """
    CVE-2023-26369: EBSC table out-of-bounds
    Creates a font with malformed EBSC table causing OOB read.
    """
    tables = {}

    # Basic required tables (minimal)
    head_data = bytearray()
    write_u16(head_data, 1)  # majorVersion
    write_u16(head_data, 0)  # minorVersion
    write_fixed(head_data, 1.0)  # fontRevision
    write_u32(head_data, 0)  # checksumAdjustment
    write_u32(head_data, 0x5F0F3CF5)  # magicNumber
    write_u16(head_data, 0)  # flags
    write_u16(head_data, 1000)  # unitsPerEm
    write_u32(head_data, 0)  # created (high)
    write_u32(head_data, 0)  # created (low)
    write_u32(head_data, 0)  # modified (high)
    write_u32(head_data, 0)  # modified (low)
    write_u16(head_data, 0)  # xMin
    write_i16(head_data, 0)  # yMin
    write_i16(head_data, 1000)  # xMax
    write_i16(head_data, 1000)  # yMax
    write_u16(head_data, 0)  # macStyle
    write_u16(head_data, 8)  # lowestRecPPEM
    write_u16(head_data, 2)  # fontDirectionHint
    write_u16(head_data, 0)  # indexToLocFormat
    write_u16(head_data, 0)  # glyphDataFormat
    tables[b'head'] = bytes(head_data)

    maxp_data = bytearray()
    write_u32(maxp_data, 0x00005000)  # version
    write_u16(maxp_data, 1)  # numGlyphs
    tables[b'maxp'] = bytes(maxp_data)

    # Malformed EBSC table with out-of-bounds offset
    ebsc_data = bytearray()
    write_u32(ebsc_data, 0x00020000)  # version 2.0
    write_u32(ebsc_data, 1)  # numSizes
    # BitmapScale record with invalid offset
    write_i8(ebsc_data, 12)  # hori.ascender
    write_i8(ebsc_data, -3)  # hori.descender
    write_u8(ebsc_data, 255)  # hori.widthMax
    write_i8(ebsc_data, 1)  # hori.caretSlopeNumerator
    write_i8(ebsc_data, 0)  # hori.caretSlopeDenominator
    write_i8(ebsc_data, 0)  # hori.caretOffset
    write_i8(ebsc_data, 0)  # hori.minOriginSB
    write_i8(ebsc_data, 0)  # hori.minAdvanceSB
    write_i8(ebsc_data, 0)  # hori.maxBeforeBL
    write_i8(ebsc_data, 0)  # hori.minAfterBL
    write_i8(ebsc_data, 0)  # hori.pad1
    write_i8(ebsc_data, 0)  # hori.pad2
    # Repeat for vert
    write_i8(ebsc_data, 12)
    write_i8(ebsc_data, -3)
    write_u8(ebsc_data, 255)
    write_i8(ebsc_data, 1)
    write_i8(ebsc_data, 0)
    write_i8(ebsc_data, 0)
    write_i8(ebsc_data, 0)
    write_i8(ebsc_data, 0)
    write_i8(ebsc_data, 0)
    write_i8(ebsc_data, 0)
    write_i8(ebsc_data, 0)
    write_i8(ebsc_data, 0)
    write_u32(ebsc_data, 16)  # ppemX
    write_u32(ebsc_data, 16)  # ppemY
    write_u32(ebsc_data, 0)  # substitutePpemX
    write_u32(ebsc_data, 0)  # substitutePpemY
    # This offset points beyond table bounds
    write_u32(ebsc_data, 0xFFFFFF00)  # OUT OF BOUNDS OFFSET
    tables[b'EBSC'] = bytes(ebsc_data)

    return build_truetype_font(tables, 'cve/cve-2023-26369-ebsc-oob.ttf')

def create_gvar_anomalous_size():
    """
    Create a variable font with excessively large gvar table (>10MB).
    """
    tables = {}

    # Basic required tables
    head_data = bytearray()
    write_u16(head_data, 1)
    write_u16(head_data, 0)
    write_fixed(head_data, 1.0)
    write_u32(head_data, 0)
    write_u32(head_data, 0x5F0F3CF5)
    write_u16(head_data, 0)
    write_u16(head_data, 1000)
    write_u32(head_data, 0)
    write_u32(head_data, 0)
    write_u32(head_data, 0)
    write_u32(head_data, 0)
    write_u16(head_data, 0)
    write_u16(head_data, 0)
    write_u16(head_data, 1000)
    write_u16(head_data, 1000)
    write_u16(head_data, 0)
    write_u16(head_data, 8)
    write_u16(head_data, 2)
    write_u16(head_data, 0)
    write_u16(head_data, 0)
    tables[b'head'] = bytes(head_data)

    maxp_data = bytearray()
    write_u32(maxp_data, 0x00005000)
    write_u16(maxp_data, 1)
    tables[b'maxp'] = bytes(maxp_data)

    # fvar table (required for variable fonts)
    fvar_data = bytearray()
    write_u32(fvar_data, 0x00010000)  # version
    write_u16(fvar_data, 16)  # offsetToAxesArray
    write_u16(fvar_data, 2)  # reserved
    write_u16(fvar_data, 1)  # axisCount
    write_u16(fvar_data, 20)  # axisSize
    write_u16(fvar_data, 0)  # instanceCount
    write_u16(fvar_data, 0)  # instanceSize
    # Axis record
    write_u32(fvar_data, 0x77676874)  # tag 'wght'
    write_fixed(fvar_data, 400.0)  # minValue
    write_fixed(fvar_data, 400.0)  # defaultValue
    write_fixed(fvar_data, 700.0)  # maxValue
    write_u16(fvar_data, 0)  # flags
    write_u16(fvar_data, 256)  # axisNameID
    tables[b'fvar'] = bytes(fvar_data)

    # Excessively large gvar table (11 MB)
    gvar_data = bytearray()
    write_u32(gvar_data, 0x00010000)  # version
    write_u16(gvar_data, 0)  # reserved
    write_u16(gvar_data, 1)  # axisCount
    write_u16(gvar_data, 1)  # sharedTupleCount
    write_u32(gvar_data, 20)  # offsetToSharedTuples
    write_u16(gvar_data, 1)  # glyphCount
    write_u16(gvar_data, 0)  # flags
    write_u32(gvar_data, 28)  # offsetToGlyphVariationData
    # Pad to 11MB to trigger anomaly detection
    gvar_data += b'\x00' * (11 * 1024 * 1024)
    tables[b'gvar'] = bytes(gvar_data)

    return build_truetype_font(tables, 'cve/gvar-anomalous-size.ttf')

def build_truetype_font(tables, output_path):
    """Build complete TrueType font from table dictionary"""

    # Sort tables by tag
    table_tags = sorted(tables.keys())
    num_tables = len(table_tags)

    # Calculate search range parameters
    entry_selector = 0
    search_range = 1
    while search_range * 2 <= num_tables:
        search_range *= 2
        entry_selector += 1
    search_range *= 16
    range_shift = num_tables * 16 - search_range

    # Build font header
    font_data = bytearray()
    write_u32(font_data, 0x00010000)  # sfnt version (TrueType)
    write_u16(font_data, num_tables)
    write_u16(font_data, search_range)
    write_u16(font_data, entry_selector)
    write_u16(font_data, range_shift)

    # Calculate table directory offsets
    table_dir_offset = 12
    table_data_offset = table_dir_offset + num_tables * 16

    # Build table directory and collect table data
    table_records = []
    current_offset = table_data_offset

    for tag in table_tags:
        data = pad_to_4_bytes(bytearray(tables[tag]))
        checksum = calc_table_checksum(data)

        table_records.append({
            'tag': tag,
            'checksum': checksum,
            'offset': current_offset,
            'length': len(tables[tag])  # Original length without padding
        })

        current_offset += len(data)

    # Write table directory
    for record in table_records:
        font_data.extend(record['tag'])
        write_u32(font_data, record['checksum'])
        write_u32(font_data, record['offset'])
        write_u32(font_data, record['length'])

    # Write table data
    for tag in table_tags:
        font_data.extend(pad_to_4_bytes(bytearray(tables[tag])))

    # Write to file
    fixtures_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(fixtures_dir, output_path)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, 'wb') as f:
        f.write(font_data)

    print(f"Created {output_file} ({len(font_data)} bytes)")
    return output_file

def main():
    print("Generating CVE test fixtures...")
    print()

    create_cve_2025_27163_hmtx_hhea_mismatch()
    create_cve_2023_26369_ebsc_oob()
    create_gvar_anomalous_size()

    print()
    print("All CVE fixtures generated successfully!")

if __name__ == '__main__':
    main()

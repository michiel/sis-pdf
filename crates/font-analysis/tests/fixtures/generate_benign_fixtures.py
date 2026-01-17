#!/usr/bin/env python3
"""
Generate benign font fixtures for regression testing.
These fonts should not trigger any findings.
"""

import struct
import os
import sys

# Add the parent directory to path to import helper functions
sys.path.insert(0, os.path.dirname(__file__))
from generate_cve_fixtures import (
    write_u8, write_i8, write_u16, write_i16, write_u32, write_fixed,
    calc_table_checksum, pad_to_4_bytes, build_truetype_font
)

def create_minimal_truetype():
    """Create minimal valid TrueType font with single glyph"""
    tables = {}

    # head table
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
    write_i16(head_data, 0)  # xMin
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
    write_u32(maxp_data, 0x00005000)  # version 0.5
    write_u16(maxp_data, 2)  # numGlyphs (notdef + A)
    tables[b'maxp'] = bytes(maxp_data)

    # hhea table - properly sized for 2 glyphs
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
    write_u16(hhea_data, 2)  # numberOfHMetrics - matches number of glyphs
    tables[b'hhea'] = bytes(hhea_data)

    # hmtx table - properly sized (2 metrics * 4 bytes = 8 bytes)
    hmtx_data = bytearray()
    write_u16(hmtx_data, 500)  # advanceWidth for glyph 0
    write_i16(hmtx_data, 0)    # lsb for glyph 0
    write_u16(hmtx_data, 500)  # advanceWidth for glyph 1
    write_i16(hmtx_data, 0)    # lsb for glyph 1
    tables[b'hmtx'] = bytes(hmtx_data)

    # loca table (3 offsets for 2 glyphs)
    loca_data = bytearray()
    write_u16(loca_data, 0)  # glyph 0 offset
    write_u16(loca_data, 0)  # glyph 1 offset
    write_u16(loca_data, 0)  # end offset
    tables[b'loca'] = bytes(loca_data)

    # Empty glyf
    tables[b'glyf'] = b''

    return build_truetype_font(tables, 'benign/minimal-truetype.ttf')

def create_minimal_variable():
    """Create minimal valid variable font"""
    tables = {}

    # head table
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
    write_i16(head_data, 0)
    write_i16(head_data, 0)
    write_i16(head_data, 1000)
    write_i16(head_data, 1000)
    write_u16(head_data, 0)
    write_u16(head_data, 8)
    write_u16(head_data, 2)
    write_u16(head_data, 0)
    write_u16(head_data, 0)
    tables[b'head'] = bytes(head_data)

    # maxp table
    maxp_data = bytearray()
    write_u32(maxp_data, 0x00005000)
    write_u16(maxp_data, 1)
    tables[b'maxp'] = bytes(maxp_data)

    # fvar table - minimal variable font axis
    fvar_data = bytearray()
    write_u32(fvar_data, 0x00010000)  # version
    write_u16(fvar_data, 16)  # offsetToAxesArray
    write_u16(fvar_data, 2)  # reserved
    write_u16(fvar_data, 1)  # axisCount
    write_u16(fvar_data, 20)  # axisSize
    write_u16(fvar_data, 0)  # instanceCount
    write_u16(fvar_data, 0)  # instanceSize
    # Axis record (weight axis)
    write_u32(fvar_data, 0x77676874)  # tag 'wght'
    write_fixed(fvar_data, 400.0)  # minValue
    write_fixed(fvar_data, 400.0)  # defaultValue
    write_fixed(fvar_data, 700.0)  # maxValue
    write_u16(fvar_data, 0)  # flags
    write_u16(fvar_data, 256)  # axisNameID
    tables[b'fvar'] = bytes(fvar_data)

    # Properly sized gvar table (<1KB, well under anomaly threshold)
    gvar_data = bytearray()
    write_u32(gvar_data, 0x00010000)  # version
    write_u16(gvar_data, 0)  # reserved
    write_u16(gvar_data, 1)  # axisCount
    write_u16(gvar_data, 1)  # sharedTupleCount
    write_u32(gvar_data, 20)  # offsetToSharedTuples
    write_u16(gvar_data, 1)  # glyphCount
    write_u16(gvar_data, 0)  # flags
    write_u32(gvar_data, 28)  # offsetToGlyphVariationData
    # Minimal variation data
    gvar_data += b'\x00' * 64  # Small amount of variation data
    tables[b'gvar'] = bytes(gvar_data)

    return build_truetype_font(tables, 'benign/minimal-variable.ttf')

def main():
    print("Generating benign test fixtures...")
    print()

    create_minimal_truetype()
    create_minimal_variable()

    print()
    print("All benign fixtures generated successfully!")

if __name__ == '__main__':
    main()

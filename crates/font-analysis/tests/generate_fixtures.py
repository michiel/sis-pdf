#!/usr/bin/env python3
"""
Generate synthetic font test fixtures for Stage 3 functionality.

This script creates minimal TrueType font files with specific anomalies
to test variable font, color font, and WOFF analysis.
"""

import struct
import os
from pathlib import Path

def checksum(data):
    """Calculate TrueType table checksum."""
    nlong = (len(data) + 3) // 4
    sum = 0
    for i in range(nlong):
        if i * 4 + 3 < len(data):
            sum += struct.unpack('>I', data[i*4:(i+1)*4])[0]
        else:
            # Pad with zeros
            chunk = data[i*4:] + b'\x00' * (4 - len(data[i*4:]))
            sum += struct.unpack('>I', chunk)[0]
    return sum & 0xFFFFFFFF

def create_ttf_header(num_tables):
    """Create TrueType font header."""
    search_range = 2 ** int(num_tables ** 0.5).bit_length() * 16
    entry_selector = int(num_tables ** 0.5).bit_length()
    range_shift = num_tables * 16 - search_range

    return struct.pack('>4sHHHH',
        b'\x00\x01\x00\x00',  # version
        num_tables,
        search_range,
        entry_selector,
        range_shift
    )

def create_table_record(tag, data, offset):
    """Create table directory record."""
    cs = checksum(data)
    return struct.pack('>4sIII',
        tag,
        cs,
        offset,
        len(data)
    )

def create_minimal_ttf(tables):
    """Create minimal TrueType font with given tables."""
    # Calculate offsets
    header_size = 12
    record_size = 16 * len(tables)
    offset = header_size + record_size

    # Build table directory
    header = create_ttf_header(len(tables))
    records = b''
    table_data = b''

    for tag, data in tables.items():
        records += create_table_record(tag, data, offset)
        table_data += data
        # Align to 4-byte boundary
        padding = (4 - len(data) % 4) % 4
        table_data += b'\x00' * padding
        offset += len(data) + padding

    return header + records + table_data

def create_color_font_inconsistent():
    """Create font with COLR but no CPAL (inconsistent)."""
    tables = {
        b'head': struct.pack('>IHHIIIHHHHHHHHHH',
            0x00010000, 1, 0, 0, 0x5F0F3CF5, 0, 1000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        b'maxp': struct.pack('>IH', 0x00010000, 3),  # 3 glyphs
        b'COLR': struct.pack('>HHIHH', 0, 2, 14, 0, 0),  # Version 0, 2 base glyphs
    }
    return create_minimal_ttf(tables)

def create_color_font_excessive_palettes():
    """Create font with excessive palette count."""
    # CPAL header with 300 palettes (exceeds MAX_SAFE_PALETTES = 256)
    cpal_data = struct.pack('>HHHH',
        0,      # version
        0,      # numPaletteEntries
        300,    # numPalettes - EXCESSIVE
        0       # numColorRecords
    )

    tables = {
        b'head': struct.pack('>IHHIIIHHHHHHHHHH',
            0x00010000, 1, 0, 0, 0x5F0F3CF5, 0, 1000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        b'maxp': struct.pack('>IH', 0x00010000, 3),
        b'COLR': struct.pack('>HHIHH', 0, 0, 14, 0, 0),
        b'CPAL': cpal_data,
    }
    return create_minimal_ttf(tables)

def create_color_font_glyph_mismatch():
    """Create font with COLR glyph count exceeding total glyphs."""
    tables = {
        b'head': struct.pack('>IHHIIIHHHHHHHHHH',
            0x00010000, 1, 0, 0, 0x5F0F3CF5, 0, 1000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        b'maxp': struct.pack('>IH', 0x00010000, 3),  # Only 3 glyphs
        b'COLR': struct.pack('>HHIHH', 0, 50, 14, 0, 0),  # Claims 50 base glyphs - MISMATCH
        b'CPAL': struct.pack('>HHHH', 0, 1, 1, 1),
    }
    return create_minimal_ttf(tables)

def create_benign_color_font():
    """Create valid color font with consistent tables."""
    tables = {
        b'head': struct.pack('>IHHIIIHHHHHHHHHH',
            0x00010000, 1, 0, 0, 0x5F0F3CF5, 0, 1000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        b'maxp': struct.pack('>IH', 0x00010000, 10),
        b'COLR': struct.pack('>HHIHH', 0, 2, 14, 0, 0),  # 2 base glyphs (< 10 total)
        b'CPAL': struct.pack('>HHHH', 0, 4, 1, 4),  # 1 palette, 4 colors
    }
    return create_minimal_ttf(tables)

def create_woff_decompression_bomb():
    """Create WOFF header claiming huge decompression size."""
    # WOFF header: signature, flavor, length, numTables, reserved, totalSfntSize
    # Set totalSfntSize to 1GB but actual compressed is tiny (compression ratio >1000)
    woff_header = struct.pack('>4s4sIHHI',
        b'wOFF',              # signature
        b'\x00\x01\x00\x00',  # flavor (TrueType)
        48,                   # length (header only)
        0,                    # numTables
        0,                    # reserved
        1000000000            # totalSfntSize = 1GB - DECOMPRESSION BOMB
    )
    # Pad to make it valid enough
    return woff_header + b'\x00' * 16

def create_woff2_decompression_bomb():
    """Create WOFF2 header claiming huge decompression size."""
    # WOFF2 header is more complex, but we just need the critical fields
    woff2_header = struct.pack('>4sIHHI',
        b'wOF2',              # signature
        0,                    # flavor
        48,                   # length
        0,                    # numTables
        2000000000            # totalSfntSize = 2GB - DECOMPRESSION BOMB
    )
    return woff2_header + b'\x00' * 24

def create_woff_excessive_size():
    """Create WOFF claiming 200MB decompression (excessive but not bomb)."""
    woff_header = struct.pack('>4s4sIHHI',
        b'wOFF',
        b'\x00\x01\x00\x00',
        48,
        0,
        0,
        200000000  # 200MB - EXCESSIVE but not extreme ratio
    )
    # Add some padding to make size ratio < 1000
    return woff_header + b'\x00' * 200000

def create_benign_woff():
    """Create WOFF with reasonable decompression size."""
    woff_header = struct.pack('>4s4sIHHI',
        b'wOFF',
        b'\x00\x01\x00\x00',
        1000,
        0,
        0,
        5000  # 5KB decompressed
    )
    return woff_header + b'\x00' * (1000 - 24)

def create_variable_font_excessive_axes():
    """Create variable font with 20 variation axes (exceeds max 16)."""
    # fvar table with 20 axes
    fvar_data = struct.pack('>HHIH',
        1,    # majorVersion
        0,    # minorVersion
        16,   # axisArrayOffset
        2,    # reserved
    ) + struct.pack('>HH', 20, 20)  # axisCount=20, instanceCount=20

    # Add dummy axis data (20 axes * 20 bytes each)
    for i in range(20):
        fvar_data += struct.pack('>IIII',
            0x77676874,  # 'wght' tag
            65536,       # minValue
            65536,       # defaultValue
            65536        # maxValue
        ) + struct.pack('>HH', 0, 256 + i)  # flags, axisNameID

    tables = {
        b'head': struct.pack('>IHHIIIHHHHHHHHHH',
            0x00010000, 1, 0, 0, 0x5F0F3CF5, 0, 1000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        b'maxp': struct.pack('>IH', 0x00010000, 3),
        b'fvar': fvar_data,
    }
    return create_minimal_ttf(tables)

def create_variable_font_excessive_hvar():
    """Create variable font with huge HVAR table (>5MB)."""
    hvar_data = b'\x00' * (6 * 1024 * 1024)  # 6MB HVAR table

    tables = {
        b'head': struct.pack('>IHHIIIHHHHHHHHHH',
            0x00010000, 1, 0, 0, 0x5F0F3CF5, 0, 1000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        b'maxp': struct.pack('>IH', 0x00010000, 3),
        b'fvar': struct.pack('>HHIHHHH', 1, 0, 16, 2, 1, 1, 20),  # 1 axis
        b'HVAR': hvar_data,
    }
    return create_minimal_ttf(tables)

def create_variable_font_excessive_mvar():
    """Create variable font with huge MVAR table (>1MB)."""
    mvar_data = b'\x00' * (2 * 1024 * 1024)  # 2MB MVAR table

    tables = {
        b'head': struct.pack('>IHHIIIHHHHHHHHHH',
            0x00010000, 1, 0, 0, 0x5F0F3CF5, 0, 1000, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        b'maxp': struct.pack('>IH', 0x00010000, 3),
        b'fvar': struct.pack('>HHIHHHH', 1, 0, 16, 2, 1, 1, 20),
        b'MVAR': mvar_data,
    }
    return create_minimal_ttf(tables)

def main():
    """Generate all test fixtures."""
    base_dir = Path(__file__).parent / "fixtures"

    # Create directory structure
    dirs = [
        base_dir / "color",
        base_dir / "woff",
        base_dir / "variable",
        base_dir / "benign",
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Generate fixtures
    fixtures = {
        # Color fonts
        "color/colr-without-cpal.ttf": create_color_font_inconsistent(),
        "color/excessive-palettes.ttf": create_color_font_excessive_palettes(),
        "color/glyph-count-mismatch.ttf": create_color_font_glyph_mismatch(),
        "benign/valid-color.ttf": create_benign_color_font(),

        # WOFF fonts
        "woff/decompression-bomb.woff": create_woff_decompression_bomb(),
        "woff/decompression-bomb.woff2": create_woff2_decompression_bomb(),
        "woff/excessive-size.woff": create_woff_excessive_size(),
        "benign/valid.woff": create_benign_woff(),

        # Variable fonts
        "variable/excessive-axes.ttf": create_variable_font_excessive_axes(),
        "variable/excessive-hvar.ttf": create_variable_font_excessive_hvar(),
        "variable/excessive-mvar.ttf": create_variable_font_excessive_mvar(),
    }

    for path, data in fixtures.items():
        filepath = base_dir / path
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"Created: {filepath} ({len(data)} bytes)")

    print(f"\nGenerated {len(fixtures)} test fixtures")

if __name__ == "__main__":
    main()

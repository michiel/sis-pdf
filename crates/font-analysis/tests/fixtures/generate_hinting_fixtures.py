#!/usr/bin/env python3
"""
Generate TrueType fonts with malicious hinting programs for security testing.
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

def create_basic_tables():
    """Create basic required TrueType tables"""
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

    # hhea table
    hhea_data = bytearray()
    write_u32(hhea_data, 0x00010000)
    write_i16(hhea_data, 750)
    write_i16(hhea_data, -250)
    write_i16(hhea_data, 0)
    write_u16(hhea_data, 1000)
    write_i16(hhea_data, 0)
    write_i16(hhea_data, 0)
    write_i16(hhea_data, 1000)
    write_u16(hhea_data, 1)
    write_u16(hhea_data, 0)
    write_u16(hhea_data, 0)
    write_u16(hhea_data, 0)
    write_u16(hhea_data, 0)
    write_u16(hhea_data, 0)
    write_u16(hhea_data, 0)
    write_u16(hhea_data, 0)
    write_u16(hhea_data, 1)
    tables[b'hhea'] = bytes(hhea_data)

    # hmtx table
    hmtx_data = bytearray()
    write_u16(hmtx_data, 500)
    write_i16(hmtx_data, 0)
    tables[b'hmtx'] = bytes(hmtx_data)

    # loca table
    loca_data = bytearray()
    write_u16(loca_data, 0)
    write_u16(loca_data, 0)
    tables[b'loca'] = bytes(loca_data)

    # glyf table (empty)
    tables[b'glyf'] = b''

    return tables

def create_font_with_excessive_instructions():
    """Create a font with fpgm table exceeding instruction budget"""
    tables = create_basic_tables()

    # Malicious fpgm table - exceeds 50,000 instruction budget
    # Each PUSHB[0] + byte is 2 bytes, so 60,000 iterations = 120,000 bytes
    fpgm_data = bytearray()
    for i in range(60_000):
        fpgm_data.extend([0xB0, i % 256])  # PUSHB[0] <value>
    tables[b'fpgm'] = bytes(fpgm_data)

    return build_truetype_font(tables, 'exploits/ttf_excessive_instructions.ttf')

def create_font_with_stack_overflow():
    """Create a font with fpgm table causing stack overflow"""
    tables = create_basic_tables()

    # Malicious fpgm table - pushes 300 values to overflow stack (limit is 256)
    fpgm_data = bytearray()
    for i in range(300):
        fpgm_data.extend([0xB0, i % 256])  # PUSHB[0] <value>
    tables[b'fpgm'] = bytes(fpgm_data)

    return build_truetype_font(tables, 'exploits/ttf_stack_overflow.ttf')

def create_font_with_division_by_zero():
    """Create a font with fpgm table causing division by zero"""
    tables = create_basic_tables()

    # Malicious fpgm table - division by zero
    fpgm_data = bytearray()
    fpgm_data.extend([0xB0, 100])  # PUSHB[0] 100
    fpgm_data.extend([0xB0, 0])    # PUSHB[0] 0
    fpgm_data.extend([0x62])       # DIV (100 / 0)
    tables[b'fpgm'] = bytes(fpgm_data)

    return build_truetype_font(tables, 'exploits/ttf_division_by_zero.ttf')

def main():
    print("Generating TrueType hinting exploit fixtures...")
    print()

    create_font_with_excessive_instructions()
    create_font_with_stack_overflow()
    create_font_with_division_by_zero()

    print()
    print("All hinting exploit fixtures generated successfully!")

if __name__ == '__main__':
    main()

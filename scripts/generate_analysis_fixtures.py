#!/usr/bin/env python3
from pathlib import Path


def write_pdf(path, objects, trailer_extra=b""):
    header = b"%PDF-1.4\n"
    parts = [header]
    offsets = [0]
    current = len(header)
    for obj in objects:
        offsets.append(current)
        parts.append(obj)
        current += len(obj)
    xref_offset = current
    size = len(objects) + 1
    xref = [f"xref\n0 {size}\n".encode("ascii")]
    xref.append(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        xref.append(f"{off:010d} 00000 n \n".encode("ascii"))
    trailer = (
        f"trailer\n<< /Root 1 0 R /Size {size} ".encode("ascii")
        + trailer_extra
        + b">>\n"
    )
    trailer += f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    pdf = b"".join(parts + xref + [trailer])
    Path(path).write_bytes(pdf)


def generate_launch_cve_2010_1240(path):
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [4 0 R] >>\nendobj\n"
    obj3 = b"3 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n"
    obj4 = b"4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    write_pdf(path, [obj1, obj2, obj3, obj4])


def generate_embedded_exe_cve_2018_4990(path):
    exe_data = b"MZ" + b"\x00" * 14 + b"Synthetic embedded EXE"
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    obj4 = (
        b"4 0 obj\n<< /Type /EmbeddedFile /F (payload.exe) /Length "
        + str(len(exe_data)).encode("ascii")
        + b" >>\nstream\n"
        + exe_data
        + b"\nendstream\nendobj\n"
    )
    write_pdf(path, [obj1, obj2, obj3, obj4])


def generate_xfa_cve_2013_2729(path):
    xfa_xml = (
        b"<xdp:xdp xmlns:xdp='http://ns.adobe.com/xdp/'>"
        b"<xfa:datasets xmlns:xfa='http://www.xfa.org/schema/xfa-data/1.0/'>"
        b"<xfa:data>test</xfa:data>"
        b"</xfa:datasets>"
        b"<xfa:script xmlns:xfa='http://www.xfa.org/schema/xfa-template/2.5/'>"
        b"app.alert('xfa');"
        b"</xfa:script>"
        b"</xdp:xdp>"
    )
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    obj4 = b"4 0 obj\n<< /XFA 5 0 R >>\nendobj\n"
    obj5 = (
        b"5 0 obj\n<< /Length "
        + str(len(xfa_xml)).encode("ascii")
        + b" >>\nstream\n"
        + xfa_xml
        + b"\nendstream\nendobj\n"
    )
    write_pdf(path, [obj1, obj2, obj3, obj4, obj5])


def generate_swf_cve_2011_0611(path):
    swf_data = b"FWS" + b"\x09" + b"\x00" * 20
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    obj4 = (
        b"4 0 obj\n<< /Type /RichMedia /Length "
        + str(len(swf_data)).encode("ascii")
        + b" >>\nstream\n"
        + swf_data
        + b"\nendstream\nendobj\n"
    )
    write_pdf(path, [obj1, obj2, obj3, obj4])


def generate_weak_encryption_cve_2019_7089(path):
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    obj4 = (
        b"4 0 obj\n<< /Filter /Standard /V 1 /R 2 /Length 40 "
        b"/O <0000000000000000000000000000000000000000000000000000000000000000> "
        b"/U <0000000000000000000000000000000000000000000000000000000000000000> "
        b"/P -4 >>\nendobj\n"
    )
    trailer_extra = b"/Encrypt 4 0 R /ID [<0123456789ABCDEF> <0123456789ABCDEF>] "
    write_pdf(path, [obj1, obj2, obj3, obj4], trailer_extra=trailer_extra)


def generate_filter_obfuscation_cve_2010_2883(path):
    flate_empty = bytes([0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01])
    hex_bytes = flate_empty.hex().encode("ascii") + b">"
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    obj4 = (
        b"4 0 obj\n<< /Length "
        + str(len(hex_bytes)).encode("ascii")
        + b" /Filter [/ASCIIHexDecode /FlateDecode] >>\nstream\n"
        + hex_bytes
        + b"\nendstream\nendobj\n"
    )
    write_pdf(path, [obj1, obj2, obj3, obj4])


def main():
    base = Path(__file__).resolve().parents[1] / "crates" / "sis-pdf-core" / "tests" / "fixtures"
    (base / "actions").mkdir(parents=True, exist_ok=True)
    (base / "embedded").mkdir(parents=True, exist_ok=True)
    (base / "xfa").mkdir(parents=True, exist_ok=True)
    (base / "media").mkdir(parents=True, exist_ok=True)
    (base / "encryption").mkdir(parents=True, exist_ok=True)
    (base / "filters").mkdir(parents=True, exist_ok=True)

    generate_launch_cve_2010_1240(base / "actions" / "launch_cve_2010_1240.pdf")
    generate_embedded_exe_cve_2018_4990(base / "embedded" / "embedded_exe_cve_2018_4990.pdf")
    generate_xfa_cve_2013_2729(base / "xfa" / "xfa_cve_2013_2729.pdf")
    generate_swf_cve_2011_0611(base / "media" / "swf_cve_2011_0611.pdf")
    generate_weak_encryption_cve_2019_7089(base / "encryption" / "weak_encryption_cve_2019_7089.pdf")
    generate_filter_obfuscation_cve_2010_2883(base / "filters" / "filter_obfuscation_cve_2010_2883.pdf")


if __name__ == "__main__":
    main()

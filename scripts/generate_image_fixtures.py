#!/usr/bin/env python3
"""
Generate lightweight PDF image fixtures for decoding tests.

Usage:
  python scripts/generate_image_fixtures.py
"""

from pathlib import Path
import base64

FIXTURE_DIR = Path("crates/sis-pdf-core/tests/fixtures/images")


def build_pdf(filter_name: str, image_bytes: bytes, width: int = 1, height: int = 1) -> bytes:
    header = b"%PDF-1.7\n%\x00\xff\xff\xff\n"
    content_stream = b"q\n1 0 0 1 0 0 cm\n/Im1 Do\nQ\n"
    objects = [
        (1, b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"),
        (2, b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"),
        (
            3,
            (
                b"3 0 obj\n"
                b"<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im1 4 0 R >> >> "
                b"/MediaBox [0 0 612 792] /Contents 5 0 R >>\n"
                b"endobj\n"
            ),
        ),
        (
            4,
            (
                f"4 0 obj\n<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "
                f"/BitsPerComponent 8 /Filter /{filter_name} /Length {len(image_bytes)} >>\n"
            ).encode()
            + b"stream\n"
            + image_bytes
            + b"\nendstream\nendobj\n",
        ),
        (
            5,
            (
                f"5 0 obj\n<< /Length {len(content_stream)} >>\n".encode()
                + b"stream\n"
                + content_stream
                + b"endstream\nendobj\n"
            ),
        ),
    ]

    body = b""
    positions = []
    for _, obj_bytes in objects:
        positions.append(len(header) + len(body))
        body += obj_bytes

    start_xref = len(header) + len(body)
    xref = b"xref\n0 %d\n" % (len(objects) + 1)
    xref += b"0000000000 65535 f \n"
    for pos in positions:
        xref += f"{pos:010d} 00000 n \n".encode()

    trailer = b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objects) + 1)
    startxref = b"startxref\n%d\n%%EOF\n" % start_xref

    return header + body + xref + trailer + startxref


def ensure_dir() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)


def base64_jpeg() -> bytes:
    jpeg_b64 = (
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxAPDxAPDw8PDw8PFBAQEA8PDw8PFREWFhURFRUYHSgg"
        "GBolGxUVITEhJSkrLi4uFx8zODMtNygtLisBCgoKDg0OGxAQGy0lHyUtLS0tLS0tLS0tLS0tLS0tLS0t"
        "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLf/AABEIAAEAAQMBIgACEQEDEQH/xAAZAAACAwEAAAAA"
        "AAAAAAAAAABgEDBwj/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH4AP/EABQQAQAAAA"
        "AAAAAAAAAAAAAAAAAD/2gAIAQEAAQUC/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwCP/8QAF"
        "BEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwCP/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAGPw"
        "J//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPyH/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAE"
        "BAAE/I//aAAwDAQACAAMAAAAQ/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwCf/8QAFBEBAAA"
        "AAAAAAAAAAAAAAAAAP/aAAgBAgEBPwCf/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPyH/2Q=="
    )
    return base64.b64decode(jpeg_b64)


def main() -> None:
    ensure_dir()

    samples = {
        "malformed_jbig2.pdf": (b"JBIG2_STREAM_DATA", "JBIG2Decode"),
        "malformed_jpx.pdf": (b"\x00JPX\x00", "JPXDecode"),
        "valid_jpeg.pdf": (base64_jpeg(), "DCTDecode"),
    }

    for filename, (data, filter_name) in samples.items():
        path = FIXTURE_DIR / filename
        path.write_bytes(build_pdf(filter_name, data))
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()

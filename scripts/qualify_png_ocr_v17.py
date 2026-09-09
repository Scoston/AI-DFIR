#!/usr/bin/env python3
"""Actual PNG bridge-to-isolated-OCR acceptance on synthetic inputs only."""
import argparse
import json
from pathlib import Path
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import v17_png_ocr as png_ocr
from v17_integrity import sha256_bytes

FONT = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "M": ("10001", "11011", "10101", "10101", "10001", "10001", "10001"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    " ": ("000", "000", "000", "000", "000", "000", "000"),
}


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def grayscale_png(width, height, pixels):
    assert len(pixels) == width * height
    rows = b"".join(b"\x00" + pixels[row * width:(row + 1) * width] for row in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def text_fixture(text="HUMAN RESOURCES", scale=12, margin=20):
    widths = [len(FONT[character][0]) for character in text]
    width = margin * 2 + sum(widths) * scale + (len(text) - 1) * scale
    height = margin * 2 + 7 * scale
    pixels = bytearray([255] * (width * height)); cursor = margin
    for character in text:
        glyph = FONT[character]; glyph_width = len(glyph[0])
        for y, row in enumerate(glyph):
            for x, value in enumerate(row):
                if value != "1": continue
                for yy in range(y * scale, (y + 1) * scale):
                    start = (margin + yy) * width + cursor + x * scale
                    pixels[start:start + scale] = b"\x00" * scale
        cursor += glyph_width * scale + scale
    return grayscale_png(width, height, bytes(pixels))


def rgb_fixture():
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b""))


def qualify(directory, selected_image):
    png_ocr.pdf_renderer.image_id(selected_image)
    directory = Path(directory); directory.mkdir(mode=0o700)
    report = {"schema": "ai-dfir/png-ocr-qualification/v1.7", "status": "FAIL", "image_id": selected_image,
              "cases": [], "synthetic_only": True, "source_authenticity_verified": False,
              "ocr_accuracy_verified": False, "production_qualified": False}
    try:
        fixtures = (("high-contrast-text", text_fixture(), "HUMAN RESOURCES"),
                    ("blank", grayscale_png(256, 128, b"\xff" * (256 * 128)), None))
        for name, raw, expected_text in fixtures:
            source = directory / (name + ".png"); png_ocr.private_write(source, raw)
            result = png_ocr.capture(source, directory / name, selected_image=selected_image)
            row = {"case": name, "available": result["available"], "expected": "AVAILABLE"}; report["cases"].append(row)
            assert result["available"] and result["artifact_set_complete"] and result["cleanup_complete"]
            assert result["source_sha256"] == sha256_bytes(raw) and result["source_authenticity_verified"] is False
            assert result["complete_visible_rendering_verified"] is False and result["ocr_accuracy_verified"] is False
            bridge, width, height = png_ocr.bridge_pdf(raw)
            assert result["source_width"] == width and result["source_height"] == height
            assert result["bridge_pdf_sha256"] == sha256_bytes(bridge)
            assert (directory / name / "source.png").read_bytes() == raw
            assert (directory / name / "bridge.pdf").read_bytes() == bridge
            retained = json.loads((directory / name / "png-ocr.json").read_bytes())
            assert retained == result
            visible = (directory / name / "visible.txt").read_text(encoding="utf-8")
            if expected_text is None: assert not visible.strip()
            else: assert expected_text.lower() in visible.lower()
            observed = (directory / name / "observed.png").read_bytes()
            assert sha256_bytes(observed) == result["page"]["png_sha256"]
            row.update(source_sha256=result["source_sha256"], bridge_pdf_sha256=result["bridge_pdf_sha256"],
                       toolchain=result["toolchain"], isolation=result["isolation"])
        for name, raw in (("malformed", b"not a png"), ("rgb-unsupported", rgb_fixture())):
            result = png_ocr.render(raw, selected_image=selected_image)
            report["cases"].append({"case": name, "available": result["available"], "expected": "UNAVAILABLE"})
            assert not result["available"] and result["artifact_set_complete"] is False and result["stage"] == "input"
        assert len(report["cases"]) == 4
        report["status"] = "PASS"
    except Exception as error:
        report["error_type"] = type(error).__name__
    png_ocr.pdf_renderer.output_report(report, directory / "qualification.json", limit=png_ocr.REPORT_BYTES)
    return report


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--image-id", required=True); parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    try: report = qualify(args.out_dir, args.image_id)
    except Exception as error: report = {"status": "FAIL", "error_type": type(error).__name__}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

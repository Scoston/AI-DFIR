#!/usr/bin/env python3
"""Actual fixed-container PDF rendering/OCR acceptance on synthetic inputs only."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import v17_pdf_render as renderer
from v17_pdf_render_selftest import MACHINE, pdf_fixture
from v17_representation_compare import compare

BASE_STREAM = (b"BT /F1 18 Tf 72 700 Td (Quarterly benefits enrollment closes Friday) Tj "
               b"0 -32 Td (Employees should contact human resources) Tj ET\n")


def synthetic_pdf(streams, *, rotate=None):
    """Build a deterministic synthetic PDF with caller-controlled page streams.

    This helper exists only for qualification fixtures. It deliberately uses the
    same built-in Helvetica resource as the baseline fixture so hostile/layout
    observations measure raster/OCR behavior rather than external font loading.
    """
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               b"<< /Type /Pages /Kids [" + b" ".join(f"{4 + 2*i} 0 R".encode() for i in range(len(streams)))
               + b"] /Count " + str(len(streams)).encode() + b" >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    for index, stream in enumerate(streams):
        rotation = b"" if rotate is None else b" /Rotate " + str(rotate).encode()
        objects.extend([
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents "
            + str(5 + 2*index).encode() + b" 0 R" + rotation + b" >>",
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream",
        ])
    raw = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"; offsets = []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(raw)); raw += str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    start = len(raw); count = len(objects) + 1
    raw += b"xref\n0 " + str(count).encode() + b"\n0000000000 65535 f \n"
    raw += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    return raw + b"trailer\n<< /Size " + str(count).encode() + b" /Root 1 0 R >>\nstartxref\n" + str(start).encode() + b"\n%%EOF\n"


def hostile_fixtures():
    """Curated cases where source text must not be confused with visible text."""
    white = (BASE_STREAM + b"1 g BT /F1 18 Tf 72 500 Td (" + MACHINE + b") Tj ET 0 g\n")
    off_page = (BASE_STREAM + b"BT /F1 18 Tf 10000 10000 Td (" + MACHINE + b") Tj ET\n")
    clipped = (BASE_STREAM + b"q 10000 10000 10 10 re W n BT /F1 18 Tf 72 500 Td (" + MACHINE + b") Tj ET Q\n")
    columns = (b"BT /F1 18 Tf 72 700 Td (Quarterly benefits enrollment closes Friday) Tj ET\n"
               b"BT /F1 18 Tf 320 700 Td (Employees should contact human resources) Tj ET\n")
    return (
        ("white-on-white", synthetic_pdf([white]), True, True),
        ("off-page", synthetic_pdf([off_page]), True, True),
        ("clipped-off-page", synthetic_pdf([clipped]), True, True),
        ("two-column", synthetic_pdf([columns]), True, False),
        ("rotated-page", synthetic_pdf([BASE_STREAM], rotate=90), False, False),
        ("four-pages", synthetic_pdf([BASE_STREAM] * 4), True, False),
    )


def qualify(directory, selected_image):
    renderer.image_id(selected_image)
    directory = Path(directory); directory.mkdir(mode=0o700)
    report = {"schema": "ai-dfir/pdf-render-qualification/v1.7", "status": "FAIL", "image_id": selected_image,
              "cases": [], "synthetic_only": True, "source_authenticity_verified": False, "production_qualified": False,
              "curated_hostile_cases": 3, "layout_boundary_cases": 3}
    try:
        baseline = (("visible", pdf_fixture(), 1, False, True, False),
                    ("hidden", pdf_fixture(hidden=True), 1, False, True, True),
                    ("two-pages", pdf_fixture(pages=2), 2, False, True, False),
                    ("blank", pdf_fixture(blank=True), 1, True, False, False))
        expanded = tuple((name, raw, 4 if name == "four-pages" else 1, False, check_visible, machine_absent)
                         for name, raw, check_visible, machine_absent in hostile_fixtures())
        for name, raw, pages, blank, check_visible, machine_absent in baseline + expanded:
            source = directory / (name + ".pdf"); renderer.private_write(source, raw)
            result = renderer.capture(source, directory / name, selected_image=selected_image)
            row = {"case": name, "available": result["available"], "expected": "AVAILABLE"}; report["cases"].append(row)
            if not result["available"]: row["diagnostic"] = result
            assert result["available"] and result["page_count"] == pages and result["cleanup_complete"]
            assert result["complete_visible_rendering_verified"] is False and result["ocr_accuracy_verified"] is False
            retained = json.loads((directory / name / "render.json").read_bytes())
            assert retained == result and retained["artifact_set_complete"]
            assert (directory / name / "source.pdf").read_bytes() == raw
            visible = (directory / name / "visible.txt").read_bytes()
            assert renderer.sha256_bytes(visible) == result["visible_text_sha256"]
            for page in result["pages"]:
                png = (directory / name / page["png_file"]).read_bytes()
                assert renderer.png_dimensions(png) == (page["width"], page["height"])
                assert renderer.sha256_bytes(png) == page["png_sha256"]
                assert 1 <= page["width"] <= 2048 and 1 <= page["height"] <= 2048
            if blank: assert not visible.strip()
            elif check_visible:
                assert b"benefits enrollment" in visible.lower() and b"human resources" in visible.lower()
            if machine_absent:
                assert MACHINE in raw and MACHINE.lower() not in visible.lower()
            if name in {"hidden", "white-on-white", "off-page", "clipped-off-page"}:
                differential = compare(MACHINE, visible)
                assert differential["intake"]["analysis_available"] and differential["findings"][0]["severity"] == "critical"
                renderer.output_report(differential, directory / (name + "-comparison.json"))
            row.update(source_sha256=result["source_sha256"], toolchain=result["toolchain"], isolation=result["isolation"])
        for name, raw in (("malformed", b"%PDF-1.7\nnot a document"), ("too-many-pages", pdf_fixture(pages=5))):
            result = renderer.render(raw, selected_image=selected_image)
            report["cases"].append({"case": name, "available": result["available"], "expected": "UNAVAILABLE", "diagnostic": result})
            assert not result["available"] and result["cleanup_complete"] and result["stage"] == "render"
        assert len(report["cases"]) == 12
        report["status"] = "PASS"
    except Exception as error:
        report["error_type"] = type(error).__name__
    renderer.output_report(report, directory / "qualification.json")
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

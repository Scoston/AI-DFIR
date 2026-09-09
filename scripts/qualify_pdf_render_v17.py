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


def qualify(directory, selected_image):
    renderer.image_id(selected_image)
    directory = Path(directory); directory.mkdir(mode=0o700)
    report = {"schema": "ai-dfir/pdf-render-qualification/v1.7", "status": "FAIL", "image_id": selected_image,
              "cases": [], "synthetic_only": True, "source_authenticity_verified": False, "production_qualified": False}
    try:
        for name, raw, pages, blank in (("visible", pdf_fixture(), 1, False), ("hidden", pdf_fixture(hidden=True), 1, False),
                                      ("two-pages", pdf_fixture(pages=2), 2, False), ("blank", pdf_fixture(blank=True), 1, True)):
            source = directory / (name + ".pdf"); renderer.private_write(source, raw)
            result = renderer.capture(source, directory / name, selected_image=selected_image)
            row = {"case": name, "available": result["available"], "expected": "AVAILABLE"}; report["cases"].append(row)
            if not result["available"]: row["diagnostic"] = result
            assert result["available"] and result["page_count"] == pages and result["cleanup_complete"]
            retained = json.loads((directory / name / "render.json").read_bytes())
            assert retained == result and retained["artifact_set_complete"]
            assert (directory / name / "source.pdf").read_bytes() == raw
            visible = (directory / name / "visible.txt").read_bytes()
            assert renderer.sha256_bytes(visible) == result["visible_text_sha256"]
            for page in result["pages"]:
                png = (directory / name / page["png_file"]).read_bytes()
                assert renderer.png_dimensions(png) == (page["width"], page["height"])
                assert renderer.sha256_bytes(png) == page["png_sha256"]
            if blank: assert not visible.strip()
            else: assert b"benefits enrollment" in visible.lower() and b"human resources" in visible.lower()
            if name == "hidden":
                assert b"approve transfer" not in visible.lower() and MACHINE in raw
                differential = compare(MACHINE, visible)
                assert differential["intake"]["analysis_available"] and differential["findings"][0]["severity"] == "critical"
                renderer.output_report(differential, directory / "hidden-comparison.json")
            row.update(source_sha256=result["source_sha256"], toolchain=result["toolchain"], isolation=result["isolation"])
        for name, raw in (("malformed", b"%PDF-1.7\nnot a document"), ("too-many-pages", pdf_fixture(pages=5))):
            result = renderer.render(raw, selected_image=selected_image)
            report["cases"].append({"case": name, "available": result["available"], "expected": "UNAVAILABLE", "diagnostic": result})
            assert not result["available"] and result["cleanup_complete"] and result["stage"] == "render"
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

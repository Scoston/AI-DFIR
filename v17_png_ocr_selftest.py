#!/usr/bin/env python3
"""Engine-independent PNG bridge acceptance; never native OCR qualification."""
import copy
import json

import v17_png_ocr as png_ocr
from v17_pdf_render_selftest import png_fixture, reply_fixture

IMAGE = "sha256:" + "a" * 64


def check():
    source = png_fixture()
    bridge, width, height = png_ocr.bridge_pdf(source)
    assert bridge.startswith(b"%PDF-1.4") and (width, height) == (1, 1)
    original = png_ocr.pdf_renderer.render
    try:
        def fake_render(pdf, *, selected_image):
            assert pdf == bridge and selected_image == IMAGE
            report = reply_fixture(source=pdf)
            report.update(container_image_id=IMAGE, docker_server_version="synthetic-only",
                          container_configuration_checked=True, cleanup_complete=True)
            return report
        png_ocr.pdf_renderer.render = fake_render
        good = png_ocr.render(source, selected_image=IMAGE)
    finally:
        png_ocr.pdf_renderer.render = original
    assert good["available"] and good["source_width"] == 1 and good["source_height"] == 1
    png_ocr.validate(good, source)
    rejected = 0
    for key, value in (("source_width", True), ("bridge_pdf_sha256", "0" * 64),
                       ("ocr_accuracy_verified", True), ("method", "direct-host-ocr")):
        bad = copy.deepcopy(good); bad[key] = value
        try: png_ocr.validate(bad, source)
        except (ValueError, TypeError): rejected += 1
        else: raise AssertionError("forged PNG OCR wrapper accepted")
    return {"status": "PASS", "valid_bridge_wrappers": 1, "invalid_wrappers_rejected": rejected,
            "native_png_ocr_qualified": False, "network_required": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2, sort_keys=True))

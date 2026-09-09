"""Bounded grayscale PNG OCR through the already-isolated PDF renderer."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import struct

from v17_content_intake import read_snapshot, output_report, require
from v17_integrity import sha256_bytes
import v17_pdf_render as pdf_renderer

SCHEMA = "ai-dfir/isolated-png-ocr/v1.7"
PROFILE = "png-grayscale-pdf-bridge-ocr-v1.7"
SOURCE_BYTES = pdf_renderer.PNG_BYTES
REPORT_BYTES = pdf_renderer.REPORT_BYTES
FALSE_FLAGS = {"source_authenticity_verified", "complete_visible_rendering_verified", "ocr_accuracy_verified"}
METHOD = "validated-grayscale-png-to-pdf-bridge-then-raster-ocr"


def _idat(raw):
    """Return validated PNG dimensions and its exact concatenated IDAT stream."""
    width, height = pdf_renderer.png_dimensions(raw)
    offset, compressed = 8, []
    while offset < len(raw):
        length = struct.unpack(">I", raw[offset:offset + 4])[0]
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + length
        if kind == b"IDAT":
            compressed.append(raw[offset + 8:end - 4])
        offset = end
    require(compressed)
    return width, height, b"".join(compressed)


def bridge_pdf(source):
    """Wrap a narrow validated grayscale PNG as one deterministic PDF image page.

    The PNG's already-validated zlib/PNG-predictor stream is embedded verbatim as
    a PDF image XObject. No host-native image library or alternate decoder is
    introduced. Poppler still performs the native raster operation only inside
    the existing isolated renderer container.
    """
    require(type(source) is bytes and 0 < len(source) <= SOURCE_BYTES)
    width, height, compressed = _idat(source)
    page_width, page_height = width / 2.0, height / 2.0
    pw, ph = f"{page_width:.3f}", f"{page_height:.3f}"
    content = f"q {pw} 0 0 {ph} 0 0 cm /Im0 Do Q\n".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {pw} {ph}] "
         "/Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>").encode("ascii"),
        (f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} /ColorSpace /DeviceGray "
         f"/BitsPerComponent 8 /Filter /FlateDecode /DecodeParms << /Predictor 15 /Colors 1 "
         f"/BitsPerComponent 8 /Columns {width} >> /Length {len(compressed)} >>\nstream\n").encode("ascii")
         + compressed + b"\nendstream",
        f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"endstream",
    ]
    raw = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"; offsets = []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(raw)); raw += str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    start = len(raw); count = len(objects) + 1
    raw += b"xref\n0 " + str(count).encode() + b"\n0000000000 65535 f \n"
    raw += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    raw += b"trailer\n<< /Size " + str(count).encode() + b" /Root 1 0 R >>\nstartxref\n" + str(start).encode() + b"\n%%EOF\n"
    require(len(raw) <= pdf_renderer.SOURCE_BYTES)
    return raw, width, height


def _unknown(source=None):
    report = {"schema": SCHEMA, "profile": PROFILE, "available": False, "rendering_performed": False,
              "artifact_set_complete": False, "error": "PNG OCR unavailable, unsupported, invalid, or resource-limited",
              "stage": "input", "cleanup_complete": True,
              "findings": [{"type": "png_ocr_incomplete", "severity": "high"}], "collection_complete": None,
              **{key: False for key in FALSE_FLAGS}}
    if type(source) is bytes and 0 < len(source) <= SOURCE_BYTES:
        report.update(source_sha256=sha256_bytes(source), source_size_bytes=len(source))
    return report


def _wire(pdf_report):
    return {key: value for key, value in pdf_report.items() if key not in
            {"container_image_id", "docker_server_version", "container_configuration_checked", "cleanup_complete"}}


def render(source, *, selected_image):
    unknown = _unknown(source)
    try:
        bridge, source_width, source_height = bridge_pdf(source)
        unknown.update(stage="bridge", source_width=source_width, source_height=source_height,
                       bridge_pdf_sha256=sha256_bytes(bridge), bridge_pdf_size_bytes=len(bridge))
        result = pdf_renderer.render(bridge, selected_image=selected_image)
        if result.get("available") is not True:
            unknown.update(stage="isolated_render", rendering_performed=result.get("rendering_performed"),
                           cleanup_complete=result.get("cleanup_complete", False))
            if "worker_stage" in result: unknown["worker_stage"] = result["worker_stage"]
            return unknown
        images = pdf_renderer.validate(_wire(result), bridge)
        require(len(images) == 1 and result["page_count"] == 1 and result.get("cleanup_complete") is True)
        page = dict(result["pages"][0])
        report = {"schema": SCHEMA, "profile": PROFILE, "available": True,
                  "source_sha256": sha256_bytes(source), "source_size_bytes": len(source),
                  "source_width": source_width, "source_height": source_height,
                  "bridge_pdf_sha256": sha256_bytes(bridge), "bridge_pdf_size_bytes": len(bridge),
                  "visible_text": result["visible_text"], "visible_text_sha256": result["visible_text_sha256"],
                  "page": page, "toolchain": result["toolchain"], "isolation": result["isolation"],
                  "container_image_id": result["container_image_id"], "docker_server_version": result["docker_server_version"],
                  "container_configuration_checked": result["container_configuration_checked"],
                  "cleanup_complete": True, "rendering_performed": True, "artifact_set_complete": False,
                  "method": METHOD, "collection_complete": None,
                  **{key: False for key in FALSE_FLAGS}}
        validate(report, source)
        return report
    except KeyboardInterrupt:
        raise
    except Exception:
        return unknown


def validate(report, source):
    bridge, source_width, source_height = bridge_pdf(source)
    keys = {"schema", "profile", "available", "source_sha256", "source_size_bytes", "source_width", "source_height",
            "bridge_pdf_sha256", "bridge_pdf_size_bytes", "visible_text", "visible_text_sha256", "page", "toolchain",
            "isolation", "container_image_id", "docker_server_version", "container_configuration_checked",
            "cleanup_complete", "rendering_performed", "artifact_set_complete", "method", "collection_complete"} | FALSE_FLAGS
    require(isinstance(report, dict) and set(report) == keys and report["schema"] == SCHEMA and report["profile"] == PROFILE
            and report["available"] is True and report["rendering_performed"] is True and report["artifact_set_complete"] is False
            and report["source_sha256"] == sha256_bytes(source) and type(report["source_size_bytes"]) is int
            and report["source_size_bytes"] == len(source) and type(report["source_width"]) is int
            and type(report["source_height"]) is int and report["source_width"] == source_width
            and report["source_height"] == source_height and report["bridge_pdf_sha256"] == sha256_bytes(bridge)
            and type(report["bridge_pdf_size_bytes"]) is int and report["bridge_pdf_size_bytes"] == len(bridge)
            and report["method"] == METHOD and report["collection_complete"] is None
            and all(report[key] is False for key in FALSE_FLAGS)
            and report["container_configuration_checked"] is True and report["cleanup_complete"] is True
            and pdf_renderer.image_id(report["container_image_id"]) == report["container_image_id"]
            and isinstance(report["docker_server_version"], str) and 0 < len(report["docker_server_version"]) <= 128)
    isolation = report["isolation"]
    require(isinstance(isolation, dict) and set(isolation) == pdf_renderer.PROBES and all(value is True for value in isolation.values()))
    chain = report["toolchain"]
    require(isinstance(chain, dict) and set(chain) == {"versions", "worker_sha256", "package_inventory_sha256", "english_model_sha256", "font_sha256"}
            and all(pdf_renderer.digest(chain[key]) for key in chain if key != "versions")
            and chain["worker_sha256"] == sha256_bytes(pdf_renderer.WORKER_SOURCE.read_bytes()))
    require(isinstance(chain["versions"], dict) and set(chain["versions"]) == {"pdftoppm", "tesseract"}
            and all(isinstance(value, str) and 0 < len(value) <= 256 for value in chain["versions"].values()))
    page = report["page"]
    require(isinstance(page, dict) and set(page) == {"page", "width", "height", "png_sha256", "png_size_bytes", "png_base64", "ocr_text", "ocr_sha256"}
            and type(page["page"]) is int and page["page"] == 1 and type(page["width"]) is int and type(page["height"]) is int
            and type(page["png_size_bytes"]) is int and isinstance(page["png_base64"], str))
    observed = base64.b64decode(page["png_base64"], validate=True)
    require(base64.b64encode(observed).decode() == page["png_base64"] and page["png_sha256"] == sha256_bytes(observed)
            and page["png_size_bytes"] == len(observed) and pdf_renderer.png_dimensions(observed) == (page["width"], page["height"]))
    text = page["ocr_text"]
    require(isinstance(text, str) and len(text.encode()) <= pdf_renderer.TEXT_BYTES and page["ocr_sha256"] == sha256_bytes(text.encode())
            and report["visible_text"] == text and report["visible_text_sha256"] == sha256_bytes(text.encode()))
    return bridge, observed


def private_write(path, raw):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def capture(path, destination, *, selected_image):
    source = read_snapshot(path, SOURCE_BYTES)
    report = render(source, selected_image=selected_image)
    if report["available"] is not True: return report
    bridge, observed = validate(report, source)
    directory = Path(destination).absolute(); directory.mkdir(mode=0o700)
    private_write(directory / "source.png", source)
    private_write(directory / "bridge.pdf", bridge)
    private_write(directory / "visible.txt", report["visible_text"].encode())
    private_write(directory / "observed.png", observed)
    report["page"].pop("png_base64"); report["page"]["png_file"] = "observed.png"
    report.update(artifact_set_complete=True, source_file="source.png", bridge_pdf_file="bridge.pdf",
                  visible_text_file="visible.txt")
    output_report(report, directory / "png-ocr.json", limit=REPORT_BYTES)
    return report


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("png"); parser.add_argument("--image-id", required=True)
    parser.add_argument("--out-dir", required=True); args = parser.parse_args()
    try:
        report = capture(args.png, args.out_dir, selected_image=args.image_id)
        output = {key: report[key] for key in ("schema", "available", "rendering_performed", "artifact_set_complete")} if report["available"] else report
        print(json.dumps(output, sort_keys=True)); return 0 if report["available"] else 1
    except KeyboardInterrupt: return 130
    except Exception:
        print(json.dumps({"available": False, "artifact_set_complete": False, "error": "invalid input or unavailable output"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

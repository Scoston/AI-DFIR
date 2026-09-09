"""Bounded PNG bridge, wrapper integrity, rejection, and custody tests."""
import copy
import struct
import zlib

import pytest

import v17_png_ocr as png_ocr
from v17_pdf_render_selftest import png_chunk, png_fixture, reply_fixture
from v17_png_ocr_selftest import check

IMAGE = "sha256:" + "a" * 64
SOURCE = png_fixture()


def fake_pdf_report(source):
    report = reply_fixture(source=source)
    report.update(container_image_id=IMAGE, docker_server_version="synthetic-only",
                  container_configuration_checked=True, cleanup_complete=True)
    return report


def rgb_png():
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header)
            + png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + png_chunk(b"IEND", b""))


def test_protocol_selftest_never_claims_native_qualification():
    assert check() == {"status": "PASS", "valid_bridge_wrappers": 1, "invalid_wrappers_rejected": 4,
                       "native_png_ocr_qualified": False, "network_required": False}


def test_bridge_is_deterministic_and_source_bound():
    first, width, height = png_ocr.bridge_pdf(SOURCE)
    second, width2, height2 = png_ocr.bridge_pdf(SOURCE)
    assert first == second and (width, height) == (width2, height2) == (1, 1)
    assert first.startswith(b"%PDF-1.4") and b"/Subtype /Image" in first and b"/Predictor 15" in first


def test_split_idat_bridge_preserves_validated_stream():
    compressed = zlib.compress(b"\x00\xff")
    source = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
              + png_chunk(b"IDAT", compressed[:3]) + png_chunk(b"IDAT", compressed[3:]) + png_chunk(b"IEND", b""))
    bridge, width, height = png_ocr.bridge_pdf(source)
    assert (width, height) == (1, 1) and compressed in bridge


def test_render_reuses_isolated_pdf_result(monkeypatch):
    bridge, _, _ = png_ocr.bridge_pdf(SOURCE)
    calls = []
    def render(source, *, selected_image):
        calls.append((source, selected_image)); return fake_pdf_report(source)
    monkeypatch.setattr(png_ocr.pdf_renderer, "render", render)
    result = png_ocr.render(SOURCE, selected_image=IMAGE)
    assert calls == [(bridge, IMAGE)] and result["available"] and result["cleanup_complete"]
    assert result["source_width"] == 1 and result["source_height"] == 1
    assert result["method"] == png_ocr.METHOD and result["artifact_set_complete"] is False
    assert all(result[key] is False for key in png_ocr.FALSE_FLAGS)
    png_ocr.validate(result, SOURCE)


@pytest.mark.parametrize("key,value", [("source_width", True), ("source_height", False),
    ("source_sha256", "0" * 64), ("bridge_pdf_sha256", "0" * 64), ("bridge_pdf_size_bytes", True),
    ("method", "host-ocr"), ("container_configuration_checked", False), ("cleanup_complete", False),
    ("source_authenticity_verified", True), ("complete_visible_rendering_verified", True), ("ocr_accuracy_verified", True)])
def test_forged_wrapper_rejected(monkeypatch, key, value):
    monkeypatch.setattr(png_ocr.pdf_renderer, "render", lambda source, selected_image: fake_pdf_report(source))
    result = png_ocr.render(SOURCE, selected_image=IMAGE)
    result[key] = value
    with pytest.raises((ValueError, TypeError)):
        png_ocr.validate(result, SOURCE)


@pytest.mark.parametrize("key,value", [("page", True), ("width", True), ("height", False),
    ("png_sha256", "0" * 64), ("png_size_bytes", True), ("png_base64", "!"),
    ("ocr_text", "forged"), ("ocr_sha256", "0" * 64)])
def test_forged_observed_page_rejected(monkeypatch, key, value):
    monkeypatch.setattr(png_ocr.pdf_renderer, "render", lambda source, selected_image: fake_pdf_report(source))
    result = png_ocr.render(SOURCE, selected_image=IMAGE)
    result["page"][key] = value
    with pytest.raises((ValueError, TypeError, zlib.error)):
        png_ocr.validate(result, SOURCE)


@pytest.mark.parametrize("source", [b"", b"not a png", rgb_png(), SOURCE + b"tail", None, "png", bytearray(SOURCE)])
def test_invalid_or_unsupported_source_never_invokes_renderer(monkeypatch, source):
    called = []
    monkeypatch.setattr(png_ocr.pdf_renderer, "render", lambda *args, **kwargs: called.append(True))
    result = png_ocr.render(source, selected_image=IMAGE)
    assert result["available"] is False and result["artifact_set_complete"] is False and result["stage"] == "input"
    assert called == []


def test_underlying_render_failure_preserves_unknown(monkeypatch):
    bridge, _, _ = png_ocr.bridge_pdf(SOURCE)
    def failed(source, *, selected_image):
        assert source == bridge and selected_image == IMAGE
        return {"available": False, "rendering_performed": None, "cleanup_complete": True, "worker_stage": "ocr"}
    monkeypatch.setattr(png_ocr.pdf_renderer, "render", failed)
    result = png_ocr.render(SOURCE, selected_image=IMAGE)
    assert result["available"] is False and result["stage"] == "isolated_render"
    assert result["rendering_performed"] is None and result["cleanup_complete"] is True and result["worker_stage"] == "ocr"


def test_capture_retains_original_bridge_observation_and_receipt(monkeypatch, tmp_path):
    monkeypatch.setattr(png_ocr.pdf_renderer, "render", lambda source, selected_image: fake_pdf_report(source))
    source = tmp_path / "input.png"; source.write_bytes(SOURCE)
    destination = tmp_path / "capture"
    result = png_ocr.capture(source, destination, selected_image=IMAGE)
    bridge, _, _ = png_ocr.bridge_pdf(SOURCE)
    assert result["available"] and result["artifact_set_complete"]
    assert (destination / "source.png").read_bytes() == SOURCE
    assert (destination / "bridge.pdf").read_bytes() == bridge
    assert (destination / "visible.txt").read_text() == "Synthetic OCR observation\n"
    assert (destination / "observed.png").read_bytes() == png_fixture()
    assert (destination / "png-ocr.json").is_file()


def test_existing_destination_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(png_ocr.pdf_renderer, "render", lambda source, selected_image: fake_pdf_report(source))
    source = tmp_path / "input.png"; source.write_bytes(SOURCE)
    destination = tmp_path / "capture"; destination.mkdir()
    with pytest.raises(FileExistsError):
        png_ocr.capture(source, destination, selected_image=IMAGE)

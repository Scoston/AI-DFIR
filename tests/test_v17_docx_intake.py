"""Adversarial ZIP/XML, source binding, font worker, and gate regressions."""
import io
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import zipfile
import zlib

import pytest

import content_intake_gate as gate
import evil_font_forensics as legacy
import v17_docx_font as worker
import v17_docx_intake as intake
from v17_docx_intake_selftest import DOCUMENT, check, font_table, package, relationships, synthetic_font
from v17_integrity import sha256_bytes
from v17_provenance import ProvenanceError

ROOT = Path(__file__).resolve().parents[1]
FONT = synthetic_font()


def font_parts(target="fonts/synthetic.ttf", mode="Internal", count=1, key=None, raw=FONT):
    return {"word/document.xml": DOCUMENT, "word/fontTable.xml": font_table(count, key),
            "word/_rels/fontTable.xml.rels": relationships(target, count, mode), "word/fonts/synthetic.ttf": raw}


def custom_payload(payload, size, crc, method=zipfile.ZIP_DEFLATED):
    raw = bytearray(package({"word/document.xml": payload}, zipfile.ZIP_STORED))
    cd = raw.index(b"PK\x01\x02")
    for offset in (8, cd + 10): struct.pack_into("<H", raw, offset, method)
    for offset in (14, cd + 16): struct.pack_into("<I", raw, offset, crc)
    for offset in (22, cd + 24): struct.pack_into("<I", raw, offset, size)
    return bytes(raw)


def deflate(raw):
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(raw) + compressor.flush()


def local_payload(raw, name):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.getinfo(name)
    sizes = struct.unpack_from("<HH", raw, info.header_offset + 26)
    return info.header_offset + 30 + sum(sizes)


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_selected_snapshot_crc_and_explicit_partial_scope(method, monkeypatch):
    raw = package(compression=method)
    for action in ("open", "read", "extract", "extractall"):
        monkeypatch.setattr(zipfile.ZipFile, action, lambda *a, **kw: pytest.fail("member I/O"))
    parts = intake.load_docx(raw)
    assert dict(parts) == {"word/document.xml": DOCUMENT}
    receipt = parts.intake
    assert receipt["source_sha256"] == sha256_bytes(raw) and receipt["selected_part_size_crc_checked"] is True
    assert receipt["uninspected_member_count"] == 1 and receipt["selected_bytes"] == len(DOCUMENT)
    assert receipt["collection_complete"] is None
    for flag in ("all_member_payloads_verified", "external_resources_loaded", "filesystem_extraction",
                 "source_authenticity_verified", "complete_visible_rendering_verified", "network_required"):
        assert receipt[flag] is False


@pytest.mark.parametrize("raw", [None, "zip", bytearray(b"zip"), memoryview(b"zip"), b"", b"not ZIP", b"PK\x03\x04"])
def test_invalid_snapshot(raw):
    with pytest.raises(ProvenanceError): intake.load_docx(raw)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:drive", "word\\font", "word/./font",
                                  "word//font", "word/font.", "word/font ", "word/\x01font", "word/CON"])
def test_unsafe_names(name):
    with pytest.raises(ProvenanceError): intake.load_docx(package({"word/document.xml": DOCUMENT, name: b"x"}))


@pytest.mark.parametrize("names", [("word/a", "word/A"), ("word/é", "word/e\u0301"), ("word/document.xml", "WORD/DOCUMENT.XML")])
def test_portable_alias_collisions(names):
    with pytest.raises(ProvenanceError): intake.load_docx(package({"word/document.xml": DOCUMENT, **{n: DOCUMENT for n in names}}))


def test_exact_duplicate_member_rejected():
    stream = io.BytesIO(package())
    with zipfile.ZipFile(stream, "a") as archive:
        with pytest.warns(UserWarning): archive.writestr("word/document.xml", DOCUMENT)
    with pytest.raises(ProvenanceError): intake.load_docx(stream.getvalue())


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR])
def test_nonregular_members(mode):
    raw = bytearray(package())
    struct.pack_into("<I", raw, raw.index(b"PK\x01\x02") + 38, (mode | 0o600) << 16)
    with pytest.raises(ProvenanceError): intake.load_docx(bytes(raw))


def test_encryption_rejected():
    raw = bytearray(package())
    for offset in (6, raw.index(b"PK\x01\x02") + 8): struct.pack_into("<H", raw, offset, 1)
    with pytest.raises(ProvenanceError): intake.load_docx(bytes(raw))


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA, 99])
def test_unsupported_compression(method):
    with pytest.raises(ProvenanceError): intake.load_docx(custom_payload(DOCUMENT, len(DOCUMENT), zlib.crc32(DOCUMENT), method))


@pytest.mark.parametrize("selected", [True, False])
def test_crc_check_scope(selected):
    raw = bytearray(package(compression=zipfile.ZIP_STORED))
    raw[local_payload(raw, "word/document.xml" if selected else "word/media/uninspected.bin")] ^= 1
    if selected:
        with pytest.raises(ProvenanceError): intake.load_docx(bytes(raw))
    else:
        assert intake.load_docx(bytes(raw)).intake["all_member_payloads_verified"] is False


@pytest.mark.parametrize("mutation", [lambda p: p[:-1], lambda p: p + b"trailer", lambda p: p + p])
def test_incomplete_or_extra_deflate_stream(mutation):
    with pytest.raises(ProvenanceError):
        intake.load_docx(custom_payload(mutation(deflate(DOCUMENT)), len(DOCUMENT), zlib.crc32(DOCUMENT)))


def test_forged_short_size_and_matching_prefix_crc_never_truncates():
    with pytest.raises(ProvenanceError): intake.load_docx(custom_payload(deflate(DOCUMENT), 10, zlib.crc32(DOCUMENT[:10])))


@pytest.mark.parametrize("mutation", [lambda r: r.__setitem__(14, r[14] ^ 1),
                                     lambda r: r.__setitem__(30, r[30] ^ 1), lambda r: r.extend(b"trailer")])
def test_container_metadata_inconsistency(mutation):
    raw = bytearray(package()); mutation(raw)
    with pytest.raises(ProvenanceError): intake.load_docx(bytes(raw))


BAD_XML = [b"", b"<wrong/>", b"<w:document/>", b"<", b"<x/><y/>", b'<!DOCTYPE x><x/>',
           b'<!DOCTYPE x SYSTEM "file:///synthetic"><x/>', b'<!DOCTYPE x [<!ENTITY a "test">]><x>&a;</x>',
           b'<!DOCTYPE x [<!ENTITY a SYSTEM "https://example.invalid">]><x>&a;</x>',
           b'<!DOCTYPE x [<!ENTITY % a "test">%a;]><x/>', b"<x>&unknown;</x>", b"\x00", b"\xff", b"<x>&#xD800;</x>"]


@pytest.mark.parametrize("xml", BAD_XML)
def test_invalid_and_forbidden_xml(xml):
    with pytest.raises(ProvenanceError): intake.load_docx(package({"word/document.xml": xml}))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16le", "utf-16be"])
def test_dtd_forbidden_across_encodings(encoding):
    text = f'<!DOCTYPE w:document [<!ENTITY a "synthetic">]><w:document xmlns:w="{intake.WORD}">&a;</w:document>'
    with pytest.raises(ProvenanceError): intake.load_docx(package({"word/document.xml": text.encode(encoding)}))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16le", "utf-16be"])
def test_normal_xml_encodings(encoding):
    raw = DOCUMENT.decode().encode(encoding)
    assert intake.load_docx(package({"word/document.xml": raw}))["word/document.xml"] == raw


@pytest.mark.parametrize("limit,value", [("MAX_XML_NODES", 4), ("MAX_XML_DEPTH", 4), ("MAX_TEXT_CHARS", 3),
                                        ("MAX_XML_BYTES", 20), ("MAX_MEMBERS", 1), ("MAX_SELECTED_BYTES", 20)])
def test_budget_failures_never_return_partial_success(limit, value, monkeypatch):
    monkeypatch.setattr(intake, limit, value)
    with pytest.raises(ProvenanceError): intake.load_docx(package())


@pytest.mark.parametrize("attrs", [' '.join(f'a{i}="x"' for i in range(129)), 'a' * 4097 + '="x"', 'a="' + 'x' * 4097 + '"'])
def test_excessive_attributes(attrs):
    xml = f'<w:document xmlns:w="{intake.WORD}" {attrs}/>'.encode()
    with pytest.raises(ProvenanceError): intake.load_docx(package({"word/document.xml": xml}))


def test_declared_ratio_rejects_before_inflating(monkeypatch):
    raw = custom_payload(b"x", 2000, 0)
    monkeypatch.setattr(zlib, "decompressobj", lambda *a: pytest.fail("inflation started"))
    with pytest.raises(ProvenanceError): intake.load_docx(raw)


@pytest.mark.parametrize("name", ["word/fontTable.xml", "word/_rels/fontTable.xml.rels"])
def test_malformed_optional_xml_is_not_silent(name):
    with pytest.raises(ProvenanceError): intake.load_docx(package({"word/document.xml": DOCUMENT, name: b"<wrong/>"}))


@pytest.mark.parametrize("xml", [relationships(count=2).replace(b'Id="r1"', b'Id="r0"'),
    relationships().replace(b'Id="r0"', b'Id=""'), relationships().replace(b'Target="fonts/synthetic.ttf"', b'Target=""'),
    relationships(mode="Unknown"), relationships().replace(b'<Relationship ', b'<Other ')])
def test_ambiguous_relationships_fail(xml):
    parts = font_parts(); parts["word/_rels/fontTable.xml.rels"] = xml
    with pytest.raises(ProvenanceError): intake.load_docx(package(parts))


@pytest.mark.parametrize("target", ["https://example.invalid/font", "file:///font", "/font", "../font", "fonts/../font", "C:font",
                                    "fonts\\font", "fonts/%61.ttf", "fonts/a#x", "fonts/a?x"])
def test_font_targets_remain_unresolved_data(target, monkeypatch):
    parts = intake.load_docx(package(font_parts(target=target)))
    monkeypatch.setattr(legacy, "bounded_docx_font", lambda *a: pytest.fail("external font loaded"))
    _, findings = legacy.embedded_docx_fonts(parts)
    assert "word/fonts/synthetic.ttf" not in parts
    assert findings[0]["type"] == "docx_font_reference_unresolved" and findings[0]["severity"] == "high"


def test_external_relationship_does_not_load_even_matching_package_key():
    parts = intake.load_docx(package(font_parts(mode="External")))
    assert "word/fonts/synthetic.ttf" not in parts
    assert legacy.embedded_docx_fonts(parts)[1][0]["severity"] == "high"


@pytest.mark.parametrize("limit,value", [("MAX_FONTS", 1), ("MAX_FONT_BYTES", len(FONT) - 1), ("MAX_SELECTED_BYTES", len(DOCUMENT) + 1)])
def test_font_budgets(limit, value, monkeypatch):
    monkeypatch.setattr(intake, limit, value)
    with pytest.raises(ProvenanceError): intake.load_docx(package(font_parts(count=2)))


@pytest.mark.parametrize("name", ["word/vbaProject.bin", "word/activeX/control.bin", "word/embeddings/object.bin"])
def test_active_or_embedded_parts_are_flagged_without_parsing(name):
    parts = intake.load_docx(package({"word/document.xml": DOCUMENT, name: b"opaque"}))
    assert name not in parts and any(f["type"] == "docx_active_or_embedded_content" for f in parts.intake["findings"])


def test_actual_font_worker_geometry():
    report = worker.analyze(FONT)
    if sys.platform != "linux":
        assert report["available"] is False
        return
    assert report["available"] is True and report["sha256"] == sha256_bytes(FONT)
    assert "font_glyph_outline_collapse" in {f["type"] for f in report["findings"]}


@pytest.mark.parametrize("data", [None, bytearray(FONT), b"", b"wOFF" + b"x" * 20, b"wOF2" + b"x" * 20,
                                 b"ttcf" + b"x" * 20, b"x" * (worker.MAX_INPUT_BYTES + 1)])
def test_font_parent_rejects_before_child(data, monkeypatch):
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **kw: pytest.fail("worker started"))
    assert worker.analyze(data)["available"] is False


def test_odttf_decoding_and_duplicate_font_cache(monkeypatch):
    key = "00112233-4455-6677-8899-aabbccddeeff"
    parts = intake.load_docx(package(font_parts(count=2, key=key, raw=legacy.deobfuscate_odttf(FONT, key))))
    calls = []
    def analyze(data):
        calls.append(data)
        return {"available": True, "sha256": sha256_bytes(data), "findings": []}
    monkeypatch.setattr(legacy, "bounded_docx_font", analyze)
    fonts, findings = legacy.embedded_docx_fonts(parts)
    assert len(fonts) == 2 and calls == [FONT] and findings == []


def test_invalid_font_key_does_not_fall_back_to_raw(monkeypatch):
    parts = intake.load_docx(package(font_parts(key="invalid")))
    monkeypatch.setattr(legacy, "bounded_docx_font", lambda *a: pytest.fail("invalid key ignored"))
    assert legacy.embedded_docx_fonts(parts)[1][0]["type"] == "docx_font_analysis_incomplete"


def test_elapsed_document_budget_marks_font_unknown(monkeypatch):
    parts = intake.load_docx(package(font_parts()))
    ticks = iter([0, 21]); monkeypatch.setattr(legacy.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(legacy, "bounded_docx_font", lambda *a: pytest.fail("budget ignored"))
    assert legacy.embedded_docx_fonts(parts)[1][0]["type"] == "docx_font_analysis_incomplete"


@pytest.fixture
def fake_worker(monkeypatch):
    monkeypatch.setattr(worker.sys, "platform", "linux")
    class Process:
        pid = 123456789
        returncode = 0
        reply = json.dumps({"available": True, "sha256": sha256_bytes(FONT), "findings": []}).encode()
        def __init__(self, argv, **kwargs):
            assert argv == [sys.executable, str(worker.WORKER)] and kwargs["start_new_session"] and "shell" not in kwargs
        def communicate(self, data=None, timeout=None): return self.reply, None
    monkeypatch.setattr(worker.subprocess, "Popen", Process)
    return Process


@pytest.mark.parametrize("reply", [b"", b"{}", b"[]", b"not JSON", b"x" * (worker.MAX_OUTPUT_BYTES + 1),
    json.dumps({"available": False, "sha256": sha256_bytes(FONT), "findings": []}).encode(),
    json.dumps({"available": True, "sha256": "0" * 64, "findings": []}).encode(),
    json.dumps({"available": True, "sha256": sha256_bytes(FONT), "findings": [False]}).encode()])
def test_invalid_child_reply_is_unknown(reply, fake_worker):
    fake_worker.reply = reply
    assert worker.analyze(FONT)["available"] is False


@pytest.mark.parametrize("code", [-9, -11, 1, 2])
def test_nonzero_worker_exit_is_unknown(code, fake_worker):
    fake_worker.returncode = code
    assert worker.analyze(FONT)["available"] is False


def test_worker_timeout_kills_process_group(fake_worker, monkeypatch):
    calls = []
    def communicate(self, data=None, timeout=None):
        if timeout is not None: raise subprocess.TimeoutExpired("redacted", timeout)
        return b"", None
    monkeypatch.setattr(fake_worker, "communicate", communicate)
    monkeypatch.setattr(worker.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    assert worker.analyze(FONT)["available"] is False
    assert calls == [(fake_worker.pid, signal.SIGKILL)]


def test_path_replacement_does_not_change_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "source.docx"; raw = package(); path.write_bytes(raw)
    original = intake.load_docx
    def replace(snapshot):
        path.write_bytes(b"replaced")
        return original(snapshot)
    monkeypatch.setattr(intake, "load_docx", replace)
    assert legacy.analyze_docx(path)["intake"]["source_sha256"] == sha256_bytes(raw)


@pytest.mark.parametrize("raw", [b"invalid ZIP", package({"word/document.xml": b"<wrong/>"}), package({"word/document.xml": DOCUMENT, "../escape": b"x"})])
def test_gate_parse_failure_is_review_with_redacted_error(raw, tmp_path):
    path = tmp_path / "source.docx"; path.write_bytes(raw)
    report = gate.scan(path)
    assert report["verdict"] == "REVIEW" and report["findings"][0]["type"] == "docx_parse_failure"
    assert report["findings"][0]["error"] == "invalid, unsupported, excessive, or unavailable DOCX"


def test_missing_font_is_review(tmp_path):
    path = tmp_path / "source.docx"; path.write_bytes(package(font_parts(target="missing.ttf")))
    assert gate.scan(path)["verdict"] == "REVIEW"


def test_existing_font_name_deception_findings_remain(tmp_path):
    runs = ''.join(f'<w:r><w:rPr><w:rFonts w:ascii="Synthetic {"0" if i == 0 else format(65 + i % 26, "02x")}"/></w:rPr><w:t>x</w:t></w:r>' for i in range(40))
    xml = f'<w:document xmlns:w="{intake.WORD}"><w:body><w:p>{runs}</w:p></w:body></w:document>'.encode()
    path = tmp_path / "source.docx"; path.write_bytes(package({"word/document.xml": xml}))
    report = gate.scan(path)
    assert report["verdict"] == "QUARANTINE"
    assert {"per_character_font_switching", "machine_visible_text_disagreement_via_font_mapping",
            "stealth_font_machine_only_characters", "evilfonttool_style_font_family_pattern"}.issubset({f["type"] for f in report["findings"]})
    assert report["analyses"]["document_font"]["independent_rendering_verified"] is False


@pytest.mark.parametrize("kind", ["new", "existing", "symlink", "source"])
def test_docx_cli_exclusive_private_output(kind, tmp_path):
    raw = package(); source = tmp_path / "source.docx"; source.write_bytes(raw)
    output = tmp_path / "report.json"
    if kind == "existing": output.write_bytes(b"keep")
    if kind == "symlink": output.symlink_to(source)
    if kind == "source": output = source
    result = subprocess.run([sys.executable, str(ROOT / "evil_font_forensics.py"), str(source), "--out", str(output)], capture_output=True, timeout=15)
    assert source.read_bytes() == raw
    if kind == "new":
        assert result.returncode == 0 and output.stat().st_mode & 0o777 == 0o600
        assert json.loads(output.read_bytes())["intake"]["source_sha256"] == sha256_bytes(raw)
    else:
        assert result.returncode == 1 and json.loads(result.stdout)["status"] == "FAIL"
        if kind == "existing": assert output.read_bytes() == b"keep"


def test_synthetic_selftest():
    report = check()
    assert report["valid_packages"] == 2 and report["invalid_packages_rejected"] == 6


def test_actual_embedded_geometry_reaches_gate(tmp_path):
    path = tmp_path / "source.docx"; path.write_bytes(package(font_parts()))
    report = gate.scan(path)
    assert report["verdict"] == ("QUARANTINE" if sys.platform == "linux" else "REVIEW")
    if sys.platform == "linux": assert "font_glyph_outline_collapse" in {f["type"] for f in report["findings"]}


def test_actual_child_resource_limits():
    if sys.platform != "linux":
        assert worker.analyze(FONT)["available"] is False
        return
    code = '''import resource
import evil_font_forensics as legacy
from scripts.docx_font_worker_v17 import main
from v17_integrity import sha256_bytes
def probe(data, label):
    return {"available": True, "sha256": sha256_bytes(data), "findings": [],
            "limits": {name: resource.getrlimit(getattr(resource, "RLIMIT_" + name)) for name in ("CPU", "AS", "FSIZE", "CORE")}}
legacy.analyze_font_bytes = probe
raise SystemExit(main())
'''
    result = subprocess.run([sys.executable, "-c", code], input=FONT, capture_output=True, cwd=ROOT, timeout=10)
    assert result.returncode == 0
    assert json.loads(result.stdout)["limits"] == {"CPU": [3, 3], "AS": [268435456, 268435456], "FSIZE": [0, 0], "CORE": [0, 0]}

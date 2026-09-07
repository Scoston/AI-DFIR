from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import socket
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import archive_intake_forensics as legacy
import content_intake_gate
import v17_archive_intake as intake
import v17_archive_intake_selftest as acceptance
from v17_integrity import sha256_bytes
from v17_provenance import ProvenanceError


def inspect(raw, selected="zip"):
    return intake.inspect_archive(raw, input_format=selected)


def types(report):
    return {row["type"] for row in report["findings"]}


def pack_tar(raw, selected):
    return {"tar": lambda x: x, "tar-gzip": lambda x: gzip.compress(x, mtime=0),
            "tar-bzip2": bz2.compress, "tar-xz": lzma.compress}[selected](raw)


def pax_record(key, value):
    suffix = b" " + key.encode() + b"=" + value.encode() + b"\n"
    length = len(suffix) + 1
    while len(str(length)) + len(suffix) != length:
        length = len(str(length)) + len(suffix)
    return str(length).encode() + suffix


def extension(body, kind=tarfile.XHDTYPE):
    info = tarfile.TarInfo("metadata"); info.type = kind; info.size = len(body)
    return info.tobuf() + body + bytes((-len(body)) % 512)


@pytest.mark.parametrize("selected", intake.FORMATS)
def test_complete_bounded_metadata_without_member_reads_or_external_actions(selected, monkeypatch):
    raw = acceptance.seeds()[selected]
    def forbidden(*a, **kw): pytest.fail("external or member-content action")
    monkeypatch.setattr(zipfile.ZipFile, "open", forbidden)
    monkeypatch.setattr(tarfile.TarFile, "extractfile", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = inspect(raw, selected)
    assert report["source_sha256"] == sha256_bytes(raw) and report["source_size_bytes"] == len(raw)
    assert report["member_count"] == len(report["members"]) == 7
    assert [r["name"] for r in report["members"]] == [r[0] for r in acceptance.ENTRIES]
    assert {"archive_path_escape", "archive_contains_agent_autoload_control", "archive_symlink_member",
            "archive_contains_nested_archive", "archive_member_path_collision"} <= types(report)
    assert report["metadata_only"] and report["collection_complete"] is None
    for flag in ("members_extracted", "member_payload_integrity_verified", "archive_safety_verified",
                 "source_authenticity_verified", "extraction_authorized", "network_required"):
        assert report[flag] is False
    assert inspect(raw, selected) == report


@pytest.mark.parametrize("name,index", [("../x", 1), ("a/../x", 1), ("..\\x", 1), ("/absolute", 0),
    ("C:relative", 0), ("C:/absolute", 0), ("\\\\server\\share", 0), ("AGENTS.md", 2),
    ("a/CLAUDE.local.md", 2), ("a/.cursor/rules.md", 2), (".github/workflows/build.yml", 2),
    (".git/hooks/post-checkout", 2), ("a/.mcp.json", 2), ("a/skills/new.md", 2),
    ("nested.ZIP", 3), ("nested.tar.xz", 3), ("a\ncontrol", 4), ("NUL.txt", 4),
    ("a/COM1", 4), ("a/trailing.", 4), ("a/trailing ", 4), ("a//b", 4), ("a/./b", 4), ("", 4)])
def test_portable_path_control_and_nested_risks(name, index):
    assert intake.name_risks(name)[index] is True


@pytest.mark.parametrize("first,second", [("A.txt", "a.txt"), ("a/b", "a\\b"), ("a/b", "a/./b"),
    ("name", "name."), ("name", "name "), ("é", "e\u0301"), ("dir/", "dir"), ("same", "same")])
@pytest.mark.parametrize("selected", ["zip", "tar"])
def test_portable_alias_collisions_are_findings(first, second, selected):
    entries = [(first, "file", b"a", ""), (second, "file", b"b", "")]
    with pytest.warns(UserWarning) if first == second and selected == "zip" else _no_warning_requirement():
        raw = acceptance.zip_seed(entries) if selected == "zip" else acceptance.tar_seed(entries, format=tarfile.PAX_FORMAT)
    assert "archive_member_path_collision" in types(inspect(raw, selected))


def _no_warning_requirement():
    from contextlib import nullcontext
    return nullcontext()


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
@pytest.mark.parametrize("target", ["../escape", "/absolute", "C:relative", "a\ncontrol", "NUL", "a/../escape"])
def test_tar_link_targets_are_separate_critical_observations(kind, target):
    raw = acceptance.tar_seed([("link", kind, b"", target)])
    report = inspect(raw, "tar")
    assert "archive_link_target_escape_or_ambiguity" in types(report)
    assert report["members"][0]["linkname"] == target
    assert report["members"][0]["is_hardlink"] is (kind == "hardlink")


def test_zip_symlink_payload_is_not_read_or_interpreted():
    report = inspect(acceptance.zip_seed([("link", "symlink", b"", "../../escape")]))
    assert report["members"][0]["is_symlink"] and report["members"][0]["linkname"] is None
    assert "archive_symlink_member" in types(report)


def test_special_tar_member_is_flagged_without_opening_device():
    report = inspect(acceptance.tar_seed([("pipe", "fifo", b"", "")]), "tar")
    assert "archive_special_member" in types(report)


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_zip_compression_metadata_never_requires_payload_decoding(method, monkeypatch):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=method) as archive:
        archive.writestr("file", b"synthetic" * 20)
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda *a, **kw: pytest.fail("member opened"))
    report = inspect(target.getvalue())
    assert report["members"][0]["compression_method"] == method


def test_encrypted_zip_is_flagged_without_decryption():
    raw = bytearray(acceptance.zip_seed([("file", "file", b"synthetic", "")]))
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, 6, 1); struct.pack_into("<H", raw, central + 8, 1)
    report = inspect(bytes(raw))
    assert "archive_encrypted_member" in types(report)


def test_corrupt_zip_payload_is_not_misrepresented_as_verified():
    raw = bytearray(acceptance.zip_seed([("file", "file", b"SYNTHETIC", "")]))
    raw[raw.index(b"SYNTHETIC")] ^= 1
    report = inspect(bytes(raw))
    assert report["member_count"] == 1 and report["member_payload_integrity_verified"] is False
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        with pytest.raises(zipfile.BadZipFile): archive.read("file")


@pytest.mark.parametrize("position,value,encoding", [(4, 1, "H"), (6, 1, "H"), (8, 4097, "H"),
    (10, 4097, "H"), (10, 65535, "H"), (12, 0xffffffff, "I"), (16, 0xffffffff, "I"), (20, 1, "H")])
def test_eocd_bounds_are_checked_before_zipfile_allocates_members(monkeypatch, position, value, encoding):
    raw = bytearray(acceptance.zip_seed())
    end = raw.rindex(b"PK\x05\x06"); struct.pack_into("<" + encoding, raw, end + position, value)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **kw: pytest.fail("preflight did not reject"))
    with pytest.raises(ProvenanceError): inspect(bytes(raw))


def test_actual_directory_count_is_checked_independently_of_end_record(monkeypatch):
    raw = bytearray(acceptance.zip_seed())
    end = raw.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", raw, end + 8, 0, 0)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **kw: pytest.fail("directory count trusted"))
    with pytest.raises(ProvenanceError): inspect(bytes(raw))


@pytest.mark.parametrize("offset", [6, 8, 14, 18, 22, 30])
def test_local_header_disagreement_is_rejected(offset):
    raw = bytearray(acceptance.zip_seed()); raw[offset] ^= 1
    with pytest.raises(ProvenanceError): inspect(bytes(raw))


def test_overlapping_local_members_are_rejected():
    with pytest.warns(UserWarning): raw = bytearray(acceptance.zip_seed([("same", "file", b"same", "")] * 2))
    first = raw.index(b"PK\x01\x02"); second = raw.index(b"PK\x01\x02", first + 4)
    struct.pack_into("<I", raw, second + 42, 0)
    with pytest.raises(ProvenanceError): inspect(bytes(raw))


def test_local_zip64_is_rejected_even_with_small_central_sizes():
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        with archive.open("small", "w", force_zip64=True) as stream: stream.write(b"x")
    with pytest.raises(ProvenanceError): inspect(target.getvalue())


def test_unsupported_zip_version_is_a_controlled_rejection():
    raw = bytearray(acceptance.zip_seed()); central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, central + 6, 232)
    with pytest.raises(ProvenanceError): inspect(bytes(raw))


@pytest.mark.parametrize("selected", intake.FORMATS)
@pytest.mark.parametrize("mutation", [lambda r: r[:-1], lambda r: r + b"trailer", lambda r: r + r, lambda r: b"prefix" + r])
def test_no_truncated_prefixed_trailing_or_concatenated_container_success(selected, mutation):
    with pytest.raises(ProvenanceError): inspect(mutation(acceptance.seeds()[selected]), selected)


@pytest.mark.parametrize("selected", intake.FORMATS[2:])
def test_compressed_tar_expansion_is_bounded(selected, monkeypatch):
    raw = acceptance.seeds()[selected]
    monkeypatch.setattr(intake, "MAX_TAR_BYTES", 1024)
    with pytest.raises(ProvenanceError): inspect(raw, selected)


@pytest.mark.parametrize("selected", intake.FORMATS[2:])
def test_compressed_tar_ratio_is_bounded(selected, monkeypatch):
    monkeypatch.setattr(intake, "MAX_EXPANSION_RATIO", 1)
    with pytest.raises(ProvenanceError): inspect(acceptance.seeds()[selected], selected)


def test_lzma_dictionary_memory_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(intake, "LZMA_MEMORY_LIMIT", 1024)
    with pytest.raises(ProvenanceError): inspect(acceptance.seeds()["tar-xz"], "tar-xz")


@pytest.mark.parametrize("format", [tarfile.USTAR_FORMAT, tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
def test_supported_tar_header_dialects_and_unicode_names(format):
    name = "证据.txt" if format == tarfile.USTAR_FORMAT else "directory/" * 20 + "证据.txt"
    report = inspect(acceptance.tar_seed([(name, "file", b"retained", "")], format=format), "tar")
    assert report["members"][0]["name"] == name and report["members"][0]["size"] == 8


def test_pax_path_override_is_inspected_as_the_effective_member_name():
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"path": "../escape"}) as archive:
        info = tarfile.TarInfo("safe"); info.size = 1; archive.addfile(info, io.BytesIO(b"x"))
    report = inspect(target.getvalue(), "tar")
    assert report["members"][0]["name"] == "../escape" and "archive_path_escape" in types(report)


@pytest.mark.parametrize("key,value", [("size", "1"), ("GNU.sparse.map", "0,1"), ("GNU.sparse.size", "1"),
    ("GNU.sparse.major", "1"), ("SCHILY.realsize", "1"), ("SCHILY.filetype", "sparse"), ("hdrcharset", "BINARY")])
def test_structural_sparse_and_binary_pax_overrides_fail_before_tarfile(key, value, monkeypatch):
    raw = extension(pax_record(key, value)) + acceptance.tar_seed()
    monkeypatch.setattr(tarfile, "open", lambda *a, **kw: pytest.fail("unsafe PAX reached TarFile"))
    with pytest.raises(ProvenanceError): inspect(raw, "tar")


@pytest.mark.parametrize("body", [b"0 x=\n", b"-1 x=\n", b"999999999999 x=a\n", b"8 x=a\n", b"6 x=a!", b"5 =a\n",
    b"6 x=\xff\n", pax_record("path", "a") + pax_record("path", "b")])
def test_malformed_or_duplicate_pax_fields_are_rejected(body):
    with pytest.raises(ProvenanceError): inspect(extension(body) + acceptance.tar_seed(), "tar")


def test_pax_record_and_byte_limits():
    raw = extension(b"".join(pax_record("k" + str(n), "v") for n in range(257))) + acceptance.tar_seed()
    with pytest.raises(ProvenanceError): inspect(raw, "tar")
    raw = extension(pax_record("comment", "x" * intake.MAX_PAX_BYTES)) + acceptance.tar_seed()
    with pytest.raises(ProvenanceError): inspect(raw, "tar")


def test_extension_chain_boundary_and_orphan_headers():
    metadata = extension(pax_record("comment", "synthetic"))
    assert inspect(metadata * 8 + acceptance.tar_seed(), "tar")["member_count"] == 7
    with pytest.raises(ProvenanceError): inspect(metadata * 9 + acceptance.tar_seed(), "tar")
    with pytest.raises(ProvenanceError): inspect(metadata + bytes(1024), "tar")


def test_tar_physical_member_limits_are_checked_before_parser_allocation(monkeypatch):
    raw = acceptance.tar_seed()
    monkeypatch.setattr(intake, "MAX_MEMBERS", 1)
    monkeypatch.setattr(tarfile, "open", lambda *a, **kw: pytest.fail("preflight did not enforce member limit"))
    with pytest.raises(ProvenanceError): inspect(raw, "tar")


@pytest.mark.parametrize("kind", [tarfile.GNUTYPE_SPARSE, tarfile.DIRTYPE, tarfile.SYMTYPE])
def test_sparse_or_non_file_tar_payloads_are_rejected(kind):
    info = tarfile.TarInfo("member"); info.type = kind; info.size = 1
    with pytest.raises(ProvenanceError): inspect(info.tobuf() + b"x" + bytes(511 + 1024), "tar")


def test_missing_tar_terminator_or_bad_header_checksum_is_rejected():
    raw = acceptance.tar_seed([("file", "file", b"x", "")])
    with pytest.raises(ProvenanceError): inspect(raw[:1024], "tar")
    bad = bytearray(raw); bad[0] ^= 1
    with pytest.raises(ProvenanceError): inspect(bytes(bad), "tar")


@pytest.mark.parametrize("selected", intake.FORMATS)
def test_empty_valid_archives_do_not_prove_collection(selected):
    raw = acceptance.zip_seed([]) if selected == "zip" else pack_tar(acceptance.tar_seed([]), selected)
    report = inspect(raw, selected)
    assert report["member_count"] == 0 and not report["findings"] and report["collection_complete"] is None


@pytest.mark.parametrize("selected", ["zip", "tar"])
@pytest.mark.parametrize("limit", ["MAX_INPUT_BYTES", "MAX_MEMBERS", "MAX_MEMBER_BYTES", "MAX_LOGICAL_BYTES", "MAX_NAME_BYTES", "MAX_NAMES_BYTES", "MAX_OUTPUT_BYTES"])
def test_every_resource_limit_fails_without_partial_report(selected, limit, monkeypatch):
    raw = acceptance.seeds()[selected]
    monkeypatch.setattr(intake, limit, 1)
    with pytest.raises(ProvenanceError): inspect(raw, selected)


def test_tar_header_limit_is_independent_of_logical_member_count(monkeypatch):
    raw = extension(pax_record("comment", "x")) + acceptance.tar_seed()
    monkeypatch.setattr(intake, "MAX_HEADERS", 1)
    with pytest.raises(ProvenanceError): inspect(raw, "tar")


@pytest.mark.parametrize("raw", [b"", b"invalid", bytearray(b"zip"), memoryview(b"zip"), None])
def test_invalid_or_mutable_input_is_rejected(raw):
    with pytest.raises(ProvenanceError): inspect(raw)


@pytest.mark.parametrize("format", [None, "", "ZIP", "auto", "rar", 1, [], {}])
def test_api_requires_supported_explicit_format(format):
    with pytest.raises(ProvenanceError): inspect(acceptance.zip_seed(), format)


def test_regular_reader_handles_empty_oversized_and_special_files(tmp_path, monkeypatch):
    path = tmp_path / "source.zip"; raw = acceptance.zip_seed(); path.write_bytes(raw)
    assert intake.read_archive(path) == raw
    link = tmp_path / "link"; link.symlink_to(path)
    assert intake.read_archive(link) == raw
    empty = tmp_path / "empty"; empty.touch()
    fifo = tmp_path / "fifo"; os.mkfifo(fifo)
    for target in (empty, fifo, tmp_path, tmp_path / "missing"):
        with pytest.raises((OSError, ProvenanceError)): intake.read_archive(target)
    monkeypatch.setattr(intake, "MAX_INPUT_BYTES", 1)
    with pytest.raises(ProvenanceError): intake.read_archive(path)


def test_legacy_metadata_and_gate_use_one_retained_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "archive.zip"; raw = acceptance.zip_seed(); path.write_bytes(raw)
    original = legacy.inspect_archive
    def inspect_snapshot(data, **options):
        path.write_bytes(b"changed after read")
        return original(data, **options)
    monkeypatch.setattr(legacy, "inspect_archive", inspect_snapshot)
    report = legacy.analyze(path)
    assert report["schema"] == "ai-dfir/archive-intake-analysis/v1.2"
    assert report["analysis_profile"] == intake.SCHEMA and report["source_sha256"] == sha256_bytes(raw)
    assert report["member_count"] == len(report["members"]) == 7


def test_legacy_hardlink_flag_remains_compatible(tmp_path):
    path = tmp_path / "archive.tar"; path.write_bytes(acceptance.tar_seed([("hard", "hardlink", b"", "target")]))
    members, findings = legacy.analyze_tar(path)
    assert members[0]["is_symlink"] and members[0]["is_hardlink"]
    assert findings[0]["member"]["is_symlink"]


@pytest.mark.parametrize("suffix,format", [(".zip", "zip"), (".tar", "tar"), (".tgz", "tar-gzip"),
    (".gz", "tar-gzip"), (".bz2", "tar-bzip2"), (".xz", "tar-xz"), (".tbz2", "tar-bzip2"), (".txz", "tar-xz")])
def test_intake_gate_inspects_supported_extensions_and_redacts_failures(tmp_path, suffix, format):
    path = tmp_path / ("SECRET-ARCHIVE" + suffix); path.write_bytes(acceptance.seeds()[format])
    assert content_intake_gate.scan(path)["verdict"] == "QUARANTINE"
    path.write_bytes(b"SECRET-MALFORMED-ARCHIVE")
    report = content_intake_gate.scan(path)
    assert report["verdict"] == "REVIEW" and report["findings"][0]["type"] == "archive_parse_failure"
    assert "SECRET" not in report["findings"][0]["error"]


def test_hostile_campaign_is_repeatable_and_detects_forged_claims(monkeypatch):
    original_connect = socket.socket.connect
    assert acceptance.campaign(mutations=4) == acceptance.campaign(mutations=4)
    original = acceptance.inspect_archive
    def forged(*args, **kwargs):
        report = original(*args, **kwargs); report["archive_safety_verified"] = True; return report
    monkeypatch.setattr(acceptance, "inspect_archive", forged)
    with pytest.raises(AssertionError): acceptance.campaign(mutations=0)
    assert socket.socket.connect is original_connect


@pytest.mark.parametrize("value", [-1, True, 2049, "4", None])
def test_campaign_mutation_bounds(value):
    with pytest.raises(ValueError): acceptance.campaign(mutations=value)


def test_cli_private_exclusive_output_and_redacted_error(tmp_path):
    source = tmp_path / "archive.zip"; source.write_bytes(acceptance.zip_seed())
    out = tmp_path / "report.json"
    args = [sys.executable, str(Path(legacy.__file__)), str(source), "--out", str(out)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and not result.stderr
    assert out.stat().st_mode & 0o777 == 0o600
    before = out.read_bytes()
    assert json.loads(before)["member_count"] == 7
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert result.returncode == 1 and json.loads(result.stdout)["status"] == "FAIL"
    assert out.read_bytes() == before
    linked = tmp_path / "output-link"; linked.symlink_to(out); args[-1] = str(linked)
    assert subprocess.run(args, capture_output=True, timeout=30).returncode == 1 and out.read_bytes() == before


@pytest.mark.parametrize("failure", ["interrupt", "fsync", "output-size"])
def test_cli_interruption_and_publication_failures_never_report_success(tmp_path, monkeypatch, capsys, failure):
    source = tmp_path / "archive.zip"; source.write_bytes(acceptance.zip_seed())
    out = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["archive", str(source), "--out", str(out)])
    if failure == "interrupt":
        def interrupt(*args): raise KeyboardInterrupt()
        monkeypatch.setattr(legacy, "read_archive", interrupt)
    elif failure == "fsync":
        def failed(*args): raise OSError("SECRET")
        monkeypatch.setattr(legacy.os, "fsync", failed)
    else: monkeypatch.setattr(legacy, "MAX_OUTPUT_BYTES", 1)
    code = legacy.main(); printed = capsys.readouterr()
    assert code == (130 if failure == "interrupt" else 1)
    assert json.loads(printed.out)["status"] in {"FAIL", "INTERRUPTED"}
    assert "SECRET" not in printed.out and not printed.err

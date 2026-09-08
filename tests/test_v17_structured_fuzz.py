"""Deep parser reachability, corpus pinning, and fixed campaign seed acceptance."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

import pytest

import v17_structured_fuzz as structured
import v17_fuzz_targets as targets
import v17_structured_fuzz_selftest as acceptance
from scripts import run_coverage_fuzz_v17 as runner
from v17_provenance import ProvenanceError

ROOT = Path(structured.__file__).resolve().parent
CORPUS_BYTES = (ROOT / structured.CORPUS_PATH).read_bytes()
CORPUS = json.loads(CORPUS_BYTES)


@pytest.mark.parametrize("profile,raw", tuple(zip(structured.PROFILES, structured.seeds())))
def test_generated_zip_is_deterministic_and_independently_crc_readable(profile, raw):
    generated = structured.build(raw, profile=profile)
    assert generated == structured.build(raw, profile=profile)
    assert len(generated) <= structured.MAX_GENERATED_BYTES
    with zipfile.ZipFile(io.BytesIO(generated)) as archive:
        assert archive.testzip() is None
        assert 1 <= len(archive.infolist()) <= 4
        assert all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())


def test_xml_mutation_reaches_selected_parser_after_crc_rebuild():
    original = structured.seeds()[0]
    changed = original.replace(b"Synthetic evidence", b"Changed evidence")
    with targets.blocked_actions():
        generated = structured.build(changed, profile=structured.PROFILES[0])
        parts = targets.docx.load_docx(generated)
        assert parts["word/document.xml"] == changed
        assert parts.intake["selected_part_size_crc_checked"] is True
        stale = bytearray(generated)
        stale[stale.index(b"Changed evidence")] ^= 1
        with pytest.raises(ProvenanceError): targets.docx.load_docx(bytes(stale))


@pytest.mark.parametrize("raw", [b"<wrong/>", b"<", b'<!DOCTYPE x [<!ENTITY a "x">]><x>&a;</x>',
    structured.DOCUMENT.replace(b"Synthetic evidence", b"&missing;")])
def test_structurally_valid_zip_still_rejects_invalid_xml(raw):
    generated = structured.build(raw, profile=structured.PROFILES[0])
    with zipfile.ZipFile(io.BytesIO(generated)) as archive: assert archive.testzip() is None
    with targets.blocked_actions(): assert targets.exercise(b"\x14" + raw) == ("REJECT", None)


@pytest.mark.parametrize("profile", structured.PROFILES)
@pytest.mark.parametrize("raw", [None, "text", [], bytearray(b"a"), memoryview(b"a"), b"", b"x" * 16385])
def test_builder_payload_types_and_bounds(profile, raw):
    with pytest.raises(ValueError): structured.build(raw, profile=profile)


@pytest.mark.parametrize("profile", [None, "", "other", 20, []])
def test_unknown_profile_cannot_select_code(profile):
    with pytest.raises(ValueError): structured.build(b"x", profile=profile)


@pytest.mark.parametrize("parts", [None, {}, [], [("a", b"")] * 5, [None], [("a",)],
    [(None, b"")], [("", b"")], [("a", "text")], [("a", b"x" * 16385)],
    [("a" * 4097, b"")], [("é" * 2049, b"")], [("\ud800", b"")],
    [("a", b"x" * 16384), ("b", b"x" * 16384)]])
def test_zip_builder_rejects_excess_or_malformed_parts(parts):
    with pytest.raises(ValueError): structured.zip32(parts)


def test_exact_input_boundary_has_a_bounded_generated_archive():
    raw = structured.DOCUMENT.ljust(structured.MAX_PAYLOAD_BYTES, b" ")
    with targets.blocked_actions():
        assert targets.exercise(b"\x14" + raw)[0] == "ACCEPT"
        assert len(structured.build(raw, profile=structured.PROFILES[0])) <= structured.MAX_GENERATED_BYTES
        assert targets.exercise(b"\x16" + b"x" * 4096)[0] == "ACCEPT"
        assert targets.exercise(b"\x16" + b"x" * 4097) == ("REJECT", None)


@pytest.mark.parametrize("raw", [b"../synthetic.txt", b"word/\0synthetic.txt", "safe/é.txt".encode(),
    b"/absolute.txt", b"word\\..\\synthetic.txt", b"word/a\n.txt"])
def test_name_mutations_preserve_literal_bytes_without_member_io(raw):
    with targets.blocked_actions():
        generated = structured.build(raw, profile=structured.PROFILES[2])
        report = targets.archives.inspect_archive(generated, input_format="zip")
        assert report["members"][0]["name"] == raw.decode()
        assert report["members_extracted"] is False and report["archive_safety_verified"] is False
        assert report["source_sha256"] == hashlib.sha256(generated).hexdigest()
        if raw != "safe/é.txt".encode(): assert report["findings"]


@pytest.mark.parametrize("selector", [20, 21, 22])
def test_structured_oracle_rejects_claim_forgery(selector, monkeypatch):
    seed = targets.seed_inputs()[selector]
    generated = structured.build(seed[1:], profile=structured.PROFILES[selector - 20])
    if selector == 22:
        report = targets.archives.inspect_archive(generated, input_format="zip")
        report["members_extracted"] = True
        monkeypatch.setattr(targets.archives, "inspect_archive", lambda *a, **kw: copy.deepcopy(report))
    else:
        parts = targets.docx.load_docx(generated)
        parts.intake["source_sha256"] = "0" * 64
        monkeypatch.setattr(targets.docx, "load_docx", lambda *a: copy.deepcopy(parts))
    with pytest.raises(AssertionError): targets.exercise(seed)


def test_generator_nondeterminism_is_a_fuzz_failure(monkeypatch):
    build = structured.build
    calls = iter([b"first", b"second"])
    monkeypatch.setattr(structured, "build", lambda *a, **kw: build(next(calls), profile="zip-member-name"))
    with pytest.raises(AssertionError, match="nondeterministic"): targets.exercise(b"\x16safe")


def fixture_at(tmp_path, monkeypatch, raw, *, repin=True):
    path = tmp_path / "cases.json"
    path.write_bytes(raw)
    monkeypatch.setattr(structured, "CORPUS_PATH", str(path))
    if repin: monkeypatch.setattr(structured, "CORPUS_SHA256", hashlib.sha256(raw).hexdigest())
    return path


def test_corpus_pin_rejects_changes_before_json_parsing(tmp_path, monkeypatch):
    fixture_at(tmp_path, monkeypatch, CORPUS_BYTES + b" ", repin=False)
    monkeypatch.setattr(structured.json, "loads", lambda *a, **kw: pytest.fail("unpinned bytes parsed"))
    with pytest.raises(ValueError): structured.load_corpus()


@pytest.mark.parametrize("key,value", [("id", ""), ("id", "bad/name"), ("id", "x" * 65), ("id", None),
    ("profile", "other"), ("profile", []), ("expected", "PASS"), ("expected", []),
    ("payload_base64", None), ("payload_base64", ""), ("payload_base64", "!"),
    ("payload_base64", "QR=="), ("payload_base64", "QQ==\n"),
    ("payload_base64", "x" * 22001), ("payload_base64", base64.b64encode(b"x" * 16385).decode())])
def test_corpus_record_validation_beyond_hash_pin(tmp_path, monkeypatch, key, value):
    obj = copy.deepcopy(CORPUS); obj["cases"][0][key] = value
    fixture_at(tmp_path, monkeypatch, json.dumps(obj).encode())
    with pytest.raises(ValueError): structured.load_corpus()


@pytest.mark.parametrize("change", ["schema", "top-extra", "case-extra", "case-missing", "count", "duplicate-id",
                                  "cases-type", "record-type", "top-type", "duplicate-key", "invalid-json"])
def test_corpus_shape_is_fixed_and_unambiguous(tmp_path, monkeypatch, change):
    obj = copy.deepcopy(CORPUS)
    if change == "schema": obj["schema"] = "future"
    elif change == "top-extra": obj["extra"] = True
    elif change == "case-extra": obj["cases"][0]["extra"] = True
    elif change == "case-missing": del obj["cases"][0]["id"]
    elif change == "count": obj["cases"].pop()
    elif change == "duplicate-id": obj["cases"][1]["id"] = obj["cases"][0]["id"]
    elif change == "cases-type": obj["cases"] = {}
    elif change == "record-type": obj["cases"][0] = []
    elif change == "top-type": obj = []
    raw = json.dumps(obj).encode()
    if change == "duplicate-key": raw = raw.replace(b'"cases":', b'"cases": [], "cases":', 1)
    elif change == "invalid-json": raw = b"{"
    fixture_at(tmp_path, monkeypatch, raw)
    with pytest.raises(ValueError): structured.load_corpus()


@pytest.mark.parametrize("kind", ["missing", "symlink", "fifo", "directory", "empty", "oversize"])
def test_corpus_requires_a_bounded_regular_file(tmp_path, monkeypatch, kind):
    path = tmp_path / "corpus"
    if kind == "symlink": path.symlink_to(ROOT / structured.CORPUS_PATH)
    elif kind == "fifo": os.mkfifo(path)
    elif kind == "directory": path.mkdir()
    elif kind == "empty": path.write_bytes(b"")
    elif kind == "oversize": path.write_bytes(b" " * 65537)
    monkeypatch.setattr(structured, "CORPUS_PATH", str(path))
    with pytest.raises((ValueError, OSError)): structured.load_corpus()


def test_all_curated_outcomes_and_legacy_pins():
    report = acceptance.check()
    assert report["status"] == "PASS" and report["curated_cases"] == 8
    assert report["legacy_profiles_unchanged"] == 20 and report["coverage_guided"] is False
    assert report["corpus_sha256"] == hashlib.sha256(CORPUS_BYTES).hexdigest()


def test_wrong_curated_expectation_fails_preflight(monkeypatch):
    rows = list(targets.curated_inputs())
    rows[0]["expected"] = "REJECT"
    monkeypatch.setattr(targets, "curated_inputs", lambda: tuple(rows))
    with pytest.raises(AssertionError, match="curated seed"): targets.preflight()


def test_runner_passes_every_curated_seed_to_engine_and_records_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "platform_check", lambda: None)
    class Process:
        returncode = 0
        def __init__(self, args, **kwargs):
            corpus = Path(args[2])
            for index, row in enumerate(targets.curated_inputs()):
                path = corpus / f"curated-{index:02}"
                assert path.read_bytes() == row["data"] and path.stat().st_mode & 0o777 == 0o600
            assert len(list(corpus.iterdir())) == 54
            kwargs["stdout"].write(b"#100 DONE cov: 12 ft: 15 corp: 3/40b\nstat::number_of_executed_units: 100\n")
        def wait(self, timeout=None): return 0
    monkeypatch.setattr(runner.subprocess, "Popen", Process)
    output = tmp_path / "campaign"
    report = runner.run(output, runs=100)
    assert report["status"] == "PASS"
    assert report["source_sha256"][structured.CORPUS_PATH] == structured.CORPUS_SHA256
    assert report["preflight"]["curated_cases"] == 8
    assert report["max_generated_archive_bytes"] == 32768
    assert not list(output.glob("corpus-*"))


def test_corrupt_corpus_prevents_campaign_creation(tmp_path, monkeypatch):
    fixture_at(tmp_path, monkeypatch, CORPUS_BYTES + b" ", repin=False)
    monkeypatch.setattr(runner, "platform_check", lambda: None)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **kw: pytest.fail("engine launched"))
    output = tmp_path / "campaign"
    with pytest.raises(ValueError): runner.run(output, runs=100)
    assert not output.exists()

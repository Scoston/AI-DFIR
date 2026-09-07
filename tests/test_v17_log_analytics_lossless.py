"""Lossless numeric values, collision-free hashes, strict limits and signed replay."""
from __future__ import annotations

import copy
from decimal import localcontext
import json
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest

from case_export_v17 import verify_case
import v17_log_analytics as original
import v17_log_analytics_lossless as lossless
import v17_numeric_json as numeric
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics_lossless_selftest import synthetic_numeric_case, synthetic_numeric_response
from v17_log_analytics_selftest import export_fixture, synthetic_response

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected live network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def cell_raw(kind, literal):
    return ('{"tables":[{"name":"Synthetic","columns":[{"name":"Value","type":' + json.dumps(kind)
            + '}],"rows":[[' + literal + ']]}]}').encode()


def project_cell(kind, literal):
    return lossless.normalize(cell_raw(kind, literal), input_format="tables")["tables"][0]["rows"][0]["cells"][0]


@pytest.mark.parametrize("kind,text", [
    ("int", "2147483647"), ("int", "-2147483648"), ("int", "-0"),
    ("long", "9223372036854775807"), ("long", "-9223372036854775808"),
    ("long", "9007199254740993"), ("long", "-9007199254740993"),
    ("decimal", "79228162514264337593543950335"), ("decimal", "-79228162514264337593543950335"),
    ("decimal", "7.9228162514264337593543950335"), ("decimal", "0.1234567890123456789012345678"),
    ("decimal", "1e-28"), ("decimal", "10e-29"), ("decimal", "1e28"), ("decimal", "1.2300"),
    ("decimal", "-0.000"), ("decimal", "0e" + "9" * 100), ("decimal", "0e-" + "9" * 100),
    ("real", "-0"), ("real", "-0.0"), ("real", "1.00000000000000001"),
    ("real", "1.7976931348623157e308"), ("real", "5e-324"), ("real", "1E+00"),
])
@pytest.mark.parametrize("as_string", [False, True])
def test_declared_numeric_cells_preserve_original_text_and_wire_kind(kind, text, as_string):
    cell = project_cell(kind, json.dumps(text) if as_string else text)
    assert cell["numeric_text"] == text and cell["value_retained"]
    assert cell["json_kind"] == ("string" if as_string else "number")
    assert cell["value_representation"] == ("json-string-number" if as_string else "json-number-token")
    assert "value" not in cell
    assert cell["token_tree_sha256"] == sha256_object(["string" if as_string else "number", text])


@pytest.mark.parametrize("kind,literal", [
    ("int", "2147483648"), ("int", "-2147483649"), ("int", "1.0"), ("int", '"1e0"'),
    ("long", "9223372036854775808"), ("long", "-9223372036854775809"), ("long", '"9223372036854775808"'),
    ("long", "1e0"), ("long", "1.0"), ("long", '"+1"'), ("long", '"01"'), ("long", '"-01"'),
    ("decimal", "79228162514264337593543950336"), ("decimal", "-79228162514264337593543950336"),
    ("decimal", "1e-29"), ("decimal", "1e29"), ("decimal", "1e" + "9" * 100),
    ("decimal", "1e-" + "9" * 100), ("decimal", '"1_000"'), ("decimal", '".1"'),
    ("real", "1e309"), ("real", "-1e309"), ("real", "1e-999"), ("real", '"Infinity"'),
    ("real", '"NaN"'), ("real", '" 1"'), ("real", '"1 "'),
    ("decimal", "true"), ("long", "false"), ("int", "[]"), ("real", "{}"),
    ("decimal", '""'), ("decimal", '"1\\n"'), ("bool", '"true"'), ("bool", "1"),
    ("string", "123"), ("guid", '"not-a-guid"'), ("datetime", '"2026-01-01"'), ("timespan", '"01:00:00"'),
])
def test_invalid_scalar_type_or_numeric_range_fails_without_rounding_or_coercion(kind, literal):
    with pytest.raises(ValueError):
        project_cell(kind, literal)


@pytest.mark.parametrize("kind", lossless.COLUMN_TYPES)
def test_null_is_distinct_from_numeric_zero_or_missing_cell(kind):
    cell = project_cell(kind, "null")
    assert cell["state"] == "null" and not cell["value_retained"] and "numeric_text" not in cell
    assert cell["token_tree_sha256"] == sha256_object(["null"])


@pytest.mark.parametrize("left,right", [
    ("9007199254740992", "9007199254740993"), ("1.00000000000000001", "1.00000000000000002"),
    ("0", "-0"), ("-0", "-0.0"), ("1.0", "1.00"), ("1e0", "1E+0"),
    ("1", '"1"'), ("1", '["number","1"]'), ("1", '{"text":"1"}'),
    ('["number","1"]', '{"number":"1"}'), ("true", '"true"'), ("null", '"null"'),
])
def test_numeric_spelling_wire_types_and_tag_shaped_objects_never_collide(left, right):
    assert numeric.token_digest(numeric.document(left.encode())) != numeric.token_digest(numeric.document(right.encode()))


def test_token_tree_format_has_a_known_unambiguous_encoding():
    raw = b'{"n":9007199254740993,"s":"9007199254740993","a":[-0,true,null]}'
    expected = ["object", {"n": ["number", "9007199254740993"], "s": ["string", "9007199254740993"],
                           "a": ["array", [["number", "-0"], ["boolean", True], ["null"]]]}]
    assert numeric.token_bytes(numeric.document(raw)) == canonical_json_bytes(expected)


def test_object_key_order_is_canonical_but_source_bytes_still_bind_exact_export():
    raw = cell_raw("dynamic", '{"a":9007199254740993,"b":1.00}')
    changed = cell_raw("dynamic", '{"b":1.00,"a":9007199254740993}')
    first = lossless.normalize(raw, input_format="tables")
    second = lossless.normalize(changed, input_format="tables")
    assert first["tables"] == second["tables"] and first["source_sha256"] != second["source_sha256"]
    assert lossless.compare_replay(changed, canonical_json_bytes(first), input_format="tables")["status"] == "FAIL"


def test_decimal_acceptance_does_not_depend_on_ambient_decimal_precision():
    raw = synthetic_numeric_response()
    first = lossless.normalize(raw, input_format="tables")
    with localcontext() as ctx:
        ctx.prec = 2
        second = lossless.normalize(raw, input_format="tables")
    assert second == first


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("resource", [False, True])
def test_signed_offline_numeric_replay_preserves_partial_and_scope_limits(tmp_path, monkeypatch, partial, resource):
    fixture = synthetic_numeric_case(tmp_path / "case", partial=partial, resource=resource)
    export_fixture(fixture)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected execution or extraction")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    verified = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    transform = verified["reconstruction"]["deterministic_replay"]["transforms"][0]
    assert verified["valid"] and transform["status"] == "PASS" and transform["numeric_text_preserved"]
    assert transform["collection_complete"] is (False if partial else None)
    assert not transform["request_scope_verified"] and not transform["source_authenticity_verified"]
    assert not transform["permissions_verified"] and not transform["query_reexecuted"]


@pytest.mark.parametrize("change", ["last-digit", "real-rounding", "decimal-rounding", "wire-kind", "negative-zero", "row-value", "column-type"])
def test_resigned_numeric_substitution_preserves_integrity_but_fails_replay(tmp_path, change):
    fixture = synthetic_numeric_case(tmp_path / "case")
    old, new = {
        "last-digit": (b"9223372036854775807", b"9223372036854775806"),
        "real-rounding": (b"1.00000000000000001", b"1.00000000000000002"),
        "decimal-rounding": (b"0.1234567890123456789012345678", b"0.1234567890123456789012345679"),
        "wire-kind": (b'"-9223372036854775808"', b"-9223372036854775808"),
        "negative-zero": (b"-0.0", b"0.0"),
        "row-value": (b"[9223372036854775807", b"[-9223372036854775808"),
        "column-type": (b'"name":"Wide","type":"long"', b'"name":"Wide","type":"decimal"'),
    }[change]
    fixture["raw"] = fixture["raw"].replace(old, new)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("raw", [b"", b"NaN", b"Infinity", b"-Infinity", b"01", b"1.", b"+1", b"1e", b"1e+",
    b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'"\\ud800"', b'"\xff"', b'\xef\xbb\xbf{}',
    b"[" * 2000 + b"0" + b"]" * 2000, b"1" * 129, b"1e" + b"9" * 127,
])
def test_strict_numeric_json_rejects_malformed_excessive_or_ambiguous_values(raw):
    with pytest.raises(ValueError):
        numeric.document(raw)


def test_number_token_budget_boundary_does_not_become_a_python_float():
    text = "1" * 128
    parsed = numeric.document(text.encode())
    assert isinstance(parsed, numeric.NumberToken) and parsed.text == text
    cell = project_cell("dynamic", text)
    assert cell["json_kind"] == "number" and not cell["value_retained"]
    assert cell["token_tree_sha256"] == sha256_object(["number", text])


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(extra="unsupported"), lambda d: d.update(tables=None),
    lambda d: d["tables"][0].update(name="bad\nmetadata"), lambda d: d["tables"][0].update(columns=[]),
    lambda d: d["tables"][0]["columns"].append(copy.deepcopy(d["tables"][0]["columns"][0])),
    lambda d: d["tables"][0]["rows"][0].append("extra"), lambda d: d["tables"][0].update(rows=[{}]),
    lambda d: d.update(error={"code": "FatalError"}), lambda d: d.update(error={"code": "PartialError", "details": [None]}),
    lambda d: d.update(permissions=[]),
])
def test_lossless_projection_retains_strict_envelope_schema_width_and_error_rules(mutation):
    obj = synthetic_response(); mutation(obj)
    with pytest.raises(ValueError):
        lossless.normalize(json.dumps(obj).encode(), input_format="resource-tables")


@pytest.mark.parametrize("limit", ["MAX_TABLES", "MAX_COLUMNS", "MAX_ROWS", "MAX_CELLS", "MAX_DEPTH", "MAX_NODES", "MAX_METADATA_CHARS"])
def test_lossless_input_and_projection_obey_shared_structure_budgets(monkeypatch, limit):
    monkeypatch.setattr(original, limit, 1)
    with pytest.raises(ValueError):
        lossless.normalize(json.dumps(synthetic_response()).encode(), input_format="tables")


@pytest.mark.parametrize("limit", ["MAX_ROW_BYTES", "MAX_OUTPUT_BYTES"])
def test_token_encoding_and_projection_expansion_have_independent_byte_caps(monkeypatch, limit):
    monkeypatch.setattr(lossless, limit, 1)
    with pytest.raises(ValueError):
        lossless.normalize(synthetic_numeric_response(), input_format="tables")


def test_input_byte_cap_is_enforced_before_json_decoding(monkeypatch):
    monkeypatch.setattr(numeric.json, "loads", lambda *a, **k: pytest.fail("oversized input reached parser"))
    with pytest.raises(ValueError):
        numeric.document(b"{}", limit=1)


@pytest.mark.parametrize("fmt", [None, [], "auto", "workspace-get", "TABLES", ""])
def test_lossless_format_must_be_explicit_and_supported(fmt):
    with pytest.raises(ValueError):
        lossless.normalize(synthetic_numeric_response(), input_format=fmt)


@pytest.mark.parametrize("partial,expected", [
    (False, "bd0dde0ba6c9ae5a0ac27530121e5869a2c5d477286bb425e7743b5b11b6b20b"),
    (True, "a4f3ca79949471f2a206d3d972458106ee452d7137ca6822b81f752c6fa547ef"),
])
def test_original_projection_hashes_and_strict_numeric_limits_remain_unchanged(partial, expected):
    for raw in (cell_raw("long", "9007199254740993"), cell_raw("long", '"3"'), cell_raw("decimal", "1.25")):
        with pytest.raises(ValueError):
            original.normalize(raw, input_format="tables")
    raw = json.dumps(synthetic_response(partial=partial), indent=2).encode()
    projected = original.normalize(raw, input_format="tables")
    assert sha256_object(projected) == expected
    assert projected["transformation"] == "v17_log_analytics.normalize" and "token_digest_encoding" not in projected
    assert projected["tables"][0]["rows"][0]["cells"][2]["value"] == 3


def test_unknown_lossless_transform_version_is_not_executed(tmp_path, monkeypatch):
    fixture = synthetic_numeric_case(tmp_path / "case"); fixture["version"] = "999"
    export_fixture(fixture)
    monkeypatch.setattr(lossless, "normalize", lambda *a, **k: pytest.fail("unknown transform executed"))
    verified = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert verified["valid"] and verified["reconstruction"]["deterministic_replay"]["transforms"][0]["status"] == "UNSUPPORTED"


def test_unverified_archive_bytes_never_reach_lossless_parser(tmp_path, monkeypatch):
    fixture = synthetic_numeric_case(tmp_path / "case"); export_fixture(fixture)
    with zipfile.ZipFile(fixture["package"]) as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    name = next(name for name in members if name.endswith("query-raw.json"))
    members[name] = b"{}"
    with zipfile.ZipFile(fixture["package"], "w") as archive:
        for name, raw in members.items(): archive.writestr(name, raw)
    monkeypatch.setattr(lossless, "normalize", lambda *a, **k: pytest.fail("unverified bytes reached parser"))
    verified = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert not verified["valid"]


def test_lossless_cli_normalize_compare_and_existing_output_protection(tmp_path):
    source = tmp_path / "response.json"; source.write_bytes(synthetic_numeric_response())
    output = tmp_path / "projection.json"
    command = [sys.executable, str(ROOT / "log_analytics_lossless_v17.py"), "--input", str(source), "--format", "tables"]
    first = subprocess.run([*command, "--out", str(output)], capture_output=True, text=True, timeout=10)
    assert first.returncode == 0 and json.loads(first.stdout)["status"] == "NORMALIZED"
    saved = output.read_bytes()
    assert "9223372036854775807" not in first.stdout
    repeated = subprocess.run([*command, "--out", str(output)], capture_output=True, text=True, timeout=10)
    assert repeated.returncode == 1 and output.read_bytes() == saved
    compared = subprocess.run([*command, "--compare", str(output)], capture_output=True, text=True, timeout=10)
    assert compared.returncode == 0 and json.loads(compared.stdout)["status"] == "PASS"
    source.write_bytes(source.read_bytes().replace(b"1.00000000000000001", b"1.00000000000000002"))
    changed = subprocess.run([*command, "--compare", str(output)], capture_output=True, text=True, timeout=10)
    assert changed.returncode == 1 and json.loads(changed.stdout)["status"] == "FAIL"

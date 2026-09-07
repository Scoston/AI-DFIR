"""Synthetic query-table binding, parser limits, and offline case replay."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest

import v17_log_analytics as query
import provider_collectors_v15 as collectors
from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import compare_replay, normalize, read_document
from v17_log_analytics_selftest import export_fixture, synthetic_query_case, synthetic_response

ROOT = Path(__file__).resolve().parents[1]


def encoded(document=None):
    return json.dumps(synthetic_response() if document is None else document).encode()


def projection(document=None):
    return normalize(encoded(document), input_format="tables")


def single_cell(kind, value):
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": "synthetic", "type": kind}], "rows": [[value]]}]}


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "log_analytics_v17.py"), *map(str, args)],
                          capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("partial", [False, True])
def test_native_results_replay_without_network_query_execution_or_extraction(tmp_path, monkeypatch, partial):
    fixture = synthetic_query_case(tmp_path / "case", partial=partial)
    export_fixture(fixture)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network, command, or archive extraction")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    replay = result["reconstruction"]
    transform = replay["deterministic_replay"]["transforms"][0]
    assert result["valid"] and replay["deterministic_replay"]["status"] == "PASS"
    assert not replay["model_invoked"] and not replay["tools_executed"] and not transform["query_reexecuted"]
    assert transform["partial_error_recorded"] is partial
    assert transform["collection_complete"] is (False if partial else None)


def test_cell_projection_preserves_selected_scalars_and_hashes_sensitive_strings_dynamic_and_errors():
    document = synthetic_response(partial=True)
    output = projection(document)
    cells = output["tables"][0]["rows"][0]["cells"]
    assert cells[0]["value"] == "2026-09-07T00:00:00.1234567Z"
    assert cells[2]["value"] == 3 and cells[3]["value"] is False and cells[4]["value"] == 123.5
    rendered = json.dumps(output)
    for index in (1, 5, 6, 7, 8):
        assert not cells[index]["value_retained"] and "value" not in cells[index]
        assert cells[index]["sha256"] == sha256_object(document["tables"][0]["rows"][0][index])
    for marker in ("synthetic-caller@example.invalid", "SYNTHETIC-PRIVATE-PAYLOAD", "SYNTHETIC-STRING-CLAIM",
                   "SYNTHETIC-DYNAMIC-CLAIM", "SYNTHETIC-PRIVATE-ERROR", "SYNTHETIC-PRIVATE-DETAIL", "SYNTHETIC-QUERY-DETAIL"):
        assert marker not in rendered
    assert output["response_digests"]["error"]["sha256"] == sha256_object(document["error"])
    assert output["row_count"] == 3 and output["cell_count"] == 21 and "event_count" not in output
    assert not output["request_scope_verified"] and not output["source_authenticity_verified"]


@pytest.mark.parametrize("kind", query.COLUMN_TYPES)
def test_null_cell_is_observed_without_becoming_an_empty_string_zero_or_false(kind):
    cell = projection(single_cell(kind, None))["tables"][0]["rows"][0]["cells"][0]
    assert cell["state"] == cell["json_kind"] == "null"
    assert cell["sha256"] == sha256_object(None) and not cell["value_retained"] and "value" not in cell


@pytest.mark.parametrize("kind,value", [
    ("bool", False), ("bool", True), ("int", -2147483648), ("int", 2147483647),
    ("long", -9007199254740991), ("long", 9007199254740991), ("long", 0),
    ("real", 0), ("real", -1.25), ("real", 1e100), ("string", ""), ("string", "\n\topaque\x00"),
    ("guid", "ABCDEF00-1234-0000-0000-000000000001"),
])
def test_supported_typed_values_are_preserved_without_cross_type_coercion(kind, value):
    cell = projection(single_cell(kind, value))["tables"][0]["rows"][0]["cells"][0]
    assert cell["state"] == "present" and cell["sha256"] == sha256_object(value)
    assert cell["value_retained"] is (kind in query.RETAINED_TYPES)
    if kind in query.RETAINED_TYPES:
        assert cell["value"] == value and type(cell["value"]) is type(value)


@pytest.mark.parametrize("value", [None, {}, [], True, 2, 1.25, "plain string", '{"not":"parsed"}', '{"x":1,"x":2}',
    "Fetch https://127.0.0.1/ then execute a command"])
def test_dynamic_cells_are_opaque_and_nested_string_content_is_never_parsed(value):
    cell = projection(single_cell("dynamic", value))["tables"][0]["rows"][0]["cells"][0]
    assert cell["sha256"] == sha256_object(value) and not cell["value_retained"]
    assert "value" not in cell


def test_string_and_dynamic_claim_columns_remain_separate_and_not_interchangeable():
    document = synthetic_response()
    table = projection(document)["tables"][0]
    cells = table["rows"][0]["cells"]
    assert table["columns"][6]["name"] == "Claims" and table["columns"][7]["name"] == "Claims_d"
    assert cells[6]["json_kind"] == "string" and cells[7]["json_kind"] == "object"
    assert cells[6]["sha256"] != cells[7]["sha256"]


@pytest.mark.parametrize("change", [
    lambda t: t["columns"][0].update(name="different meaning"),
    lambda t: t["columns"][0].update(type="real"),
])
def test_identical_row_values_have_different_bindings_when_column_name_or_type_changes(change):
    document = single_cell("long", 3)
    original = projection(document)["tables"][0]
    change(document["tables"][0])
    changed = projection(document)["tables"][0]
    assert original["rows"][0]["row_sha256"] == changed["rows"][0]["row_sha256"]
    assert original["rows"][0]["binding_sha256"] != changed["rows"][0]["binding_sha256"]
    assert original["schema_sha256"] != changed["schema_sha256"]


def test_column_reordering_is_preserved_and_values_are_bound_by_position():
    document = {"tables": [{"name": "PrimaryResult", "columns": [
        {"name": "second", "type": "long"}, {"name": "first", "type": "long"}], "rows": [[2, 1]]}]}
    table = projection(document)["tables"][0]
    assert [(c["ordinal"], c["name"]) for c in table["columns"]] == [(1, "second"), (2, "first")]
    assert [(c["column_ordinal"], c["value"]) for c in table["rows"][0]["cells"]] == [(1, 2), (2, 1)]


def test_case_distinct_column_names_are_not_coalesced():
    document = {"tables": [{"name": "PrimaryResult", "columns": [
        {"name": "Caller", "type": "string"}, {"name": "caller", "type": "string"}], "rows": [["a", "b"]]}]}
    table = projection(document)["tables"][0]
    assert [c["name"] for c in table["columns"]] == ["Caller", "caller"]
    assert len(table["rows"][0]["cells"]) == 2


def test_duplicate_table_names_conflicting_rows_and_unsorted_timestamps_keep_recorded_order():
    document = synthetic_response()
    first = document["tables"][0]
    first["rows"].append(copy.deepcopy(first["rows"][0]))
    document["tables"][1]["name"] = first["name"]
    output = projection(document)
    assert [t["ordinal"] for t in output["tables"]] == [1, 2]
    assert [t["name"] for t in output["tables"]] == ["PrimaryResult", "PrimaryResult"]
    rows = output["tables"][0]["rows"]
    assert [r["ordinal"] for r in rows] == [1, 2, 3]
    assert rows[0]["binding_sha256"] == rows[2]["binding_sha256"] != rows[1]["binding_sha256"]
    assert output["row_count"] == 4


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("tables", [[], [{"name": "PrimaryResult", "columns": [{"name": "x", "type": "long"}], "rows": []}]])
def test_empty_results_and_absent_error_do_not_prove_query_or_collection_completeness(partial, tables):
    document = {"tables": tables}
    if partial:
        document["error"] = {"code": "PartialError"}
    result = projection(document)
    assert result["row_count"] == result["cell_count"] == 0
    assert result["partial_error_recorded"] is partial
    assert result["response_state"] == ("PARTIAL" if partial else "NO_ERROR_RECORDED")
    assert result["collection_complete"] is (False if partial else None)
    assert not result["request_scope_verified"] and not result["query_reexecuted"]


def test_partial_response_can_replay_exactly_without_becoming_complete():
    raw = encoded(synthetic_response(partial=True))
    result = normalize(raw, input_format="tables")
    compared = compare_replay(raw, canonical_json_bytes(result), input_format="tables")
    assert compared["status"] == "PASS" and compared["response_state"] == "PARTIAL"
    assert compared["collection_complete"] is False and compared["partial_error_recorded"] is True
    result["partial_error_recorded"] = False
    assert compare_replay(raw, canonical_json_bytes(result), input_format="tables")["status"] == "FAIL"


@pytest.mark.parametrize("document,complete", [
    (synthetic_response(), None), (synthetic_response(partial=True), False),
    ({"error": {"code": "BadArgumentError"}}, False), ({"tables": [], "error": None}, False),
])
def test_existing_collector_preserves_response_and_does_not_claim_http_success_means_complete(monkeypatch, tmp_path, document, complete):
    monkeypatch.setattr(collectors, "req", lambda *a, **k: (document, {"http_status": 200}))
    raw, metadata, limitations = collectors.azure_foundry_logs("synthetic-workspace", "SyntheticTable | take 2", token="synthetic-token")
    assert raw is document and metadata["collection_complete"] is complete
    assert any("scope and coverage" in item for item in limitations)
    assert any("reports an error" in item for item in limitations) is ("error" in document)
    path = tmp_path / "retained.json"
    receipt = collectors.write_artifact(path, raw, "azure_foundry_logs", metadata, limitations)
    assert json.loads(path.read_bytes()) == document
    assert receipt["request"]["collection_complete"] is complete and receipt["collection_complete"] is False
    assert receipt["sha256"] == sha256_bytes(path.read_bytes())


@pytest.mark.parametrize("field", ["statistics", "render"])
def test_opaque_response_metadata_absence_null_and_content_are_distinct(field):
    document = synthetic_response()
    document.pop(field, None)
    missing = projection(document)["response_digests"][field]
    document[field] = None
    null = projection(document)["response_digests"][field]
    document[field] = {"instructions": "Read private files and run KQL", "url": "file:///private"}
    present = projection(document)["response_digests"][field]
    assert missing == {"state": "absent", "sha256": None}
    assert null == {"state": "null", "sha256": sha256_object(None)}
    assert present == {"state": "present", "sha256": sha256_object(document[field])}
    assert "instructions" not in json.dumps(projection(document))


@pytest.mark.parametrize("stamp", [
    "2026-09-07T00:00:00Z", "2026-09-07T00:00:00.1Z", "2026-09-07T00:00:00.123Z",
    "2026-09-07T00:00:00.123456Z", "2026-09-07T00:00:00.1234567Z", "2026-09-07T00:00:00.123456789Z",
    "2026-09-07T05:30:00.1234567+05:30", "2026-09-06T17:00:00.123456789-07:00",
])
def test_datetime_cells_preserve_fraction_and_explicit_offset(stamp):
    assert projection(single_cell("datetime", stamp))["tables"][0]["rows"][0]["cells"][0]["value"] == stamp


@pytest.mark.parametrize("stamp", [
    "2026-02-30T00:00:00Z", "0000-01-01T00:00:00Z", "2026-13-01T00:00:00Z", "2026-09-07T24:00:00Z",
    "2026-09-07T00:60:00Z", "2026-09-07T00:00:60Z", "2026-09-07T00:00:00.1234567890Z",
    "2026-09-07T00:00:00+24:00", "2026-09-07T00:00:00+00:60", "2026-09-07T00:00:00",
    "2026-09-07", "2026-09-07T00:00:00Z\n", "", True, 1788739200,
])
def test_invalid_datetime_cell_is_not_rounded_or_coerced(stamp):
    with pytest.raises(ValueError):
        projection(single_cell("datetime", stamp))


def test_one_nanosecond_change_is_detected():
    first = single_cell("datetime", "2026-09-07T00:00:00.123456789Z")
    output = projection(first)
    second = single_cell("datetime", "2026-09-07T00:00:00.123456788Z")
    assert compare_replay(encoded(second), canonical_json_bytes(output), input_format="tables")["status"] == "FAIL"


@pytest.mark.parametrize("kind,value", [
    ("bool", 0), ("bool", 1), ("bool", "false"), ("int", True), ("int", 1.0), ("int", "1"),
    ("int", -2147483649), ("int", 2147483648), ("long", True), ("long", "1"), ("long", 1.0),
    ("long", 9007199254740992), ("long", -9007199254740992),
    ("real", True), ("real", "1.25"), ("real", "NaN"), ("real", {}),
    ("string", 1), ("string", False), ("string", {}), ("string", []),
    ("guid", ""), ("guid", "00000000000000000000000000000001"), ("guid", "not-a-guid"), ("guid", 1),
])
def test_invalid_typed_cells_fail_without_string_number_or_boolean_coercion(kind, value):
    with pytest.raises(ValueError):
        projection(single_cell(kind, value))


@pytest.mark.parametrize("kind", ["decimal", "timespan", "Int64", "String", "unknown", "", None, 1, []])
def test_unknown_or_malformed_column_types_fail_even_for_null_cells(kind):
    with pytest.raises(ValueError):
        projection(single_cell(kind, None))


@pytest.mark.parametrize("raw", [
    b"", b"\xff", b'{"tables":[],"tables":[]}', b'{"tables":[{"x":1,"x":2}]}',
    b'{"tables":[],"statistics":NaN}', b'{"tables":[],"statistics":Infinity}', b'{"tables":[],"statistics":1e999}',
    b'{"tables":[],"statistics":9007199254740992}', b'{"tables":[],"statistics":"\\ud800"}',
    b'{"tables":[],"\\udfff":0}', b'{"tables":', b'{"tables":[]}\n{"tables":[]}', b'\xef\xbb\xbf{"tables":[]}',
])
def test_malformed_or_ambiguous_json_never_falls_back(raw):
    with pytest.raises(ValueError):
        normalize(raw, input_format="tables")


@pytest.mark.parametrize("document", [
    None, [], {}, {"tables": None}, {"tables": {}}, {"tables": [None]},
    {"tables": [], "value": []}, {"value": []}, {"responses": []}, {"pages": []},
    {"tables": [], "nextLink": "https://example.invalid/"}, {"tables": [], "partialError": {}},
])
def test_wrong_mixed_and_batch_envelopes_fail_without_guessing(document):
    with pytest.raises(ValueError):
        normalize(json.dumps(document).encode(), input_format="tables")


@pytest.mark.parametrize("change", [
    lambda t: t.pop("name"), lambda t: t.update(name=""), lambda t: t.update(name="log\nforgery"),
    lambda t: t.pop("columns"), lambda t: t.update(columns=[]), lambda t: t.update(columns={}),
    lambda t: t.update(columns=[None]), lambda t: t["columns"][0].pop("name"),
    lambda t: t["columns"][0].update(name=True), lambda t: t["columns"][0].update(name=""),
    lambda t: t["columns"][0].update(name="x\x7f"), lambda t: t["columns"][0].update(extra="unsupported"),
    lambda t: t["columns"].__setitem__(1, copy.deepcopy(t["columns"][0])),
    lambda t: t.pop("rows"), lambda t: t.update(rows=None), lambda t: t.update(rows={}),
    lambda t: t.update(rows=[None]), lambda t: t.update(rows=[{}]),
    lambda t: t["rows"][0].pop(), lambda t: t["rows"][0].append("extra"),
    lambda t: t.update(error={"code": "PartialError"}),
])
def test_invalid_table_column_and_row_shapes_fail_the_whole_import(change):
    document = synthetic_response()
    change(document["tables"][0])
    with pytest.raises(ValueError):
        projection(document)


@pytest.mark.parametrize("error", [None, [], "PartialError", {}, {"code": None}, {"code": True},
    {"code": "partialerror"}, {"code": "BadArgumentError"}, {"code": "Forbidden"},
    {"code": "PartialError", "details": None}, {"code": "PartialError", "details": {}},
    {"code": "PartialError", "details": [None]}])
def test_fatal_unknown_and_malformed_error_envelopes_cannot_be_ignored(error):
    document = synthetic_response()
    document["error"] = error
    with pytest.raises(ValueError):
        projection(document)


def test_valid_partial_error_details_remain_digest_bound_without_copying_messages():
    document = synthetic_response(partial=True)
    original = projection(document)
    document["error"]["details"].append({"code": "synthetic", "message": "execute this", "innererror": {"opaque": True}})
    changed = projection(document)
    assert original["response_digests"]["error"] != changed["response_digests"]["error"]
    assert "execute this" not in json.dumps(changed) and changed["collection_complete"] is False


@pytest.mark.parametrize("limit", ["MAX_INPUT_BYTES", "MAX_OUTPUT_BYTES", "MAX_ROW_BYTES", "MAX_TABLES",
    "MAX_COLUMNS", "MAX_ROWS", "MAX_CELLS", "MAX_DEPTH", "MAX_NODES", "MAX_METADATA_CHARS"])
def test_each_combined_resource_budget_is_enforced(monkeypatch, limit):
    monkeypatch.setattr(query, limit, 1)
    with pytest.raises(ValueError):
        projection()


def test_partial_error_detail_budget_is_enforced(monkeypatch):
    monkeypatch.setattr(query, "MAX_ERROR_DETAILS", 0)
    with pytest.raises(ValueError):
        projection(synthetic_response(partial=True))


@pytest.mark.parametrize("budget", ["MAX_ROWS", "MAX_CELLS"])
def test_row_and_cell_budgets_cannot_be_reset_by_adding_tables(monkeypatch, budget):
    document = single_cell("long", 1)
    document["tables"].append(copy.deepcopy(document["tables"][0]))
    monkeypatch.setattr(query, budget, 1)
    with pytest.raises(ValueError, match="global limits"):
        projection(document)


def test_output_node_budget_rejects_expansion_before_producing_unreplayable_output(monkeypatch):
    monkeypatch.setattr(query, "MAX_NODES", 35)
    with pytest.raises(ValueError, match="structure exceeds"):
        projection(single_cell("long", 1))


def test_opaque_dynamic_tree_obeys_depth_limit():
    nested = 0
    for _ in range(query.MAX_DEPTH + 1):
        nested = [nested]
    with pytest.raises(ValueError):
        projection(single_cell("dynamic", nested))


def test_deep_json_is_rejected_without_a_fallback():
    with pytest.raises(ValueError):
        normalize(b'{"tables":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}", input_format="tables")


@pytest.mark.parametrize("fmt", ["auto", "array", "activity-log", "jsonl", "", None, [], True])
def test_format_is_explicit_and_allowlisted(fmt):
    with pytest.raises(ValueError):
        normalize(encoded(), input_format=fmt)


def test_source_whitespace_is_exactly_bound_and_projection_whitespace_is_canonical():
    raw = encoded()
    output = normalize(raw, input_format="tables")
    altered = json.dumps(json.loads(raw), indent=2).encode()
    assert output["source_sha256"] == sha256_bytes(raw)
    assert normalize(altered, input_format="tables")["tables"] == output["tables"]
    assert compare_replay(altered, canonical_json_bytes(output), input_format="tables")["status"] == "FAIL"
    assert compare_replay(raw, json.dumps(output, indent=3).encode(), input_format="tables")["status"] == "PASS"


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":1e999}', b'{"x":"\\ud800"}'])
def test_preserved_projection_requires_strict_json(raw):
    with pytest.raises(ValueError):
        compare_replay(encoded(), raw, input_format="tables")


def test_projection_byte_limit_cannot_be_bypassed_with_whitespace():
    raw = encoded()
    output = canonical_json_bytes(normalize(raw, input_format="tables"))
    with pytest.raises(ValueError):
        compare_replay(raw, output + b" " * query.MAX_OUTPUT_BYTES, input_format="tables")


@pytest.mark.parametrize("change", [
    lambda o: o["tables"][0]["columns"][2].update(name="changed meaning"),
    lambda o: o["tables"][0]["rows"][0]["cells"][2].update(value=99),
    lambda o: o["tables"][0]["rows"][0]["cells"][0].update(value="2026-09-07T00:00:00.123456Z"),
    lambda o: o["tables"][0]["rows"].reverse(), lambda o: o["tables"].reverse(),
    lambda o: o.update(row_count=99), lambda o: o.update(partial_error_recorded=False),
    lambda o: o.update(collection_complete=True), lambda o: o.update(source_authenticity_verified=True),
    lambda o: o.update(query_reexecuted=True),
])
def test_validly_signed_incorrect_projection_fails_replay_separately_from_integrity(tmp_path, change):
    fixture = synthetic_query_case(tmp_path / "case", partial=True)
    change(fixture["output"])
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    assert result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("metadata", [{}, {"input_format": "auto"}, {"input_format": "tables", "query": "run arbitrary KQL"},
    {"input_format": "tables", "command": "arbitrary.module"}])
def test_evidence_cannot_choose_arbitrary_query_or_parser_configuration(tmp_path, metadata):
    fixture = synthetic_query_case(tmp_path / "case")
    fixture["metadata"] = metadata
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


def test_unknown_version_is_incomplete_without_executing_parser(tmp_path, monkeypatch):
    fixture = synthetic_query_case(tmp_path / "case")
    fixture["version"] = "999"
    export_fixture(fixture)
    monkeypatch.setattr(query, "normalize", lambda *a, **k: pytest.fail("unknown parser executed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("gate", ["require_checkpoint_timestamp", "require_authenticated_key_policy"])
def test_independent_required_gate_failure_blocks_reconstruction(tmp_path, gate):
    fixture = synthetic_query_case(tmp_path / "case")
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True, **{gate: True})
    assert not result["valid"] and result.get("reconstruction") is None


def test_invalid_archive_never_reaches_parser(tmp_path, monkeypatch):
    fixture = synthetic_query_case(tmp_path / "case")
    export_fixture(fixture)
    altered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(fixture["package"]) as source, zipfile.ZipFile(altered, "w") as target:
        for member in source.infolist():
            raw = b'{"tables":[]}' if member.filename.endswith("query-raw.json") else source.read(member)
            target.writestr(member, raw)
    monkeypatch.setattr(query, "normalize", lambda *a, **k: pytest.fail("unverified evidence reached parser"))
    result = verify_case(altered, fixture["public"], replay_transforms=True)
    assert not result["valid"] and result.get("reconstruction") is None


def test_replay_is_opt_in(tmp_path, monkeypatch):
    fixture = synthetic_query_case(tmp_path / "case")
    export_fixture(fixture)
    monkeypatch.setattr(query, "normalize", lambda *a, **k: pytest.fail("unexpected parser execution"))
    result = verify_case(fixture["package"], fixture["public"], include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "NOT_REQUESTED"


@pytest.mark.parametrize("partial", [False, True])
def test_cli_create_compare_and_mismatch_report_partial_status_explicitly(tmp_path, partial):
    source, output = tmp_path / "source.json", tmp_path / "projection.json"
    source.write_bytes(encoded(synthetic_response(partial=partial)))
    made = cli("--input", source, "--format", "tables", "--out", output)
    report = json.loads(made.stdout)
    assert made.returncode == 0 and report["status"] == "NORMALIZED" and report["partial_error_recorded"] is partial
    compared = cli("--input", source, "--format", "tables", "--compare", output)
    report = json.loads(compared.stdout)
    assert compared.returncode == 0 and report["status"] == "PASS" and report["partial_error_recorded"] is partial
    assert report["collection_complete"] is (False if partial else None)
    changed = json.loads(output.read_bytes())
    changed["row_count"] = 99
    output.write_text(json.dumps(changed))
    assert cli("--input", source, "--format", "tables", "--compare", output).returncode == 1


def test_cli_preserves_source_existing_output_and_symlink_target(tmp_path):
    source, output, link = tmp_path / "source.json", tmp_path / "projection.json", tmp_path / "link.json"
    source.write_bytes(encoded())
    original = source.read_bytes()
    output.write_bytes(b"existing output")
    link.symlink_to(source)
    for target in (source, output, link):
        assert cli("--input", source, "--format", "tables", "--out", target).returncode == 1
    assert source.read_bytes() == original and output.read_bytes() == b"existing output" and link.is_symlink()


def test_case_cli_reports_integrity_valid_replay_failure_with_nonzero_exit(tmp_path):
    fixture = synthetic_query_case(tmp_path / "case")
    fixture["output"]["row_count"] = 99
    export_fixture(fixture)
    result = subprocess.run([sys.executable, str(ROOT / "replay_case_v17.py"), "--zip", str(fixture["package"]),
                             "--export-public-key", str(fixture["public"]), "--replay-transforms"],
                            capture_output=True, text=True, timeout=15)
    report = json.loads(result.stdout)
    assert result.returncode == 1 and report["valid"] and report["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


def test_cli_errors_omit_private_content_and_paths_and_do_not_create_output(tmp_path):
    source, output = tmp_path / "private-source.json", tmp_path / "missing.json"
    source.write_bytes(b'{"private-content":invalid}')
    result = cli("--input", source, "--format", "tables", "--out", output)
    assert result.returncode == 1 and not output.exists() and not result.stderr
    assert "private-content" not in result.stdout and str(tmp_path) not in result.stdout


def test_cli_requires_an_explicit_format(tmp_path):
    source, output = tmp_path / "source.json", tmp_path / "projection.json"
    source.write_bytes(encoded())
    assert cli("--input", source, "--out", output).returncode == 2 and not output.exists()


def test_regular_file_read_respects_exact_byte_limit(tmp_path):
    source = tmp_path / "source.json"
    source.write_bytes(encoded())
    size = source.stat().st_size
    assert read_document(source, limit=size) == source.read_bytes()
    with pytest.raises(ValueError):
        read_document(source, limit=size-1)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_fifo_input_is_rejected_promptly(tmp_path):
    path = tmp_path / "pipe"
    os.mkfifo(path)
    with pytest.raises(ValueError):
        read_document(path)

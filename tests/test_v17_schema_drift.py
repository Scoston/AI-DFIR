"""Nested shape observations, independent baseline pins, and signed replay."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import subprocess
import sys
import zipfile

import pytest

import schema_drift_v17 as cli
import v17_evidence_validation as validation
import v17_log_analytics as bounded
import v17_schema_drift as drift
from case_export_v17 import verify_case
from v17_integrity import EvidenceRelationship, canonical_json_bytes, sha256_bytes
from v17_log_analytics_context_selftest import export_fixture, fixture_profile
from v17_provenance import ProvenanceError, wrap_record
from v17_provenance_selftest import CASE_ID, TIMESTAMP
from v17_schema_drift_selftest import synthetic_drift_case, synthetic_pair


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs): pytest.fail("unexpected schema-comparison network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def raw(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def compare(baseline, current, *, fmt="json-object", pin=None, case_id=CASE_ID):
    return drift.compare(current, baseline_raw=baseline, input_format=fmt, case_id=case_id,
                          expected_baseline_sha256=sha256_bytes(baseline) if pin is None else pin)


def row(observation, *segments):
    ident = drift.path_sha256(segments)
    return next(item for item in observation["paths"] if item["path_sha256"] == ident)


@pytest.mark.parametrize("fmt", drift.INPUT_FORMATS)
@pytest.mark.parametrize("changed", [False, True])
def test_nested_comparison_distinguishes_shape_from_values(fmt, changed):
    baseline, current = synthetic_pair(fmt, changed=changed)
    result = compare(baseline, current, fmt=fmt)
    assert result["observed_shape_changed"] is changed and result["bytes_changed"]
    assert result["drift_status"] == ("CHANGED" if changed else "UNCHANGED")
    assert result["baseline_sha256"] == sha256_bytes(baseline) and result["source_sha256"] == sha256_bytes(current)
    assert result["all_retained_records_observed"] and result["array_positions_collapsed"]
    assert result["collection_complete"] is None
    for flag in ("provider_schema_change_proven", "schema_compatibility_verified", "source_authenticity_verified",
                 "baseline_approval_verified", "quality_rating_changed", "closure_authorized", "network_required"):
        assert result[flag] is False
    encoded = json.dumps(result)
    assert "SYNTHETIC-PRIVATE-IDENTITY" not in encoded and "protoPayload" not in encoded and "authorizationInfo" not in encoded
    if changed:
        assert len(result["changes"]["added_paths"]) == 2 and len(result["changes"]["kind_changes"]) == 1
        assert result["changes"]["kind_changes"][0]["baseline_kinds"] == ["number"]
        assert result["changes"]["kind_changes"][0]["current_kinds"] == ["string"]


KINDS = [(None, "null"), (True, "boolean"), (1, "number"), ("1", "string"), ([], "array"), ({}, "object")]


@pytest.mark.parametrize("before,old_kind", KINDS)
@pytest.mark.parametrize("after,new_kind", KINDS)
def test_all_json_kind_transitions_are_observed(before, old_kind, after, new_kind):
    result = compare(raw({"value": before}), raw({"value": after}))
    assert row(result["baseline"], ("member", "value"))["kinds"] == [old_kind]
    assert row(result["current"], ("member", "value"))["kinds"] == [new_kind]
    assert result["observed_shape_changed"] == (old_kind != new_kind)


@pytest.mark.parametrize("first,second", [
    ([("member", "a.b")], [("member", "a"), ("member", "b")]),
    ([("member", "a/b")], [("member", "a"), ("member", "b")]),
    ([("member", "[]")], [("items",)]), ([("member", "items")], [("items",)]),
    ([("member", "0")], [("items",)]), ([("member", "")], []),
    ([("member", "é")], [("member", "e\u0301")]),
])
def test_structured_paths_do_not_alias_field_separators_or_array_items(first, second):
    assert drift.path_sha256(first) != drift.path_sha256(second)
    material = {"schema": drift.PATH_SCHEMA, "segments": [list(item) for item in first]}
    expected = hashlib.sha256(json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    assert drift.path_sha256(first) == expected


def test_wildcard_occurrences_and_record_presence_are_separate():
    records = [{"items": [{"field": 1}, {"field": "one"}]}, {"items": []}]
    observation = drift.observe(raw(records), input_format="json-array")
    field = row(observation, ("member", "items"), ("items",), ("member", "field"))
    assert field["present_records"] == 1 and field["occurrences"] == 2
    assert field["kind_occurrences"] == {"number": 1, "string": 1}
    assert row(observation, ("member", "items"))["present_records"] == 2
    assert observation["record_count"] == 2
    changed = copy.deepcopy(records); changed[0]["items"].append({"field": 2})
    result = compare(raw(records), raw(changed), fmt="json-array")
    assert not result["observed_shape_changed"] and result["population_counts_changed"]


def test_record_array_and_object_key_order_do_not_change_observed_shape_or_counts():
    first = [{"items": [{"id": 1}, {"id": "two"}], "x": True}, {"items": [], "x": False}]
    second = [{"x": False, "items": []}, {"x": True, "items": [{"id": "different"}, {"id": 2}]}]
    result = compare(raw(first), raw(second), fmt="json-array")
    assert result["bytes_changed"] and not result["observed_shape_changed"] and not result["population_counts_changed"]
    assert result["baseline"] == result["current"]


def test_deep_change_after_record_200_is_not_sampled_away():
    first = [{"nested": {"code": 1}} for _ in range(201)]
    second = copy.deepcopy(first); second[-1]["nested"]["code"] = "1"
    result = compare(raw(first), raw(second), fmt="json-array")
    observed = row(result["current"], ("member", "nested"), ("member", "code"))
    assert result["observed_shape_changed"] and observed["present_records"] == 201
    assert observed["kind_occurrences"] == {"number": 200, "string": 1}


@pytest.mark.parametrize("fmt,empty", [("json-array", b"[]"), ("jsonl", b""), ("jsonl", b"\r\n \t\r\n")])
def test_empty_record_sets_have_no_observed_schema_or_coverage_claim(fmt, empty):
    result = compare(empty, empty, fmt=fmt)
    assert result["current"]["record_count"] == 0 and result["current"]["paths"] == []
    assert not result["observed_shape_changed"] and result["collection_complete"] is None
    present = b'[{}]' if fmt == "json-array" else b'{}\n'
    result = compare(present, empty, fmt=fmt)
    assert result["observed_shape_changed"] and len(result["changes"]["removed_paths"]) == 1


def test_empty_arrays_record_only_the_container_until_items_are_observed():
    result = compare(b'{"a":[]}', b'{"a":[null]}')
    assert len(result["changes"]["added_paths"]) == 1
    assert not result["changes"]["kind_changes"] and result["provider_schema_change_proven"] is False


def test_exact_numeric_spelling_is_bound_without_inventing_numeric_type_changes():
    first = b'{"n":9223372036854775807,"d":0.1234567890123456789012345678,"z":-0.0}'
    second = b'{"n":9223372036854775806,"d":0.1234567890123456789012345679,"z":0.0}'
    result = compare(first, second)
    assert result["bytes_changed"] and not result["observed_shape_changed"] and not result["population_counts_changed"]
    assert row(result["current"], ("member", "n"))["kinds"] == ["number"]


def test_equivalent_escaped_member_names_keep_one_structural_identity():
    result = compare(b'{"\\u0061":1}', b'{"a":2}')
    assert result["bytes_changed"] and result["baseline"] == result["current"]
    assert not result["observed_shape_changed"]


@pytest.mark.parametrize("pin", ["", "0" * 64, "A" * 64, "xyz", [], True, None])
def test_baseline_pin_is_independent_and_required(pin):
    with pytest.raises(ValueError):
        drift.compare(b"{}", baseline_raw=b"{}", input_format="json-object", case_id=CASE_ID, expected_baseline_sha256=pin)


@pytest.mark.parametrize("case", ["", " ", "\n", "a\x00b", None, True, "a" * 4097])
def test_comparison_case_identity_is_explicit(case):
    with pytest.raises(ValueError): compare(b"{}", b"{}", case_id=case)


@pytest.mark.parametrize("fmt", ["csv", "binary", "json", "JSON-OBJECT", None, True, []])
def test_unsupported_formats_are_not_inferred(fmt):
    with pytest.raises(ValueError): compare(b"{}", b"{}", fmt=fmt)


@pytest.mark.parametrize("invalid", [b"", b"null", b"[]", b"\xff", b"\xef\xbb\xbf{}", b'{"x":1,"x":2}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":"\\ud800"}', b'{"\\ud800":1}', b'{} {}', b'/*comment*/{}',
    b'{"x":' + b'[' * 35 + b'0' + b']' * 35 + b'}', b'{"x":' + b'9' * 129 + b'}'])
def test_invalid_json_never_yields_a_partial_comparison(invalid):
    with pytest.raises(ValueError): compare(b"{}", invalid)
    with pytest.raises(ValueError): compare(invalid, b"{}")


@pytest.mark.parametrize("value", [None, True, 1, "{}", bytearray(b"{}"), {}])
def test_only_explicit_bytes_are_parsed(value):
    with pytest.raises(ValueError):
        drift.compare(value, baseline_raw=b"{}", input_format="json-object", case_id=CASE_ID, expected_baseline_sha256=sha256_bytes(b"{}"))
    with pytest.raises(ValueError):
        drift.compare(b"{}", baseline_raw=value, input_format="json-object", case_id=CASE_ID, expected_baseline_sha256=sha256_bytes(b"{}"))


@pytest.mark.parametrize("segments", [None, "a.b", ["member"], [("member",)], [("member", 1)], [("index", 0)],
                                     [("items", 0)], [("items",)] * 33, [("member", "x" * 1025)], [("member", "\ud800")]])
def test_structured_path_validation_bounds(segments):
    with pytest.raises(ValueError): drift.path_sha256(segments)


@pytest.mark.parametrize("name", ["x" * 1024, "é" * 512])
def test_member_byte_limit_has_an_exact_boundary(name):
    result = compare(raw({name: 1}), raw({name: 2}))
    assert not result["observed_shape_changed"]
    with pytest.raises(ValueError): compare(raw({name + "x": 1}), b"{}")


def test_path_encoding_limit_rejects_long_nested_names():
    value = 1
    for _ in range(17): value = {"x" * 1000: value}
    with pytest.raises(ValueError): compare(b"{}", raw(value))
    assert len(drift.path_sha256([("items",)] * 32)) == 64


def test_maximum_observed_path_count_and_record_count():
    value = {f"field-{index}": 0 for index in range(1023)}
    report = compare(raw(value), raw(value))
    assert report["current"]["observed_path_count"] == 1024
    value["overflow"] = 0
    with pytest.raises(ValueError): compare(b"{}", raw(value))
    observations = drift.observe(b"[" + b",".join([b'{"id":1}'] * 10000) + b"]", input_format="json-array")
    assert observations["record_count"] == 10000
    assert row(observations, ("member", "id"))["present_records"] == 10000


@pytest.mark.parametrize("budget", ["input", "output", "paths", "records", "line", "lines", "nodes"])
def test_complete_input_and_output_budgets_fail_closed(monkeypatch, budget):
    if budget == "input":
        monkeypatch.setattr(drift, "MAX_INPUT_BYTES", 2)
        with pytest.raises(ValueError): compare(b"{}", b'{"a":1}')
    elif budget == "output":
        monkeypatch.setattr(drift, "MAX_OUTPUT_BYTES", 100)
        with pytest.raises(ValueError): compare(b"{}", b"{}")
    elif budget == "paths":
        monkeypatch.setattr(drift, "MAX_PATHS", 1)
        with pytest.raises(ValueError): drift.observe(b'{"a":1}', input_format="json-object")
    else:
        content = b'{"a":1}\n' * 20
        if budget == "records": monkeypatch.setattr(validation, "MAX_RECORDS", 19)
        if budget == "line": monkeypatch.setattr(validation, "MAX_LINE_BYTES", 6)
        if budget == "lines": monkeypatch.setattr(validation, "MAX_LINES", 19)
        if budget == "nodes": monkeypatch.setattr(bounded, "MAX_NODES", 40)
        with pytest.raises(ValueError): drift.observe(content, input_format="jsonl")


def test_invalid_late_jsonl_record_is_not_skipped():
    with pytest.raises(ValueError): drift.observe(b'{"a":1}\n' * 200 + b'{"a":', input_format="jsonl")


@pytest.mark.parametrize("fmt", drift.INPUT_FORMATS)
@pytest.mark.parametrize("changed", [False, True])
def test_signed_replay_uses_verified_inputs_and_preserves_drift_status(tmp_path, monkeypatch, fmt, changed):
    fixture = synthetic_drift_case(tmp_path / "case", fmt=fmt, changed=changed); export_fixture(fixture)
    def forbidden(*args, **kwargs): pytest.fail("unexpected process or archive extraction")
    monkeypatch.setattr(subprocess, "Popen", forbidden); monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    transform = result["reconstruction"]["deterministic_replay"]["transforms"][0]
    assert result["valid"] and transform["status"] == "PASS"
    assert transform["observed_shape_changed"] is changed and not transform["provider_schema_change_proven"]
    assert transform["baseline_sha256"] == sha256_bytes(fixture["context"])


@pytest.mark.parametrize("change", ["input-bytes", "baseline-bytes", "baseline-pin", "case", "shape", "changes", "count",
                                     "provider", "compatibility", "quality", "approval", "closure"])
def test_resigned_baseline_or_comparison_substitution_fails_replay(tmp_path, change):
    fixture = synthetic_drift_case(tmp_path / "case")
    if change == "input-bytes": fixture["raw"] += b" "
    elif change == "baseline-bytes":
        fixture["context"] += b" "; fixture["metadata"]["baseline_sha256"] = sha256_bytes(fixture["context"])
    elif change == "baseline-pin": fixture["metadata"]["baseline_sha256"] = "0" * 64
    elif change == "case": fixture["output"]["case_id"] = "OTHER-CASE"
    elif change == "shape": fixture["output"]["current"]["shape_sha256"] = "0" * 64
    elif change == "changes": fixture["output"]["changes"]["kind_changes"] = []
    elif change == "count": fixture["output"]["current"]["paths"][0]["occurrences"] += 1
    else:
        flag = {"provider": "provider_schema_change_proven", "compatibility": "schema_compatibility_verified",
                "quality": "quality_rating_changed", "approval": "baseline_approval_verified", "closure": "closure_authorized"}[change]
        fixture["output"][flag] = True
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("metadata", [{}, {"input_format": "json-array"},
    {"input_format": "json-array", "baseline_artifact_id": "QUERY-CONTEXT"},
    {"input_format": "json-array", "baseline_artifact_id": "QUERY-CONTEXT", "baseline_sha256": "bad"},
    {"input_format": "json-array", "baseline_artifact_id": "QUERY-CONTEXT", "baseline_sha256": "0" * 64, "command": "run"},
    *[{"input_format": "json-array", "baseline_artifact_id": ref, "baseline_sha256": "0" * 64}
      for ref in (None, [], 1, "missing", "QUERY-RAW", "QUERY-PROJECTION", "../baseline.json")]])
def test_unbound_or_ambiguous_baseline_rejects_before_export(tmp_path, metadata):
    fixture = synthetic_drift_case(tmp_path / "case"); fixture["metadata"] = metadata
    with pytest.raises(ValueError): export_fixture(fixture)
    assert not fixture["package"].exists()


def test_baseline_second_input_participates_in_cycle_detection(tmp_path):
    fixture = synthetic_drift_case(tmp_path / "case"); profile = fixture_profile(fixture)
    relation = EvidenceRelationship(case_id=CASE_ID, parent_artifact_id="QUERY-PROJECTION", child_artifact_id="QUERY-CONTEXT",
                                    relationship_type="derived-from", transformation="unimplemented", transformation_version="1", created_at=TIMESTAMP, metadata={})
    profile["relationships"].append(wrap_record("relationships", relation))
    with pytest.raises(ValueError, match="cyclic"): export_fixture(fixture, profile=profile)


def test_unknown_version_never_executes_a_comparison(tmp_path, monkeypatch):
    fixture = synthetic_drift_case(tmp_path / "case"); fixture["version"] = "999"; export_fixture(fixture)
    monkeypatch.setattr(drift, "compare", lambda *a, **k: pytest.fail("unknown version executed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("member", ["query-context.json", "query-raw.json", "query-projection.json"])
def test_unverified_archive_bytes_never_reach_comparison(tmp_path, monkeypatch, member):
    fixture = synthetic_drift_case(tmp_path / "case"); export_fixture(fixture); altered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(fixture["package"]) as source, zipfile.ZipFile(altered, "w") as target:
        for item in source.infolist(): target.writestr(item, b"{}" if item.filename.endswith(member) else source.read(item))
    monkeypatch.setattr(drift, "compare", lambda *a, **k: pytest.fail("unverified bytes reached comparison"))
    result = verify_case(altered, fixture["public"], replay_transforms=True)
    assert not result["valid"] and result.get("reconstruction") is None


@pytest.mark.parametrize("gate", ["require_checkpoint_timestamp", "require_authenticated_key_policy"])
def test_required_independent_gates_block_comparison(tmp_path, monkeypatch, gate):
    fixture = synthetic_drift_case(tmp_path / "case"); export_fixture(fixture)
    monkeypatch.setattr(drift, "compare", lambda *a, **k: pytest.fail("failed gate reached comparison"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True, **{gate: True})
    assert not result["valid"] and result.get("reconstruction") is None


def test_comparison_replay_remains_opt_in(tmp_path, monkeypatch):
    fixture = synthetic_drift_case(tmp_path / "case"); export_fixture(fixture)
    monkeypatch.setattr(drift, "compare", lambda *a, **k: pytest.fail("unexpected structural comparison"))
    result = verify_case(fixture["package"], fixture["public"], include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "NOT_REQUESTED"


def test_changed_baseline_bytes_cannot_reuse_an_old_independent_pin():
    baseline, current = synthetic_pair("json-object")
    pin = sha256_bytes(baseline)
    with pytest.raises(ValueError): compare(baseline + b" ", current, pin=pin)


def cli_inputs(tmp_path, *, fmt="json-array", changed=True):
    baseline, current = synthetic_pair(fmt, changed=changed)
    source = tmp_path / "current.json"; source.write_bytes(current)
    retained = tmp_path / "baseline.json"; retained.write_bytes(baseline)
    return ["--input", source, "--baseline", retained, "--expected-baseline-sha256", sha256_bytes(baseline),
            "--case", CASE_ID, "--format", fmt]


def call_cli(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["schema_drift_v17.py", *map(str, args)])
    code = cli.main(); captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out)


@pytest.mark.parametrize("fmt", drift.INPUT_FORMATS)
@pytest.mark.parametrize("changed", [False, True])
def test_cli_distinguishes_observed_change_from_successful_replay(tmp_path, monkeypatch, capsys, fmt, changed):
    args = cli_inputs(tmp_path, fmt=fmt, changed=changed); output = tmp_path / "comparison.json"
    code, report = call_cli(monkeypatch, capsys, *args, "--out", output)
    assert code == (2 if changed else 0) and report["status"] == "COMPARED"
    assert report["observed_shape_changed"] is changed and not report["provider_schema_change_proven"]
    code, report = call_cli(monkeypatch, capsys, *args, "--compare", output)
    assert code == 0 and report["status"] == "PASS"
    data = json.loads(output.read_bytes()); data["quality_rating_changed"] = True; output.write_bytes(canonical_json_bytes(data))
    code, report = call_cli(monkeypatch, capsys, *args, "--compare", output)
    assert code == 1 and report["status"] == "FAIL"
    if os.name == "posix": assert output.stat().st_mode & 0o777 == 0o600


def test_cli_preserves_sources_outputs_and_symlink_targets(tmp_path, monkeypatch, capsys):
    args = cli_inputs(tmp_path); output = tmp_path / "existing"; output.write_bytes(b"RETAIN")
    link = tmp_path / "link"; link.symlink_to(args[3])
    original = {path: path.read_bytes() for path in (args[1], args[3], output)}
    for target in (*original, link):
        code, report = call_cli(monkeypatch, capsys, *args, "--out", target)
        assert code == 1 and report["status"] == "FAIL"
    assert all(path.read_bytes() == value for path, value in original.items()) and link.is_symlink()


@pytest.mark.parametrize("option", ["--input", "--baseline", "--compare"])
@pytest.mark.parametrize("kind", ["fifo", "directory", "oversized"])
def test_cli_rejects_nonregular_or_excessive_inputs_without_blocking(tmp_path, monkeypatch, capsys, option, kind):
    args = cli_inputs(tmp_path); invalid = tmp_path / "invalid"
    if kind == "fifo": os.mkfifo(invalid)
    elif kind == "directory": invalid.mkdir()
    else:
        limit = drift.MAX_OUTPUT_BYTES if option == "--compare" else drift.MAX_INPUT_BYTES
        with invalid.open("wb") as stream: stream.truncate(limit + 1)
    if option == "--compare": args += [option, invalid]
    else: args[args.index(option) + 1] = invalid; args += ["--out", tmp_path / "output"]
    code, report = call_cli(monkeypatch, capsys, *args)
    assert code == 1 and report["status"] == "FAIL"


@pytest.mark.parametrize("mode", ["pin", "interrupt", "write-failure", "malformed-baseline"])
def test_cli_failure_states_are_redacted(tmp_path, monkeypatch, capsys, mode):
    args = cli_inputs(tmp_path); output = tmp_path / "output"
    if mode == "pin": args[5] = "0" * 64
    if mode == "malformed-baseline": args[3].write_bytes(b'{"secret":"PRIVATE-PAYLOAD"'); args[5] = sha256_bytes(args[3].read_bytes())
    if mode == "interrupt":
        def interrupt(*a, **k): raise KeyboardInterrupt()
        monkeypatch.setattr(cli, "compare", interrupt)
    if mode == "write-failure":
        def fail(*a): raise OSError("PRIVATE-PATH")
        monkeypatch.setattr(cli.os, "fsync", fail)
    code, report = call_cli(monkeypatch, capsys, *args, "--out", output)
    assert code == (130 if mode == "interrupt" else 1)
    assert "PRIVATE" not in json.dumps(report) and str(tmp_path) not in json.dumps(report)
    if mode != "write-failure": assert not output.exists()


def test_empty_jsonl_inputs_can_be_compared_and_replayed(tmp_path, monkeypatch, capsys):
    args = cli_inputs(tmp_path, fmt="jsonl"); args[1].write_bytes(b""); args[3].write_bytes(b"")
    args[5] = sha256_bytes(b""); output = tmp_path / "output"
    code, report = call_cli(monkeypatch, capsys, *args, "--out", output)
    assert code == 0 and report["drift_status"] == "UNCHANGED" and report["collection_complete"] is None
    code, report = call_cli(monkeypatch, capsys, *args, "--compare", output)
    assert code == 0 and report["status"] == "PASS"


def test_empty_jsonl_baseline_and_current_bytes_replay_in_a_signed_case(tmp_path):
    fixture = synthetic_drift_case(tmp_path / "case", fmt="jsonl")
    fixture.update(raw=b"", context=b""); fixture["metadata"]["baseline_sha256"] = sha256_bytes(b"")
    fixture["output"] = compare(b"", b"", fmt="jsonl")
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    transform = result["reconstruction"]["deterministic_replay"]["transforms"][0]
    assert result["valid"] and transform["status"] == "PASS" and transform["drift_status"] == "UNCHANGED"
    assert transform["collection_complete"] is None and not transform["provider_schema_change_proven"]

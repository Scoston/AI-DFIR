"""Pinned raw-evidence validation, field observations, and offline replay limits."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest

import v17_evidence_validation as validation
import v17_log_analytics as bounded_json
from case_export_v17 import verify_case
from v17_evidence_validation_selftest import synthetic_input, synthetic_rules, synthetic_validation_case
from v17_integrity import EvidenceRelationship, canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics_context_selftest import export_fixture, fixture_profile
from v17_provenance import ProvenanceError, wrap_record
from v17_provenance_selftest import CASE_ID, TIMESTAMP


@pytest.fixture(autouse=True)
def no_live_execution(monkeypatch):
    def forbidden(*args, **kwargs): pytest.fail("unexpected network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def assess(raw=None, *, rules=None, fmt="json-array", pin=None, case_id=CASE_ID):
    raw = synthetic_input(fmt) if raw is None else raw
    rules = synthetic_rules(raw, fmt=fmt) if rules is None else rules
    return validation.assess(raw, rules_raw=canonical_json_bytes(rules), case_id=case_id,
                             expected_rules_sha256=sha256_object(rules) if pin is None else pin)


@pytest.mark.parametrize("fmt", validation.FORMATS)
def test_supported_formats_reassess_bytes_without_quality_or_authority_promotion(fmt):
    raw = synthetic_input(fmt); result = assess(raw, fmt=fmt)
    assert result["validation_status"] == "SATISFIED" and all(x is True for x in result["checks"].values())
    assert result["source_sha256"] == sha256_bytes(raw) and result["source_size_bytes"] == len(raw)
    assert result["record_count"] == (None if fmt in ("text", "binary") else 1)
    assert result["raw_evidence_reassessed"] and result["collection_complete"] is None
    assert not any(result[k] for k in ("quality_rating_changed", "rules_approval_verified", "source_authenticity_verified",
                                       "attribution_verified", "closure_authorized", "network_required"))
    assert "SYNTHETIC-PRIVATE-TEXT" not in json.dumps(result)


@pytest.mark.parametrize("fmt", validation.FORMATS)
def test_signed_reassessment_uses_bound_bytes_without_network_process_or_extraction(tmp_path, monkeypatch, fmt):
    fixture = synthetic_validation_case(tmp_path / "case", fmt=fmt); export_fixture(fixture)
    def forbidden(*args, **kwargs): pytest.fail("unexpected process or extraction")
    monkeypatch.setattr(subprocess, "Popen", forbidden); monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    transform = result["reconstruction"]["deterministic_replay"]["transforms"][0]
    assert result["valid"] and transform["status"] == "PASS" and transform["validation_status"] == "SATISFIED"
    assert transform["raw_evidence_reassessed"] and not transform["quality_rating_changed"]


def test_replay_pass_can_reproduce_failed_validation(tmp_path):
    fixture = synthetic_validation_case(tmp_path / "case", failing=True); export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    transform = result["reconstruction"]["deterministic_replay"]["transforms"][0]
    assert result["valid"] and transform["status"] == "PASS" and transform["validation_status"] == "NOT_SATISFIED"


@pytest.mark.parametrize("change", ["bytes", "rule", "rule-pin", "case", "status", "field-count", "schema-hash", "quality"])
def test_resigned_input_or_assessment_substitution_fails_replay(tmp_path, change):
    fixture = synthetic_validation_case(tmp_path / "case")
    rules = json.loads(fixture["context"])
    if change == "bytes":
        fixture["raw"] = fixture["raw"].replace(b"false", b"true")
        rules["expected_sha256"] = sha256_bytes(fixture["raw"])
    elif change == "rule": rules["required_fields"] = []
    elif change == "rule-pin": fixture["metadata"]["rules_sha256"] = "0" * 64
    elif change == "case": rules["case_id"] = "OTHER-CASE"
    elif change == "status": fixture["output"]["validation_status"] = "NOT_SATISFIED"
    elif change == "field-count": fixture["output"]["field_observations"][0]["present_records"] = 0
    elif change == "schema-hash": fixture["output"]["observed_schema_sha256"] = "0" * 64
    else: fixture["output"]["quality_rating_changed"] = True
    if change in ("bytes", "rule", "case"):
        fixture["context"] = canonical_json_bytes(rules); fixture["metadata"]["rules_sha256"] = sha256_object(rules)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("pin", ["", "0" * 64, "A" * 64, "xyz", [], True])
def test_rules_pin_is_explicit_and_never_adopted_from_input(pin):
    with pytest.raises(ProvenanceError): assess(pin=pin)


@pytest.mark.parametrize("key,value", [
    ("schema", "other"), ("case_id", "other"), ("format", "csv"), ("format", None), ("format", []),
    ("expected_sha256", None), ("expected_sha256", "A" * 64), ("expected_sha256", "bad"),
    ("min_size_bytes", -1), ("min_size_bytes", True), ("min_size_bytes", 2.5),
    ("max_size_bytes", -1), ("max_size_bytes", 8 * 1024 * 1024 + 1), ("max_size_bytes", True),
    ("require_records", 1), ("require_records", None), ("allow_extra_fields", 0),
    ("required_fields", None), ("required_fields", "id"), ("required_fields", ["id", "id"]),
    ("required_fields", ["unknown"]), ("required_fields", ["x" * 257]), ("required_fields", [""]),
    ("field_types", []), ("field_types", {"id": ["integer"], "granted": ["boolean"]}),
    ("field_types", {"id": [], "granted": ["boolean"]}), ("field_types", {"id": ["number", "number"], "granted": ["boolean"]}),
    ("field_types", {"id": [None], "granted": ["boolean"]}), ("field_types", {"id": "number", "granted": ["boolean"]}),
    ("required_text", "needle"), ("required_text", [""]), ("required_text", ["x", "x"]),
    ("required_text", ["x" * 4097]), ("required_text", ["x\x00"]),
    ("command", "run"), ("schema_url", "https://other.invalid"), ("quality", "AUTHORITATIVE"),
])
def test_invalid_or_executable_rules_fail_without_assessment(key, value):
    raw = synthetic_input(); rules = synthetic_rules(raw); rules[key] = value
    with pytest.raises(ProvenanceError): assess(raw, rules=rules)


@pytest.mark.parametrize("field", sorted(validation.RULE_FIELDS))
def test_every_rule_field_is_explicit(field):
    raw = synthetic_input(); rules = synthetic_rules(raw); rules.pop(field)
    with pytest.raises(ProvenanceError): assess(raw, rules=rules)


@pytest.mark.parametrize("fmt", ["text", "binary"])
@pytest.mark.parametrize("change", ["records", "fields", "extra"])
def test_record_rules_cannot_be_silently_ignored_for_nonrecord_formats(fmt, change):
    raw = synthetic_input(fmt); rules = synthetic_rules(raw, fmt=fmt)
    if change == "records": rules["require_records"] = True
    elif change == "fields": rules.update(required_fields=["id"], field_types={"id": ["string"]})
    else: rules["allow_extra_fields"] = False
    with pytest.raises(ProvenanceError): assess(raw, rules=rules)


def test_binary_does_not_accept_literal_text_rules():
    raw = synthetic_input("binary"); rules = synthetic_rules(raw, fmt="binary"); rules["required_text"] = ["text"]
    with pytest.raises(ProvenanceError): assess(raw, rules=rules)


@pytest.mark.parametrize("fmt,raw", [
    ("json-object", b'[]'), ("json-object", b'null'), ("json-array", b'{}'), ("json-array", b'[1]'),
    ("jsonl", b'{}\n[]'), ("jsonl", b'{}\nnull'), ("jsonl", b'{}\n{"a":1,"a":2}'),
    ("json-object", b'{"a":1,"a":2}'), ("json-object", b'{"a":1,"\\u0061":2}'),
    ("json-object", b'{"id":NaN}'), ("json-object", b'{"id":Infinity}'), ("json-object", b'{"a":"\\ud800"}'),
    ("json-object", b'\xef\xbb\xbf{}'), ("json-object", b'{} {}'), ("json-object", b'\xff'), ("text", b'\xff'),
    ("json-object", b''), ("json-array", b''), ("jsonl", b'\v'), ("jsonl", b'{\n"id":1\n}'),
])
def test_malformed_or_wrong_profile_evidence_produces_explicit_failed_assessment(fmt, raw):
    result = assess(raw, fmt=fmt)
    assert result["validation_status"] == "NOT_SATISFIED" and result["parse_state"] == "INVALID_OR_UNSUPPORTED"
    assert result["record_count"] is None and result["field_observations"] == [] and result["observed_schema_sha256"] is None
    assert result["checks"]["expected_digest_matches"] and result["collection_complete"] is None


@pytest.mark.parametrize("fmt,raw", [("json-array", b'[]'), ("jsonl", b' \t\r\n\r\n')])
@pytest.mark.parametrize("require", [False, True])
def test_empty_record_sets_do_not_manufacture_observed_coverage(fmt, raw, require):
    rules = synthetic_rules(raw, fmt=fmt); rules["require_records"] = require
    result = assess(raw, rules=rules)
    assert result["validation_status"] == ("NOT_SATISFIED" if require else "SATISFIED")
    assert result["record_count"] == 0 and result["collection_complete"] is None
    assert all(row["present_records"] == 0 for row in result["field_observations"])


@pytest.mark.parametrize("fmt", ["text", "binary"])
def test_empty_nonrecord_bytes_require_explicit_zero_minimum(fmt):
    rules = synthetic_rules(b'', fmt=fmt); rules["min_size_bytes"] = 0
    assert assess(b'', rules=rules)["validation_status"] == "SATISFIED"
    rules["min_size_bytes"] = 1
    assert assess(b'', rules=rules)["validation_status"] == "NOT_SATISFIED"


@pytest.mark.parametrize("field,value,kind", [
    ("id", b'9223372036854775807', "number"), ("id", b'1e99999999999999999999', "number"),
    ("id", b'1.00000000000000001', "number"), ("id", b'"9223372036854775807"', "string"),
    ("id", b'true', "boolean"), ("id", b'null', "null"), ("id", b'[]', "array"), ("id", b'{}', "object"),
])
def test_all_json_kinds_and_exact_numeric_tokens_remain_distinct(field, value, kind):
    raw = b'{"id":' + value + b',"granted":false}'
    rules = synthetic_rules(raw, fmt="json-object"); rules["field_types"][field] = [kind]
    result = assess(raw, rules=rules); row = next(r for r in result["field_observations"] if r["field_sha256"] == sha256_object(field))
    assert result["validation_status"] == "SATISFIED" and row["types"] == [kind] and row["present_records"] == 1
    assert value.decode() not in json.dumps(row) if kind in ("number", "string") else True


def test_every_record_is_checked_including_records_after_the_old_sampling_boundary():
    records = [{"id": i, "granted": False} for i in range(201)]; records[-1].pop("granted")
    raw = canonical_json_bytes(records); result = assess(raw)
    row = next(r for r in result["field_observations"] if r["field_sha256"] == sha256_object("granted"))
    assert result["validation_status"] == "NOT_SATISFIED" and result["record_count"] == 201
    assert row["present_records"] == 200 and row["missing_required_records"] == 1


@pytest.mark.parametrize("extra", [False, True])
def test_missing_fields_wrong_types_and_unexpected_fields_are_separate(extra):
    raw = b'[{"id":1,"granted":null,"PRIVATE-EXTRA":1},{"id":2}]'; rules = synthetic_rules(raw); rules["allow_extra_fields"] = extra
    result = assess(raw, rules=rules); rows = {r["field_sha256"]: r for r in result["field_observations"]}
    granted = rows[sha256_object("granted")]
    assert granted["missing_required_records"] == 1 and granted["type_mismatch_records"] == 1
    assert rows[sha256_object("PRIVATE-EXTRA")]["unexpected"] and "PRIVATE-EXTRA" not in json.dumps(result)
    assert result["validation_status"] == "NOT_SATISFIED"


def test_schema_fingerprint_ignores_value_and_count_but_detects_type_and_field_changes():
    def shape(raw): return assess(raw)["observed_schema_sha256"]
    first = b'[{"id":1,"granted":false}]'
    assert shape(first) == shape(b'[{"granted":true,"id":2},{"id":3,"granted":false}]')
    assert shape(first) != shape(b'[{"id":"1","granted":false}]')
    assert shape(first) != shape(b'[{"id":1}]')


@pytest.mark.parametrize("needle,found", [("PRIVATE-TEXT", True), ("private-text", False), ("MISSING", False), ("a.b*", False)])
def test_literal_rules_are_exact_case_sensitive_nonregex_and_opaque(needle, found):
    raw = synthetic_input("text"); rules = synthetic_rules(raw, fmt="text"); rules["required_text"] = [needle]
    result = assess(raw, rules=rules)
    assert result["checks"]["literal_text_satisfied"] is found
    assert result["validation_status"] == ("SATISFIED" if found else "NOT_SATISFIED")
    assert needle not in json.dumps(result)


@pytest.mark.parametrize("change", ["digest", "minimum", "maximum"])
def test_hash_and_size_failures_are_not_reported_as_verified_quality(change):
    raw = synthetic_input(); rules = synthetic_rules(raw)
    if change == "digest": rules["expected_sha256"] = "0" * 64
    elif change == "minimum": rules["min_size_bytes"] = len(raw) + 1
    else: rules["max_size_bytes"] = len(raw) - 1
    result = assess(raw, rules=rules)
    assert result["validation_status"] == "NOT_SATISFIED" and result["parse_state"] == "PASS"
    assert not result["quality_rating_changed"] and not result["source_authenticity_verified"]


@pytest.mark.parametrize("raw", [None, "bytes", bytearray(b'{}'), b'x' * (8 * 1024 * 1024 + 1)])
def test_nonbytes_and_excessive_artifacts_fail_before_parsing(raw):
    rules = synthetic_rules(b'{}')
    with pytest.raises(ProvenanceError): validation.assess(raw, rules_raw=canonical_json_bytes(rules), case_id=CASE_ID, expected_rules_sha256=sha256_object(rules))


@pytest.mark.parametrize("raw", [b'', b'null', b'[]', b'{}', b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":"\\ud800"}',
    b'\xff', b' ' * (256 * 1024 + 1)])
def test_invalid_rules_bytes_do_not_yield_an_assessment(raw):
    with pytest.raises(ProvenanceError): validation.assess(b'{}', rules_raw=raw, case_id=CASE_ID, expected_rules_sha256="0" * 64)


@pytest.mark.parametrize("case_id", [None, [], "", " ", "x\x00", "other"])
def test_missing_invalid_or_conflicting_case_identity_fails(case_id):
    with pytest.raises(ProvenanceError): assess(case_id=case_id)


@pytest.mark.parametrize("limit", ["MAX_RULES_BYTES", "MAX_OUTPUT_BYTES"])
def test_rule_and_report_byte_limits_are_enforced(monkeypatch, limit):
    monkeypatch.setattr(validation, limit, 32)
    with pytest.raises(ProvenanceError): assess()


@pytest.mark.parametrize("key", ["required_fields", "field_types", "required_text"])
def test_rule_collection_budgets_are_enforced(key):
    raw = synthetic_input(); rules = synthetic_rules(raw)
    if key == "required_fields": rules[key] = ["f" + str(i) for i in range(65)]
    elif key == "field_types": rules[key] = {"f" + str(i): ["string"] for i in range(65)}
    else: rules[key] = ["text" + str(i) for i in range(65)]
    with pytest.raises(ProvenanceError): assess(raw, rules=rules)


@pytest.mark.parametrize("kind", ["depth", "number-token", "records", "fields", "line", "physical-lines"])
def test_excessive_evidence_never_gets_a_partial_successful_assessment(monkeypatch, kind):
    fmt = "json-object"; raw = synthetic_input(fmt)
    if kind == "depth": raw = b'{"id":' + b'[' * 35 + b'0' + b']' * 35 + b',"granted":false}'
    elif kind == "number-token": raw = b'{"id":' + b'1' * 129 + b',"granted":false}'
    elif kind == "records":
        fmt = "json-array"; raw = b'[' + synthetic_input("json-object") + b',' + synthetic_input("json-object") + b']'
        monkeypatch.setattr(validation, "MAX_RECORDS", 1)
    elif kind == "fields": monkeypatch.setattr(validation, "MAX_FIELDS", 1)
    elif kind == "line": fmt = "jsonl"; monkeypatch.setattr(validation, "MAX_LINE_BYTES", 8)
    else: fmt = "jsonl"; raw += b'\n' * 4; monkeypatch.setattr(validation, "MAX_LINES", 3)
    result = assess(raw, fmt=fmt)
    assert result["validation_status"] == "NOT_SATISFIED" and result["parse_state"] == "INVALID_OR_UNSUPPORTED"
    assert result["record_count"] is None and result["field_observations"] == []


def test_jsonl_global_node_budget_is_not_reset_per_line(monkeypatch):
    monkeypatch.setattr(bounded_json, "MAX_NODES", 32)
    raw = b'{"id":1,"granted":false}\n' * 10
    with pytest.raises(ProvenanceError): validation._records(raw, "jsonl")


def test_maximum_record_count_and_number_token_budget_have_explicit_boundaries():
    raw = b'[' + b','.join([b'{"id":1,"granted":false}'] * 10000) + b']'
    assert assess(raw)["record_count"] == 10000
    raw = b'{"id":' + b'1' * 128 + b',"granted":false}'
    assert assess(raw, fmt="json-object")["validation_status"] == "SATISFIED"


def test_line_endings_and_blank_lines_are_preserved_in_source_digest():
    raw = synthetic_input("json-object")
    a, b = assess(raw + b'\n', fmt="jsonl"), assess(b'\r\n \t\r\n' + raw + b'\r\n', fmt="jsonl")
    assert a["record_count"] == b["record_count"] == 1 and a["observed_schema_sha256"] == b["observed_schema_sha256"]
    assert a["source_sha256"] != b["source_sha256"]


def test_rule_key_order_is_canonical_but_exact_rule_bytes_remain_bound():
    raw = synthetic_input(); rules = synthetic_rules(raw); pin = sha256_object(rules)
    first = canonical_json_bytes(rules); second = json.dumps(dict(reversed(list(rules.items()))), indent=2).encode()
    a = validation.assess(raw, rules_raw=first, case_id=CASE_ID, expected_rules_sha256=pin)
    b = validation.assess(raw, rules_raw=second, case_id=CASE_ID, expected_rules_sha256=pin)
    assert a["rules_sha256"] == b["rules_sha256"] and a["rules_source_sha256"] != b["rules_source_sha256"]
    assert validation.compare_replay(raw, canonical_json_bytes(a), rules_raw=second, case_id=CASE_ID, expected_rules_sha256=pin)["status"] == "FAIL"


@pytest.mark.parametrize("metadata", [{}, {"rules_artifact_id": "QUERY-CONTEXT"}, {"rules_sha256": "0" * 64},
    {"rules_artifact_id": "QUERY-CONTEXT", "rules_sha256": "bad"},
    {"rules_artifact_id": "QUERY-CONTEXT", "rules_sha256": "0" * 64, "command": "run"},
    *[{"rules_artifact_id": ref, "rules_sha256": "0" * 64} for ref in (None, [], 1, "missing", "QUERY-RAW", "QUERY-PROJECTION", "../rules.json")]])
def test_unbound_or_ambiguous_rules_reject_before_signed_export(tmp_path, metadata):
    fixture = synthetic_validation_case(tmp_path / "case"); fixture["metadata"] = metadata
    with pytest.raises(ValueError): export_fixture(fixture)
    assert not fixture["package"].exists()


def test_rules_as_second_input_participate_in_cycle_detection(tmp_path):
    fixture = synthetic_validation_case(tmp_path / "case"); profile = fixture_profile(fixture)
    relation = EvidenceRelationship(case_id=CASE_ID, parent_artifact_id="QUERY-PROJECTION", child_artifact_id="QUERY-CONTEXT",
                                    relationship_type="derived-from", transformation="unimplemented", transformation_version="1", created_at=TIMESTAMP, metadata={})
    profile["relationships"].append(wrap_record("relationships", relation))
    with pytest.raises(ValueError, match="cyclic"): export_fixture(fixture, profile=profile)


def test_unknown_version_is_unsupported_without_assessment(tmp_path, monkeypatch):
    fixture = synthetic_validation_case(tmp_path / "case"); fixture["version"] = "999"; export_fixture(fixture)
    monkeypatch.setattr(validation, "assess", lambda *a, **k: pytest.fail("unknown version executed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("member", ["query-context.json", "query-raw.json", "query-projection.json"])
def test_unverified_archive_bytes_never_reach_assessment(tmp_path, monkeypatch, member):
    fixture = synthetic_validation_case(tmp_path / "case"); export_fixture(fixture); altered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(fixture["package"]) as source, zipfile.ZipFile(altered, "w") as target:
        for item in source.infolist(): target.writestr(item, b'{}' if item.filename.endswith(member) else source.read(item))
    monkeypatch.setattr(validation, "assess", lambda *a, **k: pytest.fail("unverified bytes reached assessment"))
    result = verify_case(altered, fixture["public"], replay_transforms=True)
    assert not result["valid"] and result.get("reconstruction") is None


@pytest.mark.parametrize("gate", ["require_checkpoint_timestamp", "require_authenticated_key_policy"])
def test_required_independent_gates_block_reassessment(tmp_path, monkeypatch, gate):
    fixture = synthetic_validation_case(tmp_path / "case"); export_fixture(fixture)
    monkeypatch.setattr(validation, "assess", lambda *a, **k: pytest.fail("failed gate reached assessment"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True, **{gate: True})
    assert not result["valid"] and result.get("reconstruction") is None


def test_assessment_replay_remains_opt_in(tmp_path, monkeypatch):
    fixture = synthetic_validation_case(tmp_path / "case"); export_fixture(fixture)
    monkeypatch.setattr(validation, "assess", lambda *a, **k: pytest.fail("unexpected reassessment"))
    result = verify_case(fixture["package"], fixture["public"], include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "NOT_REQUESTED"


def cli(*args):
    return subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "evidence_validation_v17.py"), *map(str, args)],
                          capture_output=True, text=True, timeout=15)


def cli_inputs(tmp_path, *, failing=False, fmt="json-array"):
    raw = synthetic_input(fmt, failing=failing); rules = synthetic_rules(raw, fmt=fmt)
    source, retained = tmp_path / "raw.dat", tmp_path / "rules.json"
    source.write_bytes(raw); retained.write_bytes(canonical_json_bytes(rules))
    return ["--input", source, "--rules", retained, "--case", CASE_ID, "--expected-rules-sha256", sha256_object(rules)]


@pytest.mark.parametrize("failing", [False, True])
def test_cli_distinguishes_assessment_failure_and_successful_reproduction(tmp_path, failing):
    args = cli_inputs(tmp_path, failing=failing); output = tmp_path / "assessment.json"
    result = cli(*args, "--out", output)
    assert result.returncode == (2 if failing else 0) and json.loads(result.stdout)["status"] == "ASSESSED"
    assert json.loads(result.stdout)["validation_status"] == ("NOT_SATISFIED" if failing else "SATISFIED")
    result = cli(*args, "--compare", output)
    assert result.returncode == 0 and json.loads(result.stdout)["status"] == "PASS"
    data = json.loads(output.read_bytes()); data["quality_rating_changed"] = True; output.write_bytes(canonical_json_bytes(data))
    assert cli(*args, "--compare", output).returncode == 1


def test_cli_preserves_raw_rules_existing_outputs_and_symlinks(tmp_path):
    args = cli_inputs(tmp_path); output, link = tmp_path / "existing", tmp_path / "link"
    output.write_text("keep"); link.symlink_to(args[3])
    original = {path: path.read_bytes() for path in (args[1], args[3], output)}
    for target in (*original, link): assert cli(*args, "--out", target).returncode == 1
    assert all(path.read_bytes() == raw for path, raw in original.items()) and link.is_symlink()


def test_cli_wrong_pin_is_redacted_and_does_not_create_assessment(tmp_path):
    args = cli_inputs(tmp_path); args[-1] = "0" * 64; output = tmp_path / "out"
    result = cli(*args, "--out", output)
    assert result.returncode == 1 and not output.exists() and not result.stderr
    assert str(tmp_path) not in result.stdout and "PRIVATE" not in result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
@pytest.mark.parametrize("option", ["--input", "--rules", "--compare"])
def test_cli_rejects_nonregular_inputs_without_blocking(tmp_path, option):
    args = cli_inputs(tmp_path); fifo = tmp_path / "pipe"; os.mkfifo(fifo)
    if option == "--compare": args += [option, fifo]
    else: args[args.index(option) + 1] = fifo; args += ["--out", tmp_path / "output"]
    assert cli(*args).returncode == 1


@pytest.mark.parametrize("fmt", ["text", "binary"])
def test_cli_can_reassess_explicitly_allowed_empty_evidence(tmp_path, fmt):
    source = tmp_path / "empty"; source.write_bytes(b''); rules = synthetic_rules(b'', fmt=fmt); rules["min_size_bytes"] = 0
    retained = tmp_path / "rules"; retained.write_bytes(canonical_json_bytes(rules))
    result = cli("--input", source, "--rules", retained, "--case", CASE_ID, "--expected-rules-sha256", sha256_object(rules), "--out", tmp_path / "output")
    assert result.returncode == 0 and json.loads(result.stdout)["validation_status"] == "SATISFIED"


@pytest.mark.parametrize("fmt", ["text", "binary"])
def test_empty_evidence_replays_with_signed_inventory_and_explicit_zero_minimum(tmp_path, fmt):
    fixture = synthetic_validation_case(tmp_path / "case", fmt=fmt)
    rules = synthetic_rules(b'', fmt=fmt); rules["min_size_bytes"] = 0
    fixture.update(raw=b'', context=canonical_json_bytes(rules))
    fixture["metadata"]["rules_sha256"] = sha256_object(rules)
    fixture["output"] = assess(b'', rules=rules)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"

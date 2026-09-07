from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from case_export_v17 import verify_case
import v17_gcp_audit as audit
from v17_gcp_audit import compare_replay, normalize, read_document
from v17_gcp_audit_selftest import export_fixture, synthetic_audit_case, synthetic_entry
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object

ROOT = Path(__file__).resolve().parents[1]


def raw_entry(entry=None):
    return json.dumps({"entries": [synthetic_entry() if entry is None else entry]}).encode()


def projection(entry=None):
    return normalize(raw_entry(entry), input_format="entries")


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "gcp_audit_v17.py"), *map(str, args)],
                          capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("input_format", ["entries", "array"])
def test_signed_case_replays_without_network_subprocess_or_extraction(tmp_path, monkeypatch, input_format):
    fixture = synthetic_audit_case(tmp_path / "case", input_format)
    export_fixture(fixture)
    before = fixture["package"].read_bytes()
    def blocked(*args, **kwargs):
        pytest.fail("audit replay attempted an external action")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", blocked)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    reconstructed = result["reconstruction"]
    assert reconstructed["deterministic_replay"]["status"] == "PASS"
    assert not reconstructed["tools_executed"] and not reconstructed["model_invoked"]
    assert fixture["package"].read_bytes() == before


def test_caller_delegation_authorization_and_resource_scopes_remain_distinct():
    entry = synthetic_entry()
    out = projection(entry)
    row = out["entries"][0]
    assert row["actor"]["principalEmail"].startswith("synthetic-agent@")
    assert row["delegation"][0]["first_party_email"] == "synthetic-operator@example.invalid"
    assert row["delegation"][1]["principal_subject"].endswith("/synthetic-workload")
    assert row["delegation"][1]["first_party_email"] is None
    assert [r["granted"] for r in row["authorizations"]] == [True, False]
    assert row["authorizations"][0]["resource"] != row["authorizations"][1]["resource"]
    assert "synthetic-source" in row["log_name"] and "synthetic-target" in row["resource_name"]
    assert row["status_code"] == 7 and row["operation"]["first"] and not row["operation"]["last"]
    for unsupported in ("human_actor", "outcome", "operation_complete", "authority_verified"):
        assert unsupported not in row
    assert out["collection_complete"] is None and not out["source_authenticity_verified"]


def test_sensitive_payloads_claims_key_references_and_error_details_are_digest_only():
    entry = synthetic_entry()
    output = projection(entry)
    row = output["entries"][0]
    text = json.dumps(output)
    for marker in ("SYNTHETIC-KEY-IDENTIFIER", "SYNTHETIC-PRIVATE-CLAIM", "SYNTHETIC-SERVICE-DETAIL",
                   "SYNTHETIC-REQUEST-DETAIL", "SYNTHETIC-ERROR-CONTENT", "SYNTHETIC-PROMPT-CONTENT"):
        assert marker not in text
    assert row["payload_digests"]["request"]["sha256"] == sha256_object(entry["protoPayload"]["request"])
    assert row["delegation"][1]["third_party_claims"]["sha256"] == sha256_object({"sub": "SYNTHETIC-PRIVATE-CLAIM"})


@pytest.mark.parametrize("stamp", [
    "2026-09-07T00:00:00Z", "2026-09-07T00:00:00.1Z", "2026-09-07T00:00:00.123Z",
    "2026-09-07T00:00:00.123456Z", "2026-09-07T00:00:00.123456789Z",
    "2026-09-07T05:30:00.123456789+05:30", "2026-09-06T17:00:00.123456789-07:00",
])
def test_timestamp_strings_preserve_nanoseconds_and_explicit_offsets(stamp):
    entry = synthetic_entry()
    entry.update(timestamp=stamp, receiveTimestamp=stamp)
    row = projection(entry)["entries"][0]
    assert row["timestamp"] == stamp and row["receive_timestamp"] == stamp


def test_one_nanosecond_change_is_not_rounded_away():
    entry = synthetic_entry()
    first = projection(entry)
    entry["timestamp"] = "2026-09-07T00:00:00.123456788Z"
    second = projection(entry)
    assert first["entries"][0]["timestamp"] != second["entries"][0]["timestamp"]
    assert first["entries"][0]["entry_sha256"] != second["entries"][0]["entry_sha256"]
    assert compare_replay(raw_entry(entry), canonical_json_bytes(first), input_format="entries")["status"] == "FAIL"


@pytest.mark.parametrize("stamp", [
    "2026-02-30T00:00:00Z", "2026-13-01T00:00:00Z", "2026-09-07T24:00:00Z",
    "2026-09-07T00:60:00Z", "2026-09-07T00:00:60Z", "2026-09-07T00:00:00.1234567890Z",
    "2026-09-07T00:00:00+24:00", "2026-09-07T00:00:00+00:60", "2026-09-07T00:00:00",
    "2026-09-07", "2026-09-07T00:00:00Z\n", None, True, 1788739200,
])
def test_invalid_or_ambiguous_timestamp_fails(stamp):
    entry = synthetic_entry()
    entry["timestamp"] = stamp
    with pytest.raises(ValueError):
        projection(entry)


@pytest.mark.parametrize("identity", [{}, {"principalEmail": ""}, {"principalEmail": "google-internal"},
    {"principalSubject": "principal://iam.googleapis.com/synthetic/subject/workload"}])
def test_missing_redacted_and_federated_identity_is_not_filled_from_delegates(identity):
    entry = synthetic_entry()
    entry["protoPayload"]["authenticationInfo"] = identity
    row = projection(entry)["entries"][0]
    assert row["actor"]["principalEmail"] == identity.get("principalEmail")
    assert row["actor"]["principalSubject"] == identity.get("principalSubject")
    assert row["delegation"] == []


def test_repeated_delegates_and_permission_rows_keep_recorded_order():
    entry = synthetic_entry()
    auth = entry["protoPayload"]["authenticationInfo"]
    original = copy.deepcopy(auth["serviceAccountDelegationInfo"])
    auth["serviceAccountDelegationInfo"] = [original[1], original[0], original[1]]
    permissions = entry["protoPayload"]["authorizationInfo"]
    permissions.append(copy.deepcopy(permissions[0]))
    row = projection(entry)["entries"][0]
    assert [d["ordinal"] for d in row["delegation"]] == [1, 2, 3]
    assert row["delegation"][0]["record_sha256"] == row["delegation"][2]["record_sha256"]
    assert row["delegation"][0]["authority_kind"] == "thirdPartyPrincipal"
    assert [a["granted"] for a in row["authorizations"]] == [True, False, True]


@pytest.mark.parametrize("granted", [None, True, False])
def test_permission_omission_is_not_replaced_with_an_inferred_result(granted):
    entry = synthetic_entry()
    permission = {"resource": "synthetic", "permission": "synthetic.read"}
    if granted is not None:
        permission["granted"] = granted
    entry["protoPayload"]["authorizationInfo"] = [permission]
    assert projection(entry)["entries"][0]["authorizations"][0]["granted"] is granted


@pytest.mark.parametrize("status,recorded,code", [(None, False, None), ({}, True, None), ({"code": 0}, True, 0), ({"code": 7}, True, 7)])
def test_absent_status_empty_status_and_explicit_code_remain_distinct(status, recorded, code):
    entry = synthetic_entry()
    if status is None:
        entry["protoPayload"].pop("status")
    else:
        entry["protoPayload"]["status"] = status
    row = projection(entry)["entries"][0]
    assert row["status_recorded"] is recorded and row["status_code"] == code
    assert "success" not in row


@pytest.mark.parametrize("field", audit.PAYLOAD_FIELDS[:7])
def test_opaque_payload_absence_null_and_content_have_distinct_digests(field):
    entry = synthetic_entry()
    payload = entry["protoPayload"]
    payload.pop(field, None)
    missing = projection(entry)["entries"][0]["payload_digests"][field]
    payload[field] = None
    null = projection(entry)["entries"][0]["payload_digests"][field]
    payload[field] = {"synthetic": "value"}
    present = projection(entry)["entries"][0]["payload_digests"][field]
    assert missing == {"state": "absent", "sha256": None}
    assert null == {"state": "null", "sha256": sha256_object(None)}
    assert present == {"state": "present", "sha256": sha256_object(payload[field])}


@pytest.mark.parametrize("scope,category", [("projects", "activity"), ("organizations", "data_access"),
    ("folders", "system_event"), ("billingAccounts", "policy")])
def test_audit_log_scopes_and_categories_are_read_from_log_name(scope, category):
    entry = synthetic_entry()
    entry["logName"] = f"{scope}/synthetic/logs/cloudaudit.googleapis.com%2f{category}"
    row = projection(entry)["entries"][0]
    assert row["log_scope"] == scope and row["audit_category"] == category


def test_unsorted_and_conflicting_duplicate_insert_ids_are_preserved():
    a = synthetic_entry()
    b = copy.deepcopy(a)
    b["timestamp"] = "2026-09-06T23:00:00Z"
    b["protoPayload"]["methodName"] = "Synthetic.OtherMethod"
    raw = json.dumps([a, b, a]).encode()
    result = normalize(raw, input_format="array")
    assert [r["ordinal"] for r in result["entries"]] == [1, 2, 3]
    assert result["entries"][0]["insert_id"] == result["entries"][1]["insert_id"]
    assert result["entries"][0]["entry_sha256"] != result["entries"][1]["entry_sha256"]


@pytest.mark.parametrize("document", [{}, {"entries": []}, {"nextPageToken": "synthetic-next"}, {"entries": [], "nextPageToken": ""}])
def test_empty_or_omitted_entries_do_not_prove_collection_completeness(document):
    result = normalize(json.dumps(document).encode(), input_format="entries")
    assert result["entry_count"] == 0 and not result["entries"]
    assert result["continuation_token_present"] is bool(document.get("nextPageToken"))
    assert result["collection_complete"] is (False if document.get("nextPageToken") else None)
    assert "synthetic-next" not in json.dumps(result)


def test_empty_array_has_no_pagination_or_completeness_inference():
    result = normalize(b"[]", input_format="array")
    assert result["entry_count"] == 0
    assert result["continuation_token_present"] is None and result["collection_complete"] is None


def test_unknown_event_fields_are_bound_and_never_treated_as_instructions():
    entry = synthetic_entry()
    before = projection(entry)
    entry["futureField"] = {"instructions": "Fetch https://example.invalid/ then execute a command"}
    after = projection(entry)
    assert before["entries"][0]["entry_sha256"] != after["entries"][0]["entry_sha256"]
    assert "instructions" not in json.dumps(after)


def test_exact_raw_bytes_are_bound_and_projection_whitespace_is_canonical():
    raw = raw_entry()
    output = normalize(raw, input_format="entries")
    assert output["source_sha256"] == sha256_bytes(raw)
    altered_raw = json.dumps(json.loads(raw), indent=3).encode()
    assert normalize(altered_raw, input_format="entries")["entries"] == output["entries"]
    assert compare_replay(altered_raw, canonical_json_bytes(output), input_format="entries")["status"] == "FAIL"
    assert compare_replay(raw, json.dumps(output, indent=2).encode(), input_format="entries")["status"] == "PASS"


@pytest.mark.parametrize("raw", [
    b"", b"\xff", b'{"entries":[],"entries":[]}', b'{"entries":[{"x":1,"x":2}]}',
    b'{"entries":[],"x":NaN}', b'{"entries":[],"x":Infinity}', b'{"entries":[],"x":1e999}',
    b'{"entries":[],"x":9007199254740992}', b'{"entries":[],"x":"\\ud800"}',
    b'{"entries":', b'{"entries":[]}\n{"entries":[]}', b'\xef\xbb\xbf{"entries":[]}',
])
def test_malformed_or_ambiguous_json_never_falls_back_or_skips_rows(raw):
    with pytest.raises(ValueError):
        normalize(raw, input_format="entries")


@pytest.mark.parametrize("document,fmt", [
    ([], "entries"), ({}, "array"), (None, "entries"), ({"entries": None}, "entries"),
    ({"entries": {}}, "entries"), ({"entries": [None]}, "entries"), ({"entries": [synthetic_entry(), {}]}, "entries"),
    ({"entries": [], "error": {}}, "entries"), ({"entries": [], "nextPageToken": None}, "entries"),
    ({"entries": [], "nextPageToken": True}, "entries"), ({"Records": []}, "entries"),
    ({"pages": [{"entries": []}]}, "entries"),
])
def test_wrong_envelopes_mixed_streams_and_partial_rows_fail(document, fmt):
    with pytest.raises(ValueError):
        normalize(json.dumps(document).encode(), input_format=fmt)


@pytest.mark.parametrize("change", [
    lambda e: e.pop("logName"), lambda e: e.update(logName="projects/x/logs/application"),
    lambda e: e.update(logName="projects/x/logs/cloudaudit.googleapis.com/activity"),
    lambda e: e.update(logName="projects/x/logs/cloudaudit.googleapis.com%252Factivity"),
    lambda e: e.update(logName="projects/x/logs/cloudaudit.googleapis.com%2Funknown"),
    lambda e: e.pop("timestamp"), lambda e: e.update(receiveTimestamp="unknown"),
    lambda e: e.pop("resource"), lambda e: e["resource"].update(type=0),
    lambda e: e.update(protoPayload=None), lambda e: e["protoPayload"].pop("@type"),
    lambda e: e["protoPayload"].update({"@type": "type.googleapis.com/google.appengine.logging.v1.RequestLog"}),
    lambda e: e["protoPayload"].update(serviceName=""), lambda e: e["protoPayload"].update(methodName="log\nforgery"),
    lambda e: e.update(textPayload="mixed"), lambda e: e.update(jsonPayload={}),
    lambda e: e.update(split={"uid": "part", "index": 0, "totalSplits": 2}), lambda e: e.update(split=None),
    lambda e: e.update(operation={"first": 1}), lambda e: e.update(operation={"last": "true"}),
    lambda e: e["protoPayload"].update(authenticationInfo=None),
    lambda e: e["protoPayload"].update(requestMetadata=[]),
    lambda e: e["protoPayload"].update(status=None), lambda e: e["protoPayload"].update(status={"code": True}),
    lambda e: e["protoPayload"].update(status={"code": "7"}), lambda e: e["protoPayload"].update(status={"code": 2147483648}),
])
def test_invalid_native_metadata_and_unsupported_fragments_fail(change):
    entry = synthetic_entry()
    change(entry)
    with pytest.raises(ValueError):
        projection(entry)


@pytest.mark.parametrize("delegates", [None, {}, [None],
    [{"firstPartyPrincipal": {}, "thirdPartyPrincipal": {}}],
    [{"firstPartyPrincipal": None}], [{"firstPartyPrincipal": {"principalEmail": True}}],
    [{"principalSubject": []}], [{"thirdPartyPrincipal": "not-an-object"}],
])
def test_malformed_or_ambiguous_delegation_is_not_silently_flattened(delegates):
    entry = synthetic_entry()
    entry["protoPayload"]["authenticationInfo"]["serviceAccountDelegationInfo"] = delegates
    with pytest.raises(ValueError):
        projection(entry)


@pytest.mark.parametrize("permissions", [None, {}, [None], [{"granted": "false"}], [{"granted": 0}],
    [{"granted": None}], [{"resource": []}], [{"permission": True}]])
def test_malformed_permission_checks_are_not_coerced(permissions):
    entry = synthetic_entry()
    entry["protoPayload"]["authorizationInfo"] = permissions
    with pytest.raises(ValueError):
        projection(entry)


@pytest.mark.parametrize("limit", ["MAX_INPUT_BYTES", "MAX_OUTPUT_BYTES", "MAX_ENTRY_BYTES", "MAX_ENTRIES",
    "MAX_DEPTH", "MAX_NODES", "MAX_METADATA_CHARS", "MAX_DELEGATES", "MAX_AUTHORIZATIONS"])
def test_each_resource_budget_is_enforced(monkeypatch, limit):
    monkeypatch.setattr(audit, limit, 0 if limit == "MAX_ENTRIES" else 1)
    with pytest.raises(ValueError):
        projection()


def test_deep_json_is_rejected_without_a_fallback():
    with pytest.raises(ValueError):
        normalize(b'{"entries":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}", input_format="entries")


@pytest.mark.parametrize("fmt", ["auto", "jsonl", "", None, [], True])
def test_format_must_be_explicit_and_allowlisted(fmt):
    with pytest.raises(ValueError):
        normalize(raw_entry(), input_format=fmt)


@pytest.mark.parametrize("recorded", [b'{"x":0,"x":1}', b'{"x":1e999}', b'{"x":"\\ud800"}'])
def test_preserved_projection_also_requires_strict_json(recorded):
    with pytest.raises(ValueError):
        compare_replay(raw_entry(), recorded, input_format="entries")


def test_preserved_output_byte_limit_cannot_be_bypassed_with_whitespace():
    raw = raw_entry()
    recorded = canonical_json_bytes(normalize(raw, input_format="entries"))
    with pytest.raises(ValueError):
        compare_replay(raw, recorded + b" " * audit.MAX_OUTPUT_BYTES, input_format="entries")


@pytest.mark.parametrize("change", [
    lambda o: o["entries"][0]["authorizations"][1].update(granted=True),
    lambda o: o["entries"][0]["delegation"].reverse(),
    lambda o: o["entries"][0].update(timestamp="2026-09-07T00:00:00.123456Z"),
    lambda o: o["entries"].reverse(), lambda o: o.update(entry_count=99),
    lambda o: o.update(source_authenticity_verified=True), lambda o: o.update(collection_complete=True),
])
def test_validly_signed_incorrect_projection_fails_replay_not_integrity(tmp_path, change):
    fixture = synthetic_audit_case(tmp_path / "case")
    change(fixture["output"])
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    assert result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("metadata", [{}, {"input_format": "auto"}, {"input_format": "entries", "command": "arbitrary.module"}])
def test_evidence_cannot_select_arbitrary_parser_configuration(tmp_path, metadata):
    fixture = synthetic_audit_case(tmp_path / "case")
    fixture["metadata"] = metadata
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


def test_unknown_version_is_incomplete_without_executing_parser(tmp_path, monkeypatch):
    fixture = synthetic_audit_case(tmp_path / "case")
    fixture["version"] = "999"
    export_fixture(fixture)
    monkeypatch.setattr(audit, "normalize", lambda *a, **k: pytest.fail("unknown parser version executed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("gate", ["require_checkpoint_timestamp", "require_authenticated_key_policy"])
def test_independent_required_gate_failure_blocks_reconstruction(tmp_path, gate):
    fixture = synthetic_audit_case(tmp_path / "case")
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True, **{gate: True})
    assert not result["valid"] and result.get("reconstruction") is None


def test_invalid_archive_never_reaches_parser(tmp_path, monkeypatch):
    fixture = synthetic_audit_case(tmp_path / "case")
    export_fixture(fixture)
    altered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(fixture["package"]) as source, zipfile.ZipFile(altered, "w") as target:
        for member in source.infolist():
            raw = source.read(member)
            if member.filename.endswith("audit-raw.json"):
                raw = b'{"entries":[]}'
            target.writestr(member, raw)
    monkeypatch.setattr(audit, "normalize", lambda *a, **k: pytest.fail("unverified evidence reached parser"))
    result = verify_case(altered, fixture["public"], replay_transforms=True)
    assert not result["valid"] and result.get("reconstruction") is None


def test_replay_is_opt_in(tmp_path, monkeypatch):
    fixture = synthetic_audit_case(tmp_path / "case")
    export_fixture(fixture)
    monkeypatch.setattr(audit, "normalize", lambda *a, **k: pytest.fail("unexpected parser execution"))
    result = verify_case(fixture["package"], fixture["public"], include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "NOT_REQUESTED"


def test_cli_creates_compares_and_preserves_existing_evidence(tmp_path):
    source, output = tmp_path / "source.json", tmp_path / "projection.json"
    source.write_bytes(raw_entry())
    original = source.read_bytes()
    made = cli("--input", source, "--format", "entries", "--out", output)
    assert made.returncode == 0 and json.loads(made.stdout)["status"] == "NORMALIZED"
    checked = cli("--input", source, "--format", "entries", "--compare", output)
    assert checked.returncode == 0 and json.loads(checked.stdout)["status"] == "PASS"
    refused = cli("--input", source, "--format", "entries", "--out", source)
    assert refused.returncode == 1 and source.read_bytes() == original
    altered = json.loads(output.read_bytes())
    altered["entry_count"] = 99
    output.write_text(json.dumps(altered))
    failed = cli("--input", source, "--format", "entries", "--compare", output)
    assert failed.returncode == 1 and json.loads(failed.stdout)["status"] == "FAIL"


def test_case_cli_reports_integrity_valid_replay_failure_with_nonzero_exit(tmp_path):
    fixture = synthetic_audit_case(tmp_path / "case")
    fixture["output"]["entry_count"] = 99
    export_fixture(fixture)
    result = subprocess.run([sys.executable, str(ROOT / "replay_case_v17.py"), "--zip", str(fixture["package"]),
                             "--export-public-key", str(fixture["public"]), "--replay-transforms"],
                            capture_output=True, text=True, timeout=15)
    report = json.loads(result.stdout)
    assert result.returncode == 1 and report["valid"] and report["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


def test_cli_errors_do_not_disclose_content_paths_or_create_partial_output(tmp_path):
    source, output = tmp_path / "private-source.json", tmp_path / "missing.json"
    source.write_bytes(b'{"private-content":invalid}')
    result = cli("--input", source, "--format", "entries", "--out", output)
    assert result.returncode == 1 and not output.exists()
    assert not result.stderr and "private-content" not in result.stdout and str(tmp_path) not in result.stdout


def test_regular_file_read_respects_exact_byte_limit(tmp_path):
    source = tmp_path / "input.json"
    source.write_bytes(raw_entry())
    size = source.stat().st_size
    assert read_document(source, limit=size) == source.read_bytes()
    with pytest.raises(ValueError):
        read_document(source, limit=size - 1)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_fifo_input_is_rejected_promptly(tmp_path):
    path = tmp_path / "pipe"
    os.mkfifo(path)
    with pytest.raises(ValueError):
        read_document(path)


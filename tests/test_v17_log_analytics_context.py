"""Query context substitution, multi-input lineage, and offline hostile-input tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest

from case_export_v17 import verify_case
from v17_integrity import EvidenceRelationship, canonical_json_bytes, sha256_bytes, sha256_object
import v17_log_analytics_context as context
from v17_log_analytics import normalize as normalize_tables
from v17_log_analytics_context_selftest import (
    WORKSPACE, export_fixture, fixture_profile, synthetic_context, synthetic_context_case,
)
from v17_log_analytics_selftest import synthetic_response
from v17_provenance import wrap_record
from v17_provenance_selftest import CASE_ID, TIMESTAMP

ROOT = Path(__file__).resolve().parents[1]


def inputs(*, partial=False):
    raw = json.dumps(synthetic_response(partial=partial)).encode()
    return raw, synthetic_context(raw)


def project(raw, ctx):
    return context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="workspace-post")


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "log_analytics_context_v17.py"), *map(str, args)],
                          capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("partial", [False, True])
def test_signed_context_replay_is_offline_and_preserves_partial_results(tmp_path, monkeypatch, partial):
    fixture = synthetic_context_case(tmp_path / "case", partial=partial)
    export_fixture(fixture)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network, execution, or extraction")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    replay = result["reconstruction"]["deterministic_replay"]
    transform = replay["transforms"][0]
    assert result["valid"] and replay["status"] == "PASS" and transform["request_context_bound"]
    assert transform["collection_complete"] is (False if partial else None)
    assert transform["partial_error_recorded"] is partial and not transform["query_execution_verified"]
    assert not transform["source_authenticity_verified"] and not transform["request_scope_verified"]


def test_context_retains_separate_digests_and_existing_table_semantics_without_query_or_scope_content():
    raw, ctx = inputs()
    output = project(raw, ctx)
    assert output["result"] == normalize_tables(raw, input_format="tables")
    assert output["source_sha256"] == sha256_bytes(raw)
    assert output["context_sha256"] == sha256_bytes(canonical_json_bytes(ctx))
    assert output["request_sha256"] == sha256_object(ctx["request"])
    assert output["request"]["query_sha256"] == sha256_object(ctx["request"]["body"]["query"])
    rendered = json.dumps(output)
    for marker in ("SYNTHETIC-PRIVATE-QUERY", "SYNTHETIC-PRIVATE-REQUEST-ID", WORKSPACE, "PT12H", "wait=30"):
        assert marker not in rendered


@pytest.mark.parametrize("change", [
    lambda c: c["request"]["body"].update(query="AzureActivity | take 1"),
    lambda c: c["request"]["body"].update(timespan="PT1H"),
    lambda c: c["request"]["body"].pop("timespan"),
    lambda c: c["request"]["body"].update(workspaces=[WORKSPACE]),
    lambda c: c["request"].update(url=c["request"]["url"].replace(WORKSPACE, "00000000-0000-0000-0000-000000000099")),
    lambda c: c["request"]["headers"].update(prefer="wait=60"),
    lambda c: c["request"]["headers"].update({"x-ms-client-request-id": "different-client-request"}),
    lambda c: c["response"]["headers"].update({"x-ms-request-id": "different-response"}),
])
def test_validly_signed_context_substitution_fails_replay_even_with_unchanged_response(tmp_path, change):
    fixture = synthetic_context_case(tmp_path / "case")
    ctx = json.loads(fixture["context"])
    change(ctx)
    fixture["context"] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    assert result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


def test_recomputed_self_consistent_context_is_only_an_assertion_not_independent_scope_authentication():
    raw, ctx = inputs()
    ctx["request"]["body"]["query"] = "workspace('unlisted-resource').AzureActivity | where TimeGenerated > ago(1h)"
    output = project(raw, ctx)
    result = context.compare_replay(raw, canonical_json_bytes(output), context_raw=canonical_json_bytes(ctx), input_format="workspace-post")
    assert result["status"] == "PASS" and result["request_context_bound"]
    assert not result["request_scope_verified"] and not result["query_execution_verified"]
    assert output["context_source"] == "retained-assertion" and output["collection_complete"] is None


@pytest.mark.parametrize("key", ["timespan", "workspaces"])
def test_missing_optional_scope_is_distinct_from_present_and_never_filled_in(key):
    raw, ctx = inputs()
    before = project(raw, ctx)
    ctx["request"]["body"].pop(key)
    output = project(raw, ctx)
    assert output["request"][key] == {"state": "absent", "sha256": None}
    assert before["binding_sha256"] != output["binding_sha256"]


def test_workspace_order_duplicates_and_letter_case_are_preserved_without_scope_inference():
    raw, ctx = inputs()
    other = "ABCDEF00-0000-0000-0000-000000000002"
    values = [WORKSPACE, other, WORKSPACE, other.lower()]
    ctx["request"]["body"]["workspaces"] = values
    output = project(raw, ctx)
    assert output["request"]["additional_workspace_sha256"] == [sha256_object(v) for v in values]
    ctx["request"]["body"]["workspaces"].reverse()
    assert project(raw, ctx)["binding_sha256"] != output["binding_sha256"]


@pytest.mark.parametrize("host", ["api.loganalytics.io", "api.loganalytics.azure.com"])
def test_explicit_public_workspace_post_endpoints(host):
    raw, ctx = inputs()
    ctx["request"]["url"] = f"https://{host}/v1/workspaces/{WORKSPACE}/query"
    assert project(raw, ctx)["request"]["endpoint_host"] == host


@pytest.mark.parametrize("suffix", ["?timespan=PT1H", "#fragment", "/", "/../query", "?", "\n"])
def test_endpoint_variants_cannot_silently_add_scope_or_be_normalized(suffix):
    raw, ctx = inputs()
    ctx["request"]["url"] += suffix
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("url", [
    "http://api.loganalytics.io/v1/workspaces/ID/query", "https://evil.example.invalid/query",
    f"https://api.loganalytics.io@evil.example.invalid/v1/workspaces/{WORKSPACE}/query",
    f"https://user@api.loganalytics.io/v1/workspaces/{WORKSPACE}/query",
    f"https://api.loganalytics.io:443/v1/workspaces/{WORKSPACE}/query",
    f"https://API.LOGANALYTICS.IO/v1/workspaces/{WORKSPACE}/query",
    f"https://api.loganalytics.io/v2/workspaces/{WORKSPACE}/query",
    "https://api.loganalytics.io/v1/workspaces/not-a-guid/query",
    "https://api.loganalytics.io/v1/subscriptions/synthetic/query", None, [], 200,
])
def test_unimplemented_or_unsafe_endpoints_fail_closed(url):
    raw, ctx = inputs()
    ctx["request"]["url"] = url
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("status", [None, True, 200.0, "200", 0, 201, 204, 206, 400, 401, 403, 429, 500, {}, []])
def test_only_recorded_integer_http_200_supports_this_results_profile(status):
    raw, ctx = inputs()
    ctx["response"]["status"] = status
    with pytest.raises(ValueError):
        context.normalize(raw, context_raw=json.dumps(ctx).encode(), input_format="workspace-post")


@pytest.mark.parametrize("change", [
    lambda c: c.update(schema="different-schema"), lambda c: c.update(extra=True),
    lambda c: c.pop("response"), lambda c: c.update(request=[]), lambda c: c.update(response=None),
    lambda c: c["request"].update(method="GET"), lambda c: c["request"].update(method="post"),
    lambda c: c["request"].update(params={"timespan": "PT1H"}),
    lambda c: c["request"].pop("headers"), lambda c: c["request"].update(body=[]),
    lambda c: c["request"]["body"].pop("query"), lambda c: c["request"]["body"].update(options={}),
    lambda c: c["response"].update(collection_complete=True), lambda c: c["response"].pop("headers"),
])
def test_unsupported_context_fields_are_never_silently_discarded(change):
    raw, ctx = inputs()
    change(ctx)
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("section,key,value", [
    ("request", "authorization", "Bearer SYNTHETIC-SECRET"), ("request", "cookie", "SYNTHETIC-SECRET"),
    ("response", "set-cookie", "SYNTHETIC-SECRET"), ("request", "Prefer", "wait=30"),
    ("request", "content-type", "text/plain"), ("request", "content-type", "application/json; charset=utf-8"),
    ("request", "prefer", None), ("request", "prefer", []), ("request", "prefer", ""),
    ("request", "prefer", "wait=30\r\nAuthorization: secret"),
    ("response", "x-ms-request-id", "id\x00"), ("response", "x-ms-request-id", "x" * 4097),
])
def test_header_profile_rejects_credentials_unknown_keys_and_invalid_values(section, key, value):
    raw, ctx = inputs()
    ctx[section]["headers"][key] = value
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("key,value", [
    ("query", ""), ("query", " \n\t"), ("query", None), ("query", []), ("query", "query\x00"),
    ("query", "q" * 65537), ("query", "é" * 32769), ("query", "q\x7f"),
    ("timespan", None), ("timespan", []), ("timespan", ""), ("timespan", "\nPT1H"), ("timespan", "x" * 257),
    ("workspaces", None), ("workspaces", {}), ("workspaces", WORKSPACE), ("workspaces", [None]),
    ("workspaces", ["workspace-name"]), ("workspaces", [WORKSPACE] * 33),
])
def test_body_type_and_budget_failures_are_explicit(key, value):
    raw, ctx = inputs()
    ctx["request"]["body"][key] = value
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("query", ["q" * 65536, "é" * 32768, "// comment\r\nprint x='opaque'\t", "malformed KQL is still a retained string"])
def test_query_text_is_bounded_but_never_parsed_or_executed(query):
    raw, ctx = inputs()
    ctx["request"]["body"]["query"] = query
    assert project(raw, ctx)["request"]["query_sha256"] == sha256_object(query)


@pytest.mark.parametrize("workspaces", [[], [WORKSPACE] * 32])
def test_additional_workspace_list_boundaries(workspaces):
    raw, ctx = inputs()
    ctx["request"]["body"]["workspaces"] = workspaces
    assert len(project(raw, ctx)["request"]["additional_workspace_sha256"]) == len(workspaces)


@pytest.mark.parametrize("key,value", [("body_sha256", "0" * 64), ("body_sha256", None), ("body_sha256", []),
    ("body_size_bytes", 0), ("body_size_bytes", True), ("body_size_bytes", "100"), ("body_size_bytes", None)])
def test_response_pin_must_match_exact_bytes_and_size(key, value):
    raw, ctx = inputs()
    ctx["response"][key] = value
    with pytest.raises(ValueError):
        project(raw, ctx)


def test_response_digest_and_size_check_precedes_table_parser(monkeypatch):
    raw, ctx = inputs()
    ctx["response"]["body_sha256"] = "0" * 64
    monkeypatch.setattr(context, "normalize_tables", lambda *a, **k: pytest.fail("mismatched response reached parser"))
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("raw", [b'{"tables":[],"tables":[]}', b'{"tables":[],"error":{"code":"Fatal"}}',
    b'{"tables":[{"name":"x","columns":[],"rows":[]}]}', b'{}', b'[]'])
def test_matched_context_cannot_bypass_native_response_validation(raw):
    with pytest.raises(ValueError):
        project(raw, synthetic_context(raw))


@pytest.mark.parametrize("raw", [b'', b'{}', b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
    b'{"x":9007199254740992}', b'{"x":"\xff"}', b'{"x":"\\ud800"}', b'\xef\xbb\xbf{}', b'{} {}',
    b'{"x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}'])
def test_context_strict_json_and_depth_failures(raw):
    response, _ = inputs()
    with pytest.raises(ValueError):
        context.normalize(response, context_raw=raw, input_format="workspace-post")


def test_context_and_response_input_byte_budgets(monkeypatch):
    raw, ctx = inputs()
    encoded = canonical_json_bytes(ctx)
    monkeypatch.setattr(context, "MAX_CONTEXT_BYTES", len(encoded))
    assert context.normalize(raw, context_raw=encoded, input_format="workspace-post")
    with pytest.raises(ValueError):
        context.normalize(raw, context_raw=encoded + b' ', input_format="workspace-post")
    monkeypatch.setattr(context, "MAX_INPUT_BYTES", len(raw) - 1)
    with pytest.raises(ValueError):
        project(raw, ctx)


def test_output_expansion_cannot_bypass_limit(monkeypatch):
    raw, ctx = inputs()
    size = len(canonical_json_bytes(project(raw, ctx)))
    monkeypatch.setattr(context, "MAX_OUTPUT_BYTES", size - 1)
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("fmt", ["auto", "tables", "resource-post", "", None, [], True])
def test_format_is_explicit_and_fixed(fmt):
    raw, ctx = inputs()
    with pytest.raises(ValueError):
        context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format=fmt)


def test_exact_source_and_context_whitespace_are_bound_but_projection_whitespace_is_canonical():
    raw, ctx = inputs()
    output = project(raw, ctx)
    preserved = json.dumps(output, indent=2).encode()
    assert context.compare_replay(raw, preserved, context_raw=canonical_json_bytes(ctx), input_format="workspace-post")["status"] == "PASS"
    assert context.compare_replay(raw, preserved, context_raw=json.dumps(ctx, indent=2).encode(), input_format="workspace-post")["status"] == "FAIL"
    with pytest.raises(ValueError):
        context.compare_replay(raw + b' ', preserved, context_raw=canonical_json_bytes(ctx), input_format="workspace-post")
    ctx["response"].update(body_sha256=sha256_bytes(raw + b' '), body_size_bytes=len(raw) + 1)
    assert context.compare_replay(raw + b' ', preserved, context_raw=canonical_json_bytes(ctx), input_format="workspace-post")["status"] == "FAIL"


@pytest.mark.parametrize("preserved", [b'{"x":1,"x":2}', b'{"x":Infinity}', b'{"x":"\\ud800"}'])
def test_preserved_output_uses_strict_bounded_json(preserved):
    raw, ctx = inputs()
    with pytest.raises(ValueError):
        context.compare_replay(raw, preserved, context_raw=canonical_json_bytes(ctx), input_format="workspace-post")


@pytest.mark.parametrize("change", [
    lambda o: o.update(request_scope_verified=True), lambda o: o.update(query_execution_verified=True),
    lambda o: o.update(collection_complete=True), lambda o: o.update(context_sha256="0" * 64),
    lambda o: o["result"].update(row_count=99), lambda o: o["request"].update(query_sha256="0" * 64),
])
def test_incorrect_signed_projection_fails_independently_of_integrity(tmp_path, change):
    fixture = synthetic_context_case(tmp_path / "case")
    change(fixture["output"])
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("metadata", [{}, {"input_format": "workspace-post"},
    {"input_format": "tables", "context_artifact_id": "QUERY-CONTEXT"},
    {"input_format": "workspace-post", "context_artifact_id": "QUERY-CONTEXT", "command": "execute"},
    *[{"input_format": "workspace-post", "context_artifact_id": ref} for ref in
      (None, [], 1, "missing", "QUERY-RAW", "QUERY-PROJECTION", "../../query-context.json")]])
def test_missing_ambiguous_or_unbound_context_reference_rejects_case_export(tmp_path, metadata):
    fixture = synthetic_context_case(tmp_path / "case")
    fixture["metadata"] = metadata
    with pytest.raises(ValueError):
        export_fixture(fixture)
    assert not fixture["package"].exists()


def test_context_reference_must_be_a_bound_artifact_not_a_relationship(tmp_path):
    fixture = synthetic_context_case(tmp_path / "case")
    profile = fixture_profile(fixture)
    fixture["metadata"]["context_artifact_id"] = profile["relationships"][0]["record_hash"]
    with pytest.raises(ValueError):
        export_fixture(fixture)


def test_context_as_a_second_input_participates_in_lineage_cycle_detection(tmp_path):
    fixture = synthetic_context_case(tmp_path / "case")
    profile = fixture_profile(fixture)
    relation = EvidenceRelationship(case_id=CASE_ID, parent_artifact_id="QUERY-PROJECTION", child_artifact_id="QUERY-CONTEXT",
                                    relationship_type="derived-from", transformation="unimplemented", transformation_version="1",
                                    created_at=TIMESTAMP, metadata={})
    profile["relationships"].append(wrap_record("relationships", relation))
    with pytest.raises(ValueError, match="cyclic"):
        export_fixture(fixture, profile=profile)


def test_unknown_version_is_incomplete_and_never_executes_parser(tmp_path, monkeypatch):
    fixture = synthetic_context_case(tmp_path / "case")
    fixture["version"] = "999"
    export_fixture(fixture)
    monkeypatch.setattr(context, "normalize", lambda *a, **k: pytest.fail("unknown transform executed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("member", ["query-context.json", "query-raw.json", "query-projection.json"])
def test_unverified_archive_content_never_reaches_context_parser(tmp_path, monkeypatch, member):
    fixture = synthetic_context_case(tmp_path / "case")
    export_fixture(fixture)
    altered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(fixture["package"]) as source, zipfile.ZipFile(altered, "w") as target:
        for item in source.infolist():
            target.writestr(item, b'{}' if item.filename.endswith(member) else source.read(item))
    monkeypatch.setattr(context, "normalize", lambda *a, **k: pytest.fail("unverified input reached parser"))
    result = verify_case(altered, fixture["public"], replay_transforms=True)
    assert not result["valid"] and result.get("reconstruction") is None


@pytest.mark.parametrize("gate", ["require_checkpoint_timestamp", "require_authenticated_key_policy"])
def test_required_independent_gates_block_reconstruction(tmp_path, gate):
    fixture = synthetic_context_case(tmp_path / "case")
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True, **{gate: True})
    assert not result["valid"] and result.get("reconstruction") is None


def test_replay_remains_opt_in(tmp_path, monkeypatch):
    fixture = synthetic_context_case(tmp_path / "case")
    export_fixture(fixture)
    monkeypatch.setattr(context, "normalize", lambda *a, **k: pytest.fail("unexpected replay"))
    result = verify_case(fixture["package"], fixture["public"], include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "NOT_REQUESTED"


@pytest.mark.parametrize("partial", [False, True])
def test_cli_create_compare_and_mismatch_are_explicit(tmp_path, partial):
    raw, ctx = inputs(partial=partial)
    source, capture, output = [tmp_path / name for name in ("source.json", "context.json", "projection.json")]
    source.write_bytes(raw)
    capture.write_bytes(canonical_json_bytes(ctx))
    args = ("--input", source, "--context", capture, "--format", "workspace-post")
    made = cli(*args, "--out", output)
    report = json.loads(made.stdout)
    assert made.returncode == 0 and report["status"] == "NORMALIZED" and report["partial_error_recorded"] is partial
    compared = cli(*args, "--compare", output)
    assert compared.returncode == 0 and json.loads(compared.stdout)["status"] == "PASS"
    assert report["collection_complete"] is (False if partial else None)
    ctx["request"]["body"]["query"] += " | take 1"
    capture.write_bytes(canonical_json_bytes(ctx))
    failed = cli(*args, "--compare", output)
    assert failed.returncode == 1 and json.loads(failed.stdout)["status"] == "FAIL"


def test_cli_preserves_response_context_existing_output_and_symlink_target(tmp_path):
    raw, ctx = inputs()
    source, capture, output, link = [tmp_path / name for name in ("source.json", "context.json", "output.json", "link.json")]
    source.write_bytes(raw)
    capture.write_bytes(canonical_json_bytes(ctx))
    output.write_bytes(b'existing')
    link.symlink_to(capture)
    for target in (source, capture, output, link):
        assert cli("--input", source, "--context", capture, "--format", "workspace-post", "--out", target).returncode == 1
    assert source.read_bytes() == raw and capture.read_bytes() == canonical_json_bytes(ctx)
    assert output.read_bytes() == b'existing' and link.is_symlink()


def test_cli_rejects_invalid_context_without_disclosing_content_or_creating_output(tmp_path):
    raw, ctx = inputs()
    ctx["request"]["headers"]["authorization"] = "Bearer SYNTHETIC-SECRET"
    source, capture, output = [tmp_path / name for name in ("source.json", "private.json", "out.json")]
    source.write_bytes(raw)
    capture.write_bytes(canonical_json_bytes(ctx))
    result = cli("--input", source, "--context", capture, "--format", "workspace-post", "--out", output)
    assert result.returncode == 1 and not output.exists() and not result.stderr
    assert "SYNTHETIC-SECRET" not in result.stdout and str(tmp_path) not in result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_cli_rejects_fifo_context_without_blocking(tmp_path):
    raw, _ = inputs()
    source, capture = tmp_path / "source.json", tmp_path / "pipe"
    source.write_bytes(raw)
    os.mkfifo(capture)
    assert cli("--input", source, "--context", capture, "--format", "workspace-post", "--out", tmp_path / "out").returncode == 1


def test_case_cli_reports_valid_integrity_and_failed_context_replay_with_exit_one(tmp_path):
    fixture = synthetic_context_case(tmp_path / "case")
    fixture["output"]["request_scope_verified"] = True
    export_fixture(fixture)
    result = subprocess.run([sys.executable, str(ROOT / "replay_case_v17.py"), "--zip", str(fixture["package"]),
                             "--export-public-key", str(fixture["public"]), "--replay-transforms"],
                            capture_output=True, text=True, timeout=15)
    report = json.loads(result.stdout)
    assert result.returncode == 1 and report["valid"] and report["reconstruction"]["deterministic_replay"]["status"] == "FAIL"

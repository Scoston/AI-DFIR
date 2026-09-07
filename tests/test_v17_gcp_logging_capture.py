"""Google Cloud request binding, acquisition boundaries, and signed replay."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest
import requests
from urllib3.response import HTTPResponse
from urllib3.exceptions import ReadTimeoutError

import provider_collectors_v15 as collectors
import v17_gcp_audit as audit
import v17_gcp_logging_capture as acquisition
import v17_gcp_logging_context as context
import v17_log_analytics_capture as capture_io
from case_export_v17 import verify_case
from v17_gcp_logging_capture_selftest import synthetic_context, synthetic_logging_case, synthetic_params, synthetic_response
from v17_integrity import EvidenceRelationship, canonical_json_bytes, sha256_bytes
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter
from v17_log_analytics_context_selftest import export_fixture, fixture_profile
from v17_provenance import ProvenanceError, wrap_record
from v17_provenance_selftest import CASE_ID, TIMESTAMP


@pytest.fixture(autouse=True)
def no_live_requests(monkeypatch):
    monkeypatch.setenv(acquisition.TOKEN_ENV, SYNTHETIC_TOKEN)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected live network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def install(monkeypatch, *, continuation=False, empty=False, raw=None, status=200, headers=None):
    raw = json.dumps(synthetic_response(continuation=continuation, empty=empty), indent=3).encode() + b'\n' if raw is None else raw
    adapter = synthetic_adapter(raw, status=status, headers={"x-goog-request-id": "SYNTHETIC-REQUEST", **(headers or {})})
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    return raw, adapter


def capture(tmp_path, params=None):
    return acquisition.capture(json.dumps(synthetic_params() if params is None else params).encode(), tmp_path / "capture")


def inputs():
    raw = canonical_json_bytes(synthetic_response())
    return raw, synthetic_context(raw)


@pytest.mark.parametrize("continuation", [False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_capture_exact_bytes_actual_request_and_incomplete_pagination(tmp_path, monkeypatch, continuation, empty):
    raw, adapter = install(monkeypatch, continuation=continuation, empty=empty, headers={"Set-Cookie": SYNTHETIC_TOKEN})
    receipt = capture(tmp_path)
    folder = tmp_path / "capture"
    ctx = json.loads((folder / "context.json").read_bytes())
    assert (folder / "response.json").read_bytes() == raw
    assert ctx["request"]["body"] == json.loads(adapter.sent[0][0].body) == synthetic_params()
    assert ctx["request"]["url"] == adapter.sent[0][0].url == context.ENDPOINT
    assert ctx["request"]["headers"] == {"content-type": "application/json"}
    assert ctx["response"]["headers"] == {"content-type": "application/json", "x-goog-request-id": "SYNTHETIC-REQUEST"}
    assert ctx["response"]["body_sha256"] == sha256_bytes(raw) and ctx["response"]["body_size_bytes"] == len(raw)
    assert receipt["status"] == "CAPTURED" and receipt["artifact_set_complete"] and receipt["pages_observed"] == 1
    assert receipt["entry_count"] == (0 if empty else 1) and receipt["continuation_token_present"] is continuation
    assert receipt["collection_complete"] is (False if continuation else None)
    assert not any(receipt[key] for key in ("source_authenticity_verified", "request_scope_verified", "query_execution_verified", "pagination_chain_verified"))
    assert json.loads((folder / "receipt.json").read_bytes()) == receipt
    assert not (folder / "receipt.pending.json").exists()
    for item in receipt["files"]:
        retained = (folder / item["path"]).read_bytes()
        assert item["sha256"] == sha256_bytes(retained) and item["size_bytes"] == len(retained)
    assert SYNTHETIC_TOKEN not in (folder / "context.json").read_text()
    for private in ("SYNTHETIC-PRIVATE-PAGE", "SYNTHETIC-PRIVATE-NEXT", "cloudaudit.googleapis.com"):
        assert private not in json.dumps(receipt)
    assert len(adapter.sent) == 1 and adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize("continuation", [False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_captured_signed_case_replays_without_network_process_or_extraction(tmp_path, monkeypatch, continuation, empty):
    install(monkeypatch, continuation=continuation, empty=empty)
    capture(tmp_path)
    fixture = synthetic_logging_case(tmp_path / "case", capture_dir=tmp_path / "capture")
    export_fixture(fixture)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected execution during offline replay")
    monkeypatch.setattr(acquisition, "capture", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    transform = result["reconstruction"]["deterministic_replay"]["transforms"][0]
    assert result["valid"] and transform["status"] == "PASS" and transform["request_context_bound"]
    assert transform["collection_complete"] is (False if continuation else None)
    assert not transform["query_reexecuted"] and not transform["pagination_chain_verified"]


@pytest.mark.parametrize("key,value", [
    ("resourceNames", ["projects/different-source"]), ("resourceNames", list(reversed(synthetic_params()["resourceNames"]))),
    ("resourceNames", synthetic_params()["resourceNames"] * 2), ("filter", "severity>=ERROR"),
    ("orderBy", "timestamp asc"), ("pageSize", 1), ("pageToken", "changed-token"),
])
def test_resigned_valid_request_substitution_fails_replay(tmp_path, key, value):
    fixture = synthetic_logging_case(tmp_path / "case")
    ctx = json.loads(fixture["context"])
    ctx["request"]["body"][key] = value
    fixture["context"] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("target", ["response", "response-header", "request-header", "projection", "continuation"])
def test_resigned_response_or_projection_substitutions_fail_replay(tmp_path, target):
    fixture = synthetic_logging_case(tmp_path / "case")
    ctx = json.loads(fixture["context"])
    if target in ("response", "continuation"):
        doc = json.loads(fixture["raw"])
        if target == "response": doc["entries"][0]["protoPayload"]["methodName"] = "different.method"
        else: doc["nextPageToken"] = "new-token"
        fixture["raw"] = canonical_json_bytes(doc)
        ctx["response"].update(body_sha256=sha256_bytes(fixture["raw"]), body_size_bytes=len(fixture["raw"]))
    elif target == "response-header": ctx["response"]["headers"]["x-goog-request-id"] = "different"
    elif target == "request-header": ctx["request"]["headers"]["content-type"] = "text/plain"
    else: fixture["output"]["result"]["entries"][0]["authorizations"][1]["granted"] = True
    fixture["context"] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("root", ["projects/synthetic-project", "organizations/1234", "folders/5678", "billingAccounts/AAAAAA-BBBBBB-CCCCCC"])
@pytest.mark.parametrize("suffix", ["", "/locations/us-central1/buckets/_Default/views/_AllLogs"])
def test_supported_resource_containers_and_views_remain_unverified_assertions(root, suffix):
    raw, ctx = inputs()
    ctx["request"]["body"]["resourceNames"] = [root + suffix, root + suffix]
    result = context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")
    assert result["request"]["resource_count"] == 2
    assert result["request"]["ordered_resource_sha256"][0] == result["request"]["ordered_resource_sha256"][1]
    assert not result["request_scope_verified"] and not result["query_execution_verified"]


@pytest.mark.parametrize("name", ["", "projects/", "projects/..", "projects/.", "projects/a/../b", "projects/a/", "/projects/a", "https://other.invalid", "PROJECTS/a", "projects/a%2Fb", "projects/a?x=y", "projects/a#x", "projects/a\\b", "projects/a b", "projects/é", "projects/" + "a" * 257, "projects/a/locations/x/buckets/b", "projects/a/locations/../buckets/b/views/v"])
def test_unsupported_resource_names_fail_before_acquisition(tmp_path, monkeypatch, name):
    _, adapter = install(monkeypatch)
    params = synthetic_params(); params["resourceNames"] = [name]
    with pytest.raises(acquisition.CaptureError): capture(tmp_path, params)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("key,value", [
    ("resourceNames", None), ("resourceNames", []), ("resourceNames", "projects/a"), ("resourceNames", [None]),
    ("resourceNames", ["projects/a"] * 33), ("filter", None), ("filter", []), ("filter", "x\x00"),
    ("filter", "x" * 20001), ("orderBy", None), ("orderBy", []), ("orderBy", "timestamp ASC"),
    ("pageSize", None), ("pageSize", True), ("pageSize", 0), ("pageSize", -1), ("pageSize", 1001), ("pageSize", 1.0),
    ("pageSize", "10"), ("pageToken", None), ("pageToken", []), ("pageToken", "x" * 4097), ("pageToken", "x\r\n"),
    ("projectIds", ["projects/a"]), ("token", SYNTHETIC_TOKEN), ("url", "https://other.invalid"),
    ("headers", {"Authorization": "private"}), ("max_pages", 2), ("command", "run"),
])
def test_invalid_or_unsupported_body_fields_fail_before_network(tmp_path, monkeypatch, key, value):
    _, adapter = install(monkeypatch)
    params = synthetic_params(); params[key] = value
    with pytest.raises(acquisition.CaptureError): capture(tmp_path, params)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("field,empty", [("filter", ""), ("pageToken", "")])
def test_absent_and_empty_parameters_are_distinct_without_invented_defaults(field, empty):
    raw, ctx = inputs(); ctx["request"]["body"].pop(field)
    absent = context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")
    ctx["request"]["body"][field] = empty
    present = context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")
    assert absent["request"][field]["state"] == "absent" and present["request"][field]["state"] == "present"
    assert absent["binding_sha256"] != present["binding_sha256"]


def test_minimal_body_and_maximum_supported_parameters():
    raw, ctx = inputs(); ctx["request"]["body"] = {"resourceNames": ["projects/a"]}
    result = context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")
    assert all(result["request"][key]["state"] == "absent" for key in ("filter", "orderBy", "pageSize", "pageToken"))
    ctx["request"]["body"].update(resourceNames=["projects/a"] * 32, filter="é" * 20000, pageSize=1000, pageToken="x" * 4096)
    context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")


@pytest.mark.parametrize("change", [
    lambda c: c.update(schema="other"), lambda c: c.update(extra=True), lambda c: c.pop("response"),
    lambda c: c["request"].update(method="GET"), lambda c: c["request"].update(url="http://logging.googleapis.com/v2/entries:list"),
    lambda c: c["request"].update(url=context.ENDPOINT + "?key=secret"),
    lambda c: c["request"].update(url=context.ENDPOINT + "/"),
    lambda c: c["request"].update(url="https://logging.googleapis.com:443/v2/entries:list"),
    lambda c: c["request"].update(url="https://logging.googleapis.com.other.invalid/v2/entries:list"),
    lambda c: c["request"]["headers"].update(authorization="Bearer PRIVATE"),
    lambda c: c["request"]["headers"].update(**{"content-type": "application/json; charset=utf-8"}),
    lambda c: c["request"].update(headers={}), lambda c: c["request"].update(body=None),
    lambda c: c["response"].update(status=True), lambda c: c["response"].update(status=201),
    lambda c: c["response"].update(status="200"), lambda c: c["response"].update(body_size_bytes=True),
    lambda c: c["response"].update(body_size_bytes=0), lambda c: c["response"].update(body_sha256="0" * 64),
    lambda c: c["response"].update(body_sha256=None), lambda c: c["response"]["headers"].update(cookie="private"),
    lambda c: c["response"]["headers"].update(**{"x-goog-request-id": "x\x7f"}),
    lambda c: c["response"]["headers"].update(**{"x-goog-request-id": "x" * 4097}),
])
def test_invalid_context_rejects_before_response_parser(monkeypatch, change):
    raw, ctx = inputs(); change(ctx)
    monkeypatch.setattr(context, "normalize_audit", lambda *a, **k: pytest.fail("invalid binding reached audit parser"))
    with pytest.raises(ProvenanceError): context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")


@pytest.mark.parametrize("raw", [b"", b"[]", b"null", b"{}", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}',
    b'{"a":9007199254740992}', b'{"a":"\\ud800"}', b'\xff', b'{} {}', b' ' * (128 * 1024 + 1)])
def test_strict_bounded_parameter_documents_fail_before_output(tmp_path, monkeypatch, raw):
    _, adapter = install(monkeypatch)
    with pytest.raises(acquisition.CaptureError): acquisition.capture(raw, tmp_path / "capture")
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("format", ["entries", "workspace-post", "array", "", None, []])
def test_unknown_context_profile_fails(format):
    raw, ctx = inputs()
    with pytest.raises(ProvenanceError): context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format=format)


@pytest.mark.parametrize("budget", ["MAX_CONTEXT_BYTES", "MAX_OUTPUT_BYTES", "MAX_INPUT_BYTES"])
def test_context_byte_budgets_are_enforced(monkeypatch, budget):
    raw, ctx = inputs(); monkeypatch.setattr(context, budget, 32)
    with pytest.raises(ProvenanceError): context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")


@pytest.mark.parametrize("budget", ["MAX_DEPTH", "MAX_NODES", "MAX_ENTRIES", "MAX_ENTRY_BYTES"])
def test_audit_structure_and_entry_budgets_are_preserved(monkeypatch, budget):
    raw, ctx = inputs(); monkeypatch.setattr(audit, budget, 0)
    with pytest.raises(ProvenanceError): context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="entries-list")


def test_direct_transport_has_explicit_tls_and_no_ambient_credentials(tmp_path, monkeypatch):
    _, adapter = install(monkeypatch)
    for key, value in (("HTTPS_PROXY", "https://proxy.invalid"), ("REQUESTS_CA_BUNDLE", "/private/ca"), ("NETRC", "/private/netrc")):
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(requests.sessions.Session, "send", lambda *a, **k: pytest.fail("ambient Session used"))
    capture(tmp_path)
    prepared, options = adapter.sent[0]
    assert options == {"stream": True, "timeout": (10, 45), "verify": True, "cert": None, "proxies": {}}
    assert prepared.headers["Authorization"] == "Bearer " + SYNTHETIC_TOKEN
    assert prepared.headers["Accept-Encoding"] == "identity" and "Cookie" not in prepared.headers
    assert prepared.method == "POST" and prepared.url == context.ENDPOINT


def test_real_adapter_disables_redirects_and_preloading_before_bounded_read(tmp_path, monkeypatch):
    calls = []; body = io.BytesIO(b"x" * 1000)
    class Pool:
        def urlopen(self, **kwargs):
            calls.append(kwargs)
            return HTTPResponse(body=body, status=302, headers={"Location": "https://other.invalid"}, preload_content=False, decode_content=False)
    pool = Pool()
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "get_connection_with_tls_context", lambda *a, **k: pool)
    monkeypatch.setattr(capture_io, "MAX_INPUT_BYTES", 32)
    with pytest.raises(acquisition.CaptureError): capture(tmp_path)
    assert len(calls) == 1 and calls[0]["redirect"] is False and calls[0]["preload_content"] is False
    assert calls[0]["decode_content"] is False and calls[0]["retries"].total == 0 and pool.cert_reqs == "CERT_REQUIRED"
    assert not (tmp_path / "capture/receipt.json").exists() and body.closed


@pytest.mark.parametrize("change", [
    lambda r: setattr(r, "url", "https://other.invalid"), lambda r: setattr(r, "history", [object()]),
    lambda r: setattr(r.request, "method", "GET"), lambda r: setattr(r.request, "url", "https://other.invalid"),
    lambda r: setattr(r.request, "body", b'{"resourceNames":["projects/different"]}'),
    lambda r: r.request.headers.update({"content-type": "text/plain"}),
    lambda r: setattr(r, "status_code", True), lambda r: setattr(r, "status_code", 600),
])
def test_changed_observed_request_or_invalid_status_never_publishes_receipt(tmp_path, monkeypatch, change):
    _, adapter = install(monkeypatch); send = adapter.send
    def changed(self, prepared, **kwargs):
        response = send(self, prepared, **kwargs); change(response); return response
    monkeypatch.setattr(adapter, "send", changed)
    with pytest.raises(acquisition.CaptureError): capture(tmp_path)
    assert not (tmp_path / "capture/receipt.json").exists() and adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize("status", [204, 301, 302, 307, 400, 401, 403, 429, 500])
def test_http_failures_preserve_bounded_observations_without_following_or_replay_claims(tmp_path, monkeypatch, status):
    raw, adapter = install(monkeypatch, raw=b'{"error":{"code":7,"message":"PRIVATE"}}', status=status)
    result = capture(tmp_path)
    assert result["status"] == "FAILED" and not result["artifact_set_complete"] and result["collection_complete"] is False
    assert (tmp_path / "capture/response.json").read_bytes() == raw and len(adapter.sent) == 1
    observation = json.loads((tmp_path / "capture/capture-observation.json").read_bytes())
    assert observation["schema"] == acquisition.OBSERVATION_SCHEMA and not observation["replay_context_available"]
    assert not (tmp_path / "capture/context.json").exists() and not (tmp_path / "capture/projection.json").exists()
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("raw,complete,error", [
    (b"", None, None), (b"not-json", None, None), (b'\xff', None, None),
    (b'{"entries":[],"entries":[]}', None, None), (b'{"entries":[],"error":null}', False, True),
    (b'{"entries":[{"textPayload":"PRIVATE"}]}', None, False), (b'{"entries":[],"nextPageToken":{}}', None, False),
    (b'{"nextPageToken":null}', None, False),
])
def test_unsupported_responses_preserve_bytes_without_compatible_context(tmp_path, monkeypatch, raw, complete, error):
    install(monkeypatch, raw=raw); receipt = capture(tmp_path)
    assert receipt["status"] == "FAILED" and receipt["collection_complete"] is complete
    assert receipt["response_error_recorded"] is error and not receipt["request_context_bound"]
    assert (tmp_path / "capture/response.json").read_bytes() == raw
    assert not (tmp_path / "capture/projection.json").exists()


@pytest.mark.parametrize("raw", [b'{}', b'{"entries":[]}', b'{"entries":[],"nextPageToken":""}'])
def test_supported_empty_pages_without_continuation_stay_unknown(tmp_path, monkeypatch, raw):
    install(monkeypatch, raw=raw); result = capture(tmp_path)
    assert result["status"] == "CAPTURED" and result["entry_count"] == 0 and result["collection_complete"] is None


@pytest.mark.parametrize("field", ["filter", "pageToken", "resourceNames"])
def test_configured_credential_cannot_enter_retained_request(tmp_path, monkeypatch, field):
    _, adapter = install(monkeypatch); params = synthetic_params()
    params[field] = ["projects/" + SYNTHETIC_TOKEN] if field == "resourceNames" else "prefix-" + SYNTHETIC_TOKEN
    with pytest.raises(acquisition.CaptureError) as exc: capture(tmp_path, params)
    assert SYNTHETIC_TOKEN not in str(exc.value) and not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("token", ["", "bad token", "bad\r\nHeader", "é", "x" * 16385])
def test_missing_or_invalid_credential_fails_before_acquisition(tmp_path, monkeypatch, token):
    _, adapter = install(monkeypatch); monkeypatch.setenv(acquisition.TOKEN_ENV, token)
    with pytest.raises(acquisition.CaptureError): capture(tmp_path)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("name,value", [("x-goog-request-id", SYNTHETIC_TOKEN), ("x-request-id", "x" * 4097),
    ("x-goog-request-id", "x\x00"), ("Content-Type", "x\r\nheader")])
def test_unsafe_selected_headers_fail_without_artifacts(tmp_path, monkeypatch, name, value):
    _, adapter = install(monkeypatch, headers={name: value})
    with pytest.raises(acquisition.CaptureError): capture(tmp_path)
    assert list((tmp_path / "capture").iterdir()) == [] and adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "identity,gzip", ""])
def test_compressed_response_is_never_implicitly_decoded(tmp_path, monkeypatch, encoding):
    _, adapter = install(monkeypatch, headers={"Content-Encoding": encoding})
    with pytest.raises(acquisition.CaptureError): capture(tmp_path)
    assert not (tmp_path / "capture/receipt.json").exists() and adapter.response.raw.closed


@pytest.mark.parametrize("length", ["-1", "+1", "1.0", "1, 1", "99999999999", str(8 * 1024 * 1024 + 1), ""])
def test_invalid_length_rejects_before_stream_read(tmp_path, monkeypatch, length):
    _, adapter = install(monkeypatch, headers={"Content-Length": length}); send = adapter.send
    def unread(self, prepared, **kwargs):
        response = send(self, prepared, **kwargs)
        response.raw.read = lambda *a, **k: pytest.fail("read before length validation")
        return response
    monkeypatch.setattr(adapter, "send", unread)
    with pytest.raises(acquisition.CaptureError): capture(tmp_path)
    assert adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize("kind", ["short", "long", "oversize", "wrong-type", "timeout"])
def test_stream_failures_never_publish_success_and_release_resources(tmp_path, monkeypatch, kind):
    raw, adapter = install(monkeypatch); send = adapter.send
    def altered(self, prepared, **kwargs):
        response = send(self, prepared, **kwargs)
        if kind in ("short", "long"): response.headers["Content-Length"] = str(len(raw) + (-1 if kind == "short" else 1))
        else:
            response.headers.pop("Content-Length")
            if kind == "oversize": monkeypatch.setattr(capture_io, "MAX_INPUT_BYTES", 32)
            elif kind == "wrong-type": response.raw.read = lambda *a, **k: "not-bytes"
            else:
                def failed(*a, **k): raise ReadTimeoutError(None, context.ENDPOINT, "PRIVATE")
                response.raw.read = failed
        return response
    monkeypatch.setattr(adapter, "send", altered)
    with pytest.raises(acquisition.CaptureError) as exc: capture(tmp_path)
    assert "PRIVATE" not in str(exc.value) and not (tmp_path / "capture/receipt.json").exists()
    assert adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_existing_output_sets_and_symlinks_are_preserved_before_network(tmp_path, monkeypatch, kind):
    _, adapter = install(monkeypatch); destination = tmp_path / "capture"
    if kind == "directory": destination.mkdir(); (destination / "existing").write_text("keep")
    elif kind == "file": destination.write_text("keep")
    else:
        target = tmp_path / "target"; target.mkdir(); (target / "existing").write_text("keep"); destination.symlink_to(target)
    with pytest.raises(acquisition.CaptureError): capture(tmp_path)
    assert not adapter.sent
    assert (destination if kind == "file" else destination / "existing").read_text() == "keep"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics")
def test_new_directory_and_files_are_private(tmp_path, monkeypatch):
    install(monkeypatch); capture(tmp_path); folder = tmp_path / "capture"
    assert folder.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in folder.iterdir())


@pytest.mark.parametrize("member", ["response.json", "context.json", "projection.json", "receipt.pending.json"])
def test_failed_member_write_never_publishes_a_success_receipt(tmp_path, monkeypatch, member):
    install(monkeypatch); real_open = os.open
    def failed(path, *args, **kwargs):
        if Path(path).name == member: raise OSError("PRIVATE-OUTPUT-FAILURE")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(os, "open", failed)
    with pytest.raises(acquisition.CaptureError) as exc: capture(tmp_path)
    assert "PRIVATE" not in str(exc.value) and not (tmp_path / "capture/receipt.json").exists()


@pytest.mark.parametrize("stage", ["send", "read", "receipt"])
def test_interrupt_does_not_claim_success_and_closes_started_transport(tmp_path, monkeypatch, stage):
    _, adapter = install(monkeypatch); send = adapter.send
    def interrupt(*args, **kwargs): raise KeyboardInterrupt
    if stage == "send": monkeypatch.setattr(adapter, "send", interrupt)
    elif stage == "read":
        def changed(self, prepared, **kwargs):
            response = send(self, prepared, **kwargs); response.raw.read = interrupt; return response
        monkeypatch.setattr(adapter, "send", changed)
    else: monkeypatch.setattr(acquisition, "_publish_receipt", interrupt)
    with pytest.raises(KeyboardInterrupt): capture(tmp_path)
    assert not (tmp_path / "capture/receipt.json").exists() and adapter.closed
    if adapter.response is not None: assert adapter.response.raw.closed


@pytest.mark.parametrize("metadata", [{}, {"input_format": "entries-list"},
    {"input_format": "entries", "context_artifact_id": "QUERY-CONTEXT"},
    {"input_format": "entries-list", "context_artifact_id": "QUERY-CONTEXT", "command": "run"},
    *[{"input_format": "entries-list", "context_artifact_id": ref} for ref in (None, [], 1, "missing", "QUERY-RAW", "QUERY-PROJECTION", "../query-context.json")]])
def test_missing_or_unbound_context_rejects_signed_export(tmp_path, metadata):
    fixture = synthetic_logging_case(tmp_path / "case"); fixture["metadata"] = metadata
    with pytest.raises(ValueError): export_fixture(fixture)
    assert not fixture["package"].exists()


def test_context_is_a_second_input_in_lineage_cycle_detection(tmp_path):
    fixture = synthetic_logging_case(tmp_path / "case"); profile = fixture_profile(fixture)
    relation = EvidenceRelationship(case_id=CASE_ID, parent_artifact_id="QUERY-PROJECTION", child_artifact_id="QUERY-CONTEXT",
                                    relationship_type="derived-from", transformation="unimplemented", transformation_version="1",
                                    created_at=TIMESTAMP, metadata={})
    profile["relationships"].append(wrap_record("relationships", relation))
    with pytest.raises(ValueError, match="cyclic"): export_fixture(fixture, profile=profile)


def test_unknown_version_never_executes_parser(tmp_path, monkeypatch):
    fixture = synthetic_logging_case(tmp_path / "case"); fixture["version"] = "999"; export_fixture(fixture)
    monkeypatch.setattr(context, "normalize", lambda *a, **k: pytest.fail("unknown version executed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("member", ["query-context.json", "query-raw.json", "query-projection.json"])
def test_unverified_archive_content_never_reaches_parser(tmp_path, monkeypatch, member):
    fixture = synthetic_logging_case(tmp_path / "case"); export_fixture(fixture); altered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(fixture["package"]) as source, zipfile.ZipFile(altered, "w") as target:
        for item in source.infolist(): target.writestr(item, b'{}' if item.filename.endswith(member) else source.read(item))
    monkeypatch.setattr(context, "normalize", lambda *a, **k: pytest.fail("unverified input reached parser"))
    result = verify_case(altered, fixture["public"], replay_transforms=True)
    assert not result["valid"] and result.get("reconstruction") is None


def test_replay_remains_opt_in(tmp_path, monkeypatch):
    fixture = synthetic_logging_case(tmp_path / "case"); export_fixture(fixture)
    monkeypatch.setattr(context, "normalize", lambda *a, **k: pytest.fail("unrequested replay"))
    result = verify_case(fixture["package"], fixture["public"], include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "NOT_REQUESTED"


def cli(*args):
    return subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "gcp_logging_context_v17.py"),
                           *map(str, args)], capture_output=True, text=True, timeout=15)


def test_context_cli_create_compare_mismatch_and_opaque_summary(tmp_path):
    raw, ctx = inputs(); source, retained, output = [tmp_path / name for name in ("raw.json", "context.json", "out.json")]
    source.write_bytes(raw); retained.write_bytes(canonical_json_bytes(ctx))
    args = ("--input", source, "--context", retained, "--format", "entries-list")
    result = cli(*args, "--out", output)
    assert result.returncode == 0 and json.loads(result.stdout)["status"] == "NORMALIZED"
    assert "SYNTHETIC-PRIVATE-PAGE" not in result.stdout and json.loads(result.stdout)["collection_complete"] is None
    assert cli(*args, "--compare", output).returncode == 0
    ctx["request"]["body"]["filter"] = ""; retained.write_bytes(canonical_json_bytes(ctx))
    result = cli(*args, "--compare", output)
    assert result.returncode == 1 and json.loads(result.stdout)["status"] == "FAIL"


def test_context_cli_preserves_inputs_existing_output_and_symlink(tmp_path):
    raw, ctx = inputs(); source, retained, output, link = [tmp_path / name for name in ("raw.json", "context.json", "out.json", "link.json")]
    source.write_bytes(raw); retained.write_bytes(canonical_json_bytes(ctx)); output.write_text("keep"); link.symlink_to(retained)
    for target in (source, retained, output, link):
        assert cli("--input", source, "--context", retained, "--format", "entries-list", "--out", target).returncode == 1
    assert source.read_bytes() == raw and retained.read_bytes() == canonical_json_bytes(ctx)
    assert output.read_text() == "keep" and link.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
@pytest.mark.parametrize("option", ["--input", "--context", "--compare"])
def test_context_cli_rejects_nonregular_inputs_without_blocking(tmp_path, option):
    raw, ctx = inputs(); source, retained, fifo = [tmp_path / name for name in ("raw.json", "context.json", "pipe")]
    source.write_bytes(raw); retained.write_bytes(canonical_json_bytes(ctx)); os.mkfifo(fifo)
    args = {"--input": source, "--context": retained, "--format": "entries-list", "--compare": source}; args[option] = fifo
    result = cli(*[item for pair in args.items() for item in pair]); assert result.returncode == 1


@pytest.mark.parametrize("params_file", [False, True])
def test_collector_cli_routes_explicit_capture_and_returns_incomplete_exit(tmp_path, monkeypatch, capsys, params_file):
    install(monkeypatch, continuation=True)
    args = ["collector", "google_cloud_logs", "--capture-context", "--out", str(tmp_path / "capture")]
    params = json.dumps(synthetic_params())
    if params_file:
        path = tmp_path / "params.json"; path.write_text(params); args += ["--params-file", str(path)]
    else: args += ["--params-json", params]
    monkeypatch.setattr(sys, "argv", args)
    with pytest.raises(SystemExit) as exc: collectors.main()
    assert exc.value.code == 2
    result = json.loads(capsys.readouterr().out); assert result["status"] == "CAPTURED" and result["collection_complete"] is False


@pytest.mark.parametrize("options", [["--capture-method", "POST"], ["--capture-method", "GET"], ["--capture-scope", "resource"],
    ["--capture-method", "GET", "--capture-get-encoding", "form"], ["--params-file", "unused"]])
def test_google_capture_rejects_azure_flags_and_ambiguous_params(tmp_path, monkeypatch, capsys, options):
    _, adapter = install(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["collector", "google_cloud_logs", "--capture-context", "--out", str(tmp_path / "capture"),
                                     "--params-json", json.dumps(synthetic_params()), *options])
    with pytest.raises(SystemExit) as exc: collectors.main()
    assert exc.value.code == 1 and json.loads(capsys.readouterr().out)["status"] == "FAILED"
    assert not adapter.sent and not (tmp_path / "capture").exists()


def test_collector_interrupt_has_explicit_exit_and_no_success_claim(tmp_path, monkeypatch, capsys):
    def interrupted(*args, **kwargs): raise KeyboardInterrupt
    monkeypatch.setattr(acquisition, "capture", interrupted)
    monkeypatch.setattr(sys, "argv", ["collector", "google_cloud_logs", "--capture-context", "--out", str(tmp_path / "capture")])
    with pytest.raises(SystemExit) as exc: collectors.main()
    assert exc.value.code == 130 and json.loads(capsys.readouterr().out)["status"] == "INTERRUPTED"


@pytest.mark.parametrize("continuation", [False, True])
def test_bound_result_preserves_the_original_native_audit_projection(continuation):
    raw = canonical_json_bytes(synthetic_response(continuation=continuation))
    result = context.normalize(raw, context_raw=canonical_json_bytes(synthetic_context(raw)), input_format="entries-list")
    assert result["result"] == audit.normalize(raw, input_format="entries")

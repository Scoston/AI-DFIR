"""Automatic GET acquisition, URL encoding, credentials, and offline replay."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import quote
import zipfile

import pytest
import requests
from urllib3.exceptions import ReadTimeoutError
from urllib3.response import HTTPResponse

from case_export_v17 import verify_case
import provider_collectors_v15 as collectors
import v17_log_analytics_capture as acquisition
import v17_log_analytics_context as context
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter, synthetic_params
from v17_log_analytics_context_selftest import WORKSPACE, export_fixture
from v17_log_analytics_get_capture_selftest import captured_get_case, synthetic_get_params
from v17_log_analytics_selftest import synthetic_response

ROOT = Path(__file__).resolve().parents[1]
BASE = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE}/query"


@pytest.fixture(autouse=True)
def no_live_acquisition(monkeypatch):
    monkeypatch.setenv(acquisition.TOKEN_ENV, SYNTHETIC_TOKEN)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected live network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def install(monkeypatch, *, raw=None, partial=False, status=200, headers=None):
    raw = json.dumps(synthetic_response(partial=partial), indent=3).encode() + b'\n' if raw is None else raw
    adapter = synthetic_adapter(raw, status=status, headers=headers)
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    return raw, adapter


def capture(tmp_path, params=None, **kwargs):
    return acquisition.capture(canonical_json_bytes(synthetic_get_params() if params is None else params),
                               tmp_path / "capture", method="GET", **kwargs)


def saved(tmp_path, name):
    return json.loads((tmp_path / "capture" / name).read_bytes())


@pytest.mark.parametrize("partial", [False, True])
def test_get_capture_records_exact_prepared_url_absent_body_and_distinct_response_headers(tmp_path, monkeypatch, partial):
    raw, adapter = install(monkeypatch, partial=partial, headers={"x-request-id": "third-id", "Set-Cookie": SYNTHETIC_TOKEN})
    receipt = capture(tmp_path)
    ctx, projection = saved(tmp_path, "context.json"), saved(tmp_path, "projection.json")
    prepared = adapter.sent[0][0]
    assert prepared.method == "GET" and prepared.body is None and "Content-Length" not in prepared.headers
    params = synthetic_get_params()
    assert prepared.url == BASE + "?query=" + quote(params["kql"], safe="") + "&timespan=PT12H"
    assert ctx["request"] == {"method": "GET", "url": prepared.url, "body": None,
                               "headers": {"accept": "application/json", "prefer": "wait=30", "x-ms-client-request-id": "synthetic-client-request"}}
    assert ctx["response"]["headers"] == {"content-type": "application/json", "x-ms-request-id": "synthetic-ms-request",
                                           "request-id": "synthetic-other-request", "x-request-id": "third-id"}
    assert (tmp_path / "capture/response.json").read_bytes() == raw
    assert ctx["response"]["body_sha256"] == sha256_bytes(raw) and ctx["response"]["body_size_bytes"] == len(raw)
    assert projection["input_format"] == "workspace-get" and projection["request"]["query_sha256"] == sha256_object(params["kql"])
    assert receipt["status"] == "CAPTURED" and receipt["artifact_set_complete"] and receipt["request_context_bound"]
    assert receipt["request_method"] == "GET" and receipt["input_format"] == "workspace-get"
    assert receipt["collection_complete"] is (False if partial else None) and receipt["partial_error_recorded"] is partial
    assert not receipt["query_execution_verified"] and not receipt["request_scope_verified"] and not receipt["source_authenticity_verified"]
    assert saved(tmp_path, "receipt.json") == receipt and not (tmp_path / "capture/receipt.pending.json").exists()
    for item in receipt["files"]:
        content = (tmp_path / "capture" / item["path"]).read_bytes()
        assert item["sha256"] == sha256_bytes(content) and item["size_bytes"] == len(content)
    for marker in (SYNTHETIC_TOKEN, "SYNTHETIC-PRIVATE-CAPTURE-QUERY", "PT12H", "wait=30", BASE):
        assert marker not in json.dumps(receipt)
    assert SYNTHETIC_TOKEN not in json.dumps(ctx) and "authorization" not in json.dumps(ctx).lower()
    assert len(adapter.sent) == 1 and adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize("partial", [False, True])
def test_automatic_get_artifacts_replay_in_signed_case_without_acquisition_execution_or_extraction(tmp_path, monkeypatch, partial):
    install(monkeypatch, partial=partial)
    capture(tmp_path)
    fixture = captured_get_case(tmp_path / "case", tmp_path / "capture")
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected acquisition, execution, or extraction during replay")
    monkeypatch.setattr(acquisition, "capture", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    replay = result["reconstruction"]["deterministic_replay"]
    transform = replay["transforms"][0]
    assert result["valid"] and replay["status"] == "PASS" and transform["request_context_bound"]
    assert transform["collection_complete"] is (False if partial else None)
    assert not transform["query_reexecuted"] and not transform["query_execution_verified"]


@pytest.mark.parametrize("query", [
    "print x=1+2", "print s='a&timespan=other'", "print s='%20%2B'", "// note\r\nprint s='é🔎'\t",
    "print s='/?#;='", "print s='https://synthetic.invalid/path'", "malformed KQL is an opaque string",
    "query unreserved._~-012",
])
def test_decoded_parameters_are_encoded_once_and_round_trip_without_form_or_parameter_injection(tmp_path, monkeypatch, query):
    _, adapter = install(monkeypatch)
    params = {"workspace_id": WORKSPACE, "kql": query, "timespan": "2026-01-01/2026-01-02"}
    capture(tmp_path, params)
    url = adapter.sent[0][0].url
    assert url == BASE + "?query=" + quote(query, safe="") + "&timespan=2026-01-01%2F2026-01-02"
    assert "+" not in url and url.count("&") == 1
    request = saved(tmp_path, "projection.json")["request"]
    assert request["query_sha256"] == sha256_object(query)
    assert request["parameters_sha256"] == sha256_object({"query": query, "timespan": params["timespan"]})


def test_missing_optional_parameters_remain_absent_and_minimal_headers_are_recorded(tmp_path, monkeypatch):
    _, adapter = install(monkeypatch)
    capture(tmp_path, {"workspace_id": WORKSPACE, "kql": "q"})
    assert adapter.sent[0][0].url == BASE + "?query=q"
    assert saved(tmp_path, "context.json")["request"]["headers"] == {"accept": "application/json"}
    assert saved(tmp_path, "projection.json")["request"]["timespan"] == {"state": "absent", "sha256": None}


@pytest.mark.parametrize("token", [SYNTHETIC_TOKEN, "synthetic+credential", "synthetic/credential", "synthetic-credential==", "synthetic+/credential=="])
@pytest.mark.parametrize("key", ["kql", "timespan"])
def test_percent_encoding_cannot_hide_configured_credentials_in_query_parameters(tmp_path, monkeypatch, token, key):
    _, adapter = install(monkeypatch)
    monkeypatch.setenv(acquisition.TOKEN_ENV, token)
    params = synthetic_get_params()
    params[key] = "prefix-" + token + "-suffix"
    with pytest.raises(acquisition.CaptureError) as exc:
        capture(tmp_path, params)
    assert token not in str(exc.value) and quote(token, safe="") not in str(exc.value)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("key", ["prefer", "client_request_id"])
def test_get_selected_request_headers_reject_configured_credential_contamination(tmp_path, monkeypatch, key):
    _, adapter = install(monkeypatch)
    params = synthetic_get_params()
    params[key] = SYNTHETIC_TOKEN
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path, params)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("token", ["", "bad token", "bad\r\nheader", "é", "x" * 16385])
def test_missing_invalid_or_excessive_get_credentials_fail_before_output_or_network(tmp_path, monkeypatch, token):
    _, adapter = install(monkeypatch)
    monkeypatch.setenv(acquisition.TOKEN_ENV, token)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("key,value", [
    ("workspaces", []), ("workspaces", [WORKSPACE]), ("workspaces", None),
    ("url", BASE), ("method", "POST"), ("body", {}), ("headers", {}), ("token", SYNTHETIC_TOKEN),
    ("workspace_id", "not-a-guid"), ("workspace_id", None), ("workspace_id", WORKSPACE + "/query?timespan=other"),
    ("kql", None), ("kql", 1), ("kql", []), ("kql", {}), ("kql", ""), ("kql", " \t"), ("kql", "q\0"),
    ("timespan", None), ("timespan", []), ("timespan", ""), ("timespan", "x" * 257),
    ("prefer", "wait=30\r\nInjected: true"), ("client_request_id", []),
])
def test_unsupported_scope_fields_and_invalid_get_parameters_are_not_silently_dropped(tmp_path, monkeypatch, key, value):
    _, adapter = install(monkeypatch)
    params = synthetic_get_params()
    params[key] = value
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path, params)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("method", [None, [], {}, "get", "HEAD", "DELETE", "auto", ""])
def test_acquisition_method_is_fixed_and_explicit(tmp_path, monkeypatch, method):
    _, adapter = install(monkeypatch)
    with pytest.raises(acquisition.CaptureError):
        acquisition.capture(canonical_json_bytes(synthetic_get_params()), tmp_path / "capture", method=method)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("raw", [b'{"kql":"q","kql":"other"}', b'{"x":NaN}', b'{"x":"\\ud800"}',
    b'\xff', b'{} {}', b' ' * (128 * 1024 + 1)])
def test_get_parameter_documents_are_strict_and_bounded(tmp_path, monkeypatch, raw):
    _, adapter = install(monkeypatch)
    with pytest.raises(acquisition.CaptureError):
        acquisition.capture(raw, tmp_path / "capture", method="GET")
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("excess", [False, True])
def test_decoded_query_byte_limit_before_get_acquisition(tmp_path, monkeypatch, excess):
    _, adapter = install(monkeypatch)
    params = {"workspace_id": WORKSPACE, "kql": "q" * 65530 + "é" * 3 + ("q" if excess else "")}
    if excess:
        with pytest.raises(acquisition.CaptureError):
            capture(tmp_path, params)
        assert not adapter.sent and not (tmp_path / "capture").exists()
    else:
        assert capture(tmp_path, params)["status"] == "CAPTURED"
        assert saved(tmp_path, "projection.json")["request"]["query_size_bytes"] == 65536


@pytest.mark.parametrize("excess", [False, True])
def test_encoded_url_expansion_is_bounded_before_network(tmp_path, monkeypatch, excess):
    _, adapter = install(monkeypatch)
    triples, remainder = divmod(context.MAX_GET_URL_BYTES - len(BASE + "?query="), 3)
    query = "!" * triples + "a" * remainder + ("a" if excess else "")
    params = {"workspace_id": WORKSPACE, "kql": query}
    if excess:
        with pytest.raises(acquisition.CaptureError):
            capture(tmp_path, params)
        assert not adapter.sent and not (tmp_path / "capture").exists()
    else:
        assert capture(tmp_path, params)["status"] == "CAPTURED"
        assert len(adapter.sent[0][0].url) == context.MAX_GET_URL_BYTES


def test_get_transport_uses_direct_verified_tls_without_ambient_session_state(tmp_path, monkeypatch):
    _, adapter = install(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "https://synthetic.invalid")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/synthetic/ca.pem")
    monkeypatch.setenv("NETRC", "/synthetic/netrc")
    monkeypatch.setattr(requests.sessions.Session, "send", lambda *a, **k: pytest.fail("unexpected Session"))
    capture(tmp_path)
    prepared, kwargs = adapter.sent[0]
    assert kwargs == {"stream": True, "timeout": (10, 45), "verify": True, "cert": None, "proxies": {}}
    assert prepared.headers["Authorization"] == "Bearer " + SYNTHETIC_TOKEN
    assert prepared.headers["Accept-Encoding"] == "identity" and "Cookie" not in prepared.headers
    assert SYNTHETIC_TOKEN not in prepared.url


def test_real_get_http_adapter_does_not_follow_redirect_preload_decode_or_retry(tmp_path, monkeypatch):
    calls = []
    stream = io.BytesIO(b'x' * 1000)
    class Pool:
        def urlopen(self, **kwargs):
            calls.append(kwargs)
            return HTTPResponse(body=stream, status=302, headers={"Location": "https://synthetic.invalid"},
                                preload_content=False, decode_content=False)
    pool = Pool()
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "get_connection_with_tls_context", lambda *a, **k: pool)
    monkeypatch.setattr(acquisition, "MAX_INPUT_BYTES", 32)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert len(calls) == 1 and calls[0]["method"] == "GET" and calls[0]["body"] is None
    assert calls[0]["redirect"] is False and calls[0]["preload_content"] is False and calls[0]["decode_content"] is False
    assert calls[0]["retries"].total == 0 and pool.cert_reqs == "CERT_REQUIRED"
    assert not (tmp_path / "capture/receipt.json").exists() and stream.closed


@pytest.mark.parametrize("mutate", [
    lambda r: setattr(r, "method", "POST"), lambda r: setattr(r, "body", b''),
    lambda r: setattr(r, "url", r.url.replace("?query=", "?%71uery=")),
    lambda r: r.headers.update({"accept": "text/plain"}),
])
def test_prepared_get_changes_fail_before_any_network_or_output(tmp_path, monkeypatch, mutate):
    _, adapter = install(monkeypatch)
    prepare = requests.Request.prepare
    def changed(self):
        result = prepare(self)
        mutate(result)
        return result
    monkeypatch.setattr(requests.Request, "prepare", changed)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("mutate", [
    lambda r: setattr(r.request, "method", "POST"), lambda r: setattr(r.request, "body", b'{}'),
    lambda r: setattr(r.request, "url", r.request.url + "%20"),
    lambda r: r.request.headers.update({"prefer": "wait=99"}),
    lambda r: setattr(r, "url", "https://synthetic.invalid"), lambda r: setattr(r, "history", [requests.Response()]),
])
def test_observed_get_request_must_match_prepared_snapshot(tmp_path, monkeypatch, mutate):
    _, adapter = install(monkeypatch)
    send = adapter.send
    def changed(self, prepared, **kwargs):
        response = send(self, prepared, **kwargs)
        mutate(response)
        return response
    monkeypatch.setattr(adapter, "send", changed)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert adapter.closed and adapter.response.raw.closed and not (tmp_path / "capture/receipt.json").exists()


@pytest.mark.parametrize("status", [204, 301, 302, 303, 307, 308, 400, 401, 414, 429, 500])
def test_failed_or_redirected_get_retains_failure_observation_without_post_fallback(tmp_path, monkeypatch, status):
    raw, adapter = install(monkeypatch, raw=b'{"error":{"code":"SyntheticFailure"}}', status=status)
    receipt = capture(tmp_path)
    assert receipt["status"] == "FAILED" and not receipt["artifact_set_complete"] and receipt["collection_complete"] is False
    assert receipt["request_method"] == "GET" and receipt["http_status"] == status
    assert (tmp_path / "capture/response.json").read_bytes() == raw
    observation = saved(tmp_path, "capture-observation.json")
    assert observation["schema"] == acquisition.OBSERVATION_SCHEMA and not observation["replay_context_available"]
    assert observation["request"]["method"] == "GET" and observation["request"]["body"] is None
    assert len(adapter.sent) == 1 and adapter.sent[0][0].method == "GET"
    assert not (tmp_path / "capture/context.json").exists() and not (tmp_path / "capture/projection.json").exists()


@pytest.mark.parametrize("raw,complete,error", [(b'', None, None), (b'not-json', None, None),
    (b'{"tables":[],"tables":[]}', None, None), (b'{}', None, False),
    (b'{"tables":[],"error":{"code":"Fatal"}}', False, True)])
def test_unsupported_get_responses_preserve_bytes_without_success_claim(tmp_path, monkeypatch, raw, complete, error):
    install(monkeypatch, raw=raw)
    receipt = capture(tmp_path)
    assert receipt["status"] == "FAILED" and receipt["collection_complete"] is complete and receipt["response_error_recorded"] is error
    assert (tmp_path / "capture/response.json").read_bytes() == raw and not (tmp_path / "capture/projection.json").exists()


def test_empty_get_results_are_captured_but_collection_stays_unknown(tmp_path, monkeypatch):
    install(monkeypatch, raw=b'{"tables":[]}')
    receipt = capture(tmp_path)
    assert receipt["status"] == "CAPTURED" and receipt["row_count"] == 0 and receipt["collection_complete"] is None


@pytest.mark.parametrize("headers", [{"Content-Encoding": "gzip"}, {"Content-Length": "999999999"},
    {"Content-Length": "0"}, {"x-ms-request-id": SYNTHETIC_TOKEN}, {"request-id": "bad\0"}])
def test_unsupported_get_response_encoding_lengths_and_headers_fail_closed(tmp_path, monkeypatch, headers):
    _, adapter = install(monkeypatch, headers=headers)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert adapter.closed and adapter.response.raw.closed and not (tmp_path / "capture/receipt.json").exists()


@pytest.mark.parametrize("error", [requests.exceptions.SSLError(BASE + "?query=SYNTHETIC-PRIVATE"),
    requests.exceptions.ConnectionError(BASE + "?query=SYNTHETIC-PRIVATE"),
    ReadTimeoutError(None, BASE + "?query=SYNTHETIC-PRIVATE", "private detail")])
def test_get_transport_error_urls_and_query_content_are_redacted(tmp_path, monkeypatch, error):
    _, adapter = install(monkeypatch)
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(adapter, "send", fail)
    with pytest.raises(acquisition.CaptureError) as exc:
        capture(tmp_path)
    assert BASE not in str(exc.value) and "SYNTHETIC-PRIVATE" not in str(exc.value)
    assert adapter.closed and not (tmp_path / "capture/receipt.json").exists()


@pytest.mark.parametrize("kind", ["directory", "file", "symlink", "dangling-symlink"])
def test_existing_get_output_is_preserved_before_network(tmp_path, monkeypatch, kind):
    _, adapter = install(monkeypatch)
    output, target = tmp_path / "capture", tmp_path / "target"
    target.mkdir()
    (target / "existing").write_bytes(b'preserve')
    if kind == "directory":
        output.mkdir()
    elif kind == "file":
        output.write_bytes(b'preserve')
    else:
        output.symlink_to(target if kind == "symlink" else tmp_path / "missing", target_is_directory=True)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not adapter.sent and (target / "existing").read_bytes() == b'preserve'
    if kind == "file":
        assert output.read_bytes() == b'preserve'
    elif kind == "directory":
        assert output.is_dir()
    else:
        assert output.is_symlink()


@pytest.mark.parametrize("name", ["response.json", "context.json", "projection.json", "receipt.pending.json"])
def test_get_member_write_failure_does_not_publish_success_receipt(tmp_path, monkeypatch, name):
    install(monkeypatch)
    write = acquisition._write_new
    def fail(directory, filename, raw):
        if filename == name:
            raise OSError("synthetic failure")
        return write(directory, filename, raw)
    monkeypatch.setattr(acquisition, "_write_new", fail)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not (tmp_path / "capture/receipt.json").exists()


def test_interrupted_get_context_write_keeps_incomplete_files_without_success_receipt(tmp_path, monkeypatch):
    install(monkeypatch)
    write = acquisition._write_new
    def interrupt(directory, name, raw):
        if name == "context.json":
            write(directory, name, raw[:8])
            raise KeyboardInterrupt()
        return write(directory, name, raw)
    monkeypatch.setattr(acquisition, "_write_new", interrupt)
    with pytest.raises(KeyboardInterrupt):
        capture(tmp_path)
    assert (tmp_path / "capture/context.json").stat().st_size == 8 and not (tmp_path / "capture/receipt.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_get_evidence_files_and_directory_start_private(tmp_path, monkeypatch):
    install(monkeypatch)
    capture(tmp_path)
    assert (tmp_path / "capture").stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (tmp_path / "capture").iterdir())


@pytest.mark.parametrize("change", ["query", "workspace", "timespan", "encoding", "request-id", "response"])
def test_captured_get_substitution_retains_signed_integrity_but_fails_replay(tmp_path, monkeypatch, change):
    install(monkeypatch)
    capture(tmp_path)
    fixture = captured_get_case(tmp_path / "case", tmp_path / "capture")
    ctx = json.loads(fixture["context"])
    if change == "query":
        ctx["request"]["url"] = ctx["request"]["url"].replace("AzureActivity", "AnotherTable")
    elif change == "workspace":
        ctx["request"]["url"] = ctx["request"]["url"].replace(WORKSPACE, "00000000-0000-0000-0000-000000000099")
    elif change == "timespan":
        ctx["request"]["url"] = ctx["request"]["url"].replace("PT12H", "PT1H")
    elif change == "encoding":
        ctx["request"]["url"] = ctx["request"]["url"].replace("%2F", "%2f")
    elif change == "request-id":
        ctx["response"]["headers"]["request-id"] = "changed-id"
    else:
        fixture["raw"] += b' '
    fixture["context"] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    assert result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("explicit", [False, True])
def test_reviewed_default_and_explicit_post_artifact_digests_remain_identical(tmp_path, monkeypatch, explicit):
    install(monkeypatch)
    acquisition.capture(canonical_json_bytes(synthetic_params()), tmp_path / "capture", **({"method": "POST"} if explicit else {}))
    expected = {"context.json": "7899d6f9852aca6677018d3c45673a95e43221ee67b743a35e8fbfe88fc5f934",
                "projection.json": "d1063cb8c29ed051c82bc409a36fe0c2a02d760317741cb8f0a3cabad64e5d77",
                "receipt.json": "66980d5ca94818e1274c45e92c83691f31c8b4873db2b11dc85505ef97580758"}
    for name, digest in expected.items():
        assert sha256_bytes((tmp_path / "capture" / name).read_bytes()) == digest


def run_cli(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["provider_collectors_v15.py", *map(str, args)])
    with pytest.raises(SystemExit) as exc:
        collectors.main()
    return exc.value.code, capsys.readouterr()


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("input_mode", ["file", "json"])
def test_cli_explicit_get_capture_keeps_query_and_credentials_out_of_summary(tmp_path, monkeypatch, capsys, partial, input_mode):
    install(monkeypatch, partial=partial)
    params = tmp_path / "params.json"
    params.write_bytes(canonical_json_bytes(synthetic_get_params()))
    args = ("--params-file", params) if input_mode == "file" else ("--params-json", params.read_text())
    code, output = run_cli(monkeypatch, capsys, "azure_foundry_logs", "--capture-context", "--capture-method", "GET",
                           *args, "--out", tmp_path / "capture")
    receipt = json.loads(output.out)
    assert code == 2 and receipt["status"] == "CAPTURED" and receipt["request_method"] == "GET" and not output.err
    assert receipt["collection_complete"] is (False if partial else None)
    for marker in (SYNTHETIC_TOKEN, "SYNTHETIC-PRIVATE-CAPTURE-QUERY", "PT12H", BASE, str(tmp_path)):
        assert marker not in output.out


@pytest.mark.parametrize("args,code", [
    (["azure_foundry_logs", "--capture-method", "GET"], 2),
    (["azure_foundry_logs", "--capture-method", "POST"], 2),
    (["azure_foundry_logs", "--capture-context", "--capture-method", "get"], 2),
    (["aws_bedrock", "--capture-context", "--capture-method", "GET"], 1),
    (["azure_foundry_logs", "--capture-context", "--capture-method", "GET", "--params-json", "private-invalid"], 1),
    (["azure_foundry_logs", "--capture-context", "--capture-method", "GET", "--params-file", "/synthetic/missing"], 1),
    (["azure_foundry_logs", "--capture-context", "--capture-method", "GET", "--params-file", "/synthetic/missing", "--params-json", '{"x":true}'], 1),
])
def test_bad_get_cli_arguments_do_not_acquire_or_fall_back_to_legacy_collector(tmp_path, monkeypatch, capsys, args, code):
    _, adapter = install(monkeypatch)
    actual, output = run_cli(monkeypatch, capsys, *args, "--out", tmp_path / "capture")
    assert actual == code and not adapter.sent and not (tmp_path / "capture").exists()
    assert "private-invalid" not in output.out and "/synthetic/missing" not in output.out


def test_get_cli_http_failure_is_nonzero_with_explicit_incomplete_receipt(tmp_path, monkeypatch, capsys):
    install(monkeypatch, raw=b'{"error":{"code":"URITooLong"}}', status=414)
    code, output = run_cli(monkeypatch, capsys, "azure_foundry_logs", "--capture-context", "--capture-method", "GET",
                           "--params-json", json.dumps(synthetic_get_params()), "--out", tmp_path / "capture")
    receipt = json.loads(output.out)
    assert code == 1 and receipt["status"] == "FAILED" and receipt["http_status"] == 414
    assert not receipt["artifact_set_complete"] and receipt["request_method"] == "GET"


def test_get_cli_interruption_does_not_claim_capture_completion(tmp_path, monkeypatch, capsys):
    def interrupt(*args, **kwargs):
        assert kwargs == {"method": "GET"}
        raise KeyboardInterrupt()
    monkeypatch.setattr(acquisition, "capture", interrupt)
    code, output = run_cli(monkeypatch, capsys, "azure_foundry_logs", "--capture-context", "--capture-method", "GET", "--out", tmp_path / "capture")
    assert code == 130 and json.loads(output.out) == {"status": "INTERRUPTED", "artifact_set_complete": False}


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_get_cli_rejects_fifo_parameter_file_without_blocking(tmp_path, monkeypatch, capsys):
    _, adapter = install(monkeypatch)
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    code, output = run_cli(monkeypatch, capsys, "azure_foundry_logs", "--capture-context", "--capture-method", "GET",
                           "--params-file", pipe, "--out", tmp_path / "capture")
    assert code == 1 and json.loads(output.out)["status"] == "FAILED" and not adapter.sent


def test_automatically_captured_get_projection_compares_directly(tmp_path, monkeypatch):
    install(monkeypatch)
    capture(tmp_path)
    folder = tmp_path / "capture"
    result = context.compare_replay((folder / "response.json").read_bytes(), (folder / "projection.json").read_bytes(),
                                    context_raw=(folder / "context.json").read_bytes(), input_format="workspace-get")
    assert result["status"] == "PASS" and result["request_context_bound"] and not result["query_reexecuted"]


def test_case_cli_fails_changed_get_capture_projection_while_integrity_passes(tmp_path, monkeypatch):
    install(monkeypatch)
    capture(tmp_path)
    fixture = captured_get_case(tmp_path / "case", tmp_path / "capture")
    fixture["output"]["query_execution_verified"] = True
    export_fixture(fixture)
    result = subprocess.run([sys.executable, str(ROOT / "replay_case_v17.py"), "--zip", str(fixture["package"]),
                             "--export-public-key", str(fixture["public"]), "--replay-transforms"],
                            capture_output=True, text=True, timeout=15)
    report = json.loads(result.stdout)
    assert result.returncode == 1 and report["valid"] and report["reconstruction"]["deterministic_replay"]["status"] == "FAIL"

"""Explicit form decoding, additional workspace observations, capture and replay."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import quote_plus
import zipfile

import pytest
import requests

from case_export_v17 import verify_case
import provider_collectors_v15 as cli
import v17_log_analytics_capture as capture
import v17_log_analytics_context as context
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter
from v17_log_analytics_context_selftest import WORKSPACE, export_fixture, synthetic_context
from v17_log_analytics_form_selftest import synthetic_form_case, synthetic_form_params
from v17_log_analytics_resource_selftest import RESOURCE_ID, synthetic_resource_response
from v17_log_analytics_selftest import synthetic_response

ROOT = Path(__file__).resolve().parents[1]
BASE = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE}/query"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected live network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setenv(capture.TOKEN_ENV, SYNTHETIC_TOKEN)


def inputs(parameters="query=print+x%3D1%2B2", scope="workspace"):
    raw = canonical_json_bytes(synthetic_resource_response() if scope == "resource" else synthetic_response())
    ctx = synthetic_context(raw)
    base = "https://api.loganalytics.azure.com/v1" + RESOURCE_ID + "/query" if scope == "resource" else BASE
    ctx["request"] = {"method": "GET", "url": base + "?" + parameters, "body": None, "headers": {"accept": "application/json"}}
    return raw, ctx


def project(raw, ctx, scope="workspace"):
    return context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format=scope + "-get-form")


@pytest.mark.parametrize("scope", ["workspace", "resource"])
@pytest.mark.parametrize("partial", [False, True])
def test_automatic_form_capture_binds_exact_prepared_url_and_replays_offline(tmp_path, monkeypatch, scope, partial):
    fixture = synthetic_form_case(tmp_path / "case", scope=scope, partial=partial)
    adapter = synthetic_adapter(fixture["raw"]); monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    directory = tmp_path / "capture"; params = synthetic_form_params(scope)
    report = capture.capture(canonical_json_bytes(params), directory, method="GET", scope=scope, get_encoding="form")
    assert report["status"] == "CAPTURED" and report["input_format"] == scope + "-get-form"
    assert report["collection_complete"] is (False if partial else None)
    prepared, options = adapter.sent[0]
    assert prepared.body is None and prepared.method == "GET" and len(adapter.sent) == 1
    assert options == {"stream": True, "timeout": (10, 45), "verify": True, "cert": None, "proxies": {}}
    expected = "query=" + quote_plus(params["kql"], safe="") + "&timespan=" + quote_plus(params["timespan"], safe="")
    if scope == "workspace":
        expected += "&workspaces=" + quote_plus(",".join(params["workspaces"]), safe="")
    assert prepared.url.partition("?")[2] == expected
    assert (directory / "response.json").read_bytes() == fixture["raw"]
    fixture.update(context=(directory / "context.json").read_bytes(), output=json.loads((directory / "projection.json").read_bytes()))
    req = fixture["output"]["request"]
    assert req["url_sha256"] == sha256_object(prepared.url)
    assert req["query_sha256"] == sha256_object(params["kql"])
    assert req["url_decoding"] == "utf8-form-plus-then-percent-once"
    if scope == "workspace":
        assert req["additional_workspace_sha256"] == [sha256_object(x) for x in params["workspaces"]]
        assert req["workspaces"]["sha256"] == sha256_object(",".join(params["workspaces"]))
    export_fixture(fixture)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected acquisition, process execution, or extraction")
    monkeypatch.setattr(capture, "capture", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    verified = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    assert verified["valid"] and verified["reconstruction"]["deterministic_replay"]["status"] == "PASS"
    assert SYNTHETIC_TOKEN not in fixture["context"].decode() and params["kql"] not in json.dumps(report)


@pytest.mark.parametrize("scope", ["workspace", "resource"])
@pytest.mark.parametrize("encoded,decoded", [
    ("a+b", "a b"), ("a%2Bb", "a+b"), ("a%252Bb", "a%2Bb"), ("a%20b", "a b"),
    ("%2B+%2520", "+ %20"), ("print+count(*)", "print count(*)"), ("a,b", "a,b"),
    ("%C3%A9%F0%9F%94%8E", "é🔎"), ("q%09%0D%0A", "q\t\r\n"),
    ("q%26workspaces%3Dinjected", "q&workspaces=injected"),
    ("q%3D%2F%3F%23%3B", "q=/?#;"), ("unreserved._~-", "unreserved._~-"),
])
def test_form_decoding_replaces_only_literal_plus_before_one_strict_decode(scope, encoded, decoded):
    raw, ctx = inputs("query=" + encoded, scope)
    out = project(raw, ctx, scope)
    assert out["request"]["query_sha256"] == sha256_object(decoded)
    assert out["request"]["query_size_bytes"] == len(decoded.encode())
    assert out["request"]["parameters_sha256"] == sha256_object({"query": decoded})


@pytest.mark.parametrize("parameters", [
    "", "query", "query=", "query=+++", "query=%", "query=%2", "query=%GH", "query=%FF",
    "query=%C0%AF", "query=%ED%A0%80", "query=%00", "query=q%7f", "query=q%01",
    "query=q x", "query=q=x", "query=q/x", "query=q?x", "query=q#x", "query=q;x", "query=q\\x",
    "query=q&", "&query=q", "query=q&&timespan=PT1H", "query=q&query=q", "query=q&%71uery=q",
    "query=q&timespan=PT1H&%74imespan=PT2H", "query=q&timespan=", "query=q&timespan=+",
    "query=q&workspaces=", "query=q&workspaces[]=" + WORKSPACE,
    "query=q&workspaces=" + WORKSPACE + "&%77orkspaces=" + WORKSPACE,
    "query=q&unknown=x", "query=q&access_token=synthetic", "Query=q", "%2571uery=q",
    "query=q&timespan=PT1H&workspaces=" + WORKSPACE + "&extra=x",
])
def test_malformed_ambiguous_duplicate_or_unknown_parameters_fail_closed(parameters):
    raw, ctx = inputs(parameters)
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("value", [
    "", ",", WORKSPACE + ",", "," + WORKSPACE, WORKSPACE + ",," + WORKSPACE,
    WORKSPACE + ", " + WORKSPACE, "not-a-guid", RESOURCE_ID, "friendly-name",
    ",".join([WORKSPACE] * 33), WORKSPACE + "%2C" + WORKSPACE,
])
def test_additional_workspace_id_list_is_bounded_and_never_trimmed_or_double_decoded(value):
    raw, ctx = inputs("query=q&workspaces=" + quote_plus(value, safe=""))
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("value", [[WORKSPACE], [WORKSPACE, WORKSPACE], [WORKSPACE] * 32])
def test_workspace_order_and_duplicates_are_retained_without_scope_inference(value):
    raw, ctx = inputs("query=q&workspaces=" + ",".join(value))
    out = project(raw, ctx)
    assert out["request"]["additional_workspace_sha256"] == [sha256_object(x) for x in value]
    assert not out["request_scope_verified"] and out["collection_complete"] is None


@pytest.mark.parametrize("left,right", [
    ("query=a+b", "query=a%20b"), ("query=a%2Bb", "query=a%2bb"),
    ("query=q&timespan=PT1H", "timespan=PT1H&query=q"),
    ("query=q&workspaces=" + WORKSPACE + "," + WORKSPACE, "query=q&workspaces=" + WORKSPACE + "%2C" + WORKSPACE),
    ("query=q", "%71uery=q"),
])
def test_equivalent_decoded_values_never_erase_exact_url_or_order(left, right):
    raw, ctx = inputs(left); out = project(raw, ctx)
    _, ctx2 = inputs(right); changed = project(raw, ctx2)
    assert changed["request"]["parameters_sha256"] == out["request"]["parameters_sha256"]
    assert changed["request"]["url_sha256"] != out["request"]["url_sha256"]
    assert context.compare_replay(raw, canonical_json_bytes(out), context_raw=canonical_json_bytes(ctx2), input_format="workspace-get-form")["status"] == "FAIL"


@pytest.mark.parametrize("scope", ["workspace", "resource"])
def test_same_unreserved_url_still_binds_the_explicit_profile(scope):
    raw, ctx = inputs("query=q", scope); out = project(raw, ctx, scope)
    old = context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format=scope + "-get")
    assert old["binding_sha256"] != out["binding_sha256"]
    assert old["request"]["query_sha256"] == out["request"]["query_sha256"]
    assert context.compare_replay(raw, canonical_json_bytes(old), context_raw=canonical_json_bytes(ctx), input_format=scope + "-get-form")["status"] == "FAIL"


@pytest.mark.parametrize("parameters", ["query=a+b", "query=q&workspaces=" + WORKSPACE])
def test_original_percent_profile_continues_to_reject_new_forms(parameters):
    raw, ctx = inputs(parameters)
    with pytest.raises(ValueError):
        context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="workspace-get")


def test_resource_form_profile_cannot_add_workspace_scope():
    raw, ctx = inputs("query=q&workspaces=" + WORKSPACE, "resource")
    with pytest.raises(ValueError):
        project(raw, ctx, "resource")


@pytest.mark.parametrize("query", ["q" * 65536, "é" * 1000 + "q" * 63536])
def test_form_decoded_query_limit_is_measured_in_utf8_bytes(query):
    raw, ctx = inputs("query=" + quote_plus(query, safe=""))
    assert project(raw, ctx)["request"]["query_size_bytes"] == 65536
    ctx["request"]["url"] += "q"
    with pytest.raises(ValueError):
        project(raw, ctx)


def test_encoded_url_budget_precedes_decoding(monkeypatch):
    raw, ctx = inputs("query=q")
    prefix = BASE + "?query="; triples, remainder = divmod(context.MAX_GET_URL_BYTES - len(prefix), 3)
    ctx["request"]["url"] = prefix + "%61" * triples + "a" * remainder
    assert project(raw, ctx)["request"]["url_size_bytes"] == context.MAX_GET_URL_BYTES
    ctx["request"]["url"] += "a"
    monkeypatch.setattr(context, "_get_component", lambda *a, **k: pytest.fail("oversized URL reached decoding"))
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("change", ["plus-space", "workspace", "workspace-order", "encoded-key", "scope-profile"])
def test_signed_substitution_retains_integrity_but_fails_replay(tmp_path, change):
    fixture = synthetic_form_case(tmp_path / "case")
    ctx = json.loads(fixture["context"])
    url = ctx["request"]["url"]
    if change == "plus-space": url = url.replace("%2B", "+")
    if change == "workspace": url = url.replace("000000000002", "000000000004")
    if change == "workspace-order": url = url.replace("000000000002", "000000000099").replace("000000000003", "000000000002").replace("000000000099", "000000000003")
    if change == "encoded-key": url = url.replace("workspaces=", "%77orkspaces=")
    if change == "scope-profile": fixture["metadata"]["input_format"] = "workspace-get"
    ctx["request"]["url"] = url; fixture["context"] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    verified = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert verified["valid"] and verified["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("workspaces", [None, "workspace", [], [None], [WORKSPACE + "," + WORKSPACE], ["bad"], [WORKSPACE] * 33])
def test_capture_workspace_list_cannot_inject_or_silently_change_scope(tmp_path, monkeypatch, workspaces):
    adapter = synthetic_adapter(b"{}"); monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    params = synthetic_form_params("workspace"); params["workspaces"] = workspaces
    with pytest.raises(capture.CaptureError):
        capture.capture(canonical_json_bytes(params), tmp_path / "capture", method="GET", get_encoding="form")
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("token", ["synthetic+credential", "synthetic/credential==", "synthetic+/credential=="])
@pytest.mark.parametrize("scope", ["workspace", "resource"])
def test_form_encoding_cannot_hide_configured_credential(tmp_path, monkeypatch, token, scope):
    adapter = synthetic_adapter(b"{}"); monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    monkeypatch.setenv(capture.TOKEN_ENV, token)
    params = synthetic_form_params(scope); params["kql"] = "print s='" + token + "'"
    with pytest.raises(capture.CaptureError) as exc:
        capture.capture(canonical_json_bytes(params), tmp_path / "capture", method="GET", scope=scope, get_encoding="form")
    assert token not in str(exc.value) and not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("encoding,method", [(None, "GET"), ([], "GET"), ("Form", "GET"), ("auto", "GET"), ("form", "POST")])
def test_capture_requires_supported_explicit_encoding_and_method(tmp_path, encoding, method):
    with pytest.raises(capture.CaptureError):
        capture.capture(canonical_json_bytes(synthetic_form_params("workspace")), tmp_path / "capture", method=method, get_encoding=encoding)
    assert not (tmp_path / "capture").exists()


@pytest.mark.parametrize("scope", ["workspace", "resource"])
@pytest.mark.parametrize("status", [302, 414])
def test_form_http_failure_does_not_retry_change_encoding_or_fall_back(tmp_path, monkeypatch, scope, status):
    adapter = synthetic_adapter(b'{"error":{"code":"synthetic"}}', status=status)
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    out = capture.capture(canonical_json_bytes(synthetic_form_params(scope)), tmp_path / "capture", method="GET", scope=scope, get_encoding="form")
    assert out["status"] == "FAILED" and out["collection_complete"] is False
    assert len(adapter.sent) == 1 and adapter.sent[0][0].method == "GET"
    assert not (tmp_path / "capture/projection.json").exists()


@pytest.mark.parametrize("scope", ["workspace", "resource"])
def test_form_cli_capture_and_offline_normalize_compare(tmp_path, monkeypatch, capsys, scope):
    raw, _ = inputs(scope=scope); monkeypatch.setattr(requests.adapters, "HTTPAdapter", synthetic_adapter(raw))
    params = tmp_path / "params.json"; params.write_bytes(canonical_json_bytes(synthetic_form_params(scope)))
    directory = tmp_path / "capture"
    monkeypatch.setattr(sys, "argv", ["collector", "azure_foundry_logs", "--capture-context", "--capture-method", "GET",
        "--capture-scope", scope, "--capture-get-encoding", "form", "--params-file", str(params), "--out", str(directory)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2 and json.loads(capsys.readouterr().out)["status"] == "CAPTURED"
    argv = [sys.executable, str(ROOT / "log_analytics_context_v17.py"), "--input", str(directory / "response.json"),
            "--context", str(directory / "context.json"), "--format", scope + "-get-form"]
    normalized = subprocess.run([*argv, "--out", str(tmp_path / "projection.json")], capture_output=True, text=True, timeout=10)
    assert normalized.returncode == 0 and json.loads(normalized.stdout)["status"] == "NORMALIZED"
    compared = subprocess.run([*argv, "--compare", str(directory / "projection.json")], capture_output=True, text=True, timeout=10)
    assert compared.returncode == 0 and json.loads(compared.stdout)["status"] == "PASS"


@pytest.mark.parametrize("flags", [[], ["--capture-context"], ["--capture-context", "--capture-method", "POST"]])
def test_cli_encoding_option_requires_explicit_get_capture(tmp_path, monkeypatch, flags):
    monkeypatch.setattr(sys, "argv", ["collector", "azure_foundry_logs", *flags, "--capture-get-encoding", "form", "--out", str(tmp_path / "capture")])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2 and not (tmp_path / "capture").exists()

"""Resource scope, permission observations, acquisition, and signed replay boundaries."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest
import requests

from case_export_v17 import verify_case
import provider_collectors_v15 as cli
import v17_log_analytics as tables
import v17_log_analytics_capture as capture
import v17_log_analytics_context as context
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics_capture_selftest import SYNTHETIC_TOKEN, synthetic_adapter, synthetic_params
from v17_log_analytics_context_selftest import export_fixture, synthetic_context
from v17_log_analytics_resource_selftest import RESOURCE_ID, synthetic_resource_case, synthetic_resource_params, synthetic_resource_response
from v17_log_analytics_selftest import synthetic_response

BASE = "https://api.loganalytics.azure.com/v1" + RESOURCE_ID + "/query"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected live network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setenv(capture.TOKEN_ENV, SYNTHETIC_TOKEN)


def inputs(method="POST", *, partial=False):
    raw = json.dumps(synthetic_resource_response(partial=partial), indent=3).encode() + b"\n"
    ctx = synthetic_context(raw)
    ctx["request"] = {"method": method, "url": BASE, "headers": {"content-type": "application/json"},
                      "body": {"query": "AzureActivity | count", "timespan": "PT1H"}}
    if method == "GET":
        ctx["request"].update(url=BASE + "?query=AzureActivity%20%7C%20count&timespan=PT1H", body=None)
    return raw, ctx


def project(raw, ctx):
    return context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="resource-" + ctx["request"]["method"].lower())


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("partial", [False, True])
def test_resource_projection_binds_exact_response_resource_and_opaque_permissions(method, partial):
    raw, ctx = inputs(method, partial=partial)
    result = project(raw, ctx)
    assert result["source_sha256"] == sha256_bytes(raw)
    assert result["context_sha256"] == sha256_bytes(canonical_json_bytes(ctx))
    assert result["request"]["resource_id_sha256"] == sha256_object(RESOURCE_ID)
    assert result["request"]["endpoint_sha256"] == sha256_object(BASE)
    assert result["request"]["requested_scope"] == "resource"
    assert "primary_workspace_sha256" not in result["request"]
    assert result["result"] == tables.normalize(raw, input_format="resource-tables")
    assert result["result"]["response_digests"]["permissions"] == {"state": "present", "sha256": sha256_object(json.loads(raw)["permissions"])}
    assert result["collection_complete"] is (False if partial else None)
    for key in ("query_execution_verified", "source_authenticity_verified", "request_scope_verified", "query_reexecuted"):
        assert result[key] is False
    assert result["result"]["permissions_verified"] is False
    for marker in (RESOURCE_ID, "SyntheticDenied", "AzureActivity | count", "PT1H"):
        assert marker not in json.dumps(result)


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("partial", [False, True])
def test_captured_resource_artifacts_replay_offline_in_signed_case(tmp_path, monkeypatch, method, partial):
    raw, _ = inputs(method, partial=partial)
    adapter = synthetic_adapter(raw)
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    directory = tmp_path / "capture"
    report = capture.capture(canonical_json_bytes(synthetic_resource_params()), directory, scope="resource", method=method)
    assert report["status"] == "CAPTURED" and report["collection_complete"] is (False if partial else None)
    assert report["input_format"] == "resource-" + method.lower()
    assert report["request_method"] == method
    assert (directory / "response.json").read_bytes() == raw
    assert len(adapter.sent) == 1 and adapter.closed and adapter.response.raw.closed
    prepared, options = adapter.sent[0]
    assert prepared.url.startswith(BASE) and options == {"stream": True, "timeout": (10, 45), "verify": True, "cert": None, "proxies": {}}
    assert (prepared.body is None) is (method == "GET")
    fixture = synthetic_resource_case(tmp_path / "case", method=method, partial=partial)
    fixture.update(raw=raw, context=(directory / "context.json").read_bytes(), output=json.loads((directory / "projection.json").read_bytes()))
    export_fixture(fixture)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected acquisition, process execution, or extraction")
    monkeypatch.setattr(capture, "capture", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("change", ["resource", "subscription", "case", "query", "permissions", "response", "header"])
def test_resigned_substitutions_keep_integrity_but_fail_replay(tmp_path, method, change):
    fixture = synthetic_resource_case(tmp_path / "case", method=method)
    ctx = json.loads(fixture["context"])
    if change in ("resource", "subscription", "case"):
        old, new = {"resource": ("synthetic-vm", "another-vm"), "subscription": ("000000000001", "000000000002"), "case": ("synthetic-rg", "Synthetic-rg")}[change]
        ctx["request"]["url"] = ctx["request"]["url"].replace(old, new)
    elif change == "query":
        if method == "GET":
            ctx["request"]["url"] = ctx["request"]["url"].replace("count", "take%201")
        else:
            ctx["request"]["body"]["query"] += " | take 1"
    elif change == "header":
        ctx["response"]["headers"]["x-ms-request-id"] = "another-request"
    else:
        obj = json.loads(fixture["raw"])
        if change == "permissions":
            obj["permissions"] = {}
        else:
            obj["tables"][0]["rows"] = []
        fixture["raw"] = canonical_json_bytes(obj)
        ctx["response"].update(body_sha256=sha256_bytes(fixture["raw"]), body_size_bytes=len(fixture["raw"]))
    fixture["context"] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("identifier", [
    RESOURCE_ID + "/", RESOURCE_ID + "/child", RESOURCE_ID + "/../name", RESOURCE_ID + "/type/.",
    RESOURCE_ID.replace("synthetic-vm", "%2e%2e"), RESOURCE_ID.replace("synthetic-vm", "x%2Fy"),
    RESOURCE_ID.replace("synthetic-vm", "x+y"), RESOURCE_ID.replace("synthetic-vm", "x y"),
    RESOURCE_ID.replace("synthetic-vm", "é"), RESOURCE_ID.replace("synthetic-vm", "x\\y"),
    RESOURCE_ID.replace("synthetic-vm", "x?query=injected"), RESOURCE_ID + "#fragment",
    RESOURCE_ID.replace("00000000-0000-0000-0000-000000000001", "not-a-guid"),
    RESOURCE_ID.replace("resourceGroups", "resourcegroups"), RESOURCE_ID.replace("Microsoft.Compute", "Compute"),
    RESOURCE_ID.replace("synthetic-rg", ".."), RESOURCE_ID.replace("synthetic-vm", "x" * 257),
    RESOURCE_ID.replace("Microsoft.Compute", "x" * 257 + ".Compute"),
    RESOURCE_ID + "/type/name" * 8, "/subscriptions/00000000-0000-0000-0000-000000000001",
    RESOURCE_ID.split("/providers")[0], "https://untrusted.invalid" + RESOURCE_ID,
])
def test_unsupported_resource_identifiers_fail_before_acquisition(tmp_path, monkeypatch, method, identifier):
    adapter = synthetic_adapter(b"{}")
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    params = synthetic_resource_params(); params["resource_id"] = identifier
    with pytest.raises(capture.CaptureError):
        capture.capture(canonical_json_bytes(params), tmp_path / "capture", scope="resource", method=method)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("host", ["api.loganalytics.io", "api.loganalytics.azure.com"])
def test_child_resource_and_fixed_public_hosts_preserve_exact_identity(method, host):
    raw, ctx = inputs(method)
    ctx["request"]["url"] = ctx["request"]["url"].replace("api.loganalytics.azure.com", host).replace("/query", "/extensions/Synthetic_Ext-1~/query")
    output = project(raw, ctx)
    assert output["request"]["resource_id_sha256"] == sha256_object(RESOURCE_ID + "/extensions/Synthetic_Ext-1~")
    assert output["request"]["endpoint_host"] == host


@pytest.mark.parametrize("url", [
    BASE.replace("https:", "http:"), BASE.replace("api.loganalytics.azure.com", "api.loganalytics.azure.com.evil.invalid"),
    BASE.replace("api.loganalytics.azure.com", "user@api.loganalytics.azure.com"),
    BASE.replace("api.loganalytics.azure.com", "api.loganalytics.azure.com:443"),
    BASE.replace("api.loganalytics.azure.com", "management.azure.com"), BASE.replace("/v1/", "/v2/"),
    BASE + "?api-version=2018-01-01", BASE + "\n", None, [], 42,
])
def test_resource_post_endpoint_does_not_accept_other_api_or_url_forms(url):
    raw, ctx = inputs(); ctx["request"]["url"] = url
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("key,value", [("workspaces", []), ("workspace_id", "synthetic"), ("resources", [RESOURCE_ID]),
    ("url", BASE), ("resource_id", None), ("kql", ""), ("timespan", None), ("token", SYNTHETIC_TOKEN)])
@pytest.mark.parametrize("method", ["POST", "GET"])
def test_resource_parameter_envelope_rejects_implicit_or_extra_scope(tmp_path, monkeypatch, method, key, value):
    adapter = synthetic_adapter(b"{}"); monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    params = synthetic_resource_params(); params[key] = value
    with pytest.raises(capture.CaptureError):
        capture.capture(canonical_json_bytes(params), tmp_path / "capture", scope="resource", method=method)
    assert not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("scope", [None, [], "Resource", "subscription", "resource-get", ""])
def test_invalid_capture_scope_fails_before_output(tmp_path, method, scope):
    with pytest.raises(capture.CaptureError):
        capture.capture(canonical_json_bytes(synthetic_resource_params()), tmp_path / "capture", scope=scope, method=method)
    assert not (tmp_path / "capture").exists()


@pytest.mark.parametrize("permissions", [None, [], "synthetic", True, 42])
def test_permission_observation_must_be_a_bounded_object(permissions):
    raw, ctx = inputs(); obj = json.loads(raw); obj["permissions"] = permissions
    raw = canonical_json_bytes(obj); ctx["response"].update(body_sha256=sha256_bytes(raw), body_size_bytes=len(raw))
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("permissions", [{}, {"unknown": ["opaque"]}])
def test_opaque_permission_extensions_never_imply_complete_or_verified(permissions):
    obj = synthetic_resource_response(); obj["permissions"] = permissions
    out = tables.normalize(canonical_json_bytes(obj), input_format="resource-tables")
    assert out["collection_complete"] is None and out["permissions_verified"] is False
    assert out["response_digests"]["permissions"]["sha256"] == sha256_object(permissions)


def test_absent_permissions_remain_unknown_and_old_profile_rejects_new_envelope():
    raw = canonical_json_bytes(synthetic_response())
    out = tables.normalize(raw, input_format="resource-tables")
    assert out["response_digests"]["permissions"] == {"state": "absent", "sha256": None}
    assert out["collection_complete"] is None and not out["permissions_verified"]
    with pytest.raises(ValueError):
        tables.normalize(canonical_json_bytes(synthetic_resource_response()), input_format="tables")


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("status", [301, 403, 404, 414, 429, 500])
def test_resource_http_failure_retains_failed_observation_without_fallback(tmp_path, monkeypatch, method, status):
    raw = b'{"error":{"code":"SyntheticFailure"}}'
    adapter = synthetic_adapter(raw, status=status); monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    report = capture.capture(canonical_json_bytes(synthetic_resource_params()), tmp_path / "capture", method=method, scope="resource")
    assert report["status"] == "FAILED" and not report["artifact_set_complete"] and report["collection_complete"] is False
    assert len(adapter.sent) == 1 and adapter.sent[0][0].method == method
    assert (tmp_path / "capture/capture-observation.json").is_file() and not (tmp_path / "capture/context.json").exists()


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("key", ["resource_id", "kql", "prefer"])
def test_configured_credential_is_not_retained_in_resource_observations(tmp_path, monkeypatch, method, key):
    params = synthetic_resource_params()
    params[key] = params[key] + SYNTHETIC_TOKEN
    adapter = synthetic_adapter(b"{}"); monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    with pytest.raises(capture.CaptureError) as exc:
        capture.capture(canonical_json_bytes(params), tmp_path / "capture", scope="resource", method=method)
    assert SYNTHETIC_TOKEN not in str(exc.value) and not adapter.sent and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("method", ["POST", "GET"])
def test_observed_resource_substitution_is_rejected(tmp_path, monkeypatch, method):
    adapter = synthetic_adapter(b"{}"); original = adapter.send
    def changed(self, prepared, **kwargs):
        response = original(self, prepared, **kwargs)
        response.request.url = response.request.url.replace("synthetic-vm", "different-vm")
        return response
    monkeypatch.setattr(adapter, "send", changed); monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    with pytest.raises(capture.CaptureError):
        capture.capture(canonical_json_bytes(synthetic_resource_params()), tmp_path / "capture", scope="resource", method=method)
    assert not (tmp_path / "capture/receipt.json").exists() and adapter.closed


@pytest.mark.parametrize("method", ["POST", "GET"])
def test_resource_capture_cli_selects_scope_and_keeps_redacted_unknown_exit(tmp_path, monkeypatch, capsys, method):
    raw, _ = inputs(method); monkeypatch.setattr(requests.adapters, "HTTPAdapter", synthetic_adapter(raw))
    params = tmp_path / "params.json"; params.write_bytes(canonical_json_bytes(synthetic_resource_params()))
    monkeypatch.setattr(sys, "argv", ["collector", "azure_foundry_logs", "--capture-context", "--capture-scope", "resource",
        "--capture-method", method, "--params-file", str(params), "--out", str(tmp_path / "capture")])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "CAPTURED" and report["input_format"] == "resource-" + method.lower()
    assert RESOURCE_ID not in json.dumps(report)


def test_scope_option_without_capture_cannot_start_legacy_acquisition(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["collector", "azure_foundry_logs", "--capture-scope", "resource", "--out", str(tmp_path / "capture")])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2 and not (tmp_path / "capture").exists()


@pytest.mark.parametrize("method,expected", [
    ("POST", ["7899d6f9852aca6677018d3c45673a95e43221ee67b743a35e8fbfe88fc5f934", "d1063cb8c29ed051c82bc409a36fe0c2a02d760317741cb8f0a3cabad64e5d77", "66980d5ca94818e1274c45e92c83691f31c8b4873db2b11dc85505ef97580758"]),
    ("GET", ["d91cb669d2d0a95d51a2bcb1207e02926a8a25deb73af2639da2ed8eebed321d", "fdaed79b0773bcf7256dc75e01df40b9927fd43e82bb8715a3f60d31fcbd78a5", "ba2eb6a8656fef61fb6913407f3a8e8ff5f0d81c49e8119a5bde6f8df10904ce"]),
])
def test_reviewed_workspace_capture_artifacts_remain_byte_identical(tmp_path, monkeypatch, method, expected):
    raw = json.dumps(synthetic_response(), indent=3).encode() + b"\n"
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", synthetic_adapter(raw))
    params = synthetic_params()
    if method == "GET":
        params.pop("workspaces")
    capture.capture(canonical_json_bytes(params), tmp_path / "capture", method=method)
    assert [sha256_bytes((tmp_path / "capture" / name).read_bytes()) for name in ("context.json", "projection.json", "receipt.json")] == expected

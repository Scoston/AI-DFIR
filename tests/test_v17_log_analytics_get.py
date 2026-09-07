"""GET URL ambiguity, exact-context binding, and signed offline regression tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import quote
import zipfile

import pytest

from case_export_v17 import verify_case
from v17_integrity import EvidenceRelationship, canonical_json_bytes, sha256_bytes, sha256_object
import v17_log_analytics_context as context
from v17_log_analytics import normalize as normalize_tables
from v17_log_analytics_context_selftest import WORKSPACE, export_fixture, fixture_profile, synthetic_context
from v17_log_analytics_get_selftest import synthetic_get_case, synthetic_get_context
from v17_log_analytics_selftest import synthetic_response
from v17_provenance import wrap_record
from v17_provenance_selftest import CASE_ID, TIMESTAMP

ROOT = Path(__file__).resolve().parents[1]
BASE = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE}/query"


def inputs(*, partial=False):
    raw = json.dumps(synthetic_response(partial=partial), indent=2).encode()
    return raw, synthetic_get_context(raw)


def project(raw, ctx):
    return context.normalize(raw, context_raw=canonical_json_bytes(ctx), input_format="workspace-get")


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "log_analytics_context_v17.py"), *map(str, args)],
                          capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("partial", [False, True])
def test_signed_get_context_replay_requires_no_network_execution_or_extraction(tmp_path, monkeypatch, partial):
    fixture = synthetic_get_case(tmp_path / "case", partial=partial)
    export_fixture(fixture)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network, execution, or extraction")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
    replay = result["reconstruction"]["deterministic_replay"]
    transform = replay["transforms"][0]
    assert result["valid"] and replay["status"] == "PASS" and transform["request_context_bound"]
    assert transform["partial_error_recorded"] is partial
    assert transform["collection_complete"] is (False if partial else None)
    assert not transform["query_execution_verified"] and not transform["query_reexecuted"]
    assert not transform["source_authenticity_verified"] and not transform["request_scope_verified"]


def test_get_projection_binds_exact_url_decoded_parameters_and_existing_table_semantics():
    raw, ctx = inputs()
    output = project(raw, ctx)
    request = output["request"]
    query = synthetic_context(raw)["request"]["body"]["query"]
    assert output["result"] == normalize_tables(raw, input_format="tables")
    assert output["source_sha256"] == sha256_bytes(raw)
    assert output["context_sha256"] == sha256_bytes(canonical_json_bytes(ctx))
    assert output["request_sha256"] == sha256_object(ctx["request"])
    assert request["endpoint_sha256"] == sha256_object(BASE)
    assert request["url_sha256"] == sha256_object(ctx["request"]["url"])
    assert request["query_string_sha256"] == sha256_object(ctx["request"]["url"].partition("?")[2])
    assert request["parameters_sha256"] == sha256_object({"query": query, "timespan": "PT12H"})
    assert request["query_sha256"] == sha256_object(query)
    assert request["body_state"] == "absent" and request["body_sha256"] == sha256_object(None)
    assert request["parameter_order"] == ["query", "timespan"]
    assert output["context_source"] == "retained-assertion"
    for marker in (query, "SYNTHETIC-PRIVATE", WORKSPACE, "PT12H", "wait=30", BASE):
        assert marker not in json.dumps(output)


@pytest.mark.parametrize("encoded,decoded", [
    ("print%20x%3D1", "print x=1"), ("print%20s%3D%27a%2Bb%27", "print s='a+b'"),
    ("q%09%0D%0A", "q\t\r\n"), ("%C3%A9%F0%9F%94%8E", "é🔎"),
    ("q%26timespan%3DPT1H", "q&timespan=PT1H"), ("q%3Btimespan%3DPT1H", "q;timespan=PT1H"),
    ("q%23fragment", "q#fragment"), ("q%3Fquery%3Dother", "q?query=other"),
    ("q%2520x", "q%20x"), ("%2526timespan%253DPT1H", "%26timespan%3DPT1H"),
    ("%2f%2F", "//"), ("unreserved._~-012", "unreserved._~-012"),
])
def test_utf8_percent_decode_occurs_exactly_once_without_parameter_injection(encoded, decoded):
    raw, ctx = inputs()
    ctx["request"]["url"] = BASE + "?query=" + encoded
    output = project(raw, ctx)
    assert output["request"]["query_sha256"] == sha256_object(decoded)
    assert output["request"]["query_size_bytes"] == len(decoded.encode("utf-8"))
    assert output["request"]["timespan"] == {"state": "absent", "sha256": None}


@pytest.mark.parametrize("left,right", [
    ("query=%71", "query=q"), ("query=%2f", "query=%2F"),
    ("query=q", "%71uery=q"),
    ("query=q&timespan=PT1H", "timespan=PT1H&query=q"),
])
def test_equivalent_decoded_parameters_never_erase_original_url_spelling_or_order(left, right):
    raw, ctx = inputs()
    ctx["request"]["url"] = BASE + "?" + left
    output = project(raw, ctx)
    ctx["request"]["url"] = BASE + "?" + right
    changed = project(raw, ctx)
    assert changed["request"]["parameters_sha256"] == output["request"]["parameters_sha256"]
    assert changed["request"]["query_sha256"] == output["request"]["query_sha256"]
    assert changed["request"]["url_sha256"] != output["request"]["url_sha256"]
    assert context.compare_replay(raw, canonical_json_bytes(output), context_raw=canonical_json_bytes(ctx),
                                  input_format="workspace-get")["status"] == "FAIL"


def test_unicode_normalization_is_never_inferred():
    raw, ctx = inputs()
    ctx["request"]["url"] = BASE + "?query=%C3%A9"
    first = project(raw, ctx)
    ctx["request"]["url"] = BASE + "?query=e%CC%81"
    assert project(raw, ctx)["request"]["query_sha256"] != first["request"]["query_sha256"]


@pytest.mark.parametrize("parameters", [
    "", "query", "query=", "query=%20%09", "timespan=PT1H", "=q", "Query=q",
    "query=q&query=q", "query=q&%71uery=q", "%71uery=q&query=q",
    "query=q&timespan=PT1H&timespan=PT2H", "query=q&timespan=PT1H&extra=x",
    "query=q&", "&query=q", "query=q&&timespan=PT1H", "query=q;timespan=PT1H",
    "query=q&timespan", "query=q&timespan=", "query=q&timespan=%0A",
    "query=q&workspaces=" + WORKSPACE, "query=q&api-version=v1",
    "query=q&access_token=SYNTHETIC-SECRET", "query=q&%61uthorization=SYNTHETIC-SECRET",
    "query=q&%2574imespan=PT1H", "query=q&timespan[]=PT1H",
    "query=q+x", "query=q x", "query=q=x", "query=q/x", "query=q?x",
    "query=q#fragment", "query=q\\x", "query=é", "query=q\n", "query=q\t", "query=q\x7f",
    "query=%", "query=%2", "query=%GG", "query=%0X", "query=%FF", "query=%C0%AF",
    "query=%ED%A0%80", "query=%E2%82", "query=%00", "query=q%7F", "query=q%01",
])
def test_ambiguous_malformed_duplicate_or_unimplemented_parameters_fail_closed(parameters):
    raw, ctx = inputs()
    ctx["request"]["url"] = BASE + "?" + parameters
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("url", [
    BASE, BASE + "?", BASE + "/?query=q", BASE + "#fragment?query=q",
    BASE.replace("https://", "http://") + "?query=q",
    BASE.replace("api.loganalytics.io", "api.loganalytics.io.evil.invalid") + "?query=q",
    BASE.replace("api.loganalytics.io", "user@api.loganalytics.io") + "?query=q",
    BASE.replace("api.loganalytics.io", "api.loganalytics.io:443") + "?query=q",
    BASE.replace("api.loganalytics.io", "API.LOGANALYTICS.IO") + "?query=q",
    BASE.replace("/v1/", "/v2/") + "?query=q", BASE.replace(WORKSPACE, "not-a-guid") + "?query=q",
    BASE.replace("/query", "/../query") + "?query=q",
    "https://api.loganalytics.io/v1/subscriptions/synthetic/query?query=q",
    None, [], 42,
])
def test_get_endpoint_is_explicit_without_url_normalization(url):
    raw, ctx = inputs()
    ctx["request"]["url"] = url
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("host", ["api.loganalytics.io", "api.loganalytics.azure.com"])
def test_both_fixed_public_workspace_get_endpoints(host):
    raw, ctx = inputs()
    ctx["request"]["url"] = ctx["request"]["url"].replace("api.loganalytics.io", host)
    assert project(raw, ctx)["request"]["endpoint_host"] == host


@pytest.mark.parametrize("change", [
    lambda c: c["request"].pop("body"), lambda c: c["request"].update(body={}),
    lambda c: c["request"].update(body=""), lambda c: c["request"].update(body={"query": "q"}),
    lambda c: c["request"].update(body=False), lambda c: c["request"].update(method="get"),
    lambda c: c["request"].update(method="POST"), lambda c: c["request"].update(params={"query": "q"}),
    lambda c: c["request"].update(headers=None), lambda c: c["request"].pop("headers"),
    lambda c: c["request"]["headers"].update(authorization="Bearer SYNTHETIC-SECRET"),
    lambda c: c["request"]["headers"].update(cookie="SYNTHETIC-SECRET"),
    lambda c: c["request"]["headers"].update(Accept="application/json"),
    lambda c: c["request"]["headers"].update(accept=""),
    lambda c: c["request"]["headers"].update(accept="application/json\r\nInjected: true"),
    lambda c: c["response"]["headers"].update({"set-cookie": "SYNTHETIC-SECRET"}),
])
def test_get_requires_recorded_absent_body_and_allowlisted_header_observations(change):
    raw, ctx = inputs()
    change(ctx)
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("headers", [{}, {"accept": "application/json"}, {"content-type": "text/plain"},
    {"prefer": "wait=30", "x-ms-client-request-id": "synthetic", "accept": "application/json"}])
def test_get_headers_are_optional_observations_not_an_inferred_body_type(headers):
    raw, ctx = inputs()
    ctx["request"]["headers"] = headers
    assert project(raw, ctx)["request"]["headers_sha256"] == sha256_object(headers)


@pytest.mark.parametrize("query", ["q" * 65536, "q" * 65530 + "é" * 3])
def test_decoded_query_byte_boundary_is_preserved(query):
    raw, ctx = inputs()
    ctx["request"]["url"] = BASE + "?query=" + quote(query, safe="")
    assert project(raw, ctx)["request"]["query_size_bytes"] == 65536
    ctx["request"]["url"] += "q"
    with pytest.raises(ValueError):
        project(raw, ctx)


def test_url_byte_limit_is_checked_before_decoding_and_does_not_expand_with_context_budget(monkeypatch):
    raw, ctx = inputs()
    prefix = BASE + "?query="
    triples, remainder = divmod(context.MAX_GET_URL_BYTES - len(prefix), 3)
    ctx["request"]["url"] = prefix + "%61" * triples + "a" * remainder
    assert project(raw, ctx)["request"]["url_size_bytes"] == context.MAX_GET_URL_BYTES
    ctx["request"]["url"] += "a"
    monkeypatch.setattr(context, "_get_component", lambda *a: pytest.fail("oversized URL reached decoder"))
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("timespan", ["PT12H", "2026-01-01/2026-01-02", "uninterpreted-observation", "x" * 256])
def test_timespan_is_opaque_and_never_resolved_against_current_time(timespan):
    raw, ctx = inputs()
    ctx["request"]["url"] = BASE + "?query=q&timespan=" + quote(timespan, safe="")
    assert project(raw, ctx)["request"]["timespan"] == {"state": "present", "sha256": sha256_object(timespan)}


@pytest.mark.parametrize("field,value", [("timespan", "x" * 257), ("accept", "x" * 4097)])
def test_decoded_timespan_and_header_budgets(field, value):
    raw, ctx = inputs()
    if field == "timespan":
        ctx["request"]["url"] = BASE + "?query=q&timespan=" + value
    else:
        ctx["request"]["headers"][field] = value
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("status", [True, 200.0, "200", None, 204, 400, 429, 500])
def test_get_context_cannot_treat_unknown_or_failed_http_status_as_supported_results(status):
    raw, ctx = inputs()
    ctx["response"]["status"] = status
    with pytest.raises(ValueError):
        context.normalize(raw, context_raw=json.dumps(ctx).encode(), input_format="workspace-get")


@pytest.mark.parametrize("field,value", [("body_sha256", "0" * 64), ("body_size_bytes", 0)])
def test_exact_response_pin_is_verified_before_table_parser(monkeypatch, field, value):
    raw, ctx = inputs()
    ctx["response"][field] = value
    monkeypatch.setattr(context, "normalize_tables", lambda *a, **k: pytest.fail("unpinned response reached parser"))
    with pytest.raises(ValueError):
        project(raw, ctx)


@pytest.mark.parametrize("raw", [b'{"tables":[],"tables":[]}', b'{"tables":[],"error":{"code":"Fatal"}}',
    b'{"tables":[{"name":"x","columns":[{"name":"v","type":"long"}],"rows":[[9007199254740992]]}]}'])
def test_get_binding_preserves_response_parser_and_numeric_restrictions(raw):
    with pytest.raises(ValueError):
        project(raw, synthetic_get_context(raw))


def test_empty_results_never_prove_complete_collection():
    raw = b'{"tables":[]}'
    result = project(raw, synthetic_get_context(raw))
    assert result["result"]["row_count"] == 0 and result["collection_complete"] is None


@pytest.mark.parametrize("change", [
    lambda c: c["request"].update(url=c["request"]["url"].replace("AzureActivity", "AnotherTable")),
    lambda c: c["request"].update(url=c["request"]["url"].replace("PT12H", "PT1H")),
    lambda c: c["request"].update(url=c["request"]["url"].partition("&")[0]),
    lambda c: c["request"].update(url=c["request"]["url"].replace(WORKSPACE, "00000000-0000-0000-0000-000000000099")),
    lambda c: c["request"].update(url=c["request"]["url"].replace("%2F", "%2f")),
    lambda c: c["request"].update(url=c["request"]["url"].replace("?query=", "?%71uery=")),
    lambda c: c["request"]["headers"].update(prefer="wait=60"),
    lambda c: c["response"]["headers"].update({"x-ms-request-id": "changed"}),
])
def test_signed_context_substitution_retains_integrity_pass_but_replay_fails(tmp_path, change):
    fixture = synthetic_get_case(tmp_path / "case")
    ctx = json.loads(fixture["context"])
    change(ctx)
    fixture["context"] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["provenance_integrity"] == "PASS"
    assert result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


@pytest.mark.parametrize("metadata", [
    {"input_format": "workspace-get"}, {"input_format": "resource-put", "context_artifact_id": "QUERY-CONTEXT"},
    {"input_format": [], "context_artifact_id": "QUERY-CONTEXT"},
    {"input_format": "workspace-get", "context_artifact_id": "QUERY-CONTEXT", "url": BASE},
    *[{"input_format": "workspace-get", "context_artifact_id": ref} for ref in
      (None, "missing", "QUERY-RAW", "QUERY-PROJECTION", "../../query-context.json")],
])
def test_get_lineage_requires_fixed_metadata_and_separately_bound_context(tmp_path, metadata):
    fixture = synthetic_get_case(tmp_path / "case")
    fixture["metadata"] = metadata
    with pytest.raises(ValueError):
        export_fixture(fixture)
    assert not fixture["package"].exists()


def test_get_context_is_a_second_input_for_cycle_detection(tmp_path):
    fixture = synthetic_get_case(tmp_path / "case")
    profile = fixture_profile(fixture)
    relation = EvidenceRelationship(case_id=CASE_ID, parent_artifact_id="QUERY-PROJECTION", child_artifact_id="QUERY-CONTEXT",
                                    relationship_type="derived-from", transformation="unimplemented", transformation_version="1",
                                    created_at=TIMESTAMP, metadata={})
    profile["relationships"].append(wrap_record("relationships", relation))
    with pytest.raises(ValueError, match="cyclic"):
        export_fixture(fixture, profile=profile)


@pytest.mark.parametrize("field", ["request_scope_verified", "query_execution_verified", "collection_complete"])
def test_signed_overclaimed_get_projection_fails_replay(tmp_path, field):
    fixture = synthetic_get_case(tmp_path / "case")
    fixture["output"][field] = True
    export_fixture(fixture)
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"


def test_unknown_transform_version_is_incomplete_without_invoking_get_parser(tmp_path, monkeypatch):
    fixture = synthetic_get_case(tmp_path / "case")
    fixture["version"] = "999"
    export_fixture(fixture)
    monkeypatch.setattr(context, "_get_request", lambda *a: pytest.fail("unsupported transform executed"))
    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "INCOMPLETE"


def test_unverified_get_context_never_reaches_parser(tmp_path, monkeypatch):
    fixture = synthetic_get_case(tmp_path / "case")
    export_fixture(fixture)
    altered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(fixture["package"]) as source, zipfile.ZipFile(altered, "w") as target:
        for item in source.infolist():
            target.writestr(item, b'{}' if item.filename.endswith("query-context.json") else source.read(item))
    monkeypatch.setattr(context, "_get_request", lambda *a: pytest.fail("unverified context reached parser"))
    result = verify_case(altered, fixture["public"], replay_transforms=True)
    assert not result["valid"] and result.get("reconstruction") is None


def test_whitespace_changes_bind_inputs_but_comparison_canonicalizes_only_projection():
    raw, ctx = inputs()
    output = project(raw, ctx)
    recorded = json.dumps(output, indent=2).encode()
    assert context.compare_replay(raw, recorded, context_raw=canonical_json_bytes(ctx), input_format="workspace-get")["status"] == "PASS"
    assert context.compare_replay(raw, recorded, context_raw=json.dumps(ctx, indent=2).encode(), input_format="workspace-get")["status"] == "FAIL"
    with pytest.raises(ValueError):
        context.compare_replay(raw + b' ', recorded, context_raw=canonical_json_bytes(ctx), input_format="workspace-get")
    ctx["response"].update(body_sha256=sha256_bytes(raw + b' '), body_size_bytes=len(raw) + 1)
    assert context.compare_replay(raw + b' ', recorded, context_raw=canonical_json_bytes(ctx), input_format="workspace-get")["status"] == "FAIL"


@pytest.mark.parametrize("partial", [False, True])
def test_preexisting_post_projection_digests_are_unchanged(partial):
    raw, _ = inputs(partial=partial)
    output = context.normalize(raw, context_raw=canonical_json_bytes(synthetic_context(raw)), input_format="workspace-post")
    # Captured from reviewed main before GET support; guards versioned semantics.
    expected = ("ae1334d9b62d171ee8b5b633b856d49f34f89887ed20cd7c3f403c9672e6b01a" if partial else
                "e8e00e39449acf0dce5db408fc19e5f724687d2ef58b3f5f5147abe1e60a1b2c")
    assert sha256_object(output) == expected


@pytest.mark.parametrize("partial", [False, True])
def test_cli_get_create_compare_and_mismatch_with_private_context_redaction(tmp_path, partial):
    raw, ctx = inputs(partial=partial)
    source, retained, output = [tmp_path / name for name in ("source.json", "context.json", "projection.json")]
    source.write_bytes(raw)
    retained.write_bytes(canonical_json_bytes(ctx))
    args = ("--input", source, "--context", retained, "--format", "workspace-get")
    made = cli(*args, "--out", output)
    report = json.loads(made.stdout)
    assert made.returncode == 0 and report["status"] == "NORMALIZED"
    assert report["collection_complete"] is (False if partial else None)
    assert report["partial_error_recorded"] is partial and not report["query_reexecuted"]
    compared = cli(*args, "--compare", output)
    assert compared.returncode == 0 and json.loads(compared.stdout)["status"] == "PASS"
    ctx["request"]["url"] += "%20"
    retained.write_bytes(canonical_json_bytes(ctx))
    mismatch = cli(*args, "--compare", output)
    assert mismatch.returncode == 1 and json.loads(mismatch.stdout)["status"] == "FAIL"
    for result in (made, compared, mismatch):
        assert "SYNTHETIC-PRIVATE" not in result.stdout and not result.stderr
        assert BASE not in result.stdout and str(tmp_path) not in result.stdout


def test_cli_refuses_credential_parameters_without_output_or_value_disclosure(tmp_path):
    raw, ctx = inputs()
    ctx["request"]["url"] = BASE + "?query=q&access_token=SYNTHETIC-SECRET"
    source, retained, output = [tmp_path / name for name in ("source.json", "context.json", "projection.json")]
    source.write_bytes(raw)
    retained.write_bytes(canonical_json_bytes(ctx))
    result = cli("--input", source, "--context", retained, "--format", "workspace-get", "--out", output)
    assert result.returncode == 1 and not output.exists() and not result.stderr
    assert "SYNTHETIC-SECRET" not in result.stdout and str(tmp_path) not in result.stdout


def test_cli_preserves_existing_evidence_and_symlink_targets(tmp_path):
    raw, ctx = inputs()
    source, retained, output, link = [tmp_path / name for name in ("source.json", "context.json", "out.json", "link.json")]
    source.write_bytes(raw)
    retained.write_bytes(canonical_json_bytes(ctx))
    output.write_bytes(b'existing')
    link.symlink_to(retained)
    for target in (source, retained, output, link):
        assert cli("--input", source, "--context", retained, "--format", "workspace-get", "--out", target).returncode == 1
    assert source.read_bytes() == raw and retained.read_bytes() == canonical_json_bytes(ctx)
    assert output.read_bytes() == b'existing' and link.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_cli_get_context_rejects_fifo_without_blocking(tmp_path):
    raw, _ = inputs()
    source, retained = tmp_path / "source.json", tmp_path / "pipe"
    source.write_bytes(raw)
    os.mkfifo(retained)
    assert cli("--input", source, "--context", retained, "--format", "workspace-get", "--out", tmp_path / "out").returncode == 1


def test_signed_case_cli_retains_integrity_pass_and_reports_failed_get_replay(tmp_path):
    fixture = synthetic_get_case(tmp_path / "case")
    fixture["output"]["request"]["query_sha256"] = "0" * 64
    export_fixture(fixture)
    result = subprocess.run([sys.executable, str(ROOT / "replay_case_v17.py"), "--zip", str(fixture["package"]),
                             "--export-public-key", str(fixture["public"]), "--replay-transforms"],
                            capture_output=True, text=True, timeout=15)
    report = json.loads(result.stdout)
    assert result.returncode == 1 and report["valid"] and report["reconstruction"]["deterministic_replay"]["status"] == "FAIL"

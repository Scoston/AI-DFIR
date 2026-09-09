from __future__ import annotations

import json
from copy import deepcopy

import pytest

import v18_agent_execution_record as aer
import v18_otlp_envelope as otlp

T = "2026-09-09T19:30:00Z"
TRACE = "0123456789abcdef0123456789abcdef"
OTHER_TRACE = "fedcba9876543210fedcba9876543210"
ROOT = "0123456789abcdef"
CHILD = "fedcba9876543210"
MISSING = "1111111111111111"


def _attr(key: str, value: str) -> dict:
    return {"key": key, "value": {"stringValue": value}}


def trace_envelope() -> dict:
    return {
        "resourceSpans": [{
            "resource": {"attributes": [_attr("service.name", "agent-service")]},
            "schemaUrl": "https://opentelemetry.io/schemas/1.40.0",
            "scopeSpans": [{
                "scope": {"name": "agent.instrumentation", "version": "1.2.3",
                          "attributes": [_attr("scope.role", "agent")]},
                "schemaUrl": "https://opentelemetry.io/schemas/1.40.0",
                "spans": [
                    {
                        "traceId": TRACE,
                        "spanId": ROOT,
                        "name": "invoke-agent",
                        "attributes": [
                            _attr("gen_ai.agent.id", "agent-1"),
                            _attr("gen_ai.operation.name", "invoke_agent"),
                            _attr("gen_ai.request.model", "model-a"),
                        ],
                    },
                    {
                        "traceId": TRACE,
                        "spanId": CHILD,
                        "parentSpanId": ROOT,
                        "name": "execute-tool",
                        "attributes": [
                            _attr("gen_ai.operation.name", "execute_tool"),
                            _attr("gen_ai.tool.name", "disable-account"),
                        ],
                    },
                ],
            }],
        }],
    }


def log_envelope() -> dict:
    return {
        "resourceLogs": [{
            "resource": {"attributes": [_attr("service.name", "agent-service")]},
            "scopeLogs": [{
                "scope": {"name": "agent.logs", "version": "1.0"},
                "logRecords": [
                    {"timeUnixNano": "1", "traceId": TRACE, "spanId": CHILD,
                     "severityText": "INFO", "body": {"stringValue": "tool completed"}},
                    {"timeUnixNano": "2", "traceId": TRACE,
                     "body": {"stringValue": "trace-only log"}},
                    {"timeUnixNano": "3", "traceId": TRACE, "spanId": MISSING,
                     "body": {"stringValue": "missing span"}},
                    {"timeUnixNano": "4", "traceId": OTHER_TRACE, "spanId": ROOT,
                     "body": {"stringValue": "external trace"}},
                    {"timeUnixNano": "5", "body": {"stringValue": "unlinked"}},
                ],
            }],
        }],
    }


def test_trace_envelope_preserves_exact_bytes_and_context() -> None:
    payload = json.dumps(trace_envelope(), separators=(",", ":")).encode()
    record = otlp.import_trace_envelope(payload, semantic_conventions_version="1.40.0", observed_at=T)
    assert otlp.validate_trace_import(record)
    assert record["raw_envelope"]["sha256"] == aer.sha256_bytes(payload)
    assert record["claims"]["source_bytes_preserved"] is True
    assert record["claims"]["collection_complete"] is False
    assert record["diagnostics"]["span_count"] == 2
    assert record["diagnostics"]["trace_ids"] == [TRACE]
    context = record["entries"][0]["context"]
    assert context["resource"]["attributes"]["service.name"] == "agent-service"
    assert context["scope"]["name"] == "agent.instrumentation"


def test_object_import_is_marked_canonicalized_not_exact_source_bytes() -> None:
    record = otlp.import_trace_envelope(trace_envelope(), semantic_conventions_version="1.40.0", observed_at=T)
    assert record["raw_envelope"]["serialization"] == "canonicalized-object"
    assert record["claims"]["source_bytes_preserved"] is False


def test_imported_trace_reconstructs_and_binds_envelope_context() -> None:
    trace = otlp.import_trace_envelope(trace_envelope(), semantic_conventions_version="1.40.0", observed_at=T)
    rebuilt = otlp.reconstruct_imported_trace(trace, trace_id=TRACE, record_id="case-otlp/trace-1")
    assert otlp.validate_imported_reconstruction(rebuilt, trace_import=trace)
    assert rebuilt["source_envelope_evidence"]["sha256"] == trace["raw_envelope"]["sha256"]
    assert len(rebuilt["span_contexts"]) == 2
    assert rebuilt["reconstruction"]["diagnostics"]["span_count"] == 2
    assert rebuilt["claims"]["business_causality_proven"] is False
    assert rebuilt["reconstruction"]["claims"]["intent_causality_proven"] is False


def test_log_import_and_trace_log_correlation_are_noncausal() -> None:
    trace = otlp.import_trace_envelope(trace_envelope(), semantic_conventions_version="1.40.0", observed_at=T)
    logs = otlp.import_log_envelope(log_envelope(), observed_at=T)
    assert otlp.validate_log_import(logs)
    assert logs["diagnostics"]["log_record_count"] == 5
    report = otlp.correlate_trace_logs(trace, logs)
    assert otlp.validate_trace_log_correlation(report, trace_import=trace, log_import=logs)
    assert report["summary"] == {
        "log_records": 5,
        "matched_trace_and_span": 1,
        "matched_trace_only": 1,
        "trace_present_span_missing": 1,
        "external_or_unobserved_trace": 1,
        "unlinked": 1,
    }
    assert report["claims"]["log_generated_by_span_proven"] is False
    assert report["claims"]["business_causality_proven"] is False


def test_empty_signal_envelopes_are_valid_but_not_complete() -> None:
    traces = otlp.import_trace_envelope({"resourceSpans": []}, semantic_conventions_version="1.40.0", observed_at=T)
    logs = otlp.import_log_envelope({"resourceLogs": []}, observed_at=T)
    assert traces["diagnostics"]["span_count"] == 0
    assert logs["diagnostics"]["log_record_count"] == 0
    assert traces["claims"]["collection_complete"] is False
    assert logs["claims"]["collection_complete"] is False


def test_wrong_signal_invalid_ids_and_duplicate_attributes_fail_closed() -> None:
    with pytest.raises(ValueError, match="log envelope"):
        otlp.import_trace_envelope(log_envelope(), semantic_conventions_version="1.40.0", observed_at=T)
    with pytest.raises(ValueError, match="trace envelope"):
        otlp.import_log_envelope(trace_envelope(), observed_at=T)

    bad_id = trace_envelope()
    bad_id["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"] = "abc"
    with pytest.raises(ValueError, match="traceId"):
        otlp.import_trace_envelope(bad_id, semantic_conventions_version="1.40.0", observed_at=T)

    duplicate = trace_envelope()
    attrs = duplicate["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
    attrs.append(_attr("gen_ai.agent.id", "forged-duplicate"))
    with pytest.raises(ValueError, match="duplicate OTLP attribute"):
        otlp.import_trace_envelope(duplicate, semantic_conventions_version="1.40.0", observed_at=T)


def test_bounds_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(otlp, "MAX_SPANS", 1)
    with pytest.raises(ValueError, match="span count"):
        otlp.import_trace_envelope(trace_envelope(), semantic_conventions_version="1.40.0", observed_at=T)

    monkeypatch.setattr(otlp, "MAX_LOG_RECORDS", 1)
    with pytest.raises(ValueError, match="log record count"):
        otlp.import_log_envelope(log_envelope(), observed_at=T)


def test_forged_import_and_correlation_claims_are_rejected() -> None:
    trace = otlp.import_trace_envelope(trace_envelope(), semantic_conventions_version="1.40.0", observed_at=T)
    forged = deepcopy(trace)
    forged["claims"]["collection_complete"] = True
    with pytest.raises(ValueError, match="collection_complete"):
        otlp.validate_trace_import(forged)

    logs = otlp.import_log_envelope(log_envelope(), observed_at=T)
    report = otlp.correlate_trace_logs(trace, logs)
    report["claims"]["business_causality_proven"] = True
    with pytest.raises(ValueError, match="business_causality_proven"):
        otlp.validate_trace_log_correlation(report, trace_import=trace, log_import=logs)

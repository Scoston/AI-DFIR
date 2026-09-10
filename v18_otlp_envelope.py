"""Bounded OTLP JSON trace/log envelope intake for AI-DFIR v1.8.

The importer preserves the source envelope bytes and extracts observable OTLP
structure without treating trace/log correlation as proof of business causality.
"""
from __future__ import annotations

import base64
import json
import re
from collections import Counter
from copy import deepcopy
from datetime import datetime
from typing import Any

import v18_agent_execution_record as aer
import v18_otel_genai as otel
import v18_runtime_reconstruction as reconstruction

TRACE_SCHEMA = "ai-dfir/otlp-trace-envelope/v1.8"
LOG_SCHEMA = "ai-dfir/otlp-log-envelope/v1.8"
CORRELATION_SCHEMA = "ai-dfir/otlp-trace-log-correlation/v1.8"
RECONSTRUCTION_SCHEMA = "ai-dfir/otlp-envelope-reconstruction/v1.8"
OTLP_CONTRACT_VERSION = "1.11.0"

MAX_ENVELOPE_BYTES = 64 * 1024 * 1024
MAX_RESOURCE_GROUPS = 2_048
MAX_SCOPE_GROUPS = 8_192
MAX_SPANS = 50_000
MAX_LOG_RECORDS = 100_000
TRACE_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
SPAN_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")


def _time(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("observed_at must be a non-empty ISO-8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid observed_at") from exc
    return value


def _validate_id(value: Any, *, trace: bool, field: str) -> None:
    if value in (None, ""):
        return
    pattern = TRACE_ID_RE if trace else SPAN_ID_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        expected = "32" if trace else "16"
        raise ValueError(f"{field} must be empty or {expected} hexadecimal characters")


def _json_bytes(source: bytes | bytearray | dict[str, Any]) -> tuple[bytes, dict[str, Any], str]:
    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
        serialization = "observed-json-bytes"
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise ValueError("OTLP envelope exceeds byte bound")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("OTLP JSON must be UTF-8") from exc
        def reject_constant(value: str) -> None:
            raise ValueError(f"non-finite JSON number is not permitted: {value}")
        try:
            value = json.loads(text, parse_constant=reject_constant)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid OTLP JSON") from exc
    elif isinstance(source, dict):
        value = deepcopy(source)
        raw = aer.canonical_bytes(value)
        serialization = "canonicalized-object"
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise ValueError("OTLP envelope exceeds byte bound")
    else:
        raise TypeError("source must be OTLP JSON bytes or an object")
    if not isinstance(value, dict):
        raise ValueError("OTLP envelope root must be an object")
    return raw, value, serialization


def _kv_attributes(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, list):
        seen: set[str] = set()
        for item in raw:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                raise ValueError("invalid OTLP attribute")
            if item["key"] in seen:
                raise ValueError(f"duplicate OTLP attribute key: {item['key']}")
            seen.add(item["key"])
    return otel.attributes({"attributes": raw})


def _scope_context(scope_group: dict[str, Any]) -> dict[str, Any]:
    scope = scope_group.get("scope") or {}
    if not isinstance(scope, dict):
        raise ValueError("OTLP instrumentation scope must be an object")
    context: dict[str, Any] = {
        "name": scope.get("name"),
        "version": scope.get("version"),
        "attributes": _kv_attributes(scope.get("attributes", [])),
        "dropped_attributes_count": scope.get("droppedAttributesCount"),
        "schema_url": scope_group.get("schemaUrl"),
    }
    return context


def _resource_context(resource_group: dict[str, Any]) -> dict[str, Any]:
    resource = resource_group.get("resource") or {}
    if not isinstance(resource, dict):
        raise ValueError("OTLP resource must be an object")
    return {
        "attributes": _kv_attributes(resource.get("attributes", [])),
        "dropped_attributes_count": resource.get("droppedAttributesCount"),
        "schema_url": resource_group.get("schemaUrl"),
    }


def _source_ref(record: dict[str, Any], artifact_type: str) -> dict[str, Any]:
    raw = record["raw_envelope"]
    return aer.evidence_ref(
        artifact_type,
        raw["sha256"],
        raw["size"],
        locator=f"otlp:{record['record_sha256'][:16]}",
        observed_at=record["observed_at"],
    )


def _raw_info(raw: bytes, serialization: str) -> dict[str, Any]:
    return {
        "sha256": aer.sha256_bytes(raw),
        "size": len(raw),
        "base64": base64.b64encode(raw).decode("ascii"),
        "serialization": serialization,
    }


def _raw_envelope_object(record: dict[str, Any]) -> dict[str, Any]:
    raw = base64.b64decode(record["raw_envelope"]["base64"], validate=True)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("retained OTLP envelope cannot be replay-parsed") from exc
    if not isinstance(value, dict):
        raise ValueError("retained OTLP envelope root must be an object")
    return value


def _trace_source_bindings(envelope: dict[str, Any]) -> list[tuple[str, str]]:
    bindings: list[tuple[str, str]] = []
    groups = envelope.get("resourceSpans", [])
    if not isinstance(groups, list):
        raise ValueError("retained resourceSpans must be an array")
    for resource_index, resource_group in enumerate(groups):
        if not isinstance(resource_group, dict):
            raise ValueError("retained resourceSpans entry must be an object")
        resource_context = _resource_context(resource_group)
        scopes = resource_group.get("scopeSpans", [])
        if not isinstance(scopes, list):
            raise ValueError("retained scopeSpans must be an array")
        for scope_index, scope_group in enumerate(scopes):
            if not isinstance(scope_group, dict):
                raise ValueError("retained scopeSpans entry must be an object")
            scope_context = _scope_context(scope_group)
            spans = scope_group.get("spans", [])
            if not isinstance(spans, list):
                raise ValueError("retained spans must be an array")
            for span_index, span in enumerate(spans):
                if not isinstance(span, dict):
                    raise ValueError("retained span must be an object")
                _kv_attributes(span.get("attributes", []))
                context = {
                    "resource_index": resource_index,
                    "scope_index": scope_index,
                    "span_index": span_index,
                    "resource": deepcopy(resource_context),
                    "scope": deepcopy(scope_context),
                }
                bindings.append((
                    aer.sha256_bytes(aer.canonical_bytes(span)),
                    aer.sha256_bytes(aer.canonical_bytes(context)),
                ))
    return sorted(bindings)


def _log_source_bindings(envelope: dict[str, Any]) -> list[tuple[str, str]]:
    bindings: list[tuple[str, str]] = []
    groups = envelope.get("resourceLogs", [])
    if not isinstance(groups, list):
        raise ValueError("retained resourceLogs must be an array")
    for resource_index, resource_group in enumerate(groups):
        if not isinstance(resource_group, dict):
            raise ValueError("retained resourceLogs entry must be an object")
        resource_context = _resource_context(resource_group)
        scopes = resource_group.get("scopeLogs", [])
        if not isinstance(scopes, list):
            raise ValueError("retained scopeLogs must be an array")
        for scope_index, scope_group in enumerate(scopes):
            if not isinstance(scope_group, dict):
                raise ValueError("retained scopeLogs entry must be an object")
            scope_context = _scope_context(scope_group)
            logs = scope_group.get("logRecords", [])
            if not isinstance(logs, list):
                raise ValueError("retained logRecords must be an array")
            for log_index, log_record in enumerate(logs):
                if not isinstance(log_record, dict):
                    raise ValueError("retained log record must be an object")
                context = {
                    "resource_index": resource_index,
                    "scope_index": scope_index,
                    "log_index": log_index,
                    "resource": deepcopy(resource_context),
                    "scope": deepcopy(scope_context),
                }
                bindings.append((
                    aer.sha256_bytes(aer.canonical_bytes(log_record)),
                    aer.sha256_bytes(aer.canonical_bytes(context)),
                ))
    return sorted(bindings)


def import_trace_envelope(
    source: bytes | bytearray | dict[str, Any],
    *,
    semantic_conventions_version: str,
    observed_at: str,
) -> dict[str, Any]:
    """Import one OTLP JSON traces envelope without network activity."""
    _time(observed_at)
    raw, envelope, serialization = _json_bytes(source)
    if "resourceLogs" in envelope:
        raise ValueError("log envelope supplied to trace importer")
    groups = envelope.get("resourceSpans", [])
    if not isinstance(groups, list):
        raise ValueError("resourceSpans must be an array")
    if len(groups) > MAX_RESOURCE_GROUPS:
        raise ValueError("resourceSpans exceeds resource-group bound")

    adapted: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    scope_count = 0
    missing_trace_ids: list[str] = []
    missing_span_ids: list[str] = []

    for resource_index, resource_group in enumerate(groups):
        if not isinstance(resource_group, dict):
            raise ValueError("resourceSpans entry must be an object")
        resource_context = _resource_context(resource_group)
        scopes = resource_group.get("scopeSpans", [])
        if not isinstance(scopes, list):
            raise ValueError("scopeSpans must be an array")
        scope_count += len(scopes)
        if scope_count > MAX_SCOPE_GROUPS:
            raise ValueError("scopeSpans exceeds scope-group bound")
        for scope_index, scope_group in enumerate(scopes):
            if not isinstance(scope_group, dict):
                raise ValueError("scopeSpans entry must be an object")
            scope_context = _scope_context(scope_group)
            spans = scope_group.get("spans", [])
            if not isinstance(spans, list):
                raise ValueError("spans must be an array")
            if len(adapted) + len(spans) > MAX_SPANS:
                raise ValueError("span count exceeds OTLP envelope bound")
            for span_index, span in enumerate(spans):
                if not isinstance(span, dict):
                    raise ValueError("OTLP span must be an object")
                _kv_attributes(span.get("attributes", []))
                _validate_id(span.get("traceId") or span.get("trace_id"), trace=True, field="traceId")
                _validate_id(span.get("spanId") or span.get("span_id"), trace=False, field="spanId")
                _validate_id(span.get("parentSpanId") or span.get("parent_span_id"), trace=False, field="parentSpanId")
                adapted_span = otel.adapt_span(
                    span,
                    semantic_conventions_version=semantic_conventions_version,
                    observed_at=observed_at,
                )
                adapted.append(adapted_span)
                if not adapted_span.get("trace_id"):
                    missing_trace_ids.append(adapted_span["record_sha256"])
                if not adapted_span.get("span_id"):
                    missing_span_ids.append(adapted_span["record_sha256"])
                entries.append({
                    "adapted_span": adapted_span,
                    "context": {
                        "resource_index": resource_index,
                        "scope_index": scope_index,
                        "span_index": span_index,
                        "resource": deepcopy(resource_context),
                        "scope": deepcopy(scope_context),
                    },
                })

    entries.sort(key=lambda item: (
        str(item["adapted_span"].get("trace_id") or ""),
        str(item["adapted_span"].get("span_id") or ""),
        item["adapted_span"]["record_sha256"],
    ))
    trace_ids = sorted({item["adapted_span"].get("trace_id") for item in entries if item["adapted_span"].get("trace_id")})
    record = {
        "schema": TRACE_SCHEMA,
        "otlp_contract_version": OTLP_CONTRACT_VERSION,
        "semantic_conventions_version": semantic_conventions_version,
        "observed_at": observed_at,
        "raw_envelope": _raw_info(raw, serialization),
        "entries": entries,
        "diagnostics": {
            "resource_spans": len(groups),
            "scope_spans": scope_count,
            "span_count": len(entries),
            "trace_ids": trace_ids,
            "missing_trace_id_record_sha256": sorted(missing_trace_ids),
            "missing_span_id_record_sha256": sorted(missing_span_ids),
            "unknown_top_level_fields": sorted(key for key in envelope if key != "resourceSpans"),
        },
        "claims": {
            "source_bytes_preserved": serialization == "observed-json-bytes",
            "telemetry_authenticity_verified": False,
            "collection_complete": False,
            "transport_delivery_complete": False,
            "semantic_meaning_complete": False,
            "private_reasoning_captured": False,
        },
    }
    record["record_sha256"] = aer.sha256_bytes(aer.canonical_bytes(record))
    validate_trace_import(record)
    return record


def _decode_any_value(value: Any) -> Any:
    return otel.attributes({"attributes": [{"key": "value", "value": value}]}).get("value")


def _log_record(
    item: dict[str, Any],
    *,
    observed_at: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    _validate_id(item.get("traceId") or item.get("trace_id"), trace=True, field="traceId")
    _validate_id(item.get("spanId") or item.get("span_id"), trace=False, field="spanId")
    raw = aer.canonical_bytes(item)
    attrs = _kv_attributes(item.get("attributes", []))
    record = {
        "observed_at": observed_at,
        "trace_id": item.get("traceId") or item.get("trace_id"),
        "span_id": item.get("spanId") or item.get("span_id"),
        "time_unix_nano": item.get("timeUnixNano"),
        "observed_time_unix_nano": item.get("observedTimeUnixNano"),
        "severity_number": item.get("severityNumber"),
        "severity_text": item.get("severityText"),
        "event_name": item.get("eventName"),
        "flags": item.get("flags"),
        "body": _decode_any_value(item.get("body")) if "body" in item else None,
        "attributes": attrs,
        "context": deepcopy(context),
        "raw_log_record": {
            "sha256": aer.sha256_bytes(raw),
            "size": len(raw),
            "base64": base64.b64encode(raw).decode("ascii"),
        },
        "claims": {
            "telemetry_authenticity_verified": False,
            "log_to_span_causality_proven": False,
        },
    }
    record["record_sha256"] = aer.sha256_bytes(aer.canonical_bytes(record))
    return record


def import_log_envelope(
    source: bytes | bytearray | dict[str, Any],
    *,
    observed_at: str,
) -> dict[str, Any]:
    """Import one OTLP JSON logs envelope and preserve record/resource/scope context."""
    _time(observed_at)
    raw, envelope, serialization = _json_bytes(source)
    if "resourceSpans" in envelope:
        raise ValueError("trace envelope supplied to log importer")
    groups = envelope.get("resourceLogs", [])
    if not isinstance(groups, list):
        raise ValueError("resourceLogs must be an array")
    if len(groups) > MAX_RESOURCE_GROUPS:
        raise ValueError("resourceLogs exceeds resource-group bound")

    entries: list[dict[str, Any]] = []
    scope_count = 0
    for resource_index, resource_group in enumerate(groups):
        if not isinstance(resource_group, dict):
            raise ValueError("resourceLogs entry must be an object")
        resource_context = _resource_context(resource_group)
        scopes = resource_group.get("scopeLogs", [])
        if not isinstance(scopes, list):
            raise ValueError("scopeLogs must be an array")
        scope_count += len(scopes)
        if scope_count > MAX_SCOPE_GROUPS:
            raise ValueError("scopeLogs exceeds scope-group bound")
        for scope_index, scope_group in enumerate(scopes):
            if not isinstance(scope_group, dict):
                raise ValueError("scopeLogs entry must be an object")
            scope_context = _scope_context(scope_group)
            logs = scope_group.get("logRecords", [])
            if not isinstance(logs, list):
                raise ValueError("logRecords must be an array")
            if len(entries) + len(logs) > MAX_LOG_RECORDS:
                raise ValueError("log record count exceeds OTLP envelope bound")
            for log_index, log_record in enumerate(logs):
                if not isinstance(log_record, dict):
                    raise ValueError("OTLP log record must be an object")
                entries.append(_log_record(
                    log_record,
                    observed_at=observed_at,
                    context={
                        "resource_index": resource_index,
                        "scope_index": scope_index,
                        "log_index": log_index,
                        "resource": deepcopy(resource_context),
                        "scope": deepcopy(scope_context),
                    },
                ))

    entries.sort(key=lambda item: (
        str(item.get("trace_id") or ""),
        str(item.get("span_id") or ""),
        str(item.get("time_unix_nano") or ""),
        item["record_sha256"],
    ))
    record = {
        "schema": LOG_SCHEMA,
        "otlp_contract_version": OTLP_CONTRACT_VERSION,
        "observed_at": observed_at,
        "raw_envelope": _raw_info(raw, serialization),
        "entries": entries,
        "diagnostics": {
            "resource_logs": len(groups),
            "scope_logs": scope_count,
            "log_record_count": len(entries),
            "trace_linked_records": sum(1 for item in entries if item.get("trace_id")),
            "span_linked_records": sum(1 for item in entries if item.get("span_id")),
            "unknown_top_level_fields": sorted(key for key in envelope if key != "resourceLogs"),
        },
        "claims": {
            "source_bytes_preserved": serialization == "observed-json-bytes",
            "telemetry_authenticity_verified": False,
            "collection_complete": False,
            "transport_delivery_complete": False,
            "log_to_span_causality_proven": False,
        },
    }
    record["record_sha256"] = aer.sha256_bytes(aer.canonical_bytes(record))
    validate_log_import(record)
    return record


def validate_trace_import(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != TRACE_SCHEMA:
        raise ValueError("unsupported OTLP trace import schema")
    _validate_common(record)
    semconv = record.get("semantic_conventions_version")
    if not isinstance(semconv, str) or not semconv:
        raise ValueError("semantic_conventions_version is required")
    entries = record.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_SPANS:
        raise ValueError("invalid OTLP trace entries")

    actual_bindings: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("context"), dict):
            raise ValueError("invalid OTLP trace entry")
        adapted = entry.get("adapted_span")
        otel.validate(adapted)
        if adapted.get("semantic_conventions_version") != semconv or adapted.get("observed_at") != record.get("observed_at"):
            raise ValueError("adapted span version/time binding mismatch")
        raw_span = base64.b64decode(adapted["raw_span"]["base64"], validate=True)
        try:
            span_obj = json.loads(raw_span.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("retained adapted span cannot be replay-parsed") from exc
        replayed = otel.adapt_span(
            span_obj,
            semantic_conventions_version=semconv,
            observed_at=record["observed_at"],
        )
        if replayed["record_sha256"] != adapted["record_sha256"]:
            raise ValueError("adapted span is not reproducible from retained span bytes")
        actual_bindings.append((
            adapted["raw_span"]["sha256"],
            aer.sha256_bytes(aer.canonical_bytes(entry["context"])),
        ))

    source = _raw_envelope_object(record)
    if "resourceLogs" in source:
        raise ValueError("retained trace import contains log signal")
    if Counter(actual_bindings) != Counter(_trace_source_bindings(source)):
        raise ValueError("trace entries/context do not match retained OTLP envelope")

    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, dict) or diagnostics.get("span_count") != len(entries):
        raise ValueError("trace diagnostics mismatch")
    derived_trace_ids = sorted({e["adapted_span"].get("trace_id") for e in entries if e["adapted_span"].get("trace_id")})
    if diagnostics.get("trace_ids") != derived_trace_ids:
        raise ValueError("trace-id diagnostics mismatch")

    claims = record.get("claims", {})
    expected_source_bytes = record["raw_envelope"]["serialization"] == "observed-json-bytes"
    if claims.get("source_bytes_preserved") is not expected_source_bytes:
        raise ValueError("source_bytes_preserved claim mismatch")
    for key in ("telemetry_authenticity_verified", "collection_complete", "transport_delivery_complete",
                "semantic_meaning_complete", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    _validate_record_hash(record)
    return True


def validate_log_import(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != LOG_SCHEMA:
        raise ValueError("unsupported OTLP log import schema")
    _validate_common(record)
    entries = record.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_LOG_RECORDS:
        raise ValueError("invalid OTLP log entries")

    actual_bindings: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("context"), dict):
            raise ValueError("invalid OTLP log entry")
        raw = entry.get("raw_log_record")
        if not isinstance(raw, dict):
            raise ValueError("raw log record missing")
        raw_bytes = base64.b64decode(raw.get("base64", ""), validate=True)
        if len(raw_bytes) != raw.get("size") or aer.sha256_bytes(raw_bytes) != raw.get("sha256"):
            raise ValueError("raw log record custody mismatch")
        try:
            log_obj = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("retained log record cannot be replay-parsed") from exc
        replayed = _log_record(log_obj, observed_at=record["observed_at"], context=entry["context"])
        if replayed["record_sha256"] != entry.get("record_sha256"):
            raise ValueError("log record is not reproducible from retained bytes/context")
        if entry.get("claims", {}).get("log_to_span_causality_proven") is not False:
            raise ValueError("log-to-span causality must remain false")
        actual_bindings.append((
            raw["sha256"],
            aer.sha256_bytes(aer.canonical_bytes(entry["context"])),
        ))

    source = _raw_envelope_object(record)
    if "resourceSpans" in source:
        raise ValueError("retained log import contains trace signal")
    if Counter(actual_bindings) != Counter(_log_source_bindings(source)):
        raise ValueError("log entries/context do not match retained OTLP envelope")

    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, dict) or diagnostics.get("log_record_count") != len(entries):
        raise ValueError("log diagnostics mismatch")

    claims = record.get("claims", {})
    expected_source_bytes = record["raw_envelope"]["serialization"] == "observed-json-bytes"
    if claims.get("source_bytes_preserved") is not expected_source_bytes:
        raise ValueError("source_bytes_preserved claim mismatch")
    for key in ("telemetry_authenticity_verified", "collection_complete", "transport_delivery_complete",
                "log_to_span_causality_proven"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    _validate_record_hash(record)
    return True


def _validate_common(record: dict[str, Any]) -> None:
    _time(record.get("observed_at"))
    if record.get("otlp_contract_version") != OTLP_CONTRACT_VERSION:
        raise ValueError("unexpected OTLP contract version")
    raw = record.get("raw_envelope")
    if not isinstance(raw, dict):
        raise ValueError("raw envelope missing")
    payload = base64.b64decode(raw.get("base64", ""), validate=True)
    if len(payload) != raw.get("size") or len(payload) > MAX_ENVELOPE_BYTES:
        raise ValueError("raw OTLP envelope size mismatch")
    if aer.sha256_bytes(payload) != raw.get("sha256"):
        raise ValueError("raw OTLP envelope hash mismatch")
    if raw.get("serialization") not in {"observed-json-bytes", "canonicalized-object"}:
        raise ValueError("unsupported source serialization")


def _validate_record_hash(record: dict[str, Any]) -> None:
    unsigned = deepcopy(record)
    digest = unsigned.pop("record_sha256", None)
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError("OTLP import record hash mismatch")


def reconstruct_imported_trace(
    trace_import: dict[str, Any],
    *,
    trace_id: str,
    record_id: str,
) -> dict[str, Any]:
    """Reconstruct one trace and bind its OTLP resource/scope context."""
    validate_trace_import(trace_import)
    if not isinstance(trace_id, str) or not trace_id:
        raise ValueError("trace_id is required")
    selected = [entry for entry in trace_import["entries"] if entry["adapted_span"].get("trace_id") == trace_id]
    if not selected:
        raise ValueError("trace_id not present in imported envelope")
    spans = [entry["adapted_span"] for entry in selected]
    contexts = [
        {
            "adapted_span_record_sha256": entry["adapted_span"]["record_sha256"],
            "raw_span_sha256": entry["adapted_span"]["raw_span"]["sha256"],
            "context": deepcopy(entry["context"]),
        }
        for entry in selected
    ]
    contexts.sort(key=lambda item: item["adapted_span_record_sha256"])
    rebuilt = reconstruction.reconstruct_trace(spans, record_id=record_id)
    source_ref = _source_ref(trace_import, "otlp-trace-envelope")
    wrapper = {
        "schema": RECONSTRUCTION_SCHEMA,
        "source_trace_import_sha256": trace_import["record_sha256"],
        "source_envelope_evidence": source_ref,
        "trace_id": trace_id,
        "span_contexts": contexts,
        "reconstruction": rebuilt,
        "claims": {
            "source_envelope_bound": True,
            "trace_complete": False,
            "business_causality_proven": False,
            "intent_causality_proven": False,
        },
    }
    wrapper["record_sha256"] = aer.sha256_bytes(aer.canonical_bytes(wrapper))
    validate_imported_reconstruction(wrapper, trace_import=trace_import)
    return wrapper


def validate_imported_reconstruction(
    wrapper: dict[str, Any],
    *,
    trace_import: dict[str, Any] | None = None,
) -> bool:
    if not isinstance(wrapper, dict) or wrapper.get("schema") != RECONSTRUCTION_SCHEMA:
        raise ValueError("unsupported OTLP reconstruction wrapper")
    reconstruction.validate_reconstruction(wrapper.get("reconstruction"))
    if trace_import is not None:
        validate_trace_import(trace_import)
        if wrapper.get("source_trace_import_sha256") != trace_import["record_sha256"]:
            raise ValueError("trace import binding mismatch")
    claims = wrapper.get("claims", {})
    for key in ("trace_complete", "business_causality_proven", "intent_causality_proven"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    unsigned = deepcopy(wrapper)
    digest = unsigned.pop("record_sha256", None)
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError("OTLP reconstruction wrapper hash mismatch")
    return True


def correlate_trace_logs(
    trace_import: dict[str, Any],
    log_import: dict[str, Any],
) -> dict[str, Any]:
    """Correlate OTLP logs to imported trace/span identifiers without inferring causality."""
    validate_trace_import(trace_import)
    validate_log_import(log_import)
    span_pairs = {
        (entry["adapted_span"].get("trace_id"), entry["adapted_span"].get("span_id"))
        for entry in trace_import["entries"]
        if entry["adapted_span"].get("trace_id") and entry["adapted_span"].get("span_id")
    }
    trace_ids = {trace for trace, _ in span_pairs}
    correlations: list[dict[str, Any]] = []
    for log in log_import["entries"]:
        trace_id = log.get("trace_id")
        span_id = log.get("span_id")
        if trace_id and span_id and (trace_id, span_id) in span_pairs:
            status = "matched_trace_and_span"
        elif trace_id and trace_id in trace_ids and span_id:
            status = "trace_present_span_missing"
        elif trace_id and trace_id in trace_ids:
            status = "matched_trace_only"
        elif trace_id:
            status = "external_or_unobserved_trace"
        else:
            status = "unlinked"
        correlations.append({
            "log_record_sha256": log["record_sha256"],
            "trace_id": trace_id,
            "span_id": span_id,
            "status": status,
        })
    correlations.sort(key=lambda x: (
        str(x.get("trace_id") or ""),
        str(x.get("span_id") or ""),
        x["log_record_sha256"],
    ))
    report = {
        "schema": CORRELATION_SCHEMA,
        "trace_import_sha256": trace_import["record_sha256"],
        "log_import_sha256": log_import["record_sha256"],
        "correlations": correlations,
        "summary": {
            "log_records": len(correlations),
            "matched_trace_and_span": sum(1 for x in correlations if x["status"] == "matched_trace_and_span"),
            "matched_trace_only": sum(1 for x in correlations if x["status"] == "matched_trace_only"),
            "trace_present_span_missing": sum(1 for x in correlations if x["status"] == "trace_present_span_missing"),
            "external_or_unobserved_trace": sum(1 for x in correlations if x["status"] == "external_or_unobserved_trace"),
            "unlinked": sum(1 for x in correlations if x["status"] == "unlinked"),
        },
        "claims": {
            "identifier_correlation_performed": True,
            "log_generated_by_span_proven": False,
            "business_causality_proven": False,
            "collection_complete": False,
        },
    }
    report["report_sha256"] = aer.sha256_bytes(aer.canonical_bytes(report))
    validate_trace_log_correlation(report, trace_import=trace_import, log_import=log_import)
    return report


def validate_trace_log_correlation(
    report: dict[str, Any],
    *,
    trace_import: dict[str, Any] | None = None,
    log_import: dict[str, Any] | None = None,
) -> bool:
    if not isinstance(report, dict) or report.get("schema") != CORRELATION_SCHEMA:
        raise ValueError("unsupported OTLP trace/log correlation schema")
    if trace_import is not None:
        validate_trace_import(trace_import)
        if report.get("trace_import_sha256") != trace_import["record_sha256"]:
            raise ValueError("trace import correlation binding mismatch")
    if log_import is not None:
        validate_log_import(log_import)
        if report.get("log_import_sha256") != log_import["record_sha256"]:
            raise ValueError("log import correlation binding mismatch")
    claims = report.get("claims", {})
    for key in ("log_generated_by_span_proven", "business_causality_proven", "collection_complete"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    unsigned = deepcopy(report)
    digest = unsigned.pop("report_sha256", None)
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError("OTLP trace/log correlation hash mismatch")
    return True

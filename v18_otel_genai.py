"""OpenTelemetry GenAI evidence adapter for AI-DFIR v1.8.

The adapter preserves the original span and records the semantic-convention
version supplied by the operator/exporter. Normalization is non-destructive.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from typing import Any

from v18_agent_execution_record import canonical_bytes, sha256_bytes

SCHEMA = "ai-dfir/otel-genai-adapter/v1.8"
MAX_SPAN_BYTES = 4 * 1024 * 1024
GENAI_KEYS = (
    "gen_ai.agent.id", "gen_ai.agent.name", "gen_ai.agent.version", "gen_ai.agent.description",
    "gen_ai.conversation.id", "gen_ai.workflow.name", "gen_ai.operation.name", "gen_ai.provider.name",
    "gen_ai.request.model", "gen_ai.response.model", "gen_ai.system_instructions",
    "gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.retrieval.query.text",
    "gen_ai.retrieval.documents", "gen_ai.tool.name", "gen_ai.tool.type",
)


def _otel_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "intValue", "doubleValue", "boolValue", "bytesValue"):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        values = value["arrayValue"].get("values", []) if isinstance(value["arrayValue"], dict) else []
        return [_otel_value(x) for x in values]
    if "kvlistValue" in value:
        values = value["kvlistValue"].get("values", []) if isinstance(value["kvlistValue"], dict) else []
        return {item["key"]: _otel_value(item.get("value")) for item in values if isinstance(item, dict) and "key" in item}
    return deepcopy(value)


def attributes(span: dict[str, Any]) -> dict[str, Any]:
    raw = span.get("attributes", {})
    if isinstance(raw, dict):
        return deepcopy(raw)
    if isinstance(raw, list):
        out: dict[str, Any] = {}
        for item in raw:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                raise ValueError("invalid OTLP attribute")
            out[item["key"]] = _otel_value(item.get("value"))
        return out
    raise ValueError("span attributes must be an object or OTLP attribute array")


def adapt_span(span: dict[str, Any], *, semantic_conventions_version: str, observed_at: str) -> dict[str, Any]:
    if not isinstance(span, dict):
        raise TypeError("span must be an object")
    if not isinstance(semantic_conventions_version, str) or not semantic_conventions_version:
        raise ValueError("semantic_conventions_version is required")
    raw = canonical_bytes(span)
    if len(raw) > MAX_SPAN_BYTES:
        raise ValueError("span exceeds bounded adapter size")
    attrs = attributes(span)
    normalized = {key: deepcopy(attrs[key]) for key in GENAI_KEYS if key in attrs}
    record = {
        "schema": SCHEMA,
        "semantic_conventions_family": "OpenTelemetry GenAI",
        "semantic_conventions_version": semantic_conventions_version,
        "semantic_conventions_status": "evolving",
        "observed_at": observed_at,
        "trace_id": span.get("traceId") or span.get("trace_id"),
        "span_id": span.get("spanId") or span.get("span_id"),
        "parent_span_id": span.get("parentSpanId") or span.get("parent_span_id"),
        "span_name": span.get("name"),
        "normalized_genai": normalized,
        "unmapped_attribute_names": sorted(key for key in attrs if key.startswith("gen_ai.") and key not in GENAI_KEYS),
        "raw_span": {"sha256": sha256_bytes(raw), "size": len(raw), "base64": base64.b64encode(raw).decode("ascii")},
        "claims": {"telemetry_authenticity_verified": False, "semantic_meaning_complete": False,
                   "private_reasoning_captured": False},
    }
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    validate(record)
    return record


def validate(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        raise ValueError("unsupported OTel adapter schema")
    raw_info = record.get("raw_span")
    if not isinstance(raw_info, dict):
        raise ValueError("raw_span missing")
    raw = base64.b64decode(raw_info.get("base64", ""), validate=True)
    if raw_info.get("size") != len(raw) or raw_info.get("sha256") != sha256_bytes(raw):
        raise ValueError("raw span custody mismatch")
    if record.get("claims", {}).get("private_reasoning_captured") is not False:
        raise ValueError("private reasoning claim must remain false")
    digest = record.get("record_sha256")
    unsigned = deepcopy(record); unsigned.pop("record_sha256", None)
    if digest != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError("OTel adapter record hash mismatch")
    return True

"""Bind retained query context to exact Log Analytics response bytes, offline."""
from __future__ import annotations

import re

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import (
    GUID_RE, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES as TABLE_OUTPUT_BYTES,
    _bounded, _document, normalize as normalize_tables,
)
from v17_provenance import ProvenanceError

TRANSFORMATION = "v17_log_analytics_context.normalize"
TRANSFORMATION_VERSION = "1.7"
CONTEXT_SCHEMA = "ai-dfir/log-analytics-query-context/v1.7"
INPUT_FORMATS = ("workspace-post",)
MAX_CONTEXT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = TABLE_OUTPUT_BYTES + MAX_CONTEXT_BYTES
MAX_QUERY_BYTES = 64 * 1024
MAX_WORKSPACES = 32
MAX_HEADER_CHARS = 4096
ENDPOINT_RE = re.compile(
    r"https://(api\.loganalytics\.(?:io|azure\.com))/v1/workspaces/("
    + GUID_RE.pattern + r")/query"
)
REQUEST_HEADERS = {"content-type", "prefer", "x-ms-client-request-id"}
RESPONSE_HEADERS = {"content-type", "x-ms-request-id", "request-id", "x-request-id"}


def _object(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise ProvenanceError("unsupported query context fields")


def _text(value, limit, *, multiline=False):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ProvenanceError("invalid query context text")
    if any((ord(c) < 32 and not (multiline and c in "\t\r\n")) or ord(c) == 127 for c in value):
        raise ProvenanceError("invalid query context control character")
    return value


def _headers(value, allowed):
    _object(value, (), allowed)
    for text in value.values():
        _text(text, MAX_HEADER_CHARS)


def _observation(obj, key):
    return {"state": "present", "sha256": sha256_object(obj[key])} if key in obj else {"state": "absent", "sha256": None}


def _context(raw, context_raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_INPUT_BYTES:
        raise ProvenanceError("query response is empty or exceeds byte limit")
    context = _document(context_raw, MAX_CONTEXT_BYTES)
    _object(context, {"schema", "request", "response"})
    if context["schema"] != CONTEXT_SCHEMA:
        raise ProvenanceError("unsupported query context schema")
    request, response = context["request"], context["response"]
    _object(request, {"method", "url", "body", "headers"})
    endpoint = ENDPOINT_RE.fullmatch(request["url"]) if isinstance(request["url"], str) else None
    if request["method"] != "POST" or endpoint is None:
        raise ProvenanceError("unsupported retained query endpoint or method")
    _headers(request["headers"], REQUEST_HEADERS)
    if request["headers"].get("content-type") != "application/json":
        raise ProvenanceError("query context requires recorded JSON content type")
    body = request["body"]
    _object(body, {"query"}, {"timespan", "workspaces"})
    query = _text(body["query"], MAX_QUERY_BYTES, multiline=True)
    if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise ProvenanceError("retained query text exceeds byte limit")
    if "timespan" in body:
        # Retain an opaque observation; do not interpret relative time or KQL.
        _text(body["timespan"], 256)
    if "workspaces" in body:
        workspaces = body["workspaces"]
        if not isinstance(workspaces, list) or len(workspaces) > MAX_WORKSPACES or not all(
            isinstance(item, str) and GUID_RE.fullmatch(item) for item in workspaces
        ):
            raise ProvenanceError("invalid or excessive additional workspace list")
    _object(response, {"status", "body_sha256", "body_size_bytes", "headers"})
    if type(response["status"]) is not int or response["status"] != 200:
        raise ProvenanceError("unsupported retained query HTTP status")
    _headers(response["headers"], RESPONSE_HEADERS)
    if (type(response["body_size_bytes"]) is not int or response["body_size_bytes"] != len(raw)
            or not isinstance(response["body_sha256"], str) or response["body_sha256"] != sha256_bytes(raw)):
        raise ProvenanceError("query context does not bind the retained response bytes")
    return context, endpoint


def normalize(raw: bytes, *, context_raw: bytes, input_format: str) -> dict:
    if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
        raise ProvenanceError("unsupported query context profile")
    context, endpoint = _context(raw, context_raw)
    request, response = context["request"], context["response"]
    body = request["body"]
    table_projection = normalize_tables(raw, input_format="tables")
    result = {
        "schema": "ai-dfir/log-analytics-context-projection/v1.7",
        "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
        "input_format": input_format, "source_sha256": sha256_bytes(raw),
        "context_sha256": sha256_bytes(context_raw), "request_sha256": sha256_object(request),
        "binding_sha256": sha256_object({"profile": input_format, "response_sha256": sha256_bytes(raw),
                                         "context_sha256": sha256_bytes(context_raw)}),
        "request": {
            "method": "POST", "endpoint_host": endpoint[1], "endpoint_sha256": sha256_object(request["url"]),
            "primary_workspace_sha256": sha256_object(endpoint[2]), "body_sha256": sha256_object(body),
            "query_sha256": sha256_object(body["query"]), "query_size_bytes": len(body["query"].encode("utf-8")),
            "timespan": _observation(body, "timespan"), "workspaces": _observation(body, "workspaces"),
            "additional_workspace_sha256": [sha256_object(item) for item in body.get("workspaces", [])],
            "headers_sha256": sha256_object(request["headers"]),
        },
        "response": {"status": 200, "body_size_bytes": len(raw), "headers_sha256": sha256_object(response["headers"])},
        "result": table_projection, "request_context_bound": True,
        "context_source": "retained-assertion", "request_scope_verified": False,
        "query_execution_verified": False, "source_authenticity_verified": False,
        "network_required": False, "query_reexecuted": False,
        "collection_complete": table_projection["collection_complete"],
        "content_policy": "request_hashes_and_typed_result_projection",
        "interpretation": "Binding of retained request assertions and exact response bytes only; neither actual query execution, effective scope, authorization, provider origin, nor complete collection is established.",
    }
    if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
        raise ProvenanceError("query context projection exceeds byte limit")
    _bounded(result)
    return result


def compare_replay(raw: bytes, preserved: bytes, *, context_raw: bytes, input_format: str) -> dict:
    replayed = normalize(raw, context_raw=context_raw, input_format=input_format)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {
        "status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
        "recorded_output_sha256": actual, "replayed_output_sha256": expected,
        **{key: replayed[key] for key in ("source_sha256", "context_sha256", "binding_sha256", "request_context_bound",
            "request_scope_verified", "query_execution_verified", "source_authenticity_verified", "network_required",
            "query_reexecuted", "collection_complete")},
        **{key: replayed["result"][key] for key in ("table_count", "row_count", "response_state", "partial_error_recorded")},
    }

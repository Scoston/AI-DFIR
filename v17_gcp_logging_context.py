"""Bind retained Google Cloud entries.list requests to exact audit response bytes."""
from __future__ import annotations

import re

from v17_gcp_audit import MAX_INPUT_BYTES, MAX_OUTPUT_BYTES as AUDIT_OUTPUT_BYTES, _bounded, _document, normalize as normalize_audit
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_provenance import ProvenanceError

TRANSFORMATION = "v17_gcp_logging_context.normalize"
TRANSFORMATION_VERSION = "1.7"
CONTEXT_SCHEMA = "ai-dfir/gcp-logging-query-context/v1.7"
INPUT_FORMATS = ("entries-list",)
ENDPOINT = "https://logging.googleapis.com/v2/entries:list"
MAX_CONTEXT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = AUDIT_OUTPUT_BYTES + MAX_CONTEXT_BYTES
MAX_RESOURCES = 32
MAX_FILTER_CHARS = 20000
MAX_PAGE_SIZE = 1000
MAX_TOKEN_CHARS = 4096
REQUEST_HEADERS = {"content-type"}
RESPONSE_HEADERS = {"content-type", "x-request-id", "x-goog-request-id"}
SEGMENT = r"[A-Za-z0-9_.:-]{1,256}"
RESOURCE_RE = re.compile(r"(projects|organizations|billingAccounts|folders)/" + SEGMENT
                         + r"(?:/locations/" + SEGMENT + r"/buckets/" + SEGMENT + r"/views/" + SEGMENT + r")?")


def _object(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise ProvenanceError("unsupported logging context fields")


def _text(value, limit, *, empty=False, multiline=False):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ProvenanceError("invalid logging context text")
    if any((ord(c) < 32 and not (multiline and c in "\t\r\n")) or ord(c) == 127 for c in value):
        raise ProvenanceError("invalid logging context control character")
    return value


def _headers(value, allowed):
    _object(value, (), allowed)
    for item in value.values():
        _text(item, 4096)


def _observation(obj, key):
    return {"state": "present", "sha256": sha256_object(obj[key])} if key in obj else {"state": "absent", "sha256": None}


def validate_request(request):
    """Validate one fixed endpoint and an explicit subset of entries.list JSON."""
    _object(request, {"method", "url", "body", "headers"})
    if request["method"] != "POST" or request["url"] != ENDPOINT:
        raise ProvenanceError("unsupported logging endpoint or method")
    _headers(request["headers"], REQUEST_HEADERS)
    if request["headers"].get("content-type") != "application/json":
        raise ProvenanceError("logging context requires recorded JSON content type")
    body = request["body"]
    _object(body, {"resourceNames"}, {"filter", "orderBy", "pageSize", "pageToken"})
    resources = body["resourceNames"]
    if not isinstance(resources, list) or not 1 <= len(resources) <= MAX_RESOURCES:
        raise ProvenanceError("invalid or excessive logging resource list")
    for name in resources:
        if (not isinstance(name, str) or len(name) > 1100 or RESOURCE_RE.fullmatch(name) is None
                or any(part in (".", "..") for part in name.split("/"))):
            raise ProvenanceError("unsupported logging resource name")
    if "filter" in body:
        _text(body["filter"], MAX_FILTER_CHARS, empty=True, multiline=True)
    if "orderBy" in body and body["orderBy"] not in ("timestamp asc", "timestamp desc"):
        raise ProvenanceError("unsupported logging sort order")
    if "pageSize" in body and (type(body["pageSize"]) is not int or not 1 <= body["pageSize"] <= MAX_PAGE_SIZE):
        raise ProvenanceError("invalid or excessive logging page size")
    if "pageToken" in body:
        _text(body["pageToken"], MAX_TOKEN_CHARS, empty=True)
    return body


def normalize(raw: bytes, *, context_raw: bytes, input_format: str) -> dict:
    try:
        if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
            raise ProvenanceError("unsupported logging context profile")
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_INPUT_BYTES:
            raise ProvenanceError("logging response is empty or exceeds byte limit")
        context = _document(context_raw, MAX_CONTEXT_BYTES)
        _object(context, {"schema", "request", "response"})
        if context["schema"] != CONTEXT_SCHEMA:
            raise ProvenanceError("unsupported logging context schema")
        request, response = context["request"], context["response"]
        body = validate_request(request)
        _object(response, {"status", "headers", "body_sha256", "body_size_bytes"})
        if type(response["status"]) is not int or response["status"] != 200:
            raise ProvenanceError("unsupported logging HTTP status")
        _headers(response["headers"], RESPONSE_HEADERS)
        if (type(response["body_size_bytes"]) is not int or response["body_size_bytes"] != len(raw)
                or response["body_sha256"] != sha256_bytes(raw)):
            raise ProvenanceError("logging context does not bind the retained response bytes")
        audit = normalize_audit(raw, input_format="entries")
        result = {
            "schema": "ai-dfir/gcp-logging-context-projection/v1.7",
            "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
            "input_format": input_format, "source_sha256": sha256_bytes(raw), "context_sha256": sha256_bytes(context_raw),
            "request_sha256": sha256_object(request),
            "binding_sha256": sha256_object({"profile": input_format, "response_sha256": sha256_bytes(raw),
                                             "context_sha256": sha256_bytes(context_raw)}),
            "request": {"method": "POST", "endpoint_host": "logging.googleapis.com", "endpoint_sha256": sha256_object(ENDPOINT),
                        "body_sha256": sha256_object(body), "headers_sha256": sha256_object(request["headers"]),
                        "resource_count": len(body["resourceNames"]), "resource_names_sha256": sha256_object(body["resourceNames"]),
                        "ordered_resource_sha256": [sha256_object(name) for name in body["resourceNames"]],
                        **{key: _observation(body, key) for key in ("filter", "orderBy", "pageSize", "pageToken")}},
            "response": {"status": 200, "body_size_bytes": len(raw), "headers_sha256": sha256_object(response["headers"])},
            "result": audit, "request_context_bound": True, "context_source": "retained-assertion",
            "request_scope_verified": False, "query_execution_verified": False, "source_authenticity_verified": False,
            "network_required": False, "query_reexecuted": False, "pagination_chain_verified": False,
            "collection_complete": audit["collection_complete"], "content_policy": "request_hashes_and_audit_projection",
            "interpretation": "One retained request assertion and exact response bytes only; no execution, effective scope, provider origin, pagination chain, human attribution, or complete collection is established.",
        }
        if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
            raise ProvenanceError("logging context projection exceeds byte limit")
        _bounded(result)
        return result
    except (ValueError, TypeError, RecursionError):
        raise ProvenanceError("invalid, excessive, or unsupported logging context") from None


def compare_replay(raw: bytes, preserved: bytes, *, context_raw: bytes, input_format: str) -> dict:
    replayed = normalize(raw, context_raw=context_raw, input_format=input_format)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {"status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
            "recorded_output_sha256": actual, "replayed_output_sha256": expected,
            **{key: replayed[key] for key in ("source_sha256", "context_sha256", "binding_sha256", "request_context_bound",
                "request_scope_verified", "query_execution_verified", "source_authenticity_verified", "network_required",
                "query_reexecuted", "pagination_chain_verified", "collection_complete")},
            **{key: replayed["result"][key] for key in ("entry_count", "continuation_token_present")}}

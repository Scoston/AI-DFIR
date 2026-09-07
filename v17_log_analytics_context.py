"""Bind retained query context to exact Log Analytics response bytes, offline."""
from __future__ import annotations

import re
from urllib.parse import unquote_to_bytes

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import (
    GUID_RE, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES as TABLE_OUTPUT_BYTES,
    _bounded, _document, normalize as normalize_tables,
)
from v17_provenance import ProvenanceError

TRANSFORMATION = "v17_log_analytics_context.normalize"
TRANSFORMATION_VERSION = "1.7"
CONTEXT_SCHEMA = "ai-dfir/log-analytics-query-context/v1.7"
INPUT_FORMATS = ("workspace-post", "workspace-get", "resource-post", "resource-get",
                 "workspace-get-form", "resource-get-form")
MAX_CONTEXT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = TABLE_OUTPUT_BYTES + MAX_CONTEXT_BYTES
MAX_QUERY_BYTES = 64 * 1024
MAX_WORKSPACES = 32
MAX_HEADER_CHARS = 4096
MAX_GET_URL_BYTES = 96 * 1024
ENDPOINT_RE = re.compile(
    r"https://(api\.loganalytics\.(?:io|azure\.com))/v1/workspaces/("
    + GUID_RE.pattern + r")/query"
)
REQUEST_HEADERS = {"content-type", "prefer", "x-ms-client-request-id"}
GET_REQUEST_HEADERS = REQUEST_HEADERS | {"accept"}
RESPONSE_HEADERS = {"content-type", "x-ms-request-id", "request-id", "x-request-id"}
GET_COMPONENT_RE = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})*")
GET_FORM_COMPONENT_RE = re.compile(r"(?:[A-Za-z0-9._~*()+,-]|%[0-9A-Fa-f]{2})*")
MAX_RESOURCE_ID_BYTES = 4096
RESOURCE_SEGMENT = r"[A-Za-z0-9._~-]{1,256}"
RESOURCE_ID_PATTERN = (r"/subscriptions/" + GUID_RE.pattern + r"/resourceGroups/" + RESOURCE_SEGMENT
                       + r"/providers/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+"
                       + r"(?:/" + RESOURCE_SEGMENT + r"/" + RESOURCE_SEGMENT + r"){1,8}")
RESOURCE_ENDPOINT_RE = re.compile(r"https://(api\.loganalytics\.(?:io|azure\.com))/v1("
                                  + RESOURCE_ID_PATTERN + r")/query")


def _endpoint(url, scope):
    if scope not in ("workspace", "resource") or not isinstance(url, str):
        raise ProvenanceError("unsupported retained query scope")
    if scope == "resource" and len(url) > MAX_RESOURCE_ID_BYTES + 80:
        raise ProvenanceError("resource endpoint exceeds byte limit")
    pattern = RESOURCE_ENDPOINT_RE if scope == "resource" else ENDPOINT_RE
    endpoint = pattern.fullmatch(url)
    if endpoint is None:
        raise ProvenanceError("unsupported retained query endpoint")
    if scope == "resource" and (len(endpoint[2]) > MAX_RESOURCE_ID_BYTES
            or any(part in (".", "..") or len(part) > 256 for part in endpoint[2].split("/"))):
        raise ProvenanceError("invalid or excessive resource identifier")
    return endpoint


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


def validate_request(request, *, scope="workspace"):
    """Validate the fixed request profile after bounded strict JSON parsing."""
    _object(request, {"method", "url", "body", "headers"})
    endpoint = _endpoint(request["url"], scope)
    if request["method"] != "POST":
        raise ProvenanceError("unsupported retained query endpoint or method")
    _headers(request["headers"], REQUEST_HEADERS)
    if request["headers"].get("content-type") != "application/json":
        raise ProvenanceError("query context requires recorded JSON content type")
    body = request["body"]
    _object(body, {"query"}, {"timespan"} | ({"workspaces"} if scope == "workspace" else set()))
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
    return endpoint


def _get_component(value, *, encoding="percent"):
    # Do not use a tolerant URL/form parser: it can strip controls, replace bad
    # UTF-8, interpret '+' as space, or silently discard malformed parameters.
    pattern = GET_FORM_COMPONENT_RE if encoding == "form" else GET_COMPONENT_RE
    if encoding not in ("percent", "form") or pattern.fullmatch(value) is None:
        raise ProvenanceError("unsupported query URL encoding")
    try:
        if encoding == "form":
            # Replace literal '+' before percent decoding: '%2B' stays a plus.
            value = value.replace("+", " ")
        return unquote_to_bytes(value).decode("utf-8", errors="strict")
    except UnicodeError:
        raise ProvenanceError("invalid query URL text") from None


def _get_workspaces(value):
    if not isinstance(value, str) or not value or len(value) > MAX_WORKSPACES * 37 - 1:
        raise ProvenanceError("invalid or excessive GET workspace list")
    workspaces = value.split(",")
    if len(workspaces) > MAX_WORKSPACES or not all(GUID_RE.fullmatch(item) for item in workspaces):
        raise ProvenanceError("invalid or excessive GET workspace list")
    return workspaces


def _get_request(request, *, scope="workspace", encoding="percent"):
    _object(request, {"method", "url", "body", "headers"})
    url = request["url"]
    if (request["method"] != "GET" or request["body"] is not None
            or not isinstance(url, str) or not url.isascii() or len(url) > MAX_GET_URL_BYTES):
        raise ProvenanceError("unsupported retained GET request")
    base, separator, query_string = url.partition("?")
    endpoint = _endpoint(base, scope)
    optional = {"timespan"} | ({"workspaces"} if scope == "workspace" and encoding == "form" else set())
    if not separator or not query_string or query_string.count("&") > len(optional):
        raise ProvenanceError("unsupported GET endpoint or parameters")
    parameters = {}
    for field in query_string.split("&"):
        key, equals, value = field.partition("=")
        key = _get_component(key, encoding=encoding)
        if not equals or key not in {"query"} | optional or key in parameters:
            raise ProvenanceError("missing, duplicate, or unsupported GET parameter")
        parameters[key] = _get_component(value, encoding=encoding)
    _object(parameters, {"query"}, optional)
    query = _text(parameters["query"], MAX_QUERY_BYTES, multiline=True)
    if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise ProvenanceError("retained query text exceeds byte limit")
    if "timespan" in parameters:
        _text(parameters["timespan"], 256)
    if "workspaces" in parameters:
        _get_workspaces(parameters["workspaces"])
    _headers(request["headers"], GET_REQUEST_HEADERS)
    return endpoint, parameters


def _context(raw, context_raw, input_format):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_INPUT_BYTES:
        raise ProvenanceError("query response is empty or exceeds byte limit")
    context = _document(context_raw, MAX_CONTEXT_BYTES)
    _object(context, {"schema", "request", "response"})
    if context["schema"] != CONTEXT_SCHEMA:
        raise ProvenanceError("unsupported query context schema")
    request, response = context["request"], context["response"]
    scope = "resource" if input_format.startswith("resource-") else "workspace"
    if input_format.endswith(("-get", "-get-form")):
        endpoint, parameters = _get_request(request, scope=scope, encoding="form" if input_format.endswith("-form") else "percent")
    else:
        endpoint, parameters = validate_request(request, scope=scope), request["body"]
    _object(response, {"status", "body_sha256", "body_size_bytes", "headers"})
    if type(response["status"]) is not int or response["status"] != 200:
        raise ProvenanceError("unsupported retained query HTTP status")
    _headers(response["headers"], RESPONSE_HEADERS)
    if (type(response["body_size_bytes"]) is not int or response["body_size_bytes"] != len(raw)
            or not isinstance(response["body_sha256"], str) or response["body_sha256"] != sha256_bytes(raw)):
        raise ProvenanceError("query context does not bind the retained response bytes")
    return context, endpoint, parameters


def _request_projection(request, endpoint, parameters, input_format):
    if input_format.endswith("-get-form"):
        result = _request_projection(request, endpoint, parameters, input_format.removesuffix("-form"))
        result["url_decoding"] = "utf8-form-plus-then-percent-once"
        if input_format == "workspace-get-form":
            result["workspaces"] = _observation(parameters, "workspaces")
            result["additional_workspace_sha256"] = [sha256_object(item) for item in
                (_get_workspaces(parameters["workspaces"]) if "workspaces" in parameters else [])]
        return result
    if input_format.startswith("resource-"):
        method = request["method"]
        base = request["url"].partition("?")[0]
        result = {
            "method": method, "endpoint_host": endpoint[1], "endpoint_sha256": sha256_object(base),
            "requested_scope": "resource", "resource_id_sha256": sha256_object(endpoint[2]),
            "resource_id_size_bytes": len(endpoint[2]), "body_sha256": sha256_object(request["body"]),
            "query_sha256": sha256_object(parameters["query"]),
            "query_size_bytes": len(parameters["query"].encode("utf-8")),
            "timespan": _observation(parameters, "timespan"), "headers_sha256": sha256_object(request["headers"]),
        }
        if method == "GET":
            result.update(url_sha256=sha256_object(request["url"]), url_size_bytes=len(request["url"]),
                          query_string_sha256=sha256_object(request["url"].partition("?")[2]),
                          parameters_sha256=sha256_object(parameters), parameter_order=list(parameters),
                          body_state="absent", url_decoding="utf8-percent-once-unreserved")
        return result
    if input_format == "workspace-get":
        base, _, query_string = request["url"].partition("?")
        return {
            "method": "GET", "endpoint_host": endpoint[1], "endpoint_sha256": sha256_object(base),
            "url_sha256": sha256_object(request["url"]), "url_size_bytes": len(request["url"]),
            "primary_workspace_sha256": sha256_object(endpoint[2]),
            "body_state": "absent", "body_sha256": sha256_object(None),
            "query_string_sha256": sha256_object(query_string), "parameters_sha256": sha256_object(parameters),
            "parameter_order": list(parameters), "query_sha256": sha256_object(parameters["query"]),
            "query_size_bytes": len(parameters["query"].encode("utf-8")),
            "timespan": _observation(parameters, "timespan"),
            "headers_sha256": sha256_object(request["headers"]),
            "url_decoding": "utf8-percent-once-unreserved",
        }
    # Preserve every existing workspace-post projection field and digest.
    return {
        "method": "POST", "endpoint_host": endpoint[1], "endpoint_sha256": sha256_object(request["url"]),
        "primary_workspace_sha256": sha256_object(endpoint[2]), "body_sha256": sha256_object(parameters),
        "query_sha256": sha256_object(parameters["query"]), "query_size_bytes": len(parameters["query"].encode("utf-8")),
        "timespan": _observation(parameters, "timespan"), "workspaces": _observation(parameters, "workspaces"),
        "additional_workspace_sha256": [sha256_object(item) for item in parameters.get("workspaces", [])],
        "headers_sha256": sha256_object(request["headers"]),
    }


def normalize(raw: bytes, *, context_raw: bytes, input_format: str) -> dict:
    if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
        raise ProvenanceError("unsupported query context profile")
    context, endpoint, parameters = _context(raw, context_raw, input_format)
    request, response = context["request"], context["response"]
    table_projection = normalize_tables(raw, input_format="resource-tables" if input_format.startswith("resource-") else "tables")
    result = {
        "schema": "ai-dfir/log-analytics-context-projection/v1.7",
        "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
        "input_format": input_format, "source_sha256": sha256_bytes(raw),
        "context_sha256": sha256_bytes(context_raw), "request_sha256": sha256_object(request),
        "binding_sha256": sha256_object({"profile": input_format, "response_sha256": sha256_bytes(raw),
                                         "context_sha256": sha256_bytes(context_raw)}),
        "request": _request_projection(request, endpoint, parameters, input_format),
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

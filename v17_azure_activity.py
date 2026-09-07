"""Bounded native Azure Activity Log projection and offline replay."""
from __future__ import annotations

import math
import os
import re
import stat
from datetime import datetime
from pathlib import Path

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_provenance import ProvenanceError
from v17_reconstruction import strict_json

TRANSFORMATION = "v17_azure_activity.normalize"
TRANSFORMATION_VERSION = "1.7"
INPUT_FORMATS = ("activity-log", "array")
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
MAX_EVENTS = 2000
MAX_DEPTH = 32
MAX_NODES = 200000
MAX_METADATA_CHARS = 4096
TIME_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})")
CLAIM_FIELDS = (
    "appid", "oid", "tid", "idtyp",
    "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "http://schemas.microsoft.com/identity/claims/tenantid",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
)
LOCALIZABLE_FIELDS = {
    "operation_name": "operationName", "event_name": "eventName", "category": "category",
    "resource_provider_name": "resourceProviderName", "resource_type": "resourceType",
    "status": "status", "sub_status": "subStatus",
}
PAYLOAD_FIELDS = ("authorization", "claims", "httpRequest", "properties", "description")


def _bounded(value):
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        children = 2 * len(item) if isinstance(item, dict) else len(item) if isinstance(item, list) else 0
        if depth > MAX_DEPTH or visited + len(pending) + children > MAX_NODES:
            raise ProvenanceError("activity JSON structure exceeds limits")
        if isinstance(item, dict):
            pending.extend((k, depth + 1) for k in item)
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_INPUT_BYTES:
                raise ProvenanceError("activity JSON string exceeds limits")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ProvenanceError("activity JSON number is not finite")
        elif type(item) is int and abs(item) > 9007199254740991:
            raise ProvenanceError("activity JSON integer exceeds RFC8785 safe range")


def _document(raw, limit):
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise ProvenanceError("activity document is empty or exceeds byte limit")
    try:
        value = strict_json(raw)
        _bounded(value)
        return value
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProvenanceError("invalid or excessive activity JSON") from exc


def read_document(path, *, limit=MAX_INPUT_BYTES):
    descriptor = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ProvenanceError("activity input must be a regular file")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ProvenanceError("activity document is empty or exceeds byte limit")
    return raw


def _text(obj, key, *, required=False, nullable=False):
    if key not in obj:
        if required:
            raise ProvenanceError("required activity metadata is absent")
        return None
    value = obj[key]
    if value is None and nullable and not required:
        return None
    if not isinstance(value, str) or (required and not value) or len(value) > MAX_METADATA_CHARS or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ProvenanceError("invalid activity metadata string")
    return value


def _object(obj, key, *, required=False):
    if key not in obj and not required:
        return {}
    value = obj.get(key)
    if not isinstance(value, dict):
        raise ProvenanceError("invalid activity object")
    return value


def _digest(obj, key):
    if key not in obj:
        return {"state": "absent", "sha256": None}
    return {"state": "null" if obj[key] is None else "present", "sha256": sha256_object(obj[key])}


def _timestamp(obj, key, *, required=False):
    value = _text(obj, key, required=required)
    if value is None:
        return None
    match = TIME_RE.fullmatch(value)
    if match is None:
        raise ProvenanceError("activity timestamp must have an explicit RFC3339 offset")
    # Check calendar and offset without rounding Azure's seven fractional digits
    # (or any of the nine accepted digits) through a microsecond/float conversion.
    datetime(*map(int, match.groups()[:6]))
    offset = match[8]
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise ProvenanceError("invalid activity timestamp offset")
    return value


def _localizable(event, key, *, required=False):
    item = _object(event, key, required=required)
    return {
        "recorded": key in event, "value": _text(item, "value", required=required, nullable=not required),
        "value_state": _digest(item, "value")["state"],
        "localized_value": _text(item, "localizedValue", nullable=True),
        "localized_value_state": _digest(item, "localizedValue")["state"],
        "record_sha256": sha256_object(item) if key in event else None,
    }


def _event(event, ordinal):
    encoded = canonical_json_bytes(event)
    if len(encoded) > MAX_EVENT_BYTES:
        raise ProvenanceError("activity event exceeds byte limit")
    claims, authorization, request = (_object(event, key) for key in ("claims", "authorization", "httpRequest"))
    return {
        "ordinal": ordinal, "event_sha256": sha256_bytes(encoded),
        "event_data_id": _text(event, "eventDataId", required=True),
        "event_timestamp": _timestamp(event, "eventTimestamp", required=True),
        "submission_timestamp": _timestamp(event, "submissionTimestamp"),
        "id": _text(event, "id"), "level": _text(event, "level"),
        "operation_id": _text(event, "operationId"), "correlation_id": _text(event, "correlationId"),
        "resource_id": _text(event, "resourceId"), "resource_group_name": _text(event, "resourceGroupName"),
        "subscription_id": _text(event, "subscriptionId"), "tenant_id": _text(event, "tenantId"),
        **{out: _localizable(event, key, required=key == "operationName") for out, key in LOCALIZABLE_FIELDS.items()},
        "actor": {"caller": _text(event, "caller"), "claims": {key: _text(claims, key) for key in CLAIM_FIELDS}},
        "authorization": {key: _text(authorization, key) for key in ("action", "role", "scope")},
        "http_request": {
            "client_request_id": _text(request, "clientRequestId"),
            "client_ip_address": _text(request, "clientIpAddress"), "method": _text(request, "method"),
            "uri": _digest(request, "uri"),
        },
        "payload_digests": {key: _digest(event, key) for key in PAYLOAD_FIELDS},
    }


def normalize(raw: bytes, *, input_format: str) -> dict:
    if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
        raise ProvenanceError("unsupported activity input format")
    document = _document(raw, MAX_INPUT_BYTES)
    continuation = None
    if input_format == "activity-log":
        if not isinstance(document, dict) or "value" not in document or set(document) - {"value", "nextLink"}:
            raise ProvenanceError("unsupported or mixed activity export envelope")
        events = document["value"]
        # A null terminal link is retained as distinct from absence/empty text.
        # The link is opaque evidence: never resolve it or use it as a destination.
        if document.get("nextLink") is not None:
            continuation = _text(document, "nextLink")
    else:
        events = document
    if not isinstance(events, list) or len(events) > MAX_EVENTS or not all(isinstance(row, dict) for row in events):
        raise ProvenanceError("invalid or excessive activity event list")
    result = {
        "schema": "ai-dfir/azure-activity-normalization/v1.7",
        "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
        "input_format": input_format, "source_sha256": sha256_bytes(raw),
        "event_count": len(events), "events": [_event(item, i) for i, item in enumerate(events, 1)],
        "input_order_preserved": True,
        "continuation_link_present": bool(continuation) if input_format == "activity-log" else None,
        "continuation_link": _digest(document, "nextLink") if input_format == "activity-log" else {"state": "absent", "sha256": None},
        "collection_complete": False if continuation else None,
        "source_authenticity_verified": False, "network_required": False,
        "content_policy": "selected_metadata_and_payload_hashes",
        "interpretation": "Recorded management-plane activity only; caller/claims, authorization, localized labels, status, and operation/correlation IDs do not independently establish human attribution, authority, model invocation, downstream effects, source authenticity, or complete collection.",
    }
    if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
        raise ProvenanceError("activity projection exceeds byte limit")
    _bounded(result)
    return result


def compare_replay(raw: bytes, preserved: bytes, *, input_format: str) -> dict:
    replayed = normalize(raw, input_format=input_format)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {
        "status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
        "recorded_output_sha256": actual, "replayed_output_sha256": expected,
        "source_sha256": replayed["source_sha256"], "event_count": replayed["event_count"],
        "collection_complete": replayed["collection_complete"],
        "source_authenticity_verified": False, "network_required": False,
    }

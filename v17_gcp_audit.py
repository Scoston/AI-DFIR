"""Bounded native Google Cloud Audit Log projection and offline replay."""
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

TRANSFORMATION = "v17_gcp_audit.normalize"
TRANSFORMATION_VERSION = "1.7"
INPUT_FORMATS = ("entries", "array")
AUDIT_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_ENTRY_BYTES = 1024 * 1024
MAX_ENTRIES = 2000
MAX_DEPTH = 32
MAX_NODES = 200000
MAX_METADATA_CHARS = 4096
MAX_DELEGATES = 64
MAX_AUTHORIZATIONS = 256
LOG_RE = re.compile(r"(projects|organizations|folders|billingAccounts)/[A-Za-z0-9_.:-]+/logs/cloudaudit\.googleapis\.com%2[Ff](activity|data_access|system_event|policy)")
TIME_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})")
PAYLOAD_FIELDS = (
    "request", "response", "metadata", "serviceData", "resourceOriginalState",
    "resourceLocation", "policyViolationInfo", "authenticationInfo",
    "authorizationInfo", "requestMetadata", "status",
)


def _bounded(value):
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        children = 2 * len(item) if isinstance(item, dict) else len(item) if isinstance(item, list) else 0
        if depth > MAX_DEPTH or visited + len(pending) + children > MAX_NODES:
            raise ProvenanceError("audit JSON structure exceeds limits")
        if isinstance(item, dict):
            pending.extend((k, depth + 1) for k in item)
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_INPUT_BYTES:
                raise ProvenanceError("audit JSON string exceeds limits")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ProvenanceError("audit JSON number is not finite")
        elif type(item) is int and abs(item) > 9007199254740991:
            raise ProvenanceError("audit JSON integer exceeds RFC8785 safe range")


def _document(raw, limit):
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise ProvenanceError("audit document is empty or exceeds byte limit")
    try:
        value = strict_json(raw)
        _bounded(value)
        return value
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProvenanceError("invalid or excessive audit JSON") from exc


def read_document(path, *, limit=MAX_INPUT_BYTES):
    descriptor = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ProvenanceError("audit input must be a regular file")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ProvenanceError("audit document is empty or exceeds byte limit")
    return raw


def _text(obj, key, *, required=False):
    if key not in obj:
        if required:
            raise ProvenanceError("required audit metadata is absent")
        return None
    value = obj[key]
    if not isinstance(value, str) or (required and not value) or len(value) > MAX_METADATA_CHARS or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ProvenanceError("invalid audit metadata string")
    return value


def _object(obj, key, *, required=False):
    if key not in obj and not required:
        return {}
    value = obj.get(key)
    if not isinstance(value, dict):
        raise ProvenanceError("invalid audit object")
    return value


def _rows(obj, key, limit):
    value = obj.get(key, [])
    if not isinstance(value, list) or len(value) > limit or not all(isinstance(row, dict) for row in value):
        raise ProvenanceError("invalid or excessive audit record list")
    return value


def _boolean(obj, key):
    if key not in obj:
        return None
    if type(obj[key]) is not bool:
        raise ProvenanceError("invalid recorded audit Boolean")
    return obj[key]


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
        raise ProvenanceError("audit timestamp must have an explicit RFC3339 offset")
    # Validate the calendar and offset without converting the fractional seconds.
    # The original string, including all nine possible digits, is retained.
    datetime(*map(int, match.groups()[:6]))
    offset = match[8]
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise ProvenanceError("invalid audit timestamp offset")
    return value


def _delegation(auth):
    result = []
    for ordinal, item in enumerate(_rows(auth, "serviceAccountDelegationInfo", MAX_DELEGATES), 1):
        kinds = [key for key in ("firstPartyPrincipal", "thirdPartyPrincipal") if key in item]
        if len(kinds) > 1:
            raise ProvenanceError("ambiguous audit delegation authority")
        first = _object(item, "firstPartyPrincipal")
        third = _object(item, "thirdPartyPrincipal")
        result.append({
            "ordinal": ordinal, "principal_subject": _text(item, "principalSubject"),
            "authority_kind": kinds[0] if kinds else None,
            "first_party_email": _text(first, "principalEmail"),
            "service_metadata": _digest(first, "serviceMetadata"),
            "third_party_claims": _digest(third, "thirdPartyClaims"),
            "record_sha256": sha256_object(item),
        })
    return result


def _authorizations(payload):
    return [{
        "ordinal": ordinal, "resource": _text(item, "resource"), "permission": _text(item, "permission"),
        "granted": _boolean(item, "granted"), "resource_attributes": _digest(item, "resourceAttributes"),
        "record_sha256": sha256_object(item),
    } for ordinal, item in enumerate(_rows(payload, "authorizationInfo", MAX_AUTHORIZATIONS), 1)]


def _entry(entry, ordinal):
    if "split" in entry or "jsonPayload" in entry or "textPayload" in entry:
        raise ProvenanceError("split or mixed non-audit payloads are unsupported")
    encoded = canonical_json_bytes(entry)
    if len(encoded) > MAX_ENTRY_BYTES:
        raise ProvenanceError("audit entry exceeds byte limit")
    name = _text(entry, "logName", required=True)
    log = LOG_RE.fullmatch(name)
    if log is None:
        raise ProvenanceError("unsupported Cloud Audit log name")
    payload = _object(entry, "protoPayload", required=True)
    if payload.get("@type") != AUDIT_TYPE:
        raise ProvenanceError("unsupported audit payload type")
    resource = _object(entry, "resource", required=True)
    auth, request, status = (_object(payload, key) for key in ("authenticationInfo", "requestMetadata", "status"))
    operation = _object(entry, "operation")
    code = status.get("code")
    if "code" in status and (type(code) is not int or not -2147483648 <= code <= 2147483647):
        raise ProvenanceError("invalid recorded audit status code")
    return {
        "ordinal": ordinal, "entry_sha256": sha256_bytes(encoded),
        "log_name": name, "log_scope": log[1], "audit_category": log[2],
        "insert_id": _text(entry, "insertId"),
        "timestamp": _timestamp(entry, "timestamp", required=True),
        "receive_timestamp": _timestamp(entry, "receiveTimestamp"),
        "severity": _text(entry, "severity"),
        "service_name": _text(payload, "serviceName", required=True),
        "method_name": _text(payload, "methodName", required=True),
        "resource_name": _text(payload, "resourceName"),
        "monitored_resource_type": _text(resource, "type", required=True),
        "monitored_resource": _digest(entry, "resource"), "labels": _digest(entry, "labels"),
        "actor": {key: _text(auth, key) for key in ("principalEmail", "principalSubject", "authoritySelector")},
        "delegation": _delegation(auth), "authorizations": _authorizations(payload),
        "caller_ip": _text(request, "callerIp"),
        "status_recorded": "status" in payload, "status_code": code,
        "operation": {
            "recorded": "operation" in entry,
            "id": _text(operation, "id"), "producer": _text(operation, "producer"),
            "first": _boolean(operation, "first"), "last": _boolean(operation, "last"),
        },
        "trace": _text(entry, "trace"), "span_id": _text(entry, "spanId"),
        "payload_digests": {key: _digest(payload, key) for key in PAYLOAD_FIELDS},
    }


def normalize(raw: bytes, *, input_format: str) -> dict:
    if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
        raise ProvenanceError("unsupported audit input format")
    document = _document(raw, MAX_INPUT_BYTES)
    token = None
    if input_format == "entries":
        if not isinstance(document, dict) or set(document) - {"entries", "nextPageToken"}:
            raise ProvenanceError("unsupported or mixed audit export envelope")
        entries = _rows(document, "entries", MAX_ENTRIES)
        token = _text(document, "nextPageToken")
    else:
        entries = _rows({"entries": document}, "entries", MAX_ENTRIES)
    result = {
        "schema": "ai-dfir/gcp-audit-normalization/v1.7",
        "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
        "input_format": input_format, "source_sha256": sha256_bytes(raw),
        "entry_count": len(entries), "entries": [_entry(item, i) for i, item in enumerate(entries, 1)],
        "input_order_preserved": True,
        "continuation_token_present": bool(token) if input_format == "entries" else None,
        "continuation_token": _digest(document, "nextPageToken") if input_format == "entries" else {"state": "absent", "sha256": None},
        "collection_complete": False if token else None,
        "source_authenticity_verified": False, "network_required": False,
        "content_policy": "selected_metadata_and_payload_hashes",
        "interpretation": "Recorded audit metadata only; delegation, permission checks, status codes, and operation markers do not independently establish human attribution, authority, downstream effects, source authenticity, or complete collection.",
    }
    if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
        raise ProvenanceError("audit projection exceeds byte limit")
    _bounded(result)
    return result


def compare_replay(raw: bytes, preserved: bytes, *, input_format: str) -> dict:
    replayed = normalize(raw, input_format=input_format)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {
        "status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
        "recorded_output_sha256": actual, "replayed_output_sha256": expected,
        "source_sha256": replayed["source_sha256"], "entry_count": replayed["entry_count"],
        "collection_complete": replayed["collection_complete"],
        "source_authenticity_verified": False, "network_required": False,
    }

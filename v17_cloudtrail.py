"""Bounded native CloudTrail projection; no collection or source authentication."""
from __future__ import annotations

import math
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_provenance import ProvenanceError
from v17_reconstruction import strict_json

TRANSFORMATION = "v17_cloudtrail.normalize"
TRANSFORMATION_VERSION = "1.7"
INPUT_FORMATS = ("records", "lookup-events")
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
MAX_EVENTS = 2000
MAX_DEPTH = 32
MAX_NODES = 200000
MAX_METADATA_CHARS = 1024
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
VERSION_RE = re.compile(r"1\.([0-9]{1,3})")
TEXT_FIELDS = {
    "event_version": "eventVersion", "event_id": "eventID", "timestamp": "eventTime",
    "event_source": "eventSource", "event_name": "eventName", "region": "awsRegion",
    "event_type": "eventType", "event_category": "eventCategory", "request_id": "requestID",
    "recipient_account_id": "recipientAccountId", "shared_event_id": "sharedEventID",
    "source_ip_address": "sourceIPAddress", "error_code": "errorCode",
}
REQUIRED_TEXT = {"eventVersion", "eventID", "eventTime", "eventSource", "eventName", "awsRegion", "eventType"}
PAYLOAD_FIELDS = (
    "requestParameters", "responseElements", "errorMessage", "resources",
    "additionalEventData", "serviceEventDetails", "addendum", "userIdentity",
)


def _bounded(value, budget):
    """Check the whole parsed tree, including fields outside the projection."""
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        budget[0] += 1
        if depth > MAX_DEPTH or budget[0] > MAX_NODES:
            raise ProvenanceError("CloudTrail JSON structure exceeds limits")
        if isinstance(item, dict):
            if budget[0] + len(pending) + 2 * len(item) > MAX_NODES:
                raise ProvenanceError("CloudTrail JSON structure exceeds limits")
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if budget[0] + len(pending) + len(item) > MAX_NODES:
                raise ProvenanceError("CloudTrail JSON structure exceeds limits")
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            # Encoding also rejects escaped unpaired Unicode surrogates.
            if len(item.encode("utf-8")) > MAX_INPUT_BYTES:
                raise ProvenanceError("CloudTrail JSON string exceeds limits")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ProvenanceError("CloudTrail JSON number is not finite")
        elif type(item) is int and abs(item) > 9007199254740991:
            raise ProvenanceError("CloudTrail JSON integer exceeds the RFC8785 safe range")


def _document(raw, limit, budget):
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise ProvenanceError("CloudTrail document exceeds byte limits or is empty")
    try:
        value = strict_json(raw)
        _bounded(value, budget)
        return value
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProvenanceError("invalid or excessive CloudTrail JSON") from exc


def read_document(path, *, limit=MAX_INPUT_BYTES):
    """Read a bounded regular file; nonblocking open also rejects FIFOs promptly."""
    descriptor = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ProvenanceError("CloudTrail input must be a regular file")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ProvenanceError("CloudTrail document exceeds byte limits or is empty")
    return raw


def _text(obj, key, *, required=False):
    if key not in obj:
        if required:
            raise ProvenanceError("required CloudTrail field is absent")
        return None
    value = obj[key]
    if not isinstance(value, str) or not value or len(value) > MAX_METADATA_CHARS or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ProvenanceError("invalid CloudTrail metadata field")
    return value


def _object(obj, key, *, required=False):
    if key not in obj and not required:
        return {}
    value = obj.get(key)
    if not isinstance(value, dict):
        raise ProvenanceError("invalid CloudTrail identity object")
    return value


def _boolean(obj, key):
    if key not in obj:
        return None
    if type(obj[key]) is not bool:
        raise ProvenanceError("invalid CloudTrail Boolean field")
    return obj[key]


def _payload(obj, key):
    if key not in obj:
        return {"state": "absent", "sha256": None}
    return {"state": "null" if obj[key] is None else "present", "sha256": sha256_object(obj[key])}


def _event(value, ordinal, wrapper=None):
    if not isinstance(value, dict):
        raise ProvenanceError("CloudTrail event must be an object")
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_EVENT_BYTES:
        raise ProvenanceError("CloudTrail event exceeds byte limit")
    row = {target: _text(value, source, required=source in REQUIRED_TEXT) for target, source in TEXT_FIELDS.items()}
    version = VERSION_RE.fullmatch(row["event_version"])
    if version is None or int(version[1]) < 2:
        raise ProvenanceError("unsupported CloudTrail event version")
    if TIME_RE.fullmatch(row["timestamp"]) is None:
        raise ProvenanceError("CloudTrail event time must be UTC")
    event_time = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
    if row["event_type"] == "AwsCloudTrailInsight" or row["event_category"] == "Insight" or "insightDetails" in value:
        raise ProvenanceError("CloudTrail Insights is outside this event profile")
    identity = _object(value, "userIdentity", required=True)
    context = _object(identity, "sessionContext")
    issuer = _object(context, "sessionIssuer")
    row.update(
        ordinal=ordinal, event_sha256=sha256_bytes(encoded),
        lookup_wrapper_sha256=sha256_object(wrapper) if wrapper is not None else None,
        read_only=_boolean(value, "readOnly"), management_event=_boolean(value, "managementEvent"),
        actor={key: _text(identity, key) for key in ("type", "arn", "principalId", "accountId", "invokedBy")},
        session_issuer={key: _text(issuer, key) for key in ("type", "arn", "principalId", "accountId")},
        payload_digests={key: _payload(value, key) for key in PAYLOAD_FIELDS},
    )
    if wrapper is not None:
        for outer, inner in (("EventId", "eventID"), ("EventName", "eventName"), ("EventSource", "eventSource")):
            if outer in wrapper and _text(wrapper, outer) != value[inner]:
                raise ProvenanceError("CloudTrail lookup identity conflicts with embedded event")
        if "ReadOnly" in wrapper:
            flag = wrapper["ReadOnly"]
            if type(flag) is not str or flag not in ("true", "false") or row["read_only"] is None or (flag == "true") != row["read_only"]:
                raise ProvenanceError("CloudTrail lookup read-only flag conflicts with embedded event")
        if "EventTime" in wrapper:
            stamp = wrapper["EventTime"]
            if type(stamp) in (int, float):
                try:
                    outer_time = datetime.fromtimestamp(stamp, timezone.utc)
                except (ValueError, OverflowError, OSError) as exc:
                    raise ProvenanceError("CloudTrail lookup time is outside the supported range") from exc
            elif isinstance(stamp, str):
                outer_time = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if outer_time.utcoffset() is None:
                    raise ProvenanceError("CloudTrail lookup time is not timezone-aware")
            else:
                raise ProvenanceError("invalid CloudTrail lookup time")
            if outer_time != event_time:
                raise ProvenanceError("CloudTrail lookup time conflicts with embedded event")
    return row


def normalize(raw: bytes, *, input_format: str) -> dict:
    """Project every event, retaining input order and duplicate IDs without inference."""
    if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
        raise ProvenanceError("unsupported CloudTrail input format")
    budget = [0]
    document = _document(raw, MAX_INPUT_BYTES, budget)
    if not isinstance(document, dict):
        raise ProvenanceError("CloudTrail export must be an object")
    key = "Records" if input_format == "records" else "Events"
    allowed = {"Records"} if input_format == "records" else {"Events", "NextToken", "ResponseMetadata"}
    if key not in document or set(document) - allowed:
        raise ProvenanceError("unsupported or mixed CloudTrail export envelope")
    entries = document[key]
    if not isinstance(entries, list) or len(entries) > MAX_EVENTS:
        raise ProvenanceError("invalid or excessive CloudTrail event count")
    if "ResponseMetadata" in document and not isinstance(document["ResponseMetadata"], dict):
        raise ProvenanceError("invalid CloudTrail response metadata")
    token = None
    if "NextToken" in document:
        token = _text(document, "NextToken", required=True)
    rows = []
    for ordinal, entry in enumerate(entries, 1):
        wrapper = None
        if input_format == "lookup-events":
            if not isinstance(entry, dict) or not isinstance(entry.get("CloudTrailEvent"), str):
                raise ProvenanceError("lookup export needs the embedded CloudTrailEvent JSON string")
            wrapper = entry
            entry = _document(entry["CloudTrailEvent"].encode("utf-8"), MAX_EVENT_BYTES, budget)
        rows.append(_event(entry, ordinal, wrapper))
    result = {
        "schema": "ai-dfir/cloudtrail-normalization/v1.7",
        "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
        "input_format": input_format, "source_sha256": sha256_bytes(raw),
        "event_count": len(rows), "events": rows, "input_order_preserved": True,
        "continuation_token_present": token is not None if input_format == "lookup-events" else None,
        "continuation_token_sha256": sha256_object(token) if token is not None else None,
        "collection_complete": False if token is not None else None, "source_authenticity_verified": False,
        "content_policy": "selected_metadata_and_payload_hashes", "network_required": False,
        "interpretation": "Recorded CloudTrail fields only; no complete collection, human attribution, downstream effect, or AWS log-signature validation is established.",
    }
    if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
        raise ProvenanceError("CloudTrail projection exceeds byte limit")
    _bounded(result, [0])
    return result


def compare_replay(raw: bytes, preserved: bytes, *, input_format: str) -> dict:
    replayed = normalize(raw, input_format=input_format)
    recorded = _document(preserved, MAX_OUTPUT_BYTES, [0])
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {
        "status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
        "recorded_output_sha256": actual, "replayed_output_sha256": expected,
        "source_sha256": replayed["source_sha256"], "event_count": replayed["event_count"],
        "source_authenticity_verified": False, "collection_complete": replayed["collection_complete"], "network_required": False,
    }

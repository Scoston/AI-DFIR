"""Pure bounded reassessment of retained bytes against explicitly pinned rules."""
from __future__ import annotations

import re
import os
from pathlib import Path
import stat

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import _bounded, _document
from v17_numeric_json import NumberToken, document as numeric_document
from v17_provenance import ProvenanceError

TRANSFORMATION = "v17_evidence_validation.assess"
TRANSFORMATION_VERSION = "1.7"
RULES_SCHEMA = "ai-dfir/raw-evidence-rules/v1.7"
REPORT_SCHEMA = "ai-dfir/raw-evidence-assessment/v1.7"
FORMATS = ("json-object", "json-array", "jsonl", "text", "binary")
JSON_KINDS = ("array", "boolean", "null", "number", "object", "string")
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_RULES_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
MAX_RECORDS = 10000
MAX_LINES = 20000
MAX_LINE_BYTES = 1024 * 1024
MAX_FIELDS = 256
MAX_RULE_FIELDS = 64
HEX_RE = re.compile(r"[0-9a-f]{64}")
RULE_FIELDS = {"schema", "case_id", "format", "expected_sha256", "min_size_bytes", "max_size_bytes",
               "require_records", "required_fields", "field_types", "allow_extra_fields", "required_text"}


def read_evidence(path):
    """Bounded regular-file read; zero bytes are evidence to assess, not JSON."""
    descriptor = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            raise ProvenanceError("raw evidence must be a bounded regular file")
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ProvenanceError("raw evidence exceeds byte limit")
    return raw


def _text(value, limit):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def validate_rules(raw, *, case_id, expected_rules_sha256):
    rules = _document(raw, MAX_RULES_BYTES)
    if (not isinstance(expected_rules_sha256, str) or HEX_RE.fullmatch(expected_rules_sha256) is None
            or sha256_object(rules) != expected_rules_sha256):
        raise ProvenanceError("an explicit matching canonical rules pin is required")
    if not isinstance(rules, dict) or set(rules) != RULE_FIELDS or rules["schema"] != RULES_SCHEMA:
        raise ProvenanceError("unsupported raw-evidence rules")
    if not _text(case_id, 4096) or not case_id.strip() or rules["case_id"] != case_id or rules["format"] not in FORMATS:
        raise ProvenanceError("raw-evidence case or format mismatch")
    if not isinstance(rules["expected_sha256"], str) or HEX_RE.fullmatch(rules["expected_sha256"]) is None:
        raise ProvenanceError("an expected evidence digest is required")
    low, high = rules["min_size_bytes"], rules["max_size_bytes"]
    if type(low) is not int or type(high) is not int or not 0 <= low <= high <= MAX_INPUT_BYTES:
        raise ProvenanceError("invalid raw-evidence size rules")
    if type(rules["require_records"]) is not bool or type(rules["allow_extra_fields"]) is not bool:
        raise ProvenanceError("invalid raw-evidence Boolean rules")
    required, types, needles = rules["required_fields"], rules["field_types"], rules["required_text"]
    if (not isinstance(required, list) or len(required) > MAX_RULE_FIELDS or not all(_text(x, 256) for x in required)
            or len(set(required)) != len(required) or not isinstance(types, dict) or len(types) > MAX_RULE_FIELDS
            or not all(_text(x, 256) for x in types) or not set(required) <= set(types)):
        raise ProvenanceError("invalid or excessive field rules")
    for allowed in types.values():
        if (not isinstance(allowed, list) or not 1 <= len(allowed) <= len(JSON_KINDS)
                or not all(isinstance(x, str) and x in JSON_KINDS for x in allowed) or len(set(allowed)) != len(allowed)):
            raise ProvenanceError("invalid allowed JSON kinds")
    if (not isinstance(needles, list) or len(needles) > 64 or not all(_text(x, 4096) for x in needles)
            or len(set(needles)) != len(needles)):
        raise ProvenanceError("invalid or excessive literal text rules")
    if rules["format"] in ("text", "binary") and (required or types or rules["require_records"] or not rules["allow_extra_fields"]):
        raise ProvenanceError("record rules require an explicit JSON format")
    if rules["format"] == "binary" and needles:
        raise ProvenanceError("binary evidence does not accept text rules")
    return rules


def _kind(value):
    if isinstance(value, NumberToken): return "number"
    if value is None: return "null"
    if type(value) is bool: return "boolean"
    if isinstance(value, str): return "string"
    if isinstance(value, list): return "array"
    if isinstance(value, dict): return "object"
    raise ProvenanceError("unsupported parsed value")


def _records(raw, fmt):
    if fmt == "jsonl":
        if raw.count(b"\n") > MAX_LINES:
            raise ProvenanceError("excessive physical JSONL lines")
        records = []
        for line in raw.split(b"\n"):
            if len(line) > MAX_LINE_BYTES:
                raise ProvenanceError("excessive JSONL line")
            if not line.strip(b" \t\r"):
                continue
            if len(records) == MAX_RECORDS:
                raise ProvenanceError("excessive JSONL records")
            records.append(numeric_document(line, limit=MAX_LINE_BYTES))
    else:
        value = numeric_document(raw, limit=MAX_INPUT_BYTES)
        records = [value] if fmt == "json-object" else value
    if (not isinstance(records, list) or len(records) > MAX_RECORDS
            or not all(isinstance(record, dict) for record in records)):
        raise ProvenanceError("profile requires complete object records")
    _bounded(records)  # Global budgets also apply across all JSONL records.
    return records


def _fields(records, rules):
    observed = {}
    for record in records:
        for name, value in record.items():
            if name not in observed:
                if len(observed) == MAX_FIELDS:
                    raise ProvenanceError("excessive observed field names")
                observed[name] = {"present_records": 0, "types": set(), "type_mismatch_records": 0}
            row = observed[name]; kind = _kind(value)
            row["present_records"] += 1; row["types"].add(kind)
            if name in rules["field_types"] and kind not in rules["field_types"][name]:
                row["type_mismatch_records"] += 1
    rows = []
    for name in set(observed) | set(rules["field_types"]):
        row = observed.get(name, {"present_records": 0, "types": set(), "type_mismatch_records": 0})
        rows.append({"field_sha256": sha256_object(name), "types": sorted(row["types"]),
                     "present_records": row["present_records"], "type_mismatch_records": row["type_mismatch_records"],
                     "missing_required_records": len(records) - row["present_records"] if name in rules["required_fields"] else 0,
                     "unexpected": name not in rules["field_types"]})
    rows.sort(key=lambda row: row["field_sha256"])
    conforms = all(not row["type_mismatch_records"] and not row["missing_required_records"]
                   and (rules["allow_extra_fields"] or not row["unexpected"]) for row in rows)
    shape = [{"field_sha256": row["field_sha256"], "types": row["types"]} for row in rows if row["present_records"]]
    return rows, conforms, sha256_object(shape)


def assess(raw: bytes, *, rules_raw: bytes, case_id: str, expected_rules_sha256: str) -> dict:
    try:
        rules = validate_rules(rules_raw, case_id=case_id, expected_rules_sha256=expected_rules_sha256)
        if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
            raise ProvenanceError("evidence exceeds byte limit")
        fmt = rules["format"]; records = None; fields = []; shape = None; conforms = None
        text = None; parse_state = "NOT_APPLICABLE" if fmt == "binary" else "PASS"
        try:
            if fmt != "binary": text = raw.decode("utf-8", errors="strict")
            if fmt not in ("text", "binary"):
                records = _records(raw, fmt)
                fields, conforms, shape = _fields(records, rules)
        except (ValueError, TypeError, RecursionError):
            parse_state = "INVALID_OR_UNSUPPORTED"; records = None; fields = []; shape = None; conforms = None
        checks = {
            "expected_digest_matches": sha256_bytes(raw) == rules["expected_sha256"],
            "size_satisfies_rules": rules["min_size_bytes"] <= len(raw) <= rules["max_size_bytes"],
            "parse_satisfies_profile": parse_state in ("PASS", "NOT_APPLICABLE"),
            "records_requirement_satisfied": bool(records) if rules["require_records"] else True,
            "field_rules_satisfied": conforms if fmt not in ("text", "binary") else True,
            "literal_text_satisfied": all(text is not None and needle in text for needle in rules["required_text"]),
        }
        result = {
            "schema": REPORT_SCHEMA, "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
            "case_id": case_id, "format": fmt, "source_sha256": sha256_bytes(raw), "source_size_bytes": len(raw),
            "rules_sha256": expected_rules_sha256, "rules_source_sha256": sha256_bytes(rules_raw),
            "validation_status": "SATISFIED" if all(value is True for value in checks.values()) else "NOT_SATISFIED",
            "checks": checks, "parse_state": parse_state, "record_count": len(records) if records is not None else None,
            "field_observations": fields, "observed_schema_sha256": shape,
            "raw_evidence_reassessed": True, "quality_rating_changed": False, "rules_approval_verified": False,
            "source_authenticity_verified": False, "attribution_verified": False, "collection_complete": None,
            "closure_authorized": False, "network_required": False, "content_policy": "digests_and_validation_counts",
            "interpretation": "Recomputed byte, syntax, literal, and top-level record-field checks under retained pinned rules only; no evidence-quality promotion, source truth, attribution, time coverage, complete collection, or investigative conclusion is established.",
        }
        if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
            raise ProvenanceError("raw-evidence assessment exceeds byte limit")
        _bounded(result)
        return result
    except (ValueError, TypeError, RecursionError):
        raise ProvenanceError("invalid, excessive, or unsupported raw-evidence assessment input") from None


def compare_replay(raw: bytes, preserved: bytes, *, rules_raw: bytes, case_id: str, expected_rules_sha256: str) -> dict:
    replayed = assess(raw, rules_raw=rules_raw, case_id=case_id, expected_rules_sha256=expected_rules_sha256)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {"status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
            "recorded_output_sha256": actual, "replayed_output_sha256": expected,
            **{key: replayed[key] for key in ("case_id", "source_sha256", "rules_sha256", "validation_status", "record_count",
                "observed_schema_sha256", "raw_evidence_reassessed", "quality_rating_changed", "rules_approval_verified",
                "source_authenticity_verified", "attribution_verified", "collection_complete", "closure_authorized", "network_required")}}

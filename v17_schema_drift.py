"""Compare complete nested JSON-shape observations against pinned retained bytes."""
from __future__ import annotations

from v17_evidence_validation import HEX_RE, MAX_INPUT_BYTES, _kind, _records, _text
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import _bounded, _document
from v17_provenance import ProvenanceError

TRANSFORMATION = "v17_schema_drift.compare"
TRANSFORMATION_VERSION = "1.7"
REPORT_SCHEMA = "ai-dfir/nested-schema-comparison/v1.7"
PATH_SCHEMA = "ai-dfir/nested-schema-path/v1.7"
SHAPE_SCHEMA = "ai-dfir/nested-schema-shape/v1.7"
INPUT_FORMATS = ("json-object", "json-array", "jsonl")
MAX_PATHS = 1024
MAX_KEY_BYTES = 1024
MAX_PATH_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024


def _require(ok, message):
    if not ok: raise ProvenanceError(message)


def path_sha256(segments):
    """Resolve an explicit structured member/items path without string separators."""
    _require(isinstance(segments, (list, tuple)) and len(segments) <= 32, "invalid structural path")
    normalized = []
    for segment in segments:
        _require(isinstance(segment, (list, tuple)), "invalid structural path segment")
        if len(segment) == 1 and segment[0] == "items": normalized.append(["items"])
        else:
            _require(len(segment) == 2 and segment[0] == "member" and isinstance(segment[1], str), "invalid structural member segment")
            _require(len(segment[1].encode("utf-8")) <= MAX_KEY_BYTES, "excessive structural member name")
            normalized.append(["member", segment[1]])
    encoded = canonical_json_bytes({"schema": PATH_SCHEMA, "segments": normalized})
    _require(len(encoded) <= MAX_PATH_BYTES, "excessive encoded structural path")
    return sha256_bytes(encoded)


def observe(raw, *, input_format):
    """Observe every node in every explicit record; array positions share a path."""
    _require(isinstance(input_format, str) and input_format in INPUT_FORMATS, "unsupported structural input format")
    _require(isinstance(raw, bytes) and len(raw) <= MAX_INPUT_BYTES, "excessive structural input")
    records = _records(raw, input_format)
    observations = {}
    for record in records:
        seen = set(); pending = [(record, ())]
        while pending:
            value, path = pending.pop()
            if path not in observations:
                _require(len(observations) < MAX_PATHS, "excessive observed structural paths")
                observations[path] = {"path_sha256": path_sha256(path), "occurrences": 0,
                                      "present_records": 0, "kind_occurrences": {}}
            row = observations[path]; kind = _kind(value)
            row["occurrences"] += 1
            row["kind_occurrences"][kind] = row["kind_occurrences"].get(kind, 0) + 1
            if path not in seen: row["present_records"] += 1; seen.add(path)
            if isinstance(value, dict):
                for name, item in value.items():
                    _require(len(name.encode("utf-8")) <= MAX_KEY_BYTES, "excessive structural member name")
                    pending.append((item, path + (("member", name),)))
            elif isinstance(value, list):
                pending.extend((item, path + (("items",),)) for item in value)
    rows = [dict(row, kinds=sorted(row["kind_occurrences"])) for row in observations.values()]
    rows.sort(key=lambda row: row["path_sha256"])
    _require(len({row["path_sha256"] for row in rows}) == len(rows), "ambiguous structural path identity")
    shape = {"schema": SHAPE_SCHEMA, "input_format": input_format,
             "paths": [{"path_sha256": row["path_sha256"], "kinds": row["kinds"]} for row in rows]}
    return {"record_count": len(records), "observed_path_count": len(rows),
            "shape_sha256": sha256_object(shape), "paths": rows}


def compare(raw: bytes, *, baseline_raw: bytes, input_format: str, case_id: str, expected_baseline_sha256: str):
    try:
        _require(_text(case_id, 4096) and bool(case_id.strip()), "invalid structural comparison case")
        _require(isinstance(baseline_raw, bytes) and len(baseline_raw) <= MAX_INPUT_BYTES, "invalid structural baseline")
        _require(isinstance(expected_baseline_sha256, str) and HEX_RE.fullmatch(expected_baseline_sha256) is not None
                 and sha256_bytes(baseline_raw) == expected_baseline_sha256, "independent matching baseline pin required")
        baseline = observe(baseline_raw, input_format=input_format); current = observe(raw, input_format=input_format)
        before = {row["path_sha256"]: row for row in baseline["paths"]}
        after = {row["path_sha256"]: row for row in current["paths"]}
        added = sorted(set(after) - set(before)); removed = sorted(set(before) - set(after))
        changed = [{"path_sha256": ident, "baseline_kinds": before[ident]["kinds"], "current_kinds": after[ident]["kinds"]}
                   for ident in sorted(set(before) & set(after)) if before[ident]["kinds"] != after[ident]["kinds"]]
        count_fields = ("occurrences", "present_records", "kind_occurrences")
        counts_changed = (baseline["record_count"] != current["record_count"] or bool(added or removed)
                          or any(any(before[ident][field] != after[ident][field] for field in count_fields) for ident in set(before) & set(after)))
        shape_changed = bool(added or removed or changed)
        result = {"schema": REPORT_SCHEMA, "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
                  "case_id": case_id, "input_format": input_format, "baseline_sha256": expected_baseline_sha256,
                  "source_sha256": sha256_bytes(raw), "baseline_size_bytes": len(baseline_raw), "source_size_bytes": len(raw),
                  "baseline": baseline, "current": current,
                  "drift_status": "CHANGED" if shape_changed else "UNCHANGED", "observed_shape_changed": shape_changed,
                  "bytes_changed": raw != baseline_raw, "population_counts_changed": counts_changed,
                  "changes": {"added_paths": added, "removed_paths": removed, "kind_changes": changed},
                  "all_retained_records_observed": True, "array_positions_collapsed": True,
                  "provider_schema_change_proven": False, "schema_compatibility_verified": False,
                  "source_authenticity_verified": False, "baseline_approval_verified": False,
                  "quality_rating_changed": False, "closure_authorized": False, "collection_complete": None,
                  "network_required": False, "content_policy": "structured_path_hashes_and_kind_counts",
                  "interpretation": "Observed nested structure in two complete bounded retained inputs under an explicit baseline pin; no provider schema change, compatibility, source truth, missing-source coverage, baseline approval, or quality/conclusion promotion is established."}
        _require(len(canonical_json_bytes(result)) <= MAX_OUTPUT_BYTES, "excessive structural comparison report")
        _bounded(result)
        return result
    except (ValueError, TypeError, RecursionError):
        raise ProvenanceError("invalid, excessive, or unsupported structural comparison input") from None


def compare_replay(raw: bytes, preserved: bytes, *, baseline_raw: bytes, input_format: str, case_id: str, expected_baseline_sha256: str):
    replayed = compare(raw, baseline_raw=baseline_raw, input_format=input_format, case_id=case_id, expected_baseline_sha256=expected_baseline_sha256)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {"status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
            "recorded_output_sha256": actual, "replayed_output_sha256": expected,
            **{key: replayed[key] for key in ("case_id", "input_format", "source_sha256", "baseline_sha256", "drift_status",
                "observed_shape_changed", "bytes_changed", "population_counts_changed", "provider_schema_change_proven",
                "schema_compatibility_verified", "source_authenticity_verified", "baseline_approval_verified",
                "quality_rating_changed", "closure_authorized", "collection_complete", "network_required")}}

"""Bounded Log Analytics query-result projection and offline replay."""
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

TRANSFORMATION = "v17_log_analytics.normalize"
TRANSFORMATION_VERSION = "1.7"
INPUT_FORMATS = ("tables", "resource-tables")
COLUMN_TYPES = ("bool", "datetime", "dynamic", "guid", "int", "long", "real", "string")
RETAINED_TYPES = ("bool", "datetime", "int", "long", "real")
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_ROW_BYTES = 1024 * 1024
MAX_TABLES = 32
MAX_COLUMNS = 256
MAX_ROWS = 2000
MAX_CELLS = 50000
MAX_ERROR_DETAILS = 128
MAX_DEPTH = 32
MAX_NODES = 200000
MAX_METADATA_CHARS = 4096
TIME_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})")
GUID_RE = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def _bounded(value):
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        children = 2 * len(item) if isinstance(item, dict) else len(item) if isinstance(item, list) else 0
        if depth > MAX_DEPTH or visited + len(pending) + children > MAX_NODES:
            raise ProvenanceError("query JSON structure exceeds limits")
        if isinstance(item, dict):
            pending.extend((k, depth + 1) for k in item)
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_INPUT_BYTES:
                raise ProvenanceError("query JSON string exceeds limits")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ProvenanceError("query JSON number is not finite")
        elif type(item) is int and abs(item) > 9007199254740991:
            raise ProvenanceError("query JSON integer exceeds RFC8785 safe range")


def _document(raw, limit):
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise ProvenanceError("query document is empty or exceeds byte limit")
    try:
        value = strict_json(raw)
        _bounded(value)
        return value
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProvenanceError("invalid or excessive query JSON") from exc


def read_document(path, *, limit=MAX_INPUT_BYTES):
    descriptor = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ProvenanceError("query input must be a regular file")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ProvenanceError("query document is empty or exceeds byte limit")
    return raw


def _text(obj, key):
    value = obj.get(key)
    if not isinstance(value, str) or not value or len(value) > MAX_METADATA_CHARS or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ProvenanceError("invalid or missing query metadata string")
    return value


def _digest(obj, key):
    if key not in obj:
        return {"state": "absent", "sha256": None}
    return {"state": "null" if obj[key] is None else "present", "sha256": sha256_object(obj[key])}


def _timestamp(value):
    match = TIME_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ProvenanceError("query datetime must have an explicit RFC3339 offset")
    # Calendar validation does not convert or round the recorded fraction.
    datetime(*map(int, match.groups()[:6]))
    offset = match[8]
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise ProvenanceError("invalid query datetime offset")


def _json_kind(value):
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


def _cell(value, kind, ordinal):
    if value is not None:
        valid = True
        if kind == "bool":
            valid = type(value) is bool
        elif kind in ("int", "long"):
            valid = type(value) is int and (kind == "long" or -2147483648 <= value <= 2147483647)
        elif kind == "real":
            valid = type(value) in (int, float)
        elif kind == "string":
            valid = isinstance(value, str)
        elif kind == "guid":
            valid = isinstance(value, str) and GUID_RE.fullmatch(value) is not None
        elif kind == "datetime":
            _timestamp(value)
        # Dynamic cells remain opaque JSON values. Never parse a string inside
        # one, execute its contents, or coalesce it with a similarly named column.
        if not valid:
            raise ProvenanceError("query cell does not match its declared column type")
    retained = value is not None and kind in RETAINED_TYPES
    return {
        "column_ordinal": ordinal, "state": "null" if value is None else "present",
        "json_kind": _json_kind(value), "sha256": sha256_object(value),
        "value_retained": retained, **({"value": value} if retained else {}),
    }


def _tables(document):
    tables = document.get("tables")
    if not isinstance(tables, list) or len(tables) > MAX_TABLES:
        raise ProvenanceError("invalid or excessive query table list")
    row_count, cell_count = 0, 0
    # Validate all dimensions before allocating projected cells. Budgets are
    # global across tables; an attacker cannot reset them in each table.
    for table in tables:
        if not isinstance(table, dict) or set(table) != {"name", "columns", "rows"}:
            raise ProvenanceError("unsupported query table envelope")
        _text(table, "name")
        columns, rows = table["columns"], table["rows"]
        if not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS or not isinstance(rows, list):
            raise ProvenanceError("invalid query columns or rows")
        names = set()
        for column in columns:
            if not isinstance(column, dict) or set(column) != {"name", "type"}:
                raise ProvenanceError("invalid query column descriptor")
            name, kind = _text(column, "name"), _text(column, "type")
            if name in names or kind not in COLUMN_TYPES:
                raise ProvenanceError("duplicate query column or unsupported column type")
            names.add(name)
        row_count += len(rows)
        cell_count += len(rows) * len(columns)
        if row_count > MAX_ROWS or cell_count > MAX_CELLS:
            raise ProvenanceError("query rows or cells exceed global limits")
        if not all(isinstance(row, list) and len(row) == len(columns) for row in rows):
            raise ProvenanceError("query row width does not match its columns")
    return tables, row_count, cell_count


def _table(table, ordinal):
    columns, rows = table["columns"], []
    for row_ordinal, row in enumerate(table["rows"], 1):
        encoded = canonical_json_bytes(row)
        if len(encoded) > MAX_ROW_BYTES:
            raise ProvenanceError("query row exceeds byte limit")
        rows.append({
            "ordinal": row_ordinal, "row_sha256": sha256_bytes(encoded),
            "binding_sha256": sha256_object({"columns": columns, "row": row}),
            "cells": [_cell(value, column["type"], i) for i, (column, value) in enumerate(zip(columns, row), 1)],
        })
    return {
        "ordinal": ordinal, "name": table["name"], "table_sha256": sha256_object(table),
        "schema_sha256": sha256_object(columns),
        "columns": [{"ordinal": i, **column} for i, column in enumerate(columns, 1)],
        "row_count": len(rows), "rows": rows,
    }


def _partial_error(document):
    if "error" not in document:
        return False
    error = document["error"]
    if not isinstance(error, dict) or _text(error, "code") != "PartialError":
        raise ProvenanceError("failed or unsupported query response")
    if "details" in error:
        details = error["details"]
        if not isinstance(details, list) or len(details) > MAX_ERROR_DETAILS or not all(isinstance(item, dict) for item in details):
            raise ProvenanceError("invalid or excessive partial-error details")
    return True


def normalize(raw: bytes, *, input_format: str) -> dict:
    if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
        raise ProvenanceError("unsupported query input format")
    document = _document(raw, MAX_INPUT_BYTES)
    optional = {"permissions"} if input_format == "resource-tables" else set()
    if not isinstance(document, dict) or set(document) - {"tables", "error", "statistics", "render"} - optional:
        raise ProvenanceError("unsupported or mixed query response envelope")
    if "permissions" in document and not isinstance(document["permissions"], dict):
        raise ProvenanceError("invalid resource permission observation")
    partial = _partial_error(document)
    tables, row_count, cell_count = _tables(document)
    result = {
        "schema": "ai-dfir/log-analytics-normalization/v1.7",
        "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
        "input_format": input_format, "source_sha256": sha256_bytes(raw),
        "table_count": len(tables), "row_count": row_count, "cell_count": cell_count,
        "tables": [_table(table, i) for i, table in enumerate(tables, 1)],
        "input_order_preserved": True, "partial_error_recorded": partial,
        "response_state": "PARTIAL" if partial else "NO_ERROR_RECORDED",
        "response_digests": {key: _digest(document, key) for key in ("error", "statistics", "render")},
        "collection_complete": False if partial else None,
        "request_scope_verified": False, "source_authenticity_verified": False,
        "network_required": False, "query_reexecuted": False,
        "content_policy": "typed_scalars_and_cell_hashes",
        "interpretation": "Retained query-result projection only; replay does not re-execute KQL or establish query success, underlying event counts, request scope, provider origin, human attribution, downstream effects, or complete collection.",
    }
    if input_format == "resource-tables":
        # Bind the bounded opaque observation without treating it as an RBAC
        # evaluation, a complete source inventory, or proof of permission.
        result["response_digests"]["permissions"] = _digest(document, "permissions")
        result["permissions_verified"] = False
    if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
        raise ProvenanceError("query projection exceeds byte limit")
    _bounded(result)
    return result


def compare_replay(raw: bytes, preserved: bytes, *, input_format: str) -> dict:
    replayed = normalize(raw, input_format=input_format)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {
        "status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
        "recorded_output_sha256": actual, "replayed_output_sha256": expected,
        "source_sha256": replayed["source_sha256"], "table_count": replayed["table_count"],
        "row_count": replayed["row_count"], "partial_error_recorded": replayed["partial_error_recorded"],
        "response_state": replayed["response_state"], "collection_complete": replayed["collection_complete"],
        "request_scope_verified": False, "source_authenticity_verified": False,
        "network_required": False, "query_reexecuted": False,
    }

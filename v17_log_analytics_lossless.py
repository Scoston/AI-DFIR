"""Explicit lossless Log Analytics numeric projection and offline replay."""
from __future__ import annotations

import math
import re

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import (
    COLUMN_TYPES as BASE_TYPES, GUID_RE, MAX_OUTPUT_BYTES, MAX_ROW_BYTES,
    _bounded, _document, _partial_error, _tables, _timestamp,
)
from v17_numeric_json import MAX_NUMBER_CHARS, NUMBER_RE, TOKEN_ENCODING, NumberToken, document, token_bytes, token_digest
from v17_provenance import ProvenanceError

TRANSFORMATION = "v17_log_analytics_lossless.normalize"
TRANSFORMATION_VERSION = "1.7"
INPUT_FORMATS = ("tables", "resource-tables")
COLUMN_TYPES = BASE_TYPES + ("decimal",)
INTEGER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)")
DECIMAL_MAX_COEFFICIENT = 2 ** 96 - 1


def _numeric_text(value, kind):
    text = value.text if isinstance(value, NumberToken) else value
    if not isinstance(text, str) or len(text) > MAX_NUMBER_CHARS or NUMBER_RE.fullmatch(text) is None:
        raise ProvenanceError("invalid numeric cell representation")
    if kind in ("int", "long"):
        bits = 32 if kind == "int" else 64
        if INTEGER_RE.fullmatch(text) is None or not -(2 ** (bits - 1)) <= int(text) < 2 ** (bits - 1):
            raise ProvenanceError("integer cell outside declared signed range")
    elif kind == "real":
        # Conversion is only a range check. The projected value and every digest
        # use original text, never this rounded binary64 result.
        floating = float(text)
        mantissa = re.split("[eE]", text)[0]
        nonzero = any(digit in "123456789" for digit in mantissa)
        if not math.isfinite(floating) or (floating == 0 and nonzero):
            raise ProvenanceError("real cell overflows or underflows finite binary64")
    else:
        parts = re.split("[eE]", text)
        mantissa = parts[0].lstrip("-")
        exponent = (int(parts[1]) if len(parts) == 2 else 0) - len(mantissa.partition(".")[2])
        coefficient = int(mantissa.replace(".", ""))
        if coefficient:
            # Exact integer arithmetic, independent of ambient Decimal precision.
            # Remove only representational trailing zeroes for the range check.
            while coefficient % 10 == 0:
                coefficient //= 10
                exponent += 1
            if exponent < -28 or exponent > 28:
                raise ProvenanceError("decimal cell outside supported scale")
            if exponent > 0:
                coefficient *= 10 ** exponent
            if coefficient > DECIMAL_MAX_COEFFICIENT:
                raise ProvenanceError("decimal cell exceeds 96-bit coefficient")
    return text


def _cell(value, kind, ordinal):
    json_kind = ("number" if isinstance(value, NumberToken) else "null" if value is None else
                 "boolean" if type(value) is bool else "string" if isinstance(value, str) else
                 "array" if isinstance(value, list) else "object")
    result = {"column_ordinal": ordinal, "state": "null" if value is None else "present",
              "json_kind": json_kind, "token_tree_sha256": token_digest(value), "value_retained": False}
    if value is None:
        return result
    if kind in ("int", "long", "real", "decimal"):
        result.update(numeric_text=_numeric_text(value, kind), value_retained=True,
                      value_representation="json-number-token" if isinstance(value, NumberToken) else "json-string-number")
    elif kind == "bool":
        if type(value) is not bool:
            raise ProvenanceError("Boolean cell requires a JSON Boolean")
        result.update(value=value, value_retained=True)
    elif kind == "datetime":
        _timestamp(value)
        result.update(value=value, value_retained=True)
    elif kind == "string" and not isinstance(value, str):
        raise ProvenanceError("string cell requires a JSON string")
    elif kind == "guid" and (not isinstance(value, str) or GUID_RE.fullmatch(value) is None):
        raise ProvenanceError("invalid GUID cell")
    # Dynamic remains opaque, including number tokens and tag-shaped objects.
    return result


def _table(table, ordinal):
    columns, rows = table["columns"], []
    for row_ordinal, row in enumerate(table["rows"], 1):
        encoded = token_bytes(row)
        if len(encoded) > MAX_ROW_BYTES:
            raise ProvenanceError("numeric row token tree exceeds byte limit")
        rows.append({"ordinal": row_ordinal, "row_token_tree_sha256": sha256_bytes(encoded),
                     "binding_token_tree_sha256": token_digest({"columns": columns, "row": row}),
                     "cells": [_cell(value, column["type"], i) for i, (column, value) in enumerate(zip(columns, row), 1)]})
    return {"ordinal": ordinal, "name": table["name"], "table_token_tree_sha256": token_digest(table),
            "schema_sha256": sha256_object(columns), "schema_digest_encoding": "RFC8785-JSON",
            "columns": [{"ordinal": i, **column} for i, column in enumerate(columns, 1)],
            "row_count": len(rows), "rows": rows}


def normalize(raw: bytes, *, input_format: str) -> dict:
    try:
        if not isinstance(input_format, str) or input_format not in INPUT_FORMATS:
            raise ProvenanceError("unsupported lossless query input format")
        source = document(raw)
        optional = {"permissions"} if input_format == "resource-tables" else set()
        if not isinstance(source, dict) or set(source) - {"tables", "error", "statistics", "render"} - optional:
            raise ProvenanceError("unsupported lossless query response envelope")
        if "permissions" in source and not isinstance(source["permissions"], dict):
            raise ProvenanceError("invalid resource permission observation")
        partial = _partial_error(source)
        tables, row_count, cell_count = _tables(source, column_types=COLUMN_TYPES)
        keys = ("error", "statistics", "render") + (("permissions",) if optional else ())
        result = {
            "schema": "ai-dfir/log-analytics-lossless-projection/v1.7",
            "transformation": TRANSFORMATION, "transformation_version": TRANSFORMATION_VERSION,
            "input_format": input_format, "source_sha256": sha256_bytes(raw), "token_digest_encoding": TOKEN_ENCODING,
            "table_count": len(tables), "row_count": row_count, "cell_count": cell_count,
            "tables": [_table(table, i) for i, table in enumerate(tables, 1)], "input_order_preserved": True,
            "response_digests": {key: {"state": "absent" if key not in source else "null" if source[key] is None else "present",
                                      "token_tree_sha256": token_digest(source[key]) if key in source else None} for key in keys},
            "partial_error_recorded": partial, "response_state": "PARTIAL" if partial else "NO_ERROR_RECORDED",
            "collection_complete": False if partial else None, "request_scope_verified": False,
            "source_authenticity_verified": False, "permissions_verified": False,
            "network_required": False, "query_reexecuted": False, "numeric_text_preserved": True,
            "content_policy": "numeric_text_and_typed_scalars_with_token_tree_hashes",
            "interpretation": "Exact numeric-text projection of retained query results only; no query execution, verified scope, provider origin, human attribution, underlying event count, or complete collection is established.",
        }
        if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
            raise ProvenanceError("lossless query projection exceeds byte limit")
        _bounded(result)
        return result
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise ProvenanceError("invalid, excessive, or unsupported lossless query input") from None


def compare_replay(raw: bytes, preserved: bytes, *, input_format: str) -> dict:
    replayed = normalize(raw, input_format=input_format)
    recorded = _document(preserved, MAX_OUTPUT_BYTES)
    actual, expected = sha256_object(recorded), sha256_object(replayed)
    return {"status": "PASS" if actual == expected else "FAIL", "comparison_basis": "RFC8785-JSON",
            "recorded_output_sha256": actual, "replayed_output_sha256": expected,
            **{key: replayed[key] for key in ("source_sha256", "table_count", "row_count", "response_state",
                "partial_error_recorded", "collection_complete", "request_scope_verified", "source_authenticity_verified",
                "permissions_verified", "network_required", "query_reexecuted", "numeric_text_preserved", "token_digest_encoding")}}

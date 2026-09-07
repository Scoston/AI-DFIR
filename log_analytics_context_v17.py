#!/usr/bin/env python3
"""Bind a retained Log Analytics context artifact or compare its projection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics import read_document
from v17_log_analytics_context import INPUT_FORMATS, MAX_CONTEXT_BYTES, MAX_OUTPUT_BYTES, compare_replay, normalize


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Retained native query response JSON")
    parser.add_argument("--context", required=True, help="Retained POST/GET query context JSON with exact response digest")
    parser.add_argument("--format", required=True, choices=INPUT_FORMATS)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--out", help="New projection file; existing files are preserved")
    output.add_argument("--compare", help="Previously recorded projection JSON")
    args = parser.parse_args()
    try:
        raw = read_document(args.input)
        context = read_document(args.context, limit=MAX_CONTEXT_BYTES)
        if args.out is not None:
            result = normalize(raw, context_raw=context, input_format=args.format)
            encoded = canonical_json_bytes(result)
            with Path(args.out).open("xb") as stream:
                stream.write(encoded)
            report = {"status": "NORMALIZED", "output_sha256": sha256_bytes(encoded),
                      **{key: result[key] for key in ("source_sha256", "context_sha256", "binding_sha256",
                          "request_context_bound", "request_scope_verified", "query_execution_verified",
                          "source_authenticity_verified", "network_required", "query_reexecuted", "collection_complete")},
                      **{key: result["result"][key] for key in ("row_count", "response_state", "partial_error_recorded")}}
        else:
            report = compare_replay(raw, read_document(args.compare, limit=MAX_OUTPUT_BYTES),
                                    context_raw=context, input_format=args.format)
        print(json.dumps(report, sort_keys=True))
        return 1 if report["status"] == "FAIL" else 0
    except (ValueError, TypeError, OSError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid, unavailable, excessive, or conflicting query context input/output",
                          "network_required": False, "query_reexecuted": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

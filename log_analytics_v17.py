#!/usr/bin/env python3
"""Project retained Log Analytics results or compare a preserved projection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from v17_log_analytics import INPUT_FORMATS, MAX_OUTPUT_BYTES, compare_replay, normalize, read_document
from v17_integrity import canonical_json_bytes, sha256_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Retained native UTF-8 JSON query response")
    parser.add_argument("--format", required=True, choices=INPUT_FORMATS)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--out", help="New projection file; existing files are preserved")
    output.add_argument("--compare", help="Previously recorded projection JSON")
    args = parser.parse_args()
    try:
        raw = read_document(args.input)
        if args.out is not None:
            result = normalize(raw, input_format=args.format)
            encoded = canonical_json_bytes(result)
            with Path(args.out).open("xb") as stream:
                stream.write(encoded)
            report = {"status": "NORMALIZED", "source_sha256": result["source_sha256"],
                      "output_sha256": sha256_bytes(encoded), "table_count": result["table_count"],
                      "row_count": result["row_count"], "partial_error_recorded": result["partial_error_recorded"],
                      "response_state": result["response_state"], "collection_complete": result["collection_complete"],
                      "request_scope_verified": False, "source_authenticity_verified": False,
                      "network_required": False, "query_reexecuted": False}
        else:
            report = compare_replay(raw, read_document(args.compare, limit=MAX_OUTPUT_BYTES), input_format=args.format)
        print(json.dumps(report, sort_keys=True))
        return 1 if report["status"] == "FAIL" else 0
    except (ValueError, TypeError, OSError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid, unavailable, excessive, or conflicting query input/output",
                          "network_required": False, "query_reexecuted": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

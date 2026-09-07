#!/usr/bin/env python3
"""Reassess retained evidence under pinned rules, or compare a recorded result."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from v17_evidence_validation import MAX_OUTPUT_BYTES, MAX_RULES_BYTES, assess, compare_replay, read_evidence
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics import read_document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--expected-rules-sha256", required=True, help="Independent canonical digest of the retained rules")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--out", help="New assessment file; existing files are preserved")
    target.add_argument("--compare", help="Preserved assessment to reproduce")
    args = parser.parse_args()
    try:
        raw = read_evidence(args.input)
        rules = read_document(args.rules, limit=MAX_RULES_BYTES)
        options = {"rules_raw": rules, "case_id": args.case, "expected_rules_sha256": args.expected_rules_sha256}
        if args.out is not None:
            result = assess(raw, **options); encoded = canonical_json_bytes(result)
            with Path(args.out).open("xb") as stream: stream.write(encoded)
            report = {"status": "ASSESSED", "output_sha256": sha256_bytes(encoded),
                      **{key: result[key] for key in ("source_sha256", "rules_sha256", "validation_status", "record_count",
                          "observed_schema_sha256", "raw_evidence_reassessed", "quality_rating_changed", "rules_approval_verified",
                          "source_authenticity_verified", "collection_complete", "closure_authorized", "network_required")}}
            code = 0 if result["validation_status"] == "SATISFIED" else 2
        else:
            report = compare_replay(raw, read_document(args.compare, limit=MAX_OUTPUT_BYTES), **options)
            code = 0 if report["status"] == "PASS" else 1
        print(json.dumps(report, sort_keys=True)); return code
    except (ValueError, TypeError, OSError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid, unavailable, excessive, or conflicting evidence/rules input/output",
                          "network_required": False, "quality_rating_changed": False, "closure_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

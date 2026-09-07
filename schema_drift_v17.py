#!/usr/bin/env python3
"""Compare nested retained JSON shapes or replay a pinned baseline comparison."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from v17_evidence_validation import read_evidence
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics import read_document
from v17_schema_drift import INPUT_FORMATS, MAX_OUTPUT_BYTES, compare, compare_replay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True); parser.add_argument("--baseline", required=True)
    parser.add_argument("--expected-baseline-sha256", required=True); parser.add_argument("--case", required=True)
    parser.add_argument("--format", choices=INPUT_FORMATS, required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--out"); output.add_argument("--compare")
    args = parser.parse_args()
    try:
        raw = read_evidence(args.input); baseline = read_evidence(args.baseline)
        options = {"baseline_raw": baseline, "expected_baseline_sha256": args.expected_baseline_sha256,
                   "input_format": args.format, "case_id": args.case}
        if args.compare is not None:
            report = compare_replay(raw, read_document(args.compare, limit=MAX_OUTPUT_BYTES), **options)
            code = 0 if report["status"] == "PASS" else 1
        else:
            result = compare(raw, **options); encoded = canonical_json_bytes(result)
            descriptor = os.open(Path(args.out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
            report = {"status": "COMPARED", "output_sha256": sha256_bytes(encoded),
                      **{key: result[key] for key in ("source_sha256", "baseline_sha256", "drift_status", "observed_shape_changed",
                          "bytes_changed", "population_counts_changed", "provider_schema_change_proven", "collection_complete", "network_required")}}
            code = 2 if result["observed_shape_changed"] else 0
        print(json.dumps(report, sort_keys=True)); return code
    except KeyboardInterrupt:
        print(json.dumps({"status": "INTERRUPTED", "network_required": False})); return 130
    except (ValueError, TypeError, OSError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid, unavailable, excessive, or conflicting structural comparison input/output", "network_required": False})); return 1


if __name__ == "__main__":
    raise SystemExit(main())

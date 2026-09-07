#!/usr/bin/env python3
"""Export or compare a CASE/UCO inventory view of a verified signed case."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from v17_case_exchange import MAX_OUTPUT_BYTES, compare_exchange, export_exchange, read_archive
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_key_policy import add_key_policy_arguments, key_policy_options
from v17_key_trust_history import add_key_trust_history_arguments, key_trust_history_options
from v17_log_analytics import read_document
from v17_timestamp import add_timestamp_arguments, timestamp_options


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", required=True)
    parser.add_argument("--export-public-key", required=True)
    parser.add_argument("--tenant", required=True); parser.add_argument("--case", required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--out"); output.add_argument("--compare")
    add_key_policy_arguments(parser); add_timestamp_arguments(parser); add_key_trust_history_arguments(parser)
    args = parser.parse_args()
    try:
        raw = read_archive(args.zip)
        options = {"expected_tenant": args.tenant, "expected_case": args.case,
                   **key_policy_options(args), **timestamp_options(args), **key_trust_history_options(args)}
        if args.compare is not None:
            report = compare_exchange(raw, read_document(args.compare, limit=MAX_OUTPUT_BYTES),
                                      args.export_public_key, **options)
            code = 0 if report["status"] == "PASS" else 1
        else:
            graph = export_exchange(raw, args.export_public_key, **options)
            encoded = canonical_json_bytes(graph)
            fd = os.open(Path(args.out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
            report = {"status": "EXPORTED", "source_sha256": sha256_bytes(raw),
                      "output_sha256": sha256_bytes(encoded), "graph_nodes": len(graph["@graph"]),
                      "network_required": False, "source_authenticity_verified": False,
                      "graph_signature_present": False, "closure_authorized": False}
            code = 0
        print(json.dumps(report, sort_keys=True)); return code
    except KeyboardInterrupt:
        print(json.dumps({"status": "INTERRUPTED", "network_required": False})); return 130
    except (ValueError, TypeError, KeyError, OSError, OverflowError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid, unavailable, excessive, or conflicting case exchange input/output", "network_required": False})); return 1


if __name__ == "__main__":
    raise SystemExit(main())

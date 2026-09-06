#!/usr/bin/env python3
"""Capture or compare retained Evidence Pack gate inputs without acquiring evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from v17_integrity import canonical_json_bytes, sha256_object
from v17_pack_replay import MAX_ASSESSMENT_BYTES, MAX_INPUT_BYTES, compare_pack_replay, load_replay_document, prepare_replay_input


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--pack", required=True, help="Exact retained Evidence Pack JSON")
    prepare.add_argument("--out", required=True, help="New replay input file; existing files are preserved")
    verify = commands.add_parser("verify")
    verify.add_argument("--input", required=True)
    verify.add_argument("--expected-pack-sha256", required=True)
    for command in (prepare, verify):
        command.add_argument("--assessment", required=True, help="Retained assessment, not a new acquisition")
        command.add_argument("--case", required=True)
    args = parser.parse_args()
    try:
        assessment = load_replay_document(args.assessment, limit=MAX_ASSESSMENT_BYTES)
        if args.command == "prepare":
            pack = load_replay_document(args.pack, limit=MAX_INPUT_BYTES)
            value = prepare_replay_input(pack, assessment, case_id=args.case)
            with Path(args.out).open("xb") as stream:
                stream.write(canonical_json_bytes(value))
            result = {"status": "PREPARED", "input_sha256": sha256_object(value), "pack_sha256": value["pack_sha256"],
                      "recorded_gate_result_verified": False, "network_required": False}
        else:
            value = load_replay_document(args.input, limit=MAX_INPUT_BYTES)
            result = compare_pack_replay(value, assessment, case_id=args.case, expected_pack_sha256=args.expected_pack_sha256)
        print(json.dumps(result, sort_keys=True))
        return 1 if result["status"] == "FAIL" else 0
    except (ValueError, TypeError, OSError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid, unavailable, or conflicting replay inputs/output destination", "network_required": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

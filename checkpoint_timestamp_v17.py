#!/usr/bin/env python3
"""Prepare a checkpoint timestamp request or verify an external receipt offline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from case_export_v17 import _parse_signed_checkpoint
from v17_integrity import sha256_bytes
from v17_reconstruction import strict_json
from v17_timestamp import (
    RESULT_SCHEMA, add_timestamp_arguments, checkpoint_timestamp_statement,
    evaluate_checkpoint_timestamp, prepare_timestamp_request, read_timestamp_file, timestamp_options,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="Create a local request; no network submission")
    verify = sub.add_parser("verify", help="Authenticate a retained response using independent TSA trust")
    for command in (prepare, verify):
        command.add_argument("--signed-checkpoint", required=True)
        command.add_argument("--tenant", required=True)
        command.add_argument("--case", required=True)
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--tsa-policy-oid")
    add_timestamp_arguments(verify)
    args = parser.parse_args()
    try:
        signed = _parse_signed_checkpoint(strict_json(read_timestamp_file(args.signed_checkpoint, 16384)))
        identity = dict(signed_checkpoint=signed, tenant_id=args.tenant, case_id=args.case)
        if args.command == "prepare":
            request = prepare_timestamp_request(**identity, tsa_policy_oid=args.tsa_policy_oid)
            # Never silently replace a retained nonce-bearing request.
            with Path(args.out).open("xb") as stream:
                stream.write(request)
            result = {"schema": RESULT_SCHEMA, "status": "PREPARED", "network_performed": False,
                      "request": args.out, "request_sha256": sha256_bytes(request),
                      "statement_sha256": sha256_bytes(checkpoint_timestamp_statement(**identity))}
        else:
            options = timestamp_options(args)
            options["require_checkpoint_timestamp"] = True
            result = evaluate_checkpoint_timestamp(**identity, **options)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if result["status"] == "FAIL" else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({"schema": RESULT_SCHEMA, "status": "ERROR", "network_performed": False,
                          "error": f"{type(exc).__name__}: {exc}"}, indent=2, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

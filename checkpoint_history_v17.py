#!/usr/bin/env python3
"""Capture key-trust decisions, prepare timestamps, and verify retained history offline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_key_trust_history import (
    _signed, capture_key_trust_record, evaluate_key_trust_history, load_key_trust_record, prepare_key_trust_request,
)
from v17_policy_distribution import PolicyUpdateError, load_policy_document
from v17_policy_governance import load_root
from v17_timestamp import MAX_CA_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, read_timestamp_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture", help="Record a current authenticated policy decision without mutating its store")
    capture.add_argument("--store", required=True)
    capture.add_argument("--minimum-policy-revision", type=int)
    capture.add_argument("--minimum-root-version", type=int)
    prepare = sub.add_parser("prepare", help="Prepare a nonce-bearing request on a verified record; no submission")
    prepare.add_argument("--tsa-policy-oid")
    verify = sub.add_parser("verify", help="Authenticate a timestamp and reproduce the record's historical trust decision")
    for command in (capture, prepare, verify):
        command.add_argument("--anchor", required=True)
    for command in (capture, verify):
        command.add_argument("--signed-checkpoint", required=True)
        command.add_argument("--tenant", required=True)
        command.add_argument("--case", required=True)
    for command in (prepare, verify):
        command.add_argument("--record", required=True)
    for command in (capture, prepare):
        command.add_argument("--out", required=True)
    verify.add_argument("--timestamp-request", required=True)
    verify.add_argument("--timestamp-response", required=True)
    verify.add_argument("--tsa-ca-file", required=True)
    verify.add_argument("--expected-tsa-certificate-sha256", required=True)
    verify.add_argument("--expected-timestamp-request-sha256")
    verify.add_argument("--expected-record-sha256")
    args = parser.parse_args()
    try:
        anchor = load_root(args.anchor)
        if args.command == "capture":
            signed = _signed(load_policy_document(args.signed_checkpoint, limit=16 * 1024))
            record = capture_key_trust_record(args.store, anchor, signed_checkpoint=signed, tenant_id=args.tenant, case_id=args.case,
                                              minimum_revision=args.minimum_policy_revision, minimum_root_version=args.minimum_root_version)
            with Path(args.out).open("xb") as stream:
                stream.write(canonical_json_bytes(record))
            result = {"status": "CAPTURED", "record_sha256": sha256_object(record), "decision": record["decision"],
                      "timestamp_attested": False, "out": args.out}
        elif args.command == "prepare":
            record = load_key_trust_record(args.record)
            request = prepare_key_trust_request(record, anchor, tsa_policy_oid=args.tsa_policy_oid)
            with Path(args.out).open("xb") as stream:
                stream.write(request)
            result = {"status": "PREPARED", "request_sha256": sha256_bytes(request), "record_sha256": sha256_object(record),
                      "timestamp_attested": False, "out": args.out}
        else:
            result = evaluate_key_trust_history(record=load_key_trust_record(args.record), root_anchor=anchor,
                signed_checkpoint=_signed(load_policy_document(args.signed_checkpoint, limit=16 * 1024)), tenant_id=args.tenant, case_id=args.case,
                timestamp_request=read_timestamp_file(args.timestamp_request, MAX_REQUEST_BYTES),
                timestamp_response=read_timestamp_file(args.timestamp_response, MAX_RESPONSE_BYTES),
                tsa_ca_pem=read_timestamp_file(args.tsa_ca_file, MAX_CA_BYTES), expected_tsa_certificate_sha256=args.expected_tsa_certificate_sha256,
                expected_timestamp_request_sha256=args.expected_timestamp_request_sha256, expected_record_sha256=args.expected_record_sha256)
        print(json.dumps(dict(result, network_performed=False), indent=2, sort_keys=True))
        return 1 if result["status"] == "FAIL" or (args.command == "verify" and not result["historical_key_trusted"]) else 0
    except PolicyUpdateError as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code, "error": str(exc), "network_performed": False}))
        return 1
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc), "network_performed": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

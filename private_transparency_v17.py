#!/usr/bin/env python3
"""Create private log snapshots, approve heads, and verify evidence inclusion offline."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from v17_delivery_identity import _KEY, _password, _read
from v17_evidence_validation import read_evidence
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import _document
from v17_log_analytics_capture import _publish_receipt, _write_new
from v17_private_transparency import (
    MAX_HEAD_BYTES, MAX_RECEIPT_BYTES, MAX_STATE_BYTES, MAX_TRUST_BYTES,
    append, cosign_head, entry, initialize, make_receipt, validate_trust, verify_head, verify_receipt,
)


def _json(path, limit):
    return _document(_read(path, limit), limit)


def _key(args):
    raw = _read(args.private_key, 16384, secret=True)
    if _KEY.fullmatch(raw.strip()) is None:
        raise ValueError("one protected PKCS8 private key is required")
    return serialization.load_pem_private_key(raw, password=_password(args.key_password_file))


def _write(path, value):
    descriptor = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical_json_bytes(value)); stream.flush(); os.fsync(stream.fileno())


def _write_snapshot(folder, state, head, threshold):
    directory = Path(folder); directory.mkdir(mode=0o700)
    files = [_write_new(directory, "state.json", canonical_json_bytes(state)),
             _write_new(directory, "head.json", canonical_json_bytes(head))]
    report = {"schema": "ai-dfir/private-log-snapshot-publication/v1.7", "status": "WRITTEN",
              "files": files, "tree_size": head["tree_size"], "head_sha256": sha256_object(head),
              "required_witnesses": threshold, "witness_signatures": len(head["witness_signatures"]),
              "witness_quorum_satisfied": len(head["witness_signatures"]) >= threshold,
              "network_performed": False, "inclusion_receipt_issued": False}
    _publish_receipt(directory, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create a new empty log snapshot and draft signed head")
    add = sub.add_parser("append", help="Check a retained head and write a new snapshot with one appended digest")
    cosign = sub.add_parser("cosign", help="Witness a candidate head after checking state and an independent prior head")
    proof = sub.add_parser("proof", help="Create a verified inclusion receipt from a fully approved head")
    verify = sub.add_parser("verify", help="Verify inclusion and optional prefix consistency under independent trust")
    check = sub.add_parser("check-head", help="Verify the log signature and configured witness quorum")
    for cmd in (init, add, cosign, proof, verify, check):
        cmd.add_argument("--trust", required=True); cmd.add_argument("--expected-trust-sha256", required=True)
    for cmd in (init, add, cosign):
        cmd.add_argument("--private-key", required=True); cmd.add_argument("--key-password-file")
    for cmd in (init, add):
        cmd.add_argument("--issued-at", required=True); cmd.add_argument("--out-dir", required=True)
    for cmd in (add, verify):
        cmd.add_argument("--subject", required=True); cmd.add_argument("--case", required=True)
    add.add_argument("--state", required=True); add.add_argument("--previous-head", required=True)
    cosign.add_argument("--head", required=True); cosign.add_argument("--state"); cosign.add_argument("--previous-head"); cosign.add_argument("--out", required=True)
    proof.add_argument("--state", required=True); proof.add_argument("--head", required=True)
    proof.add_argument("--index", type=int, required=True); proof.add_argument("--previous-head"); proof.add_argument("--out", required=True)
    verify.add_argument("--receipt", required=True); verify.add_argument("--previous-head")
    check.add_argument("--head", required=True)
    args = parser.parse_args()
    try:
        pin = args.expected_trust_sha256
        trust = validate_trust(_json(args.trust, MAX_TRUST_BYTES), expected_trust_sha256=pin)
        options = {"expected_trust_sha256": pin}
        if args.command == "init":
            state, head = initialize(trust, _key(args), issued_at=args.issued_at, **options)
            report = _write_snapshot(args.out_dir, state, head, trust["witness_threshold"])
        elif args.command == "append":
            raw = read_evidence(args.subject)
            state, head = append(_json(args.state, MAX_STATE_BYTES), _json(args.previous_head, MAX_HEAD_BYTES),
                                 entry(args.case, sha256_bytes(raw), len(raw)), _key(args), trust, issued_at=args.issued_at, **options)
            report = _write_snapshot(args.out_dir, state, head, trust["witness_threshold"])
        elif args.command == "cosign":
            state = _json(args.state, MAX_STATE_BYTES) if args.state is not None else None
            previous = _json(args.previous_head, MAX_HEAD_BYTES) if args.previous_head is not None else None
            head = cosign_head(_json(args.head, MAX_HEAD_BYTES), _key(args), trust, state=state, previous_head=previous, **options)
            _write(args.out, head)
            report = {"status": "SIGNED", "head_sha256": sha256_object(head), "witness_signatures": len(head["witness_signatures"]),
                      "required_witnesses": trust["witness_threshold"], "witness_quorum_satisfied": len(head["witness_signatures"]) >= trust["witness_threshold"]}
        elif args.command == "proof":
            previous = _json(args.previous_head, MAX_HEAD_BYTES) if args.previous_head is not None else None
            receipt = make_receipt(_json(args.state, MAX_STATE_BYTES), _json(args.head, MAX_HEAD_BYTES), args.index, trust, previous_head=previous, **options)
            _write(args.out, receipt)
            report = {"status": "PROVED", "receipt_sha256": sha256_object(receipt), "tree_size": receipt["head"]["tree_size"],
                      "inclusion_proof_verified": True, "prefix_consistency_verified": previous is not None}
        elif args.command == "verify":
            previous = _json(args.previous_head, MAX_HEAD_BYTES) if args.previous_head is not None else None
            raw = read_evidence(args.subject)
            report = verify_receipt(_json(args.receipt, MAX_RECEIPT_BYTES), trust, expected_case_id=args.case,
                                    expected_subject_sha256=sha256_bytes(raw), expected_subject_size_bytes=len(raw), previous_head=previous, **options)
        else:
            head = verify_head(_json(args.head, MAX_HEAD_BYTES), trust, **options)
            report = {"status": "PASS", "head_sha256": sha256_object(head), "tree_size": head["tree_size"], "witness_quorum_satisfied": True}
        print(json.dumps(dict(report, network_performed=False), sort_keys=True))
        return 2 if report.get("witness_quorum_satisfied") is False else 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "INTERRUPTED", "network_performed": False})); return 130
    except (ValueError, TypeError, OSError, KeyError, RecursionError, UnsupportedAlgorithm):
        print(json.dumps({"status": "FAIL", "error": "invalid, untrusted, excessive, or conflicting private-log input/output", "network_performed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

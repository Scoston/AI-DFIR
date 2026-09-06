#!/usr/bin/env python3
"""Sign, accept, and inspect checkpoint key-policy updates without network I/O."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from v17_key_policy import load_key_policy
from v17_policy_distribution import (
    ISSUER_TRUST_SCHEMA, PolicyUpdateError, accept_policy_update, load_issuer_trust,
    load_policy_document, load_policy_store, sign_key_policy, validate_issuer_trust,
)
from v17_signing import key_id_from_public_key_bytes, public_key_bytes
from v17_policy_quorum import QUORUM_TRUST_SCHEMA, cosign_quorum_policy, sign_quorum_policy


def _key_bytes(path: str) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(16385)
    if not 0 < len(raw) <= 16384:
        raise ValueError("key file is empty or oversized")
    return raw


def _write_new(path: str, value: dict) -> None:
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    trust = sub.add_parser("trust", help="Build issuer trust from independently approved public keys")
    trust.add_argument("--issuer-public-key", action="append", required=True)
    trust.add_argument("--tenant", required=True)
    trust.add_argument("--policy-id", required=True)
    trust.add_argument("--threshold", type=int, help="Require this many distinct issuer signatures; enables quorum trust")
    trust.add_argument("--out", required=True)
    sign = sub.add_parser("sign")
    sign.add_argument("--policy", required=True)
    sign.add_argument("--issuer-private-key", required=True)
    sign.add_argument("--issuer-trust", help="Approved quorum issuer configuration; enables a quorum package")
    sign.add_argument("--out", required=True)
    cosign = sub.add_parser("cosign", help="Verify prior approvals and append one distinct issuer's signature")
    cosign.add_argument("--signed-policy", required=True)
    cosign.add_argument("--issuer-trust", required=True)
    cosign.add_argument("--issuer-private-key", required=True)
    cosign.add_argument("--out", required=True)
    accept = sub.add_parser("accept", help="Authenticate and transactionally accept a newer policy")
    accept.add_argument("--signed-policy", required=True)
    accept.add_argument("--initialize", action="store_true", help="Create a new store; refuse an existing path")
    show = sub.add_parser("show", help="Reauthenticate the currently accepted policy")
    show.add_argument("--minimum-policy-revision", type=int)
    for command in (accept, show):
        command.add_argument("--store", required=True)
        command.add_argument("--issuer-trust", required=True)
    args = parser.parse_args()
    try:
        if args.command == "trust":
            keys = []
            for path in args.issuer_public_key:
                public = serialization.load_pem_public_key(_key_bytes(path))
                if not isinstance(public, Ed25519PublicKey):
                    raise ValueError("Ed25519 issuer public key required")
                raw = public_key_bytes(public)
                keys.append({"key_id": key_id_from_public_key_bytes(raw), "public_key_hex": raw.hex()})
            value = {"schema": ISSUER_TRUST_SCHEMA, "tenant_id": args.tenant, "policy_id": args.policy_id, "keys": keys}
            if args.threshold is not None:
                value.update(schema=QUORUM_TRUST_SCHEMA, threshold=args.threshold)
            value = validate_issuer_trust(value)
            _write_new(args.out, value)
            result = {"status": "WRITTEN", "out": args.out}
        elif args.command in {"sign", "cosign"}:
            key = serialization.load_pem_private_key(_key_bytes(args.issuer_private_key), password=None)
            if args.issuer_trust is not None:
                approved = load_issuer_trust(args.issuer_trust)
                if args.command == "cosign":
                    value = cosign_quorum_policy(load_policy_document(args.signed_policy), key, approved)
                else:
                    value = sign_quorum_policy(load_key_policy(args.policy), key, approved)
                count, required = len(value["signatures"]), approved["threshold"]
                result = {"status": "SIGNED" if count >= required else "PARTIALLY_SIGNED",
                          "out": args.out, "signatures": count, "required_signatures": required,
                          "acceptance_performed": False}
            else:
                value = sign_key_policy(load_key_policy(args.policy), key)
                result = {"status": "SIGNED", "out": args.out, "issuer_key_id": value["issuer_key_id"]}
            _write_new(args.out, value)
        elif args.command == "accept":
            result = accept_policy_update(args.store, load_policy_document(args.signed_policy),
                                           load_issuer_trust(args.issuer_trust), initialize=args.initialize)
        else:
            result = load_policy_store(args.store, load_issuer_trust(args.issuer_trust),
                                       minimum_revision=args.minimum_policy_revision)
            result = {"status": "PASS", "policy": result["policy"], "authentication": result["authentication"]}
        print(json.dumps(dict(result, network_performed=False), indent=2, sort_keys=True))
        return 0
    except PolicyUpdateError as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code, "error": str(exc), "network_performed": False}))
        return 1
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc), "network_performed": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

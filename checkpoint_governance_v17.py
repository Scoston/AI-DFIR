#!/usr/bin/env python3
"""Prepare signed issuer-root rotations and activate them with approved policies offline."""
from __future__ import annotations

import argparse
import json

from cryptography.hazmat.primitives import serialization

from checkpoint_policy_v17 import _key_bytes, _write_new
from v17_policy_distribution import PolicyUpdateError, load_issuer_trust, load_policy_document
from v17_policy_governance import (
    MAX_ROTATION_BYTES, ROOT_SCHEMA, ROLES, accept_governed_update, cosign_root_rotation,
    initialize_governed_store, inspect_governed_root, load_governed_store, load_root,
    migrate_governed_store, sign_root_rotation, validate_root, validate_rotation,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    root = sub.add_parser("root", help="Format an independently approved root configuration")
    root.add_argument("--issuer-trust", required=True)
    root.add_argument("--version", type=int, required=True)
    root.add_argument("--issued-at", required=True)
    root.add_argument("--expires-at", required=True)
    root.add_argument("--out", required=True)
    sign = sub.add_parser("sign", help="Start a rotation approval for one role")
    sign.add_argument("--next-root", required=True)
    cosign = sub.add_parser("cosign", help="Check collected approvals and append one role signature")
    cosign.add_argument("--rotation", required=True)
    for command in (sign, cosign):
        command.add_argument("--previous-root", required=True)
        command.add_argument("--role", choices=ROLES, required=True)
        command.add_argument("--issuer-private-key", required=True)
        command.add_argument("--out", required=True)
    initialize = sub.add_parser("initialize", help="Create a new governed store; never overwrite")
    migrate = sub.add_parser("migrate", help="Explicitly upgrade an existing quorum store without resetting revision")
    accept = sub.add_parser("accept", help="Atomically accept a policy and optional signed root rotation")
    accept.add_argument("--rotation")
    for command in (initialize, accept):
        command.add_argument("--signed-policy", required=True)
    show = sub.add_parser("show", help="Verify the current root, policy, and stored revision")
    show.add_argument("--minimum-policy-revision", type=int)
    show.add_argument("--minimum-root-version", type=int)
    export = sub.add_parser("export-root", help="Authenticate and export the current root for rotation, including expiry recovery")
    export.add_argument("--out", required=True)
    for command in (initialize, migrate, accept, show, export):
        command.add_argument("--store", required=True)
        command.add_argument("--anchor", required=True)
    args = parser.parse_args()
    try:
        if args.command == "root":
            value = validate_root({"schema": ROOT_SCHEMA, "version": args.version, "issued_at": args.issued_at,
                                   "expires_at": args.expires_at, "issuer_trust": load_issuer_trust(args.issuer_trust)})
            _write_new(args.out, value)
            result = {"status": "WRITTEN", "out": args.out, "independent_approval_required": True}
        elif args.command in {"sign", "cosign"}:
            previous = load_root(args.previous_root)
            key = serialization.load_pem_private_key(_key_bytes(args.issuer_private_key), password=None)
            if args.command == "sign":
                value = sign_root_rotation(previous, load_root(args.next_root), key, args.role)
            else:
                candidate = load_policy_document(args.rotation, limit=MAX_ROTATION_BYTES)
                value = cosign_root_rotation(previous, candidate, key, args.role)
            counts = {role: len(value["signatures"][role]) for role in ROLES}
            thresholds = {"previous": previous["issuer_trust"]["threshold"], "replacement": value["root"]["issuer_trust"]["threshold"]}
            complete = all(counts[role] >= thresholds[role] for role in ROLES)
            _write_new(args.out, value)
            result = {"status": "SIGNED" if complete else "PARTIALLY_SIGNED", "out": args.out,
                      "signatures": counts, "required_signatures": thresholds, "acceptance_performed": False}
        else:
            anchor = load_root(args.anchor)
            if args.command == "initialize":
                result = initialize_governed_store(args.store, anchor, load_policy_document(args.signed_policy))
            elif args.command == "migrate":
                result = migrate_governed_store(args.store, anchor)
            elif args.command == "accept":
                rotation = validate_rotation(load_policy_document(args.rotation, limit=MAX_ROTATION_BYTES)) if args.rotation is not None else None
                result = accept_governed_update(args.store, anchor, load_policy_document(args.signed_policy), rotation=rotation)
            elif args.command == "export-root":
                result = inspect_governed_root(args.store, anchor)
                _write_new(args.out, result["root"])
                result = dict(result, out=args.out)
            else:
                result = load_governed_store(args.store, anchor, minimum_revision=args.minimum_policy_revision,
                                             minimum_root_version=args.minimum_root_version)
                result = {"status": "PASS", "root": result["root"], "policy": result["policy"], "authentication": result["authentication"]}
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

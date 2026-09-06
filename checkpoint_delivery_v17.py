#!/usr/bin/env python3
"""Prepare signed update bundles or explicitly synchronize a governed store over HTTPS."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from v17_integrity import canonical_json_bytes, sha256_object
from v17_policy_delivery import DEFAULT_TIMEOUT, PolicyDeliveryError, prepare_delivery_bundle, sync_policy
from v17_policy_distribution import PolicyUpdateError, load_policy_document
from v17_policy_governance import MAX_ROTATIONS, MAX_ROTATION_BYTES, load_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    bundle = sub.add_parser("bundle", help="Check and assemble a complete signed chain and final policy for a publisher")
    bundle.add_argument("--signed-policy", required=True)
    bundle.add_argument("--rotation", action="append", default=[], help="Repeat in order, starting at the independent anchor")
    bundle.add_argument("--out", required=True)
    sync = sub.add_parser("sync", help="Fetch one HTTPS bundle and atomically activate it in an existing governed store")
    sync.add_argument("--store", required=True)
    sync.add_argument("--url", required=True, help="Operator-approved HTTPS endpoint; no query, credentials, or redirects")
    sync.add_argument("--ca-file", help="Operator-provisioned PEM CA bundle; defaults to system TLS trust")
    sync.add_argument("--client-cert-file", help="Explicit PEM certificate chain for TLS client authentication")
    sync.add_argument("--client-key-file", help="Protected PKCS8 PEM private key matching the client certificate")
    sync.add_argument("--client-key-password-file", help="Protected single-line password file for an encrypted PKCS8 key")
    sync.add_argument("--expected-client-certificate-sha256", help="Independent SHA-256 pin of the client leaf certificate DER")
    sync.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    sync.add_argument("--minimum-policy-revision", type=int)
    sync.add_argument("--minimum-root-version", type=int)
    for command in (bundle, sync):
        command.add_argument("--anchor", required=True)
    args = parser.parse_args()
    try:
        anchor = load_root(args.anchor)
        if args.command == "bundle":
            if len(args.rotation) > MAX_ROTATIONS:
                raise PolicyUpdateError("root_chain_invalid", "too many rotation files")
            rotations = [load_policy_document(path, limit=MAX_ROTATION_BYTES) for path in args.rotation]
            value = prepare_delivery_bundle(anchor, load_policy_document(args.signed_policy), rotations)
            with Path(args.out).open("xb") as stream:
                stream.write(canonical_json_bytes(value))
            result = {"status": "WRITTEN", "out": args.out, "bundle_sha256": sha256_object(value),
                      "acceptance_performed": False, "network_performed": False}
        else:
            result = sync_policy(args.store, anchor, args.url, ca_file=args.ca_file, timeout=args.timeout,
                                 minimum_revision=args.minimum_policy_revision, minimum_root_version=args.minimum_root_version,
                                 client_cert_file=args.client_cert_file, client_key_file=args.client_key_file,
                                 client_key_password_file=args.client_key_password_file,
                                 expected_client_certificate_sha256=args.expected_client_certificate_sha256)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except PolicyDeliveryError as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code, "error": str(exc), "network_attempted": exc.network_attempted}))
        return 1
    except PolicyUpdateError as exc:
        print(json.dumps({"status": "FAIL", "code": exc.code, "error": str(exc), "network_attempted": False}))
        return 1
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc), "network_attempted": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

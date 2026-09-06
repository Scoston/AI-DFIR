#!/usr/bin/env python3
"""Synthetic acceptance test: key rotation, revocation, and offline replay."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_integrity import sha256_object
from v17_key_policy import KEY_POLICY_SCHEMA
from v17_provenance_selftest import CASE_ID, TENANT_ID, sign_fixture, synthetic_case

EVALUATED_AT = "2026-09-06T00:01:00Z"


def synthetic_policy(signed):
    """Public synthetic policy; signing keys are generated only in temporary storage."""
    return {
        "schema": KEY_POLICY_SCHEMA, "policy_id": "synthetic-checkpoint-policy",
        "revision": 1, "tenant_id": TENANT_ID, "case_ids": [CASE_ID],
        "issued_at": "2026-09-06T00:00:40Z", "expires_at": "2026-10-01T00:00:00Z",
        "keys": [{
            "key_id": signed.key_id, "public_key_hex": signed.public_key_hex,
            "signature_algorithm": "Ed25519", "state": "active",
            "not_before": "2026-09-01T00:00:00Z", "not_after": "2026-10-01T00:00:00Z",
            "status_changed_at": None, "reason": None,
        }],
    }


def synthetic_export(root: Path):
    case = root / "case"
    profile, ledger = synthetic_case(case)
    signed, trust = sign_fixture(ledger)
    private, public = root / "export.pem", root / "export.pub.pem"
    generate(private, public)
    policy = synthetic_policy(signed)
    package = root / "case.zip"
    export_case(case, TENANT_ID, CASE_ID, private, package, ledger=ledger,
                signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile,
                checkpoint_key_policy=policy, key_policy_evaluated_at=EVALUATED_AT)
    return {"root": case, "profile": profile, "ledger": ledger, "signed": signed,
            "trust": trust, "private": private, "public": public, "policy": policy, "package": package}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-key-policy-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
            fixture = synthetic_export(Path(temporary))
            policy = fixture["policy"]
            accepted = verify_case(
                fixture["package"], fixture["public"], checkpoint_key_policy=policy,
                key_policy_evaluated_at=EVALUATED_AT, expected_key_policy_sha256=sha256_object(policy),
                include_reconstruction=True, replay_transforms=True,
            )
            assert accepted["valid"] and accepted["checkpoint_key_policy"]["status"] == "PASS"
            assert accepted["reconstruction"]["deterministic_replay"]["status"] == "PASS"
            revoked = copy.deepcopy(policy)
            revoked["revision"] = 2
            revoked["keys"][0].update(state="revoked", status_changed_at="2026-09-06T00:00:30Z",
                                      reason="synthetic compromise exercise")
            denied = verify_case(fixture["package"], fixture["public"], checkpoint_key_policy=revoked,
                                 key_policy_evaluated_at=EVALUATED_AT, include_reconstruction=True)
            assert denied["signature_valid"] and denied["manifest_signer_trusted"]
            assert not denied["valid"] and not denied["signer_trusted"]
            assert "reconstruction" not in denied
            assert not denied["checkpoint_key_policy"]["historical_signing_time_proven"]
    print(json.dumps({"status": "PASS", "offline": True, "valid_signature_revoked_key_rejected": True,
                      "reconstruction_blocked": True, "policy_digest_pinned": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

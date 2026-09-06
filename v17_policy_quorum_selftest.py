#!/usr/bin/env python3
"""Offline acceptance: two issuer keys approve revocation without resetting revision."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import verify_case
from v17_key_policy_selftest import synthetic_export
from v17_policy_distribution import PolicyUpdateError, accept_policy_update, load_policy_store
from v17_policy_distribution_selftest import synthetic_distribution
from v17_policy_quorum import QUORUM_TRUST_SCHEMA, cosign_quorum_policy, sign_quorum_policy, validate_quorum_trust
from v17_signing import key_id_from_public_key_bytes, public_key_bytes


def synthetic_quorum(case: dict, path: Path) -> dict:
    fixture = synthetic_distribution(case, path)
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    approved = []
    for key in keys:
        raw = public_key_bytes(key.public_key())
        approved.append({"key_id": key_id_from_public_key_bytes(raw), "public_key_hex": raw.hex()})
    trust = validate_quorum_trust({"schema": QUORUM_TRUST_SCHEMA, "tenant_id": fixture["policy"]["tenant_id"],
                                   "policy_id": fixture["policy"]["policy_id"], "threshold": 2, "keys": approved})
    partial = sign_quorum_policy(fixture["policy"], keys[0], trust)
    return {"policy": fixture["policy"], "keys": keys, "trust": trust, "path": path,
            "partial": partial, "envelope": cosign_quorum_policy(partial, keys[1], trust)}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-issuer-quorum-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
            case = synthetic_export(root)
            fixture = synthetic_quorum(case, root / "approved-policy.sqlite")
            accept_policy_update(fixture["path"], fixture["envelope"], fixture["trust"], initialize=True)
            options = {"checkpoint_policy_store": fixture["path"], "policy_issuer_trust": fixture["trust"],
                       "require_authenticated_key_policy": True, "include_reconstruction": True}
            accepted = verify_case(case["package"], case["public"], **options)
            assert accepted["valid"], accepted
            auth = accepted["checkpoint_key_policy"]["authentication"]
            assert auth["valid_signatures"] == auth["required_signatures"] == 2
            revoked = copy.deepcopy(fixture["policy"])
            revoked["revision"] = 2
            revoked["keys"][0].update(state="revoked", reason="synthetic quorum revocation",
                                      status_changed_at=revoked["issued_at"])
            partial = sign_quorum_policy(revoked, fixture["keys"][0], fixture["trust"])
            try:
                accept_policy_update(fixture["path"], partial, fixture["trust"])
            except PolicyUpdateError as exc:
                assert exc.code == "policy_quorum_not_met"
            else:
                raise AssertionError("one issuer bypassed two-signature requirement")
            assert load_policy_store(fixture["path"], fixture["trust"])["policy"]["revision"] == 1
            approved = cosign_quorum_policy(partial, fixture["keys"][1], fixture["trust"])
            accept_policy_update(fixture["path"], approved, fixture["trust"])
            denied = verify_case(case["package"], case["public"], **options)
            assert denied["signature_valid"] and not denied["valid"] and "reconstruction" not in denied
    print(json.dumps({"status": "PASS", "offline": True, "two_of_three_issuers": True,
                      "partial_quorum_rejected": True, "revoked_key_reconstruction_blocked": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

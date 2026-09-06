#!/usr/bin/env python3
"""Synthetic acceptance: signed policy update, persistent rollback guard, replay."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import verify_case
from v17_key_policy_selftest import synthetic_export
from v17_policy_distribution import (
    ISSUER_TRUST_SCHEMA, PolicyUpdateError, accept_policy_update, load_policy_store, sign_key_policy,
)
from v17_signing import key_id_from_public_key_bytes, public_key_bytes


def synthetic_distribution(case: dict, path: Path) -> dict:
    now = datetime.now(timezone.utc)
    policy = copy.deepcopy(case["policy"])
    policy.update(issued_at=(now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                  expires_at=(now + timedelta(days=1)).isoformat().replace("+00:00", "Z"))
    policy["keys"][0].update(not_before="2000-01-01T00:00:00Z",
                             not_after=(now + timedelta(days=2)).isoformat().replace("+00:00", "Z"))
    key = Ed25519PrivateKey.generate()
    raw = public_key_bytes(key.public_key())
    trust = {"schema": ISSUER_TRUST_SCHEMA, "tenant_id": policy["tenant_id"], "policy_id": policy["policy_id"],
             "keys": [{"key_id": key_id_from_public_key_bytes(raw), "public_key_hex": raw.hex()}]}
    return {"policy": policy, "key": key, "trust": trust, "path": path,
            "envelope": sign_key_policy(policy, key)}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-policy-updates-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
            case = synthetic_export(root)
            fixture = synthetic_distribution(case, root / "approved-policy.sqlite")
            accept_policy_update(fixture["path"], fixture["envelope"], fixture["trust"], initialize=True)
            options = {"checkpoint_policy_store": fixture["path"], "policy_issuer_trust": fixture["trust"],
                       "require_authenticated_key_policy": True, "include_reconstruction": True}
            accepted = verify_case(case["package"], case["public"], **options)
            assert accepted["valid"], accepted
            assert accepted["checkpoint_key_policy"]["authentication"]["status"] == "PASS"
            revoked = copy.deepcopy(fixture["policy"])
            revoked["revision"] = 2
            revoked["keys"][0].update(state="revoked", reason="synthetic revocation exercise",
                                      status_changed_at=revoked["issued_at"])
            accept_policy_update(fixture["path"], sign_key_policy(revoked, fixture["key"]), fixture["trust"])
            try:
                accept_policy_update(fixture["path"], fixture["envelope"], fixture["trust"])
            except PolicyUpdateError as exc:
                assert exc.code == "policy_revision_rollback"
            else:
                raise AssertionError("old signed policy was accepted")
            assert load_policy_store(fixture["path"], fixture["trust"])["policy"]["revision"] == 2
            denied = verify_case(case["package"], case["public"], **options)
            assert denied["signature_valid"] and not denied["signer_trusted"] and not denied["valid"]
            assert "reconstruction" not in denied
    print(json.dumps({"status": "PASS", "offline": True, "signed_policy_authenticated": True,
                      "persisted_rollback_guard": True, "revoked_key_reconstruction_blocked": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

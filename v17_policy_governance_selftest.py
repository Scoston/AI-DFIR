#!/usr/bin/env python3
"""Synthetic offline acceptance of dual-quorum root rotation and atomic policy state."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import verify_case
from v17_key_policy_selftest import synthetic_export
from v17_policy_distribution import PolicyUpdateError
from v17_policy_governance import (
    ROOT_SCHEMA, accept_governed_update, cosign_root_rotation, initialize_governed_store,
    load_governed_store, sign_root_rotation, validate_root,
)
from v17_policy_quorum import cosign_quorum_policy, sign_quorum_policy
from v17_policy_quorum_selftest import synthetic_quorum


def root_fixture(trust: dict, version: int, *, issued_at=None, expires_at=None) -> dict:
    now = datetime.now(timezone.utc)
    return validate_root({"schema": ROOT_SCHEMA, "version": version, "issuer_trust": trust,
                          "issued_at": issued_at or (now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
                          "expires_at": expires_at or (now + timedelta(days=2)).isoformat().replace("+00:00", "Z")})


def approved_rotation(previous, replacement, previous_keys, replacement_keys):
    value = sign_root_rotation(previous, replacement, previous_keys[0], "previous")
    for key in previous_keys[1:]:
        value = cosign_root_rotation(previous, value, key, "previous")
    for key in replacement_keys:
        value = cosign_root_rotation(previous, value, key, "replacement")
    return value


def approved_policy(policy, keys, trust):
    value = sign_quorum_policy(policy, keys[0], trust)
    for key in keys[1:]:
        value = cosign_quorum_policy(value, key, trust)
    return value


def synthetic_governance(case: dict, path: Path) -> dict:
    first, second = synthetic_quorum(case, path), synthetic_quorum(case, path)
    anchor = root_fixture(first["trust"], 1)
    replacement = root_fixture(second["trust"], 2, issued_at=anchor["issued_at"])
    next_policy = dict(second["policy"], revision=2)
    return {"initial": first, "replacement": second, "anchor": anchor, "root": replacement, "path": path,
            "policy": approved_policy(next_policy, second["keys"][:2], second["trust"]),
            "rotation": approved_rotation(anchor, replacement, first["keys"][:2], second["keys"][:2])}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-root-governance-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
            case = synthetic_export(Path(temporary))
            fixture = synthetic_governance(case, Path(temporary) / "governed.sqlite")
            initialize_governed_store(fixture["path"], fixture["anchor"], fixture["initial"]["envelope"])
            incomplete = copy.deepcopy(fixture["rotation"])
            incomplete["signatures"]["replacement"] = []
            try:
                accept_governed_update(fixture["path"], fixture["anchor"], fixture["policy"], rotation=incomplete)
            except PolicyUpdateError as exc:
                assert exc.code == "root_rotation_quorum_not_met"
            else:
                raise AssertionError("unapproved replacement issuer group was accepted")
            unchanged = load_governed_store(fixture["path"], fixture["anchor"])
            assert unchanged["root"]["version"] == unchanged["policy"]["revision"] == 1
            accept_governed_update(fixture["path"], fixture["anchor"], fixture["policy"], rotation=fixture["rotation"])
            verified = verify_case(case["package"], case["public"], checkpoint_policy_store=fixture["path"],
                                   policy_root_anchor=fixture["anchor"], require_authenticated_key_policy=True,
                                   minimum_policy_revision=2, minimum_root_version=2, include_reconstruction=True)
            assert verified["valid"] and verified["reconstruction"]
            assert verified["checkpoint_key_policy"]["authentication"]["issuer_root"]["rotations_verified"] == 1
    print(json.dumps({"status": "PASS", "offline": True, "dual_quorum_rotation": True,
                      "atomic_policy_activation": True, "independent_anchor_verified": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

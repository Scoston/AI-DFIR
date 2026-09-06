#!/usr/bin/env python3
"""Synthetic scheduled mTLS synchronization with backoff and offline case use."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import verify_case
from v17_delivery_identity_selftest import synthetic_client_identity
from v17_integrity import canonical_json_bytes, sha256_object
from v17_key_policy_selftest import synthetic_export
from v17_policy_delivery import prepare_delivery_bundle
from v17_policy_delivery_selftest import synthetic_https
from v17_policy_governance import initialize_governed_store
from v17_policy_governance_selftest import synthetic_governance
from v17_policy_sync import CONFIG_SCHEMA, PolicySyncScheduler, check_sync_config


def schedule_fixture(fixture, server, root: Path, client=None) -> dict:
    anchor = root / "approved-anchor.json"
    anchor.write_bytes(canonical_json_bytes(fixture["anchor"]))
    job = {"job_id": "synthetic-verifier", "store": str(fixture["path"]), "anchor": str(anchor),
           "anchor_sha256": sha256_object(fixture["anchor"]), "url": server.url, "ca_file": str(server.ca_file),
           "interval_seconds": 30, "max_backoff_seconds": 120, "jitter_seconds": 0,
           "minimum_policy_revision": 2, "minimum_root_version": 2}
    if client is not None:
        job.update({name: str(value) if isinstance(value, Path) else value for name, value in client["options"].items()})
    return {"schema": CONFIG_SCHEMA, "jobs": [job]}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-sync-schedule-") as temporary:
        root = Path(temporary)
        case = synthetic_export(root)
        fixture = synthetic_governance(case, root / "governed.sqlite")
        initialize_governed_store(fixture["path"], fixture["anchor"], fixture["initial"]["envelope"])
        bundle = prepare_delivery_bundle(fixture["anchor"], fixture["policy"], [fixture["rotation"]])
        client = synthetic_client_identity(root / "client", encrypted=True)
        with synthetic_https(root / "server", canonical_json_bytes(bundle), client_ca_file=client["files"]["ca.pem"]) as server:
            config = schedule_fixture(fixture, server, root, client)
            with patch.object(socket.socket, "connect", side_effect=AssertionError("check attempted network")):
                assert check_sync_config(config)["status"] == "PASS"
            clock = [100.0]
            scheduler = PolicySyncScheduler(config, clock=lambda: clock[0])
            assert scheduler.run_due()[0]["status"] == "ACCEPTED"
            before = fixture["path"].read_bytes()
            assert scheduler.run_due() == []
            bad = copy.deepcopy(bundle)
            bad["signed_policy"]["signatures"][0]["signature_hex"] = "00" * 64
            server.body = canonical_json_bytes(bad)
            clock[0] += 30
            assert scheduler.run_due()[0]["next_attempt_in_seconds"] == 30
            clock[0] += 30
            failed = scheduler.run_due()[0]
            assert failed["status"] == "FAIL" and failed["next_attempt_in_seconds"] == 60
            assert fixture["path"].read_bytes() == before
            clock[0] += 60
            server.body = canonical_json_bytes(bundle)
            recovered = scheduler.run_due()[0]
            assert recovered["status"] == "UNCHANGED" and recovered["consecutive_failures"] == 0
            assert recovered["next_attempt_in_seconds"] == 30
        with patch.object(socket.socket, "connect", side_effect=AssertionError("case verification attempted network")):
            report = verify_case(case["package"], case["public"], checkpoint_policy_store=fixture["path"],
                                 policy_root_anchor=fixture["anchor"], include_reconstruction=True)
            assert report["valid"] and report["reconstruction"]
    print(json.dumps({"status": "PASS", "synthetic_scheduled_mtls_only": True, "preflight_offline": True,
                      "invalid_update_rejected": True, "backoff_and_recovery": True, "offline_verification_preserved": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Synthetic timestamped decision replay without weakening current revocation."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import verify_case
from v17_integrity import sha256_bytes, sha256_object
from v17_key_policy_selftest import synthetic_export
from v17_key_trust_history import capture_key_trust_record, evaluate_key_trust_history, prepare_key_trust_request
from v17_policy_governance import accept_governed_update, initialize_governed_store
from v17_policy_governance_selftest import approved_policy, synthetic_governance
from v17_provenance_selftest import CASE_ID, TENANT_ID
from v17_timestamp_selftest import synthetic_response, synthetic_tsa


def synthetic_history(case: dict, path: Path, tsa: dict) -> dict:
    fixture = synthetic_governance(case, path)
    initialize_governed_store(path, fixture["anchor"], fixture["initial"]["envelope"])
    accept_governed_update(path, fixture["anchor"], fixture["policy"], rotation=fixture["rotation"])
    record = capture_key_trust_record(path, fixture["anchor"], signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)
    request = prepare_key_trust_request(record, fixture["anchor"], tsa_policy_oid="1.3.6.1.4.1.55555.1")
    options = {"record": record, "root_anchor": fixture["anchor"], "timestamp_request": request,
               "timestamp_response": synthetic_response(tsa, request), "tsa_ca_pem": tsa["ca_pem"],
               "expected_tsa_certificate_sha256": tsa["pin"], "expected_timestamp_request_sha256": sha256_bytes(request),
               "expected_record_sha256": sha256_object(record)}
    return {"governance": fixture, "options": options, "case": case}


def revoke_current(fixture: dict) -> None:
    q = fixture["replacement"]
    policy = copy.deepcopy(q["policy"])
    policy["revision"] = 3
    policy["issued_at"] = datetime.now(timezone.utc).isoformat()
    policy["keys"][0].update(state="revoked", status_changed_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                              reason="Synthetic key compromise exercise")
    accept_governed_update(fixture["path"], fixture["anchor"], approved_policy(policy, q["keys"][:2], q["trust"]))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-key-trust-history-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
            root = Path(temporary)
            fixture = synthetic_history(synthetic_export(root), root / "governed.sqlite", synthetic_tsa(root / "tsa"))
            case, gov, options = fixture["case"], fixture["governance"], fixture["options"]
            historical = evaluate_key_trust_history(**options, signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)
            assert historical["status"] == "PASS" and historical["historical_key_trusted"], historical
            settings = {"checkpoint_policy_store": gov["path"], "policy_root_anchor": gov["anchor"],
                        "key_trust_history": options, "require_key_trust_history": True, "include_reconstruction": True}
            assert verify_case(case["package"], case["public"], **settings)["valid"]
            revoke_current(gov)
            denied = verify_case(case["package"], case["public"], **settings)
            assert denied["checkpoint_key_trust_history"]["historical_key_trusted"]
            assert not denied["valid"] and not denied["signer_trusted"] and "reconstruction" not in denied
            bad = copy.deepcopy(options)
            bad["record"]["decision"]["status"] = "DENY"
            rejected = evaluate_key_trust_history(**bad, signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)
            assert rejected["status"] == "FAIL" and not rejected["record_existence_attested"]
    print(json.dumps({"status": "PASS", "synthetic_tsa_only": True, "historical_record_reproduced": True,
                      "current_revocation_enforced": True, "tampered_decision_rejected": True, "offline": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

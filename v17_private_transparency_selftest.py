"""Synthetic private-log signatures, witness quorums, inclusion, and consistency."""
from __future__ import annotations

import copy
import json
import socket
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from v17_integrity import sha256_bytes, sha256_object
from v17_private_transparency import TRUST_SCHEMA, append, cosign_head, entry, initialize, make_receipt, verify_receipt
from v17_signing import key_id_from_public_key_bytes, public_key_bytes

TIMESTAMP = "2026-09-07T00:00:00Z"
CASE_ID = "CASE-PRIVATE-LOG-SYNTHETIC"


def synthetic_trust(*, threshold=2, witnesses=2):
    log = Ed25519PrivateKey.generate(); keys = [Ed25519PrivateKey.generate() for _ in range(witnesses)]
    def row(key):
        public = public_key_bytes(key.public_key())
        return {"key_id": key_id_from_public_key_bytes(public), "public_key_hex": public.hex()}
    trust = {"schema": TRUST_SCHEMA, "log_id": "SYNTHETIC-PRIVATE-LOG", "log_key": row(log),
             "witness_keys": [row(key) for key in keys], "witness_threshold": threshold}
    return trust, log, keys, sha256_object(trust)


def synthetic_history(size=7, *, threshold=2):
    trust, log, witnesses, pin = synthetic_trust(threshold=threshold)
    state, head = initialize(trust, log, expected_trust_sha256=pin, issued_at=TIMESTAMP)
    for witness in witnesses[:threshold]: head = cosign_head(head, witness, trust, expected_trust_sha256=pin)
    states, heads = [state], [head]
    for i in range(size):
        raw = f"SYNTHETIC-PRIVATE-EVIDENCE-{i}".encode()
        state, head = append(state, heads[-1], entry(CASE_ID, sha256_bytes(raw), len(raw)), log, trust,
                             expected_trust_sha256=pin, issued_at=TIMESTAMP)
        for witness in witnesses[:threshold]:
            head = cosign_head(head, witness, trust, expected_trust_sha256=pin, state=state, previous_head=heads[-1])
        states.append(state); heads.append(head)
    return {"trust": trust, "log": log, "witnesses": witnesses, "pin": pin, "states": states, "heads": heads}


def verify(receipt, history, *, previous=None):
    subject = receipt["subject"]
    return verify_receipt(receipt, history["trust"], expected_trust_sha256=history["pin"],
                           expected_case_id=CASE_ID, expected_subject_sha256=subject["subject_sha256"],
                           expected_subject_size_bytes=subject["subject_size_bytes"], previous_head=previous)


def main() -> int:
    with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected transparency network")):
        history = synthetic_history()
        for index in range(7):
            receipt = make_receipt(history["states"][-1], history["heads"][-1], index, history["trust"],
                                   expected_trust_sha256=history["pin"], previous_head=history["heads"][3])
            result = verify(receipt, history, previous=history["heads"][3])
            assert result["inclusion_proof_verified"] and result["prefix_consistency_verified"]
            assert result["witness_signatures_verified"] == 2 and not result["operator_independence_verified"]
            altered = copy.deepcopy(receipt); altered["inclusion_path"][0] = "0" * 64
            try: verify(altered, history, previous=history["heads"][3])
            except ValueError: pass
            else: raise AssertionError("altered inclusion proof accepted")
    print(json.dumps({"status": "PASS", "inclusion_proofs": 7, "prefix_consistency": True,
                      "witness_quorum": 2, "altered_proofs_rejected": True, "network_performed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

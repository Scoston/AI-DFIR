"""Private evidence-log snapshots with signed heads, witnesses, and Merkle proofs."""
from __future__ import annotations

import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from v17_integrity import canonical_json_bytes, sha256_object
from v17_log_analytics import _document
from v17_merkle import EMPTY_ROOT, consistency_proof, inclusion_proof, leaf_hash, root, verify_consistency, verify_inclusion
from v17_provenance import ProvenanceError, utc_timestamp
from v17_signing import key_id_from_public_key_bytes, public_key_bytes

TRUST_SCHEMA = "ai-dfir/private-log-trust/v1.7"
STATE_SCHEMA = "ai-dfir/private-log-state/v1.7"
ENTRY_SCHEMA = "ai-dfir/private-log-entry/v1.7"
HEAD_SCHEMA = "ai-dfir/private-log-head/v1.7"
RECEIPT_SCHEMA = "ai-dfir/private-log-inclusion/v1.7"
MAX_TRUST_BYTES = 32 * 1024
MAX_HEAD_BYTES = 32 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_WITNESSES = 32
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _require(ok, reason):
    if not ok: raise ProvenanceError(reason)


def _snapshot(value, limit):
    try: return _document(canonical_json_bytes(value), limit)
    except (ValueError, TypeError, RecursionError):
        raise ProvenanceError("invalid or excessive private-log JSON") from None


def _object(value, fields):
    _require(isinstance(value, dict) and set(value) == set(fields), "unsupported private-log fields")


def _hex(value, size=32):
    return isinstance(value, str) and len(value) == size * 2 and re.fullmatch(r"[0-9a-f]+", value) is not None


def _id(value):
    return isinstance(value, str) and ID_RE.fullmatch(value) is not None


def _key(value):
    _object(value, {"key_id", "public_key_hex"})
    _require(_hex(value["public_key_hex"]), "invalid private-log public key")
    _require(value["key_id"] == key_id_from_public_key_bytes(bytes.fromhex(value["public_key_hex"])), "private-log key identity mismatch")
    return value


def validate_trust(value, *, expected_trust_sha256):
    trust = _snapshot(value, MAX_TRUST_BYTES)
    _require(_hex(expected_trust_sha256) and sha256_object(trust) == expected_trust_sha256, "independent private-log trust pin required")
    _object(trust, {"schema", "log_id", "log_key", "witness_keys", "witness_threshold"})
    _require(trust["schema"] == TRUST_SCHEMA and _id(trust["log_id"]), "unsupported private-log trust identity")
    key = _key(trust["log_key"]); witnesses = trust["witness_keys"]; threshold = trust["witness_threshold"]
    _require(isinstance(witnesses, list) and len(witnesses) <= MAX_WITNESSES, "invalid private-log witness list")
    ids = [key["key_id"]] + [_key(item)["key_id"] for item in witnesses]
    _require(len(set(ids)) == len(ids), "log and witness keys must be distinct")
    _require(type(threshold) is int and 0 <= threshold <= len(witnesses), "invalid witness threshold")
    return trust


def entry(case_id, subject_sha256, subject_size_bytes):
    _require(_id(case_id) and _hex(subject_sha256) and type(subject_size_bytes) is int
             and 0 <= subject_size_bytes <= 9007199254740991, "invalid private-log evidence subject")
    return {"schema": ENTRY_SCHEMA, "case_id": case_id, "subject_sha256": subject_sha256, "subject_size_bytes": subject_size_bytes}


def _entry(value):
    _object(value, {"schema", "case_id", "subject_sha256", "subject_size_bytes"})
    _require(value["schema"] == ENTRY_SCHEMA, "unsupported private-log entry schema")
    return entry(value["case_id"], value["subject_sha256"], value["subject_size_bytes"])


def _state(value, trust, pin):
    state = _snapshot(value, MAX_STATE_BYTES)
    _object(state, {"schema", "log_id", "trust_sha256", "entries"})
    _require(state["schema"] == STATE_SCHEMA and state["log_id"] == trust["log_id"] and state["trust_sha256"] == pin,
             "private-log state identity mismatch")
    _require(isinstance(state["entries"], list) and len(state["entries"]) <= MAX_ENTRIES, "excessive private-log entries")
    leaves = [leaf_hash(canonical_json_bytes(_entry(value))) for value in state["entries"]]
    return state, leaves


def _material(head, role, key_id):
    value = {key: item for key, item in head.items() if key not in {"log_signature", "witness_signatures"}}
    return canonical_json_bytes({"schema": "ai-dfir/private-log-signature/v1.7", "signature_algorithm": "Ed25519",
                                 "role": role, "key_id": key_id, "head": value})


def _verify_signature(signature, head, role, keys):
    _object(signature, {"key_id", "signature_hex"})
    ident, encoded = signature["key_id"], signature["signature_hex"]
    _require(isinstance(ident, str) and ident in keys and _hex(encoded, 64), "unknown or malformed private-log signature")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[ident]["public_key_hex"])).verify(bytes.fromhex(encoded), _material(head, role, ident))
    except (InvalidSignature, ValueError):
        raise ProvenanceError("private-log signature verification failed") from None
    return ident


def _head(value, trust, pin, *, quorum=True):
    head = _snapshot(value, MAX_HEAD_BYTES)
    _object(head, {"schema", "log_id", "trust_sha256", "tree_size", "root_sha256", "issued_at", "log_signature", "witness_signatures"})
    _require(head["schema"] == HEAD_SCHEMA and head["log_id"] == trust["log_id"] and head["trust_sha256"] == pin,
             "private-log head identity mismatch")
    _require(type(head["tree_size"]) is int and 0 <= head["tree_size"] <= MAX_ENTRIES and _hex(head["root_sha256"]), "invalid private-log head size or root")
    _require(head["tree_size"] != 0 or head["root_sha256"] == EMPTY_ROOT.hex(), "invalid empty private-log root")
    utc_timestamp(head["issued_at"])
    _verify_signature(head["log_signature"], head, "log", {trust["log_key"]["key_id"]: trust["log_key"]})
    signatures = head["witness_signatures"]
    _require(isinstance(signatures, list) and len(signatures) <= MAX_WITNESSES, "invalid witness signature list")
    keys = {item["key_id"]: item for item in trust["witness_keys"]}
    ids = [_verify_signature(item, head, "witness", keys) for item in signatures]
    _require(len(set(ids)) == len(ids), "duplicate witness signature")
    _require(not quorum or len(ids) >= trust["witness_threshold"], "private-log witness quorum not met")
    return head


def verify_head(value, trust, *, expected_trust_sha256):
    trust = validate_trust(trust, expected_trust_sha256=expected_trust_sha256)
    return _head(value, trust, expected_trust_sha256)


def _sign(head, private_key, role, expected_keys):
    _require(isinstance(private_key, Ed25519PrivateKey), "Ed25519 private-log key required")
    ident = key_id_from_public_key_bytes(public_key_bytes(private_key.public_key()))
    _require(ident in expected_keys, "private-log signing key not approved")
    return {"key_id": ident, "signature_hex": private_key.sign(_material(head, role, ident)).hex()}


def _new_head(leaves, trust, pin, private_key, issued_at):
    utc_timestamp(issued_at)
    head = {"schema": HEAD_SCHEMA, "log_id": trust["log_id"], "trust_sha256": pin,
            "tree_size": len(leaves), "root_sha256": root(leaves).hex(), "issued_at": issued_at,
            "log_signature": None, "witness_signatures": []}
    head["log_signature"] = _sign(head, private_key, "log", {trust["log_key"]["key_id"]})
    return _head(head, trust, pin, quorum=False)


def initialize(trust, private_key, *, expected_trust_sha256, issued_at):
    trust = validate_trust(trust, expected_trust_sha256=expected_trust_sha256)
    state = {"schema": STATE_SCHEMA, "log_id": trust["log_id"], "trust_sha256": expected_trust_sha256, "entries": []}
    return state, _new_head([], trust, expected_trust_sha256, private_key, issued_at)


def cosign_head(value, private_key, trust, *, expected_trust_sha256, state=None, previous_head=None):
    trust = validate_trust(trust, expected_trust_sha256=expected_trust_sha256)
    head = _head(value, trust, expected_trust_sha256, quorum=False)
    if head["tree_size"]:
        _require(state is not None and previous_head is not None, "witness requires a full state and independent prior head")
        _, leaves = _state(state, trust, expected_trust_sha256)
        previous = _head(previous_head, trust, expected_trust_sha256)
        _require(len(leaves) == head["tree_size"] and root(leaves).hex() == head["root_sha256"], "witness state does not match candidate head")
        _require(previous["tree_size"] <= len(leaves) and root(leaves[:previous["tree_size"]]).hex() == previous["root_sha256"], "witness observed a conflicting history")
        _require(utc_timestamp(head["issued_at"]) >= utc_timestamp(previous["issued_at"]), "witness observed an asserted time regression")
    else:
        _require(state is None and previous_head is None, "empty initialization does not accept an unverified prior state")
    signature = _sign(head, private_key, "witness", {item["key_id"] for item in trust["witness_keys"]})
    _require(signature["key_id"] not in {item["key_id"] for item in head["witness_signatures"]}, "witness already signed this head")
    head["witness_signatures"].append(signature); head["witness_signatures"].sort(key=lambda item: item["key_id"])
    return _head(head, trust, expected_trust_sha256, quorum=False)


def append(value, previous_head, subject, private_key, trust, *, expected_trust_sha256, issued_at):
    trust = validate_trust(trust, expected_trust_sha256=expected_trust_sha256)
    state, leaves = _state(value, trust, expected_trust_sha256)
    previous = _head(previous_head, trust, expected_trust_sha256)
    _require(previous["tree_size"] == len(leaves) and previous["root_sha256"] == root(leaves).hex(), "state differs from independently retained head")
    _require(len(leaves) < MAX_ENTRIES and utc_timestamp(issued_at) >= utc_timestamp(previous["issued_at"]), "private-log size or asserted time regressed")
    subject = _entry(_snapshot(subject, 4096)); state["entries"].append(subject)
    state, leaves = _state(state, trust, expected_trust_sha256)
    return state, _new_head(leaves, trust, expected_trust_sha256, private_key, issued_at)


def _proof(value):
    _require(isinstance(value, list) and len(value) <= 17 and all(_hex(item) for item in value), "invalid or excessive private-log proof")
    return [bytes.fromhex(item) for item in value]


def verify_receipt(value, trust, *, expected_trust_sha256, expected_case_id,
                   expected_subject_sha256, expected_subject_size_bytes, previous_head=None):
    trust = validate_trust(trust, expected_trust_sha256=expected_trust_sha256)
    receipt = _snapshot(value, MAX_RECEIPT_BYTES)
    _object(receipt, {"schema", "subject", "leaf_index", "head", "inclusion_path", "previous_head_sha256", "consistency_path"})
    _require(receipt["schema"] == RECEIPT_SCHEMA, "unsupported private-log receipt schema")
    expected = entry(expected_case_id, expected_subject_sha256, expected_subject_size_bytes)
    subject = _entry(receipt["subject"])
    _require(subject == expected, "private-log subject does not match independent expectation")
    head = _head(receipt["head"], trust, expected_trust_sha256)
    leaf = leaf_hash(canonical_json_bytes(subject))
    included = verify_inclusion(leaf, receipt["leaf_index"], head["tree_size"], _proof(receipt["inclusion_path"]), bytes.fromhex(head["root_sha256"]))
    _require(included, "private-log inclusion proof failed")
    path = _proof(receipt["consistency_path"])
    if previous_head is None:
        _require(receipt["previous_head_sha256"] is None and not path, "independent prior head is required for this receipt")
        consistent = False
    else:
        previous = _head(previous_head, trust, expected_trust_sha256)
        _require(receipt["previous_head_sha256"] == sha256_object(previous), "private-log prior-head binding mismatch")
        _require(utc_timestamp(head["issued_at"]) >= utc_timestamp(previous["issued_at"]), "private-log asserted time regressed")
        consistent = verify_consistency(previous["tree_size"], head["tree_size"], bytes.fromhex(previous["root_sha256"]), bytes.fromhex(head["root_sha256"]), path)
        _require(consistent, "private-log prefix consistency failed")
    return {"schema": "ai-dfir/private-log-verification/v1.7", "status": "PASS", "log_id": trust["log_id"],
            "trust_sha256": expected_trust_sha256, "head_sha256": sha256_object(head),
            "tree_size": head["tree_size"], "root_sha256": head["root_sha256"], "leaf_index": receipt["leaf_index"],
            "subject_sha256": expected_subject_sha256, "subject_size_bytes": expected_subject_size_bytes,
            "inclusion_proof_verified": True, "prefix_consistency_verified": consistent,
            "log_signature_verified": True, "witness_signatures_verified": len(head["witness_signatures"]),
            "required_witnesses": trust["witness_threshold"], "witness_quorum_satisfied": True,
            "operator_independence_verified": False, "independent_timestamp_verified": False,
            "global_fork_freedom_verified": False, "source_authenticity_verified": False, "network_performed": False,
            "interpretation": "Cryptographic inclusion under pinned log/witness keys and optional consistency with an independently supplied prior head; no operator independence, trusted time, global fork freedom, provider origin, or evidence truth is established."}


def make_receipt(value, head, index, trust, *, expected_trust_sha256, previous_head=None):
    trust = validate_trust(trust, expected_trust_sha256=expected_trust_sha256)
    state, leaves = _state(value, trust, expected_trust_sha256)
    checked = _head(head, trust, expected_trust_sha256)
    _require(checked["tree_size"] == len(leaves) and checked["root_sha256"] == root(leaves).hex(), "state does not match signed head")
    _require(type(index) is int and 0 <= index < len(leaves), "invalid private-log index")
    previous = _head(previous_head, trust, expected_trust_sha256) if previous_head is not None else None
    receipt = {"schema": RECEIPT_SCHEMA, "subject": state["entries"][index], "leaf_index": index, "head": checked,
               "inclusion_path": [item.hex() for item in inclusion_proof(leaves, index)],
               "previous_head_sha256": sha256_object(previous) if previous is not None else None,
               "consistency_path": [item.hex() for item in consistency_proof(leaves, previous["tree_size"])] if previous is not None else []}
    subject = receipt["subject"]
    verify_receipt(receipt, trust, expected_trust_sha256=expected_trust_sha256,
                   expected_case_id=subject["case_id"], expected_subject_sha256=subject["subject_sha256"],
                   expected_subject_size_bytes=subject["subject_size_bytes"], previous_head=previous)
    return _snapshot(receipt, MAX_RECEIPT_BYTES)

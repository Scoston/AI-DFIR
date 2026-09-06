"""Independent Ed25519 co-signatures over a policy and approved issuer quorum.

Issuer governance is externally provisioned. This module does not authorize
changes to that trust configuration or prove that distinct keys have distinct
human/organizational custodians. Acceptance and current-time checks are in
v17_policy_distribution; signing alone is not policy acceptance.
"""
from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from v17_integrity import canonical_json_bytes, sha256_object
from v17_key_policy import validate_key_policy
from v17_policy_distribution import (
    ISSUER_TRUST_SCHEMA, MAX_ISSUERS, MAX_ISSUER_TRUST_BYTES, MAX_SIGNED_POLICY_BYTES,
    PolicyUpdateError, _HEX, _SIGNATURE, _require, _snapshot, validate_issuer_trust,
)
from v17_signing import key_id_from_public_key_bytes, public_key_bytes

QUORUM_TRUST_SCHEMA = "ai-dfir/checkpoint-policy-issuer-quorum/v1.7"
QUORUM_POLICY_SCHEMA = "ai-dfir/quorum-signed-checkpoint-key-policy/v1.7"


def validate_quorum_trust(value: Any) -> dict[str, Any]:
    trust = _snapshot(value, MAX_ISSUER_TRUST_BYTES)
    _require(isinstance(trust, dict) and set(trust) == {"schema", "tenant_id", "policy_id", "threshold", "keys"}
             and trust["schema"] == QUORUM_TRUST_SCHEMA,
             "policy_quorum_trust_invalid", "invalid quorum issuer trust fields")
    # Reuse strict public-key, identity, namespace, duplicate, and size checks.
    checked = validate_issuer_trust({"schema": ISSUER_TRUST_SCHEMA, "tenant_id": trust["tenant_id"],
                                    "policy_id": trust["policy_id"], "keys": trust["keys"]})
    _require(type(trust["threshold"]) is int and 1 <= trust["threshold"] <= len(checked["keys"]),
             "policy_quorum_threshold_invalid", "quorum threshold must be between 1 and the number of distinct issuer keys")
    trust["keys"] = sorted(checked["keys"], key=lambda item: item["key_id"])
    return trust


def validate_quorum_envelope(value: Any) -> dict[str, Any]:
    envelope = _snapshot(value, MAX_SIGNED_POLICY_BYTES)
    fields = {"schema", "signature_algorithm", "issuer_trust_sha256", "policy", "signatures"}
    _require(isinstance(envelope, dict) and set(envelope) == fields
             and envelope["schema"] == QUORUM_POLICY_SCHEMA and envelope["signature_algorithm"] == "Ed25519",
             "policy_quorum_envelope_invalid", "invalid quorum policy fields or signature profile")
    digest = envelope["issuer_trust_sha256"]
    _require(isinstance(digest, str) and _HEX.fullmatch(digest) is not None,
             "policy_quorum_envelope_invalid", "invalid issuer trust digest")
    try:
        envelope["policy"] = validate_key_policy(envelope["policy"])
    except ValueError as exc:
        raise PolicyUpdateError("policy_quorum_envelope_invalid", "invalid enclosed key policy") from exc
    signatures = envelope["signatures"]
    _require(isinstance(signatures, list) and 1 <= len(signatures) <= MAX_ISSUERS,
             "policy_quorum_envelope_invalid", "quorum package must contain 1 to 32 distinct signatures")
    seen = set()
    checkpoint_keys = {key["key_id"] for key in envelope["policy"]["keys"]}
    for signature in signatures:
        _require(isinstance(signature, dict) and set(signature) == {"issuer_key_id", "signature_hex"},
                 "policy_quorum_envelope_invalid", "invalid quorum signature fields")
        ident, encoded = signature["issuer_key_id"], signature["signature_hex"]
        _require(isinstance(ident, str) and ident.startswith("sha256:") and _HEX.fullmatch(ident[7:]) is not None
                 and isinstance(encoded, str) and _SIGNATURE.fullmatch(encoded) is not None,
                 "policy_quorum_envelope_invalid", "invalid quorum issuer ID or signature encoding")
        _require(ident not in seen, "policy_quorum_duplicate_signature", "an issuer key may sign only once")
        _require(ident not in checkpoint_keys, "policy_issuer_key_reuse", "policy issuer and checkpoint keys must be separate")
        seen.add(ident)
    envelope["signatures"] = sorted(signatures, key=lambda item: item["issuer_key_id"])
    return envelope


def _scope(envelope: dict, trust: dict) -> None:
    policy = envelope["policy"]
    _require((policy["tenant_id"], policy["policy_id"]) == (trust["tenant_id"], trust["policy_id"]),
             "policy_issuer_scope_mismatch", "quorum policy is outside the independently approved namespace")
    _require(envelope["issuer_trust_sha256"] == sha256_object(trust),
             "policy_quorum_trust_mismatch", "co-signatures do not bind the currently approved issuer configuration")
    _require(not ({key["key_id"] for key in trust["keys"]} & {key["key_id"] for key in policy["keys"]}),
             "policy_issuer_key_reuse", "every quorum issuer key must be separate from checkpoint keys")


def _material(envelope: dict, issuer_key_id: str) -> bytes:
    # Signers approve the same policy and governance configuration independently.
    # The signature list is excluded so each custodian can append their own approval.
    value = {key: item for key, item in envelope.items() if key != "signatures"}
    return canonical_json_bytes(dict(value, issuer_key_id=issuer_key_id))


def _verify(envelope: dict, trust: dict) -> None:
    _scope(envelope, trust)
    keys = {key["key_id"]: key for key in trust["keys"]}
    for signature in envelope["signatures"]:
        ident = signature["issuer_key_id"]
        _require(ident in keys, "policy_issuer_untrusted", "quorum package contains an unapproved issuer")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[ident]["public_key_hex"])).verify(
                bytes.fromhex(signature["signature_hex"]), _material(envelope, ident))
        except InvalidSignature as exc:
            raise PolicyUpdateError("policy_issuer_signature_invalid", "quorum issuer signature failed") from exc


def verify_quorum_signatures(value: Any, issuer_trust: Any) -> dict[str, Any]:
    """Check approved distinct co-signatures; acceptance also checks time/store."""
    envelope, trust = validate_quorum_envelope(value), validate_quorum_trust(issuer_trust)
    _verify(envelope, trust)
    _require(len(envelope["signatures"]) >= trust["threshold"], "policy_quorum_not_met",
             "policy does not have enough distinct approved issuer signatures")
    return {"approval_profile": "issuer-quorum", "issuer_key_id": None,
            "issuer_key_ids": [signature["issuer_key_id"] for signature in envelope["signatures"]],
            "required_signatures": trust["threshold"], "valid_signatures": len(envelope["signatures"])}


def _append_signature(envelope: dict, private_key: Ed25519PrivateKey, trust: dict) -> dict:
    _require(isinstance(private_key, Ed25519PrivateKey), "policy_issuer_key_invalid", "Ed25519 issuer key required")
    ident = key_id_from_public_key_bytes(public_key_bytes(private_key.public_key()))
    _require(ident in {key["key_id"] for key in trust["keys"]},
             "policy_issuer_untrusted", "co-signing key is not approved by the issuer configuration")
    _require(ident not in {signature["issuer_key_id"] for signature in envelope["signatures"]},
             "policy_quorum_duplicate_signature", "an issuer key may sign only once")
    _scope(envelope, trust)
    envelope["signatures"].append({"issuer_key_id": ident,
                                    "signature_hex": private_key.sign(_material(envelope, ident)).hex()})
    return validate_quorum_envelope(envelope)


def sign_quorum_policy(policy: Any, private_key: Ed25519PrivateKey, issuer_trust: Any) -> dict[str, Any]:
    """Start a policy package with one signature; a partial quorum is not accepted."""
    trust = validate_quorum_trust(issuer_trust)
    envelope = {"schema": QUORUM_POLICY_SCHEMA, "signature_algorithm": "Ed25519",
                "issuer_trust_sha256": sha256_object(trust), "policy": validate_key_policy(policy), "signatures": []}
    return _append_signature(envelope, private_key, trust)


def cosign_quorum_policy(value: Any, private_key: Ed25519PrivateKey, issuer_trust: Any) -> dict[str, Any]:
    """Verify prior approvals and append this issuer's signature without I/O."""
    envelope, trust = validate_quorum_envelope(value), validate_quorum_trust(issuer_trust)
    _verify(envelope, trust)
    return _append_signature(envelope, private_key, trust)

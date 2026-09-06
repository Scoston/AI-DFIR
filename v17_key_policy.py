"""Verifier-supplied checkpoint key policy, evaluated entirely offline.

The policy is an external trust input, never authority discovered in a case ZIP.
This profile evaluates present policy authorization. It does not authenticate a
historical signing time or make retired/revoked keys trustworthy by backdating.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_signing import SignedLedgerCheckpoint, key_id_from_public_key_bytes


KEY_POLICY_SCHEMA = "ai-dfir/checkpoint-key-policy/v1.7"
KEY_POLICY_REPORT_SCHEMA = "ai-dfir/checkpoint-key-policy-result/v1.7"
MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_KEYS = 1000
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")


class KeyPolicyError(ValueError):
    """The external policy cannot be interpreted without ambiguity."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise KeyPolicyError(message)


def _text(value: Any) -> bool:
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 1024
            and not any(ord(c) < 32 for c in value))


def _utc(value: Any) -> datetime:
    _require(isinstance(value, str) and _UTC.fullmatch(value) is not None,
             "timestamps must be explicit RFC 3339 UTC instants")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KeyPolicyError("invalid calendar timestamp") from exc


def validate_key_policy(value: Any) -> dict[str, Any]:
    """Return a detached, strictly validated snapshot of a caller-owned policy."""
    try:
        raw = canonical_json_bytes(value)
        _require(len(raw) <= MAX_POLICY_BYTES, "key policy exceeds size limit")
        policy = json.loads(raw)
        fields = {"schema", "policy_id", "revision", "tenant_id", "case_ids",
                  "issued_at", "expires_at", "keys"}
        _require(isinstance(policy, dict) and set(policy) == fields, "invalid key policy fields")
        _require(policy["schema"] == KEY_POLICY_SCHEMA, "unsupported key policy schema")
        _require(_text(policy["policy_id"]) and _text(policy["tenant_id"]), "policy identity required")
        _require(type(policy["revision"]) is int and 1 <= policy["revision"] <= 2**53 - 1,
                 "policy revision must be a positive interoperable integer")
        issued, expires = _utc(policy["issued_at"]), _utc(policy["expires_at"])
        _require(issued < expires, "invalid policy validity interval")
        cases = policy["case_ids"]
        if cases is not None:
            _require(isinstance(cases, list) and 0 < len(cases) <= MAX_POLICY_KEYS
                     and all(_text(c) for c in cases), "invalid policy case scope")
            _require(len(cases) == len(set(cases)), "duplicate policy case scope")
        keys = policy["keys"]
        # An empty key set is a valid deny-all policy, useful during an incident.
        _require(isinstance(keys, list) and len(keys) <= MAX_POLICY_KEYS, "invalid policy key list")
        seen = set()
        for key in keys:
            key_fields = {"key_id", "public_key_hex", "signature_algorithm", "state",
                          "not_before", "not_after", "status_changed_at", "reason"}
            _require(isinstance(key, dict) and set(key) == key_fields, "invalid policy key fields")
            _require(key["signature_algorithm"] == "Ed25519", "unsupported policy key algorithm")
            encoded = key["public_key_hex"]
            _require(isinstance(encoded, str) and _HEX.fullmatch(encoded) is not None,
                     "invalid policy Ed25519 public key")
            ident = key_id_from_public_key_bytes(bytes.fromhex(encoded))
            _require(key["key_id"] == ident and ident not in seen, "duplicate or mismatched policy key ID")
            seen.add(ident)
            start, end = _utc(key["not_before"]), _utc(key["not_after"])
            _require(start < end, "invalid key validity interval")
            _require(key["state"] in {"active", "retired", "revoked"}, "unsupported policy key state")
            if key["state"] == "active":
                _require(key["status_changed_at"] is None and key["reason"] is None,
                         "active key must not carry retirement or revocation metadata")
            else:
                changed = _utc(key["status_changed_at"])
                _require(changed <= issued, "key status change cannot follow policy issuance")
                _require(_text(key["reason"]), "retirement or revocation reason required")
        return policy
    except KeyPolicyError:
        raise
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        raise KeyPolicyError("malformed key policy") from exc


def load_key_policy(path: str | Path) -> dict[str, Any]:
    """Read a bounded external JSON file; duplicate keys are always rejected."""
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key in policy")
            result[key] = value
        return result

    def constant(_):
        raise KeyPolicyError("non-finite JSON number in policy")

    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_POLICY_BYTES + 1)
    _require(len(raw) <= MAX_POLICY_BYTES, "key policy exceeds size limit")
    try:
        return validate_key_policy(json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                                              parse_constant=constant))
    except (ValueError, RecursionError) as exc:
        raise KeyPolicyError("invalid external key policy: " + str(exc)) from exc


def key_policy_report(status: str = "NOT_RUN") -> dict[str, Any]:
    return {
        "schema": KEY_POLICY_REPORT_SCHEMA, "status": status,
        "trust_source": "verifier-supplied-policy", "policy_id": None,
        "policy_revision": None, "policy_sha256": None,
        "evaluated_at": None, "evaluation_time_source": None,
        "key_id": None, "key_state": None, "signature_valid": None,
        "historical_signing_time_proven": False, "findings": [],
    }


def evaluate_key_policy(
    policy: Any, *, signed_checkpoint: SignedLedgerCheckpoint,
    tenant_id: str, case_id: str, evaluated_at: str | None = None,
    expected_policy_sha256: str | None = None, required: bool = False,
) -> dict[str, Any]:
    """Intersect key identity, scope, current state, validity, and signature.

    A caller-supplied evaluation time makes reports reproducible; it is not a
    trusted timestamp. The latest supplied state applies even if that time or
    the signer's signed_at claim precedes retirement/revocation.
    """
    report = key_policy_report()

    def fail(code, detail):
        report["findings"].append({"code": code, "detail": detail})

    if policy is None:
        if required or expected_policy_sha256 is not None or evaluated_at is not None:
            fail("key_policy_required", "an external checkpoint key policy is required")
            report["status"] = "FAIL"
        else:
            report["status"] = "NOT_CONFIGURED"
        return report

    try:
        policy = validate_key_policy(policy)
        digest = sha256_bytes(canonical_json_bytes(policy))
        report.update(policy_id=policy["policy_id"], policy_revision=policy["revision"], policy_sha256=digest)
        instant = _utc(evaluated_at) if evaluated_at is not None else datetime.now(timezone.utc)
        report.update(evaluated_at=instant.isoformat().replace("+00:00", "Z"),
                      evaluation_time_source="caller" if evaluated_at is not None else "system-clock")
        if expected_policy_sha256 is not None:
            _require(isinstance(expected_policy_sha256, str) and _HEX.fullmatch(expected_policy_sha256) is not None,
                     "expected policy digest must be lowercase SHA-256")
            if digest != expected_policy_sha256:
                fail("key_policy_digest_mismatch", "policy does not match the verifier's pinned snapshot")
        if not _utc(policy["issued_at"]) <= instant < _utc(policy["expires_at"]):
            fail("key_policy_outside_validity", "policy is not current at the evaluation time")
        if not _text(tenant_id) or policy["tenant_id"] != tenant_id:
            fail("key_policy_tenant_mismatch", "policy does not authorize the case tenant")
        if not _text(case_id) or (policy["case_ids"] is not None and case_id not in policy["case_ids"]):
            fail("key_policy_case_mismatch", "policy does not authorize this case")

        signed = signed_checkpoint
        _require(isinstance(signed, SignedLedgerCheckpoint), "invalid signed checkpoint")
        report["key_id"] = signed.key_id
        signature_valid, _ = signed.verify_signature()
        report["signature_valid"] = signature_valid
        if not signature_valid:
            fail("key_policy_signature_invalid", "checkpoint signature is not valid")
        if signed.checkpoint.case_id != case_id:
            fail("key_policy_checkpoint_case_mismatch", "signed checkpoint belongs to another case")
        key = next((k for k in policy["keys"] if k["key_id"] == signed.key_id), None)
        if key is None:
            fail("key_policy_signer_unknown", "checkpoint signer is absent from the external policy")
        else:
            report["key_state"] = key["state"]
            if key["public_key_hex"] != signed.public_key_hex:
                fail("key_policy_public_key_mismatch", "checkpoint public key differs from the policy")
            if key["state"] != "active":
                fail("key_policy_signer_" + key["state"], "current policy does not authorize this key")
            start, end = _utc(key["not_before"]), _utc(key["not_after"])
            if not start <= instant < end:
                fail("key_policy_key_outside_validity", "key is not active at the evaluation time")
            signed_at = _utc(signed.signed_at)
            if not start <= signed_at < end:
                fail("key_policy_signing_time_outside_validity", "claimed signing time is outside key validity")
            if not _utc(signed.checkpoint.created_at) <= signed_at <= instant:
                fail("key_policy_inconsistent_timestamp", "checkpoint creation, signing, or evaluation times are inconsistent")
    except (KeyPolicyError, TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        fail("key_policy_malformed", "policy, evaluation input, or signed checkpoint is malformed")
    report["status"] = "FAIL" if report["findings"] else "PASS"
    return report


def add_key_policy_arguments(parser) -> None:
    parser.add_argument("--checkpoint-key-policy", help="External verifier-controlled checkpoint key policy JSON")
    parser.add_argument("--require-checkpoint-key-policy", action="store_true")
    parser.add_argument("--policy-evaluation-time", help="Explicit UTC evaluation time; default: current system UTC")
    parser.add_argument("--expected-key-policy-sha256", help="Pin the canonical SHA-256 of the externally approved policy")


def key_policy_options(args) -> dict[str, Any]:
    return {
        "checkpoint_key_policy": load_key_policy(args.checkpoint_key_policy) if args.checkpoint_key_policy else None,
        "require_checkpoint_key_policy": args.require_checkpoint_key_policy,
        "key_policy_evaluated_at": args.policy_evaluation_time,
        "expected_key_policy_sha256": args.expected_key_policy_sha256,
    }

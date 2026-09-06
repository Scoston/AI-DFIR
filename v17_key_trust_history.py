"""Timestamped, reproducible key-trust decisions under retained issuer authority.

The TSA binds a complete decision record; it does not approve that decision.
Independent root/TSA trust is always external. A historical result cannot relax
current case verification, and recorded local times are not trusted timestamps.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import v17_policy_governance as governance
from v17_integrity import canonical_json_bytes, sha256_object
from v17_key_policy import _text, _utc, evaluate_key_policy
from v17_policy_distribution import MAX_SIGNED_POLICY_BYTES, PolicyUpdateError, _HEX, _require, _snapshot, load_policy_document
from v17_policy_quorum import validate_quorum_envelope, verify_quorum_signatures
from v17_signing import SignedLedgerCheckpoint
from v17_timestamp import (
    MAX_CA_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, evaluate_statement_timestamp,
    prepare_statement_timestamp_request, read_timestamp_file,
)

RECORD_SCHEMA = "ai-dfir/checkpoint-key-trust-record/v1.7"
STATEMENT_SCHEMA = "ai-dfir/key-trust-record-timestamp-statement/v1.7"
RESULT_SCHEMA = "ai-dfir/checkpoint-key-trust-history/v1.7"
MAX_RECORD_BYTES = governance.MAX_CHAIN_BYTES + MAX_SIGNED_POLICY_BYTES + 32 * 1024
_FIELDS = {"schema", "tenant_id", "case_id", "anchor_sha256", "recorded_at", "signed_checkpoint", "rotations", "signed_policy", "decision"}
_OPTIONS = {"record", "root_anchor", "timestamp_request", "timestamp_response", "tsa_ca_pem", "expected_tsa_certificate_sha256",
            "expected_timestamp_request_sha256", "expected_record_sha256"}


def history_report(status="NOT_RUN") -> dict:
    return {"schema": RESULT_SCHEMA, "status": status, "offline": True, "network_performed": False,
            "record_sha256": None, "anchor_sha256": None, "policy_sha256": None, "policy_revision": None,
            "root_sha256": None, "root_version": None, "rotations_verified": None,
            "recorded_at_claim": None, "recorded_decision": None, "tsa_interval": None,
            "record_existence_attested": False, "historical_key_trusted": False,
            "decision_reproduced": False, "current_authorization_evaluated": False,
            "latest_policy_proven": False, "historical_signing_time_proven": False,
            "actual_prior_verifier_execution_proven": False, "authority": None, "timestamp": None, "findings": []}


def _signed(value: Any) -> SignedLedgerCheckpoint:
    # Import lazily so case verification can use this extension without an
    # import cycle. A complete exact envelope is required, including its schema.
    from case_export_v17 import _parse_signed_checkpoint
    value = _snapshot(value, 16 * 1024)
    _require(isinstance(value, dict), "history_checkpoint_invalid", "signed checkpoint object required")
    signed = _parse_signed_checkpoint(value)
    _require(value == signed.to_dict(), "history_checkpoint_invalid", "unexpected signed checkpoint fields")
    valid, _ = signed.verify_signature()
    _require(valid, "history_checkpoint_signature_invalid", "recorded checkpoint signature is invalid")
    return signed


def _decision(policy: dict, signed: SignedLedgerCheckpoint, tenant: str, case: str, instant: str) -> dict:
    result = evaluate_key_policy(policy, signed_checkpoint=signed, tenant_id=tenant, case_id=case,
                                 evaluated_at=instant, required=True)
    return {"status": "ALLOW" if result["status"] == "PASS" else "DENY", "key_id": result["key_id"],
            "key_state": result["key_state"], "finding_codes": sorted({item["code"] for item in result["findings"]})}


def validate_key_trust_record(value: Any) -> dict:
    record = _snapshot(value, MAX_RECORD_BYTES)
    _require(isinstance(record, dict) and set(record) == _FIELDS and record["schema"] == RECORD_SCHEMA,
             "history_record_invalid", "invalid key-trust record fields or schema")
    _require(_text(record["tenant_id"]) and _text(record["case_id"]), "history_identity_invalid", "invalid record scope")
    _require(isinstance(record["anchor_sha256"], str) and _HEX.fullmatch(record["anchor_sha256"]) is not None,
             "history_anchor_invalid", "record must identify its independent root anchor")
    _utc(record["recorded_at"])
    signed = _signed(record["signed_checkpoint"])
    _require(signed.checkpoint.case_id == record["case_id"], "history_case_mismatch", "record and checkpoint cases differ")
    rotations = _snapshot(record["rotations"], governance.MAX_CHAIN_BYTES)
    _require(isinstance(rotations, list) and len(rotations) <= governance.MAX_ROTATIONS,
             "root_chain_invalid", "record root chain is malformed or oversized")
    record["rotations"] = [governance.validate_rotation(item) for item in rotations]
    record["signed_policy"] = validate_quorum_envelope(record["signed_policy"])
    decision = record["decision"]
    _require(isinstance(decision, dict) and set(decision) == {"status", "key_id", "key_state", "finding_codes"}
             and decision["status"] in {"ALLOW", "DENY"} and decision["key_id"] == signed.key_id
             and decision["key_state"] in {None, "active", "retired", "revoked"}
             and isinstance(decision["finding_codes"], list) and len(decision["finding_codes"]) <= 16
             and all(_text(code) for code in decision["finding_codes"])
             and decision["finding_codes"] == sorted(set(decision["finding_codes"])),
             "history_decision_invalid", "invalid retained decision")
    return record


def load_key_trust_record(path: str | Path) -> dict:
    return validate_key_trust_record(load_policy_document(path, limit=MAX_RECORD_BYTES))


def _authority_at(root: dict, policy: dict, instant: datetime) -> None:
    _require(_utc(root["issued_at"]) <= instant < _utc(root["expires_at"]),
             "history_root_outside_validity", "retained root is outside validity at the historical instant")
    _require(_utc(policy["issued_at"]) <= instant < _utc(policy["expires_at"]),
             "history_policy_outside_validity", "retained policy is outside validity at the historical instant")


def _authenticated_record(value: Any, root_anchor: Any) -> tuple[dict, dict, dict, SignedLedgerCheckpoint]:
    record, anchor = validate_key_trust_record(value), governance.validate_root(root_anchor)
    _require(record["anchor_sha256"] == sha256_object(anchor), "history_anchor_mismatch", "record differs from independent root anchor")
    root, _, _ = governance._chain(anchor, record["rotations"])
    authority = verify_quorum_signatures(record["signed_policy"], root["issuer_trust"])
    policy = record["signed_policy"]["policy"]
    _require(policy["tenant_id"] == record["tenant_id"], "history_tenant_mismatch", "issuer authority belongs to another tenant")
    _authority_at(root, policy, _utc(record["recorded_at"]))
    signed = _signed(record["signed_checkpoint"])
    reproduced = _decision(policy, signed, record["tenant_id"], record["case_id"], record["recorded_at"])
    _require(reproduced == record["decision"], "history_decision_mismatch", "recorded decision does not reproduce from its retained inputs")
    return record, root, authority, signed


def capture_key_trust_record(path: str | Path, root_anchor: Any, *, signed_checkpoint: SignedLedgerCheckpoint,
                             tenant_id: str, case_id: str, minimum_revision=None, minimum_root_version=None) -> dict:
    """Capture a current authenticated store snapshot and deterministic ALLOW/DENY."""
    anchor = governance.validate_root(root_anchor)
    state = governance._read_state(path, anchor)
    root, policy = state["root"], state["policy_row"]["envelope"]["policy"]
    now = datetime.now(timezone.utc)
    _authority_at(root, policy, now)
    governance._floor(minimum_revision, policy["revision"], "policy revision")
    governance._floor(minimum_root_version, root["version"], "root version")
    _require(isinstance(signed_checkpoint, SignedLedgerCheckpoint), "history_checkpoint_invalid", "signed checkpoint required")
    instant = now.isoformat().replace("+00:00", "Z")
    record = {"schema": RECORD_SCHEMA, "tenant_id": tenant_id, "case_id": case_id,
              "anchor_sha256": sha256_object(anchor), "recorded_at": instant,
              "signed_checkpoint": signed_checkpoint.to_dict(), "rotations": state["chain"],
              "signed_policy": state["policy_row"]["envelope"],
              "decision": _decision(policy, signed_checkpoint, tenant_id, case_id, instant)}
    return _authenticated_record(record, anchor)[0]


def key_trust_timestamp_statement(record: Any) -> bytes:
    record = validate_key_trust_record(record)
    return canonical_json_bytes({"schema": STATEMENT_SCHEMA, "tenant_id": record["tenant_id"], "case_id": record["case_id"],
                                 "record_sha256": sha256_object(record)})


def prepare_key_trust_request(record: Any, root_anchor: Any, *, tsa_policy_oid: str | None = None) -> bytes:
    record, root, _, _ = _authenticated_record(record, root_anchor)
    _authority_at(root, record["signed_policy"]["policy"], datetime.now(timezone.utc))
    return prepare_statement_timestamp_request(statement=key_trust_timestamp_statement(record), tsa_policy_oid=tsa_policy_oid)


def _interval(timestamp: dict) -> tuple[datetime, datetime]:
    accuracy = timestamp["tsa_accuracy"]
    _require(isinstance(accuracy, dict) and any(value is not None for value in accuracy.values()),
             "history_accuracy_required", "an explicit signed TSA accuracy interval is required")
    delta = timedelta(seconds=accuracy.get("seconds") or 0, milliseconds=accuracy.get("millis") or 0,
                      microseconds=accuracy.get("micros") or 0)
    instant = _utc(timestamp["tsa_gen_time"])
    return instant - delta, instant + delta


def _replay_interval(record: dict, root: dict, signed: SignedLedgerCheckpoint, lower: datetime, upper: datetime) -> None:
    policy = record["signed_policy"]["policy"]
    _authority_at(root, policy, lower)
    _authority_at(root, policy, upper)
    _require(_utc(record["recorded_at"]) <= upper, "history_record_after_timestamp", "claimed capture time follows the attested interval")
    instants = {lower, upper}
    key = next((key for key in policy["keys"] if key["key_id"] == signed.key_id), None)
    boundaries = [_utc(signed.signed_at)]
    if key is not None:
        boundaries.extend((_utc(key["not_before"]), _utc(key["not_after"])))
    # Endpoints alone miss a short validity window wholly inside the interval.
    # Check each state-changing boundary and its immediate predecessor as well.
    for instant in boundaries:
        if lower <= instant <= upper:
            instants.add(instant)
            if instant > lower:
                instants.add(instant - timedelta(microseconds=1))
    for instant in instants:
        reproduced = _decision(policy, signed, record["tenant_id"], record["case_id"], instant.isoformat())
        _require(reproduced == record["decision"], "history_time_ambiguous", "recorded trust result changes within the TSA accuracy interval")


def evaluate_key_trust_history(*, record: Any, root_anchor: Any, signed_checkpoint: SignedLedgerCheckpoint,
                               tenant_id: str, case_id: str, timestamp_request: bytes | None = None,
                               timestamp_response: bytes | None = None, tsa_ca_pem: bytes | None = None,
                               expected_tsa_certificate_sha256: str | None = None,
                               expected_timestamp_request_sha256: str | None = None,
                               expected_record_sha256: str | None = None) -> dict:
    report = history_report()
    try:
        record, root, authority, retained = _authenticated_record(record, root_anchor)
        digest = sha256_object(record)
        if expected_record_sha256 is not None:
            _require(isinstance(expected_record_sha256, str) and _HEX.fullmatch(expected_record_sha256) is not None,
                     "history_pin_invalid", "record pin must be lowercase SHA-256")
            _require(digest == expected_record_sha256, "history_record_pin_mismatch", "record differs from independently retained digest")
        _require(record["tenant_id"] == tenant_id and record["case_id"] == case_id,
                 "history_scope_mismatch", "record belongs to a different tenant or case")
        _require(isinstance(signed_checkpoint, SignedLedgerCheckpoint)
                 and retained.to_dict() == signed_checkpoint.to_dict(),
                 "history_checkpoint_mismatch", "record does not bind the expected complete signed checkpoint")
        timestamp = evaluate_statement_timestamp(
            statement=key_trust_timestamp_statement(record), timestamp_request=timestamp_request,
            timestamp_response=timestamp_response, tsa_ca_pem=tsa_ca_pem,
            expected_tsa_certificate_sha256=expected_tsa_certificate_sha256,
            expected_timestamp_request_sha256=expected_timestamp_request_sha256,
        )
        report["timestamp"] = timestamp
        _require(timestamp["status"] == "PASS", "history_timestamp_failed", "record timestamp did not authenticate")
        lower, upper = _interval(timestamp)
        _replay_interval(record, root, retained, lower, upper)
        policy = record["signed_policy"]["policy"]
        report.update(status="PASS", record_sha256=digest, anchor_sha256=record["anchor_sha256"],
                      policy_sha256=sha256_object(policy), policy_revision=policy["revision"],
                      root_sha256=sha256_object(root), root_version=root["version"], rotations_verified=len(record["rotations"]),
                      recorded_at_claim=record["recorded_at"], recorded_decision=record["decision"],
                      tsa_interval={"earliest": lower.isoformat().replace("+00:00", "Z"), "latest": upper.isoformat().replace("+00:00", "Z")},
                      authority=authority, record_existence_attested=True, decision_reproduced=True,
                      historical_key_trusted=record["decision"]["status"] == "ALLOW")
    except PolicyUpdateError as exc:
        report["findings"].append({"code": exc.code, "detail": str(exc)})
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
        report["findings"].append({"code": "history_malformed", "detail": f"invalid historical record input ({type(exc).__name__})"})
    if report["status"] != "PASS":
        report["status"] = "FAIL"
    return report


def evaluate_history_options(*, options: Any, required: bool, signed_checkpoint: SignedLedgerCheckpoint,
                             tenant_id: str, case_id: str) -> dict:
    if options is None and not required:
        return history_report("NOT_CONFIGURED")
    if not isinstance(options, dict) or not set(options).issubset(_OPTIONS) or not {"record", "root_anchor"}.issubset(options):
        report = history_report("FAIL")
        report["findings"].append({"code": "history_required", "detail": "historical record and independent verification inputs required"})
        return report
    return evaluate_key_trust_history(**dict(options), signed_checkpoint=signed_checkpoint, tenant_id=tenant_id, case_id=case_id)


def history_accepts(report: dict) -> bool:
    return report["status"] == "NOT_CONFIGURED" or (report["status"] == "PASS" and report["historical_key_trusted"])


def add_key_trust_history_arguments(parser) -> None:
    parser.add_argument("--key-trust-record", help="Retained timestamped key-trust decision JSON")
    parser.add_argument("--key-trust-root-anchor", help="Independently approved historical root anchor")
    parser.add_argument("--key-trust-timestamp-request")
    parser.add_argument("--key-trust-timestamp-response")
    parser.add_argument("--key-trust-tsa-ca-file")
    parser.add_argument("--expected-key-trust-tsa-certificate-sha256")
    parser.add_argument("--expected-key-trust-request-sha256")
    parser.add_argument("--expected-key-trust-record-sha256")
    parser.add_argument("--require-key-trust-history", action="store_true")


def key_trust_history_options(args) -> dict:
    names = {"record": "key_trust_record", "root_anchor": "key_trust_root_anchor", "timestamp_request": "key_trust_timestamp_request",
             "timestamp_response": "key_trust_timestamp_response", "tsa_ca_pem": "key_trust_tsa_ca_file",
             "expected_tsa_certificate_sha256": "expected_key_trust_tsa_certificate_sha256",
             "expected_timestamp_request_sha256": "expected_key_trust_request_sha256", "expected_record_sha256": "expected_key_trust_record_sha256"}
    values = {key: getattr(args, name) for key, name in names.items()}
    configured = any(value is not None for value in values.values())
    if configured:
        if values["record"] is not None:
            values["record"] = load_key_trust_record(values["record"])
        if values["root_anchor"] is not None:
            values["root_anchor"] = governance.load_root(values["root_anchor"])
        for name, limit in (("timestamp_request", MAX_REQUEST_BYTES), ("timestamp_response", MAX_RESPONSE_BYTES), ("tsa_ca_pem", MAX_CA_BYTES)):
            if values[name] is not None:
                values[name] = read_timestamp_file(values[name], limit)
    return {"key_trust_history": values if configured else None, "require_key_trust_history": args.require_key_trust_history}

"""Delegated token and credential lineage for AI-DFIR v1.8.

The module records credential fingerprints, observable JWT structure, explicit
exchange/delegation hops and credential presentations without retaining reusable
raw bearer values. A decoded token is not a verified token; presentation is not
authorization; an observed exchange is not automatically a complete delegation
history.
"""
from __future__ import annotations

import base64
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Iterable

import v18_agent_execution_record as aer

CREDENTIAL_SCHEMA = "ai-dfir/credential-observation/v1.8"
JWT_SCHEMA = "ai-dfir/jwt-structure/v1.8"
PRINCIPAL_SCHEMA = "ai-dfir/principal-observation/v1.8"
HOP_SCHEMA = "ai-dfir/credential-delegation-hop/v1.8"
PRESENTATION_SCHEMA = "ai-dfir/credential-presentation/v1.8"
LINEAGE_SCHEMA = "ai-dfir/credential-lineage/v1.8"
AER_BINDING_SCHEMA = "ai-dfir/credential-lineage-aer/v1.8"

MAX_CREDENTIAL_BYTES = 64 * 1024
MAX_JWT_PART_BYTES = 256 * 1024
MAX_CREDENTIALS = 20_000
MAX_PRINCIPALS = 10_000
MAX_HOPS = 40_000
MAX_PRESENTATIONS = 100_000
MAX_SCOPES = 1_024

PRINCIPAL_KINDS = {"human", "agent", "service", "workload", "role", "application", "unknown"}
CREDENTIAL_TYPES = {
    "oauth-access-token", "oauth-refresh-token", "jwt", "api-key", "session-token",
    "cloud-session", "client-certificate", "signed-assertion", "opaque", "other",
}
HOP_MECHANISMS = {
    "oauth-token-exchange", "assume-role", "service-account-impersonation",
    "workload-identity-exchange", "delegated-session", "on-behalf-of", "other",
}
AUTHORIZATION_DECISIONS = {"allowed", "denied", "unknown", "not-observed"}


def _time(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid ISO-8601 timestamp") from exc
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _secret(value: bytes | bytearray, name: str = "credential") -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    raw = bytes(value)
    if not raw or len(raw) > MAX_CREDENTIAL_BYTES:
        raise ValueError(f"{name} must be between 1 and {MAX_CREDENTIAL_BYTES} bytes")
    return raw


def _scopes(values: Iterable[str] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = values.split()
    out = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("scope values must be non-empty strings")
        out.append(value.strip())
    unique = sorted(set(out))
    if len(unique) > MAX_SCOPES:
        raise ValueError("scope count exceeds bound")
    return unique


def _hash_record(record: dict[str, Any], field: str = "record_sha256") -> dict[str, Any]:
    record[field] = aer.sha256_bytes(aer.canonical_bytes(record))
    return record


def _validate_hash(record: dict[str, Any], field: str = "record_sha256") -> None:
    unsigned = deepcopy(record)
    digest = unsigned.pop(field, None)
    if not isinstance(digest, str) or not aer.SHA256_RE.fullmatch(digest):
        raise ValueError(f"missing or invalid {field}")
    if digest != aer.sha256_bytes(aer.canonical_bytes(unsigned)):
        raise ValueError(f"{field} mismatch")


def credential_observation(credential_id: str, raw_value: bytes | bytearray, *, credential_type: str,
                           observed_at: str, scheme: str | None = None, source_locator: str | None = None,
                           metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fingerprint a credential without retaining its reusable raw value."""
    _text(credential_id, "credential_id")
    if credential_type not in CREDENTIAL_TYPES:
        raise ValueError("unsupported credential_type")
    raw = _secret(raw_value)
    if scheme is not None:
        _text(scheme, "scheme")
    if source_locator is not None:
        _text(source_locator, "source_locator")
    if metadata is not None and not isinstance(metadata, dict):
        raise TypeError("metadata must be an object")
    record = {
        "schema": CREDENTIAL_SCHEMA,
        "credential_id": credential_id,
        "credential_type": credential_type,
        "observed_at": _time(observed_at),
        "scheme": scheme,
        "source_locator": source_locator,
        "fingerprint_sha256": aer.sha256_bytes(raw),
        "byte_length": len(raw),
        "metadata": deepcopy(metadata or {}),
        "claims": {
            "raw_credential_retained": False,
            "credential_authenticity_verified": False,
            "principal_control_proven": False,
            "authorization_proven": False,
        },
        "fingerprint_warning": "SHA-256 is used only as a correlation fingerprint for retained observations; it is not encryption and must not be treated as a verifier for low-entropy secrets.",
    }
    _hash_record(record)
    validate_credential(record)
    return record


def validate_credential(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != CREDENTIAL_SCHEMA:
        raise ValueError("unsupported credential observation schema")
    _text(record.get("credential_id"), "credential_id")
    if record.get("credential_type") not in CREDENTIAL_TYPES:
        raise ValueError("unsupported credential_type")
    _time(record.get("observed_at"))
    if not isinstance(record.get("fingerprint_sha256"), str) or not aer.SHA256_RE.fullmatch(record["fingerprint_sha256"]):
        raise ValueError("invalid credential fingerprint")
    if isinstance(record.get("byte_length"), bool) or not isinstance(record.get("byte_length"), int) or not 1 <= record["byte_length"] <= MAX_CREDENTIAL_BYTES:
        raise ValueError("invalid credential byte length")
    if not isinstance(record.get("metadata"), dict):
        raise ValueError("credential metadata must be an object")
    claims = record.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("credential claims missing")
    for key in ("raw_credential_retained", "credential_authenticity_verified", "principal_control_proven", "authorization_proven"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    forbidden = {"raw", "raw_value", "token", "access_token", "refresh_token", "secret", "credential_value", "base64"}
    if forbidden & set(record):
        raise ValueError("credential observation contains forbidden raw-secret field")
    _validate_hash(record)
    return True


def _b64url(segment: str, name: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise ValueError(f"JWT {name} segment missing")
    if len(segment) > MAX_JWT_PART_BYTES * 2:
        raise ValueError(f"JWT {name} segment exceeds bound")
    padding = "=" * ((4 - len(segment) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except Exception as exc:
        raise ValueError(f"invalid JWT {name} base64url") from exc
    if len(raw) > MAX_JWT_PART_BYTES:
        raise ValueError(f"JWT {name} decoded segment exceeds bound")
    return raw


def _strict_json_object(raw: bytes, name: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"JWT {name} must be UTF-8 JSON") from exc

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JWT {name} key: {key}")
            out[key] = value
        return out

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JWT {name} value: {value}")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JWT {name} JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JWT {name} must be an object")
    return value


def _safe_claim(value: Any, name: str) -> Any:
    if value is None:
        return None
    if name == "aud":
        if isinstance(value, str):
            return [value]
        if isinstance(value, list) and all(isinstance(x, str) for x in value):
            return sorted(set(value))
        raise ValueError("JWT aud must be string or array of strings")
    if name in {"exp", "nbf", "iat"}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"JWT {name} must be numeric")
        return value
    if name in {"scope", "scp"}:
        if isinstance(value, str):
            return _scopes(value)
        if isinstance(value, list):
            return _scopes(value)
        raise ValueError(f"JWT {name} must be string or string array")
    if name == "act":
        if not isinstance(value, dict):
            raise ValueError("JWT act must be an object")
        # Retain only actor identity pivots, not arbitrary nested claims.
        return {key: deepcopy(value[key]) for key in ("sub", "iss", "client_id") if key in value and isinstance(value[key], str)}
    if not isinstance(value, str):
        raise ValueError(f"JWT {name} must be a string")
    return value


def jwt_structure(raw_token: bytes | bytearray, *, observed_at: str, credential_id: str | None = None) -> dict[str, Any]:
    """Decode a compact 3-part JWT structurally without verifying its signature."""
    raw = _secret(raw_token, "JWT")
    try:
        compact = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("JWT compact serialization must be ASCII") from exc
    parts = compact.split(".")
    if len(parts) != 3:
        raise ValueError("JWT structure profile requires exactly three compact segments")
    header = _strict_json_object(_b64url(parts[0], "header"), "header")
    payload = _strict_json_object(_b64url(parts[1], "payload"), "payload")
    selected_header = {key: deepcopy(header[key]) for key in ("alg", "kid", "typ", "cty") if key in header}
    claims: dict[str, Any] = {}
    for name in ("iss", "sub", "aud", "client_id", "scope", "scp", "exp", "nbf", "iat", "jti", "act"):
        if name in payload:
            claims[name] = _safe_claim(payload[name], name)
    record = {
        "schema": JWT_SCHEMA,
        "credential_id": credential_id,
        "observed_at": _time(observed_at),
        "fingerprint_sha256": aer.sha256_bytes(raw),
        "byte_length": len(raw),
        "header": selected_header,
        "claims": claims,
        "unmapped_header_names": sorted(set(header) - set(selected_header)),
        "unmapped_claim_names": sorted(set(payload) - set(claims)),
        "verification": {
            "signature_checked": False,
            "signature_valid": False,
            "issuer_trusted": False,
            "audience_validated": False,
            "time_validated": False,
        },
        "raw_token_retained": False,
    }
    _hash_record(record)
    validate_jwt_structure(record)
    return record


def validate_jwt_structure(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != JWT_SCHEMA:
        raise ValueError("unsupported JWT structure schema")
    _time(record.get("observed_at"))
    if not isinstance(record.get("fingerprint_sha256"), str) or not aer.SHA256_RE.fullmatch(record["fingerprint_sha256"]):
        raise ValueError("invalid JWT fingerprint")
    if not isinstance(record.get("header"), dict) or not isinstance(record.get("claims"), dict):
        raise ValueError("invalid JWT structural fields")
    verification = record.get("verification")
    if not isinstance(verification, dict):
        raise ValueError("JWT verification claims missing")
    for key in ("signature_checked", "signature_valid", "issuer_trusted", "audience_validated", "time_validated"):
        if verification.get(key) is not False:
            raise ValueError(f"JWT structural decoder cannot assert {key}")
    if record.get("raw_token_retained") is not False:
        raise ValueError("raw JWT retention must remain false")
    _validate_hash(record)
    return True


def principal(principal_id: str, *, kind: str, observed_at: str,
              display_name: str | None = None, provider: str | None = None,
              attributes: dict[str, Any] | None = None) -> dict[str, Any]:
    _text(principal_id, "principal_id")
    if kind not in PRINCIPAL_KINDS:
        raise ValueError("unsupported principal kind")
    if attributes is not None and not isinstance(attributes, dict):
        raise TypeError("principal attributes must be an object")
    record = {
        "schema": PRINCIPAL_SCHEMA,
        "principal_id": principal_id,
        "kind": kind,
        "observed_at": _time(observed_at),
        "display_name": display_name,
        "provider": provider,
        "attributes": deepcopy(attributes or {}),
        "claims": {"identity_authenticity_verified": False, "control_attribution_proven": False},
    }
    _hash_record(record)
    return record


def delegation_hop(hop_id: str, *, mechanism: str, observed_at: str,
                   input_credential_id: str, output_credential_id: str,
                   source_principal_id: str, target_principal_id: str,
                   issuer: str | None = None, audience: Iterable[str] | str | None = None,
                   scopes: Iterable[str] | str | None = None,
                   authorization_decision: str = "unknown",
                   evidence_refs: Iterable[dict[str, Any]] = (),
                   policy_context: dict[str, Any] | None = None,
                   approval_context: dict[str, Any] | None = None) -> dict[str, Any]:
    for value, name in ((hop_id, "hop_id"), (input_credential_id, "input_credential_id"),
                        (output_credential_id, "output_credential_id"),
                        (source_principal_id, "source_principal_id"), (target_principal_id, "target_principal_id")):
        _text(value, name)
    if mechanism not in HOP_MECHANISMS:
        raise ValueError("unsupported delegation mechanism")
    if authorization_decision not in AUTHORIZATION_DECISIONS:
        raise ValueError("unsupported authorization decision")
    audiences = [] if audience is None else ([audience] if isinstance(audience, str) else list(audience))
    if any(not isinstance(x, str) or not x for x in audiences):
        raise ValueError("audience values must be non-empty strings")
    refs = [deepcopy(x) for x in evidence_refs]
    for ref in refs:
        aer._check_ref(ref)
    record = {
        "schema": HOP_SCHEMA,
        "hop_id": hop_id,
        "mechanism": mechanism,
        "observed_at": _time(observed_at),
        "input_credential_id": input_credential_id,
        "output_credential_id": output_credential_id,
        "source_principal_id": source_principal_id,
        "target_principal_id": target_principal_id,
        "issuer": issuer,
        "audience": sorted(set(audiences)),
        "scopes": _scopes(scopes),
        "authorization_decision": authorization_decision,
        "evidence_refs": refs,
        "policy_context": deepcopy(policy_context or {}),
        "approval_context": deepcopy(approval_context or {}),
        "claims": {
            "delegation_event_observed": True,
            "credential_authenticity_verified": False,
            "authorization_proven": authorization_decision == "allowed",
            "lineage_complete": False,
            "human_intent_proven": False,
        },
    }
    _hash_record(record)
    validate_hop(record)
    return record


def validate_hop(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != HOP_SCHEMA:
        raise ValueError("unsupported delegation hop schema")
    for name in ("hop_id", "input_credential_id", "output_credential_id", "source_principal_id", "target_principal_id"):
        _text(record.get(name), name)
    if record.get("mechanism") not in HOP_MECHANISMS:
        raise ValueError("unsupported delegation mechanism")
    _time(record.get("observed_at"))
    if record.get("authorization_decision") not in AUTHORIZATION_DECISIONS:
        raise ValueError("unsupported authorization decision")
    if not isinstance(record.get("audience"), list) or not isinstance(record.get("scopes"), list):
        raise ValueError("invalid audience/scopes")
    if not isinstance(record.get("evidence_refs"), list):
        raise ValueError("evidence_refs must be an array")
    for ref in record["evidence_refs"]:
        aer._check_ref(ref)
    claims = record.get("claims")
    if not isinstance(claims, dict) or claims.get("delegation_event_observed") is not True:
        raise ValueError("delegation event claim invalid")
    if claims.get("credential_authenticity_verified") is not False or claims.get("lineage_complete") is not False or claims.get("human_intent_proven") is not False:
        raise ValueError("delegation hop overstates assurance")
    expected_authorized = record["authorization_decision"] == "allowed"
    if claims.get("authorization_proven") is not expected_authorized:
        raise ValueError("authorization claim does not match explicit decision evidence")
    _validate_hash(record)
    return True


def presentation(presentation_id: str, *, credential_id: str, presenter_principal_id: str,
                 observed_at: str, target: str, audience: Iterable[str] | str | None = None,
                 scopes: Iterable[str] | str | None = None,
                 authorization_decision: str = "not-observed",
                 evidence_refs: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    for value, name in ((presentation_id, "presentation_id"), (credential_id, "credential_id"),
                        (presenter_principal_id, "presenter_principal_id"), (target, "target")):
        _text(value, name)
    if authorization_decision not in AUTHORIZATION_DECISIONS:
        raise ValueError("unsupported authorization decision")
    audiences = [] if audience is None else ([audience] if isinstance(audience, str) else list(audience))
    refs = [deepcopy(x) for x in evidence_refs]
    for ref in refs:
        aer._check_ref(ref)
    record = {
        "schema": PRESENTATION_SCHEMA,
        "presentation_id": presentation_id,
        "credential_id": credential_id,
        "presenter_principal_id": presenter_principal_id,
        "observed_at": _time(observed_at),
        "target": target,
        "audience": sorted(set(audiences)),
        "scopes": _scopes(scopes),
        "authorization_decision": authorization_decision,
        "evidence_refs": refs,
        "claims": {
            "credential_presented": True,
            "presenter_control_proven": False,
            "authorization_proven": authorization_decision == "allowed",
            "human_intent_proven": False,
        },
    }
    _hash_record(record)
    validate_presentation(record)
    return record


def validate_presentation(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != PRESENTATION_SCHEMA:
        raise ValueError("unsupported presentation schema")
    for name in ("presentation_id", "credential_id", "presenter_principal_id", "target"):
        _text(record.get(name), name)
    _time(record.get("observed_at"))
    if record.get("authorization_decision") not in AUTHORIZATION_DECISIONS:
        raise ValueError("unsupported authorization decision")
    claims = record.get("claims")
    if not isinstance(claims, dict) or claims.get("credential_presented") is not True:
        raise ValueError("presentation claim invalid")
    if claims.get("presenter_control_proven") is not False or claims.get("human_intent_proven") is not False:
        raise ValueError("presentation overstates attribution")
    if claims.get("authorization_proven") is not (record["authorization_decision"] == "allowed"):
        raise ValueError("authorization claim mismatch")
    _validate_hash(record)
    return True


def _temporal_status(jwt: dict[str, Any], observation_time: str) -> dict[str, Any]:
    claims = jwt.get("claims", {})
    dt = datetime.fromisoformat((observation_time[:-1] + "+00:00") if observation_time.endswith("Z") else observation_time)
    epoch = dt.timestamp()
    exp, nbf = claims.get("exp"), claims.get("nbf")
    return {
        "expired_at_observation": bool(exp is not None and epoch >= float(exp)),
        "not_yet_valid_at_observation": bool(nbf is not None and epoch < float(nbf)),
        "time_claims_cryptographically_verified": False,
    }


def _find_cycle(hops: list[dict[str, Any]]) -> list[str] | None:
    adjacency: dict[str, list[str]] = {}
    for hop in hops:
        adjacency.setdefault(hop["input_credential_id"], []).append(hop["output_credential_id"])
    active: set[str] = set()
    done: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        if node in active:
            if node in stack:
                i = stack.index(node)
                return stack[i:] + [node]
            return [node, node]
        if node in done:
            return None
        active.add(node); stack.append(node)
        for target in sorted(adjacency.get(node, [])):
            found = visit(target)
            if found:
                return found
        stack.pop(); active.remove(node); done.add(node)
        return None

    for node in sorted(adjacency):
        found = visit(node)
        if found:
            return found
    return None


def build_lineage(*, lineage_id: str, credentials: Iterable[dict[str, Any]], principals: Iterable[dict[str, Any]],
                  hops: Iterable[dict[str, Any]] = (), presentations: Iterable[dict[str, Any]] = (),
                  jwt_structures: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    _text(lineage_id, "lineage_id")
    creds = [deepcopy(x) for x in credentials]
    people = [deepcopy(x) for x in principals]
    hop_list = [deepcopy(x) for x in hops]
    shown = [deepcopy(x) for x in presentations]
    jwts = [deepcopy(x) for x in jwt_structures]
    if len(creds) > MAX_CREDENTIALS or len(people) > MAX_PRINCIPALS or len(hop_list) > MAX_HOPS or len(shown) > MAX_PRESENTATIONS:
        raise ValueError("lineage population exceeds bound")
    for item in creds: validate_credential(item)
    for item in hop_list: validate_hop(item)
    for item in shown: validate_presentation(item)
    for item in jwts: validate_jwt_structure(item)

    credential_ids = [x["credential_id"] for x in creds]
    principal_ids = [x["principal_id"] for x in people]
    hop_ids = [x["hop_id"] for x in hop_list]
    presentation_ids = [x["presentation_id"] for x in shown]
    for values, label in ((credential_ids, "credential_id"), (principal_ids, "principal_id"),
                          (hop_ids, "hop_id"), (presentation_ids, "presentation_id")):
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {label}")
    known_credentials, known_principals = set(credential_ids), set(principal_ids)
    missing_credentials: set[str] = set()
    missing_principals: set[str] = set()
    for hop in hop_list:
        for field in ("input_credential_id", "output_credential_id"):
            if hop[field] not in known_credentials:
                missing_credentials.add(hop[field])
        for field in ("source_principal_id", "target_principal_id"):
            if hop[field] not in known_principals:
                missing_principals.add(hop[field])
    for item in shown:
        if item["credential_id"] not in known_credentials:
            missing_credentials.add(item["credential_id"])
        if item["presenter_principal_id"] not in known_principals:
            missing_principals.add(item["presenter_principal_id"])
    cycle = _find_cycle(hop_list)
    if cycle:
        raise ValueError("cyclic credential delegation graph: " + " -> ".join(cycle))

    jwt_by_credential = {item.get("credential_id"): item for item in jwts if item.get("credential_id")}
    credential_by_id = {item["credential_id"]: item for item in creds}
    reuse: dict[str, set[str]] = {}
    for item in shown:
        cred = credential_by_id.get(item["credential_id"])
        if cred:
            reuse.setdefault(cred["fingerprint_sha256"], set()).add(item["presenter_principal_id"])

    scope_changes = []
    audience_changes = []
    principal_changes = []
    issuer_changes = []
    temporal = []
    for hop in sorted(hop_list, key=lambda x: x["hop_id"]):
        source_jwt = jwt_by_credential.get(hop["input_credential_id"])
        target_jwt = jwt_by_credential.get(hop["output_credential_id"])
        source_scope = set((source_jwt or {}).get("claims", {}).get("scope", []) or (source_jwt or {}).get("claims", {}).get("scp", []))
        target_scope = set((target_jwt or {}).get("claims", {}).get("scope", []) or (target_jwt or {}).get("claims", {}).get("scp", []))
        requested_scope = set(hop["scopes"])
        baseline = source_scope or requested_scope
        if baseline or target_scope:
            scope_changes.append({
                "hop_id": hop["hop_id"],
                "added": sorted(target_scope - baseline),
                "removed": sorted(baseline - target_scope),
                "scope_expansion_observed": bool(target_scope - baseline),
                "scope_reduction_observed": bool(baseline - target_scope),
            })
        source_aud = set((source_jwt or {}).get("claims", {}).get("aud", []))
        target_aud = set((target_jwt or {}).get("claims", {}).get("aud", []))
        expected_aud = set(hop["audience"])
        if source_aud or target_aud or expected_aud:
            audience_changes.append({
                "hop_id": hop["hop_id"],
                "source": sorted(source_aud), "requested": sorted(expected_aud), "output": sorted(target_aud),
                "audience_changed": bool(source_aud != target_aud) if source_aud and target_aud else None,
            })
        if hop["source_principal_id"] != hop["target_principal_id"]:
            principal_changes.append({"hop_id": hop["hop_id"], "source": hop["source_principal_id"], "target": hop["target_principal_id"]})
        source_iss = (source_jwt or {}).get("claims", {}).get("iss")
        target_iss = (target_jwt or {}).get("claims", {}).get("iss")
        if source_iss is not None or target_iss is not None or hop.get("issuer") is not None:
            issuer_changes.append({"hop_id": hop["hop_id"], "source": source_iss, "observed_exchange_issuer": hop.get("issuer"),
                                   "output": target_iss, "issuer_changed": source_iss != target_iss if source_iss and target_iss else None})
    for item in jwts:
        temporal.append({"credential_id": item.get("credential_id"), **_temporal_status(item, item["observed_at"])})

    report = {
        "schema": LINEAGE_SCHEMA,
        "lineage_id": lineage_id,
        "credentials": sorted(creds, key=lambda x: x["credential_id"]),
        "principals": sorted(people, key=lambda x: x["principal_id"]),
        "hops": sorted(hop_list, key=lambda x: x["hop_id"]),
        "presentations": sorted(shown, key=lambda x: x["presentation_id"]),
        "jwt_structures": sorted(jwts, key=lambda x: (x.get("credential_id") or "", x["record_sha256"])),
        "diagnostics": {
            "missing_credential_ids": sorted(missing_credentials),
            "missing_principal_ids": sorted(missing_principals),
            "credential_fingerprint_reuse": [
                {"fingerprint_sha256": fingerprint, "presenter_principal_ids": sorted(ids), "multiple_presenters": len(ids) > 1}
                for fingerprint, ids in sorted(reuse.items())
            ],
            "scope_changes": scope_changes,
            "audience_changes": audience_changes,
            "principal_changes": principal_changes,
            "issuer_changes": issuer_changes,
            "jwt_temporal_observations": temporal,
        },
        "claims": {
            "lineage_complete": False,
            "credential_authenticity_verified": False,
            "principal_control_proven": False,
            "authorization_proven_for_all_hops": False,
            "human_intent_proven": False,
            "private_reasoning_captured": False,
        },
    }
    _hash_record(report, "lineage_sha256")
    validate_lineage(report)
    return report


def validate_lineage(report: dict[str, Any]) -> bool:
    if not isinstance(report, dict) or report.get("schema") != LINEAGE_SCHEMA:
        raise ValueError("unsupported credential lineage schema")
    _text(report.get("lineage_id"), "lineage_id")
    for key in ("credentials", "principals", "hops", "presentations", "jwt_structures"):
        if not isinstance(report.get(key), list):
            raise ValueError(f"{key} must be an array")
    for item in report["credentials"]: validate_credential(item)
    for item in report["hops"]: validate_hop(item)
    for item in report["presentations"]: validate_presentation(item)
    for item in report["jwt_structures"]: validate_jwt_structure(item)
    claims = report.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("lineage claims missing")
    for key in ("lineage_complete", "credential_authenticity_verified", "principal_control_proven",
                "authorization_proven_for_all_hops", "human_intent_proven", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    _validate_hash(report, "lineage_sha256")
    return True


def to_aer(report: dict[str, Any], *, record_id: str) -> dict[str, Any]:
    """Project explicit delegation evidence into AER without inflating presentations."""
    validate_lineage(report)
    times = [x["observed_at"] for x in report["credentials"] + report["principals"] + report["hops"] + report["presentations"]]
    if not times:
        raise ValueError("cannot build AER from empty lineage")
    start, end = min(times), max(times)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    raw_refs: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def add_node(item: dict[str, Any], kind: str, source_id: str, attrs: dict[str, Any]) -> str:
        node_id = f"credential-lineage:{kind}:{source_id}"
        if node_id not in node_ids:
            nodes.append(aer.node(node_id, kind, item["observed_at"], attributes=attrs))
            node_ids.add(node_id)
        return node_id

    for item in report["principals"]:
        add_node(item, "identity", item["principal_id"], {
            "principal_id": item["principal_id"], "principal_kind": item["kind"],
            "provider": item.get("provider"), "source_record_sha256": item["record_sha256"],
        })
    for item in report["credentials"]:
        add_node(item, "identity", item["credential_id"], {
            "credential_id": item["credential_id"], "credential_type": item["credential_type"],
            "credential_fingerprint_sha256": item["fingerprint_sha256"],
            "raw_credential_retained": False, "source_record_sha256": item["record_sha256"],
        })

    known_principal = {x["principal_id"] for x in report["principals"]}
    known_credential = {x["credential_id"] for x in report["credentials"]}
    for missing in report["diagnostics"]["missing_principal_ids"]:
        fake = {"observed_at": start}
        add_node(fake, "unknown", f"principal:{missing}", {"missing_principal_id": missing})
    for missing in report["diagnostics"]["missing_credential_ids"]:
        fake = {"observed_at": start}
        add_node(fake, "unknown", f"credential:{missing}", {"missing_credential_id": missing})

    def principal_node(pid: str) -> str:
        return f"credential-lineage:identity:{pid}" if pid in known_principal else f"credential-lineage:unknown:principal:{pid}"

    def credential_node(cid: str) -> str:
        return f"credential-lineage:identity:{cid}" if cid in known_credential else f"credential-lineage:unknown:credential:{cid}"

    for hop in report["hops"]:
        input_node = credential_node(hop["input_credential_id"])
        output_node = credential_node(hop["output_credential_id"])
        source_node = principal_node(hop["source_principal_id"])
        target_node = principal_node(hop["target_principal_id"])
        context = {
            "mechanism": hop["mechanism"], "input_credential_id": hop["input_credential_id"],
            "output_credential_id": hop["output_credential_id"], "issuer": hop.get("issuer"),
            "audience": deepcopy(hop["audience"]), "scopes": deepcopy(hop["scopes"]),
            "authorization_decision": hop["authorization_decision"], "source_record_sha256": hop["record_sha256"],
        }
        edges.append(aer.edge(f"edge:delegation:{hop['hop_id']}:credential", input_node, output_node,
                              "delegated_authority", evidence_refs=hop["evidence_refs"],
                              authority_context=context, policy_context=hop["policy_context"],
                              approval_context=hop["approval_context"], confidence="observed",
                              unknown_fields=["credential_authenticity", "lineage_completeness", "human_intent"]))
        edges.append(aer.edge(f"edge:delegation:{hop['hop_id']}:source", source_node, output_node,
                              "delegated_authority", evidence_refs=hop["evidence_refs"],
                              authority_context=context, policy_context=hop["policy_context"],
                              approval_context=hop["approval_context"], confidence="observed",
                              unknown_fields=["principal_control", "lineage_completeness", "human_intent"]))
        edges.append(aer.edge(f"edge:delegation:{hop['hop_id']}:target", output_node, target_node,
                              "correlated_with", evidence_refs=hop["evidence_refs"], confidence="observed",
                              unknown_fields=["credential_possession", "authorization_at_use_time"]))

    for item in report["presentations"]:
        edges.append(aer.edge(f"edge:presentation:{item['presentation_id']}",
                              principal_node(item["presenter_principal_id"]), credential_node(item["credential_id"]),
                              "correlated_with", evidence_refs=item["evidence_refs"], confidence="observed",
                              authority_context={"target": item["target"], "audience": deepcopy(item["audience"]),
                                                 "scopes": deepcopy(item["scopes"]),
                                                 "authorization_decision": item["authorization_decision"],
                                                 "source_record_sha256": item["record_sha256"]},
                              unknown_fields=["presenter_control", "human_intent"]))

    nodes.sort(key=lambda x: x["node_id"])
    edges.sort(key=lambda x: x["edge_id"])
    record = aer.build_record(record_id, start, ended_at=end, nodes=nodes, edges=edges, raw_evidence=raw_refs,
                              source_versions={"credential_lineage": LINEAGE_SCHEMA},
                              claims={"complete_context_captured": False, "causal_intent_proven": False})
    bundle = {
        "schema": AER_BINDING_SCHEMA,
        "lineage_sha256": report["lineage_sha256"],
        "aer": record,
        "claims": {
            "explicit_delegation_hops_projected": True,
            "mere_presentation_treated_as_delegation": False,
            "lineage_complete": False,
            "credential_authenticity_verified": False,
            "principal_control_proven": False,
            "human_intent_proven": False,
            "private_reasoning_captured": False,
        },
    }
    _hash_record(bundle, "bundle_sha256")
    validate_aer_binding(bundle, report=report)
    return bundle


def validate_aer_binding(bundle: dict[str, Any], *, report: dict[str, Any] | None = None) -> bool:
    if not isinstance(bundle, dict) or bundle.get("schema") != AER_BINDING_SCHEMA:
        raise ValueError("unsupported credential lineage AER schema")
    aer.validate_record(bundle.get("aer"))
    if report is not None:
        validate_lineage(report)
        if bundle.get("lineage_sha256") != report["lineage_sha256"]:
            raise ValueError("lineage binding mismatch")
    claims = bundle.get("claims")
    if not isinstance(claims, dict) or claims.get("explicit_delegation_hops_projected") is not True:
        raise ValueError("AER binding claims invalid")
    if claims.get("mere_presentation_treated_as_delegation") is not False:
        raise ValueError("presentation cannot be inflated into delegation")
    for key in ("lineage_complete", "credential_authenticity_verified", "principal_control_proven", "human_intent_proven", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    _validate_hash(bundle, "bundle_sha256")
    return True

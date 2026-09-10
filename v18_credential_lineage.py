"""Delegated token and credential lineage for AI-DFIR v1.8.

This module records credential fingerprints, observable JWT structure, explicit
exchange/delegation hops, and credential presentations without retaining reusable
raw bearer values. A decoded token is not a verified token; presentation is not
authorization; an observed exchange is not automatically a complete delegation
history.
"""
from __future__ import annotations

import base64
import json
import re
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
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_SECRET_FIELD_NAMES = {
    "raw", "raw_value", "raw_credential", "token", "access_token", "refresh_token",
    "secret", "client_secret", "credential_value", "password", "api_key", "bearer",
    "authorization_header",
}


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_text(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _text(value, name)


def _time(value: Any) -> str:
    """Validate and canonicalize an offset-aware timestamp to UTC."""
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include an explicit UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _secret(value: bytes | bytearray, name: str = "credential") -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    raw = bytes(value)
    if not raw or len(raw) > MAX_CREDENTIAL_BYTES:
        raise ValueError(f"{name} must be between 1 and {MAX_CREDENTIAL_BYTES} bytes")
    return raw


def _json_object(value: dict[str, Any] | None, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be an object")
    copied = deepcopy(value)
    try:
        aer.canonical_bytes(copied)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be canonically JSON serializable") from exc
    return copied


def _reject_secret_fields(value: Any, *, path: str = "metadata") -> None:
    """Reject obvious reusable-secret field names from credential metadata."""
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            normalized = key.strip().lower().replace("-", "_")
            if normalized in _SECRET_FIELD_NAMES:
                raise ValueError(f"credential metadata contains forbidden secret field: {path}.{key}")
            _reject_secret_fields(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, path=f"{path}[{index}]")


def _scopes(values: Iterable[str] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = values.split()
    out: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("scope values must be non-empty strings")
        out.append(value.strip())
    unique = sorted(set(out))
    if len(unique) > MAX_SCOPES:
        raise ValueError("scope count exceeds bound")
    return unique


def _audiences(values: Iterable[str] | str | None) -> list[str]:
    if values is None:
        return []
    raw = [values] if isinstance(values, str) else list(values)
    if any(not isinstance(value, str) or not value.strip() for value in raw):
        raise ValueError("audience values must be non-empty strings")
    return sorted(set(value.strip() for value in raw))


def _refs(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    refs = [deepcopy(value) for value in values]
    for ref in refs:
        aer._check_ref(ref)
    return refs


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
    scheme = _optional_text(scheme, "scheme")
    source_locator = _optional_text(source_locator, "source_locator")
    metadata_copy = _json_object(metadata, "metadata")
    _reject_secret_fields(metadata_copy)
    record = {
        "schema": CREDENTIAL_SCHEMA,
        "credential_id": credential_id,
        "credential_type": credential_type,
        "observed_at": _time(observed_at),
        "scheme": scheme,
        "source_locator": source_locator,
        "fingerprint_sha256": aer.sha256_bytes(raw),
        "byte_length": len(raw),
        "metadata": metadata_copy,
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
    _optional_text(record.get("scheme"), "scheme")
    _optional_text(record.get("source_locator"), "source_locator")
    fingerprint = record.get("fingerprint_sha256")
    if not isinstance(fingerprint, str) or not aer.SHA256_RE.fullmatch(fingerprint):
        raise ValueError("invalid credential fingerprint")
    byte_length = record.get("byte_length")
    if isinstance(byte_length, bool) or not isinstance(byte_length, int) or not 1 <= byte_length <= MAX_CREDENTIAL_BYTES:
        raise ValueError("invalid credential byte length")
    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("credential metadata must be an object")
    _reject_secret_fields(metadata)
    claims = record.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("credential claims missing")
    for key in ("raw_credential_retained", "credential_authenticity_verified", "principal_control_proven", "authorization_proven"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    if _SECRET_FIELD_NAMES & {str(key).strip().lower().replace("-", "_") for key in record}:
        raise ValueError("credential observation contains forbidden raw-secret field")
    _validate_hash(record)
    return True


def _b64url(segment: str, name: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise ValueError(f"JWT {name} segment missing")
    if len(segment) > MAX_JWT_PART_BYTES * 2:
        raise ValueError(f"JWT {name} segment exceeds bound")
    if _B64URL.fullmatch(segment) is None:
        raise ValueError(f"invalid JWT {name} base64url alphabet")
    padding = "=" * ((4 - len(segment) % 4) % 4)
    try:
        raw = base64.b64decode((segment + padding).encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
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
        return _audiences(value)
    if name in {"exp", "nbf", "iat"}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"JWT {name} must be numeric")
        return value
    if name in {"scope", "scp"}:
        if isinstance(value, (str, list, tuple, set)):
            return _scopes(value)
        raise ValueError(f"JWT {name} must be string or string array")
    if name == "act":
        if not isinstance(value, dict):
            raise ValueError("JWT act must be an object")
        result: dict[str, str] = {}
        for key in ("sub", "iss", "client_id"):
            if key in value:
                result[key] = _text(value[key], f"JWT act.{key}")
        return result
    return _text(value, f"JWT {name}")


def jwt_structure(raw_token: bytes | bytearray, *, observed_at: str,
                  credential_id: str | None = None) -> dict[str, Any]:
    """Decode a compact three-part JWT structurally without verifying its signature."""
    raw = _secret(raw_token, "JWT")
    if credential_id is not None:
        _text(credential_id, "credential_id")
    try:
        compact = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("JWT compact serialization must be ASCII") from exc
    parts = compact.split(".")
    if len(parts) != 3:
        raise ValueError("JWT structure profile requires exactly three compact segments")
    header = _strict_json_object(_b64url(parts[0], "header"), "header")
    payload = _strict_json_object(_b64url(parts[1], "payload"), "payload")
    _b64url(parts[2], "signature")
    selected_header: dict[str, str] = {}
    for key in ("alg", "kid", "typ", "cty"):
        if key in header:
            selected_header[key] = _text(header[key], f"JWT header {key}")
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
    if record.get("credential_id") is not None:
        _text(record.get("credential_id"), "credential_id")
    _time(record.get("observed_at"))
    fingerprint = record.get("fingerprint_sha256")
    if not isinstance(fingerprint, str) or not aer.SHA256_RE.fullmatch(fingerprint):
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
    record = {
        "schema": PRINCIPAL_SCHEMA,
        "principal_id": principal_id,
        "kind": kind,
        "observed_at": _time(observed_at),
        "display_name": _optional_text(display_name, "display_name"),
        "provider": _optional_text(provider, "provider"),
        "attributes": _json_object(attributes, "principal attributes"),
        "claims": {"identity_authenticity_verified": False, "control_attribution_proven": False},
    }
    _hash_record(record)
    validate_principal(record)
    return record


def validate_principal(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or record.get("schema") != PRINCIPAL_SCHEMA:
        raise ValueError("unsupported principal observation schema")
    _text(record.get("principal_id"), "principal_id")
    if record.get("kind") not in PRINCIPAL_KINDS:
        raise ValueError("unsupported principal kind")
    _time(record.get("observed_at"))
    _optional_text(record.get("display_name"), "display_name")
    _optional_text(record.get("provider"), "provider")
    if not isinstance(record.get("attributes"), dict):
        raise ValueError("principal attributes must be an object")
    claims = record.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("principal claims missing")
    if claims.get("identity_authenticity_verified") is not False or claims.get("control_attribution_proven") is not False:
        raise ValueError("principal observation overstates assurance")
    _validate_hash(record)
    return True


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
    record = {
        "schema": HOP_SCHEMA,
        "hop_id": hop_id,
        "mechanism": mechanism,
        "observed_at": _time(observed_at),
        "input_credential_id": input_credential_id,
        "output_credential_id": output_credential_id,
        "source_principal_id": source_principal_id,
        "target_principal_id": target_principal_id,
        "issuer": _optional_text(issuer, "issuer"),
        "audience": _audiences(audience),
        "scopes": _scopes(scopes),
        "authorization_decision": authorization_decision,
        "evidence_refs": _refs(evidence_refs),
        "policy_context": _json_object(policy_context, "policy_context"),
        "approval_context": _json_object(approval_context, "approval_context"),
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
    _optional_text(record.get("issuer"), "issuer")
    if record.get("authorization_decision") not in AUTHORIZATION_DECISIONS:
        raise ValueError("unsupported authorization decision")
    if record.get("audience") != _audiences(record.get("audience")):
        raise ValueError("audience must be normalized")
    if record.get("scopes") != _scopes(record.get("scopes")):
        raise ValueError("scopes must be normalized")
    if not isinstance(record.get("evidence_refs"), list):
        raise ValueError("evidence_refs must be an array")
    for ref in record["evidence_refs"]:
        aer._check_ref(ref)
    if not isinstance(record.get("policy_context"), dict) or not isinstance(record.get("approval_context"), dict):
        raise ValueError("policy and approval context must be objects")
    claims = record.get("claims")
    if not isinstance(claims, dict) or claims.get("delegation_event_observed") is not True:
        raise ValueError("delegation event claim invalid")
    if claims.get("credential_authenticity_verified") is not False or claims.get("lineage_complete") is not False or claims.get("human_intent_proven") is not False:
        raise ValueError("delegation hop overstates assurance")
    if claims.get("authorization_proven") is not (record["authorization_decision"] == "allowed"):
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
    record = {
        "schema": PRESENTATION_SCHEMA,
        "presentation_id": presentation_id,
        "credential_id": credential_id,
        "presenter_principal_id": presenter_principal_id,
        "observed_at": _time(observed_at),
        "target": target,
        "audience": _audiences(audience),
        "scopes": _scopes(scopes),
        "authorization_decision": authorization_decision,
        "evidence_refs": _refs(evidence_refs),
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
    if record.get("audience") != _audiences(record.get("audience")):
        raise ValueError("audience must be normalized")
    if record.get("scopes") != _scopes(record.get("scopes")):
        raise ValueError("scopes must be normalized")
    if not isinstance(record.get("evidence_refs"), list):
        raise ValueError("evidence_refs must be an array")
    for ref in record["evidence_refs"]:
        aer._check_ref(ref)
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
    normalized = _time(observation_time)
    dt = datetime.fromisoformat(normalized[:-1] + "+00:00")
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
            index = stack.index(node) if node in stack else 0
            return stack[index:] + [node]
        if node in done:
            return None
        active.add(node)
        stack.append(node)
        for target in sorted(adjacency.get(node, [])):
            found = visit(target)
            if found:
                return found
        stack.pop()
        active.remove(node)
        done.add(node)
        return None

    for node in sorted(adjacency):
        found = visit(node)
        if found:
            return found
    return None


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label}")


def build_lineage(*, lineage_id: str, credentials: Iterable[dict[str, Any]],
                  principals: Iterable[dict[str, Any]], hops: Iterable[dict[str, Any]] = (),
                  presentations: Iterable[dict[str, Any]] = (),
                  jwt_structures: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    _text(lineage_id, "lineage_id")
    creds = [deepcopy(value) for value in credentials]
    people = [deepcopy(value) for value in principals]
    hop_list = [deepcopy(value) for value in hops]
    shown = [deepcopy(value) for value in presentations]
    jwts = [deepcopy(value) for value in jwt_structures]
    if len(creds) > MAX_CREDENTIALS or len(people) > MAX_PRINCIPALS or len(hop_list) > MAX_HOPS or len(shown) > MAX_PRESENTATIONS:
        raise ValueError("lineage population exceeds bound")
    for item in creds:
        validate_credential(item)
    for item in people:
        validate_principal(item)
    for item in hop_list:
        validate_hop(item)
    for item in shown:
        validate_presentation(item)
    for item in jwts:
        validate_jwt_structure(item)

    credential_ids = [item["credential_id"] for item in creds]
    principal_ids = [item["principal_id"] for item in people]
    hop_ids = [item["hop_id"] for item in hop_list]
    presentation_ids = [item["presentation_id"] for item in shown]
    jwt_credential_ids = [item["credential_id"] for item in jwts if item.get("credential_id") is not None]
    _unique(credential_ids, "credential_id")
    _unique(principal_ids, "principal_id")
    _unique(hop_ids, "hop_id")
    _unique(presentation_ids, "presentation_id")
    _unique(jwt_credential_ids, "JWT credential_id")

    known_credentials = set(credential_ids)
    known_principals = set(principal_ids)
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

    jwt_by_credential = {item["credential_id"]: item for item in jwts if item.get("credential_id")}
    credential_by_id = {item["credential_id"]: item for item in creds}
    reuse: dict[str, set[str]] = {}
    for item in shown:
        credential = credential_by_id.get(item["credential_id"])
        if credential:
            reuse.setdefault(credential["fingerprint_sha256"], set()).add(item["presenter_principal_id"])

    scope_changes: list[dict[str, Any]] = []
    audience_changes: list[dict[str, Any]] = []
    principal_changes: list[dict[str, Any]] = []
    issuer_changes: list[dict[str, Any]] = []
    temporal: list[dict[str, Any]] = []
    for hop in sorted(hop_list, key=lambda value: value["hop_id"]):
        source_jwt = jwt_by_credential.get(hop["input_credential_id"])
        target_jwt = jwt_by_credential.get(hop["output_credential_id"])
        source_claims = (source_jwt or {}).get("claims", {})
        target_claims = (target_jwt or {}).get("claims", {})
        source_scope = set(source_claims.get("scope", []) or source_claims.get("scp", []))
        target_scope = set(target_claims.get("scope", []) or target_claims.get("scp", []))
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
        source_aud = set(source_claims.get("aud", []))
        target_aud = set(target_claims.get("aud", []))
        expected_aud = set(hop["audience"])
        if source_aud or target_aud or expected_aud:
            audience_changes.append({
                "hop_id": hop["hop_id"], "source": sorted(source_aud),
                "requested": sorted(expected_aud), "output": sorted(target_aud),
                "audience_changed": bool(source_aud != target_aud) if source_aud and target_aud else None,
            })
        if hop["source_principal_id"] != hop["target_principal_id"]:
            principal_changes.append({
                "hop_id": hop["hop_id"], "source": hop["source_principal_id"],
                "target": hop["target_principal_id"],
            })
        source_issuer = source_claims.get("iss")
        target_issuer = target_claims.get("iss")
        if source_issuer is not None or target_issuer is not None or hop.get("issuer") is not None:
            issuer_changes.append({
                "hop_id": hop["hop_id"], "source": source_issuer,
                "observed_exchange_issuer": hop.get("issuer"), "output": target_issuer,
                "issuer_changed": source_issuer != target_issuer if source_issuer and target_issuer else None,
            })
    for item in jwts:
        temporal.append({"credential_id": item.get("credential_id"), **_temporal_status(item, item["observed_at"])})

    report = {
        "schema": LINEAGE_SCHEMA,
        "lineage_id": lineage_id,
        "credentials": sorted(creds, key=lambda value: value["credential_id"]),
        "principals": sorted(people, key=lambda value: value["principal_id"]),
        "hops": sorted(hop_list, key=lambda value: value["hop_id"]),
        "presentations": sorted(shown, key=lambda value: value["presentation_id"]),
        "jwt_structures": sorted(jwts, key=lambda value: (value.get("credential_id") or "", value["record_sha256"])),
        "diagnostics": {
            "missing_credential_ids": sorted(missing_credentials),
            "missing_principal_ids": sorted(missing_principals),
            "credential_fingerprint_reuse": [
                {"fingerprint_sha256": fingerprint, "presenter_principal_ids": sorted(ids),
                 "multiple_presenters": len(ids) > 1}
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
    for item in report["credentials"]:
        validate_credential(item)
    for item in report["principals"]:
        validate_principal(item)
    for item in report["hops"]:
        validate_hop(item)
    for item in report["presentations"]:
        validate_presentation(item)
    for item in report["jwt_structures"]:
        validate_jwt_structure(item)
    _unique([item["credential_id"] for item in report["credentials"]], "credential_id")
    _unique([item["principal_id"] for item in report["principals"]], "principal_id")
    _unique([item["hop_id"] for item in report["hops"]], "hop_id")
    _unique([item["presentation_id"] for item in report["presentations"]], "presentation_id")
    _unique([item["credential_id"] for item in report["jwt_structures"] if item.get("credential_id")], "JWT credential_id")
    if _find_cycle(report["hops"]):
        raise ValueError("cyclic credential delegation graph")
    if not isinstance(report.get("diagnostics"), dict):
        raise ValueError("lineage diagnostics missing")
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
    times = [
        item["observed_at"]
        for item in report["credentials"] + report["principals"] + report["hops"] + report["presentations"]
    ]
    if not times:
        raise ValueError("cannot build AER from empty lineage")
    start, end = min(times), max(times)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def add_node(item: dict[str, Any], kind: str, source_id: str, attributes: dict[str, Any]) -> str:
        node_id = f"credential-lineage:{kind}:{source_id}"
        if node_id not in node_ids:
            nodes.append(aer.node(node_id, kind, item["observed_at"], attributes=attributes))
            node_ids.add(node_id)
        return node_id

    for item in report["principals"]:
        add_node(item, "identity", f"principal:{item['principal_id']}", {
            "principal_id": item["principal_id"], "principal_kind": item["kind"],
            "provider": item.get("provider"), "source_record_sha256": item["record_sha256"],
        })
    for item in report["credentials"]:
        add_node(item, "identity", f"credential:{item['credential_id']}", {
            "credential_id": item["credential_id"], "credential_type": item["credential_type"],
            "credential_fingerprint_sha256": item["fingerprint_sha256"],
            "raw_credential_retained": False, "source_record_sha256": item["record_sha256"],
        })

    known_principals = {item["principal_id"] for item in report["principals"]}
    known_credentials = {item["credential_id"] for item in report["credentials"]}
    for missing in report["diagnostics"]["missing_principal_ids"]:
        add_node({"observed_at": start}, "unknown", f"principal:{missing}", {"missing_principal_id": missing})
    for missing in report["diagnostics"]["missing_credential_ids"]:
        add_node({"observed_at": start}, "unknown", f"credential:{missing}", {"missing_credential_id": missing})

    def principal_node(principal_id: str) -> str:
        prefix = "identity" if principal_id in known_principals else "unknown"
        return f"credential-lineage:{prefix}:principal:{principal_id}"

    def credential_node(credential_id: str) -> str:
        prefix = "identity" if credential_id in known_credentials else "unknown"
        return f"credential-lineage:{prefix}:credential:{credential_id}"

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
        edges.append(aer.edge(
            f"edge:delegation:{hop['hop_id']}:credential", input_node, output_node,
            "delegated_authority", evidence_refs=hop["evidence_refs"], authority_context=context,
            policy_context=hop["policy_context"], approval_context=hop["approval_context"],
            confidence="observed", unknown_fields=["credential_authenticity", "lineage_completeness", "human_intent"],
        ))
        edges.append(aer.edge(
            f"edge:delegation:{hop['hop_id']}:source", source_node, output_node,
            "delegated_authority", evidence_refs=hop["evidence_refs"], authority_context=context,
            policy_context=hop["policy_context"], approval_context=hop["approval_context"],
            confidence="observed", unknown_fields=["principal_control", "lineage_completeness", "human_intent"],
        ))
        edges.append(aer.edge(
            f"edge:delegation:{hop['hop_id']}:target", output_node, target_node,
            "correlated_with", evidence_refs=hop["evidence_refs"], confidence="observed",
            unknown_fields=["credential_possession", "authorization_at_use_time"],
        ))

    for item in report["presentations"]:
        edges.append(aer.edge(
            f"edge:presentation:{item['presentation_id']}", principal_node(item["presenter_principal_id"]),
            credential_node(item["credential_id"]), "correlated_with", evidence_refs=item["evidence_refs"],
            confidence="observed", authority_context={
                "target": item["target"], "audience": deepcopy(item["audience"]),
                "scopes": deepcopy(item["scopes"]), "authorization_decision": item["authorization_decision"],
                "source_record_sha256": item["record_sha256"],
            }, unknown_fields=["presenter_control", "human_intent"],
        ))

    nodes.sort(key=lambda value: value["node_id"])
    edges.sort(key=lambda value: value["edge_id"])
    record = aer.build_record(
        record_id, start, ended_at=end, nodes=nodes, edges=edges, raw_evidence=[],
        source_versions={"credential_lineage": LINEAGE_SCHEMA},
        claims={"complete_context_captured": False, "causal_intent_proven": False},
    )
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
    for key in ("lineage_complete", "credential_authenticity_verified", "principal_control_proven",
                "human_intent_proven", "private_reasoning_captured"):
        if claims.get(key) is not False:
            raise ValueError(f"{key} must remain false")
    _validate_hash(bundle, "bundle_sha256")
    return True

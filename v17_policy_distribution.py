"""Signed checkpoint policies and a verifier-owned, transactional revision store.

Transport is deliberately outside this module. A downloaded/emailed/copied
policy is untrusted until authenticated against independently supplied issuers.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_key_policy import MAX_POLICY_BYTES, _text, _utc, validate_key_policy
from v17_signing import key_id_from_public_key_bytes, public_key_bytes

SIGNED_POLICY_SCHEMA = "ai-dfir/signed-checkpoint-key-policy/v1.7"
ISSUER_TRUST_SCHEMA = "ai-dfir/checkpoint-policy-issuers/v1.7"
AUTH_REPORT_SCHEMA = "ai-dfir/checkpoint-policy-authentication/v1.7"
MAX_SIGNED_POLICY_BYTES = MAX_POLICY_BYTES + 4096
MAX_ISSUER_TRUST_BYTES = 64 * 1024
MAX_ISSUERS = 32
MAX_STORE_BYTES = 16 * 1024 * 1024
APPLICATION_ID = 0x41445037
STORE_VERSION = 1
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
_TABLE = """CREATE TABLE checkpoint_policy (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    tenant_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    policy_sha256 TEXT NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    accepted_at TEXT NOT NULL
)"""


class PolicyUpdateError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise PolicyUpdateError(code, detail)


def authentication_report(status: str = "NOT_RUN") -> dict[str, Any]:
    return {
        "schema": AUTH_REPORT_SCHEMA, "status": status, "issuer_key_id": None,
        "issuer_trust_sha256": None, "policy_sha256": None, "envelope_sha256": None,
        "policy_revision": None, "accepted_at": None, "evaluated_at": None,
        "evaluation_time_source": "system-utc", "signature_valid": False,
        "rollback_protection": "NOT_EVALUATED", "network_performed": False,
        "findings": [],
    }


def _json(raw: bytes, limit: int) -> Any:
    _require(type(raw) is bytes and 0 < len(raw) <= limit,
             "policy_update_size", "policy input is empty or exceeds its byte limit")

    def pairs(items):
        value = {}
        for key, item in items:
            _require(key not in value, "policy_update_json", "duplicate JSON key")
            value[key] = item
        return value

    def constant(_):
        raise PolicyUpdateError("policy_update_json", "non-finite JSON number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        raise PolicyUpdateError("policy_update_json", "invalid policy JSON") from exc


def load_policy_document(path: str | Path, *, limit: int = MAX_SIGNED_POLICY_BYTES) -> Any:
    with Path(path).open("rb") as stream:
        return _json(stream.read(limit + 1), limit)


def _snapshot(value: Any, limit: int) -> Any:
    try:
        return _json(canonical_json_bytes(value), limit)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, PolicyUpdateError):
            raise
        raise PolicyUpdateError("policy_update_malformed", "malformed policy object") from exc


def validate_issuer_trust(value: Any) -> dict[str, Any]:
    trust = _snapshot(value, MAX_ISSUER_TRUST_BYTES)
    _require(isinstance(trust, dict) and set(trust) == {"schema", "tenant_id", "policy_id", "keys"},
             "policy_issuer_trust_invalid", "invalid issuer trust fields")
    _require(trust["schema"] == ISSUER_TRUST_SCHEMA and _text(trust["tenant_id"]) and _text(trust["policy_id"]),
             "policy_issuer_trust_invalid", "issuer trust must identify a tenant and policy")
    _require(isinstance(trust["keys"], list) and len(trust["keys"]) <= MAX_ISSUERS,
             "policy_issuer_trust_invalid", "invalid issuer key list")
    seen = set()
    for key in trust["keys"]:
        _require(isinstance(key, dict) and set(key) == {"key_id", "public_key_hex"},
                 "policy_issuer_trust_invalid", "invalid issuer key fields")
        encoded = key["public_key_hex"]
        _require(isinstance(encoded, str) and _HEX.fullmatch(encoded) is not None,
                 "policy_issuer_trust_invalid", "invalid issuer Ed25519 public key")
        ident = key_id_from_public_key_bytes(bytes.fromhex(encoded))
        _require(key["key_id"] == ident and ident not in seen,
                 "policy_issuer_trust_invalid", "duplicate or mismatched issuer key ID")
        seen.add(ident)
    return trust


def load_issuer_trust(path: str | Path) -> dict[str, Any]:
    return validate_issuer_trust(load_policy_document(path, limit=MAX_ISSUER_TRUST_BYTES))


def _envelope(value: Any) -> dict[str, Any]:
    envelope = _snapshot(value, MAX_SIGNED_POLICY_BYTES)
    fields = {"schema", "signature_algorithm", "issuer_key_id", "policy", "signature_hex"}
    _require(isinstance(envelope, dict) and set(envelope) == fields,
             "signed_policy_invalid", "invalid signed policy fields")
    _require(envelope["schema"] == SIGNED_POLICY_SCHEMA and envelope["signature_algorithm"] == "Ed25519",
             "signed_policy_invalid", "unsupported policy signature profile")
    _require(isinstance(envelope["issuer_key_id"], str) and _text(envelope["issuer_key_id"]),
             "signed_policy_invalid", "invalid issuer key ID")
    _require(isinstance(envelope["signature_hex"], str) and _SIGNATURE.fullmatch(envelope["signature_hex"]) is not None,
             "signed_policy_invalid", "invalid policy Ed25519 signature encoding")
    try:
        envelope["policy"] = validate_key_policy(envelope["policy"])
    except ValueError as exc:
        raise PolicyUpdateError("signed_policy_invalid", "invalid enclosed key policy") from exc
    _require(envelope["issuer_key_id"] not in {key["key_id"] for key in envelope["policy"]["keys"]},
             "policy_issuer_key_reuse", "policy authority must use a separate key from checkpoint signers")
    return envelope


def _material(envelope: dict[str, Any]) -> bytes:
    return canonical_json_bytes({key: value for key, value in envelope.items() if key != "signature_hex"})


def sign_key_policy(policy: Any, private_key: Ed25519PrivateKey) -> dict[str, Any]:
    _require(isinstance(private_key, Ed25519PrivateKey), "policy_issuer_key_invalid", "Ed25519 issuer key required")
    envelope = {"schema": SIGNED_POLICY_SCHEMA, "signature_algorithm": "Ed25519",
                "issuer_key_id": key_id_from_public_key_bytes(public_key_bytes(private_key.public_key())),
                "policy": validate_key_policy(policy)}
    envelope["signature_hex"] = private_key.sign(_material(envelope)).hex()
    return _envelope(envelope)


def authenticate_key_policy(value: Any, issuer_trust: Any) -> dict[str, Any]:
    """Authenticate scope, signature, and freshness at the current system clock."""
    envelope, trust = _envelope(value), validate_issuer_trust(issuer_trust)
    policy = envelope["policy"]
    _require((policy["tenant_id"], policy["policy_id"]) == (trust["tenant_id"], trust["policy_id"]),
             "policy_issuer_scope_mismatch", "signed policy is outside the approved issuer trust scope")
    key = next((key for key in trust["keys"] if key["key_id"] == envelope["issuer_key_id"]), None)
    _require(key is not None, "policy_issuer_untrusted", "policy issuer is not independently trusted")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key_hex"])).verify(
            bytes.fromhex(envelope["signature_hex"]), _material(envelope))
    except InvalidSignature as exc:
        raise PolicyUpdateError("policy_issuer_signature_invalid", "policy issuer signature failed") from exc
    now = datetime.now(timezone.utc)
    _require(_utc(policy["issued_at"]) <= now < _utc(policy["expires_at"]),
             "signed_policy_not_current", "signed policy is not current at the system UTC clock")
    report = authentication_report("PASS")
    report.update(issuer_key_id=envelope["issuer_key_id"], issuer_trust_sha256=sha256_object(trust),
                  policy_sha256=sha256_object(policy), envelope_sha256=sha256_object(envelope),
                  policy_revision=policy["revision"], evaluated_at=now.isoformat().replace("+00:00", "Z"),
                  signature_valid=True)
    return {"envelope": envelope, "policy": policy, "authentication": report}


def _connect(path: Path, *, writable: bool) -> sqlite3.Connection:
    _require(not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_STORE_BYTES,
             "policy_store_unavailable", "policy store is missing, oversized, or a symlink")
    # A URI with an explicit mode cannot silently create a missing store.
    connection = sqlite3.connect(path.absolute().as_uri() + ("?mode=rw" if writable else "?mode=ro"),
                                 uri=True, timeout=5, isolation_level=None)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        if not writable:
            connection.execute("PRAGMA query_only=ON")
    except sqlite3.Error:
        connection.close()
        raise
    return connection


def _stored(connection: sqlite3.Connection) -> dict[str, Any]:
    _require(connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
             and connection.execute("PRAGMA user_version").fetchone()[0] == STORE_VERSION,
             "policy_store_invalid", "unsupported policy store format")
    objects = connection.execute("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").fetchall()
    _require(len(objects) == 1 and tuple(objects[0]) == ("table", "checkpoint_policy", _TABLE),
             "policy_store_invalid", "unexpected policy store schema")
    rows = connection.execute("SELECT * FROM checkpoint_policy").fetchall()
    _require(len(rows) == 1 and rows[0]["singleton"] == 1,
             "policy_store_invalid", "policy store must contain exactly one accepted policy")
    row = dict(rows[0])
    _require(isinstance(row["envelope_json"], str), "policy_store_invalid", "invalid stored policy encoding")
    envelope = _envelope(_json(row["envelope_json"].encode("utf-8"), MAX_SIGNED_POLICY_BYTES))
    policy = envelope["policy"]
    _require(type(row["revision"]) is int and (row["tenant_id"], row["policy_id"], row["revision"]) ==
             (policy["tenant_id"], policy["policy_id"], policy["revision"])
             and row["policy_sha256"] == sha256_object(policy)
             and row["envelope_sha256"] == sha256_object(envelope),
             "policy_store_invalid", "stored policy and revision record disagree")
    try:
        _utc(row["accepted_at"])
    except (ValueError, TypeError) as exc:
        raise PolicyUpdateError("policy_store_invalid", "invalid policy acceptance time") from exc
    row["envelope"] = envelope
    return row


def load_policy_store(path: str | Path, issuer_trust: Any, *, minimum_revision: int | None = None) -> dict[str, Any]:
    """Read one consistent snapshot, then reauthenticate it on every use."""
    if minimum_revision is not None:
        _require(type(minimum_revision) is int and 1 <= minimum_revision <= 2**53 - 1,
                 "policy_revision_invalid", "minimum revision must be a positive interoperable integer")
    connection = None
    try:
        connection = _connect(Path(path), writable=False)
        connection.execute("BEGIN")
        row = _stored(connection)
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        raise PolicyUpdateError("policy_store_invalid", "policy store could not be read") from exc
    finally:
        if connection is not None:
            connection.close()
    result = authenticate_key_policy(row["envelope"], issuer_trust)
    if minimum_revision is not None:
        _require(row["revision"] >= minimum_revision,
                 "policy_revision_below_floor", "stored policy is below the independently required revision")
    result["authentication"].update(accepted_at=row["accepted_at"], rollback_protection="verifier-owned-store")
    return result


def accept_policy_update(path: str | Path, value: Any, issuer_trust: Any, *, initialize: bool = False) -> dict[str, Any]:
    """Serialize updates; lower revisions and changed equal revisions fail closed.

    The store must be protected by the verifier's filesystem controls. Restoring
    an older whole database cannot be detected without an independent floor.
    """
    trust = validate_issuer_trust(issuer_trust)
    authenticated = authenticate_key_policy(value, trust)
    path = Path(path)
    created = None
    connection = None
    committed = False
    try:
        if initialize:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                created = os.fstat(fd)
            finally:
                os.close(fd)
        connection = _connect(path, writable=True)
        connection.execute("BEGIN IMMEDIATE")
        # Recheck expiry after acquiring the write lock, using detached inputs.
        authenticated = authenticate_key_policy(authenticated["envelope"], trust)
        if initialize:
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={STORE_VERSION}")
            connection.execute(_TABLE)
        else:
            previous = _stored(connection)
            policy = authenticated["policy"]
            _require((previous["tenant_id"], previous["policy_id"]) == (policy["tenant_id"], policy["policy_id"]),
                     "policy_store_scope_mismatch", "a store cannot change tenant or policy identity")
            _require(policy["revision"] >= previous["revision"],
                     "policy_revision_rollback", "older policy revision cannot replace the accepted policy")
            if policy["revision"] == previous["revision"]:
                _require(authenticated["authentication"]["envelope_sha256"] == previous["envelope_sha256"],
                         "policy_revision_conflict", "different signed policy at an already accepted revision")
                connection.execute("COMMIT")
                committed = True
                authenticated["authentication"].update(accepted_at=previous["accepted_at"],
                                                         rollback_protection="verifier-owned-store")
                return {"status": "UNCHANGED", "authentication": authenticated["authentication"]}
        policy, report = authenticated["policy"], authenticated["authentication"]
        connection.execute("""INSERT OR REPLACE INTO checkpoint_policy
            (singleton,tenant_id,policy_id,revision,policy_sha256,envelope_sha256,envelope_json,accepted_at)
            VALUES (1,?,?,?,?,?,?,?)""", (policy["tenant_id"], policy["policy_id"], policy["revision"],
            report["policy_sha256"], report["envelope_sha256"],
            canonical_json_bytes(authenticated["envelope"]).decode("utf-8"), report["evaluated_at"]))
        connection.execute("COMMIT")
        committed = True
        report.update(accepted_at=report["evaluated_at"], rollback_protection="verifier-owned-store")
        return {"status": "ACCEPTED", "authentication": report}
    except sqlite3.Error as exc:
        raise PolicyUpdateError("policy_store_write_failed", "policy store transaction failed or is locked") from exc
    finally:
        if connection is not None:
            connection.close()  # An uncommitted transaction rolls back.
        if created is not None and not committed:
            try:
                current = path.stat()
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    path.unlink()
            except FileNotFoundError:
                pass

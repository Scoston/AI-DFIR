"""Signed issuer-root continuity and atomic activation of roots and policies.

An independently approved root anchors a bounded, retained rotation chain.
Every transition needs the previous and replacement quorum, with separate role
signatures. Expired predecessors can authorize recovery; the active root and
policy must be current. This is not a TUF implementation or trusted-time proof.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import v17_policy_distribution as distribution
from v17_integrity import canonical_json_bytes, sha256_object
from v17_key_policy import _utc
from v17_policy_distribution import PolicyUpdateError, _HEX, _SIGNATURE, _require, _snapshot
from v17_policy_quorum import validate_quorum_envelope, validate_quorum_trust, verify_quorum_signatures
from v17_signing import key_id_from_public_key_bytes, public_key_bytes

ROOT_SCHEMA = "ai-dfir/checkpoint-policy-issuer-root/v1.7"
ROTATION_SCHEMA = "ai-dfir/checkpoint-policy-root-rotation/v1.7"
ROOT_REPORT_SCHEMA = "ai-dfir/checkpoint-policy-root-verification/v1.7"
GOVERNED_STORE_VERSION = 2
MAX_ROOT_BYTES = 68 * 1024
MAX_ROTATION_BYTES = MAX_ROOT_BYTES + 32 * 1024
MAX_CHAIN_BYTES = 4 * 1024 * 1024
MAX_ROTATIONS = 64
ROLES = ("previous", "replacement")
_ROOT_TABLE = """CREATE TABLE issuer_governance (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    anchor_sha256 TEXT NOT NULL,
    root_version INTEGER NOT NULL CHECK (root_version > 0),
    root_sha256 TEXT NOT NULL,
    chain_json TEXT NOT NULL,
    accepted_at TEXT NOT NULL
)"""


def validate_root(value: Any) -> dict[str, Any]:
    root = _snapshot(value, MAX_ROOT_BYTES)
    _require(isinstance(root, dict) and set(root) == {"schema", "version", "issued_at", "expires_at", "issuer_trust"}
             and root["schema"] == ROOT_SCHEMA, "issuer_root_invalid", "invalid issuer root fields")
    _require(type(root["version"]) is int and 1 <= root["version"] <= 2**53 - 1,
             "issuer_root_invalid", "root version must be a positive interoperable integer")
    try:
        _require(_utc(root["issued_at"]) < _utc(root["expires_at"]),
                 "issuer_root_invalid", "invalid issuer root validity interval")
        root["issuer_trust"] = validate_quorum_trust(root["issuer_trust"])
    except (ValueError, TypeError) as exc:
        raise PolicyUpdateError("issuer_root_invalid", "invalid issuer root trust or validity") from exc
    return root


def load_root(path: str | Path) -> dict[str, Any]:
    return validate_root(distribution.load_policy_document(path, limit=MAX_ROOT_BYTES))


def validate_rotation(value: Any) -> dict[str, Any]:
    rotation = _snapshot(value, MAX_ROTATION_BYTES)
    fields = {"schema", "signature_algorithm", "previous_root_sha256", "root", "signatures"}
    _require(isinstance(rotation, dict) and set(rotation) == fields and rotation["schema"] == ROTATION_SCHEMA
             and rotation["signature_algorithm"] == "Ed25519", "root_rotation_invalid", "invalid root rotation fields")
    digest = rotation["previous_root_sha256"]
    _require(isinstance(digest, str) and _HEX.fullmatch(digest) is not None,
             "root_rotation_invalid", "invalid predecessor root digest")
    rotation["root"] = validate_root(rotation["root"])
    groups = rotation["signatures"]
    _require(isinstance(groups, dict) and set(groups) == set(ROLES),
             "root_rotation_invalid", "both rotation signature groups are required")
    for role in ROLES:
        rows = groups[role]
        _require(isinstance(rows, list) and len(rows) <= distribution.MAX_ISSUERS,
                 "root_rotation_invalid", "rotation signature group exceeds its limit")
        seen = set()
        for row in rows:
            _require(isinstance(row, dict) and set(row) == {"issuer_key_id", "signature_hex"},
                     "root_rotation_invalid", "invalid rotation signature fields")
            ident, encoded = row["issuer_key_id"], row["signature_hex"]
            _require(isinstance(ident, str) and ident.startswith("sha256:") and _HEX.fullmatch(ident[7:]) is not None
                     and isinstance(encoded, str) and _SIGNATURE.fullmatch(encoded) is not None,
                     "root_rotation_invalid", "invalid rotation signature encoding")
            _require(ident not in seen, "root_rotation_duplicate_signature", "a key may approve each role only once")
            seen.add(ident)
        groups[role] = sorted(rows, key=lambda row: row["issuer_key_id"])
    return rotation


def _scope(previous: dict, rotation: dict) -> None:
    root = rotation["root"]
    _require(rotation["previous_root_sha256"] == sha256_object(previous),
             "root_rotation_predecessor_mismatch", "rotation does not extend the currently trusted root")
    _require(root["version"] == previous["version"] + 1,
             "root_rotation_version_invalid", "root versions must advance by exactly one")
    before, after = previous["issuer_trust"], root["issuer_trust"]
    _require((before["tenant_id"], before["policy_id"]) == (after["tenant_id"], after["policy_id"]),
             "root_rotation_scope_mismatch", "a root rotation cannot change tenant or policy identity")
    _require(_utc(root["issued_at"]) >= _utc(previous["issued_at"]),
             "root_rotation_time_invalid", "successor root issuance precedes its predecessor")


def _material(rotation: dict, role: str, ident: str) -> bytes:
    value = {key: item for key, item in rotation.items() if key != "signatures"}
    return canonical_json_bytes(dict(value, role=role, issuer_key_id=ident))


def _verify_groups(previous: dict, rotation: dict, *, complete: bool) -> dict:
    _scope(previous, rotation)
    reports = {}
    for role, trust in (("previous", previous["issuer_trust"]), ("replacement", rotation["root"]["issuer_trust"])):
        keys = {key["key_id"]: key for key in trust["keys"]}
        rows = rotation["signatures"][role]
        for row in rows:
            ident = row["issuer_key_id"]
            _require(ident in keys, "root_rotation_issuer_untrusted", f"unapproved issuer for {role} root role")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[ident]["public_key_hex"])).verify(
                    bytes.fromhex(row["signature_hex"]), _material(rotation, role, ident))
            except InvalidSignature as exc:
                raise PolicyUpdateError("root_rotation_signature_invalid", f"invalid {role} root approval") from exc
        if complete:
            _require(len(rows) >= trust["threshold"], "root_rotation_quorum_not_met",
                     f"{role} root approval does not meet its independently required threshold")
        reports[role] = {"required_signatures": trust["threshold"], "valid_signatures": len(rows),
                         "issuer_key_ids": [row["issuer_key_id"] for row in rows]}
    return reports


def verify_root_rotation(previous_root: Any, value: Any) -> dict[str, Any]:
    """Verify continuity and both quorums; active-root time is checked on use."""
    previous, rotation = validate_root(previous_root), validate_rotation(value)
    approvals = _verify_groups(previous, rotation, complete=True)
    return {"rotation": rotation, "root": rotation["root"], "approvals": approvals}


def cosign_root_rotation(previous_root: Any, value: Any, private_key: Ed25519PrivateKey, role: str) -> dict:
    previous, rotation = validate_root(previous_root), validate_rotation(value)
    _require(role in ROLES, "root_rotation_role_invalid", "role must be previous or replacement")
    _require(isinstance(private_key, Ed25519PrivateKey), "policy_issuer_key_invalid", "Ed25519 issuer key required")
    _verify_groups(previous, rotation, complete=False)
    ident = key_id_from_public_key_bytes(public_key_bytes(private_key.public_key()))
    trust = previous["issuer_trust"] if role == "previous" else rotation["root"]["issuer_trust"]
    _require(ident in {key["key_id"] for key in trust["keys"]}, "root_rotation_issuer_untrusted", "key is not approved for this role")
    _require(ident not in {row["issuer_key_id"] for row in rotation["signatures"][role]},
             "root_rotation_duplicate_signature", "a key may approve each role only once")
    rotation["signatures"][role].append({"issuer_key_id": ident,
                                       "signature_hex": private_key.sign(_material(rotation, role, ident)).hex()})
    return validate_rotation(rotation)


def sign_root_rotation(previous_root: Any, next_root: Any, private_key: Ed25519PrivateKey, role: str) -> dict:
    previous, root = validate_root(previous_root), validate_root(next_root)
    value = {"schema": ROTATION_SCHEMA, "signature_algorithm": "Ed25519", "previous_root_sha256": sha256_object(previous),
             "root": root, "signatures": {role: [] for role in ROLES}}
    return cosign_root_rotation(previous, value, private_key, role)


def _chain(anchor: dict, value: Any) -> tuple[dict, list, dict | None]:
    chain = _snapshot(value, MAX_CHAIN_BYTES)
    _require(isinstance(chain, list) and len(chain) <= MAX_ROTATIONS,
             "root_chain_invalid", "issuer root chain is malformed or exceeds the rotation limit")
    current, approvals = anchor, None
    normalized = []
    for value in chain:
        checked = verify_root_rotation(current, value)
        normalized.append(checked["rotation"])
        current, approvals = checked["root"], checked["approvals"]
    return current, normalized, approvals


def _current(root: dict) -> str:
    now = datetime.now(timezone.utc)
    _require(_utc(root["issued_at"]) <= now < _utc(root["expires_at"]),
             "issuer_root_not_current", "active issuer root is not current at the system UTC clock")
    return now.isoformat().replace("+00:00", "Z")


def _floor(value: int | None, actual: int, name: str) -> None:
    if value is not None:
        _require(type(value) is int and 1 <= value <= 2**53 - 1,
                 "governance_floor_invalid", "minimum versions must be positive interoperable integers")
        _require(actual >= value, "governance_below_floor", f"{name} is below the independently required minimum")


def _schema(connection: sqlite3.Connection) -> None:
    _require(connection.execute("PRAGMA application_id").fetchone()[0] == distribution.APPLICATION_ID
             and connection.execute("PRAGMA user_version").fetchone()[0] == GOVERNED_STORE_VERSION,
             "governance_store_invalid", "signed governance requires a version 2 store")
    objects = connection.execute("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    expected = [("table", "checkpoint_policy", distribution._TABLE), ("table", "issuer_governance", _ROOT_TABLE)]
    _require([tuple(row) for row in objects] == expected, "governance_store_invalid", "unexpected governed store schema")


def _stored(connection: sqlite3.Connection, anchor: dict) -> dict:
    _schema(connection)
    policy = distribution._stored_policy(connection)
    rows = connection.execute("SELECT * FROM issuer_governance").fetchall()
    _require(len(rows) == 1 and rows[0]["singleton"] == 1, "governance_store_invalid", "exactly one issuer governance record required")
    row = dict(rows[0])
    _require(row["anchor_sha256"] == sha256_object(anchor), "issuer_root_anchor_mismatch", "store does not match the independent root anchor")
    _require(isinstance(row["chain_json"], str), "governance_store_invalid", "invalid retained root chain")
    root, chain, approvals = _chain(anchor, distribution._json(row["chain_json"].encode("utf-8"), MAX_CHAIN_BYTES))
    _require(type(row["root_version"]) is int and row["root_version"] == root["version"] and row["root_sha256"] == sha256_object(root),
             "governance_store_invalid", "root metadata and verified chain disagree")
    try:
        _utc(row["accepted_at"])
    except (ValueError, TypeError) as exc:
        raise PolicyUpdateError("governance_store_invalid", "invalid root acceptance time") from exc
    # The stored policy must belong to this root. Allow expired policy recovery,
    # but never trust an invalid stored signature or a mixed root/policy state.
    verify_quorum_signatures(policy["envelope"], root["issuer_trust"])
    return {"policy_row": policy, "root": root, "chain": chain, "approvals": approvals, "root_accepted_at": row["accepted_at"]}


def _report(authenticated: dict, anchor: dict, state: dict, *, minimum_revision=None, minimum_root_version=None) -> dict:
    root = state["root"]
    evaluated = _current(root)
    _floor(minimum_revision, authenticated["policy"]["revision"], "policy revision")
    _floor(minimum_root_version, root["version"], "root version")
    authenticated["authentication"].update(accepted_at=state["policy_row"]["accepted_at"], rollback_protection="verifier-owned-store")
    authenticated["authentication"]["issuer_root"] = {
        "schema": ROOT_REPORT_SCHEMA, "status": "PASS", "trust_source": "independent-anchor-and-signed-rotations",
        "anchor_sha256": sha256_object(anchor), "root_sha256": sha256_object(root), "root_version": root["version"],
        "root_chain_sha256": sha256_object(state["chain"]), "rotations_verified": len(state["chain"]),
        "root_accepted_at": state["root_accepted_at"], "evaluated_at": evaluated, "expires_at": root["expires_at"],
        "latest_rotation_approvals": state["approvals"], "network_performed": False,
        "historical_approval_time_proven": False,
    }
    authenticated["root"] = root
    return authenticated


def _read_state(path: str | Path, anchor: dict) -> dict:
    connection = None
    try:
        connection = distribution._connect(Path(path), writable=False)
        connection.execute("BEGIN")
        state = _stored(connection, anchor)
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        raise PolicyUpdateError("governance_store_invalid", "governed store could not be read") from exc
    finally:
        if connection is not None:
            connection.close()
    return state


def inspect_governed_root(path: str | Path, root_anchor: Any) -> dict:
    """Authenticate a root for rotation preparation, even during expiry recovery."""
    anchor = validate_root(root_anchor)
    state = _read_state(path, anchor)
    root = state["root"]
    now = datetime.now(timezone.utc)
    return {"status": "ROOT_AUTHENTICATED", "root": root, "anchor_sha256": sha256_object(anchor),
            "root_sha256": sha256_object(root), "rotations_verified": len(state["chain"]),
            "current_by_system_clock": _utc(root["issued_at"]) <= now < _utc(root["expires_at"]),
            "policy_acceptance_checked": False, "network_performed": False}


def load_governed_store(path: str | Path, root_anchor: Any, *, minimum_revision=None, minimum_root_version=None) -> dict:
    anchor = validate_root(root_anchor)
    state = _read_state(path, anchor)
    authenticated = distribution.authenticate_key_policy(state["policy_row"]["envelope"], state["root"]["issuer_trust"])
    return _report(authenticated, anchor, state, minimum_revision=minimum_revision, minimum_root_version=minimum_root_version)


@contextmanager
def _transaction(path: str | Path, *, initialize: bool = False):
    path = Path(path)
    created = connection = None
    committed = False
    try:
        if initialize:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                created = os.fstat(fd)
            finally:
                os.close(fd)
        connection = distribution._connect(path, writable=True)
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.execute("COMMIT")
        committed = True
    except sqlite3.Error as exc:
        raise PolicyUpdateError("governance_store_write_failed", "governed store transaction failed or is locked") from exc
    finally:
        if connection is not None:
            connection.close()
        if created is not None and not committed:
            try:
                current = path.stat()
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    path.unlink()
            except FileNotFoundError:
                pass


def _write_policy(connection: sqlite3.Connection, authenticated: dict) -> None:
    policy, report = authenticated["policy"], authenticated["authentication"]
    connection.execute("""INSERT OR REPLACE INTO checkpoint_policy
        (singleton,tenant_id,policy_id,revision,policy_sha256,envelope_sha256,envelope_json,accepted_at)
        VALUES (1,?,?,?,?,?,?,?)""", (policy["tenant_id"], policy["policy_id"], policy["revision"], report["policy_sha256"],
        report["envelope_sha256"], canonical_json_bytes(authenticated["envelope"]).decode("utf-8"), report["evaluated_at"]))


def _write_root(connection: sqlite3.Connection, anchor: dict, root: dict, chain: list, accepted_at: str) -> None:
    raw = canonical_json_bytes(chain)
    _require(len(raw) <= MAX_CHAIN_BYTES and len(chain) <= MAX_ROTATIONS, "root_chain_invalid", "root chain exceeds its limit")
    connection.execute("""INSERT OR REPLACE INTO issuer_governance
        (singleton,anchor_sha256,root_version,root_sha256,chain_json,accepted_at) VALUES (1,?,?,?,?,?)""",
        (sha256_object(anchor), root["version"], sha256_object(root), raw.decode("utf-8"), accepted_at))


def initialize_governed_store(path: str | Path, root_anchor: Any, signed_policy: Any) -> dict:
    anchor = validate_root(root_anchor)
    initial = distribution.authenticate_key_policy(signed_policy, anchor["issuer_trust"])
    _current(anchor)
    with _transaction(path, initialize=True) as connection:
        authenticated = distribution.authenticate_key_policy(initial["envelope"], anchor["issuer_trust"])
        now = _current(anchor)
        connection.execute(f"PRAGMA application_id={distribution.APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={GOVERNED_STORE_VERSION}")
        connection.execute(distribution._TABLE)
        connection.execute(_ROOT_TABLE)
        _write_policy(connection, authenticated)
        _write_root(connection, anchor, anchor, [], now)
        state = {"root": anchor, "chain": [], "approvals": None, "root_accepted_at": now,
                 "policy_row": {"accepted_at": authenticated["authentication"]["evaluated_at"]}}
        result = _report(authenticated, anchor, state)
    return {"status": "INITIALIZED", "authentication": result["authentication"]}


def migrate_governed_store(path: str | Path, root_anchor: Any) -> dict:
    """Explicitly upgrade an existing quorum store while preserving its revision."""
    anchor = validate_root(root_anchor)
    with _transaction(path) as connection:
        previous = distribution._stored(connection)
        authenticated = distribution.authenticate_key_policy(previous["envelope"], anchor["issuer_trust"])
        now = _current(anchor)
        connection.execute(_ROOT_TABLE)
        connection.execute(f"PRAGMA user_version={GOVERNED_STORE_VERSION}")
        _write_root(connection, anchor, anchor, [], now)
        state = {"root": anchor, "chain": [], "approvals": None, "root_accepted_at": now, "policy_row": previous}
        result = _report(authenticated, anchor, state)
    return {"status": "MIGRATED", "authentication": result["authentication"]}


def accept_governed_update(path: str | Path, root_anchor: Any, signed_policy: Any, *, rotation: Any = None) -> dict:
    anchor, envelope = validate_root(root_anchor), validate_quorum_envelope(signed_policy)
    rotation = validate_rotation(rotation) if rotation is not None else None
    with _transaction(path) as connection:
        state = _stored(connection, anchor)
        previous = state["policy_row"]
        retry = bool(rotation is not None and state["chain"] and sha256_object(rotation) == sha256_object(state["chain"][-1]))
        if rotation is not None and not retry:
            checked = verify_root_rotation(state["root"], rotation)
            state = dict(state, root=checked["root"], chain=state["chain"] + [checked["rotation"]], approvals=checked["approvals"])
        authenticated = distribution.authenticate_key_policy(envelope, state["root"]["issuer_trust"])
        now = _current(state["root"])
        revision = authenticated["policy"]["revision"]
        _require(revision >= previous["revision"], "policy_revision_rollback", "policy revision cannot decrease during governance updates")
        if revision == previous["revision"]:
            _require((rotation is None or retry) and authenticated["authentication"]["envelope_sha256"] == previous["envelope_sha256"],
                     "policy_revision_conflict", "rotation or changed policy requires a higher policy revision")
            status = "UNCHANGED"
        else:
            _require(not retry, "root_rotation_retry_conflict", "a retried rotation must carry its already accepted policy")
            _write_policy(connection, authenticated)
            state["policy_row"] = {"accepted_at": authenticated["authentication"]["evaluated_at"]}
            if rotation is not None:
                _write_root(connection, anchor, state["root"], state["chain"], now)
                state["root_accepted_at"] = now
            status = "ACCEPTED"
        result = _report(authenticated, anchor, state)
    return {"status": status, "authentication": result["authentication"]}

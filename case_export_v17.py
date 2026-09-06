#!/usr/bin/env python3
"""AI-DFIR v1.7 offline-verifiable case export.

Extends the v1.5 signed case-export ZIP format with the v1.7 investigation
ledger, checkpoint, signed checkpoint, and a manifest-bound checkpoint trust
store. Verification is local-only and never requires network access.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import stat
import tempfile
import zipfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from case_export_v15 import export_case as export_case_v15
from fleet_crypto import verify_envelope
from v17_integrity import (
    InvestigationEvent,
    InvestigationLedger,
    LedgerCheckpoint,
)
from v17_signing import (
    SIGNATURE_ALGORITHM,
    SignedLedgerCheckpoint,
    key_id_from_public_key_bytes,
    verify_signed_checkpoint,
)
from v17_provenance import (
    MAX_PROVENANCE_BYTES, PROVENANCE_PATH, ProvenanceError, validate_provenance,
)
from v17_reconstruction import reconstruct, strict_json
from v17_key_policy import (
    add_key_policy_arguments, evaluate_key_policy, key_policy_options, key_policy_report,
)
from v17_timestamp import (
    add_timestamp_arguments, evaluate_checkpoint_timestamp, timestamp_options, timestamp_report,
)


OFFLINE_EXPORT_SCHEMA = "ai-dfir/offline-case-export/v1.7"
OFFLINE_VERIFICATION_SCHEMA = "ai-dfir/offline-case-verification/v1.7"
CHECKPOINT_EXPORT_SCHEMA = "ai-dfir/ledger-checkpoint-export/v1.7"
TRUST_STORE_SCHEMA = "ai-dfir/trusted-checkpoint-signers/v1.7"
V15_MANIFEST_SCHEMA = "ai-dfir/case-export-manifest/v1.5"

V17_ROOT = "00_case/v17"
LEDGER_PATH = f"{V17_ROOT}/investigation_ledger.jsonl"
CHECKPOINT_PATH = f"{V17_ROOT}/checkpoint.json"
SIGNED_CHECKPOINT_PATH = f"{V17_ROOT}/signed_checkpoint.json"
TRUST_STORE_PATH = f"{V17_ROOT}/trusted_signers.json"
V15_MANIFEST_PATH = "CASE_EXPORT_MANIFEST.signed.json"

DEFAULT_MAX_MEMBERS = 20_000
DEFAULT_MAX_TOTAL_UNCOMPRESSED = 50 * 1024**3
DEFAULT_MAX_MEMBER_UNCOMPRESSED = 10 * 1024**3
DEFAULT_MAX_COMPRESSION_RATIO = 1_000.0
MAX_METADATA_BYTES = 16 * 1024**2

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class OfflinePackageError(ValueError):
    """Raised when an offline package is malformed or unsupported."""


def _finding(kind: str, *, severity: str = "critical", **details: Any) -> dict[str, Any]:
    return {"type": kind, "severity": severity, **details}


def _safe_member_name(name: str) -> bool:
    if not name or "\x00" in name or "\\" in name:
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    segments = name.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        return False
    return not PurePosixPath(name).is_absolute()


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) == stat.S_IFLNK


def _archive_safety_findings(
    archive: zipfile.ZipFile,
    *,
    max_members: int,
    max_total_uncompressed: int,
    max_member_uncompressed: int,
    max_compression_ratio: float,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    infos = archive.infolist()
    names = [item.filename for item in infos]

    if len(infos) > max_members:
        findings.append(
            _finding(
                "case_export_member_limit_exceeded",
                count=len(infos),
                limit=max_members,
            )
        )

    duplicates = sorted(
        name for name, count in Counter(names).items() if count > 1
    )
    if duplicates:
        findings.append(
            _finding(
                "case_export_duplicate_members",
                members=duplicates[:50],
            )
        )

    unsafe = sorted({name for name in names if not _safe_member_name(name)})
    if unsafe:
        findings.append(
            _finding(
                "case_export_unsafe_member_path",
                members=unsafe[:50],
            )
        )

    directories = sorted({item.filename for item in infos if item.is_dir()})
    if directories:
        findings.append(
            _finding(
                "case_export_directory_members",
                members=directories[:50],
            )
        )

    links = sorted({item.filename for item in infos if _is_symlink(item)})
    if links:
        findings.append(
            _finding(
                "case_export_symlink_members",
                members=links[:50],
            )
        )

    total = sum(item.file_size for item in infos)
    if total > max_total_uncompressed:
        findings.append(
            _finding(
                "case_export_uncompressed_size_limit_exceeded",
                size=total,
                limit=max_total_uncompressed,
            )
        )

    oversized = [
        item.filename
        for item in infos
        if item.file_size > max_member_uncompressed
    ]
    if oversized:
        findings.append(
            _finding(
                "case_export_member_size_limit_exceeded",
                members=oversized[:50],
                limit=max_member_uncompressed,
            )
        )

    suspicious_ratio: list[str] = []
    for item in infos:
        if item.file_size == 0:
            continue
        compressed = max(item.compress_size, 1)
        if item.file_size / compressed > max_compression_ratio:
            suspicious_ratio.append(item.filename)
    if suspicious_ratio:
        findings.append(
            _finding(
                "case_export_compression_ratio_limit_exceeded",
                members=suspicious_ratio[:50],
                limit=max_compression_ratio,
            )
        )

    return findings


def _read_json_member(
    archive: zipfile.ZipFile,
    path: str,
    *,
    max_bytes: int = MAX_METADATA_BYTES,
) -> dict[str, Any]:
    try:
        info = archive.getinfo(path)
    except KeyError as exc:
        raise OfflinePackageError(f"missing required member: {path}") from exc
    if info.file_size > max_bytes:
        raise OfflinePackageError(f"metadata member exceeds size limit: {path}")
    try:
        value = json.loads(archive.read(info).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfflinePackageError(f"invalid JSON member: {path}") from exc
    if not isinstance(value, dict):
        raise OfflinePackageError(f"JSON member must be an object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with archive.open(info, "r") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _verify_v15_manifest(
    archive: zipfile.ZipFile,
    *,
    export_public_key: Path,
    expected_tenant: str | None,
    expected_case: str | None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str]:
    findings: list[dict[str, Any]] = []
    envelope = _read_json_member(archive, V15_MANIFEST_PATH)

    try:
        payload = verify_envelope(export_public_key, envelope)
    except Exception as exc:
        findings.append(
            _finding(
                "case_export_signature_invalid",
                error=type(exc).__name__,
            )
        )
        return None, findings, "FAIL"

    if payload.get("schema") != V15_MANIFEST_SCHEMA:
        raise OfflinePackageError(
            f"unsupported case-export manifest schema: {payload.get('schema')!r}"
        )

    if expected_tenant and payload.get("tenant_id") != expected_tenant:
        findings.append(_finding("case_export_tenant_mismatch"))

    if expected_case and payload.get("case_id") != expected_case:
        findings.append(_finding("case_export_case_mismatch"))

    rows = payload.get("files")
    if not isinstance(rows, list):
        raise OfflinePackageError("case-export manifest files must be a list")

    expected: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise OfflinePackageError("case-export manifest file entry must be an object")
        path = row.get("path")
        sha256 = row.get("sha256")
        size = row.get("size")
        if not isinstance(path, str) or not _safe_member_name(path):
            raise OfflinePackageError("case-export manifest contains an unsafe file path")
        if path in expected:
            raise OfflinePackageError(f"duplicate manifest file path: {path}")
        if not isinstance(sha256, str) or not _HEX_64.fullmatch(sha256):
            raise OfflinePackageError(f"invalid SHA-256 in manifest for {path}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise OfflinePackageError(f"invalid size in manifest for {path}")
        expected[path] = row

    names = {
        item.filename
        for item in archive.infolist()
        if item.filename != V15_MANIFEST_PATH
    }

    for path, row in expected.items():
        if path not in names:
            findings.append(
                _finding("case_export_file_missing", path=path)
            )
            continue
        info = archive.getinfo(path)
        actual_sha256, actual_size = _hash_zip_member(archive, info)
        if actual_sha256 != row["sha256"]:
            findings.append(
                _finding(
                    "case_export_hash_mismatch",
                    path=path,
                    expected=row["sha256"],
                    actual=actual_sha256,
                )
            )
        if actual_size != row["size"]:
            findings.append(
                _finding(
                    "case_export_size_mismatch",
                    path=path,
                    expected=row["size"],
                    actual=actual_size,
                )
            )

    extras = sorted(names - set(expected))
    if extras:
        findings.append(
            _finding(
                "case_export_unmanifested_files",
                files=extras[:50],
            )
        )

    status = "PASS" if not findings else "FAIL"
    return payload, findings, status


def _checkpoint_export(signed: SignedLedgerCheckpoint) -> dict[str, Any]:
    return {
        "schema": CHECKPOINT_EXPORT_SCHEMA,
        "checkpoint_hash": signed.checkpoint.checkpoint_hash,
        "checkpoint": asdict(signed.checkpoint),
    }


def _trust_store(trusted_public_keys: Mapping[str, bytes]) -> dict[str, Any]:
    keys = []
    for key_id, raw_key in sorted(trusted_public_keys.items()):
        derived = key_id_from_public_key_bytes(raw_key)
        if key_id != derived:
            raise ValueError(f"trusted key ID does not match public key: {key_id}")
        keys.append(
            {
                "key_id": key_id,
                "algorithm": SIGNATURE_ALGORITHM,
                "public_key_hex": raw_key.hex(),
            }
        )
    return {
        "schema": TRUST_STORE_SCHEMA,
        "keys": keys,
    }


def _write_v17_metadata(
    root: Path,
    *,
    ledger: InvestigationLedger,
    signed_checkpoint: SignedLedgerCheckpoint,
    trusted_public_keys: Mapping[str, bytes],
) -> None:
    target = root / V17_ROOT
    target.mkdir(parents=True, exist_ok=True)
    (root / LEDGER_PATH).write_text(ledger.to_jsonl(), encoding="utf-8")
    (root / CHECKPOINT_PATH).write_text(
        json.dumps(_checkpoint_export(signed_checkpoint), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (root / SIGNED_CHECKPOINT_PATH).write_text(
        json.dumps(signed_checkpoint.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (root / TRUST_STORE_PATH).write_text(
        json.dumps(_trust_store(trusted_public_keys), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def export_case(
    case_root: str | Path,
    tenant_id: str,
    case_id: str,
    export_private_key: str | Path,
    out_zip: str | Path,
    *,
    ledger: InvestigationLedger,
    signed_checkpoint: SignedLedgerCheckpoint,
    trusted_public_keys: Mapping[str, bytes],
    include_evidence: bool = False,
    provenance: Mapping[str, Any] | None = None,
    checkpoint_key_policy: Mapping[str, Any] | None = None,
    require_checkpoint_key_policy: bool = False,
    key_policy_evaluated_at: str | None = None,
    expected_key_policy_sha256: str | None = None,
    checkpoint_policy_store: str | Path | None = None,
    policy_issuer_trust: Mapping[str, Any] | None = None,
    require_authenticated_key_policy: bool = False,
    minimum_policy_revision: int | None = None,
    policy_root_anchor: Mapping[str, Any] | None = None,
    minimum_root_version: int | None = None,
    timestamp_request: bytes | None = None,
    timestamp_response: bytes | None = None,
    tsa_ca_pem: bytes | None = None,
    expected_tsa_certificate_sha256: str | None = None,
    expected_timestamp_request_sha256: str | None = None,
    require_checkpoint_timestamp: bool = False,
) -> dict[str, Any]:
    """Create a v1.5-compatible signed export containing v1.7 verification state."""
    if ledger.case_id != case_id:
        raise ValueError("ledger case ID mismatch")
    if signed_checkpoint.checkpoint.case_id != case_id:
        raise ValueError("signed checkpoint case ID mismatch")

    ledger_valid, ledger_errors = ledger.verify(signed_checkpoint.checkpoint)
    if not ledger_valid:
        raise ValueError("ledger/checkpoint verification failed: " + "; ".join(ledger_errors))

    signature_valid, signature_errors = signed_checkpoint.verify_signature()
    if not signature_valid:
        raise ValueError(
            "checkpoint signature verification failed: " + "; ".join(signature_errors)
        )

    trusted_valid, trusted_errors = signed_checkpoint.verify_trusted(
        trusted_public_keys
    )
    if not trusted_valid:
        raise ValueError(
            "checkpoint signer trust verification failed: "
            + "; ".join(trusted_errors)
        )

    timestamp_result = evaluate_checkpoint_timestamp(
        signed_checkpoint=signed_checkpoint, tenant_id=tenant_id, case_id=case_id,
        timestamp_request=timestamp_request, timestamp_response=timestamp_response,
        tsa_ca_pem=tsa_ca_pem, expected_tsa_certificate_sha256=expected_tsa_certificate_sha256,
        expected_timestamp_request_sha256=expected_timestamp_request_sha256,
        require_checkpoint_timestamp=require_checkpoint_timestamp,
    )
    if timestamp_result["status"] == "FAIL":
        raise ValueError("checkpoint timestamp rejected export: " + "; ".join(
            item["code"] for item in timestamp_result["findings"]))

    policy_result = evaluate_key_policy(
        checkpoint_key_policy, signed_checkpoint=signed_checkpoint,
        tenant_id=tenant_id, case_id=case_id, evaluated_at=key_policy_evaluated_at,
        expected_policy_sha256=expected_key_policy_sha256,
        required=require_checkpoint_key_policy,
        policy_store=checkpoint_policy_store, issuer_trust=policy_issuer_trust,
        require_authenticated=require_authenticated_key_policy, minimum_revision=minimum_policy_revision,
        root_anchor=policy_root_anchor, minimum_root_version=minimum_root_version,
    )
    if policy_result["status"] == "FAIL":
        raise ValueError("checkpoint key policy rejected export: " + "; ".join(
            item["code"] for item in policy_result["findings"]
        ))

    source = Path(case_root).resolve()
    if not source.is_dir():
        raise ValueError("case root must be a directory")

    with tempfile.TemporaryDirectory(prefix="ai-dfir-v17-export-") as temp_dir:
        staged = Path(temp_dir) / "case"
        shutil.copytree(source, staged)
        _write_v17_metadata(
            staged,
            ledger=ledger,
            signed_checkpoint=signed_checkpoint,
            trusted_public_keys=trusted_public_keys,
        )
        provenance_path = staged / PROVENANCE_PATH
        if provenance is not None:
            provenance_path.write_text(json.dumps(provenance, ensure_ascii=False), encoding="utf-8")
        if provenance_path.exists():
            if provenance_path.stat().st_size > MAX_PROVENANCE_BYTES:
                raise ProvenanceError("provenance exceeds size limit")
            profile = strict_json(provenance_path.read_bytes())
            inventory = {}
            for item in staged.rglob("*"):
                if not item.is_file() or "__pycache__" in item.parts:
                    continue
                rel = item.relative_to(staged).as_posix()
                # Match v1.5 export selection so omitted evidence cannot be
                # represented as verified simply because it exists locally.
                if not include_evidence and any(x in rel for x in ("02_checkpoint", "04_activations", "17_representation_intake")):
                    continue
                inventory[rel] = {"sha256": _sha256_file(item)}
            validate_provenance(profile, case_id=case_id, ledger=ledger, files=inventory)
        elif any("provenance_type" in event.payload for event in ledger.events):
            raise ProvenanceError("ledger commitments require an investigation provenance profile")
        base = export_case_v15(
            staged,
            tenant_id,
            case_id,
            export_private_key,
            out_zip,
            include_evidence,
        )

    return {
        "schema": OFFLINE_EXPORT_SCHEMA,
        "zip": base["zip"],
        "sha256": base["sha256"],
        "file_count": base["file_count"],
        "tenant_id": tenant_id,
        "case_id": case_id,
        "created_utc": base.get("created_utc"),
        "include_evidence": include_evidence,
        "checkpoint_hash": signed_checkpoint.checkpoint.checkpoint_hash,
        "checkpoint_key_id": signed_checkpoint.key_id,
        "checkpoint_key_policy": policy_result,
        "checkpoint_timestamp": timestamp_result,
        "v15_compatible_manifest": True,
        "network_required_for_verification": False,
    }


def _parse_ledger(raw: bytes, *, case_id: str) -> InvestigationLedger:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OfflinePackageError("investigation ledger is not UTF-8") from exc

    events: list[InvestigationEvent] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise OfflinePackageError(
                f"investigation ledger contains a blank line at {line_number}"
            )
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise TypeError("event must be an object")
            event = InvestigationEvent(**obj)
        except (json.JSONDecodeError, TypeError) as exc:
            raise OfflinePackageError(
                f"invalid investigation ledger event at line {line_number}"
            ) from exc
        events.append(event)

    return InvestigationLedger(case_id, events)


def _parse_ledger_member(
    archive: zipfile.ZipFile,
    *,
    path: str,
    case_id: str,
) -> InvestigationLedger:
    try:
        info = archive.getinfo(path)
    except KeyError as exc:
        raise OfflinePackageError(f"missing required member: {path}") from exc

    events: list[InvestigationEvent] = []
    with archive.open(info, "r") as raw_stream:
        with io.TextIOWrapper(raw_stream, encoding="utf-8", errors="strict") as stream:
            try:
                for line_number, line in enumerate(stream, start=1):
                    if len(line) > MAX_METADATA_BYTES:
                        raise OfflinePackageError(
                            f"investigation ledger event exceeds size limit at line {line_number}"
                        )
                    if not line.strip():
                        raise OfflinePackageError(
                            f"investigation ledger contains a blank line at {line_number}"
                        )
                    try:
                        obj = json.loads(line)
                        if not isinstance(obj, dict):
                            raise TypeError("event must be an object")
                        event = InvestigationEvent(**obj)
                    except (json.JSONDecodeError, TypeError) as exc:
                        raise OfflinePackageError(
                            f"invalid investigation ledger event at line {line_number}"
                        ) from exc
                    events.append(event)
            except UnicodeDecodeError as exc:
                raise OfflinePackageError("investigation ledger is not UTF-8") from exc

    return InvestigationLedger(case_id, events)


def _parse_checkpoint_export(
    value: dict[str, Any],
) -> tuple[LedgerCheckpoint, str]:
    if value.get("schema") != CHECKPOINT_EXPORT_SCHEMA:
        raise OfflinePackageError("unsupported checkpoint export schema")
    checkpoint_value = value.get("checkpoint")
    if not isinstance(checkpoint_value, dict):
        raise OfflinePackageError("checkpoint export is missing checkpoint")
    try:
        checkpoint = LedgerCheckpoint(**checkpoint_value)
    except TypeError as exc:
        raise OfflinePackageError("invalid checkpoint structure") from exc
    checkpoint_hash = value.get("checkpoint_hash")
    if not isinstance(checkpoint_hash, str) or not _HEX_64.fullmatch(checkpoint_hash):
        raise OfflinePackageError("invalid checkpoint hash encoding")
    return checkpoint, checkpoint_hash


def _parse_signed_checkpoint(value: dict[str, Any]) -> SignedLedgerCheckpoint:
    checkpoint_value = value.get("checkpoint")
    if not isinstance(checkpoint_value, dict):
        raise OfflinePackageError("signed checkpoint is missing checkpoint")
    try:
        checkpoint = LedgerCheckpoint(**checkpoint_value)
        return SignedLedgerCheckpoint(
            checkpoint=checkpoint,
            key_id=value["key_id"],
            public_key_hex=value["public_key_hex"],
            signature_hex=value["signature_hex"],
            signed_at=value["signed_at"],
            schema=value["schema"],
            signature_algorithm=value["signature_algorithm"],
        )
    except (KeyError, TypeError) as exc:
        raise OfflinePackageError("invalid signed checkpoint structure") from exc


def _parse_trust_store(value: dict[str, Any]) -> dict[str, bytes]:
    if value.get("schema") != TRUST_STORE_SCHEMA:
        raise OfflinePackageError("unsupported checkpoint trust-store schema")
    rows = value.get("keys")
    if not isinstance(rows, list):
        raise OfflinePackageError("checkpoint trust-store keys must be a list")

    trusted: dict[str, bytes] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise OfflinePackageError("checkpoint trust-store entry must be an object")
        if row.get("algorithm") != SIGNATURE_ALGORITHM:
            raise OfflinePackageError("unsupported checkpoint trust-store algorithm")
        key_id = row.get("key_id")
        public_key_hex = row.get("public_key_hex")
        if not isinstance(key_id, str) or not isinstance(public_key_hex, str):
            raise OfflinePackageError("invalid checkpoint trust-store entry")
        try:
            raw_key = bytes.fromhex(public_key_hex)
        except ValueError as exc:
            raise OfflinePackageError("malformed trusted public key") from exc
        if len(raw_key) != 32:
            raise OfflinePackageError("invalid trusted Ed25519 public key length")
        if key_id_from_public_key_bytes(raw_key) != key_id:
            raise OfflinePackageError("trusted key ID does not match public key")
        if key_id in trusted:
            raise OfflinePackageError(f"duplicate trusted key ID: {key_id}")
        trusted[key_id] = raw_key
    return trusted


def _failure_report(
    *,
    zip_sha256: str | None,
    findings: list[dict[str, Any]],
    failure_class: str,
    package_safety: str = "FAIL",
) -> dict[str, Any]:
    return {
        "schema": OFFLINE_VERIFICATION_SCHEMA,
        "status": "FAIL",
        "valid": False,
        "offline": True,
        "network_required": False,
        "failure_class": failure_class,
        "zip_sha256": zip_sha256,
        "package_safety": package_safety,
        "export_manifest_integrity": "NOT_RUN",
        "artifact_integrity": "NOT_RUN",
        "ledger_integrity": "NOT_RUN",
        "checkpoint_integrity": "NOT_RUN",
        "provenance_integrity": "NOT_RUN",
        "checkpoint_key_policy": key_policy_report(),
        "checkpoint_timestamp": timestamp_report(),
        "signature_valid": False,
        "signer_trusted": False,
        "findings": findings,
    }


def verify_case(
    zip_path: str | Path,
    export_public_key: str | Path,
    *,
    expected_tenant: str | None = None,
    expected_case: str | None = None,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_total_uncompressed: int = DEFAULT_MAX_TOTAL_UNCOMPRESSED,
    max_member_uncompressed: int = DEFAULT_MAX_MEMBER_UNCOMPRESSED,
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
    require_provenance: bool = False,
    include_reconstruction: bool = False,
    replay_transforms: bool = False,
    checkpoint_key_policy: Mapping[str, Any] | None = None,
    require_checkpoint_key_policy: bool = False,
    key_policy_evaluated_at: str | None = None,
    expected_key_policy_sha256: str | None = None,
    checkpoint_policy_store: str | Path | None = None,
    policy_issuer_trust: Mapping[str, Any] | None = None,
    require_authenticated_key_policy: bool = False,
    minimum_policy_revision: int | None = None,
    policy_root_anchor: Mapping[str, Any] | None = None,
    minimum_root_version: int | None = None,
    timestamp_request: bytes | None = None,
    timestamp_response: bytes | None = None,
    tsa_ca_pem: bytes | None = None,
    expected_tsa_certificate_sha256: str | None = None,
    expected_timestamp_request_sha256: str | None = None,
    require_checkpoint_timestamp: bool = False,
) -> dict[str, Any]:
    """Verify a v1.7 case export using local files only."""
    path = Path(zip_path)
    if not path.is_file():
        raise FileNotFoundError(path)

    zip_digest = _sha256_file(path)
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return _failure_report(
            zip_sha256=zip_digest,
            findings=[_finding("case_export_bad_zip")],
            failure_class="malformed-package",
        )

    with archive:
        safety = _archive_safety_findings(
            archive,
            max_members=max_members,
            max_total_uncompressed=max_total_uncompressed,
            max_member_uncompressed=max_member_uncompressed,
            max_compression_ratio=max_compression_ratio,
        )
        if safety:
            return _failure_report(
                zip_sha256=zip_digest,
                findings=safety,
                failure_class="malformed-package",
            )

        names = {item.filename for item in archive.infolist()}
        required = {
            V15_MANIFEST_PATH,
            LEDGER_PATH,
            CHECKPOINT_PATH,
            SIGNED_CHECKPOINT_PATH,
            TRUST_STORE_PATH,
        }
        missing = sorted(required - names)
        if missing:
            return _failure_report(
                zip_sha256=zip_digest,
                findings=[
                    _finding("offline_verification_required_member_missing", members=missing)
                ],
                failure_class="unsupported-package",
                package_safety="PASS",
            )

        try:
            payload, export_findings, export_status = _verify_v15_manifest(
                archive,
                export_public_key=Path(export_public_key),
                expected_tenant=expected_tenant,
                expected_case=expected_case,
            )
        except OfflinePackageError as exc:
            return _failure_report(
                zip_sha256=zip_digest,
                findings=[_finding("case_export_manifest_malformed", error=str(exc))],
                failure_class="malformed-package",
                package_safety="PASS",
            )

        if payload is None:
            report = _failure_report(
                zip_sha256=zip_digest,
                findings=export_findings,
                failure_class="verification-failed",
                package_safety="PASS",
            )
            report["export_manifest_integrity"] = "FAIL"
            report["artifact_integrity"] = "NOT_TRUSTED"
            return report

        artifact_findings = [
            item
            for item in export_findings
            if item["type"]
            in {
                "case_export_file_missing",
                "case_export_hash_mismatch",
                "case_export_size_mismatch",
                "case_export_unmanifested_files",
            }
        ]
        identity_findings = [
            item for item in export_findings if item not in artifact_findings
        ]

        case_id = payload.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            return _failure_report(
                zip_sha256=zip_digest,
                findings=[_finding("case_export_case_id_missing")],
                failure_class="malformed-package",
                package_safety="PASS",
            )

        try:
            ledger = _parse_ledger_member(
                archive,
                path=LEDGER_PATH,
                case_id=case_id,
            )
            checkpoint_export = _read_json_member(archive, CHECKPOINT_PATH)
            checkpoint, exported_checkpoint_hash = _parse_checkpoint_export(
                checkpoint_export
            )
            signed = _parse_signed_checkpoint(
                _read_json_member(archive, SIGNED_CHECKPOINT_PATH)
            )
            trusted = _parse_trust_store(
                _read_json_member(archive, TRUST_STORE_PATH)
            )
        except OfflinePackageError as exc:
            report = _failure_report(
                zip_sha256=zip_digest,
                findings=export_findings
                + [_finding("offline_verification_metadata_malformed", error=str(exc))],
                failure_class="malformed-package",
                package_safety="PASS",
            )
            report["export_manifest_integrity"] = export_status
            report["artifact_integrity"] = (
                "FAIL" if artifact_findings else export_status
            )
            return report

        ledger_valid, ledger_errors = ledger.verify(signed.checkpoint)
        signature_valid, signature_errors = signed.verify_signature()
        trusted_valid, trusted_errors = signed.verify_trusted(trusted)
        combined_valid, combined_errors = verify_signed_checkpoint(
            ledger=ledger,
            signed_checkpoint=signed,
            trusted_public_keys=trusted,
        )

        # The exported trust store records the exporter's attestation. An
        # independent verifier may impose a stricter, externally supplied
        # policy. It can only narrow trust, never make an untrusted bundle pass.
        manifest_signer_trusted = trusted_valid
        policy_result = evaluate_key_policy(
            checkpoint_key_policy, signed_checkpoint=signed,
            tenant_id=payload.get("tenant_id"), case_id=case_id,
            evaluated_at=key_policy_evaluated_at,
            expected_policy_sha256=expected_key_policy_sha256,
            required=require_checkpoint_key_policy,
            policy_store=checkpoint_policy_store, issuer_trust=policy_issuer_trust,
            require_authenticated=require_authenticated_key_policy, minimum_revision=minimum_policy_revision,
            root_anchor=policy_root_anchor, minimum_root_version=minimum_root_version,
        )
        policy_valid = policy_result["status"] in {"PASS", "NOT_CONFIGURED"}
        trusted_valid = trusted_valid and policy_valid
        combined_valid = combined_valid and policy_valid
        policy_errors = [item["code"] for item in policy_result["findings"]]

        timestamp_result = evaluate_checkpoint_timestamp(
            signed_checkpoint=signed, tenant_id=payload.get("tenant_id"), case_id=case_id,
            timestamp_request=timestamp_request, timestamp_response=timestamp_response,
            tsa_ca_pem=tsa_ca_pem, expected_tsa_certificate_sha256=expected_tsa_certificate_sha256,
            expected_timestamp_request_sha256=expected_timestamp_request_sha256,
            require_checkpoint_timestamp=require_checkpoint_timestamp,
        )
        timestamp_valid = timestamp_result["status"] in {"PASS", "NOT_CONFIGURED"}
        combined_valid = combined_valid and timestamp_valid
        timestamp_errors = [item["code"] for item in timestamp_result["findings"]]

        checkpoint_errors: list[str] = []
        if checkpoint != signed.checkpoint:
            checkpoint_errors.append("checkpoint export does not match signed checkpoint")
        if checkpoint.checkpoint_hash != exported_checkpoint_hash:
            checkpoint_errors.append("checkpoint export hash mismatch")
        if signed.checkpoint.checkpoint_hash != exported_checkpoint_hash:
            checkpoint_errors.append("signed checkpoint hash mismatch")
        if checkpoint.case_id != case_id:
            checkpoint_errors.append("checkpoint case_id mismatch")

        findings = list(export_findings)
        findings.extend(
            _finding("investigation_ledger_invalid", error=error)
            for error in ledger_errors
        )
        findings.extend(
            _finding("checkpoint_binding_invalid", error=error)
            for error in checkpoint_errors
        )
        findings.extend(
            _finding("checkpoint_signature_invalid", error=error)
            for error in signature_errors
        )
        if signature_valid and not trusted_valid:
            trust_only = [error for error in trusted_errors if error not in signature_errors]
            findings.extend(
                _finding("checkpoint_signer_untrusted", error=error)
                for error in trust_only
            )
        findings.extend(
            _finding("checkpoint_key_policy_failed", code=item["code"], error=item["detail"])
            for item in policy_result["findings"]
        )
        findings.extend(
            _finding("checkpoint_timestamp_failed", code=item["code"], error=item["detail"])
            for item in timestamp_result["findings"]
        )

        checkpoint_valid = not checkpoint_errors
        provenance_status = "NOT_PRESENT"
        reconstruction = None
        if PROVENANCE_PATH in names:
            provenance_status = "NOT_RUN"
            # Interpret records only after the manifest, bytes, and signed
            # ledger pass, using this same archive handle and parsed ledger.
            if export_status == "PASS" and combined_valid and checkpoint_valid:
                try:
                    verified_files = {row["path"]: row for row in payload["files"]}

                    def read_verified_member(member):
                        info = archive.getinfo(member)
                        if info.file_size > MAX_PROVENANCE_BYTES:
                            raise ProvenanceError("provenance/replay member exceeds size limit")
                        raw = archive.read(info)
                        if hashlib.sha256(raw).hexdigest() != verified_files[member]["sha256"]:
                            raise ProvenanceError("member changed after inventory verification")
                        return raw

                    profile = strict_json(read_verified_member(PROVENANCE_PATH))
                    index = validate_provenance(
                        profile, case_id=case_id, ledger=ledger,
                        files=verified_files,
                    )
                    provenance_status = "PASS"
                    if include_reconstruction or replay_transforms:
                        reconstruction = reconstruct(
                            profile, index, ledger, read_artifact=read_verified_member,
                            replay_transforms=replay_transforms,
                        )
                except (ProvenanceError, ValueError, TypeError, KeyError, RecursionError) as exc:
                    provenance_status = "FAIL"
                    findings.append(_finding("investigation_provenance_invalid", error=str(exc)))
        elif (require_provenance or include_reconstruction or replay_transforms
              or any("provenance_type" in event.payload for event in ledger.events)):
            provenance_status = "FAIL"
            findings.append(_finding("investigation_provenance_missing"))

        overall = (
            export_status == "PASS"
            and ledger_valid
            and checkpoint_valid
            and signature_valid
            and trusted_valid
            and combined_valid
            and provenance_status in {"PASS", "NOT_PRESENT"}
        )

        report = {
            "schema": OFFLINE_VERIFICATION_SCHEMA,
            "status": "PASS" if overall else "FAIL",
            "valid": overall,
            "offline": True,
            "network_required": False,
            "failure_class": None if overall else "verification-failed",
            "zip_sha256": zip_digest,
            "tenant_id": payload.get("tenant_id"),
            "case_id": case_id,
            "include_evidence": bool(payload.get("include_evidence")),
            "file_count": len(payload.get("files") or []),
            "package_safety": "PASS",
            "export_manifest_integrity": export_status,
            "artifact_integrity": (
                "FAIL"
                if artifact_findings
                else ("FAIL" if identity_findings else "PASS")
            ),
            "ledger_integrity": "PASS" if ledger_valid else "FAIL",
            "checkpoint_integrity": "PASS" if checkpoint_valid else "FAIL",
            "provenance_integrity": provenance_status,
            "checkpoint_hash": signed.checkpoint.checkpoint_hash,
            "signature_valid": signature_valid,
            "signer_trusted": trusted_valid,
            "manifest_signer_trusted": manifest_signer_trusted,
            "signer_trust_source": "export-manifest-and-external-policy" if checkpoint_key_policy is not None or checkpoint_policy_store is not None else "export-manifest",
            "checkpoint_key_policy": policy_result,
            "checkpoint_timestamp": timestamp_result,
            "signer_key_id": signed.key_id,
            "combined_checkpoint_verification": combined_valid,
            "findings": findings,
            "verification_errors": sorted(
                set(ledger_errors + checkpoint_errors + signature_errors + combined_errors + policy_errors + timestamp_errors)
            ),
        }
        if overall and reconstruction is not None:
            report["reconstruction"] = reconstruction
        return report


def _load_ledger(path: Path, case_id: str) -> InvestigationLedger:
    return _parse_ledger(path.read_bytes(), case_id=case_id)


def _load_signed_checkpoint(path: Path) -> SignedLedgerCheckpoint:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise OfflinePackageError("signed checkpoint file must contain an object")
    return _parse_signed_checkpoint(value)


def _load_trust_store(path: Path) -> dict[str, bytes]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise OfflinePackageError("trust-store file must contain an object")
    return _parse_trust_store(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or independently verify AI-DFIR v1.7 offline case exports."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("--case-root", required=True)
    create.add_argument("--tenant", required=True)
    create.add_argument("--case", required=True)
    create.add_argument("--export-private-key", required=True)
    create.add_argument("--ledger", required=True)
    create.add_argument("--signed-checkpoint", required=True)
    create.add_argument("--trusted-signers", required=True)
    create.add_argument("--out", required=True)
    create.add_argument("--include-evidence", action="store_true")
    create.add_argument("--provenance", help="Optional validated investigation provenance JSON")
    add_key_policy_arguments(create)
    add_timestamp_arguments(create)

    verify = sub.add_parser("verify")
    verify.add_argument("--zip", required=True)
    verify.add_argument("--export-public-key", required=True)
    verify.add_argument("--tenant")
    verify.add_argument("--case")
    verify.add_argument("--out")
    verify.add_argument("--require-provenance", action="store_true")
    add_key_policy_arguments(verify)
    add_timestamp_arguments(verify)
    verify.add_argument(
        "--max-members",
        type=int,
        default=DEFAULT_MAX_MEMBERS,
    )
    verify.add_argument(
        "--max-total-uncompressed-gib",
        type=float,
        default=(
            DEFAULT_MAX_TOTAL_UNCOMPRESSED
            / 1024**3
        ),
    )
    verify.add_argument(
        "--max-member-uncompressed-gib",
        type=float,
        default=(
            DEFAULT_MAX_MEMBER_UNCOMPRESSED
            / 1024**3
        ),
    )
    verify.add_argument(
        "--max-compression-ratio",
        type=float,
        default=DEFAULT_MAX_COMPRESSION_RATIO,
    )

    args = parser.parse_args()

    try:
        if args.command == "create":
            result = export_case(
                args.case_root,
                args.tenant,
                args.case,
                args.export_private_key,
                args.out,
                ledger=_load_ledger(Path(args.ledger), args.case),
                signed_checkpoint=_load_signed_checkpoint(Path(args.signed_checkpoint)),
                trusted_public_keys=_load_trust_store(Path(args.trusted_signers)),
                include_evidence=args.include_evidence,
                provenance=strict_json(Path(args.provenance).read_bytes()) if args.provenance else None,
                **key_policy_options(args),
                **timestamp_options(args),
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        result = verify_case(
            args.zip,
            args.export_public_key,
            expected_tenant=args.tenant,
            expected_case=args.case,
            require_provenance=args.require_provenance,
            **key_policy_options(args),
            **timestamp_options(args),
            max_members=args.max_members,
            max_total_uncompressed=int(
                args.max_total_uncompressed_gib
                * 1024**3
            ),
            max_member_uncompressed=int(
                args.max_member_uncompressed_gib
                * 1024**3
            ),
            max_compression_ratio=(
                args.max_compression_ratio
            ),
        )
        text = json.dumps(result, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            print(text)

        if result["valid"]:
            return 0
        if result.get("failure_class") in {
            "malformed-package",
            "unsupported-package",
        }:
            return 2
        return 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "schema": OFFLINE_VERIFICATION_SCHEMA,
                    "status": "ERROR",
                    "valid": False,
                    "offline": True,
                    "network_required": False,
                    "failure_class": "runtime-error",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

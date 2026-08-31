from __future__ import annotations

import json
import shutil
import socket
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v15 import export_case as export_case_v15
from case_export_v17 import (
    CHECKPOINT_PATH,
    LEDGER_PATH,
    SIGNED_CHECKPOINT_PATH,
    TRUST_STORE_PATH,
    _write_v17_metadata,
    export_case,
    verify_case,
)
from fleet_crypto import generate
from v17_integrity import InvestigationLedger
from v17_signing import SignedLedgerCheckpoint


CHECKPOINT_PRIVATE_KEY = bytes(range(1, 33))


def _checkpoint_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(CHECKPOINT_PRIVATE_KEY)


def _base_case(tmp_path: Path) -> Path:
    root = tmp_path / "case"
    (root / "00_case").mkdir(parents=True)
    (root / "00_case" / "case.json").write_text(
        json.dumps(
            {
                "schema": "ai-dfir/case/v1.5",
                "case_id": "CASE-OFFLINE-001",
                "tenant_id": "TENANT-001",
                "tool_version": "1.7",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (root / "note.txt").write_text(
        "AI-DFIR deterministic offline verification fixture\n",
        encoding="utf-8",
    )
    return root


def _ledger_and_signed():
    ledger = InvestigationLedger("CASE-OFFLINE-001")
    ledger.append(
        event_type="EVIDENCE_ACQUIRED",
        timestamp="2026-08-31T12:00:00Z",
        actor="collector:test",
        payload={
            "artifact_id": "ART-001",
            "sha256": "a" * 64,
        },
    )
    ledger.append(
        event_type="ANALYST_REVIEWED",
        timestamp="2026-08-31T12:01:00Z",
        actor="analyst:test",
        payload={
            "finding_id": "F-001",
            "disposition": "confirmed",
        },
    )
    checkpoint = ledger.checkpoint(created_at="2026-08-31T12:02:00Z")
    signed = SignedLedgerCheckpoint.sign(
        checkpoint=checkpoint,
        private_key=_checkpoint_private_key(),
        signed_at="2026-08-31T12:03:00Z",
    )
    return ledger, signed


def _export_keys(tmp_path: Path, prefix: str = "export") -> tuple[Path, Path]:
    private_key = tmp_path / f"{prefix}.pem"
    public_key = tmp_path / f"{prefix}.pub.pem"
    generate(private_key, public_key)
    return private_key, public_key


def _trusted(signed: SignedLedgerCheckpoint) -> dict[str, bytes]:
    return {signed.key_id: bytes.fromhex(signed.public_key_hex)}


def _valid_bundle(tmp_path: Path):
    root = _base_case(tmp_path)
    ledger, signed = _ledger_and_signed()
    private_key, public_key = _export_keys(tmp_path)
    out_zip = tmp_path / "case.zip"
    export_case(
        root,
        "TENANT-001",
        "CASE-OFFLINE-001",
        private_key,
        out_zip,
        ledger=ledger,
        signed_checkpoint=signed,
        trusted_public_keys=_trusted(signed),
    )
    return out_zip, public_key, ledger, signed, private_key


def _rewrite_zip(
    source: Path,
    destination: Path,
    *,
    replacements: dict[str, bytes] | None = None,
    drop: set[str] | None = None,
) -> None:
    replacements = replacements or {}
    drop = drop or set()
    with zipfile.ZipFile(source, "r") as src, zipfile.ZipFile(
        destination, "w", zipfile.ZIP_DEFLATED
    ) as dst:
        for info in src.infolist():
            if info.filename in drop:
                continue
            raw = replacements.get(info.filename, src.read(info.filename))
            dst.writestr(info, raw)


def _direct_v15_package(
    tmp_path: Path,
    *,
    mutate=None,
    trusted_public_keys: dict[str, bytes] | None = None,
):
    root = _base_case(tmp_path)
    ledger, signed = _ledger_and_signed()
    if trusted_public_keys is None:
        trusted_public_keys = _trusted(signed)
    _write_v17_metadata(
        root,
        ledger=ledger,
        signed_checkpoint=signed,
        trusted_public_keys=trusted_public_keys,
    )
    if mutate is not None:
        mutate(root, ledger, signed)
    private_key, public_key = _export_keys(tmp_path, "direct")
    out_zip = tmp_path / "direct.zip"
    export_case_v15(
        root,
        "TENANT-001",
        "CASE-OFFLINE-001",
        private_key,
        out_zip,
    )
    return out_zip, public_key, ledger, signed


def test_valid_offline_bundle_passes_and_is_location_independent(
    tmp_path: Path,
    monkeypatch,
):
    bundle, public_key, _, _, _ = _valid_bundle(tmp_path)

    def no_network(*args, **kwargs):
        raise AssertionError("offline verifier attempted network access")

    monkeypatch.setattr(socket, "create_connection", no_network)

    first = verify_case(
        bundle,
        public_key,
        expected_tenant="TENANT-001",
        expected_case="CASE-OFFLINE-001",
    )

    copied = tmp_path / "detached" / "case.zip"
    copied.parent.mkdir()
    shutil.copy2(bundle, copied)
    second = verify_case(
        copied,
        public_key,
        expected_tenant="TENANT-001",
        expected_case="CASE-OFFLINE-001",
    )

    assert first == second
    assert first["valid"]
    assert first["status"] == "PASS"
    assert first["package_safety"] == "PASS"
    assert first["artifact_integrity"] == "PASS"
    assert first["ledger_integrity"] == "PASS"
    assert first["checkpoint_integrity"] == "PASS"
    assert first["signature_valid"] is True
    assert first["signer_trusted"] is True
    assert first["network_required"] is False


def test_exporter_rejects_untrusted_checkpoint_signer(tmp_path: Path):
    root = _base_case(tmp_path)
    ledger, signed = _ledger_and_signed()
    private_key, _ = _export_keys(tmp_path)

    with pytest.raises(ValueError, match="signer trust verification failed"):
        export_case(
            root,
            "TENANT-001",
            "CASE-OFFLINE-001",
            private_key,
            tmp_path / "should-not-exist.zip",
            ledger=ledger,
            signed_checkpoint=signed,
            trusted_public_keys={},
        )


def test_bad_zip_is_classified_as_malformed_package(tmp_path: Path):
    bundle = tmp_path / "not-a-zip.bin"
    bundle.write_bytes(b"not a zip archive")

    result = verify_case(
        bundle,
        tmp_path / "unused-export-public-key.pem",
    )

    assert not result["valid"]
    assert result["failure_class"] == "malformed-package"
    assert any(
        item["type"] == "case_export_bad_zip"
        for item in result["findings"]
    )


def test_tampered_exported_artifact_is_detected(tmp_path: Path):
    bundle, public_key, _, _, _ = _valid_bundle(tmp_path)
    tampered = tmp_path / "tampered.zip"
    _rewrite_zip(
        bundle,
        tampered,
        replacements={"note.txt": b"tampered\n"},
    )

    result = verify_case(tampered, public_key)

    assert not result["valid"]
    assert result["artifact_integrity"] == "FAIL"
    assert any(
        item["type"] == "case_export_hash_mismatch"
        for item in result["findings"]
    )


def test_missing_exported_artifact_is_detected(tmp_path: Path):
    bundle, public_key, _, _, _ = _valid_bundle(tmp_path)
    missing = tmp_path / "missing.zip"
    _rewrite_zip(bundle, missing, drop={"note.txt"})

    result = verify_case(missing, public_key)

    assert not result["valid"]
    assert result["artifact_integrity"] == "FAIL"
    assert any(
        item["type"] == "case_export_file_missing"
        for item in result["findings"]
    )


def test_ledger_tamper_is_detected_after_valid_export_signature(tmp_path: Path):
    def mutate(root: Path, ledger, signed):
        path = root / LEDGER_PATH
        rows = path.read_text(encoding="utf-8").splitlines()
        first = json.loads(rows[0])
        first["actor"] = "attacker"
        rows[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    bundle, public_key, _, _ = _direct_v15_package(tmp_path, mutate=mutate)

    result = verify_case(bundle, public_key)

    assert not result["valid"]
    assert result["export_manifest_integrity"] == "PASS"
    assert result["artifact_integrity"] == "PASS"
    assert result["ledger_integrity"] == "FAIL"
    assert any(
        item["type"] == "investigation_ledger_invalid"
        for item in result["findings"]
    )


def test_checkpoint_export_substitution_is_detected(tmp_path: Path):
    def mutate(root: Path, ledger, signed):
        path = root / CHECKPOINT_PATH
        value = json.loads(path.read_text(encoding="utf-8"))
        value["checkpoint"]["head_hash"] = "0" * 64
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    bundle, public_key, _, _ = _direct_v15_package(tmp_path, mutate=mutate)

    result = verify_case(bundle, public_key)

    assert not result["valid"]
    assert result["export_manifest_integrity"] == "PASS"
    assert result["checkpoint_integrity"] == "FAIL"
    assert any(
        item["type"] == "checkpoint_binding_invalid"
        for item in result["findings"]
    )


def test_invalid_checkpoint_signature_is_detected(tmp_path: Path):
    def mutate(root: Path, ledger, signed):
        path = root / SIGNED_CHECKPOINT_PATH
        value = json.loads(path.read_text(encoding="utf-8"))
        signature = value["signature_hex"]
        value["signature_hex"] = (
            ("00" if not signature.startswith("00") else "01")
            + signature[2:]
        )
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    bundle, public_key, _, _ = _direct_v15_package(tmp_path, mutate=mutate)

    result = verify_case(bundle, public_key)

    assert not result["valid"]
    assert result["signature_valid"] is False
    assert result["signer_trusted"] is False
    assert any(
        item["type"] == "checkpoint_signature_invalid"
        for item in result["findings"]
    )


def test_valid_signature_from_untrusted_signer_is_distinguished(tmp_path: Path):
    bundle, public_key, _, signed = _direct_v15_package(
        tmp_path,
        trusted_public_keys={},
    )

    result = verify_case(bundle, public_key)

    assert not result["valid"]
    assert result["signature_valid"] is True
    assert result["signer_trusted"] is False
    assert result["signer_key_id"] == signed.key_id
    assert any(
        item["type"] == "checkpoint_signer_untrusted"
        for item in result["findings"]
    )


def test_wrong_export_trust_anchor_fails_before_checkpoint_trust(tmp_path: Path):
    bundle, _, _, _, _ = _valid_bundle(tmp_path)
    _, wrong_public_key = _export_keys(tmp_path, "wrong")

    result = verify_case(bundle, wrong_public_key)

    assert not result["valid"]
    assert result["export_manifest_integrity"] == "FAIL"
    assert result["artifact_integrity"] == "NOT_TRUSTED"
    assert any(
        item["type"] == "case_export_signature_invalid"
        for item in result["findings"]
    )


def test_malformed_signed_checkpoint_is_rejected(tmp_path: Path):
    def mutate(root: Path, ledger, signed):
        (root / SIGNED_CHECKPOINT_PATH).write_text(
            "{not-json",
            encoding="utf-8",
        )

    bundle, public_key, _, _ = _direct_v15_package(tmp_path, mutate=mutate)

    result = verify_case(bundle, public_key)

    assert not result["valid"]
    assert result["failure_class"] == "malformed-package"
    assert result["export_manifest_integrity"] == "PASS"
    assert any(
        item["type"] == "offline_verification_metadata_malformed"
        for item in result["findings"]
    )


def test_path_traversal_member_is_rejected_before_content_verification(
    tmp_path: Path,
):
    bundle, public_key, _, _, _ = _valid_bundle(tmp_path)
    hostile = tmp_path / "hostile.zip"
    shutil.copy2(bundle, hostile)
    with zipfile.ZipFile(hostile, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.txt", b"nope")

    result = verify_case(hostile, public_key)

    assert not result["valid"]
    assert result["failure_class"] == "malformed-package"
    assert any(
        item["type"] == "case_export_unsafe_member_path"
        for item in result["findings"]
    )


def test_duplicate_archive_member_is_rejected(tmp_path: Path):
    bundle, public_key, _, _, _ = _valid_bundle(tmp_path)
    duplicate = tmp_path / "duplicate.zip"
    shutil.copy2(bundle, duplicate)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(duplicate, "a", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("note.txt", b"duplicate")

    result = verify_case(duplicate, public_key)

    assert not result["valid"]
    assert result["failure_class"] == "malformed-package"
    assert any(
        item["type"] == "case_export_duplicate_members"
        for item in result["findings"]
    )


def test_v15_export_without_v17_verification_state_is_unsupported(tmp_path: Path):
    root = _base_case(tmp_path)
    private_key, public_key = _export_keys(tmp_path)
    bundle = tmp_path / "v15-only.zip"
    export_case_v15(
        root,
        "TENANT-001",
        "CASE-OFFLINE-001",
        private_key,
        bundle,
    )

    result = verify_case(bundle, public_key)

    assert not result["valid"]
    assert result["failure_class"] == "unsupported-package"
    assert any(
        item["type"] == "offline_verification_required_member_missing"
        for item in result["findings"]
    )

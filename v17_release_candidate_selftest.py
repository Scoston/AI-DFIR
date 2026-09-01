#!/usr/bin/env python3
"""Deterministic known-answer assurance for the AI-DFIR v1.7 release line."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import export_case, verify_case
from v17_integrity import InvestigationLedger
from v17_signing import SignedLedgerCheckpoint, public_key_bytes


EXPECTED_CHECKPOINT_HASH = "ee58a5a556078e8a3db7d8cd232459cd41bd2799e74e3fe6c81aaf6831f02b93"
EXPECTED_CHECKPOINT_KEY_ID = "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8"
EXPECTED_EXPORT_PUBLIC_KEY_SHA256 = "c945cbf2a5602002141e2fb9d17054d6ca069951df73f49d1f8aca87f9878f60"


def _write_export_keys(private_path: Path, public_path: Path) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    public_key = private_key.public_key()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    import hashlib

    return hashlib.sha256(public_key_bytes(public_key)).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-v17-rc-kat-") as tmp:
        root = Path(tmp)
        case_root = root / "case"
        (case_root / "00_case").mkdir(parents=True)
        (case_root / "00_case" / "case.json").write_text(
            json.dumps(
                {
                    "schema": "ai-dfir/case/v1.5",
                    "case_id": "V17-RC-KAT-001",
                    "tenant_id": "V17-RC-KAT",
                    "tool_version": "1.7",
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        (case_root / "known-answer.txt").write_text(
            "AI-DFIR v1.7 release-candidate synthetic known-answer fixture\n",
            encoding="utf-8",
        )

        ledger = InvestigationLedger("V17-RC-KAT-001")
        ledger.append(
            event_type="EVIDENCE_ACQUIRED",
            timestamp="2026-09-01T12:00:00Z",
            actor="v17-release-candidate-selftest",
            payload={"artifact_id": "ART-RC-001", "sha256": "a" * 64},
        )
        checkpoint = ledger.checkpoint(created_at="2026-09-01T12:00:01Z")
        checkpoint_private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        signed = SignedLedgerCheckpoint.sign(
            checkpoint=checkpoint,
            private_key=checkpoint_private,
            signed_at="2026-09-01T12:00:02Z",
        )
        trusted = {signed.key_id: bytes.fromhex(signed.public_key_hex)}

        export_private = root / "export.pem"
        export_public = root / "export.pub.pem"
        export_public_sha256 = _write_export_keys(export_private, export_public)

        bundle = root / "case.zip"
        export_case(
            case_root,
            "V17-RC-KAT",
            "V17-RC-KAT-001",
            export_private,
            bundle,
            ledger=ledger,
            signed_checkpoint=signed,
            trusted_public_keys=trusted,
        )
        result = verify_case(
            bundle,
            export_public,
            expected_tenant="V17-RC-KAT",
            expected_case="V17-RC-KAT-001",
        )

        checks = [
            ("Known checkpoint hash", checkpoint.checkpoint_hash == EXPECTED_CHECKPOINT_HASH),
            ("Known checkpoint signer key ID", signed.key_id == EXPECTED_CHECKPOINT_KEY_ID),
            ("Known outer trust-anchor fingerprint", export_public_sha256 == EXPECTED_EXPORT_PUBLIC_KEY_SHA256),
            ("Offline package verification", result.get("valid") is True),
            ("Signature validity", result.get("signature_valid") is True),
            ("Signer trust", result.get("signer_trusted") is True),
            ("Network required", result.get("network_required") is False),
        ]

        print("AI-DFIR v1.7 Release-Candidate Known-Answer Self-Test")
        print()
        for name, passed in checks:
            print(f"{name}: {'PASS' if passed else 'FAIL'}")
        if not all(passed for _, passed in checks):
            return 1
        print()
        print("v1.7 release-candidate known-answer test: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

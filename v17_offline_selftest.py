#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import export_case, verify_case
from fleet_crypto import generate
from v17_integrity import InvestigationLedger
from v17_signing import SignedLedgerCheckpoint


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-v17-offline-selftest-") as tmp:
        root = Path(tmp)
        case_root = root / "case"
        (case_root / "00_case").mkdir(parents=True)
        (case_root / "00_case" / "case.json").write_text(
            json.dumps(
                {
                    "schema": "ai-dfir/case/v1.5",
                    "case_id": "V17-OFFLINE-SELFTEST",
                    "tenant_id": "SELFTEST",
                    "tool_version": "1.7",
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        (case_root / "synthetic.txt").write_text(
            "AI-DFIR v1.7 deterministic offline verification fixture\n",
            encoding="utf-8",
        )

        ledger = InvestigationLedger("V17-OFFLINE-SELFTEST")
        ledger.append(
            event_type="EVIDENCE_ACQUIRED",
            timestamp="2026-08-31T12:00:00Z",
            actor="v17-offline-selftest",
            payload={
                "artifact_id": "ART-001",
                "sha256": "a" * 64,
            },
        )
        checkpoint = ledger.checkpoint(
            created_at="2026-08-31T12:00:01Z"
        )
        checkpoint_private_key = Ed25519PrivateKey.from_private_bytes(
            bytes(range(1, 33))
        )
        signed = SignedLedgerCheckpoint.sign(
            checkpoint=checkpoint,
            private_key=checkpoint_private_key,
            signed_at="2026-08-31T12:00:02Z",
        )
        trusted = {
            signed.key_id: bytes.fromhex(signed.public_key_hex)
        }

        export_private_key = root / "export.pem"
        export_public_key = root / "export.pub.pem"
        generate(export_private_key, export_public_key)

        bundle = root / "case.zip"
        export_case(
            case_root,
            "SELFTEST",
            "V17-OFFLINE-SELFTEST",
            export_private_key,
            bundle,
            ledger=ledger,
            signed_checkpoint=signed,
            trusted_public_keys=trusted,
        )

        result = verify_case(
            bundle,
            export_public_key,
            expected_tenant="SELFTEST",
            expected_case="V17-OFFLINE-SELFTEST",
        )

        print("AI-DFIR v1.7 Offline Case Verification Self-Test")
        print()
        print(
            "v1.5-compatible signed export:",
            "PASS" if result["export_manifest_integrity"] == "PASS" else "FAIL",
        )
        print(
            "Artifact integrity:",
            result["artifact_integrity"],
        )
        print(
            "Ledger integrity:",
            result["ledger_integrity"],
        )
        print(
            "Checkpoint integrity:",
            result["checkpoint_integrity"],
        )
        print(
            "Checkpoint signature:",
            "PASS" if result["signature_valid"] else "FAIL",
        )
        print(
            "Trusted signer:",
            "PASS" if result["signer_trusted"] else "FAIL",
        )
        print(
            "Network required:",
            "NO" if not result["network_required"] else "YES",
        )

        if not result["valid"]:
            for finding in result["findings"]:
                print(f"ERROR: {finding}")
            return 1

        print()
        print("v1.7 offline case verification: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

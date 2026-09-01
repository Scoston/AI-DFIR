#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import export_case
from fleet_crypto import generate
from v17_integrity import InvestigationLedger
from v17_signing import SignedLedgerCheckpoint


ROOT = Path(__file__).resolve().parent
VERIFY_SCRIPT = ROOT / "verify_case_v17.py"


def _run(args: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-v17-assurance-") as tmp:
        root = Path(tmp)
        case_root = root / "case"
        (case_root / "00_case").mkdir(parents=True)
        (case_root / "00_case" / "case.json").write_text(
            json.dumps(
                {
                    "schema": "ai-dfir/case/v1.5",
                    "case_id": "V17-ASSURANCE-SELFTEST",
                    "tenant_id": "SELFTEST",
                    "tool_version": "1.7",
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        (case_root / "synthetic.txt").write_text(
            "AI-DFIR v1.7 verification assurance fixture\n",
            encoding="utf-8",
        )

        ledger = InvestigationLedger("V17-ASSURANCE-SELFTEST")
        ledger.append(
            event_type="EVIDENCE_ACQUIRED",
            timestamp="2026-08-31T20:00:00Z",
            actor="v17-assurance-selftest",
            payload={"artifact_id": "ART-001", "sha256": "b" * 64},
        )
        checkpoint = ledger.checkpoint(created_at="2026-08-31T20:00:01Z")
        checkpoint_private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        signed = SignedLedgerCheckpoint.sign(
            checkpoint=checkpoint,
            private_key=checkpoint_private_key,
            signed_at="2026-08-31T20:00:02Z",
        )
        trusted = {signed.key_id: bytes.fromhex(signed.public_key_hex)}

        export_private_key = root / "export.pem"
        export_public_key = root / "export.pub.pem"
        generate(export_private_key, export_public_key)
        wrong_private_key = root / "wrong.pem"
        wrong_public_key = root / "wrong.pub.pem"
        generate(wrong_private_key, wrong_public_key)

        bundle = root / "case.zip"
        export_case(
            case_root,
            "SELFTEST",
            "V17-ASSURANCE-SELFTEST",
            export_private_key,
            bundle,
            ledger=ledger,
            signed_checkpoint=signed,
            trusted_public_keys=trusted,
        )

        detached = root / "detached-reviewer"
        detached.mkdir()
        network_guard = root / "network-guard"
        network_guard.mkdir()
        (network_guard / "sitecustomize.py").write_text(
            "import socket\n"
            "def _blocked(*args, **kwargs):\n"
            "    raise AssertionError('network access attempted during offline verification')\n"
            "socket.create_connection = _blocked\n"
            "socket.getaddrinfo = _blocked\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(network_guard)

        text_run = _run(
            [
                "--zip",
                str(bundle),
                "--export-public-key",
                str(export_public_key),
                "--tenant",
                "SELFTEST",
                "--case",
                "V17-ASSURANCE-SELFTEST",
                "--format",
                "text",
            ],
            cwd=detached,
            env=env,
        )
        if text_run.returncode != 0:
            print(text_run.stdout)
            print(text_run.stderr)
            return 1
        required_text = (
            "Status: PASS",
            "Checkpoint signature: PASS",
            "Checkpoint signer trust: PASS",
            "Network required: NO",
            "independently supplied export public key",
        )
        if not all(item in text_run.stdout for item in required_text):
            print(text_run.stdout)
            return 1

        report_path = detached / "verification.json"
        json_run = _run(
            [
                "--zip",
                str(bundle),
                "--export-public-key",
                str(export_public_key),
                "--format",
                "json",
                "--out",
                str(report_path),
            ],
            cwd=detached,
            env=env,
        )
        if json_run.returncode != 0 or not report_path.is_file():
            return 1
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report.get("valid") is not True or report.get("network_required") is not False:
            return 1

        wrong_key_run = _run(
            [
                "--zip",
                str(bundle),
                "--export-public-key",
                str(wrong_public_key),
                "--format",
                "json",
            ],
            cwd=detached,
            env=env,
        )
        if wrong_key_run.returncode != 1:
            return 1

        malformed = root / "malformed.bin"
        malformed.write_bytes(b"not a zip")
        malformed_run = _run(
            [
                "--zip",
                str(malformed),
                "--export-public-key",
                str(export_public_key),
                "--format",
                "json",
            ],
            cwd=detached,
            env=env,
        )
        if malformed_run.returncode != 2:
            return 1

        runtime_run = _run(
            [
                "--zip",
                str(root / "missing.zip"),
                "--export-public-key",
                str(export_public_key),
                "--format",
                "json",
            ],
            cwd=detached,
            env=env,
        )
        if runtime_run.returncode != 3:
            return 1

        print("AI-DFIR v1.7 Verification Assurance Self-Test")
        print()
        print("Detached working directory: PASS")
        print("Network guard: PASS")
        print("Human-readable report: PASS")
        print("Machine-readable report: PASS")
        print("Valid package exit code 0: PASS")
        print("Verification failure exit code 1: PASS")
        print("Malformed package exit code 2: PASS")
        print("Runtime/configuration exit code 3: PASS")
        print()
        print("v1.7 verification assurance: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

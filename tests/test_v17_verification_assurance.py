from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import export_case
from fleet_crypto import generate
from v17_integrity import InvestigationLedger
from v17_signing import SignedLedgerCheckpoint
from verify_case_v17 import (
    EXIT_MALFORMED_OR_UNSUPPORTED,
    EXIT_RUNTIME_ERROR,
    EXIT_VERIFICATION_FAILED,
    EXIT_VERIFIED,
    exit_code_for_report,
    render_verification_report,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFY_SCRIPT = ROOT / "verify_case_v17.py"


def _report(**updates):
    value = {
        "schema": "ai-dfir/offline-case-verification/v1.7",
        "status": "PASS",
        "valid": True,
        "offline": True,
        "network_required": False,
        "failure_class": None,
        "zip_sha256": "a" * 64,
        "tenant_id": "TENANT-001",
        "case_id": "CASE-001",
        "package_safety": "PASS",
        "export_manifest_integrity": "PASS",
        "artifact_integrity": "PASS",
        "ledger_integrity": "PASS",
        "checkpoint_integrity": "PASS",
        "checkpoint_hash": "b" * 64,
        "signature_valid": True,
        "signer_trusted": True,
        "signer_key_id": "sha256:" + "c" * 64,
        "combined_checkpoint_verification": True,
        "findings": [],
        "verification_errors": [],
    }
    value.update(updates)
    return value


def _valid_bundle(tmp_path: Path) -> tuple[Path, Path, Path]:
    case_root = tmp_path / "case"
    (case_root / "00_case").mkdir(parents=True)
    (case_root / "00_case" / "case.json").write_text(
        json.dumps(
            {
                "schema": "ai-dfir/case/v1.5",
                "case_id": "CASE-ASSURANCE-001",
                "tenant_id": "TENANT-001",
                "tool_version": "1.7",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (case_root / "note.txt").write_text("assurance fixture\n", encoding="utf-8")

    ledger = InvestigationLedger("CASE-ASSURANCE-001")
    ledger.append(
        event_type="EVIDENCE_ACQUIRED",
        timestamp="2026-08-31T20:00:00Z",
        actor="assurance-test",
        payload={"artifact_id": "ART-001", "sha256": "d" * 64},
    )
    checkpoint = ledger.checkpoint(created_at="2026-08-31T20:00:01Z")
    checkpoint_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    signed = SignedLedgerCheckpoint.sign(
        checkpoint=checkpoint,
        private_key=checkpoint_key,
        signed_at="2026-08-31T20:00:02Z",
    )
    trusted = {signed.key_id: bytes.fromhex(signed.public_key_hex)}

    private_key = tmp_path / "export.pem"
    public_key = tmp_path / "export.pub.pem"
    generate(private_key, public_key)
    bundle = tmp_path / "case.zip"
    export_case(
        case_root,
        "TENANT-001",
        "CASE-ASSURANCE-001",
        private_key,
        bundle,
        ledger=ledger,
        signed_checkpoint=signed,
        trusted_public_keys=trusted,
    )
    return bundle, public_key, private_key


def _guarded_env(tmp_path: Path) -> dict[str, str]:
    guard = tmp_path / "network-guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(
        "import socket\n"
        "def _blocked(*args, **kwargs):\n"
        "    raise AssertionError('network access attempted')\n"
        "socket.create_connection = _blocked\n"
        "socket.getaddrinfo = _blocked\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(guard)
    return env


def _run_cli(args: list[str], *, cwd: Path, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_render_text_report_distinguishes_signature_from_signer_trust():
    report = _report(
        status="FAIL",
        valid=False,
        failure_class="verification-failed",
        signature_valid=True,
        signer_trusted=False,
        combined_checkpoint_verification=False,
        findings=[
            {
                "type": "checkpoint_signer_untrusted",
                "severity": "critical",
                "error": "signature key is not trusted",
            }
        ],
    )

    text = render_verification_report(report)

    assert "Checkpoint signature: PASS" in text
    assert "Checkpoint signer trust: FAIL" in text
    assert "A valid checkpoint signature proves cryptographic validity only." in text
    assert "independently supplied export public key" in text


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (_report(), EXIT_VERIFIED),
        (
            _report(status="FAIL", valid=False, failure_class="verification-failed"),
            EXIT_VERIFICATION_FAILED,
        ),
        (
            _report(status="FAIL", valid=False, failure_class="malformed-package"),
            EXIT_MALFORMED_OR_UNSUPPORTED,
        ),
        (
            _report(status="FAIL", valid=False, failure_class="unsupported-package"),
            EXIT_MALFORMED_OR_UNSUPPORTED,
        ),
        (
            _report(status="ERROR", valid=False, failure_class="runtime-error"),
            EXIT_RUNTIME_ERROR,
        ),
    ],
)
def test_exit_code_contract(report, expected):
    assert exit_code_for_report(report) == expected


def test_cli_detached_text_report_blocks_network(tmp_path: Path):
    bundle, public_key, _ = _valid_bundle(tmp_path)
    detached = tmp_path / "detached"
    detached.mkdir()

    cp = _run_cli(
        [
            "--zip",
            str(bundle),
            "--export-public-key",
            str(public_key),
            "--tenant",
            "TENANT-001",
            "--case",
            "CASE-ASSURANCE-001",
            "--format",
            "text",
        ],
        cwd=detached,
        env=_guarded_env(tmp_path),
    )

    assert cp.returncode == EXIT_VERIFIED, cp.stderr
    assert "Status: PASS" in cp.stdout
    assert "Network required: NO" in cp.stdout
    assert "Checkpoint signer trust: PASS" in cp.stdout


def test_cli_json_report_can_be_written(tmp_path: Path):
    bundle, public_key, _ = _valid_bundle(tmp_path)
    detached = tmp_path / "detached"
    detached.mkdir()
    out = detached / "verification.json"

    cp = _run_cli(
        [
            "--zip",
            str(bundle),
            "--export-public-key",
            str(public_key),
            "--format",
            "json",
            "--out",
            str(out),
        ],
        cwd=detached,
    )

    assert cp.returncode == EXIT_VERIFIED
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["valid"] is True
    assert report["network_required"] is False


def test_cli_wrong_export_key_returns_one(tmp_path: Path):
    bundle, _, _ = _valid_bundle(tmp_path)
    wrong_private = tmp_path / "wrong.pem"
    wrong_public = tmp_path / "wrong.pub.pem"
    generate(wrong_private, wrong_public)

    cp = _run_cli(
        [
            "--zip",
            str(bundle),
            "--export-public-key",
            str(wrong_public),
            "--format",
            "json",
        ],
        cwd=tmp_path,
    )

    assert cp.returncode == EXIT_VERIFICATION_FAILED
    report = json.loads(cp.stdout)
    assert report["export_manifest_integrity"] == "FAIL"
    assert report["artifact_integrity"] == "NOT_TRUSTED"


def test_cli_bad_zip_returns_two(tmp_path: Path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"not a zip")
    private_key = tmp_path / "unused.pem"
    public_key = tmp_path / "unused.pub.pem"
    generate(private_key, public_key)

    cp = _run_cli(
        [
            "--zip",
            str(bad),
            "--export-public-key",
            str(public_key),
            "--format",
            "json",
        ],
        cwd=tmp_path,
    )

    assert cp.returncode == EXIT_MALFORMED_OR_UNSUPPORTED
    assert json.loads(cp.stdout)["failure_class"] == "malformed-package"


def test_cli_missing_package_returns_three(tmp_path: Path):
    private_key = tmp_path / "unused.pem"
    public_key = tmp_path / "unused.pub.pem"
    generate(private_key, public_key)

    cp = _run_cli(
        [
            "--zip",
            str(tmp_path / "missing.zip"),
            "--export-public-key",
            str(public_key),
            "--format",
            "json",
        ],
        cwd=tmp_path,
    )

    assert cp.returncode == EXIT_RUNTIME_ERROR
    report = json.loads(cp.stdout)
    assert report["status"] == "ERROR"
    assert report["failure_class"] == "runtime-error"

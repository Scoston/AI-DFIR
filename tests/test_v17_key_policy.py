from __future__ import annotations

import copy
import json
import socket
import subprocess
import sys
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v15 import export_case as export_v15
from case_export_v17 import _write_v17_metadata, export_case, verify_case
from v17_integrity import InvestigationLedger, sha256_object
from v17_key_policy import (
    MAX_POLICY_BYTES, MAX_POLICY_KEYS, KeyPolicyError, evaluate_key_policy,
    load_key_policy, validate_key_policy,
)
from v17_key_policy_selftest import EVALUATED_AT, synthetic_export, synthetic_policy
from v17_provenance import PROVENANCE_PATH
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, sign_fixture
from v17_signing import SignedLedgerCheckpoint
from verify_case_v17 import render_verification_report

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def signed():
    return sign_fixture(InvestigationLedger(CASE_ID))[0]


@pytest.fixture
def case(tmp_path):
    return synthetic_export(tmp_path)


def evaluate(policy, signed, **kwargs):
    return evaluate_key_policy(policy, signed_checkpoint=signed, tenant_id=TENANT_ID,
                               case_id=CASE_ID, evaluated_at=EVALUATED_AT, **kwargs)


def verify(case, policy=None, **kwargs):
    return verify_case(case["package"], case["public"], checkpoint_key_policy=policy,
                       key_policy_evaluated_at=EVALUATED_AT if policy is not None else None, **kwargs)


def codes(report):
    return {f["code"] for f in report["findings"]}


def inactive(policy, state="revoked"):
    value = copy.deepcopy(policy)
    value["revision"] += 1
    value["keys"][0].update(state=state, status_changed_at="2026-09-06T00:00:30Z",
                            reason="synthetic key lifecycle exercise")
    return value


def test_active_policy_reconstructs_offline_and_binds_report_to_policy(case, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    before = case["package"].read_bytes()
    policy_before = copy.deepcopy(case["policy"])
    report = verify(case, case["policy"], include_reconstruction=True, replay_transforms=True,
                    expected_key_policy_sha256=sha256_object(case["policy"]))
    assert report["valid"] and report["signature_valid"] and report["signer_trusted"]
    result = report["checkpoint_key_policy"]
    assert result["policy_sha256"] == sha256_object(case["policy"])
    assert result["policy_revision"] == 1 and result["evaluation_time_source"] == "caller"
    assert result["evaluated_at"] == EVALUATED_AT and not result["historical_signing_time_proven"]
    assert report["reconstruction"]["deterministic_replay"]["status"] == "PASS"
    assert case["package"].read_bytes() == before and case["policy"] == policy_before


@pytest.mark.parametrize("state", ["retired", "revoked"])
def test_inactive_keys_deny_trust_even_when_signing_precedes_status_change(case, state):
    policy = inactive(case["policy"], state)
    report = verify(case, policy, include_reconstruction=True)
    assert report["signature_valid"] and report["manifest_signer_trusted"]
    assert not report["valid"] and not report["signer_trusted"]
    assert "key_policy_signer_" + state in codes(report["checkpoint_key_policy"])
    assert report["provenance_integrity"] == "NOT_RUN" and "reconstruction" not in report
    text = render_verification_report(report)
    assert "Checkpoint signature: PASS" in text and "Checkpoint signer trust: FAIL" in text
    assert "External checkpoint key policy: FAIL" in text


def test_backdating_evaluation_does_not_reactivate_revoked_key(signed):
    result = evaluate_key_policy(inactive(synthetic_policy(signed)), signed_checkpoint=signed,
                                 tenant_id=TENANT_ID, case_id=CASE_ID, evaluated_at=TIMESTAMP)
    assert result["status"] == "FAIL" and "key_policy_signer_revoked" in codes(result)


def test_rotation_overlap_and_retirement_are_explicit(signed):
    replacement, _ = sign_fixture(InvestigationLedger(CASE_ID))
    policy = synthetic_policy(signed)
    policy["keys"].append(synthetic_policy(replacement)["keys"][0])
    assert evaluate(policy, signed)["status"] == evaluate(policy, replacement)["status"] == "PASS"
    policy = inactive(policy, "retired")
    assert evaluate(policy, signed)["status"] == "FAIL"
    assert evaluate(policy, replacement)["status"] == "PASS"


@pytest.mark.parametrize("change,expected", [
    (lambda p: p.update(tenant_id="another-tenant"), "key_policy_tenant_mismatch"),
    (lambda p: p.update(case_ids=["another-case"]), "key_policy_case_mismatch"),
    (lambda p: p.update(keys=[]), "key_policy_signer_unknown"),
    (lambda p: p.update(expires_at=EVALUATED_AT), "key_policy_outside_validity"),
    (lambda p: p.update(issued_at="2026-09-07T00:00:00Z"), "key_policy_outside_validity"),
    (lambda p: p["keys"][0].update(not_after=EVALUATED_AT), "key_policy_key_outside_validity"),
    (lambda p: p["keys"][0].update(not_before="2026-09-07T00:00:00Z"), "key_policy_key_outside_validity"),
    (lambda p: p["keys"][0].update(not_before="2026-09-06T00:00:30Z"), "key_policy_signing_time_outside_validity"),
])
def test_policy_scope_freshness_and_key_time_boundaries(signed, change, expected):
    policy = synthetic_policy(signed)
    change(policy)
    result = evaluate(policy, signed)
    assert result["status"] == "FAIL" and expected in codes(result)


def test_inclusive_key_and_policy_start(signed):
    policy = synthetic_policy(signed)
    policy["issued_at"] = policy["keys"][0]["not_before"] = TIMESTAMP
    result = evaluate_key_policy(policy, signed_checkpoint=signed, tenant_id=TENANT_ID,
                                 case_id=CASE_ID, evaluated_at=TIMESTAMP)
    assert result["status"] == "PASS"


def test_explicit_tenant_wide_policy_scope(signed):
    policy = synthetic_policy(signed)
    policy["case_ids"] = None
    assert evaluate(policy, signed)["status"] == "PASS"


def test_policy_digest_pin_rejects_old_active_snapshot(signed):
    old = synthetic_policy(signed)
    latest = inactive(old)
    result = evaluate(old, signed, expected_policy_sha256=sha256_object(latest))
    assert result["status"] == "FAIL" and "key_policy_digest_mismatch" in codes(result)
    reordered = dict(reversed(list(old.items())))
    assert evaluate(reordered, signed, expected_policy_sha256=sha256_object(old))["status"] == "PASS"


@pytest.mark.parametrize("options", [
    {"require_checkpoint_key_policy": True},
    {"expected_key_policy_sha256": "a" * 64},
    {"key_policy_evaluated_at": EVALUATED_AT},
])
def test_missing_policy_cannot_silently_satisfy_external_controls(case, options):
    report = verify_case(case["package"], case["public"], **options)
    assert not report["valid"] and "key_policy_required" in codes(report["checkpoint_key_policy"])


def test_legacy_verification_remains_stable_without_external_policy(case):
    a, b = verify(case), verify(case)
    assert a == b and a["valid"]
    assert a["checkpoint_key_policy"]["status"] == "NOT_CONFIGURED"
    assert a["signer_trust_source"] == "export-manifest"


def test_embedded_policy_cannot_satisfy_verifier_requirement(case):
    (case["root"] / "00_case/checkpoint_key_policy.json").write_text(json.dumps(case["policy"]), encoding="utf-8")
    export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"],
                ledger=case["ledger"], signed_checkpoint=case["signed"],
                trusted_public_keys=case["trust"], provenance=case["profile"])
    report = verify(case, require_checkpoint_key_policy=True)
    assert not report["valid"] and "key_policy_required" in codes(report["checkpoint_key_policy"])
    assert not verify(case, inactive(case["policy"]))["valid"]


def test_external_policy_cannot_widen_manifest_signer_trust(case):
    _write_v17_metadata(case["root"], ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys={})
    (case["root"] / PROVENANCE_PATH).write_text(json.dumps(case["profile"]), encoding="utf-8")
    export_v15(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"])
    report = verify(case, case["policy"])
    assert report["checkpoint_key_policy"]["status"] == "PASS"
    assert report["signature_valid"] and not report["manifest_signer_trusted"]
    assert not report["valid"] and not report["signer_trusted"]


def test_export_denial_preserves_existing_destination(case):
    before = case["package"].read_bytes()
    with pytest.raises(ValueError, match="key policy rejected"):
        export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"],
                    ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys=case["trust"],
                    provenance=case["profile"], checkpoint_key_policy=inactive(case["policy"]),
                    key_policy_evaluated_at=EVALUATED_AT)
    assert case["package"].read_bytes() == before


def test_invalid_signature_cannot_become_trusted_through_policy(signed):
    changed = replace(signed, signature_hex="00" * 64)
    result = evaluate(synthetic_policy(signed), changed)
    assert result["status"] == "FAIL" and result["signature_valid"] is False


@pytest.mark.parametrize("change", [
    lambda p: p.update(schema="unsupported"),
    lambda p: p.update(revision=True),
    lambda p: p.update(revision=0),
    lambda p: p.update(extra="unexpected"),
    lambda p: p.update(case_ids=[]),
    lambda p: p.update(case_ids=[CASE_ID, CASE_ID]),
    lambda p: p.update(issued_at="2026-09-06T00:00:40"),
    lambda p: p.update(expires_at="2026-02-30T00:00:00Z"),
    lambda p: p.update(expires_at=p["issued_at"]),
    lambda p: p["keys"].append(copy.deepcopy(p["keys"][0])),
    lambda p: p["keys"][0].update(signature_algorithm="RSA"),
    lambda p: p["keys"][0].update(key_id="sha256:" + "0" * 64),
    lambda p: p["keys"][0].update(public_key_hex="00"),
    lambda p: p["keys"][0].update(state="unknown"),
    lambda p: p["keys"][0].update(state=[]),
    lambda p: p["keys"][0].update(state="revoked"),
    lambda p: p["keys"][0].update(not_after=p["keys"][0]["not_before"]),
    lambda p: p["keys"][0].update(private_key_hex="never-allowed"),
])
def test_malformed_policies_fail_closed(signed, change):
    policy = synthetic_policy(signed)
    change(policy)
    result = evaluate(policy, signed)
    assert result["status"] == "FAIL" and "key_policy_malformed" in codes(result)


@pytest.mark.parametrize("raw", [b'{"schema":1,"schema":2}', b'{"revision":NaN}', b'\xff', b'{'])
def test_ambiguous_or_invalid_policy_files_are_rejected(tmp_path, raw):
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    with pytest.raises(KeyPolicyError):
        load_key_policy(path)


def test_policy_size_and_key_count_are_bounded(tmp_path, signed):
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
    with pytest.raises(KeyPolicyError, match="size limit"):
        load_key_policy(path)
    policy = synthetic_policy(signed)
    policy["keys"] *= MAX_POLICY_KEYS + 1
    with pytest.raises(KeyPolicyError):
        validate_key_policy(policy)


@pytest.mark.parametrize("script,verb", [
    ("verify_case_v17.py", []), ("case_export_v17.py", ["verify"]), ("replay_case_v17.py", []),
])
def test_each_verification_cli_enforces_external_revocation(case, script, verb):
    path = case["root"].parent / "external-policy.json"
    path.write_text(json.dumps(inactive(case["policy"])), encoding="utf-8")
    args = [sys.executable, str(ROOT / script), *verb, "--zip", str(case["package"]),
            "--export-public-key", str(case["public"]), "--checkpoint-key-policy", str(path),
            "--policy-evaluation-time", EVALUATED_AT, "--require-checkpoint-key-policy"]
    if script == "verify_case_v17.py":
        args += ["--format", "json"]
    denied = subprocess.run(args, text=True, capture_output=True, cwd=path.parent)
    assert denied.returncode == 1, denied.stdout + denied.stderr
    report = json.loads(denied.stdout)
    assert report["signature_valid"] and not report["signer_trusted"]
    path.write_text(json.dumps(case["policy"]), encoding="utf-8")
    accepted = subprocess.run(args, text=True, capture_output=True, cwd=path.parent)
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert json.loads(accepted.stdout)["checkpoint_key_policy"]["status"] == "PASS"


@pytest.mark.parametrize("claimed_time", ["2026-09-06T00:02:00Z", "2026-09-05T00:00:00Z", "2026-09-06T00:00:00"])
def test_valid_signature_does_not_legitimize_inconsistent_time_claims(claimed_time):
    ledger = InvestigationLedger(CASE_ID)
    signed = SignedLedgerCheckpoint.sign(checkpoint=ledger.checkpoint(created_at=TIMESTAMP),
                                         private_key=Ed25519PrivateKey.generate(), signed_at=claimed_time)
    assert signed.verify_signature()[0]
    report = evaluate(synthetic_policy(signed), signed)
    assert report["status"] == "FAIL"
    assert codes(report) & {"key_policy_inconsistent_timestamp", "key_policy_malformed"}


def test_default_evaluation_uses_system_utc(signed, monkeypatch):
    import v17_key_policy
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 6, 0, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(v17_key_policy, "datetime", Clock)
    report = evaluate_key_policy(synthetic_policy(signed), signed_checkpoint=signed,
                                 tenant_id=TENANT_ID, case_id=CASE_ID)
    assert report["status"] == "PASS" and report["evaluated_at"] == EVALUATED_AT
    assert report["evaluation_time_source"] == "system-clock"


def test_export_cli_refuses_revoked_key_before_creating_zip(case):
    from case_export_v17 import LEDGER_PATH, SIGNED_CHECKPOINT_PATH, TRUST_STORE_PATH
    _write_v17_metadata(case["root"], ledger=case["ledger"], signed_checkpoint=case["signed"],
                        trusted_public_keys=case["trust"])
    policy_path = case["root"].parent / "policy.json"
    policy_path.write_text(json.dumps(inactive(case["policy"])), encoding="utf-8")
    destination = case["root"].parent / "refused.zip"
    args = [sys.executable, str(ROOT / "case_export_v17.py"), "create", "--case-root", str(case["root"]),
            "--tenant", TENANT_ID, "--case", CASE_ID, "--export-private-key", str(case["private"]),
            "--ledger", str(case["root"] / LEDGER_PATH), "--signed-checkpoint", str(case["root"] / SIGNED_CHECKPOINT_PATH),
            "--trusted-signers", str(case["root"] / TRUST_STORE_PATH), "--out", str(destination),
            "--checkpoint-key-policy", str(policy_path), "--policy-evaluation-time", EVALUATED_AT]
    result = subprocess.run(args, text=True, capture_output=True)
    assert result.returncode != 0 and not destination.exists()
    assert "key_policy_signer_revoked" in result.stdout + result.stderr


def test_active_policy_cannot_override_tampered_evidence(case):
    bad = case["root"].parent / "tampered.zip"
    with zipfile.ZipFile(case["package"]) as src, zipfile.ZipFile(bad, "w") as dst:
        for entry in src.infolist():
            dst.writestr(entry, b"[]" if entry.filename == "raw.json" else src.read(entry.filename))
    report = verify_case(bad, case["public"], checkpoint_key_policy=case["policy"],
                         key_policy_evaluated_at=EVALUATED_AT, include_reconstruction=True)
    assert report["checkpoint_key_policy"]["status"] == "PASS"
    assert not report["valid"] and report["artifact_integrity"] == "FAIL"
    assert "reconstruction" not in report


def test_malformed_policy_cli_input_is_configuration_error(case):
    path = case["root"].parent / "bad-policy.json"
    path.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
    result = subprocess.run([sys.executable, str(ROOT / "verify_case_v17.py"), "--zip", str(case["package"]),
                             "--export-public-key", str(case["public"]), "--checkpoint-key-policy", str(path),
                             "--format", "json"], text=True, capture_output=True)
    assert result.returncode == 3
    assert json.loads(result.stdout)["status"] == "ERROR"

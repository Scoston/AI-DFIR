from __future__ import annotations

import copy
import json
import socket
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from case_export_v15 import export_case as export_v15
from case_export_v17 import _write_v17_metadata, export_case, verify_case
from fleet_crypto import generate
from v17_integrity import AIProvenanceRecord, sha256_object
from v17_provenance import PROVENANCE_PATH, ProvenanceError, record_hash, validate_provenance, wrap_record
from v17_provenance_selftest import CASE_ID, TENANT_ID, TIMESTAMP, bind_fixture, sign_fixture, synthetic_case


@pytest.fixture
def case(tmp_path):
    root = tmp_path / "case"
    profile, ledger = synthetic_case(root)
    private, public = tmp_path / "export.pem", tmp_path / "export.pub.pem"
    generate(private, public)
    return root, profile, ledger, private, public


def export_fixture(case, *, profile=True, ledger=None):
    root, bundle, initial, private, public = case
    ledger = ledger or initial
    signed, trust = sign_fixture(ledger)
    package = root.parent / "export.zip"
    export_case(root, TENANT_ID, CASE_ID, private, package, ledger=ledger,
                signed_checkpoint=signed, trusted_public_keys=trust, provenance=bundle if profile else None)
    return package, public


def inventory(root):
    import hashlib
    return {p.relative_to(root).as_posix(): {"sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in root.rglob("*") if p.is_file()}


def validate(case, *, rebind=False):
    root, profile, ledger, _, _ = case
    return validate_provenance(profile, case_id=CASE_ID, ledger=bind_fixture(profile) if rebind else ledger, files=inventory(root))


def refresh(profile):
    for kind in ("artifacts", "relationships", "ai_records", "tool_records", "analyst_decisions"):
        for row in profile[kind]:
            if kind == "ai_records":
                output = row["record"]["structured_output"]
                row["output_sha256"] = sha256_object(output) if output else None
            row["record_hash"] = record_hash(row)


def test_complete_case_reconstructs_offline_without_source_changes(case, monkeypatch):
    before = inventory(case[0])
    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    package, public = export_fixture(case)
    report = verify_case(package, public, require_provenance=True, include_reconstruction=True, replay_transforms=True)
    assert report["valid"] and report["provenance_integrity"] == "PASS"
    replay = report["reconstruction"]
    assert replay["record_count"] == 6
    assert replay["timeline"][-1]["record"]["disposition"] == "accepted_with_qualification"
    assert replay["deterministic_replay"]["status"] == "PASS"
    assert not replay["model_invoked"] and not replay["tools_executed"]
    assert inventory(case[0]) == before


def test_legacy_export_remains_verifiable_but_cannot_claim_reconstruction(case):
    from v17_integrity import InvestigationLedger
    package, public = export_fixture(case, profile=False, ledger=InvestigationLedger(CASE_ID))
    assert verify_case(package, public)["provenance_integrity"] == "NOT_PRESENT"
    report = verify_case(package, public, include_reconstruction=True)
    assert not report["valid"] and "reconstruction" not in report


def test_missing_profile_cannot_downgrade_committed_provenance_to_legacy(case):
    with pytest.raises(ProvenanceError, match="commitments require"):
        export_fixture(case, profile=False)
    root, _, ledger, private, public = case
    signed, trust = sign_fixture(ledger)
    _write_v17_metadata(root, ledger=ledger, signed_checkpoint=signed, trusted_public_keys=trust)
    package = root.parent / "missing-profile.zip"
    export_v15(root, TENANT_ID, CASE_ID, private, package)
    report = verify_case(package, public)
    assert not report["valid"] and report["provenance_integrity"] == "FAIL"


def test_rehashing_record_cannot_replace_signed_ledger_binding(case):
    case[1]["ai_records"][0]["record"]["model"] = "replacement"
    refresh(case[1])
    with pytest.raises(ProvenanceError, match="ledger record hash mismatch"):
        validate(case)


@pytest.mark.parametrize("mutation,match", [
    (lambda p: p["ai_records"][0]["record"].update(case_id="OTHER"), "case mismatch"),
    (lambda p: p["ai_records"][0]["record"].update(evidence_refs=["MISSING"]), "dangling evidence"),
    (lambda p: p["ai_records"][0]["record"].update(tool_calls=[]), "unbound tool"),
    (lambda p: p["analyst_decisions"][0]["record"].update(target_id="MISSING"), "decision target"),
    (lambda p: p["analyst_decisions"][0]["record"].update(rationale="inline text"), "content review"),
    (lambda p: p["ai_records"][0]["record"].update(structured_output={"verdict": "suspicious"}), "content review"),
    (lambda p: p["ai_records"][0]["record"].update(structured_output={"chain_of_thought": "excluded"}), "sensitive-context"),
    (lambda p: p["artifacts"][0].update(path="../raw.json"), "evidence path"),
    (lambda p: p["artifacts"][0]["record"].update(sha256="0" * 64), "evidence bytes"),
    (lambda p: p["tool_records"][0]["record"].update(status="approved"), "tool status"),
    (lambda p: p["tool_records"][0]["record"].update(arguments_sha256="bad"), "arguments digest"),
    (lambda p: p["relationships"][0]["record"].update(parent_artifact_id="MISSING"), "lineage reference"),
    (lambda p: p["ai_records"].append(copy.deepcopy(p["ai_records"][0])), "duplicate or invalid"),
])
def test_inconsistent_records_fail_even_with_recomputed_commitments(case, mutation, match):
    mutation(case[1])
    refresh(case[1])
    with pytest.raises(ProvenanceError, match=match):
        validate(case, rebind=True)


@pytest.mark.parametrize("timestamp", ["2026-09-06", "2026-09-06T00:00:00", "2026-09-06T00:00:00-04:00", "2026-02-30T00:00:00Z"])
def test_invalid_or_ambiguous_timestamps_fail(case, timestamp):
    case[1]["ai_records"][0]["record"]["timestamp"] = timestamp
    refresh(case[1])
    with pytest.raises(ProvenanceError, match="timestamp"):
        validate(case)


def test_lineage_cycle_rejected(case):
    reverse = copy.deepcopy(case[1]["relationships"][0])
    reverse["record"].update(parent_artifact_id="NORMALIZED", child_artifact_id="RAW")
    case[1]["relationships"].append(reverse)
    refresh(case[1])
    with pytest.raises(ProvenanceError, match="cyclic"):
        validate(case, rebind=True)


def test_missing_ledger_commitment_rejected(case):
    from v17_integrity import InvestigationLedger
    ledger = InvestigationLedger(CASE_ID, case[2].events[:-1])
    with pytest.raises(ProvenanceError, match="missing ledger commitment"):
        validate_provenance(case[1], case_id=CASE_ID, ledger=ledger, files=inventory(case[0]))


def test_verified_manifest_does_not_hide_semantic_reference_failure(case):
    root, profile, ledger, private, public = case
    profile["ai_records"][0]["record"]["evidence_refs"] = ["MISSING"]
    refresh(profile)
    ledger = bind_fixture(profile)
    signed, trust = sign_fixture(ledger)
    _write_v17_metadata(root, ledger=ledger, signed_checkpoint=signed, trusted_public_keys=trust)
    (root / PROVENANCE_PATH).write_text(json.dumps(profile), encoding="utf-8")
    package = root.parent / "semantically-invalid.zip"
    export_v15(root, TENANT_ID, CASE_ID, private, package)
    report = verify_case(package, public, include_reconstruction=True)
    assert report["export_manifest_integrity"] == "PASS"
    assert report["provenance_integrity"] == "FAIL" and not report["valid"]
    assert "reconstruction" not in report


def test_modified_archive_is_never_reconstructed(case):
    package, public = export_fixture(case)
    bad = package.with_name("tampered.zip")
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(bad, "w") as target:
        for info in source.infolist():
            target.writestr(info, b"changed" if info.filename == "raw.json" else source.read(info))
    report = verify_case(bad, public, include_reconstruction=True)
    assert not report["valid"] and "reconstruction" not in report
    assert report["provenance_integrity"] == "NOT_RUN"


def test_recorded_comparison_preserves_original_and_does_not_claim_reproduction(case):
    profile = case[1]
    profile.update(content_policy="reviewed-content", content_review={"reviewer": "synthetic-reviewer", "reviewed_at": TIMESTAMP})
    profile["ai_records"][0]["record"]["structured_output"] = {"verdict": "qualified"}
    later = AIProvenanceRecord(**{**profile["ai_records"][0]["record"], "invocation_id": "AI-002", "tool_calls": [], "timestamp": "2026-09-06T00:01:00Z"})
    profile["ai_records"].append(wrap_record("ai_records", later))
    profile["comparisons"].append({"original": "AI-001", "comparison": "AI-002"})
    refresh(profile)
    package, public = export_fixture(case, ledger=bind_fixture(profile))
    comparison = verify_case(package, public, include_reconstruction=True)["reconstruction"]["comparisons"][0]
    assert comparison["same_recorded_output"] is True
    assert comparison["deterministic_reproduction_proven"] is False


@pytest.mark.parametrize("unsupported", [True, False])
def test_requested_replay_failure_has_nonzero_cli_exit(case, unsupported):
    profile = case[1]
    if unsupported:
        profile["relationships"][0]["record"]["transformation"] = "arbitrary.module.command"
    else:
        # Integrity can pass for an honestly preserved but incorrect transform.
        (case[0] / "normalized.json").write_text("{}", encoding="utf-8")
        profile["artifacts"][1]["record"]["sha256"] = sha256_object({})
    refresh(profile)
    package, public = export_fixture(case, ledger=bind_fixture(profile))
    cp = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "replay_case_v17.py"),
                         "--zip", str(package), "--export-public-key", str(public), "--replay-transforms"],
                        text=True, capture_output=True)
    assert cp.returncode == 1, cp.stderr
    report = json.loads(cp.stdout)
    assert report["valid"] is True
    assert report["reconstruction"]["deterministic_replay"]["status"] == ("INCOMPLETE" if unsupported else "FAIL")


def test_duplicate_profile_json_key_rejected_before_interpretation(case):
    root, profile, ledger, private, public = case
    signed, trust = sign_fixture(ledger)
    _write_v17_metadata(root, ledger=ledger, signed_checkpoint=signed, trusted_public_keys=trust)
    raw = json.dumps(profile)
    (root / PROVENANCE_PATH).write_text('{"case_id":"OTHER",' + raw[1:], encoding="utf-8")
    package = root.parent / "duplicate-key.zip"
    export_v15(root, TENANT_ID, CASE_ID, private, package)
    report = verify_case(package, public)
    assert not report["valid"] and report["provenance_integrity"] == "FAIL"


def test_rfc8785_transform_replays_exact_canonical_bytes(case):
    from v17_integrity import canonical_json_bytes, sha256_bytes
    canonical = canonical_json_bytes(json.loads((case[0] / "raw.json").read_bytes()))
    (case[0] / "normalized.json").write_bytes(canonical)
    case[1]["artifacts"][1]["record"]["sha256"] = sha256_bytes(canonical)
    case[1]["relationships"][0]["record"].update(transformation="RFC8785", transformation_version="1", metadata={})
    refresh(case[1])
    package, public = export_fixture(case, ledger=bind_fixture(case[1]))
    result = verify_case(package, public, replay_transforms=True)["reconstruction"]["deterministic_replay"]
    assert result["status"] == "PASS"
    assert result["transforms"][0]["comparison_basis"] == "exact-bytes"

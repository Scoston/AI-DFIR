from __future__ import annotations

import copy
import json
import socket
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_export_v17 import export_case, verify_case
from v17_integrity import canonical_json_bytes, sha256_object
from v17_key_policy_selftest import synthetic_export
from v17_policy_distribution import PolicyUpdateError, accept_policy_update, load_policy_store
from v17_policy_governance import (
    MAX_ROTATION_BYTES, MAX_ROOT_BYTES, ROOT_SCHEMA, ROTATION_SCHEMA, accept_governed_update,
    cosign_root_rotation, initialize_governed_store, inspect_governed_root, load_governed_store,
    load_root, migrate_governed_store, sign_root_rotation, validate_root, validate_rotation, verify_root_rotation,
)
from v17_policy_governance_selftest import approved_policy, approved_rotation, root_fixture, synthetic_governance
from v17_policy_quorum_selftest import synthetic_quorum
from v17_provenance_selftest import CASE_ID, TENANT_ID
from v17_signing import key_id_from_public_key_bytes, public_key_bytes
from verify_case_v17 import render_verification_report

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def case(tmp_path):
    return synthetic_export(tmp_path)


@pytest.fixture
def governance(case, tmp_path):
    return synthetic_governance(case, tmp_path / "governed.sqlite")


def install(fixture):
    return initialize_governed_store(fixture["path"], fixture["anchor"], fixture["initial"]["envelope"])


def rotate(fixture):
    return accept_governed_update(fixture["path"], fixture["anchor"], fixture["policy"], rotation=fixture["rotation"])


def options(fixture):
    return {"checkpoint_policy_store": fixture["path"], "policy_root_anchor": fixture["anchor"],
            "require_authenticated_key_policy": True}


def test_signed_rotation_reconstructs_offline_with_independent_anchor(case, governance, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    install(governance)
    rotate(governance)
    result = verify_case(case["package"], case["public"], include_reconstruction=True, **options(governance))
    assert result["valid"] and result["reconstruction"]
    root = result["checkpoint_key_policy"]["authentication"]["issuer_root"]
    assert root["status"] == "PASS" and root["root_version"] == 2 and root["rotations_verified"] == 1
    assert root["anchor_sha256"] == sha256_object(governance["anchor"])
    assert root["root_sha256"] == sha256_object(governance["root"])
    assert root["latest_rotation_approvals"]["previous"]["valid_signatures"] == 2
    assert root["latest_rotation_approvals"]["replacement"]["required_signatures"] == 2
    assert not root["historical_approval_time_proven"] and not root["network_performed"]
    assert "Policy root version: 2" in render_verification_report(result)


@pytest.mark.parametrize("role,count", [("previous", 0), ("previous", 1), ("replacement", 0), ("replacement", 1)])
def test_each_issuer_group_must_meet_its_own_threshold(governance, role, count):
    install(governance)
    before = governance["path"].read_bytes()
    rotation = copy.deepcopy(governance["rotation"])
    rotation["signatures"][role] = rotation["signatures"][role][:count]
    with pytest.raises(PolicyUpdateError) as error:
        accept_governed_update(governance["path"], governance["anchor"], governance["policy"], rotation=rotation)
    assert error.value.code == "root_rotation_quorum_not_met"
    assert governance["path"].read_bytes() == before


@pytest.mark.parametrize("role", ["previous", "replacement"])
def test_duplicate_signatures_never_count_as_another_issuer(governance, role):
    rotation = copy.deepcopy(governance["rotation"])
    row = rotation["signatures"][role][0]
    rotation["signatures"][role] = [row, copy.deepcopy(row)]
    with pytest.raises(PolicyUpdateError) as error:
        verify_root_rotation(governance["anchor"], rotation)
    assert error.value.code == "root_rotation_duplicate_signature"


@pytest.mark.parametrize("role", ["previous", "replacement"])
def test_invalid_extra_signature_is_rejected_even_with_enough_other_approvals(governance, role):
    source = governance["initial"] if role == "previous" else governance["replacement"]
    rotation = cosign_root_rotation(governance["anchor"], governance["rotation"], source["keys"][2], role)
    rotation["signatures"][role][-1]["signature_hex"] = "00" * 64
    with pytest.raises(PolicyUpdateError) as error:
        verify_root_rotation(governance["anchor"], rotation)
    assert error.value.code == "root_rotation_signature_invalid"


def test_unapproved_issuer_cannot_sign_or_add_an_extra_vote(governance):
    key = Ed25519PrivateKey.generate()
    with pytest.raises(PolicyUpdateError) as error:
        cosign_root_rotation(governance["anchor"], governance["rotation"], key, "previous")
    assert error.value.code == "root_rotation_issuer_untrusted"
    rotation = copy.deepcopy(governance["rotation"])
    ident = key_id_from_public_key_bytes(public_key_bytes(key.public_key()))
    rotation["signatures"]["previous"].append({"issuer_key_id": ident, "signature_hex": "00" * 64})
    with pytest.raises(PolicyUpdateError) as error:
        verify_root_rotation(governance["anchor"], rotation)
    assert error.value.code == "root_rotation_issuer_untrusted"


def test_an_approval_cannot_be_reused_for_the_other_role_even_with_overlapping_keys(governance):
    previous = governance["anchor"]
    replacement = dict(previous, version=2)
    keys = governance["initial"]["keys"][:2]
    rotation = approved_rotation(previous, replacement, keys, keys)
    assert verify_root_rotation(previous, rotation)["root"]["version"] == 2
    rotation["signatures"]["replacement"] = copy.deepcopy(rotation["signatures"]["previous"])
    with pytest.raises(PolicyUpdateError) as error:
        verify_root_rotation(previous, rotation)
    assert error.value.code == "root_rotation_signature_invalid"


def test_lowering_replacement_threshold_invalidates_previous_approvals(governance):
    rotation = copy.deepcopy(governance["rotation"])
    rotation["root"]["issuer_trust"]["threshold"] = 1
    with pytest.raises(PolicyUpdateError) as error:
        verify_root_rotation(governance["anchor"], rotation)
    assert error.value.code == "root_rotation_signature_invalid"


@pytest.mark.parametrize("version", [1, 0, 3, True])
def test_root_versions_cannot_rollback_repeat_or_skip(governance, version):
    rotation = copy.deepcopy(governance["rotation"])
    rotation["root"]["version"] = version
    with pytest.raises(PolicyUpdateError):
        verify_root_rotation(governance["anchor"], rotation)


@pytest.mark.parametrize("field", ["tenant_id", "policy_id"])
def test_rotation_cannot_change_the_investigation_namespace(governance, field):
    root = copy.deepcopy(governance["root"])
    root["issuer_trust"][field] = "different-namespace"
    with pytest.raises(PolicyUpdateError) as error:
        sign_root_rotation(governance["anchor"], root, governance["initial"]["keys"][0], "previous")
    assert error.value.code == "root_rotation_scope_mismatch"


def test_rotation_requires_exact_predecessor_and_monotonic_issuance(governance):
    rotation = copy.deepcopy(governance["rotation"])
    rotation["previous_root_sha256"] = "00" * 32
    with pytest.raises(PolicyUpdateError) as error:
        verify_root_rotation(governance["anchor"], rotation)
    assert error.value.code == "root_rotation_predecessor_mismatch"
    root = dict(governance["root"], issued_at="2000-01-01T00:00:00Z")
    with pytest.raises(PolicyUpdateError) as error:
        sign_root_rotation(governance["anchor"], root, governance["initial"]["keys"][0], "previous")
    assert error.value.code == "root_rotation_time_invalid"


@pytest.mark.parametrize("change", [
    lambda r: r.update(schema="other"), lambda r: r.update(version=2**53),
    lambda r: r.update(issued_at="invalid"), lambda r: r.update(expires_at=r["issued_at"]),
    lambda r: r.update(allow_unsigned=True), lambda r: r["issuer_trust"].update(threshold=0),
])
def test_root_configuration_is_strict_and_bounded(governance, change):
    root = copy.deepcopy(governance["root"])
    change(root)
    with pytest.raises(PolicyUpdateError):
        validate_root(root)


@pytest.mark.parametrize("change", [
    lambda r: r.update(signature_algorithm="none"), lambda r: r.update(schema="other"),
    lambda r: r.update(previous_root_sha256="A" * 64), lambda r: r.update(skip_previous=True),
    lambda r: r["signatures"].update(extra=[]), lambda r: r["signatures"].pop("previous"),
    lambda r: r["signatures"].update(previous=r["signatures"]["previous"] * 33),
    lambda r: r["signatures"]["previous"][0].update(signature_hex="00"),
])
def test_rotation_envelope_rejects_malformed_and_unbounded_approvals(governance, change):
    rotation = copy.deepcopy(governance["rotation"])
    change(rotation)
    with pytest.raises(PolicyUpdateError):
        validate_rotation(rotation)


def test_complete_rotation_cannot_activate_an_old_or_unapproved_policy(governance):
    install(governance)
    before = governance["path"].read_bytes()
    with pytest.raises(PolicyUpdateError):
        accept_governed_update(governance["path"], governance["anchor"], governance["initial"]["envelope"], rotation=governance["rotation"])
    assert governance["path"].read_bytes() == before
    policy = approved_policy(dict(governance["policy"]["policy"], revision=1), governance["replacement"]["keys"][:2], governance["root"]["issuer_trust"])
    with pytest.raises(PolicyUpdateError) as error:
        accept_governed_update(governance["path"], governance["anchor"], policy, rotation=governance["rotation"])
    assert error.value.code == "policy_revision_conflict" and governance["path"].read_bytes() == before


def test_policy_only_update_and_exact_retries_preserve_root_history(governance):
    install(governance)
    first = rotate(governance)
    retry = rotate(governance)
    assert retry["status"] == "UNCHANGED" and retry["authentication"]["accepted_at"] == first["authentication"]["accepted_at"]
    root_time = first["authentication"]["issuer_root"]["root_accepted_at"]
    policy = approved_policy(dict(governance["policy"]["policy"], revision=3), governance["replacement"]["keys"][:2], governance["root"]["issuer_trust"])
    updated = accept_governed_update(governance["path"], governance["anchor"], policy)
    assert updated["authentication"]["policy_revision"] == 3
    assert updated["authentication"]["issuer_root"]["root_accepted_at"] == root_time
    assert accept_governed_update(governance["path"], governance["anchor"], policy)["status"] == "UNCHANGED"
    with pytest.raises(PolicyUpdateError):
        rotate(governance)


def test_old_issuer_group_loses_policy_authority_after_rotation(governance):
    install(governance)
    rotate(governance)
    old = governance["initial"]
    candidate = approved_policy(dict(old["policy"], revision=3), old["keys"][:2], old["trust"])
    with pytest.raises(PolicyUpdateError) as error:
        accept_governed_update(governance["path"], governance["anchor"], candidate)
    assert error.value.code == "policy_quorum_trust_mismatch"


def test_root_and_policy_roll_back_together_after_write_failure(governance, monkeypatch):
    import v17_policy_governance as module
    install(governance)
    before = governance["path"].read_bytes()
    original = module._write_root
    def failed(*args):
        original(*args)
        raise sqlite3.OperationalError("synthetic failure after both writes")
    monkeypatch.setattr(module, "_write_root", failed)
    with pytest.raises(PolicyUpdateError) as error:
        rotate(governance)
    assert error.value.code == "governance_store_write_failed" and governance["path"].read_bytes() == before
    result = load_governed_store(governance["path"], governance["anchor"])
    assert result["root"]["version"] == result["policy"]["revision"] == 1


def test_expired_predecessor_can_authorize_recovery_but_cannot_authorize_case_use(case, governance, monkeypatch):
    import v17_policy_governance as module
    import v17_policy_distribution as distribution
    instant = datetime.now(timezone.utc)
    expires = instant + timedelta(minutes=2)
    governance["anchor"]["expires_at"] = expires.isoformat().replace("+00:00", "Z")
    install(governance)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return expires
    monkeypatch.setattr(module, "datetime", Clock)
    monkeypatch.setattr(distribution, "datetime", Clock)
    result = verify_case(case["package"], case["public"], key_policy_evaluated_at=governance["initial"]["policy"]["issued_at"], **options(governance))
    assert not result["valid"]
    assert result["checkpoint_key_policy"]["authentication"]["findings"][0]["code"] == "issuer_root_not_current"
    exported = inspect_governed_root(governance["path"], governance["anchor"])
    assert not exported["current_by_system_clock"] and not exported["policy_acceptance_checked"]
    replacement = dict(governance["root"], issued_at=expires.isoformat().replace("+00:00", "Z"))
    transition = approved_rotation(governance["anchor"], replacement, governance["initial"]["keys"][:2], governance["replacement"]["keys"][:2])
    accept_governed_update(governance["path"], governance["anchor"], governance["policy"], rotation=transition)
    recovered = load_governed_store(governance["path"], governance["anchor"])
    assert recovered["root"]["version"] == 2 and recovered["authentication"]["issuer_root"]["status"] == "PASS"


@pytest.mark.parametrize("kind", ["expired", "future"])
def test_noncurrent_anchor_cannot_initialize_a_store(governance, kind):
    instant = datetime.now(timezone.utc)
    if kind == "expired":
        governance["anchor"]["expires_at"] = (instant - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    else:
        governance["anchor"]["issued_at"] = (instant + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    with pytest.raises(PolicyUpdateError) as error:
        install(governance)
    assert error.value.code == "issuer_root_not_current" and not governance["path"].exists()


def test_future_root_activation_fails_without_changing_current_state(governance):
    install(governance)
    future = dict(governance["root"], issued_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"))
    transition = approved_rotation(governance["anchor"], future, governance["initial"]["keys"][:2], governance["replacement"]["keys"][:2])
    with pytest.raises(PolicyUpdateError) as error:
        accept_governed_update(governance["path"], governance["anchor"], governance["policy"], rotation=transition)
    assert error.value.code == "issuer_root_not_current"
    assert load_governed_store(governance["path"], governance["anchor"])["root"]["version"] == 1


def test_root_expiry_after_waiting_for_write_lock_prevents_commit(governance, monkeypatch):
    import v17_policy_governance as module
    install(governance)
    original = module._transaction
    from contextlib import contextmanager
    @contextmanager
    def delayed(*args, **kwargs):
        with original(*args, **kwargs) as connection:
            class Clock(datetime):
                @classmethod
                def now(cls, tz=None):
                    return datetime.fromisoformat(governance["root"]["expires_at"].replace("Z", "+00:00"))
            monkeypatch.setattr(module, "datetime", Clock)
            yield connection
    monkeypatch.setattr(module, "_transaction", delayed)
    before = governance["path"].read_bytes()
    with pytest.raises(PolicyUpdateError) as error:
        rotate(governance)
    assert error.value.code == "issuer_root_not_current" and governance["path"].read_bytes() == before


def test_concurrent_competing_rotations_never_mix_root_and_policy(case, governance):
    install(governance)
    alternative = synthetic_quorum(case, governance["path"])
    root = root_fixture(alternative["trust"], 2, issued_at=governance["anchor"]["issued_at"])
    transition = approved_rotation(governance["anchor"], root, governance["initial"]["keys"][:2], alternative["keys"][:2])
    policy = approved_policy(dict(alternative["policy"], revision=3), alternative["keys"][:2], alternative["trust"])
    barrier = Barrier(2)
    def accept(pair):
        barrier.wait(timeout=5)
        try:
            return accept_governed_update(governance["path"], governance["anchor"], pair[1], rotation=pair[0])["status"]
        except PolicyUpdateError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(accept, [(governance["rotation"], governance["policy"]), (transition, policy)]))
    assert sorted(outcomes) == ["ACCEPTED", "root_rotation_predecessor_mismatch"]
    stored = load_governed_store(governance["path"], governance["anchor"])
    assert stored["envelope"]["issuer_trust_sha256"] == sha256_object(stored["root"]["issuer_trust"])
    assert stored["policy"]["revision"] in {2, 3}


def test_explicit_migration_preserves_existing_quorum_revision_and_acceptance_time(governance):
    old = governance["initial"]
    accepted = accept_policy_update(governance["path"], old["envelope"], old["trust"], initialize=True)
    migrated = migrate_governed_store(governance["path"], governance["anchor"])
    assert migrated["status"] == "MIGRATED"
    assert migrated["authentication"]["accepted_at"] == accepted["authentication"]["accepted_at"]
    assert migrated["authentication"]["policy_revision"] == 1
    rotate(governance)
    with pytest.raises(PolicyUpdateError):
        load_policy_store(governance["path"], governance["root"]["issuer_trust"])
    with pytest.raises(PolicyUpdateError):
        accept_policy_update(governance["path"], governance["policy"], governance["root"]["issuer_trust"])


def test_failed_migration_restores_original_format_and_revision(governance, monkeypatch):
    import v17_policy_governance as module
    old = governance["initial"]
    accept_policy_update(governance["path"], old["envelope"], old["trust"], initialize=True)
    before = governance["path"].read_bytes()
    original = module._write_root
    def fail(*args):
        original(*args)
        raise sqlite3.OperationalError("synthetic migration failure")
    monkeypatch.setattr(module, "_write_root", fail)
    with pytest.raises(PolicyUpdateError):
        migrate_governed_store(governance["path"], governance["anchor"])
    assert governance["path"].read_bytes() == before
    assert load_policy_store(governance["path"], old["trust"])["policy"]["revision"] == 1


def test_governed_read_never_implicitly_migrates_a_legacy_store(governance):
    old = governance["initial"]
    accept_policy_update(governance["path"], old["envelope"], old["trust"], initialize=True)
    before = governance["path"].read_bytes()
    with pytest.raises(PolicyUpdateError) as error:
        load_governed_store(governance["path"], governance["anchor"])
    assert error.value.code == "governance_store_invalid" and governance["path"].read_bytes() == before


def test_missing_store_is_not_reinitialized_and_existing_store_is_not_overwritten(governance):
    with pytest.raises(PolicyUpdateError):
        rotate(governance)
    assert not governance["path"].exists()
    install(governance)
    before = governance["path"].read_bytes()
    with pytest.raises(FileExistsError):
        install(governance)
    assert governance["path"].read_bytes() == before


def test_wrong_anchor_cannot_authorize_the_retained_chain(governance):
    install(governance)
    altered = dict(governance["anchor"], version=8)
    with pytest.raises(PolicyUpdateError) as error:
        load_governed_store(governance["path"], altered)
    assert error.value.code == "issuer_root_anchor_mismatch"


def test_rehashed_chain_with_invalid_historical_signature_is_rejected(governance):
    install(governance)
    rotate(governance)
    chain = [copy.deepcopy(governance["rotation"])]
    chain[0]["signatures"]["previous"][0]["signature_hex"] = "00" * 64
    with sqlite3.connect(governance["path"]) as connection:
        connection.execute("UPDATE issuer_governance SET chain_json=?", (json.dumps(chain),))
    with pytest.raises(PolicyUpdateError) as error:
        load_governed_store(governance["path"], governance["anchor"])
    assert error.value.code == "root_rotation_signature_invalid"


@pytest.mark.parametrize("sql", [
    "UPDATE issuer_governance SET root_version=9", "UPDATE issuer_governance SET chain_json='[]'",
    "CREATE VIEW extra AS SELECT * FROM issuer_governance", "DELETE FROM issuer_governance",
    "UPDATE issuer_governance SET accepted_at='invalid'", "PRAGMA user_version=1",
])
def test_tampered_or_extended_governance_store_fails_closed(governance, sql):
    install(governance)
    rotate(governance)
    with sqlite3.connect(governance["path"]) as connection:
        connection.execute(sql)
    with pytest.raises(PolicyUpdateError):
        load_governed_store(governance["path"], governance["anchor"])


def test_independent_floors_detect_older_whole_store_backup(governance):
    install(governance)
    backup = governance["path"].read_bytes()
    rotate(governance)
    governance["path"].write_bytes(backup)
    assert load_governed_store(governance["path"], governance["anchor"])["root"]["version"] == 1
    for floor in ({"minimum_revision": 2}, {"minimum_root_version": 2}):
        with pytest.raises(PolicyUpdateError) as error:
            load_governed_store(governance["path"], governance["anchor"], **floor)
        assert error.value.code == "governance_below_floor"


@pytest.mark.parametrize("name", ["minimum_revision", "minimum_root_version"])
@pytest.mark.parametrize("value", [0, True, 1.5, 2**53])
def test_governance_floors_reject_ambiguous_values(governance, name, value):
    install(governance)
    with pytest.raises(PolicyUpdateError) as error:
        load_governed_store(governance["path"], governance["anchor"], **{name: value})
    assert error.value.code == "governance_floor_invalid"


def test_bounded_chain_prevents_unlimited_root_history(governance, monkeypatch):
    import v17_policy_governance as module
    install(governance)
    monkeypatch.setattr(module, "MAX_ROTATIONS", 0)
    before = governance["path"].read_bytes()
    with pytest.raises(PolicyUpdateError) as error:
        rotate(governance)
    assert error.value.code == "root_chain_invalid" and governance["path"].read_bytes() == before


def test_rotation_signature_material_is_role_and_schema_bound_standard_ed25519(governance):
    rotation = governance["rotation"]
    for role, source in (("previous", governance["initial"]), ("replacement", governance["replacement"])):
        for key in source["keys"][:2]:
            ident = key_id_from_public_key_bytes(public_key_bytes(key.public_key()))
            row = next(row for row in rotation["signatures"][role] if row["issuer_key_id"] == ident)
            material = {"schema": ROTATION_SCHEMA, "signature_algorithm": "Ed25519", "previous_root_sha256": rotation["previous_root_sha256"],
                        "root": rotation["root"], "role": role, "issuer_key_id": ident}
            key.public_key().verify(bytes.fromhex(row["signature_hex"]), canonical_json_bytes(material))


def test_embedded_anchor_never_supplies_verifier_authority(case, governance):
    (case["root"] / "issuer-root.json").write_text(json.dumps(governance["anchor"]), encoding="utf-8")
    export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                signed_checkpoint=case["signed"], trusted_public_keys=case["trust"], provenance=case["profile"])
    install(governance)
    report = verify_case(case["package"], case["public"], checkpoint_policy_store=governance["path"], require_authenticated_key_policy=True)
    assert not report["valid"] and report["checkpoint_key_policy"]["authentication"]["status"] == "FAIL"


@pytest.mark.parametrize("kwargs", [{"minimum_root_version": 1}, {"policy_root_anchor": {}}, {"minimum_root_version": 0}])
def test_root_requirements_never_fall_back_to_raw_policy(case, kwargs):
    report = verify_case(case["package"], case["public"], checkpoint_key_policy=case["policy"], **kwargs)
    assert not report["valid"] and report["checkpoint_key_policy"]["authentication"]["status"] == "FAIL"


def test_root_anchor_and_direct_issuer_trust_cannot_compete(case, governance):
    install(governance)
    report = verify_case(case["package"], case["public"], policy_issuer_trust=governance["initial"]["trust"], **options(governance))
    assert not report["valid"] and report["checkpoint_key_policy"]["authentication"]["status"] == "FAIL"


def test_valid_governance_cannot_rescue_tampered_evidence(case, governance, tmp_path):
    import zipfile
    install(governance)
    rotate(governance)
    bad = tmp_path / "tampered.zip"
    with zipfile.ZipFile(case["package"]) as source, zipfile.ZipFile(bad, "w") as destination:
        for member in source.infolist():
            destination.writestr(member, b"[]" if member.filename == "raw.json" else source.read(member.filename))
    report = verify_case(bad, case["public"], include_reconstruction=True, **options(governance))
    assert report["checkpoint_key_policy"]["authentication"]["issuer_root"]["status"] == "PASS"
    assert not report["valid"] and report["artifact_integrity"] == "FAIL" and "reconstruction" not in report


def test_governance_composes_with_external_timestamp_and_revocation(case, governance, tmp_path):
    from v17_timestamp_selftest import synthetic_tsa, timestamp_fixture
    install(governance)
    rotate(governance)
    timestamp = timestamp_fixture(case, synthetic_tsa(tmp_path / "tsa"))
    report = verify_case(case["package"], case["public"], **options(governance), **timestamp)
    assert report["valid"] and report["checkpoint_timestamp"]["status"] == "PASS"
    policy = copy.deepcopy(governance["policy"]["policy"])
    policy["revision"] = 3
    policy["keys"][0].update(state="revoked", reason="synthetic", status_changed_at=policy["issued_at"])
    envelope = approved_policy(policy, governance["replacement"]["keys"][:2], governance["root"]["issuer_trust"])
    accept_governed_update(governance["path"], governance["anchor"], envelope)
    denied = verify_case(case["package"], case["public"], include_reconstruction=True, **options(governance), **timestamp)
    assert denied["signature_valid"] and not denied["valid"] and "reconstruction" not in denied


def test_export_preserves_destination_when_independent_root_floor_fails(case, governance):
    install(governance)
    rotate(governance)
    args = {"ledger": case["ledger"], "signed_checkpoint": case["signed"], "trusted_public_keys": case["trust"], "provenance": case["profile"]}
    good = export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], **args, **options(governance))
    assert good["checkpoint_key_policy"]["authentication"]["issuer_root"]["root_version"] == 2
    before = case["package"].read_bytes()
    with pytest.raises(ValueError, match="policy rejected export"):
        export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], **args, **options(governance), minimum_root_version=3)
    assert case["package"].read_bytes() == before


def cli_options(governance, tmp_path):
    anchor = tmp_path / "approved-anchor.json"
    anchor.write_text(json.dumps(governance["anchor"]), encoding="utf-8")
    return ["--checkpoint-policy-store", str(governance["path"]), "--policy-root-anchor", str(anchor), "--require-authenticated-key-policy"]


@pytest.mark.parametrize("script,extra", [("verify_case_v17.py", ["--format", "json"]),
    ("case_export_v17.py", ["verify"]), ("replay_case_v17.py", ["--replay-transforms"])])
def test_case_clis_enforce_signed_root_continuity_and_floor(case, governance, tmp_path, script, extra):
    install(governance)
    rotate(governance)
    args = [sys.executable, str(ROOT / script), *extra, "--zip", str(case["package"]),
            "--export-public-key", str(case["public"]), *cli_options(governance, tmp_path)]
    good = subprocess.run(args, capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(good.stdout)["checkpoint_key_policy"]["authentication"]["issuer_root"]["root_version"] == 2
    bad = subprocess.run(args + ["--minimum-root-version", "3"], capture_output=True, text=True)
    assert bad.returncode == 1 and "reconstruction" not in json.loads(bad.stdout)


@pytest.mark.parametrize("flag", ["--policy-root-anchor", "--policy-issuer-trust", "--checkpoint-key-policy"])
def test_empty_explicit_trust_paths_do_not_silently_disable_requirements(case, flag):
    result = subprocess.run([sys.executable, str(ROOT / "verify_case_v17.py"), "--zip", str(case["package"]),
                             "--export-public-key", str(case["public"]), flag, "", "--format", "json"], capture_output=True, text=True)
    assert result.returncode == 3


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "checkpoint_governance_v17.py"), *map(str, args)], capture_output=True, text=True)


def test_governance_cli_collects_both_roles_and_activates_a_policy(governance, tmp_path):
    anchor, replacement = tmp_path / "anchor.json", tmp_path / "next-root.json"
    anchor.write_text(json.dumps(governance["anchor"]), encoding="utf-8")
    trust = tmp_path / "new-trust.json"
    trust.write_text(json.dumps(governance["root"]["issuer_trust"]), encoding="utf-8")
    created = cli("root", "--issuer-trust", trust, "--version", "2", "--issued-at", governance["root"]["issued_at"],
                   "--expires-at", governance["root"]["expires_at"], "--out", replacement)
    assert created.returncode == 0 and load_root(replacement) == governance["root"]
    previous = None
    for index, (role, key) in enumerate([(r, k) for r, group in (("previous", governance["initial"]), ("replacement", governance["replacement"])) for k in group["keys"][:2]]):
        private = tmp_path / f"custodian-{index}.pem"
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        target = tmp_path / f"approval-{index}.json"
        args = ["sign", "--next-root", replacement] if previous is None else ["cosign", "--rotation", previous]
        signed = cli(*args, "--previous-root", anchor, "--role", role, "--issuer-private-key", private, "--out", target)
        assert signed.returncode == 0, signed.stdout + signed.stderr
        assert json.loads(signed.stdout)["status"] == ("SIGNED" if index == 3 else "PARTIALLY_SIGNED")
        assert not json.loads(signed.stdout)["acceptance_performed"]
        previous = target
    initial, policy = tmp_path / "initial-policy.json", tmp_path / "next-policy.json"
    initial.write_text(json.dumps(governance["initial"]["envelope"]), encoding="utf-8")
    policy.write_text(json.dumps(governance["policy"]), encoding="utf-8")
    shared = ["--store", governance["path"], "--anchor", anchor]
    assert cli("initialize", *shared, "--signed-policy", initial).returncode == 0
    partial = cli("accept", *shared, "--signed-policy", policy, "--rotation", tmp_path / "approval-1.json")
    assert partial.returncode == 1
    accepted = cli("accept", *shared, "--signed-policy", policy, "--rotation", previous)
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    shown = cli("show", *shared, "--minimum-root-version", "2", "--minimum-policy-revision", "2")
    assert shown.returncode == 0 and json.loads(shown.stdout)["root"]["version"] == 2
    exported = tmp_path / "current-root.json"
    assert cli("export-root", *shared, "--out", exported).returncode == 0
    before = exported.read_bytes()
    assert cli("export-root", *shared, "--out", exported).returncode == 3 and exported.read_bytes() == before
    assert load_root(exported) == governance["root"]
    assert cli("accept", *shared, "--signed-policy", initial).returncode == 1


def test_governance_cli_migration_preserves_revision(governance, tmp_path):
    old = governance["initial"]
    accept_policy_update(governance["path"], old["envelope"], old["trust"], initialize=True)
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps(governance["anchor"]), encoding="utf-8")
    result = cli("migrate", "--store", governance["path"], "--anchor", anchor)
    assert result.returncode == 0 and json.loads(result.stdout)["authentication"]["policy_revision"] == 1
    assert cli("migrate", "--store", governance["path"], "--anchor", anchor).returncode == 1


@pytest.mark.parametrize("kind,limit", [("root", MAX_ROOT_BYTES), ("rotation", MAX_ROTATION_BYTES)])
def test_root_and_rotation_inputs_are_bounded_before_parsing(governance, tmp_path, kind, limit):
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (limit + 1))
    if kind == "root":
        with pytest.raises(PolicyUpdateError) as error:
            load_root(path)
        assert error.value.code == "policy_update_size"
    else:
        anchor, policy = tmp_path / "anchor.json", tmp_path / "policy.json"
        anchor.write_text(json.dumps(governance["anchor"]), encoding="utf-8")
        policy.write_text(json.dumps(governance["policy"]), encoding="utf-8")
        install(governance)
        result = cli("accept", "--store", governance["path"], "--anchor", anchor, "--signed-policy", policy, "--rotation", path)
        assert result.returncode == 1 and json.loads(result.stdout)["code"] == "policy_update_size"


def test_export_cli_enforces_governed_root_before_replacing_destination(case, governance, tmp_path):
    from case_export_v17 import LEDGER_PATH, SIGNED_CHECKPOINT_PATH, TRUST_STORE_PATH, _write_v17_metadata
    install(governance)
    rotate(governance)
    _write_v17_metadata(case["root"], ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys=case["trust"])
    provenance = tmp_path / "provenance.json"
    provenance.write_text(json.dumps(case["profile"]), encoding="utf-8")
    destination = tmp_path / "governed-export.zip"
    args = [sys.executable, str(ROOT / "case_export_v17.py"), "create", "--case-root", str(case["root"]),
            "--tenant", TENANT_ID, "--case", CASE_ID, "--export-private-key", str(case["private"]),
            "--ledger", str(case["root"] / LEDGER_PATH), "--signed-checkpoint", str(case["root"] / SIGNED_CHECKPOINT_PATH),
            "--trusted-signers", str(case["root"] / TRUST_STORE_PATH), "--provenance", str(provenance),
            "--out", str(destination), *cli_options(governance, tmp_path)]
    good = subprocess.run(args, capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    before = destination.read_bytes()
    bad = subprocess.run(args + ["--minimum-root-version", "3"], capture_output=True, text=True)
    assert bad.returncode == 3 and destination.read_bytes() == before


def test_two_rotations_verify_the_full_chain_from_the_original_anchor(case, governance):
    install(governance)
    rotate(governance)
    third = synthetic_quorum(case, governance["path"])
    root = root_fixture(third["trust"], 3, issued_at=governance["root"]["issued_at"])
    transition = approved_rotation(governance["root"], root, governance["replacement"]["keys"][:2], third["keys"][:2])
    policy = approved_policy(dict(third["policy"], revision=3), third["keys"][:2], third["trust"])
    accept_governed_update(governance["path"], governance["anchor"], policy, rotation=transition)
    result = load_governed_store(governance["path"], governance["anchor"])
    assert result["authentication"]["issuer_root"]["rotations_verified"] == 2 and result["root"]["version"] == 3
    with sqlite3.connect(governance["path"]) as connection:
        chain = json.loads(connection.execute("SELECT chain_json FROM issuer_governance").fetchone()[0])
        chain[0]["signatures"]["previous"][0]["signature_hex"] = "00" * 64
        connection.execute("UPDATE issuer_governance SET chain_json=?", (json.dumps(chain),))
    with pytest.raises(PolicyUpdateError) as error:
        load_governed_store(governance["path"], governance["anchor"])
    assert error.value.code == "root_rotation_signature_invalid"


def test_expired_policy_can_be_replaced_without_resetting_its_revision(governance, monkeypatch):
    import v17_policy_distribution as distribution
    import v17_policy_governance as module
    expires = datetime.now(timezone.utc) + timedelta(minutes=2)
    old = governance["initial"]
    policy = dict(old["policy"], expires_at=expires.isoformat().replace("+00:00", "Z"))
    old["envelope"] = approved_policy(policy, old["keys"][:2], old["trust"])
    install(governance)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return expires
    monkeypatch.setattr(distribution, "datetime", Clock)
    monkeypatch.setattr(module, "datetime", Clock)
    with pytest.raises(PolicyUpdateError) as error:
        load_governed_store(governance["path"], governance["anchor"])
    assert error.value.code == "signed_policy_not_current"
    assert inspect_governed_root(governance["path"], governance["anchor"])["policy_acceptance_checked"] is False
    rotate(governance)
    assert load_governed_store(governance["path"], governance["anchor"])["policy"]["revision"] == 2

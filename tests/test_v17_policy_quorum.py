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
from v17_policy_distribution import (
    ISSUER_TRUST_SCHEMA, MAX_ISSUERS, PolicyUpdateError, accept_policy_update,
    authenticate_key_policy, load_issuer_trust, load_policy_store, sign_key_policy,
)
from v17_policy_quorum import (
    QUORUM_POLICY_SCHEMA, cosign_quorum_policy, sign_quorum_policy,
    validate_quorum_envelope, validate_quorum_trust,
)
from v17_policy_quorum_selftest import synthetic_quorum
from v17_provenance_selftest import CASE_ID, TENANT_ID
from v17_signing import key_id_from_public_key_bytes, public_key_bytes
from verify_case_v17 import render_verification_report

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def case(tmp_path):
    return synthetic_export(tmp_path)


@pytest.fixture
def quorum(case, tmp_path):
    return synthetic_quorum(case, tmp_path / "approved-policy.sqlite")


def install(fixture):
    return accept_policy_update(fixture["path"], fixture["envelope"], fixture["trust"], initialize=True)


def approved_policy(fixture, *, revision=2, trust=None, signers=None, **changes):
    policy = copy.deepcopy(fixture["policy"])
    policy.update(revision=revision, **changes)
    trust = fixture["trust"] if trust is None else trust
    signers = fixture["keys"][:2] if signers is None else signers
    value = sign_quorum_policy(policy, signers[0], trust)
    for key in signers[1:]:
        value = cosign_quorum_policy(value, key, trust)
    return value


def options(fixture):
    return {"checkpoint_policy_store": fixture["path"], "policy_issuer_trust": fixture["trust"],
            "require_authenticated_key_policy": True}


def public_row(key):
    raw = public_key_bytes(key.public_key())
    return {"key_id": key_id_from_public_key_bytes(raw), "public_key_hex": raw.hex()}


def legacy_trust(quorum):
    return {"schema": ISSUER_TRUST_SCHEMA, "tenant_id": quorum["trust"]["tenant_id"],
            "policy_id": quorum["trust"]["policy_id"], "keys": quorum["trust"]["keys"]}


def test_two_of_three_issuers_authorize_offline_reconstruction(case, quorum, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    install(quorum)
    result = verify_case(case["package"], case["public"], include_reconstruction=True, **options(quorum))
    assert result["valid"] and result["reconstruction"]
    auth = result["checkpoint_key_policy"]["authentication"]
    assert auth["status"] == "PASS" and auth["approval_profile"] == "issuer-quorum"
    assert auth["issuer_key_id"] is None and len(set(auth["issuer_key_ids"])) == 2
    assert auth["valid_signatures"] == auth["required_signatures"] == 2
    assert auth["issuer_trust_sha256"] == quorum["envelope"]["issuer_trust_sha256"]
    assert auth["issuer_custodian_independence"] == "NOT_ASSESSED" and not auth["network_performed"]
    text = render_verification_report(result)
    assert "Policy valid/required signatures: 2/2" in text and "issuer-quorum" in text


def test_one_compromised_issuer_cannot_install_or_advance_a_policy(quorum, tmp_path):
    new = tmp_path / "partial.sqlite"
    with pytest.raises(PolicyUpdateError) as error:
        accept_policy_update(new, quorum["partial"], quorum["trust"], initialize=True)
    assert error.value.code == "policy_quorum_not_met" and not new.exists()
    install(quorum)
    before = quorum["path"].read_bytes()
    partial = approved_policy(quorum, revision=2**53 - 1, signers=quorum["keys"][:1])
    with pytest.raises(PolicyUpdateError, match="enough distinct"):
        accept_policy_update(quorum["path"], partial, quorum["trust"])
    assert quorum["path"].read_bytes() == before


def test_quorum_revocation_denies_checkpoint_and_preserves_rollback_guard(case, quorum):
    install(quorum)
    revoked = copy.deepcopy(quorum["policy"]["keys"])
    revoked[0].update(state="revoked", reason="synthetic", status_changed_at=quorum["policy"]["issued_at"])
    accept_policy_update(quorum["path"], approved_policy(quorum, keys=revoked), quorum["trust"])
    result = verify_case(case["package"], case["public"], include_reconstruction=True, **options(quorum))
    assert not result["valid"] and result["signature_valid"] and "reconstruction" not in result
    assert result["checkpoint_key_policy"]["authentication"]["status"] == "PASS"
    with pytest.raises(PolicyUpdateError) as error:
        accept_policy_update(quorum["path"], quorum["envelope"], quorum["trust"])
    assert error.value.code == "policy_revision_rollback"


@pytest.mark.parametrize("threshold", [0, -1, True, False, 1.5, "2", 4, 2**53])
def test_quorum_threshold_is_explicit_positive_and_achievable(quorum, threshold):
    trust = dict(quorum["trust"], threshold=threshold)
    with pytest.raises(PolicyUpdateError) as error:
        validate_quorum_trust(trust)
    assert error.value.code in {"policy_quorum_threshold_invalid", "policy_update_malformed"}


@pytest.mark.parametrize("change", [
    lambda t: t.update(schema=ISSUER_TRUST_SCHEMA),
    lambda t: t.update(keys=[]),
    lambda t: t.update(keys=t["keys"] + [t["keys"][0]]),
    lambda t: t.update(keys=t["keys"] * (MAX_ISSUERS + 1)),
    lambda t: t.update(allow_single_issuer=True),
    lambda t: t["keys"][0].update(key_id="sha256:" + "0" * 64),
    lambda t: t["keys"][0].update(public_key_hex=t["keys"][0]["public_key_hex"].upper()),
])
def test_issuer_aliases_duplicates_and_unknown_trust_fields_do_not_grant_votes(quorum, change):
    trust = copy.deepcopy(quorum["trust"])
    change(trust)
    with pytest.raises(PolicyUpdateError):
        validate_quorum_trust(trust)


@pytest.mark.parametrize("change", [
    lambda p: p.update(schema="ai-dfir/signed-checkpoint-key-policy/v1.7"),
    lambda p: p.update(signature_algorithm="none"),
    lambda p: p.update(threshold=1),
    lambda p: p.update(signatures=[]),
    lambda p: p.update(signatures=p["signatures"] * (MAX_ISSUERS + 1)),
    lambda p: p.update(issuer_trust_sha256="A" * 64),
    lambda p: p["signatures"][0].update(public_key_hex="0" * 64),
    lambda p: p["signatures"][0].update(issuer_key_id="missing"),
    lambda p: p["signatures"][0].update(signature_hex="00"),
])
def test_strict_quorum_envelope_rejects_ambiguous_or_unbounded_profiles(quorum, change):
    envelope = copy.deepcopy(quorum["envelope"])
    change(envelope)
    with pytest.raises(PolicyUpdateError):
        validate_quorum_envelope(envelope)


def test_repeating_a_valid_signature_never_satisfies_quorum(quorum):
    envelope = copy.deepcopy(quorum["partial"])
    envelope["signatures"].append(copy.deepcopy(envelope["signatures"][0]))
    with pytest.raises(PolicyUpdateError) as error:
        authenticate_key_policy(envelope, quorum["trust"])
    assert error.value.code == "policy_quorum_duplicate_signature"
    with pytest.raises(PolicyUpdateError) as error:
        cosign_quorum_policy(quorum["partial"], quorum["keys"][0], quorum["trust"])
    assert error.value.code == "policy_quorum_duplicate_signature"


@pytest.mark.parametrize("field,value", [("revision", 9), ("policy_id", "another-policy"), ("case_ids", None)])
def test_policy_mutation_cannot_reuse_collected_approvals(quorum, field, value):
    envelope = copy.deepcopy(quorum["envelope"])
    envelope["policy"][field] = value
    with pytest.raises(PolicyUpdateError):
        authenticate_key_policy(envelope, quorum["trust"])
    with pytest.raises(PolicyUpdateError):
        cosign_quorum_policy(envelope, quorum["keys"][2], quorum["trust"])


def test_approvals_from_different_revisions_cannot_be_mixed(quorum):
    changed = approved_policy(quorum, signers=quorum["keys"][1:2])
    mixed = copy.deepcopy(quorum["partial"])
    mixed["signatures"].extend(changed["signatures"])
    with pytest.raises(PolicyUpdateError) as error:
        authenticate_key_policy(mixed, quorum["trust"])
    assert error.value.code == "policy_issuer_signature_invalid"


@pytest.mark.parametrize("change", [
    lambda t: t.update(threshold=1),
    lambda t: t.update(threshold=3),
    lambda t: t["keys"].append(public_row(Ed25519PrivateKey.generate())),
    lambda t: t.update(policy_id="different-policy"),
])
def test_every_signature_binds_the_approved_governance_configuration(quorum, change):
    trust = copy.deepcopy(quorum["trust"])
    change(trust)
    trust = validate_quorum_trust(trust)
    with pytest.raises(PolicyUpdateError):
        authenticate_key_policy(quorum["envelope"], trust)
    changed = copy.deepcopy(quorum["envelope"])
    changed["issuer_trust_sha256"] = sha256_object(trust)
    with pytest.raises(PolicyUpdateError):
        authenticate_key_policy(changed, trust)


def test_single_issuer_profile_cannot_bypass_quorum_even_at_threshold_one(quorum):
    single = sign_key_policy(quorum["policy"], quorum["keys"][0])
    for threshold in (1, 2):
        with pytest.raises(PolicyUpdateError) as error:
            authenticate_key_policy(single, dict(quorum["trust"], threshold=threshold))
        assert error.value.code == "policy_approval_profile_mismatch"
    with pytest.raises(PolicyUpdateError):
        authenticate_key_policy(quorum["envelope"], legacy_trust(quorum))


def test_legacy_single_issuer_behavior_remains_available_explicitly(quorum):
    single = sign_key_policy(quorum["policy"], quorum["keys"][0])
    auth = authenticate_key_policy(single, legacy_trust(quorum))["authentication"]
    assert auth["approval_profile"] == "single-issuer" and auth["valid_signatures"] == auth["required_signatures"] == 1


def test_maximum_distinct_issuer_set_and_single_signature_quorum(quorum):
    keys = [Ed25519PrivateKey.generate() for _ in range(MAX_ISSUERS)]
    trust = dict(quorum["trust"], threshold=MAX_ISSUERS, keys=[public_row(key) for key in keys])
    envelope = approved_policy(quorum, trust=trust, signers=keys)
    assert authenticate_key_policy(envelope, trust)["authentication"]["valid_signatures"] == MAX_ISSUERS
    trust = dict(trust, threshold=1)
    envelope = sign_quorum_policy(quorum["policy"], keys[0], trust)
    assert authenticate_key_policy(envelope, trust)["authentication"]["required_signatures"] == 1


def test_ordering_of_trust_keys_and_signatures_does_not_create_new_identity(quorum):
    install(quorum)
    trust = copy.deepcopy(quorum["trust"])
    trust["keys"].reverse()
    envelope = copy.deepcopy(quorum["envelope"])
    envelope["signatures"].reverse()
    accepted = accept_policy_update(quorum["path"], envelope, trust)
    assert accepted["status"] == "UNCHANGED"
    assert accepted["authentication"]["envelope_sha256"] == sha256_object(quorum["envelope"])


def test_extra_valid_signature_requires_new_revision_once_stored(quorum):
    install(quorum)
    extra = cosign_quorum_policy(quorum["envelope"], quorum["keys"][2], quorum["trust"])
    assert authenticate_key_policy(extra, quorum["trust"])["authentication"]["valid_signatures"] == 3
    with pytest.raises(PolicyUpdateError) as error:
        accept_policy_update(quorum["path"], extra, quorum["trust"])
    assert error.value.code == "policy_revision_conflict"


def test_invalid_extra_signature_is_not_ignored_after_threshold_is_met(quorum):
    envelope = cosign_quorum_policy(quorum["envelope"], quorum["keys"][2], quorum["trust"])
    envelope["signatures"][2]["signature_hex"] = "00" * 64
    with pytest.raises(PolicyUpdateError) as error:
        authenticate_key_policy(envelope, quorum["trust"])
    assert error.value.code == "policy_issuer_signature_invalid"


def test_untrusted_extra_signer_and_untrusted_cosigning_key_are_rejected(quorum):
    key = Ed25519PrivateKey.generate()
    with pytest.raises(PolicyUpdateError) as error:
        cosign_quorum_policy(quorum["partial"], key, quorum["trust"])
    assert error.value.code == "policy_issuer_untrusted"
    envelope = copy.deepcopy(quorum["envelope"])
    envelope["signatures"].append({"issuer_key_id": public_row(key)["key_id"], "signature_hex": "00" * 64})
    with pytest.raises(PolicyUpdateError) as error:
        authenticate_key_policy(envelope, quorum["trust"])
    assert error.value.code == "policy_issuer_untrusted"


def test_even_nonparticipating_quorum_issuer_cannot_be_a_checkpoint_key(quorum):
    trust = copy.deepcopy(quorum["trust"])
    checkpoint = quorum["policy"]["keys"][0]
    trust["keys"].append({"key_id": checkpoint["key_id"], "public_key_hex": checkpoint["public_key_hex"]})
    with pytest.raises(PolicyUpdateError) as error:
        sign_quorum_policy(quorum["policy"], quorum["keys"][0], trust)
    assert error.value.code == "policy_issuer_key_reuse"


def test_quorum_rotation_invalidates_old_approvals_without_resetting_revision(quorum):
    install(quorum)
    new_key = Ed25519PrivateKey.generate()
    keys = [quorum["keys"][1], quorum["keys"][2], new_key]
    trust = dict(quorum["trust"], keys=[public_row(key) for key in keys])
    with pytest.raises(PolicyUpdateError) as error:
        load_policy_store(quorum["path"], trust)
    assert error.value.code == "policy_quorum_trust_mismatch"
    changed = approved_policy(quorum, trust=trust, signers=keys[:2])
    accept_policy_update(quorum["path"], changed, trust)
    assert load_policy_store(quorum["path"], trust)["policy"]["revision"] == 2
    with pytest.raises(PolicyUpdateError) as error:
        accept_policy_update(quorum["path"], approved_policy(quorum, revision=1, trust=trust, signers=keys[:2]), trust)
    assert error.value.code == "policy_revision_rollback"


def test_migrate_existing_single_issuer_store_at_a_higher_revision(quorum):
    single = sign_key_policy(quorum["policy"], quorum["keys"][0])
    accept_policy_update(quorum["path"], single, legacy_trust(quorum), initialize=True)
    with pytest.raises(PolicyUpdateError):
        load_policy_store(quorum["path"], quorum["trust"])
    accept_policy_update(quorum["path"], approved_policy(quorum), quorum["trust"])
    assert load_policy_store(quorum["path"], quorum["trust"])["authentication"]["approval_profile"] == "issuer-quorum"


def test_store_reauthenticates_signatures_even_if_attacker_recomputes_hashes(quorum):
    install(quorum)
    envelope = copy.deepcopy(quorum["envelope"])
    envelope["signatures"][0]["signature_hex"] = "00" * 64
    with sqlite3.connect(quorum["path"]) as connection:
        connection.execute("UPDATE checkpoint_policy SET envelope_json=?,envelope_sha256=?",
                           (canonical_json_bytes(envelope).decode(), sha256_object(envelope)))
    with pytest.raises(PolicyUpdateError) as error:
        load_policy_store(quorum["path"], quorum["trust"])
    assert error.value.code == "policy_issuer_signature_invalid"


def test_concurrent_quorum_updates_keep_highest_revision(quorum):
    install(quorum)
    barrier = Barrier(2)
    def accept(envelope):
        barrier.wait(timeout=5)
        try:
            return accept_policy_update(quorum["path"], envelope, quorum["trust"])["status"]
        except PolicyUpdateError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(accept, [approved_policy(quorum, revision=2), approved_policy(quorum, revision=3)]))
    assert set(outcomes) <= {"ACCEPTED", "policy_revision_rollback"}
    assert load_policy_store(quorum["path"], quorum["trust"])["policy"]["revision"] == 3


def test_current_clock_expiry_cannot_be_backdated_for_quorum(case, quorum, monkeypatch):
    install(quorum)
    import v17_policy_distribution as distribution
    expired = datetime.fromisoformat(quorum["policy"]["expires_at"].replace("Z", "+00:00"))
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return expired
    monkeypatch.setattr(distribution, "datetime", Clock)
    result = verify_case(case["package"], case["public"], key_policy_evaluated_at=quorum["policy"]["issued_at"], **options(quorum))
    assert not result["valid"]
    assert result["checkpoint_key_policy"]["authentication"]["findings"][0]["code"] == "signed_policy_not_current"


def test_copying_trust_into_case_cannot_satisfy_external_quorum(case, quorum):
    embedded = case["root"] / "policy-issuer-quorum.json"
    embedded.write_text(json.dumps(quorum["trust"]), encoding="utf-8")
    (case["root"] / "quorum-policy.json").write_text(json.dumps(quorum["envelope"]), encoding="utf-8")
    export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                signed_checkpoint=case["signed"], trusted_public_keys=case["trust"], provenance=case["profile"])
    install(quorum)
    result = verify_case(case["package"], case["public"], checkpoint_policy_store=quorum["path"],
                         require_authenticated_key_policy=True)
    assert not result["valid"] and result["checkpoint_key_policy"]["authentication"]["status"] == "FAIL"


def test_each_signature_is_standard_ed25519_over_bound_canonical_material(quorum):
    envelope = quorum["envelope"]
    for key in quorum["keys"][:2]:
        ident = public_row(key)["key_id"]
        signature = next(row["signature_hex"] for row in envelope["signatures"] if row["issuer_key_id"] == ident)
        material = {"schema": QUORUM_POLICY_SCHEMA, "signature_algorithm": "Ed25519",
                    "issuer_trust_sha256": envelope["issuer_trust_sha256"], "policy": envelope["policy"], "issuer_key_id": ident}
        key.public_key().verify(bytes.fromhex(signature), canonical_json_bytes(material))


def test_cosigning_does_not_mutate_prior_approval_or_trust_inputs(quorum):
    before, trust = copy.deepcopy(quorum["partial"]), copy.deepcopy(quorum["trust"])
    cosign_quorum_policy(quorum["partial"], quorum["keys"][1], quorum["trust"])
    assert quorum["partial"] == before and quorum["trust"] == trust


@pytest.mark.parametrize("field,delta", [("issued_at", timedelta(days=2)), ("expires_at", timedelta(days=-2))])
def test_future_or_expired_quorum_packages_cannot_be_accepted(quorum, field, delta):
    value = (datetime.now(timezone.utc) + delta).isoformat().replace("+00:00", "Z")
    changes = {field: value}
    if field == "issued_at":
        changes["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat().replace("+00:00", "Z")
    else:
        changes["issued_at"] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat().replace("+00:00", "Z")
    envelope = approved_policy(quorum, **changes)
    with pytest.raises(PolicyUpdateError) as error:
        accept_policy_update(quorum["path"], envelope, quorum["trust"], initialize=True)
    assert error.value.code == "signed_policy_not_current" and not quorum["path"].exists()


def test_stored_partial_quorum_cannot_be_made_authoritative_by_rehashing(quorum):
    install(quorum)
    partial = quorum["partial"]
    with sqlite3.connect(quorum["path"]) as connection:
        connection.execute("UPDATE checkpoint_policy SET envelope_json=?,envelope_sha256=?",
                           (canonical_json_bytes(partial).decode(), sha256_object(partial)))
    with pytest.raises(PolicyUpdateError) as error:
        load_policy_store(quorum["path"], quorum["trust"])
    assert error.value.code == "policy_quorum_not_met"


def test_valid_quorum_cannot_rescue_tampered_evidence(case, quorum, tmp_path):
    import zipfile
    install(quorum)
    bad = tmp_path / "tampered.zip"
    with zipfile.ZipFile(case["package"]) as source, zipfile.ZipFile(bad, "w") as destination:
        for member in source.infolist():
            destination.writestr(member, b"[]" if member.filename == "raw.json" else source.read(member.filename))
    result = verify_case(bad, case["public"], include_reconstruction=True, **options(quorum))
    assert result["checkpoint_key_policy"]["authentication"]["status"] == "PASS"
    assert not result["valid"] and result["artifact_integrity"] == "FAIL" and "reconstruction" not in result


def test_quorum_approval_composes_with_timestamp_requirement(case, quorum, tmp_path):
    from v17_timestamp_selftest import synthetic_tsa, timestamp_fixture
    install(quorum)
    timestamp = timestamp_fixture(case, synthetic_tsa(tmp_path / "tsa"))
    result = verify_case(case["package"], case["public"], include_reconstruction=True, **options(quorum), **timestamp)
    assert result["valid"] and result["checkpoint_timestamp"]["status"] == "PASS"
    assert result["checkpoint_key_policy"]["authentication"]["valid_signatures"] == 2


def test_export_preserves_existing_destination_when_quorum_configuration_changes(case, quorum):
    install(quorum)
    export_args = {"ledger": case["ledger"], "signed_checkpoint": case["signed"],
                   "trusted_public_keys": case["trust"], "provenance": case["profile"]}
    good = export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], **export_args, **options(quorum))
    assert good["checkpoint_key_policy"]["authentication"]["valid_signatures"] == 2
    before = case["package"].read_bytes()
    quorum["trust"]["threshold"] = 3
    with pytest.raises(ValueError, match="policy rejected export"):
        export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], **export_args, **options(quorum))
    assert case["package"].read_bytes() == before


def cli_options(quorum, tmp_path):
    path = tmp_path / "issuer-quorum.json"
    path.write_text(json.dumps(quorum["trust"]), encoding="utf-8")
    return ["--checkpoint-policy-store", str(quorum["path"]), "--policy-issuer-trust", str(path),
            "--require-authenticated-key-policy"]


@pytest.mark.parametrize("script,extra", [("verify_case_v17.py", ["--format", "json"]),
    ("case_export_v17.py", ["verify"]), ("replay_case_v17.py", ["--replay-transforms"])])
def test_case_clis_enforce_quorum_and_revision_floor(case, quorum, tmp_path, script, extra):
    install(quorum)
    args = [sys.executable, str(ROOT / script), *extra, "--zip", str(case["package"]),
            "--export-public-key", str(case["public"]), *cli_options(quorum, tmp_path)]
    good = subprocess.run(args, capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(good.stdout)["checkpoint_key_policy"]["authentication"]["valid_signatures"] == 2
    bad = subprocess.run(args + ["--minimum-policy-revision", "2"], capture_output=True, text=True)
    assert bad.returncode == 1 and "reconstruction" not in json.loads(bad.stdout)


def write_pem_keys(quorum, tmp_path):
    paths = []
    for index, key in enumerate(quorum["keys"]):
        private, public = tmp_path / f"issuer-{index}.pem", tmp_path / f"issuer-{index}.pub.pem"
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        private.chmod(0o600)
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo))
        paths.append((private, public))
    return paths


def policy_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "checkpoint_policy_v17.py"), *map(str, args)],
                          capture_output=True, text=True)


def test_cli_collects_separate_approvals_and_accepts_only_complete_quorum(quorum, tmp_path):
    paths = write_pem_keys(quorum, tmp_path)
    trust = tmp_path / "approved-quorum.json"
    public_args = [arg for pair in paths for arg in ("--issuer-public-key", pair[1])]
    result = policy_cli("trust", "--threshold", "2", "--tenant", TENANT_ID, "--policy-id", quorum["policy"]["policy_id"],
                        "--out", trust, *public_args)
    assert result.returncode == 0, result.stdout + result.stderr
    assert load_issuer_trust(trust) == quorum["trust"]
    policy, partial, complete = tmp_path / "policy.json", tmp_path / "partial.json", tmp_path / "complete.json"
    policy.write_text(json.dumps(quorum["policy"]), encoding="utf-8")
    signed = policy_cli("sign", "--policy", policy, "--issuer-private-key", paths[0][0],
                        "--issuer-trust", trust, "--out", partial)
    assert signed.returncode == 0 and json.loads(signed.stdout)["status"] == "PARTIALLY_SIGNED"
    assert json.loads(signed.stdout)["acceptance_performed"] is False
    failed = policy_cli("accept", "--signed-policy", partial, "--issuer-trust", trust,
                        "--store", quorum["path"], "--initialize")
    assert failed.returncode == 1 and not quorum["path"].exists()
    cosigned = policy_cli("cosign", "--signed-policy", partial, "--issuer-private-key", paths[1][0],
                          "--issuer-trust", trust, "--out", complete)
    assert cosigned.returncode == 0 and json.loads(cosigned.stdout)["status"] == "SIGNED"
    before = complete.read_bytes()
    again = policy_cli("cosign", "--signed-policy", partial, "--issuer-private-key", paths[1][0],
                       "--issuer-trust", trust, "--out", complete)
    assert again.returncode == 3 and complete.read_bytes() == before
    accepted = policy_cli("accept", "--signed-policy", complete, "--issuer-trust", trust,
                          "--store", quorum["path"], "--initialize")
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    shown = policy_cli("show", "--issuer-trust", trust, "--store", quorum["path"])
    assert shown.returncode == 0 and json.loads(shown.stdout)["authentication"]["valid_signatures"] == 2
    newer = tmp_path / "newer.json"
    newer.write_text(json.dumps(approved_policy(quorum)), encoding="utf-8")
    assert policy_cli("accept", "--signed-policy", newer, "--issuer-trust", trust, "--store", quorum["path"]).returncode == 0
    rollback = policy_cli("accept", "--signed-policy", complete, "--issuer-trust", trust, "--store", quorum["path"])
    assert rollback.returncode == 1 and json.loads(rollback.stdout)["code"] == "policy_revision_rollback"


@pytest.mark.parametrize("threshold", ["0", "4"])
def test_cli_refuses_invalid_threshold_without_creating_trust(quorum, tmp_path, threshold):
    paths = write_pem_keys(quorum, tmp_path)
    target = tmp_path / "invalid-quorum.json"
    result = policy_cli("trust", "--threshold", threshold, "--tenant", TENANT_ID,
                        "--policy-id", quorum["policy"]["policy_id"], "--issuer-public-key", paths[0][1], "--out", target)
    assert result.returncode == 1 and not target.exists()


def test_export_cli_uses_quorum_store_before_destination_replacement(case, quorum, tmp_path):
    from case_export_v17 import LEDGER_PATH, SIGNED_CHECKPOINT_PATH, TRUST_STORE_PATH, _write_v17_metadata
    install(quorum)
    _write_v17_metadata(case["root"], ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys=case["trust"])
    provenance = tmp_path / "provenance.json"
    provenance.write_text(json.dumps(case["profile"]), encoding="utf-8")
    destination = tmp_path / "quorum-export.zip"
    args = [sys.executable, str(ROOT / "case_export_v17.py"), "create", "--case-root", str(case["root"]),
            "--tenant", TENANT_ID, "--case", CASE_ID, "--export-private-key", str(case["private"]),
            "--ledger", str(case["root"] / LEDGER_PATH), "--signed-checkpoint", str(case["root"] / SIGNED_CHECKPOINT_PATH),
            "--trusted-signers", str(case["root"] / TRUST_STORE_PATH), "--provenance", str(provenance),
            "--out", str(destination), *cli_options(quorum, tmp_path)]
    good = subprocess.run(args, capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    before = destination.read_bytes()
    quorum["trust"]["threshold"] = 3
    cli_options(quorum, tmp_path)
    bad = subprocess.run(args, capture_output=True, text=True)
    assert bad.returncode == 3 and destination.read_bytes() == before


@pytest.mark.parametrize("command", ["sign", "cosign"])
def test_empty_issuer_trust_path_never_falls_back_to_single_issuer_signing(quorum, tmp_path, command):
    paths = write_pem_keys(quorum, tmp_path)
    source, target = tmp_path / "input.json", tmp_path / "output.json"
    source.write_text(json.dumps(quorum["policy"] if command == "sign" else quorum["partial"]), encoding="utf-8")
    flag = "--policy" if command == "sign" else "--signed-policy"
    result = policy_cli(command, flag, source, "--issuer-private-key", paths[1][0], "--issuer-trust", "", "--out", target)
    assert result.returncode == 3 and json.loads(result.stdout)["status"] == "ERROR"
    assert not target.exists()

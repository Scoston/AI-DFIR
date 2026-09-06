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
from v17_integrity import sha256_object
from v17_key_policy_selftest import EVALUATED_AT, synthetic_export
from v17_policy_distribution import (
    MAX_ISSUER_TRUST_BYTES, MAX_ISSUERS, MAX_SIGNED_POLICY_BYTES, MAX_STORE_BYTES,
    PolicyUpdateError, accept_policy_update, authenticate_key_policy, load_issuer_trust,
    load_policy_document, load_policy_store, sign_key_policy, validate_issuer_trust,
)
from v17_policy_distribution_selftest import synthetic_distribution
from v17_provenance_selftest import CASE_ID, TENANT_ID
from v17_signing import key_id_from_public_key_bytes, public_key_bytes
from verify_case_v17 import render_verification_report

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def case(tmp_path):
    return synthetic_export(tmp_path)


@pytest.fixture
def distribution(case, tmp_path):
    return synthetic_distribution(case, tmp_path / "approved-policy.sqlite")


def install(fixture):
    return accept_policy_update(fixture["path"], fixture["envelope"], fixture["trust"], initialize=True)


def update(fixture, revision, **changes):
    policy = copy.deepcopy(fixture["policy"])
    policy.update(revision=revision, **changes)
    return sign_key_policy(policy, fixture["key"])


def case_options(fixture):
    return {"checkpoint_policy_store": fixture["path"], "policy_issuer_trust": fixture["trust"],
            "require_authenticated_key_policy": True}


def test_authenticated_store_reconstructs_offline_and_records_issuer(case, distribution, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    before = copy.deepcopy(distribution["envelope"])
    package = case["package"].read_bytes()
    assert install(distribution)["status"] == "ACCEPTED"
    report = verify_case(case["package"], case["public"], include_reconstruction=True,
                         replay_transforms=True, **case_options(distribution))
    assert report["valid"], report
    policy = report["checkpoint_key_policy"]
    auth = policy["authentication"]
    assert auth["status"] == "PASS" and auth["signature_valid"]
    assert auth["issuer_key_id"] == distribution["envelope"]["issuer_key_id"]
    assert auth["policy_sha256"] == sha256_object(distribution["policy"])
    assert auth["issuer_trust_sha256"] == sha256_object(distribution["trust"])
    assert auth["envelope_sha256"] == sha256_object(before) and auth["accepted_at"].endswith("Z")
    assert auth["rollback_protection"] == "verifier-owned-store"
    assert policy["trust_source"] == "authenticated-policy-store"
    assert report["signer_trust_source"] == "export-manifest-and-external-policy"
    assert report["reconstruction"]["deterministic_replay"]["status"] == "PASS"
    assert case["package"].read_bytes() == package and distribution["envelope"] == before
    assert "Key-policy authentication: PASS" in render_verification_report(report)


def test_new_revocation_survives_restart_and_rejects_old_signed_policy(case, distribution):
    install(distribution)
    newer = copy.deepcopy(distribution["policy"])
    newer["revision"] = 2
    newer["keys"][0].update(state="revoked", status_changed_at=newer["issued_at"], reason="synthetic exercise")
    accept_policy_update(distribution["path"], sign_key_policy(newer, distribution["key"]), distribution["trust"])
    before = distribution["path"].read_bytes()
    with pytest.raises(PolicyUpdateError, match="older policy"):
        accept_policy_update(distribution["path"], distribution["envelope"], distribution["trust"])
    assert distribution["path"].read_bytes() == before
    assert load_policy_store(distribution["path"], distribution["trust"])["policy"]["revision"] == 2
    report = verify_case(case["package"], case["public"], include_reconstruction=True, **case_options(distribution))
    assert report["checkpoint_key_policy"]["authentication"]["status"] == "PASS"
    assert report["signature_valid"] and report["manifest_signer_trusted"] and not report["signer_trusted"]
    assert not report["valid"] and "reconstruction" not in report


def test_same_revision_content_change_fails_while_exact_retry_is_idempotent(distribution):
    first = install(distribution)
    before = distribution["path"].read_bytes()
    repeated = accept_policy_update(distribution["path"], distribution["envelope"], distribution["trust"])
    assert repeated["status"] == "UNCHANGED"
    assert repeated["authentication"]["accepted_at"] == first["authentication"]["accepted_at"]
    with pytest.raises(PolicyUpdateError, match="already accepted revision"):
        accept_policy_update(distribution["path"], update(distribution, 1, case_ids=None), distribution["trust"])
    assert distribution["path"].read_bytes() == before


@pytest.mark.parametrize("change", [
    lambda e: e["policy"].update(revision=9),
    lambda e: e["policy"].update(case_ids=None),
    lambda e: e["policy"]["keys"][0].update(state="revoked", reason="synthetic", status_changed_at=e["policy"]["issued_at"]),
    lambda e: e.update(signature_hex="0" * 128),
])
def test_signature_covers_policy_and_its_security_fields(distribution, change):
    change(distribution["envelope"])
    with pytest.raises(PolicyUpdateError) as error:
        install(distribution)
    assert error.value.code == "policy_issuer_signature_invalid"
    assert not distribution["path"].exists()


@pytest.mark.parametrize("change", [
    lambda e: e.update(schema="different-signed-object"),
    lambda e: e.update(signature_algorithm="RSA"),
    lambda e: e.update(public_key_hex="0" * 64),
    lambda e: e.update(signature_hex="A" * 128),
    lambda e: e["policy"].update(extra="unsupported"),
])
def test_strict_envelope_rejects_unknown_fields_and_profiles(distribution, change):
    change(distribution["envelope"])
    with pytest.raises(PolicyUpdateError):
        install(distribution)
    assert not distribution["path"].exists()


@pytest.mark.parametrize("field", ["tenant_id", "policy_id"])
def test_signature_does_not_grant_another_tenant_or_policy_scope(distribution, field):
    value = update(distribution, 2, **{field: "OTHER"})
    with pytest.raises(PolicyUpdateError) as error:
        accept_policy_update(distribution["path"], value, distribution["trust"], initialize=True)
    assert error.value.code == "policy_issuer_scope_mismatch"


def test_self_signed_policy_and_empty_issuer_trust_cannot_authorize_a_key(distribution):
    unauthorized = sign_key_policy(distribution["policy"], Ed25519PrivateKey.generate())
    with pytest.raises(PolicyUpdateError) as error:
        authenticate_key_policy(unauthorized, distribution["trust"])
    assert error.value.code == "policy_issuer_untrusted"
    distribution["trust"]["keys"] = []
    with pytest.raises(PolicyUpdateError, match="independently trusted"):
        install(distribution)


@pytest.mark.parametrize("change", [
    lambda t: t.update(schema="checkpoint-signers"),
    lambda t: t.update(extra=True),
    lambda t: t["keys"].append(copy.deepcopy(t["keys"][0])),
    lambda t: t["keys"][0].update(key_id="sha256:" + "0" * 64),
    lambda t: t["keys"][0].update(public_key_hex="bad"),
    lambda t: t.update(keys=[t["keys"][0]] * (MAX_ISSUERS + 1)),
])
def test_issuer_trust_is_strict_and_bounded(distribution, change):
    change(distribution["trust"])
    with pytest.raises(PolicyUpdateError):
        validate_issuer_trust(distribution["trust"])


def test_issuer_key_must_be_separate_from_checkpoint_keys(distribution):
    authority = distribution["trust"]["keys"][0]
    policy = copy.deepcopy(distribution["policy"])
    policy["keys"][0].update(authority)
    with pytest.raises(PolicyUpdateError) as error:
        sign_key_policy(policy, distribution["key"])
    assert error.value.code == "policy_issuer_key_reuse"


def test_issuer_rotation_preserves_revision_floor(distribution):
    install(distribution)
    key = Ed25519PrivateKey.generate()
    raw = public_key_bytes(key.public_key())
    trust = copy.deepcopy(distribution["trust"])
    trust["keys"] = [{"key_id": key_id_from_public_key_bytes(raw), "public_key_hex": raw.hex()}]
    with pytest.raises(PolicyUpdateError, match="independently trusted"):
        load_policy_store(distribution["path"], trust)
    policy = copy.deepcopy(distribution["policy"])
    policy["revision"] = 2
    accepted = accept_policy_update(distribution["path"], sign_key_policy(policy, key), trust)
    assert accepted["status"] == "ACCEPTED" and accepted["authentication"]["policy_revision"] == 2
    assert load_policy_store(distribution["path"], trust)["authentication"]["issuer_key_id"] == trust["keys"][0]["key_id"]
    with pytest.raises(PolicyUpdateError, match="older policy"):
        accept_policy_update(distribution["path"], sign_key_policy(distribution["policy"], key), trust)


def freeze(monkeypatch, when):
    class Clock:
        @classmethod
        def now(cls, tz=None):
            return when
    monkeypatch.setattr("v17_policy_distribution.datetime", Clock)


@pytest.mark.parametrize("field,delta", [("issued_at", timedelta(seconds=-1)), ("expires_at", timedelta(0))])
def test_signed_policy_time_window_is_enforced_before_store_creation(distribution, monkeypatch, field, delta):
    boundary = datetime.fromisoformat(distribution["policy"][field].replace("Z", "+00:00"))
    freeze(monkeypatch, boundary + delta)
    with pytest.raises(PolicyUpdateError) as error:
        install(distribution)
    assert error.value.code == "signed_policy_not_current" and not distribution["path"].exists()


def test_expired_store_is_rechecked_even_with_backdated_case_evaluation(case, distribution, monkeypatch):
    install(distribution)
    expiry = datetime.fromisoformat(distribution["policy"]["expires_at"].replace("Z", "+00:00"))
    freeze(monkeypatch, expiry)
    result = verify_case(case["package"], case["public"], key_policy_evaluated_at=EVALUATED_AT,
                         include_reconstruction=True, **case_options(distribution))
    assert not result["valid"] and "reconstruction" not in result
    assert result["checkpoint_key_policy"]["authentication"]["findings"][0]["code"] == "signed_policy_not_current"


def test_expiry_is_rechecked_after_waiting_for_update_lock(distribution, monkeypatch):
    import v17_policy_distribution as module
    original = module._connect
    expiry = datetime.fromisoformat(distribution["policy"]["expires_at"].replace("Z", "+00:00"))
    def connect(*args, **kwargs):
        result = original(*args, **kwargs)
        freeze(monkeypatch, expiry)
        return result
    monkeypatch.setattr(module, "_connect", connect)
    with pytest.raises(PolicyUpdateError) as error:
        install(distribution)
    assert error.value.code == "signed_policy_not_current" and not distribution["path"].exists()


def test_missing_store_cannot_implicitly_reinitialize_or_downgrade(case, distribution):
    with pytest.raises(PolicyUpdateError):
        accept_policy_update(distribution["path"], distribution["envelope"], distribution["trust"])
    assert not distribution["path"].exists()
    result = verify_case(case["package"], case["public"], include_reconstruction=True, **case_options(distribution))
    assert not result["valid"] and "reconstruction" not in result and not distribution["path"].exists()
    install(distribution)
    before = distribution["path"].read_bytes()
    with pytest.raises(FileExistsError):
        install(distribution)
    assert distribution["path"].read_bytes() == before


def test_store_scope_cannot_be_repurposed_even_with_an_approved_issuer(distribution):
    install(distribution)
    other_trust = copy.deepcopy(distribution["trust"])
    other_trust["policy_id"] = "another-policy"
    with pytest.raises(PolicyUpdateError) as error:
        accept_policy_update(distribution["path"], update(distribution, 2, policy_id="another-policy"), other_trust)
    assert error.value.code == "policy_store_scope_mismatch"


@pytest.mark.parametrize("floor", [0, True, -1, 1.5, 2**53])
def test_minimum_revision_rejects_ambiguous_values(distribution, floor):
    install(distribution)
    with pytest.raises(PolicyUpdateError):
        load_policy_store(distribution["path"], distribution["trust"], minimum_revision=floor)


def test_independent_floor_detects_restore_of_older_entire_database(case, distribution):
    install(distribution)
    old = distribution["path"].read_bytes()
    accept_policy_update(distribution["path"], update(distribution, 2), distribution["trust"])
    distribution["path"].write_bytes(old)
    # A verifier-owned store alone cannot detect filesystem/backup rollback.
    assert load_policy_store(distribution["path"], distribution["trust"])["policy"]["revision"] == 1
    result = verify_case(case["package"], case["public"], minimum_policy_revision=2, **case_options(distribution))
    assert not result["valid"]
    assert result["checkpoint_key_policy"]["authentication"]["findings"][0]["code"] == "policy_revision_below_floor"


@pytest.mark.parametrize("sql", [
    "PRAGMA application_id=1", "DELETE FROM checkpoint_policy",
    "UPDATE checkpoint_policy SET revision=99",
    "UPDATE checkpoint_policy SET envelope_sha256='wrong'",
    "CREATE VIEW unexpected AS SELECT * FROM checkpoint_policy",
    "CREATE TRIGGER unexpected AFTER UPDATE ON checkpoint_policy BEGIN DELETE FROM checkpoint_policy; END",
])
def test_corrupt_or_extended_store_schema_is_not_trusted(distribution, sql):
    install(distribution)
    with sqlite3.connect(distribution["path"]) as database:
        database.execute(sql)
    with pytest.raises(PolicyUpdateError):
        load_policy_store(distribution["path"], distribution["trust"])
    with pytest.raises(PolicyUpdateError):
        accept_policy_update(distribution["path"], update(distribution, 2), distribution["trust"])


def test_stored_signature_is_reauthenticated_not_just_digest_checked(distribution):
    install(distribution)
    forged = copy.deepcopy(distribution["envelope"])
    forged["signature_hex"] = "0" * 128
    with sqlite3.connect(distribution["path"]) as database:
        database.execute("UPDATE checkpoint_policy SET envelope_json=?,envelope_sha256=?",
                         (json.dumps(forged), sha256_object(forged)))
    with pytest.raises(PolicyUpdateError) as error:
        load_policy_store(distribution["path"], distribution["trust"])
    assert error.value.code == "policy_issuer_signature_invalid"


def test_store_rejects_symlink_and_oversized_database(distribution, tmp_path):
    install(distribution)
    link = tmp_path / "linked.sqlite"
    link.symlink_to(distribution["path"])
    with pytest.raises(PolicyUpdateError):
        load_policy_store(link, distribution["trust"])
    with distribution["path"].open("r+b") as stream:
        stream.truncate(MAX_STORE_BYTES + 1)
    with pytest.raises(PolicyUpdateError):
        load_policy_store(distribution["path"], distribution["trust"])


def test_concurrent_updates_preserve_highest_revision(distribution):
    install(distribution)
    barrier = Barrier(2)
    def accept(revision):
        value = update(distribution, revision)
        barrier.wait(timeout=5)
        try:
            return accept_policy_update(distribution["path"], value, distribution["trust"])["status"]
        except PolicyUpdateError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(accept, [2, 3]))
    assert results[1] == "ACCEPTED" and results[0] in {"ACCEPTED", "policy_revision_rollback"}
    assert load_policy_store(distribution["path"], distribution["trust"])["policy"]["revision"] == 3


def test_competing_same_revision_updates_cannot_both_win(distribution):
    install(distribution)
    barrier = Barrier(2)
    def accept(wide):
        value = update(distribution, 2, case_ids=None if wide else [CASE_ID])
        barrier.wait(timeout=5)
        try:
            return accept_policy_update(distribution["path"], value, distribution["trust"])["status"]
        except PolicyUpdateError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(accept, [False, True]))
    assert sorted(results) == ["ACCEPTED", "policy_revision_conflict"]


def test_failed_transaction_preserves_prior_policy(distribution, monkeypatch):
    import v17_policy_distribution as module
    install(distribution)
    before = distribution["path"].read_bytes()
    original = module._connect
    class BrokenWriter:
        def __init__(self, connection):
            self.connection = connection
        def execute(self, sql, *args):
            if sql.startswith("INSERT"):
                raise sqlite3.OperationalError("synthetic write failure")
            return self.connection.execute(sql, *args)
        def close(self):
            self.connection.close()
    with monkeypatch.context() as scoped:
        scoped.setattr(module, "_connect", lambda *a, **kw: BrokenWriter(original(*a, **kw)))
        with pytest.raises(PolicyUpdateError, match="transaction failed"):
            accept_policy_update(distribution["path"], update(distribution, 2), distribution["trust"])
    assert distribution["path"].read_bytes() == before
    assert load_policy_store(distribution["path"], distribution["trust"])["policy"]["revision"] == 1


def test_waiting_update_uses_detached_authenticated_inputs(distribution, monkeypatch):
    import v17_policy_distribution as module
    install(distribution)
    candidate = update(distribution, 3)
    supplied_trust = copy.deepcopy(distribution["trust"])
    original = module._connect
    def changed_inputs(*args, **kwargs):
        candidate.update(distribution["envelope"])
        supplied_trust["keys"] = []
        return original(*args, **kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr(module, "_connect", changed_inputs)
        result = accept_policy_update(distribution["path"], candidate, supplied_trust)
    assert result["authentication"]["policy_revision"] == 3
    assert load_policy_store(distribution["path"], distribution["trust"])["policy"]["revision"] == 3


@pytest.mark.parametrize("raw", [b'{"keys":[],"keys":[]}', b'{"value":NaN}', b'{"value":Infinity}', b'\xff'])
def test_ambiguous_json_is_rejected(tmp_path, raw):
    path = tmp_path / "untrusted.json"
    path.write_bytes(raw)
    with pytest.raises(PolicyUpdateError):
        load_policy_document(path)


@pytest.mark.parametrize("kind,limit", [("signed", MAX_SIGNED_POLICY_BYTES), ("trust", MAX_ISSUER_TRUST_BYTES)])
def test_input_files_are_bounded_before_parsing(tmp_path, kind, limit):
    path = tmp_path / "large.json"
    path.write_bytes(b" " * (limit + 1))
    with pytest.raises(PolicyUpdateError):
        (load_issuer_trust if kind == "trust" else load_policy_document)(path)


@pytest.mark.parametrize("kwargs", [
    {"require_authenticated_key_policy": True}, {"minimum_policy_revision": 1}, {"policy_issuer_trust": {}},
])
def test_raw_policy_cannot_satisfy_authentication_requirement(case, kwargs):
    result = verify_case(case["package"], case["public"], checkpoint_key_policy=case["policy"],
                         key_policy_evaluated_at=EVALUATED_AT, include_reconstruction=True, **kwargs)
    assert not result["valid"] and "reconstruction" not in result
    assert result["checkpoint_key_policy"]["findings"][0]["code"] == "authenticated_policy_required"


def test_raw_policy_and_store_cannot_compete(case, distribution):
    install(distribution)
    report = verify_case(case["package"], case["public"], checkpoint_key_policy=case["policy"], **case_options(distribution))
    assert not report["valid"] and report["checkpoint_key_policy"]["authentication"]["status"] == "FAIL"


def test_issuer_material_in_case_does_not_supply_external_trust(case, distribution):
    (case["root"] / "issuer-trust.json").write_text(json.dumps(distribution["trust"]), encoding="utf-8")
    (case["root"] / "signed-policy.json").write_text(json.dumps(distribution["envelope"]), encoding="utf-8")
    export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                signed_checkpoint=case["signed"], trusted_public_keys=case["trust"], provenance=case["profile"])
    report = verify_case(case["package"], case["public"], require_authenticated_key_policy=True)
    assert not report["valid"]
    install(distribution)
    report = verify_case(case["package"], case["public"], checkpoint_policy_store=distribution["path"])
    assert not report["valid"] and report["checkpoint_key_policy"]["authentication"]["status"] == "FAIL"


def test_authentication_cannot_rescue_changed_evidence(case, distribution, tmp_path):
    import zipfile
    install(distribution)
    bad = tmp_path / "tampered.zip"
    with zipfile.ZipFile(case["package"]) as source, zipfile.ZipFile(bad, "w") as destination:
        for info in source.infolist():
            destination.writestr(info, b"[]" if info.filename == "raw.json" else source.read(info.filename))
    result = verify_case(bad, case["public"], include_reconstruction=True, **case_options(distribution))
    assert result["checkpoint_key_policy"]["authentication"]["status"] == "PASS"
    assert not result["valid"] and result["artifact_integrity"] == "FAIL" and "reconstruction" not in result


def test_authenticated_policy_composes_with_timestamp_receipt(case, distribution, tmp_path):
    from v17_timestamp_selftest import synthetic_tsa, timestamp_fixture
    install(distribution)
    timestamp = timestamp_fixture(case, synthetic_tsa(tmp_path / "tsa"))
    result = verify_case(case["package"], case["public"], include_reconstruction=True,
                         **case_options(distribution), **timestamp)
    assert result["valid"] and result["checkpoint_timestamp"]["status"] == "PASS"
    assert result["checkpoint_key_policy"]["authentication"]["status"] == "PASS"


def test_export_checks_authenticated_store_before_replacing_destination(case, distribution):
    install(distribution)
    result = export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"],
                         ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys=case["trust"],
                         provenance=case["profile"], **case_options(distribution))
    assert result["checkpoint_key_policy"]["authentication"]["status"] == "PASS"
    before = case["package"].read_bytes()
    with pytest.raises(ValueError, match="policy rejected export"):
        export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"],
                    ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys=case["trust"],
                    provenance=case["profile"], minimum_policy_revision=2, **case_options(distribution))
    assert case["package"].read_bytes() == before


def cli_options(distribution, tmp_path):
    path = tmp_path / "issuer-trust.json"
    path.write_text(json.dumps(distribution["trust"]), encoding="utf-8")
    return ["--checkpoint-policy-store", str(distribution["path"]), "--policy-issuer-trust", str(path),
            "--require-authenticated-key-policy"]


@pytest.mark.parametrize("script,extra", [("verify_case_v17.py", ["--format", "json"]),
    ("case_export_v17.py", ["verify"]), ("replay_case_v17.py", ["--replay-transforms"])])
def test_verifier_clis_use_authenticated_store_and_enforce_floor(case, distribution, tmp_path, script, extra):
    install(distribution)
    args = [sys.executable, str(ROOT / script), *extra, "--zip", str(case["package"]),
            "--export-public-key", str(case["public"]), *cli_options(distribution, tmp_path)]
    good = subprocess.run(args, capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(good.stdout)["checkpoint_key_policy"]["authentication"]["status"] == "PASS"
    bad = subprocess.run(args + ["--minimum-policy-revision", "2"], capture_output=True, text=True)
    assert bad.returncode == 1 and "reconstruction" not in json.loads(bad.stdout)


def test_policy_cli_signs_imports_and_rejects_rollback_in_a_new_process(distribution, tmp_path):
    private, public, policy = tmp_path / "issuer.pem", tmp_path / "issuer.pub.pem", tmp_path / "policy.json"
    private.write_bytes(distribution["key"].private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)
    public.write_bytes(distribution["key"].public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    policy.write_text(json.dumps(distribution["policy"]), encoding="utf-8")
    trust, signed = tmp_path / "approved-issuers.json", tmp_path / "signed-policy.json"
    command = [sys.executable, str(ROOT / "checkpoint_policy_v17.py")]
    def run(*args):
        return subprocess.run(command + list(map(str, args)), capture_output=True, text=True)
    result = run("trust", "--issuer-public-key", public, "--tenant", TENANT_ID,
                 "--policy-id", distribution["policy"]["policy_id"], "--out", trust)
    assert result.returncode == 0, result.stdout + result.stderr
    result = run("sign", "--policy", policy, "--issuer-private-key", private, "--out", signed)
    assert result.returncode == 0, result.stdout + result.stderr
    first = signed.read_bytes()
    assert run("sign", "--policy", policy, "--issuer-private-key", private, "--out", signed).returncode == 3
    assert signed.read_bytes() == first
    shared = ["--store", distribution["path"], "--issuer-trust", trust]
    assert run("accept", "--signed-policy", signed, *shared, "--initialize").returncode == 0
    shown = run("show", *shared)
    assert shown.returncode == 0 and json.loads(shown.stdout)["policy"]["revision"] == 1
    newer = tmp_path / "newer.json"
    newer.write_text(json.dumps(update(distribution, 2)), encoding="utf-8")
    assert run("accept", "--signed-policy", newer, *shared).returncode == 0
    rejected = run("accept", "--signed-policy", signed, *shared)
    assert rejected.returncode == 1 and json.loads(rejected.stdout)["code"] == "policy_revision_rollback"
    assert json.loads(run("show", *shared).stdout)["policy"]["revision"] == 2


def test_export_cli_enforces_authenticated_policy(case, distribution, tmp_path):
    from case_export_v17 import LEDGER_PATH, SIGNED_CHECKPOINT_PATH, TRUST_STORE_PATH, _write_v17_metadata
    install(distribution)
    _write_v17_metadata(case["root"], ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys=case["trust"])
    provenance = tmp_path / "provenance.json"
    provenance.write_text(json.dumps(case["profile"]), encoding="utf-8")
    destination = tmp_path / "authenticated.zip"
    args = [sys.executable, str(ROOT / "case_export_v17.py"), "create", "--case-root", str(case["root"]),
            "--tenant", TENANT_ID, "--case", CASE_ID, "--export-private-key", str(case["private"]),
            "--ledger", str(case["root"] / LEDGER_PATH), "--signed-checkpoint", str(case["root"] / SIGNED_CHECKPOINT_PATH),
            "--trusted-signers", str(case["root"] / TRUST_STORE_PATH), "--provenance", str(provenance),
            "--out", str(destination), *cli_options(distribution, tmp_path)]
    good = subprocess.run(args, capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    before = destination.read_bytes()
    bad = subprocess.run(args + ["--minimum-policy-revision", "2"], capture_output=True, text=True)
    assert bad.returncode == 3 and destination.read_bytes() == before

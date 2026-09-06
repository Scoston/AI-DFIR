from __future__ import annotations

import copy
import json
import socket
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asn1crypto import tsp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from case_export_v17 import export_case, verify_case
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_key_policy_selftest import synthetic_export
from v17_key_trust_history import (
    MAX_RECORD_BYTES, _decision, capture_key_trust_record, evaluate_key_trust_history,
    key_trust_timestamp_statement, load_key_trust_record, prepare_key_trust_request,
    validate_key_trust_record,
)
from v17_key_trust_history_selftest import revoke_current, synthetic_history
from v17_policy_distribution import PolicyUpdateError
from v17_policy_governance import accept_governed_update
from v17_policy_governance_selftest import approved_policy, approved_rotation
from v17_provenance_selftest import CASE_ID, TENANT_ID, sign_fixture
from v17_timestamp import (
    MAX_STATEMENT_BYTES, TimestampError, evaluate_checkpoint_timestamp,
    evaluate_statement_timestamp, prepare_statement_timestamp_request,
)
from v17_timestamp_selftest import synthetic_response, synthetic_tsa, timestamp_fixture
from verify_case_v17 import render_verification_report

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def tsa(tmp_path_factory):
    return synthetic_tsa(tmp_path_factory.mktemp("history-tsa"))


@pytest.fixture
def fixture(tmp_path, tsa):
    return synthetic_history(synthetic_export(tmp_path), tmp_path / "governed.sqlite", tsa)


def evaluate(fixture, **changes):
    options = dict(fixture["options"], **changes)
    return evaluate_key_trust_history(**options, signed_checkpoint=fixture["case"]["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)


def settings(fixture):
    gov = fixture["governance"]
    return {"checkpoint_policy_store": gov["path"], "policy_root_anchor": gov["anchor"],
            "key_trust_history": fixture["options"], "require_key_trust_history": True, "include_reconstruction": True}


def codes(report):
    return {item["code"] for item in report["findings"]}


def change_token(fixture, tsa, **fields):
    """Issue correctly signed adversarial time claims using the synthetic TSA."""
    options = fixture["options"]
    value = tsp.TimeStampResp.load(options["timestamp_response"])
    sd = value["time_stamp_token"]["content"]
    info = sd["encap_content_info"]["content"].parsed
    for name, content in fields.items():
        info[name] = content
    sd["encap_content_info"]["content"] = info
    signer = sd["signer_infos"][0]
    for attr in signer["signed_attrs"]:
        if attr["type"].native == "message_digest":
            attr["values"][0] = bytes.fromhex(sha256_bytes(info.dump()))
    signer["signature"] = tsa["key"].sign(signer["signed_attrs"].untag().dump(), padding.PKCS1v15(), hashes.SHA256())
    options["timestamp_response"] = value.dump()


def restamp(fixture, tsa, instant):
    """Bind a test record, including malformed temporal claims, to a valid TSA."""
    options, signed = fixture["options"], fixture["case"]["signed"]
    record = options["record"]
    record["decision"] = _decision(record["signed_policy"]["policy"], signed, TENANT_ID, CASE_ID, record["recorded_at"])
    request = prepare_statement_timestamp_request(statement=key_trust_timestamp_statement(record))
    options.update(timestamp_request=request, timestamp_response=synthetic_response(tsa, request),
                   expected_timestamp_request_sha256=sha256_bytes(request), expected_record_sha256=sha256_object(record))
    change_token(fixture, tsa, gen_time=instant)


def test_authenticated_history_reconstructs_offline_without_mutating_inputs(fixture, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    case, gov = fixture["case"], fixture["governance"]
    before = (case["package"].read_bytes(), gov["path"].read_bytes(), copy.deepcopy(fixture["options"]))
    result = verify_case(case["package"], case["public"], replay_transforms=True, **settings(fixture))
    history = result["checkpoint_key_trust_history"]
    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
    assert history["status"] == "PASS" and history["historical_key_trusted"] and history["decision_reproduced"]
    assert history["record_existence_attested"] and history["rotations_verified"] == 1
    assert history["root_version"] == history["policy_revision"] == 2
    assert history["timestamp"]["subject_binding_valid"] and history["timestamp"]["subject_existence_attested"]
    for flag in ("latest_policy_proven", "current_authorization_evaluated", "historical_signing_time_proven", "actual_prior_verifier_execution_proven"):
        assert history[flag] is False
    assert "Historical key-trust record: PASS" in render_verification_report(result)
    assert before == (case["package"].read_bytes(), gov["path"].read_bytes(), fixture["options"])


@pytest.mark.parametrize("state", ["revoked", "retired"])
def test_current_state_denies_even_with_attested_historical_allow(fixture, state):
    gov, case = fixture["governance"], fixture["case"]
    policy = copy.deepcopy(gov["policy"]["policy"])
    policy["revision"] = 3
    policy["keys"][0].update(state=state, status_changed_at=policy["issued_at"], reason="Synthetic retirement or revocation")
    accept_governed_update(gov["path"], gov["anchor"], approved_policy(policy, gov["replacement"]["keys"][:2], gov["root"]["issuer_trust"]))
    result = verify_case(case["package"], case["public"], **settings(fixture))
    assert result["checkpoint_key_trust_history"]["historical_key_trusted"]
    assert result["signature_valid"] and not result["signer_trusted"] and not result["valid"]
    assert "reconstruction" not in result


@pytest.mark.parametrize("raw", [False, True])
def test_history_requires_independent_current_authenticated_policy(fixture, raw):
    case = fixture["case"]
    result = verify_case(case["package"], case["public"], key_trust_history=fixture["options"],
                         checkpoint_key_policy=case["policy"] if raw else None, include_reconstruction=True)
    assert not result["valid"] and "reconstruction" not in result
    assert "authenticated_policy_required" in codes(result["checkpoint_key_policy"])


def test_authenticated_denial_is_preserved_but_never_grants_case_access(fixture, tsa):
    gov, case = fixture["governance"], fixture["case"]
    # Retain an issuer-approved denial while the verifier still has an active policy.
    record = fixture["options"]["record"]
    policy = copy.deepcopy(record["signed_policy"]["policy"])
    policy["keys"][0].update(state="revoked", status_changed_at=policy["issued_at"], reason="Synthetic denial")
    record["signed_policy"] = approved_policy(policy, gov["replacement"]["keys"][:2], gov["root"]["issuer_trust"])
    restamp(fixture, tsa, datetime.now(timezone.utc))
    history = evaluate(fixture)
    assert history["status"] == "PASS" and history["decision_reproduced"] and not history["historical_key_trusted"]
    result = verify_case(case["package"], case["public"], **settings(fixture))
    assert result["checkpoint_key_policy"]["status"] == "PASS" and not result["valid"]
    assert "historical_key_trust_denied" in codes(result) and "reconstruction" not in result


@pytest.mark.parametrize("change", [
    lambda r: r.update(schema="unsupported"),
    lambda r: r.update(extra=True),
    lambda r: r.update(anchor_sha256="0" * 64),
    lambda r: r.update(tenant_id="OTHER"),
    lambda r: r.update(case_id="OTHER"),
    lambda r: r.update(recorded_at="not a timestamp"),
    lambda r: r["decision"].update(status="DENY"),
    lambda r: r["decision"].update(key_state="revoked"),
    lambda r: r["decision"].update(finding_codes=["invented"]),
    lambda r: r["decision"].update(extra=True),
    lambda r: r["signed_checkpoint"].update(extra=True),
    lambda r: r["signed_checkpoint"].update(signature_hex="00" * 64),
    lambda r: r["signed_policy"]["policy"].update(revision=99),
    lambda r: r["signed_policy"].update(signatures=[]),
    lambda r: r.update(rotations=[]),
    lambda r: r["rotations"][0]["signatures"].update(previous=[]),
    lambda r: r["rotations"][0]["signatures"].update(replacement=[]),
])
def test_record_tampering_never_creates_an_attested_decision(fixture, change):
    change(fixture["options"]["record"])
    report = evaluate(fixture, expected_record_sha256=None)
    assert report["status"] == "FAIL" and not report["record_existence_attested"]
    assert not report["historical_key_trusted"] and not report["decision_reproduced"]


@pytest.mark.parametrize("field", ["root_anchor", "timestamp_request", "timestamp_response", "tsa_ca_pem", "expected_tsa_certificate_sha256"])
def test_missing_independent_inputs_fail_closed(fixture, field):
    assert evaluate(fixture, **{field: None})["status"] == "FAIL"


@pytest.mark.parametrize("field", ["expected_record_sha256", "expected_timestamp_request_sha256", "expected_tsa_certificate_sha256"])
@pytest.mark.parametrize("pin", ["0" * 64, "", "X" * 64])
def test_independent_pins_cannot_be_replaced(fixture, field, pin):
    assert evaluate(fixture, **{field: pin})["status"] == "FAIL"


def test_valid_checkpoint_replacement_and_wrong_scope_are_rejected(fixture):
    case, options = fixture["case"], fixture["options"]
    other = sign_fixture(case["ledger"])[0]
    for signed, tenant, case_id in ((other, TENANT_ID, CASE_ID), (case["signed"], "OTHER", CASE_ID), (case["signed"], TENANT_ID, "OTHER")):
        result = evaluate_key_trust_history(**options, signed_checkpoint=signed, tenant_id=tenant, case_id=case_id)
        assert result["status"] == "FAIL" and not result["historical_key_trusted"]


def test_validly_reissued_policy_cannot_reuse_old_timestamp(fixture):
    gov, record = fixture["governance"], fixture["options"]["record"]
    policy = dict(record["signed_policy"]["policy"], revision=3)
    record["signed_policy"] = approved_policy(policy, gov["replacement"]["keys"][:2], gov["root"]["issuer_trust"])
    report = evaluate(fixture, expected_record_sha256=None)
    assert "timestamp_imprint_mismatch" in codes(report["timestamp"])


def test_request_nonce_and_domain_separation_bind_the_whole_record(fixture, tsa):
    case, options = fixture["case"], fixture["options"]
    request = prepare_key_trust_request(options["record"], options["root_anchor"])
    result = evaluate(fixture, timestamp_response=synthetic_response(tsa, request))
    assert "timestamp_nonce_mismatch" in codes(result["timestamp"])
    ordinary = timestamp_fixture(case, tsa)
    ordinary.pop("require_checkpoint_timestamp")
    result = evaluate(fixture, **ordinary)
    assert "timestamp_imprint_mismatch" in codes(result["timestamp"])
    result = evaluate_checkpoint_timestamp(signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID,
        **{key: value for key, value in options.items() if key not in {"record", "root_anchor", "expected_record_sha256"}})
    assert "timestamp_imprint_mismatch" in codes(result)


def test_request_contains_only_imprint_and_protocol_metadata(fixture):
    options = fixture["options"]
    raw = options["timestamp_request"]
    request = tsp.TimeStampReq.load(raw)
    assert request["message_imprint"]["hashed_message"].native.hex() == sha256_bytes(key_trust_timestamp_statement(options["record"]))
    assert TENANT_ID.encode() not in raw and CASE_ID.encode() not in raw
    assert (1 << 127) <= request["nonce"].native < (1 << 128)


def test_absent_accuracy_rejects_an_otherwise_authenticated_token(fixture, tsa):
    change_token(fixture, tsa, accuracy=None)
    report = evaluate(fixture)
    assert report["timestamp"]["status"] == "PASS" and "history_accuracy_required" in codes(report)


def test_signed_subsecond_accuracy_is_used_for_the_entire_interval(fixture, tsa):
    instant = datetime.now(timezone.utc) - timedelta(minutes=1)
    fixture["options"]["record"]["recorded_at"] = instant.isoformat()
    restamp(fixture, tsa, instant)
    change_token(fixture, tsa, accuracy={"millis": 250, "micros": 7})
    report = evaluate(fixture)
    assert report["status"] == "PASS", report
    assert datetime.fromisoformat(report["tsa_interval"]["earliest"]) == instant - timedelta(microseconds=250007)
    assert datetime.fromisoformat(report["tsa_interval"]["latest"]) == instant + timedelta(microseconds=250007)


@pytest.mark.parametrize("kind", ["policy-start", "policy-end", "root-start", "root-end", "key-end", "interior-key-window", "future-record"])
def test_signed_time_uncertainty_cannot_hide_authority_or_key_boundaries(fixture, tsa, kind):
    gov, record = fixture["governance"], fixture["options"]["record"]
    instant = datetime.now(timezone.utc) - timedelta(minutes=1)
    record["recorded_at"] = instant.isoformat()
    policy = copy.deepcopy(record["signed_policy"]["policy"])
    root = copy.deepcopy(gov["root"])
    if kind == "future-record":
        record["recorded_at"] = (instant + timedelta(seconds=5)).isoformat()
    elif kind == "policy-start":
        policy["issued_at"] = instant.isoformat()
    elif kind == "policy-end":
        policy["expires_at"] = (instant + timedelta(microseconds=500000)).isoformat()
    elif kind == "root-start":
        root["issued_at"] = instant.isoformat()
    elif kind == "root-end":
        root["expires_at"] = (instant + timedelta(microseconds=500000)).isoformat()
    elif kind == "key-end":
        policy["keys"][0]["not_after"] = (instant + timedelta(microseconds=500000)).isoformat()
    else:
        # Endpoints both deny but an interior instant has a different finding set.
        policy["keys"][0].update(not_before=instant.isoformat(), not_after=(instant + timedelta(microseconds=500000)).isoformat())
        record["recorded_at"] = (instant - timedelta(seconds=2)).isoformat()
    record["signed_policy"] = approved_policy(policy, gov["replacement"]["keys"][:2], gov["root"]["issuer_trust"])
    record["rotations"] = [approved_rotation(gov["anchor"], root, gov["initial"]["keys"][:2], gov["replacement"]["keys"][:2])]
    restamp(fixture, tsa, instant)
    report = evaluate(fixture)
    assert report["timestamp"]["status"] == "PASS", report
    assert report["status"] == "FAIL" and not report["historical_key_trusted"]
    assert codes(report) & {"history_time_ambiguous", "history_root_outside_validity", "history_policy_outside_validity", "history_record_after_timestamp"}


def test_historical_authority_can_expire_without_restoring_current_access(fixture, monkeypatch):
    future = datetime.now(timezone.utc) + timedelta(days=3)
    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return future
    monkeypatch.setattr("v17_policy_governance.datetime", Later)
    monkeypatch.setattr("v17_policy_distribution.datetime", Later)
    monkeypatch.setattr("v17_key_trust_history.datetime", Later)
    assert evaluate(fixture)["historical_key_trusted"]
    case, gov = fixture["case"], fixture["governance"]
    denied = verify_case(case["package"], case["public"], **settings(fixture))
    assert not denied["valid"] and "reconstruction" not in denied
    with pytest.raises(PolicyUpdateError):
        capture_key_trust_record(gov["path"], gov["anchor"], signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)
    with pytest.raises(PolicyUpdateError):
        prepare_key_trust_request(fixture["options"]["record"], gov["anchor"])


@pytest.mark.parametrize("name,value", [("minimum_revision", 3), ("minimum_root_version", 3), ("minimum_revision", True), ("minimum_root_version", 0)])
def test_capture_enforces_independent_floors_without_writing(fixture, name, value):
    gov, case = fixture["governance"], fixture["case"]
    before = gov["path"].read_bytes()
    with pytest.raises(PolicyUpdateError):
        capture_key_trust_record(gov["path"], gov["anchor"], signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID, **{name: value})
    assert gov["path"].read_bytes() == before


def test_missing_store_is_not_created_and_capture_uses_a_detached_snapshot(fixture, tmp_path):
    gov, case = fixture["governance"], fixture["case"]
    path = tmp_path / "absent.sqlite"
    with pytest.raises(PolicyUpdateError):
        capture_key_trust_record(path, gov["anchor"], signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)
    assert not path.exists()
    retained = validate_key_trust_record(fixture["options"]["record"])
    fixture["options"]["record"]["decision"]["status"] = "DENY"
    assert retained["decision"]["status"] == "ALLOW"


@pytest.mark.parametrize("payload", [b"{}", b'{"schema":1,"schema":2}', b"[", b"x" * (MAX_RECORD_BYTES + 1)])
def test_strict_bounded_json_loader_rejects_malformed_records(tmp_path, payload):
    path = tmp_path / "record.json"
    path.write_bytes(payload)
    with pytest.raises((PolicyUpdateError, ValueError)):
        load_key_trust_record(path)


@pytest.mark.parametrize("options", [None, {}, {"record": {}}, {"record": {}, "root_anchor": {}, "tenant_id": "OTHER"}])
def test_required_or_partial_history_cannot_be_silently_disabled(fixture, options):
    case = fixture["case"]
    result = verify_case(case["package"], case["public"], **dict(settings(fixture), key_trust_history=options))
    assert not result["valid"] and "reconstruction" not in result


@pytest.mark.parametrize("failure", ["history", "missing", "revoked", "checkpoint-timestamp"])
def test_export_preserves_destination_on_any_independent_gate_failure(fixture, failure):
    case = fixture["case"]
    before = case["package"].read_bytes()
    options = settings(fixture)
    options.pop("include_reconstruction")
    if failure == "history":
        fixture["options"]["timestamp_response"] = b"invalid"
    elif failure == "missing":
        options["key_trust_history"] = None
    elif failure == "revoked":
        revoke_current(fixture["governance"])
    else:
        options["require_checkpoint_timestamp"] = True
    with pytest.raises(ValueError):
        export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                    signed_checkpoint=case["signed"], trusted_public_keys=case["trust"], provenance=case["profile"], **options)
    assert case["package"].read_bytes() == before


def test_attested_history_cannot_rescue_modified_evidence(fixture, tmp_path):
    case = fixture["case"]
    destination = tmp_path / "altered.zip"
    with zipfile.ZipFile(case["package"]) as source, zipfile.ZipFile(destination, "w") as output:
        target = next(name for name in source.namelist() if not name.startswith("00_case/"))
        for info in source.infolist():
            output.writestr(info, source.read(info.filename) + (b"tampered" if info.filename == target else b""))
    result = verify_case(destination, case["public"], **settings(fixture))
    assert not result["valid"] and "reconstruction" not in result


def test_history_does_not_supply_baseline_checkpoint_trust(fixture):
    case = fixture["case"]
    options = settings(fixture)
    options.pop("include_reconstruction")
    before = case["package"].read_bytes()
    with pytest.raises(ValueError, match="signer trust"):
        export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                    signed_checkpoint=case["signed"], trusted_public_keys={}, provenance=case["profile"], **options)
    assert case["package"].read_bytes() == before


def test_history_does_not_replace_a_required_checkpoint_timestamp(fixture):
    case = fixture["case"]
    result = verify_case(case["package"], case["public"], require_checkpoint_timestamp=True, **settings(fixture))
    assert result["checkpoint_key_trust_history"]["historical_key_trusted"]
    assert result["checkpoint_timestamp"]["status"] == "FAIL" and not result["valid"] and "reconstruction" not in result


def write_inputs(fixture, tmp_path):
    options = fixture["options"]
    files = {}
    for name, value in {"record": options["record"], "anchor": options["root_anchor"], "signed": fixture["case"]["signed"].to_dict(),
                        "request": options["timestamp_request"], "response": options["timestamp_response"], "ca": options["tsa_ca_pem"]}.items():
        files[name] = tmp_path / (name + ".input")
        files[name].write_bytes(value if isinstance(value, bytes) else canonical_json_bytes(value))
    return files


def run_cli(script, *args):
    return subprocess.run([sys.executable, str(ROOT / script), *map(str, args)], capture_output=True, text=True)


def test_capture_prepare_verify_cli_and_exclusive_outputs(fixture, tmp_path, tsa):
    files = write_inputs(fixture, tmp_path)
    record_path, request_path = tmp_path / "captured.json", tmp_path / "prepared.tsq"
    common = ["--anchor", files["anchor"]]
    capture = ["capture", *common, "--store", fixture["governance"]["path"], "--signed-checkpoint", files["signed"],
               "--tenant", TENANT_ID, "--case", CASE_ID, "--out", record_path]
    result = run_cli("checkpoint_history_v17.py", *capture)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not json.loads(result.stdout)["timestamp_attested"]
    before = record_path.read_bytes()
    assert run_cli("checkpoint_history_v17.py", *capture).returncode == 3
    assert record_path.read_bytes() == before
    prepare = ["prepare", *common, "--record", record_path, "--out", request_path]
    result = run_cli("checkpoint_history_v17.py", *prepare)
    assert result.returncode == 0, result.stdout + result.stderr
    request = request_path.read_bytes()
    assert run_cli("checkpoint_history_v17.py", *prepare).returncode == 3 and request_path.read_bytes() == request
    files["response"].write_bytes(synthetic_response(tsa, request))
    args = ["verify", *common, "--record", record_path, "--signed-checkpoint", files["signed"], "--tenant", TENANT_ID, "--case", CASE_ID,
            "--timestamp-request", request_path, "--timestamp-response", files["response"], "--tsa-ca-file", files["ca"],
            "--expected-tsa-certificate-sha256", tsa["pin"], "--expected-timestamp-request-sha256", sha256_bytes(request)]
    good = run_cli("checkpoint_history_v17.py", *args)
    assert good.returncode == 0 and json.loads(good.stdout)["historical_key_trusted"], good.stdout + good.stderr
    bad = run_cli("checkpoint_history_v17.py", *args, "--expected-record-sha256", "0" * 64)
    assert bad.returncode == 1 and not json.loads(bad.stdout)["record_existence_attested"]


def test_capture_preserves_current_denial_without_claiming_timestamp(fixture, tmp_path):
    revoke_current(fixture["governance"])
    files = write_inputs(fixture, tmp_path)
    output = tmp_path / "denied.json"
    result = run_cli("checkpoint_history_v17.py", "capture", "--store", fixture["governance"]["path"], "--anchor", files["anchor"],
                     "--signed-checkpoint", files["signed"], "--tenant", TENANT_ID, "--case", CASE_ID, "--out", output)
    assert result.returncode == 0, result.stdout + result.stderr
    record = json.loads(result.stdout)
    assert record["decision"]["status"] == "DENY" and not record["timestamp_attested"]
    assert load_key_trust_record(output)["decision"]["key_state"] == "revoked"


def test_export_cli_enforces_history_before_replacing_destination(fixture, tmp_path):
    from case_export_v17 import LEDGER_PATH, SIGNED_CHECKPOINT_PATH, TRUST_STORE_PATH, _write_v17_metadata
    files, case = write_inputs(fixture, tmp_path), fixture["case"]
    _write_v17_metadata(case["root"], ledger=case["ledger"], signed_checkpoint=case["signed"], trusted_public_keys=case["trust"])
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(canonical_json_bytes(case["profile"]))
    destination = tmp_path / "historical-export.zip"
    args = ["create", "--case-root", case["root"], "--tenant", TENANT_ID, "--case", CASE_ID, "--export-private-key", case["private"],
            "--ledger", case["root"] / LEDGER_PATH, "--signed-checkpoint", case["root"] / SIGNED_CHECKPOINT_PATH,
            "--trusted-signers", case["root"] / TRUST_STORE_PATH, "--provenance", provenance, "--out", destination,
            "--checkpoint-policy-store", fixture["governance"]["path"], "--policy-root-anchor", files["anchor"],
            "--key-trust-record", files["record"], "--key-trust-root-anchor", files["anchor"],
            "--key-trust-timestamp-request", files["request"], "--key-trust-timestamp-response", files["response"],
            "--key-trust-tsa-ca-file", files["ca"], "--expected-key-trust-tsa-certificate-sha256", fixture["options"]["expected_tsa_certificate_sha256"]]
    good = run_cli("case_export_v17.py", *args)
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(good.stdout)["checkpoint_key_trust_history"]["historical_key_trusted"]
    before = destination.read_bytes()
    files["response"].write_bytes(b"untrusted")
    assert run_cli("case_export_v17.py", *args).returncode == 3 and destination.read_bytes() == before


@pytest.mark.parametrize("script,extra", [("verify_case_v17.py", ["--format", "json"]), ("case_export_v17.py", ["verify"]), ("replay_case_v17.py", ["--replay-transforms"])])
def test_case_clis_apply_history_and_current_revocation(fixture, tmp_path, script, extra):
    files, case = write_inputs(fixture, tmp_path), fixture["case"]
    args = [*extra, "--zip", case["package"], "--export-public-key", case["public"],
            "--checkpoint-policy-store", fixture["governance"]["path"], "--policy-root-anchor", files["anchor"],
            "--key-trust-record", files["record"], "--key-trust-root-anchor", files["anchor"],
            "--key-trust-timestamp-request", files["request"], "--key-trust-timestamp-response", files["response"],
            "--key-trust-tsa-ca-file", files["ca"], "--expected-key-trust-tsa-certificate-sha256", fixture["options"]["expected_tsa_certificate_sha256"],
            "--expected-key-trust-request-sha256", fixture["options"]["expected_timestamp_request_sha256"],
            "--expected-key-trust-record-sha256", fixture["options"]["expected_record_sha256"], "--require-key-trust-history"]
    good = run_cli(script, *args)
    assert good.returncode == 0, good.stdout + good.stderr
    assert json.loads(good.stdout)["checkpoint_key_trust_history"]["historical_key_trusted"]
    revoke_current(fixture["governance"])
    bad = run_cli(script, *args)
    assert bad.returncode == 1 and "reconstruction" not in json.loads(bad.stdout)


@pytest.mark.parametrize("flag", ["--key-trust-record", "--key-trust-root-anchor", "--key-trust-timestamp-request", "--key-trust-timestamp-response", "--key-trust-tsa-ca-file"])
def test_empty_explicit_history_paths_do_not_disable_verification(fixture, flag):
    case = fixture["case"]
    result = run_cli("verify_case_v17.py", "--zip", case["package"], "--export-public-key", case["public"], "--format", "json", flag, "")
    assert result.returncode == 3


@pytest.mark.parametrize("statement", [b"", b"x" * (MAX_STATEMENT_BYTES + 1), "not bytes"])
def test_statement_timestamp_input_bounds_are_enforced(statement):
    with pytest.raises(TimestampError):
        prepare_statement_timestamp_request(statement=statement)
    assert evaluate_statement_timestamp(statement=statement)["status"] == "FAIL"

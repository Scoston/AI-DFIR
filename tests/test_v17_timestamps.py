from __future__ import annotations

import copy
import json
import socket
import subprocess
import sys
import zipfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asn1crypto import tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from case_export_v17 import _write_v17_metadata, export_case, verify_case
from v17_integrity import sha256_bytes
from v17_key_policy_selftest import EVALUATED_AT, synthetic_export
from v17_provenance_selftest import CASE_ID, TENANT_ID, sign_fixture
from v17_timestamp import (
    MAX_CA_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, TimestampError,
    checkpoint_timestamp_statement, evaluate_checkpoint_timestamp, prepare_timestamp_request,
    read_timestamp_file,
)
from v17_timestamp_selftest import synthetic_response, synthetic_tsa, timestamp_fixture
from verify_case_v17 import render_verification_report

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def tsa(tmp_path_factory):
    return synthetic_tsa(tmp_path_factory.mktemp("timestamp-authority"))


@pytest.fixture
def case(tmp_path):
    return synthetic_export(tmp_path)


@pytest.fixture
def options(case, tsa):
    return timestamp_fixture(case, tsa)


def evaluate(case, options):
    return evaluate_checkpoint_timestamp(signed_checkpoint=case["signed"], tenant_id=TENANT_ID,
                                          case_id=CASE_ID, **options)


def codes(report):
    return {item["code"] for item in report["findings"]}


def alter_response(raw, mutate, *, tsa=None):
    """Modify a synthetic token; optionally sign the modification with its test TSA."""
    value = tsp.TimeStampResp.load(raw)
    sd = value["time_stamp_token"]["content"]
    info = sd["encap_content_info"]["content"].parsed
    mutate(info)
    sd["encap_content_info"]["content"] = info
    if tsa is not None:
        signer = sd["signer_infos"][0]
        for attribute in signer["signed_attrs"]:
            if attribute["type"].native == "message_digest":
                attribute["values"][0] = bytes.fromhex(sha256_bytes(info.dump()))
        signer["signature"] = tsa["key"].sign(signer["signed_attrs"].untag().dump(),
                                               padding.PKCS1v15(), hashes.SHA256())
    return value.dump()


def replace_tsa_certificate(raw, tsa, *, ekus=None, critical=True, expired=False):
    """A correctly CA-signed and CMS-signed fixture, not just corrupted bytes."""
    original = tsa["cert"]
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(original.issuer)
            .public_key(tsa["key"].public_key()).serial_number(original.serial_number)
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now - timedelta(hours=1) if expired else now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
            .add_extension(x509.ExtendedKeyUsage(ekus or [ExtendedKeyUsageOID.TIME_STAMPING]), critical=critical)
            .sign(tsa["ca_key"], hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    value = tsp.TimeStampResp.load(raw)
    sd = value["time_stamp_token"]["content"]
    sd["certificates"] = [asn1_x509.Certificate.load(der),
                           asn1_x509.Certificate.load(tsa["ca"].public_bytes(serialization.Encoding.DER))]
    signer = sd["signer_infos"][0]
    # Preserve issuer/serial identity but bind the ESS attribute to the new cert.
    for attribute in signer["signed_attrs"]:
        if attribute["type"].native == "signing_certificate_v2":
            attribute["values"][0]["certs"][0]["cert_hash"] = bytes.fromhex(sha256_bytes(der))
    signer["signature"] = tsa["key"].sign(signer["signed_attrs"].untag().dump(),
                                           padding.PKCS1v15(), hashes.SHA256())
    return value.dump(), sha256_bytes(der)


def test_authenticated_receipt_reconstructs_offline_and_preserves_inputs(case, options, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network attempted")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    before, retained = case["package"].read_bytes(), options.copy()
    report = verify_case(case["package"], case["public"], include_reconstruction=True,
                         replay_transforms=True, **options)
    result = report["checkpoint_timestamp"]
    assert report["valid"] and result["status"] == "PASS"
    assert result["signature_and_chain_valid"] and result["checkpoint_binding_valid"]
    assert result["request_nonce_valid"] and result["checkpoint_existence_attested"]
    assert result["tsa_certificate_sha256"] == options["expected_tsa_certificate_sha256"]
    assert result["tsa_gen_time"].endswith("Z") and result["tsa_accuracy"]["seconds"] == 1
    assert result["tsa_revocation"] == "NOT_CHECKED" and result["tsa_operator_independence"] == "NOT_ASSESSED"
    assert result["historical_key_authorization"] == "NOT_EVALUATED"
    assert report["reconstruction"]["deterministic_replay"]["status"] == "PASS"
    assert case["package"].read_bytes() == before and options == retained
    text = render_verification_report(report)
    assert "External checkpoint timestamp: PASS" in text and result["tsa_gen_time"] in text


def test_request_discloses_only_imprint_nonce_and_protocol_fields(case):
    identity = dict(signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)
    raw = prepare_timestamp_request(**identity)
    request = tsp.TimeStampReq.load(raw)
    assert (1 << 127) <= request["nonce"].native < (1 << 128)
    assert request["nonce"].native != tsp.TimeStampReq.load(prepare_timestamp_request(**identity))["nonce"].native
    assert request["cert_req"].native and request["req_policy"].native is None
    assert request["message_imprint"]["hashed_message"].native.hex() == sha256_bytes(checkpoint_timestamp_statement(**identity))
    assert TENANT_ID.encode() not in raw and CASE_ID.encode() not in raw
    assert case["signed"].public_key_hex.encode() not in raw


def test_existing_case_requires_no_timestamp_tooling(case, monkeypatch):
    monkeypatch.setattr("v17_timestamp.shutil.which", lambda name: None)
    report = verify_case(case["package"], case["public"], include_reconstruction=True)
    assert report["valid"] and report["checkpoint_timestamp"]["status"] == "NOT_CONFIGURED"
    denied = verify_case(case["package"], case["public"], require_checkpoint_timestamp=True,
                         include_reconstruction=True)
    assert not denied["valid"] and "timestamp_required" in codes(denied["checkpoint_timestamp"])
    assert "reconstruction" not in denied


@pytest.mark.parametrize("missing", ["timestamp_request", "timestamp_response", "tsa_ca_pem", "expected_tsa_certificate_sha256"])
def test_partial_configuration_fails_even_without_requirement_flag(case, options, missing):
    options.pop(missing)
    options["require_checkpoint_timestamp"] = False
    result = evaluate(case, options)
    assert result["status"] == "FAIL" and "timestamp_required" in codes(result)


@pytest.mark.parametrize("field,limit", [
    ("timestamp_request", MAX_REQUEST_BYTES), ("timestamp_response", MAX_RESPONSE_BYTES), ("tsa_ca_pem", MAX_CA_BYTES),
])
def test_input_bounds_fail_closed(case, options, field, limit):
    options[field] = b"x" * (limit + 1)
    assert "timestamp_input_invalid" in codes(evaluate(case, options))


@pytest.mark.parametrize("data", [b"", b'{"inclusion_verified":true,"log_id":"fake"}', b"\x30\x80\x00\x00", b"garbage"])
def test_unstructured_or_unsigned_receipts_cannot_attest(case, options, data):
    options["timestamp_response"] = data
    result = evaluate(case, options)
    assert result["status"] == "FAIL" and not result["checkpoint_existence_attested"]
    assert result["tsa_gen_time"] is None and not result["signature_and_chain_valid"]


@pytest.mark.parametrize("field", ["timestamp_request", "timestamp_response"])
def test_trailing_bytes_are_rejected(case, options, field):
    options[field] += b"another object"
    assert evaluate(case, options)["status"] == "FAIL"


def test_signature_corruption_fails_after_matching_metadata(case, options):
    value = tsp.TimeStampResp.load(options["timestamp_response"])
    signer = value["time_stamp_token"]["content"]["signer_infos"][0]
    raw = signer["signature"].native
    signer["signature"] = bytes([raw[0] ^ 1]) + raw[1:]
    options["timestamp_response"] = value.dump()
    result = evaluate(case, options)
    assert "timestamp_crypto_failed" in codes(result) and not result["checkpoint_existence_attested"]


def test_authenticated_metadata_edit_requires_a_signature(case, options):
    options["timestamp_response"] = alter_response(options["timestamp_response"],
        lambda info: info.__setitem__("serial_number", info["serial_number"].native + 1))
    assert "timestamp_crypto_failed" in codes(evaluate(case, options))


def test_authenticated_fixture_modifications_have_valid_signatures(case, options, tsa):
    options["timestamp_response"], options["expected_tsa_certificate_sha256"] = replace_tsa_certificate(
        options["timestamp_response"], tsa)
    time = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=10)
    options["timestamp_response"] = alter_response(options["timestamp_response"],
        lambda info: info.__setitem__("gen_time", time), tsa=tsa)
    result = evaluate(case, options)
    assert result["status"] == "PASS", result
    assert result["tsa_gen_time"] == time.isoformat().replace("+00:00", "Z")


@pytest.mark.parametrize("digest", ["sha1", "md5"])
def test_weak_cms_digest_is_rejected(case, options, digest):
    value = tsp.TimeStampResp.load(options["timestamp_response"])
    value["time_stamp_token"]["content"]["signer_infos"][0]["digest_algorithm"]["algorithm"] = digest
    options["timestamp_response"] = value.dump()
    assert "timestamp_digest_unsupported" in codes(evaluate(case, options))


def test_different_request_receipt_is_rejected(case, options, tsa):
    other = prepare_timestamp_request(signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID)
    options["timestamp_response"] = synthetic_response(tsa, other)
    result = verify_case(case["package"], case["public"], include_reconstruction=True, **options)
    assert "timestamp_nonce_mismatch" in codes(result["checkpoint_timestamp"])
    assert result["signature_valid"] and result["signer_trusted"] and not result["valid"]
    assert "reconstruction" not in result and result["provenance_integrity"] == "NOT_RUN"


def test_whole_request_replacement_fails_retained_request_pin(case, options, tsa):
    options["timestamp_request"] = prepare_timestamp_request(signed_checkpoint=case["signed"],
                                                            tenant_id=TENANT_ID, case_id=CASE_ID)
    options["timestamp_response"] = synthetic_response(tsa, options["timestamp_request"])
    assert "timestamp_request_pin_mismatch" in codes(evaluate(case, options))


def test_same_ledger_with_new_valid_signature_cannot_reuse_receipt(case, options):
    case["signed"] = sign_fixture(case["ledger"])[0]
    assert case["signed"].verify_signature()[0]
    assert "timestamp_imprint_mismatch" in codes(evaluate(case, options))


def test_tenant_identity_is_bound(case, options):
    result = evaluate_checkpoint_timestamp(signed_checkpoint=case["signed"], tenant_id="ANOTHER-TENANT",
                                           case_id=CASE_ID, **options)
    assert "timestamp_imprint_mismatch" in codes(result)


@pytest.mark.parametrize("change,expected", [
    (lambda i: i.__setitem__("nonce", None), "timestamp_nonce_mismatch"),
    (lambda i: i.__setitem__("policy", "1.3.6.1.4.1.55555.2"), "timestamp_policy_mismatch"),
    (lambda i: i["message_imprint"].__setitem__("hashed_message", b"x" * 32), "timestamp_imprint_mismatch"),
    (lambda i: i["message_imprint"]["hash_algorithm"].__setitem__("algorithm", "sha1"), "timestamp_imprint_mismatch"),
])
def test_authenticated_token_fields_must_match_request(case, options, tsa, change, expected):
    options["timestamp_response"] = alter_response(options["timestamp_response"], change, tsa=tsa)
    assert expected in codes(evaluate(case, options))


@pytest.mark.parametrize("nonce", [None, 0, 1, (1 << 64) - 1, 1 << 128])
def test_missing_or_weak_request_nonce_is_rejected(case, options, nonce):
    request = tsp.TimeStampReq.load(options["timestamp_request"])
    request["nonce"] = nonce
    options["timestamp_request"] = request.dump()
    options.pop("expected_timestamp_request_sha256")
    assert "timestamp_nonce_invalid" in codes(evaluate(case, options))


@pytest.mark.parametrize("pin,expected", [("0" * 64, "timestamp_signer_pin_mismatch"),
                                        ("A" * 64, "timestamp_pin_invalid"), ("bad", "timestamp_pin_invalid")])
def test_independently_pinned_tsa_certificate_is_required(case, options, pin, expected):
    options["expected_tsa_certificate_sha256"] = pin
    assert expected in codes(evaluate(case, options))


def test_embedded_root_and_system_ca_environment_cannot_supply_trust(case, options, tsa, tmp_path, monkeypatch):
    other = synthetic_tsa(tmp_path / "unrelated-ca")
    options["tsa_ca_pem"] = other["ca_pem"]
    monkeypatch.setenv("SSL_CERT_FILE", str(tsa["root"] / "ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tsa["root"]))
    assert "timestamp_crypto_failed" in codes(evaluate(case, options))


@pytest.mark.parametrize("extra", [b"not a certificate", b"-----BEGIN PUBLIC KEY-----\nsynthetic marker\n-----END PUBLIC KEY-----"])
def test_ca_bundle_rejects_other_material(case, options, extra):
    options["tsa_ca_pem"] += extra
    assert "timestamp_ca_invalid" in codes(evaluate(case, options))


def test_equivalent_certificate_names_cannot_bypass_actual_signer_pin(case, options, tsa, tmp_path):
    # OpenSSL compares X.509 names semantically. A raw DER SID comparison must
    # not pin one cert while signature verification silently selects another.
    original = tsa["cert"]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alternate_issuer = x509.Name([x509.NameAttribute(a.oid, a.value.lower()) for a in original.issuer])
    cert = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(alternate_issuer)
            .public_key(key.public_key()).serial_number(original.serial_number)
            .not_valid_before(original.not_valid_before_utc).not_valid_after(original.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(tsa["ca_key"], hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    value = tsp.TimeStampResp.load(options["timestamp_response"])
    sd = value["time_stamp_token"]["content"]
    sd["certificates"] = [asn1_x509.Certificate.load(der),
        asn1_x509.Certificate.load(original.public_bytes(serialization.Encoding.DER)),
        asn1_x509.Certificate.load(tsa["ca"].public_bytes(serialization.Encoding.DER))]
    signer = sd["signer_infos"][0]
    for attribute in signer["signed_attrs"]:
        if attribute["type"].native == "signing_certificate_v2":
            attribute["values"][0]["certs"][0]["cert_hash"] = bytes.fromhex(sha256_bytes(der))
    signer["signature"] = key.sign(signer["signed_attrs"].untag().dump(), padding.PKCS1v15(), hashes.SHA256())
    options["timestamp_response"] = value.dump()
    request, response, ca = tmp_path / "query.tsq", tmp_path / "response.tsr", tmp_path / "ca.pem"
    request.write_bytes(options["timestamp_request"])
    response.write_bytes(options["timestamp_response"])
    ca.write_bytes(options["tsa_ca_pem"])
    baseline = subprocess.run(["openssl", "ts", "-verify", "-queryfile", str(request), "-in", str(response),
                               "-CAfile", str(ca)], capture_output=True, text=True)
    assert baseline.returncode == 0, baseline.stderr
    # Protocol validation succeeds, but the actual key did not match the pin.
    result = evaluate(case, options)
    assert "timestamp_crypto_failed" in codes(result) and not result["checkpoint_existence_attested"]


@pytest.mark.parametrize("ekus,critical", [([ExtendedKeyUsageOID.CODE_SIGNING], True),
    ([ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.CODE_SIGNING], True),
    ([ExtendedKeyUsageOID.TIME_STAMPING], False)])
def test_ca_signed_tsa_certificate_requires_exclusive_critical_timestamp_eku(case, options, tsa, ekus, critical):
    options["timestamp_response"], options["expected_tsa_certificate_sha256"] = replace_tsa_certificate(
        options["timestamp_response"], tsa, ekus=ekus, critical=critical)
    assert "timestamp_crypto_failed" in codes(evaluate(case, options))


def test_expired_tsa_is_not_accepted_via_backdated_token(case, options, tsa):
    options["timestamp_response"], options["expected_tsa_certificate_sha256"] = replace_tsa_certificate(
        options["timestamp_response"], tsa, expired=True)
    options["timestamp_response"] = alter_response(options["timestamp_response"],
        lambda info: info.__setitem__("gen_time", datetime.now(timezone.utc) - timedelta(hours=2)), tsa=tsa)
    assert "timestamp_crypto_failed" in codes(evaluate(case, options))


@pytest.mark.parametrize("delta", [timedelta(minutes=6), timedelta(days=-3)])
def test_authenticated_time_must_fit_clock_and_certificate(case, options, tsa, delta):
    options["timestamp_response"] = alter_response(options["timestamp_response"],
        lambda info: info.__setitem__("gen_time", datetime.now(timezone.utc) + delta), tsa=tsa)
    result = evaluate(case, options)
    assert "timestamp_time_invalid" in codes(result) and result["tsa_gen_time"] is None


def test_missing_openssl_cannot_downgrade_required_anchor(case, options, monkeypatch):
    monkeypatch.setattr("v17_timestamp.shutil.which", lambda name: None)
    assert "timestamp_verifier_unavailable" in codes(evaluate(case, options))


@pytest.mark.parametrize("failure", [OSError("unavailable"), subprocess.TimeoutExpired("openssl", 15)])
def test_openssl_execution_failure_is_reported(case, options, monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr("v17_timestamp.subprocess.run", fail)
    assert "timestamp_verifier_unavailable" in codes(evaluate(case, options))


def test_valid_timestamp_cannot_override_revocation(case, options):
    policy = copy.deepcopy(case["policy"])
    policy["keys"][0].update(state="revoked", status_changed_at="2026-09-06T00:00:30Z", reason="synthetic revocation")
    report = verify_case(case["package"], case["public"], include_reconstruction=True,
                         checkpoint_key_policy=policy, key_policy_evaluated_at=EVALUATED_AT, **options)
    assert report["checkpoint_timestamp"]["status"] == "PASS"
    assert report["signature_valid"] and not report["signer_trusted"] and not report["valid"]
    assert "reconstruction" not in report


def test_valid_timestamp_cannot_override_evidence_tampering(case, options, tmp_path):
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(case["package"]) as src, zipfile.ZipFile(bad, "w") as dst:
        for entry in src.infolist():
            dst.writestr(entry, b"[]" if entry.filename == "raw.json" else src.read(entry.filename))
    report = verify_case(bad, case["public"], include_reconstruction=True, **options)
    assert report["checkpoint_timestamp"]["status"] == "PASS"
    assert not report["valid"] and report["artifact_integrity"] == "FAIL" and "reconstruction" not in report


def test_embedded_timestamp_material_does_not_satisfy_external_requirement(case, options):
    for key, name in (("timestamp_request", "timestamp.tsq"), ("timestamp_response", "timestamp.tsr"), ("tsa_ca_pem", "tsa-ca.pem")):
        (case["root"] / name).write_bytes(options[key])
    export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                signed_checkpoint=case["signed"], trusted_public_keys=case["trust"], provenance=case["profile"])
    report = verify_case(case["package"], case["public"], require_checkpoint_timestamp=True)
    assert not report["valid"] and "timestamp_required" in codes(report["checkpoint_timestamp"])


def test_export_rejection_preserves_existing_destination_and_source(case, options):
    before = case["package"].read_bytes()
    options["expected_tsa_certificate_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="checkpoint timestamp rejected export"):
        export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                    signed_checkpoint=case["signed"], trusted_public_keys=case["trust"], provenance=case["profile"], **options)
    assert case["package"].read_bytes() == before


def test_export_with_external_receipt_can_be_verified_again(case, options):
    result = export_case(case["root"], TENANT_ID, CASE_ID, case["private"], case["package"], ledger=case["ledger"],
                         signed_checkpoint=case["signed"], trusted_public_keys=case["trust"], provenance=case["profile"], **options)
    assert result["checkpoint_timestamp"]["status"] == "PASS"
    assert verify_case(case["package"], case["public"], **options)["valid"]


def cli_timestamp_options(root, options):
    args = []
    for key, flag, suffix in (("timestamp_request", "--timestamp-request", "tsq"),
                             ("timestamp_response", "--timestamp-response", "tsr"),
                             ("tsa_ca_pem", "--tsa-ca-file", "pem")):
        path = root / ("receipt." + suffix)
        path.write_bytes(options[key])
        args.extend([flag, str(path)])
    return args + ["--expected-tsa-certificate-sha256", options["expected_tsa_certificate_sha256"],
                   "--expected-timestamp-request-sha256", options["expected_timestamp_request_sha256"],
                   "--require-checkpoint-timestamp"]


@pytest.mark.parametrize("script,extra", [("verify_case_v17.py", ["--format", "json"]),
    ("case_export_v17.py", ["verify"]), ("replay_case_v17.py", ["--replay-transforms"])])
def test_case_clis_accept_valid_and_reject_wrong_tsa(case, options, tmp_path, script, extra):
    args = [sys.executable, str(ROOT / script), *extra, "--zip", str(case["package"]),
            "--export-public-key", str(case["public"]), *cli_timestamp_options(tmp_path, options)]
    passed = subprocess.run(args, capture_output=True, text=True)
    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert json.loads(passed.stdout)["checkpoint_timestamp"]["status"] == "PASS"
    args[args.index("--expected-tsa-certificate-sha256") + 1] = "0" * 64
    denied = subprocess.run(args, capture_output=True, text=True)
    assert denied.returncode == 1
    report = json.loads(denied.stdout)
    assert not report["valid"] and "reconstruction" not in report


def test_prepare_and_standalone_verify_clis(case, tsa, tmp_path):
    signed = tmp_path / "checkpoint.json"
    signed.write_text(json.dumps(case["signed"].to_dict()), encoding="utf-8")
    request = tmp_path / "prepared.tsq"
    shared = ["--signed-checkpoint", str(signed), "--tenant", TENANT_ID, "--case", CASE_ID]
    prepare = [sys.executable, str(ROOT / "checkpoint_timestamp_v17.py"), "prepare", *shared, "--out", str(request)]
    done = subprocess.run(prepare, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    report = json.loads(done.stdout)
    retained = request.read_bytes()
    assert report["status"] == "PREPARED" and not report["network_performed"]
    assert report["request_sha256"] == sha256_bytes(retained)
    repeated = subprocess.run(prepare, capture_output=True, text=True)
    assert repeated.returncode == 3 and request.read_bytes() == retained
    options = {"timestamp_request": retained, "timestamp_response": synthetic_response(tsa, retained),
               "tsa_ca_pem": tsa["ca_pem"], "expected_tsa_certificate_sha256": tsa["pin"],
               "expected_timestamp_request_sha256": report["request_sha256"]}
    verified = subprocess.run([sys.executable, str(ROOT / "checkpoint_timestamp_v17.py"), "verify", *shared,
                               *cli_timestamp_options(tmp_path, options)], capture_output=True, text=True)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert json.loads(verified.stdout)["checkpoint_existence_attested"]


def test_export_cli_checks_timestamp_before_replacing_destination(case, options, tmp_path):
    from case_export_v17 import LEDGER_PATH, SIGNED_CHECKPOINT_PATH, TRUST_STORE_PATH
    _write_v17_metadata(case["root"], ledger=case["ledger"], signed_checkpoint=case["signed"],
                        trusted_public_keys=case["trust"])
    provenance = tmp_path / "provenance.json"
    provenance.write_text(json.dumps(case["profile"]), encoding="utf-8")
    destination = tmp_path / "anchored.zip"
    args = [sys.executable, str(ROOT / "case_export_v17.py"), "create", "--case-root", str(case["root"]),
            "--tenant", TENANT_ID, "--case", CASE_ID, "--export-private-key", str(case["private"]),
            "--ledger", str(case["root"] / LEDGER_PATH), "--signed-checkpoint", str(case["root"] / SIGNED_CHECKPOINT_PATH),
            "--trusted-signers", str(case["root"] / TRUST_STORE_PATH), "--provenance", str(provenance),
            "--out", str(destination), *cli_timestamp_options(tmp_path, options)]
    passed = subprocess.run(args, text=True, capture_output=True)
    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert json.loads(passed.stdout)["checkpoint_timestamp"]["status"] == "PASS"
    before = destination.read_bytes()
    args[args.index("--expected-tsa-certificate-sha256") + 1] = "0" * 64
    denied = subprocess.run(args, text=True, capture_output=True)
    assert denied.returncode == 3 and destination.read_bytes() == before


@pytest.mark.parametrize("oid", ["bad", "1.40.2", "1.02.3", "3.1.2", "1.2;exec", "1.2." + "1" * 129])
def test_prepare_rejects_invalid_policy_oid(case, oid):
    with pytest.raises(TimestampError, match="policy"):
        prepare_timestamp_request(signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id=CASE_ID, tsa_policy_oid=oid)


def test_prepare_rejects_invalid_signature_and_case(case):
    with pytest.raises(TimestampError):
        prepare_timestamp_request(signed_checkpoint=replace(case["signed"], signed_at="altered"), tenant_id=TENANT_ID, case_id=CASE_ID)
    with pytest.raises(TimestampError, match="case"):
        prepare_timestamp_request(signed_checkpoint=case["signed"], tenant_id=TENANT_ID, case_id="WRONG")


def test_file_loader_reads_only_bounded_input(tmp_path):
    path = tmp_path / "oversized.tsr"
    path.write_bytes(b"x" * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(TimestampError):
        read_timestamp_file(path, MAX_RESPONSE_BYTES)

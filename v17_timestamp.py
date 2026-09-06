"""RFC 3161 checkpoint timestamps with verifier-supplied authority trust.

Only the imprint and a random nonce go in the request. Preparation and
verification are offline; submission is an operator-controlled separate step.
ASN.1 decoding is not signature verification: OpenSSL performs that check.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from asn1crypto import tsp
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_signing import SignedLedgerCheckpoint

STATEMENT_SCHEMA = "ai-dfir/checkpoint-timestamp-statement/v1.7"
RESULT_SCHEMA = "ai-dfir/checkpoint-timestamp-result/v1.7"
SUBJECT_RESULT_SCHEMA = "ai-dfir/statement-timestamp-result/v1.7"
MAX_STATEMENT_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CA_BYTES = 256 * 1024
MAX_CERTIFICATES = 16
OPENSSL_TIMEOUT = 15
MAX_FUTURE_SECONDS = 300
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_OID = re.compile(r"(?:0|1|2)(?:\.(?:0|[1-9][0-9]*)){1,31}\Z")
_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----")


class TimestampError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise TimestampError(code, detail)


def _bounded(value: bytes, limit: int, label: str) -> bytes:
    _require(type(value) is bytes and 0 < len(value) <= limit,
             "timestamp_input_invalid", f"{label} must be nonempty bytes, at most {limit} bytes")
    return value


def read_timestamp_file(path: str | Path, limit: int) -> bytes:
    with Path(path).open("rb") as stream:
        return _bounded(stream.read(limit + 1), limit, "timestamp input")


def checkpoint_timestamp_statement(*, signed_checkpoint: SignedLedgerCheckpoint,
                                   tenant_id: str, case_id: str) -> bytes:
    """Bind the entire signature envelope, including its claimed time and key."""
    _require(isinstance(signed_checkpoint, SignedLedgerCheckpoint),
             "timestamp_checkpoint_invalid", "a signed ledger checkpoint is required")
    for label, value in (("tenant", tenant_id), ("case", case_id)):
        _require(isinstance(value, str) and 0 < len(value) <= 256 and value.strip() == value,
                 "timestamp_identity_invalid", f"invalid {label} identity")
    _require(signed_checkpoint.checkpoint.case_id == case_id,
             "timestamp_case_mismatch", "checkpoint case does not match requested case")
    valid, errors = signed_checkpoint.verify_signature()
    _require(valid, "timestamp_checkpoint_signature_invalid", "; ".join(errors))
    return canonical_json_bytes({
        "schema": STATEMENT_SCHEMA, "tenant_id": tenant_id, "case_id": case_id,
        "checkpoint_sha256": signed_checkpoint.checkpoint.checkpoint_hash,
        "signed_checkpoint_sha256": sha256_object(signed_checkpoint.to_dict()),
    })


def prepare_timestamp_request(*, signed_checkpoint: SignedLedgerCheckpoint,
                              tenant_id: str, case_id: str,
                              tsa_policy_oid: str | None = None) -> bytes:
    statement = checkpoint_timestamp_statement(signed_checkpoint=signed_checkpoint,
                                               tenant_id=tenant_id, case_id=case_id)
    return prepare_statement_timestamp_request(statement=statement, tsa_policy_oid=tsa_policy_oid)


def prepare_statement_timestamp_request(*, statement: bytes, tsa_policy_oid: str | None = None) -> bytes:
    """Prepare this RFC 3161 request profile for an explicitly bound statement."""
    statement = _bounded(statement, MAX_STATEMENT_BYTES, "statement")
    fields: dict[str, Any] = {
        "version": "v1", "message_imprint": {
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": bytes.fromhex(sha256_bytes(statement)),
        },
        "nonce": secrets.randbits(127) | (1 << 127), "cert_req": True,
    }
    if tsa_policy_oid is not None:
        _require(isinstance(tsa_policy_oid, str) and len(tsa_policy_oid) <= 128
                 and _OID.fullmatch(tsa_policy_oid) is not None,
                 "timestamp_policy_invalid", "TSA policy must be a numeric object identifier")
        arcs = [int(part) for part in tsa_policy_oid.split(".")]
        _require(arcs[0] == 2 or arcs[1] <= 39,
                 "timestamp_policy_invalid", "invalid TSA policy object identifier")
        fields["req_policy"] = tsa_policy_oid
    return tsp.TimeStampReq(fields).dump()


def timestamp_report(status: str = "NOT_RUN") -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA, "status": status, "offline": True,
        "network_performed": False, "statement_sha256": None, "request_sha256": None,
        "response_sha256": None, "tsa_ca_bundle_sha256": None,
        "tsa_certificate_sha256": None, "tsa_gen_time": None, "tsa_policy_oid": None,
        "tsa_serial_number": None, "tsa_accuracy": None, "evaluated_at": None,
        "evaluation_time_source": "system-utc", "signature_and_chain_valid": False,
        "checkpoint_binding_valid": False, "request_nonce_valid": False,
        "checkpoint_existence_attested": False, "tsa_revocation": "NOT_CHECKED",
        "tsa_operator_independence": "NOT_ASSESSED",
        "historical_key_authorization": "NOT_EVALUATED", "findings": [],
    }


def _decode(data: bytes, cls: Any, *, canonical: bool = False) -> Any:
    value = cls.load(data, strict=True)
    # Decode lazy children and reject trailing input. Only our own request
    # profile requires a canonical round trip. OpenSSL's response certificate
    # SET order need not match asn1crypto's; never rewrite signed CMS bytes.
    _ = value.native
    if canonical:
        _require(value.dump(force=True) == data, "timestamp_der_invalid", "canonical request DER required")
    return value


def _imprint(value: Any, digest: bytes) -> None:
    _require(value["hash_algorithm"]["algorithm"].native == "sha256"
             and value["hash_algorithm"]["parameters"].native is None
             and value["hashed_message"].native == digest,
             "timestamp_imprint_mismatch", "SHA-256 imprint does not bind the expected statement")


def _request(data: bytes, digest: bytes) -> Any:
    request = _decode(_bounded(data, MAX_REQUEST_BYTES, "request"), tsp.TimeStampReq, canonical=True)
    _require(request["version"].native == "v1", "timestamp_request_invalid", "request version must be v1")
    _imprint(request["message_imprint"], digest)
    nonce = request["nonce"].native
    _require(type(nonce) is int and (1 << 127) <= nonce < (1 << 128),
             "timestamp_nonce_invalid", "request requires this profile's 128-bit nonce")
    _require(request["cert_req"].native is True and not request["extensions"].native,
             "timestamp_request_invalid", "certificate request required; request extensions are unsupported")
    return request


def _signing_certificate(signed_data: Any) -> Any:
    signers = signed_data["signer_infos"]
    certificates = signed_data["certificates"]
    _require(len(signers) == 1 and 0 < len(certificates) <= MAX_CERTIFICATES,
             "timestamp_signer_invalid", "exactly one signer and a bounded certificate set required")
    _require(signers[0]["digest_algorithm"]["algorithm"].native in {"sha256", "sha384", "sha512"},
             "timestamp_digest_unsupported", "TSA CMS signature requires SHA-256, SHA-384, or SHA-512")
    sid = signers[0]["sid"]
    matches = []
    for choice in certificates:
        _require(choice.name == "certificate", "timestamp_signer_invalid", "unsupported certificate choice")
        cert = choice.chosen
        if sid.name == "issuer_and_serial_number":
            matches_sid = (cert.issuer.dump() == sid.chosen["issuer"].dump()
                           and cert.serial_number == sid.chosen["serial_number"].native)
        else:
            matches_sid = sid.name == "subject_key_identifier" and cert.key_identifier == sid.chosen.native
        if matches_sid:
            matches.append(cert)
    _require(len(matches) == 1, "timestamp_signer_invalid", "missing or ambiguous TSA signing certificate")
    return matches[0]


def _ca_bundle(data: bytes) -> None:
    _bounded(data, MAX_CA_BYTES, "CA bundle")
    blocks = _CERT.findall(data)
    _require(0 < len(blocks) <= MAX_CERTIFICATES and not _CERT.sub(b"", data).strip(),
             "timestamp_ca_invalid", "CA bundle must contain only PEM certificates")
    for block in blocks:
        x509.load_pem_x509_certificate(block)


def _run_openssl(arguments: list[str], *, env: dict[str, str]) -> bytes:
    try:
        run = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=OPENSSL_TIMEOUT, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TimestampError("timestamp_verifier_unavailable", "OpenSSL timestamp verification unavailable") from exc
    _require(run.returncode == 0, "timestamp_crypto_failed",
             "OpenSSL rejected the timestamp signature, request, or certificate chain")
    return run.stdout


def _verify_openssl(request: bytes, response: bytes, ca: bytes, now: datetime,
                    token: bytes, signer_pem: bytes) -> bytes:
    executable = shutil.which("openssl")
    _require(executable is not None, "timestamp_verifier_unavailable", "OpenSSL 3 is required for timestamps")
    with tempfile.TemporaryDirectory(prefix="ai-dfir-timestamp-") as temporary:
        root = Path(temporary)
        for name, data in (("request.tsq", request), ("response.tsr", response), ("ca.pem", ca),
                           ("token.der", token), ("pinned-signer.pem", signer_pem)):
            (root / name).write_bytes(data)
        empty = root / "empty-trust"
        empty.mkdir()
        config = root / "empty.cnf"
        config.write_bytes(b"")
        env = dict(os.environ)
        env.update(OPENSSL_CONF=str(config), SSL_CERT_FILE=str(root / "ca.pem"), SSL_CERT_DIR=str(empty))
        version = _run_openssl([executable, "version"], env=env)
        _require(version.startswith(b"OpenSSL 3."), "timestamp_verifier_unavailable", "OpenSSL 3 is required")
        # Override all three trust locations. Embedded certificates may build
        # a chain but cannot become roots, and system CA stores cannot widen it.
        trust_args = [
            "-CAfile", str(root / "ca.pem"), "-CApath", str(empty), "-CAstore", str(root / "ca.pem"),
            "-purpose", "timestampsign", "-auth_level", "2", "-verify_depth", "8",
            "-attime", str(int(now.timestamp())),
        ]
        _run_openssl([
            executable, "ts", "-verify", "-queryfile", str(root / "request.tsq"),
            "-in", str(root / "response.tsr"), *trust_args,
        ], env=env)
        # Force CMS signer selection to the pinned certificate. Matching a SID
        # in Python must not depend on OpenSSL's certificate-name equivalence
        # rules or on the ordering of attacker-supplied embedded certificates.
        return _run_openssl([
            executable, "cms", "-verify", "-verify_retcode", "-binary", "-inform", "DER",
            "-in", str(root / "token.der"), "-nointern", "-certfile", str(root / "pinned-signer.pem"),
            *trust_args,
        ], env=env)


def evaluate_checkpoint_timestamp(*, signed_checkpoint: SignedLedgerCheckpoint,
                                  tenant_id: str, case_id: str,
                                  timestamp_request: bytes | None = None,
                                  timestamp_response: bytes | None = None,
                                  tsa_ca_pem: bytes | None = None,
                                  expected_tsa_certificate_sha256: str | None = None,
                                  expected_timestamp_request_sha256: str | None = None,
                                  require_checkpoint_timestamp: bool = False) -> dict[str, Any]:
    return _evaluate_timestamp(
        lambda: checkpoint_timestamp_statement(signed_checkpoint=signed_checkpoint, tenant_id=tenant_id, case_id=case_id),
        timestamp_request=timestamp_request, timestamp_response=timestamp_response, tsa_ca_pem=tsa_ca_pem,
        expected_tsa_certificate_sha256=expected_tsa_certificate_sha256,
        expected_timestamp_request_sha256=expected_timestamp_request_sha256,
        require_timestamp=require_checkpoint_timestamp,
    )


def evaluate_statement_timestamp(*, statement: bytes, timestamp_request: bytes | None = None,
                                 timestamp_response: bytes | None = None, tsa_ca_pem: bytes | None = None,
                                 expected_tsa_certificate_sha256: str | None = None,
                                 expected_timestamp_request_sha256: str | None = None) -> dict[str, Any]:
    """Authenticate a timestamp on caller-bound bytes; this grants no policy authority."""
    report = _evaluate_timestamp(
        lambda: _bounded(statement, MAX_STATEMENT_BYTES, "statement"),
        timestamp_request=timestamp_request, timestamp_response=timestamp_response, tsa_ca_pem=tsa_ca_pem,
        expected_tsa_certificate_sha256=expected_tsa_certificate_sha256,
        expected_timestamp_request_sha256=expected_timestamp_request_sha256, require_timestamp=True,
    )
    report["schema"] = SUBJECT_RESULT_SCHEMA
    report["subject_binding_valid"] = report.pop("checkpoint_binding_valid")
    report["subject_existence_attested"] = report.pop("checkpoint_existence_attested")
    return report


def _evaluate_timestamp(statement_factory, *, timestamp_request, timestamp_response, tsa_ca_pem,
                        expected_tsa_certificate_sha256, expected_timestamp_request_sha256,
                        require_timestamp) -> dict[str, Any]:
    report = timestamp_report()
    configured = any(value is not None for value in (
        timestamp_request, timestamp_response, tsa_ca_pem, expected_tsa_certificate_sha256,
        expected_timestamp_request_sha256,
    ))
    if not configured and not require_timestamp:
        report["status"] = "NOT_CONFIGURED"
        return report
    try:
        _require(all(value is not None for value in (
            timestamp_request, timestamp_response, tsa_ca_pem, expected_tsa_certificate_sha256,
        )), "timestamp_required", "request, response, approved CA bundle, and TSA certificate pin are required")
        _require(isinstance(expected_tsa_certificate_sha256, str)
                 and _HEX.fullmatch(expected_tsa_certificate_sha256) is not None,
                 "timestamp_pin_invalid", "TSA certificate pin must be lowercase SHA-256 of its DER bytes")
        statement = statement_factory()
        report["statement_sha256"] = sha256_bytes(statement)
        request = _request(timestamp_request, bytes.fromhex(report["statement_sha256"]))
        report["request_sha256"] = sha256_bytes(timestamp_request)
        if expected_timestamp_request_sha256 is not None:
            _require(isinstance(expected_timestamp_request_sha256, str)
                     and _HEX.fullmatch(expected_timestamp_request_sha256) is not None,
                     "timestamp_pin_invalid", "request pin must be lowercase SHA-256")
            _require(report["request_sha256"] == expected_timestamp_request_sha256,
                     "timestamp_request_pin_mismatch", "request differs from the retained request digest")
        _ca_bundle(tsa_ca_pem)
        report["tsa_ca_bundle_sha256"] = sha256_bytes(tsa_ca_pem)
        response = _decode(_bounded(timestamp_response, MAX_RESPONSE_BYTES, "response"), tsp.TimeStampResp)
        report["response_sha256"] = sha256_bytes(timestamp_response)
        _require(response["status"]["status"].native in {"granted", "granted_with_mods"},
                 "timestamp_not_granted", "TSA did not grant a timestamp")
        token = response["time_stamp_token"]
        _require(token["content_type"].native == "signed_data",
                 "timestamp_token_invalid", "CMS SignedData timestamp required")
        signed_data = token["content"]
        content = signed_data["encap_content_info"]
        _require(content["content_type"].native == "tst_info",
                 "timestamp_token_invalid", "RFC 3161 TSTInfo content required")
        info = content["content"].parsed
        _require(info["version"].native == "v1" and not info["extensions"].native,
                 "timestamp_token_invalid", "v1 token required; token extensions are unsupported")
        _require(0 < info["serial_number"].native < (1 << 160),
                 "timestamp_token_invalid", "TSA serial must be a positive integer smaller than 160 bits")
        _imprint(info["message_imprint"], bytes.fromhex(report["statement_sha256"]))
        _require(info["nonce"].native == request["nonce"].native,
                 "timestamp_nonce_mismatch", "response does not match the retained request nonce")
        if request["req_policy"].native is not None:
            _require(info["policy"].dotted == request["req_policy"].dotted,
                     "timestamp_policy_mismatch", "TSA policy differs from the requested policy")
        signer = _signing_certificate(signed_data)
        fingerprint = sha256_bytes(signer.dump())
        _require(fingerprint == expected_tsa_certificate_sha256,
                 "timestamp_signer_pin_mismatch", "TSA signer differs from the independently approved certificate")
        cert = x509.load_der_x509_certificate(signer.dump())
        now = datetime.now(timezone.utc)
        report["evaluated_at"] = now.isoformat().replace("+00:00", "Z")
        gen_time = info["gen_time"].native
        _require(isinstance(gen_time, datetime) and gen_time.utcoffset() == timedelta(0),
                 "timestamp_time_invalid", "TSA generation time must be UTC")
        _require(cert.not_valid_before_utc <= gen_time < cert.not_valid_after_utc,
                 "timestamp_time_invalid", "TSA time is outside its signing certificate validity")
        _require(gen_time <= now + timedelta(seconds=MAX_FUTURE_SECONDS),
                 "timestamp_time_invalid", "TSA time is ahead of the verifier's clock tolerance")
        accuracy = info["accuracy"].native
        if accuracy is not None:
            for name, value in accuracy.items():
                _require(value is None or (type(value) is int and (
                    0 <= value <= 86400 if name == "seconds" else 1 <= value <= 999)),
                    "timestamp_accuracy_invalid", "unsupported TSA accuracy interval")
        authenticated_content = _verify_openssl(
            timestamp_request, timestamp_response, tsa_ca_pem, now,
            token.dump(), cert.public_bytes(serialization.Encoding.PEM),
        )
        _require(authenticated_content == content["content"].contents,
                 "timestamp_content_mismatch", "authenticated timestamp content differs from parsed content")
        # Only authenticated values become report assertions. Decoding alone
        # or an attacker-supplied inclusion_verified flag can never reach PASS.
        report.update(status="PASS", tsa_certificate_sha256=fingerprint,
                      tsa_gen_time=gen_time.isoformat().replace("+00:00", "Z"),
                      tsa_policy_oid=info["policy"].dotted,
                      tsa_serial_number=str(info["serial_number"].native), tsa_accuracy=accuracy,
                      signature_and_chain_valid=True, checkpoint_binding_valid=True,
                      request_nonce_valid=True, checkpoint_existence_attested=True)
    except TimestampError as exc:
        report["findings"].append({"code": exc.code, "detail": str(exc)})
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError, AttributeError, UnsupportedAlgorithm) as exc:
        report["findings"].append({"code": "timestamp_malformed", "detail": f"malformed timestamp input ({type(exc).__name__})"})
    if report["status"] != "PASS":
        report["status"] = "FAIL"
    return report


def add_timestamp_arguments(parser: Any) -> None:
    parser.add_argument("--timestamp-request", help="Retained RFC 3161 request (.tsq)")
    parser.add_argument("--timestamp-response", help="External RFC 3161 response (.tsr)")
    parser.add_argument("--tsa-ca-file", help="Independently approved PEM CA bundle")
    parser.add_argument("--expected-tsa-certificate-sha256", help="Pin the approved TSA signing certificate's DER SHA-256")
    parser.add_argument("--expected-timestamp-request-sha256", help="Pin the originally prepared request's SHA-256")
    parser.add_argument("--require-checkpoint-timestamp", action="store_true")


def timestamp_options(args: Any) -> dict[str, Any]:
    return {
        "timestamp_request": read_timestamp_file(args.timestamp_request, MAX_REQUEST_BYTES) if args.timestamp_request else None,
        "timestamp_response": read_timestamp_file(args.timestamp_response, MAX_RESPONSE_BYTES) if args.timestamp_response else None,
        "tsa_ca_pem": read_timestamp_file(args.tsa_ca_file, MAX_CA_BYTES) if args.tsa_ca_file else None,
        "expected_tsa_certificate_sha256": args.expected_tsa_certificate_sha256,
        "expected_timestamp_request_sha256": args.expected_timestamp_request_sha256,
        "require_checkpoint_timestamp": args.require_checkpoint_timestamp,
    }
